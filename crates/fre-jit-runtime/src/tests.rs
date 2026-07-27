use std::sync::{Mutex, MutexGuard};

use fre_jit_aarch64::{
    BackendVersion, DecodedInstruction, EmitLimits, NativeAggregateResult, decode, emit,
    emit_exact_aggregate,
};
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
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
fn search_call_preserves_aapcs64_vector_callee_saved_lanes() {
    let _lock = native_test_lock();
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("fixed-width exact program");
    let image = emit(&program, EmitLimits::default()).expect("fixed-width exact image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("published kernel");
    let canaries = [
        0x0808_0808_0808_0808,
        0x0909_0909_0909_0909,
        0x1010_1010_1010_1010,
        0x1111_1111_1111_1111,
        0x1212_1212_1212_1212,
        0x1313_1313_1313_1313,
        0x1414_1414_1414_1414,
        0x1515_1515_1515_1515,
    ];
    let (raw, observed) = platform::invoke_with_vector_callee_saved_canary(
        &kernel.mapping,
        literal,
        SearchWindow::new(0, literal.len()),
        canaries,
    );
    assert_eq!(raw.status, 1);
    assert_eq!(raw.slot.start, 0);
    assert_eq!(raw.slot.end, literal.len());
    assert_eq!(observed, canaries);
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
        b"0123456789abcdef",
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
    assert_eq!(comparisons, 5_120);
}

#[test]
fn rare_pair_vector_candidates_respect_guard_pages_and_leftmost_windows() {
    const WINDOW_START: usize = 3;
    const CANDIDATE_STARTS: usize = 16;
    const FIRST_LANE: usize = 0;
    const LAST_LANE: usize = CANDIDATE_STARTS - 1;

    let _lock = native_test_lock();
    // The emitter's pinned packed-pair selector chooses these offsets. Keeping
    // both address orders here exercises the add and subtract forms used to
    // reach the secondary vector column.
    for (literal, primary_offset, secondary_offset) in [
        (b"7a".as_slice(), 0_usize, 1_usize),
        (b"a7".as_slice(), 1_usize, 0_usize),
    ] {
        assert_ne!(primary_offset, secondary_offset);
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("rare-pair exact program");
        let image = emit(&program, EmitLimits::default()).expect("rare-pair exact image");
        assert!(image.stats().vector_instructions >= 4);
        let kernel =
            publish::<Span>(&image, PublicationLimits::default()).expect("rare-pair publication");
        let window_len = CANDIDATE_STARTS
            .checked_add(literal.len())
            .and_then(|length| length.checked_sub(1))
            .expect("bounded window length");

        for (scenario, match_lanes, primary_only_lanes, expected_lane) in [
            (
                "absent-primary-lanes-0-and-15",
                [].as_slice(),
                [FIRST_LANE, LAST_LANE].as_slice(),
                None,
            ),
            (
                "lane-0",
                [FIRST_LANE].as_slice(),
                [].as_slice(),
                Some(FIRST_LANE),
            ),
            (
                "lane-15",
                [LAST_LANE].as_slice(),
                [].as_slice(),
                Some(LAST_LANE),
            ),
            (
                "lane-0-and-15",
                [FIRST_LANE, LAST_LANE].as_slice(),
                [].as_slice(),
                Some(FIRST_LANE),
            ),
        ] {
            let haystack_len = WINDOW_START
                .checked_add(window_len)
                .expect("bounded haystack length");
            let mut bytes = vec![b'x'; haystack_len];
            // A valid match before the nonzero window must never be selected.
            bytes[..literal.len()].copy_from_slice(literal);
            // Primary-only hits force the secondary vector load but must not
            // turn into exact matches.
            for &lane in primary_only_lanes {
                let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                let selected = start
                    .checked_add(primary_offset)
                    .expect("bounded selected offset");
                bytes[selected] = literal[primary_offset];
            }
            for &lane in match_lanes {
                let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                let end = start.checked_add(literal.len()).expect("bounded literal");
                bytes[start..end].copy_from_slice(literal);
            }
            let window = SearchWindow::new(WINDOW_START, bytes.len());
            let candidate_starts = window
                .end()
                .checked_sub(window.start())
                .and_then(|length| length.checked_sub(literal.len()))
                .and_then(|last_start| last_start.checked_add(1))
                .expect("literal fits in the window");
            assert_eq!(candidate_starts, CANDIDATE_STARTS);

            for right_boundary in [false, true] {
                platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                    let actual = kernel
                        .search(haystack, window)
                        .expect("guarded native execution")
                        .map(|span| (span.start(), span.end()));
                    let expected = expected_lane.map(|lane| {
                        let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                        let end = start.checked_add(literal.len()).expect("bounded literal");
                        (start, end)
                    });
                    assert_eq!(
                        actual, expected,
                        "literal={literal:?} offsets={primary_offset},{secondary_offset} \
                         scenario={scenario} right_boundary={right_boundary}"
                    );
                    assert_native_matches(&program, &kernel, haystack, window);
                })
                .expect("guarded rare-pair haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the native v7 lane matrix keeps both offset directions, every lane, all groups, and false-before-true recovery together"
)]
fn v7_sparse_recovery_covers_every_lane_group_and_pair_direction() {
    const WINDOW_START: usize = 5;
    const LANES: usize = 16;
    const GROUPS: usize = 3;
    const CANDIDATE_STARTS: usize = LANES * GROUPS;

    let _lock = native_test_lock();
    // The packed-pair policy selects 0->1 for the first literal and 1->0 for
    // the second. The next two ranked columns are staged only if the prior
    // mask still has multiple survivors.
    // The trailing space remains outside the four selected columns, so a
    // staged-mask hit can still fail whole-literal confirmation.
    for (literal, primary_offset, secondary_offset) in [
        (b"7a e ".as_slice(), 0_usize, 1_usize),
        (b"a7 e ".as_slice(), 1_usize, 0_usize),
    ] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("ranked exact program");
        let image = emit(&program, EmitLimits::default()).expect("ranked exact image");
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V7);
        let instructions = decode(image.code()).expect("v7 native image decode");
        let filter_offsets: Vec<usize> = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset,
                } => Some(usize::from(*offset)),
                _ => None,
            })
            .take(4)
            .collect();
        assert_eq!(filter_offsets.len(), 4);
        assert_eq!(filter_offsets[..2], [primary_offset, secondary_offset]);
        let verification_offset = filter_offsets[2];
        let quaternary_offset = filter_offsets[3];
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                    destination: 2,
                    source: 0
                }
            )
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::ReverseBits64 {
                    destination: 10,
                    source: 0
                }
            )
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CountLeadingZeros64 {
                    destination: 10,
                    source: 10
                }
            )
        }));
        let kernel =
            publish::<Span>(&image, PublicationLimits::default()).expect("ranked publication");
        let window_len = CANDIDATE_STARTS
            .checked_add(literal.len())
            .and_then(|length| length.checked_sub(1))
            .expect("bounded window length");
        let haystack_len = WINDOW_START
            .checked_add(window_len)
            .expect("bounded haystack length");

        for group in 0..GROUPS {
            for lane in 0..LANES {
                let candidate = group
                    .checked_mul(LANES)
                    .and_then(|start| start.checked_add(lane))
                    .expect("bounded candidate lane");
                let start = WINDOW_START
                    .checked_add(candidate)
                    .expect("bounded match start");
                let end = start.checked_add(literal.len()).expect("bounded literal");
                let mut bytes = vec![b'x'; haystack_len];
                bytes[start..end].copy_from_slice(literal);
                let window = SearchWindow::new(WINDOW_START, bytes.len());
                for right_boundary in [false, true] {
                    platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                        let actual = kernel
                            .search(haystack, window)
                            .expect("native lane execution")
                            .map(|span| (span.start(), span.end()));
                        assert_eq!(
                            actual,
                            Some((start, end)),
                            "literal={literal:?} group={group} lane={lane} \
                             right_boundary={right_boundary}"
                        );
                        assert_native_matches(&program, &kernel, haystack, window);
                    })
                    .expect("guarded ranked lane haystack");
                }
            }
        }

        for lane in 0..LANES {
            let mut bytes = vec![b'x'; haystack_len];
            let false_start = WINDOW_START.checked_add(lane).expect("bounded false start");
            for offset in [
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
            ] {
                bytes[false_start + offset] = literal[offset];
            }
            let true_start = WINDOW_START
                .checked_add(2 * LANES)
                .and_then(|start| start.checked_add(lane))
                .expect("bounded later true start");
            let true_end = true_start
                .checked_add(literal.len())
                .expect("bounded later literal");
            bytes[true_start..true_end].copy_from_slice(literal);
            let window = SearchWindow::new(WINDOW_START, bytes.len());
            for right_boundary in [false, true] {
                platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                    let actual = kernel
                        .search(haystack, window)
                        .expect("native false-then-true execution")
                        .map(|span| (span.start(), span.end()));
                    assert_eq!(
                        actual,
                        Some((true_start, true_end)),
                        "literal={literal:?} lane={lane} right_boundary={right_boundary}"
                    );
                    assert_native_matches(&program, &kernel, haystack, window);
                })
                .expect("guarded false-then-true haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the native multi-survivor matrix keeps every same-mask, next-block, tail, direction, width, and guard case explicit"
)]
fn v7_multi_survivor_masks_preserve_leftmost_across_blocks_and_tail() {
    const WINDOW_START: usize = 5;

    let _lock = native_test_lock();
    for width in [16_usize, 17, 32] {
        // Lower frequency rank wins. Four leading `a` columns therefore beat
        // the `e` at offset four and are selected in increasing order. An
        // all-`a` block consequently has sixteen simultaneous filter hits,
        // while every complete confirmation fails at offset four.
        let mut add_literal = vec![b'a'; width];
        add_literal[4] = b'e';
        let add_program = build_exact_literal::<Span>(
            &add_literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("add-direction exact program");
        let add_image = emit(&add_program, EmitLimits::default()).expect("add-direction image");
        let add_offsets = initial_v7_filter_offsets(&add_image);
        assert_eq!(add_offsets, [0, 1, 2, 3]);
        let add_kernel =
            publish::<Span>(&add_image, PublicationLimits::default()).expect("add kernel");

        for true_lane in 1..16 {
            let mut bytes = candidate_haystack(width, 32, b'a');
            install_literal(&mut bytes, WINDOW_START + true_lane, &add_literal);
            assert_guarded_v7_case(
                &add_program,
                &add_kernel,
                &bytes,
                Some(WINDOW_START + true_lane),
                "lane-0-false-then-same-mask-true",
            );
        }

        let mut several_false = candidate_haystack(width, 32, b'a');
        install_literal(&mut several_false, WINDOW_START + 9, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &several_false,
            Some(WINDOW_START + 9),
            "several-earlier-false-bits",
        );

        let mut all_sixteen_then_next = candidate_haystack(width, 32, b'a');
        install_literal(&mut all_sixteen_then_next, WINDOW_START + 16, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &all_sixteen_then_next,
            Some(WINDOW_START + 16),
            "all-sixteen-false-then-next-block-lane-zero",
        );

        let mut lane_fifteen_then_next = candidate_haystack(width, 32, b'x');
        install_filter_hit(
            &mut lane_fifteen_then_next,
            WINDOW_START + 15,
            &add_literal,
            add_offsets,
        );
        install_literal(&mut lane_fifteen_then_next, WINDOW_START + 16, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &lane_fifteen_then_next,
            Some(WINDOW_START + 16),
            "lane-fifteen-false-then-next-block-lane-zero",
        );

        let all_false_tail = candidate_haystack(width, 21, b'a');
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &all_false_tail,
            None,
            "all-sixteen-false-then-tail-none",
        );

        // These four control bytes have strict ranks 28, 29, 30, and 31.
        // Their offsets force every staged column pointer to subtract from the
        // primary offset, while lane spacings 5/10/15 avoid write conflicts.
        let mut subtract_literal = vec![b'e'; width];
        subtract_literal[8] = 0x1f;
        subtract_literal[4] = 0x1e;
        subtract_literal[2] = 0x1d;
        subtract_literal[1] = 0x1c;
        let subtract_program = build_exact_literal::<Span>(
            &subtract_literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("subtract-direction exact program");
        let subtract_image =
            emit(&subtract_program, EmitLimits::default()).expect("subtract-direction image");
        let subtract_offsets = initial_v7_filter_offsets(&subtract_image);
        assert_eq!(subtract_offsets, [8, 4, 2, 1]);
        let subtract_kernel = publish::<Span>(&subtract_image, PublicationLimits::default())
            .expect("subtract kernel");
        let mut subtract_bytes = candidate_haystack(width, 32, b'x');
        for lane in [0_usize, 5, 10, 15] {
            install_filter_hit(
                &mut subtract_bytes,
                WINDOW_START + lane,
                &subtract_literal,
                subtract_offsets,
            );
        }
        install_literal(&mut subtract_bytes, WINDOW_START + 31, &subtract_literal);
        assert_guarded_v7_case(
            &subtract_program,
            &subtract_kernel,
            &subtract_bytes,
            Some(WINDOW_START + 31),
            "ranked-subtract-multi-survivor-mask",
        );
    }
}

fn initial_v7_filter_offsets(image: &fre_jit_aarch64::NativeImage) -> [usize; 4] {
    let offsets: Vec<usize> = decode(image.code())
        .expect("v7 filter image decode")
        .iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset,
            } => Some(usize::from(*offset)),
            _ => None,
        })
        .take(4)
        .collect();
    offsets.try_into().expect("v7 has four ranked filter loads")
}

fn candidate_haystack(width: usize, candidate_starts: usize, fill: u8) -> Vec<u8> {
    let length = WINDOW_START_FOR_V7_TESTS
        .checked_add(candidate_starts)
        .and_then(|value| value.checked_add(width))
        .and_then(|value| value.checked_sub(1))
        .expect("bounded v7 multi-survivor haystack");
    vec![fill; length]
}

const WINDOW_START_FOR_V7_TESTS: usize = 5;

fn install_filter_hit(haystack: &mut [u8], start: usize, literal: &[u8], offsets: [usize; 4]) {
    for offset in offsets {
        let position = start.checked_add(offset).expect("bounded filter position");
        haystack[position] = literal[offset];
    }
}

fn install_literal(haystack: &mut [u8], start: usize, literal: &[u8]) {
    let end = start
        .checked_add(literal.len())
        .expect("bounded literal position");
    haystack[start..end].copy_from_slice(literal);
}

fn assert_guarded_v7_case(
    program: &fre_kernel_ir::ValidatedProgram<Span>,
    kernel: &crate::PublishedKernel<Span>,
    bytes: &[u8],
    expected_start: Option<usize>,
    scenario: &str,
) {
    let window = SearchWindow::new(WINDOW_START_FOR_V7_TESTS, bytes.len());
    for right_boundary in [false, true] {
        platform::with_guarded_haystack(bytes, right_boundary, |haystack| {
            let actual = kernel
                .search(haystack, window)
                .expect("guarded v7 multi-survivor execution");
            let actual = actual.map(fre_kernel_ir::MatchSpan::start);
            assert_eq!(
                actual, expected_start,
                "scenario={scenario} right_boundary={right_boundary}"
            );
            assert_native_matches(program, kernel, haystack, window);
        })
        .expect("guarded v7 multi-survivor haystack");
    }
}

#[test]
fn v7_overlapping_candidates_preserve_leftmost_and_window_nonoverlap() {
    const WINDOW_START: usize = 5;
    const CANDIDATE_STARTS: usize = 32;
    const LITERAL: &[u8] = b"aba";

    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("overlapping exact program");
    let image = emit(&program, EmitLimits::default()).expect("overlapping v7 image");
    assert_eq!(image.backend_version(), BackendVersion::SEARCH_V7);
    let kernel =
        publish::<Span>(&image, PublicationLimits::default()).expect("overlapping publication");
    let haystack_len = WINDOW_START
        .checked_add(CANDIDATE_STARTS)
        .and_then(|length| length.checked_add(LITERAL.len() - 1))
        .expect("bounded overlapping haystack");
    let mut bytes = vec![b'x'; haystack_len];
    bytes[WINDOW_START..WINDOW_START + 5].copy_from_slice(b"ababa");

    for right_boundary in [false, true] {
        platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
            let whole = SearchWindow::new(WINDOW_START, haystack.len());
            let first = kernel
                .search(haystack, whole)
                .expect("first overlapping native search")
                .map(|span| (span.start(), span.end()));
            assert_eq!(first, Some((WINDOW_START, WINDOW_START + LITERAL.len())));
            assert_native_matches(&program, &kernel, haystack, whole);

            let after_first_start = WINDOW_START + 1;
            let after_first = SearchWindow::new(after_first_start, haystack.len());
            let second = kernel
                .search(haystack, after_first)
                .expect("second overlapping native search")
                .map(|span| (span.start(), span.end()));
            assert_eq!(
                second,
                Some((WINDOW_START + 2, WINDOW_START + 2 + LITERAL.len()))
            );
            assert_native_matches(&program, &kernel, haystack, after_first);
        })
        .expect("guarded overlapping v7 haystack");
    }
}

#[test]
fn fixed_16_false_pair_confirmation_resumes_before_a_guarded_distant_match() {
    const WINDOW_START: usize = 5;
    const CANDIDATE_STARTS: usize = 48;
    const DISTANT_LANE: usize = 32;
    const LITERAL: &[u8; 16] = b"0123456789abcdef";

    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("fixed-16 exact program");
    let image = emit(&program, EmitLimits::default()).expect("fixed-16 exact image");
    let kernel =
        publish::<Span>(&image, PublicationLimits::default()).expect("fixed-16 publication");
    let window_len = CANDIDATE_STARTS
        .checked_add(LITERAL.len())
        .and_then(|length| length.checked_sub(1))
        .expect("bounded window length");

    for present in [false, true] {
        let haystack_len = WINDOW_START
            .checked_add(window_len)
            .expect("bounded guarded haystack length");
        let mut bytes = vec![b'x'; haystack_len];
        // The canonical pair for this literal is at offsets 7 and 6. This
        // candidate passes both vector columns but fails fixed-width
        // confirmation at offset 8. In particular, confirmation must reset
        // X15 from the primary-column pointer before its 16-byte load.
        let false_start = WINDOW_START;
        let false_end = false_start
            .checked_add(LITERAL.len())
            .expect("bounded false candidate");
        bytes[false_start..false_end].copy_from_slice(LITERAL);
        bytes[false_start + 8] = b'X';
        if present {
            let match_start = WINDOW_START
                .checked_add(DISTANT_LANE)
                .expect("bounded distant match");
            let match_end = match_start
                .checked_add(LITERAL.len())
                .expect("bounded distant literal");
            bytes[match_start..match_end].copy_from_slice(LITERAL);
        }
        let window = SearchWindow::new(WINDOW_START, bytes.len());

        for right_boundary in [false, true] {
            platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                let actual = kernel
                    .search(haystack, window)
                    .expect("guarded native execution")
                    .map(|span| (span.start(), span.end()));
                let expected = present.then_some((
                    WINDOW_START + DISTANT_LANE,
                    WINDOW_START + DISTANT_LANE + LITERAL.len(),
                ));
                assert_eq!(
                    actual, expected,
                    "present={present} right_boundary={right_boundary}"
                );
                assert_native_matches(&program, &kernel, haystack, window);
            })
            .expect("guarded fixed-16 false-pair haystack");
        }
    }
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

    // The canonical primary byte for this literal is at offset 7. A first-byte
    // hit at the final candidate therefore proves that scalar confirmation
    // resets its primary-column pointer before the 16-byte load at a right
    // guard boundary.
    let boundary_literal = b"0123456789abcdef";
    let boundary_program = build_exact_literal::<Span>(
        boundary_literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("fixed-width boundary program");
    let boundary_image =
        emit(&boundary_program, EmitLimits::default()).expect("fixed-width boundary image");
    let boundary_kernel =
        publish::<Span>(&boundary_image, PublicationLimits::default()).expect("boundary kernel");
    let mut final_candidate = vec![b'x'; 15];
    final_candidate.extend_from_slice(boundary_literal);
    platform::with_guarded_haystack(&final_candidate, true, |haystack| {
        let actual = boundary_kernel
            .search(haystack, SearchWindow::new(0, haystack.len()))
            .expect("final-candidate native execution")
            .map(|span| (span.start(), span.end()));
        assert_eq!(actual, Some((15, 31)));
        assert_native_matches(
            &boundary_program,
            &boundary_kernel,
            haystack,
            SearchWindow::new(0, haystack.len()),
        );
    })
    .expect("right-guard fixed-width final candidate");

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
fn mapping_guards_and_rx_permissions_are_observed_by_host() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let protections = kernel
        .mapping
        .protections()
        .expect("mapping protection query");
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
        .expect("aggregate mapping protection query");
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
