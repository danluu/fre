#![forbid(unsafe_code)]

use fre_kernels::{
    FixedAbsoluteDomainBuildErrorKind, FixedAbsoluteDomainBuildLimits, FixedAbsoluteDomainByteMask,
    FixedAbsoluteDomainCountOutcome, FixedAbsoluteDomainDescriptorIdentity,
    FixedAbsoluteDomainDisposition, FixedAbsoluteDomainOperation, FixedAbsoluteDomainPlan,
    FixedAbsoluteDomainReduceErrorKind, FixedAbsoluteDomainReduceLimits,
    FixedAbsoluteDomainReduceResource, Window,
};

fn singleton(byte: u8) -> FixedAbsoluteDomainByteMask {
    FixedAbsoluteDomainByteMask::inclusive(byte, byte)
}

fn masks(bytes: &[u8]) -> impl ExactSizeIterator<Item = FixedAbsoluteDomainByteMask> + '_ {
    bytes.iter().copied().map(singleton)
}

fn exact_reduce_limits(
    upper: fre_kernels::FixedAbsoluteDomainProspective,
) -> FixedAbsoluteDomainReduceLimits {
    FixedAbsoluteDomainReduceLimits {
        max_byte_probes: upper.byte_probes,
        max_branch_checks: upper.branch_checks,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_reducer_steps: upper.reducer_steps,
        max_total_work: upper.total_work,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "each subtraction is guarded by a positive upper bound in the exhaustive fence table"
)]
fn assert_every_run_fence(
    name: &str,
    plan: &FixedAbsoluteDomainPlan,
    haystack_len: usize,
    operation: FixedAbsoluteDomainOperation,
) {
    let window = Window::new(0, haystack_len);
    let upper = plan
        .preflight(
            haystack_len,
            window,
            operation,
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .prospective();
    let exact = exact_reduce_limits(upper);
    assert_eq!(
        plan.preflight(haystack_len, window, operation, exact)
            .unwrap()
            .prospective(),
        upper,
        "{name}"
    );

    let mut below = Vec::new();
    if upper.byte_probes > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::ByteProbes,
            FixedAbsoluteDomainReduceLimits {
                max_byte_probes: upper.byte_probes - 1,
                ..exact
            },
        ));
    }
    if upper.branch_checks > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::BranchChecks,
            FixedAbsoluteDomainReduceLimits {
                max_branch_checks: upper.branch_checks - 1,
                ..exact
            },
        ));
    }
    if upper.match_events > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::MatchEvents,
            FixedAbsoluteDomainReduceLimits {
                max_match_events: upper.match_events - 1,
                ..exact
            },
        ));
    }
    if upper.count > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::Count,
            FixedAbsoluteDomainReduceLimits {
                max_count: upper.count - 1,
                ..exact
            },
        ));
    }
    if upper.span_sum > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::SpanSum,
            FixedAbsoluteDomainReduceLimits {
                max_span_sum: upper.span_sum - 1,
                ..exact
            },
        ));
    }
    if upper.reducer_steps > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::ReducerSteps,
            FixedAbsoluteDomainReduceLimits {
                max_reducer_steps: upper.reducer_steps - 1,
                ..exact
            },
        ));
    }
    if upper.total_work > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::TotalWork,
            FixedAbsoluteDomainReduceLimits {
                max_total_work: upper.total_work - 1,
                ..exact
            },
        ));
    }
    if upper.scratch_bytes > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::ScratchBytes,
            FixedAbsoluteDomainReduceLimits {
                max_scratch_bytes: upper.scratch_bytes - 1,
                ..exact
            },
        ));
    }
    if upper.persistent_bytes > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::PersistentBytes,
            FixedAbsoluteDomainReduceLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..exact
            },
        ));
    }
    if upper.peak_bytes > 0 {
        below.push((
            FixedAbsoluteDomainReduceResource::PeakBytes,
            FixedAbsoluteDomainReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact
            },
        ));
    }
    for (resource, limits) in below {
        let error = plan
            .preflight(haystack_len, window, operation, limits)
            .expect_err("every positive one-below run fence refuses");
        assert!(
            matches!(
                error.kind,
                FixedAbsoluteDomainReduceErrorKind::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ),
            "{name}/{resource:?}: {error:?}"
        );
        assert_eq!(
            error.receipt.prospective,
            Some(upper),
            "{name}/{resource:?}"
        );
        assert_eq!(
            error.receipt.actual.source_accesses, 0,
            "{name}/{resource:?}"
        );
        assert_eq!(error.receipt.actual.allocations, 0, "{name}/{resource:?}");
    }
}

#[test]
fn endpoint_masks_are_positional_and_end_is_never_rebased_to_a_window() {
    let plan = FixedAbsoluteDomainPlan::build_end_mask_sequence(
        masks(b"ab"),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.descriptor_identity(),
        FixedAbsoluteDomainDescriptorIdentity::EndMaskSequence { width: 2 }
    );

    let matched = plan
        .span_sum(b"xab", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(matched.span_sum, 2);
    assert!(
        matched
            .accounting
            .actual
            .fits(matched.accounting.prospective)
    );
    assert_eq!(matched.accounting.actual.source_accesses, 2);

    let included = plan
        .span_sum_in(
            b"xab",
            Window::new(1, 3),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap();
    assert_eq!(included.span_sum, 2);
    for excluded in [Window::new(0, 2), Window::new(2, 3)] {
        let result = plan
            .span_sum_in(b"xab", excluded, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(result.span_sum, 0);
        assert_eq!(result.accounting.actual.source_accesses, 0);
    }

    for rejected in [b"xba".as_slice(), b"aab".as_slice(), b"abb".as_slice()] {
        let result = plan
            .span_sum(rejected, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        let expected = if rejected == b"aab" { 2 } else { 0 };
        assert_eq!(result.span_sum, expected);
    }
}

#[test]
fn endpoint_one_byte_mask_covers_all_bytes_without_unicode_conflation() {
    let mut word = FixedAbsoluteDomainByteMask::default();
    for (start, end) in [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')] {
        word.insert_inclusive(start, end);
    }
    let plan = FixedAbsoluteDomainPlan::build_end_one_byte_mask(
        word,
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for byte in u8::MIN..=u8::MAX {
        let result = plan
            .span_sum(&[byte], FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        let expected = u64::from(byte.is_ascii_alphanumeric() || byte == b'_');
        assert_eq!(result.span_sum, expected, "byte={byte:#04X}");
    }
    assert_eq!(
        plan.span_sum(b"", FixedAbsoluteDomainReduceLimits::default())
            .unwrap()
            .accounting
            .actual
            .source_accesses,
        0
    );
}

#[test]
fn endpoint_whole_repeat_words_and_start_prefix_preserve_absolute_candidates() {
    let repeat = FixedAbsoluteDomainPlan::build_whole_byte_repeat(
        b'a',
        2,
        5,
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for (haystack, expected) in [
        (b"".as_slice(), 0),
        (b"a".as_slice(), 0),
        (b"aa".as_slice(), 1),
        (b"aaaaa".as_slice(), 1),
        (b"aaaaaa".as_slice(), 0),
        (b"aaba".as_slice(), 0),
    ] {
        let result = repeat
            .count(haystack, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(result.count(), Some(expected));
        assert!(result.accounting.actual.fits(result.accounting.prospective));
    }
    assert_eq!(
        repeat
            .count_in(
                b"aa",
                Window::new(1, 2),
                FixedAbsoluteDomainReduceLimits::default(),
            )
            .unwrap()
            .count(),
        Some(0)
    );

    let words = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
        3,
        7,
        [b"aaa".as_slice(), b"aa".as_slice(), b"aa".as_slice()].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let first = words
        .count(b"aaa", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(first.count(), Some(1));
    assert_eq!(first.accounting.actual.branch_checks, 4);
    assert_eq!(first.accounting.actual.byte_probes, 3);
    assert_eq!(first.accounting.actual.selected_branch_ordinal, Some(0));
    let second = words
        .count(b"aa", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(second.count(), Some(1));
    assert_eq!(second.accounting.actual.branch_checks, 5);
    assert_eq!(second.accounting.actual.byte_probes, 2);
    assert_eq!(second.accounting.actual.selected_branch_ordinal, Some(1));
    let all_failed = words
        .count(b"ab", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(all_failed.count(), Some(0));
    assert_eq!(all_failed.accounting.actual.branch_checks, 6);
    assert_eq!(all_failed.accounting.actual.selected_branch_ordinal, None);

    let prefix = FixedAbsoluteDomainPlan::build_start_ordered_prefix(
        b"zbc",
        [b'e', b'd', b'd'].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let first = prefix
        .span_sum(b"zbce-tail", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(first.span_sum, 4);
    assert_eq!(first.accounting.actual.selected_branch_ordinal, Some(0));
    assert_eq!(first.accounting.actual.source_accesses, 4);
    assert_eq!(first.accounting.actual.byte_probes, 4);
    let second = prefix
        .span_sum(b"zbcd-tail", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(second.span_sum, 4);
    assert_eq!(second.accounting.actual.selected_branch_ordinal, Some(1));
    assert_eq!(second.accounting.actual.source_accesses, 4);
    assert_eq!(second.accounting.actual.byte_probes, 5);
    let miss = prefix
        .span_sum(b"zbcf-tail", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    assert_eq!(miss.span_sum, 0);
    assert_eq!(miss.accounting.actual.selected_branch_ordinal, None);
    assert_eq!(miss.accounting.actual.source_accesses, 4);
    assert_eq!(miss.accounting.actual.byte_probes, 6);
    assert_eq!(
        prefix
            .span_sum_in(
                b"xzbcd",
                Window::new(1, 5),
                FixedAbsoluteDomainReduceLimits::default(),
            )
            .unwrap()
            .span_sum,
        0
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven semantic witness covers byte edges, mismatch receipts, and ranged anchoring"
)]
fn endpoint_class_edges_mismatches_and_ranges_never_create_surrogate_haystacks() {
    let positional = FixedAbsoluteDomainPlan::build_end_mask_sequence(
        [
            FixedAbsoluteDomainByteMask::inclusive(b'A', b'C'),
            FixedAbsoluteDomainByteMask::inclusive(b'0', b'2'),
            FixedAbsoluteDomainByteMask::inclusive(b'x', b'z'),
        ]
        .into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for suffix in [b"A0x".as_slice(), b"C2z".as_slice()] {
        let mut haystack = b"prefix---".to_vec();
        haystack.extend_from_slice(suffix);
        assert_eq!(
            positional
                .span_sum(&haystack, FixedAbsoluteDomainReduceLimits::default())
                .unwrap()
                .span_sum,
            3
        );
        for offset in 0..suffix.len() {
            let index = haystack.len() - suffix.len() + offset;
            let saved = haystack[index];
            haystack[index] = [b'D', b'3', b'w'][offset];
            assert_eq!(
                positional
                    .span_sum(&haystack, FixedAbsoluteDomainReduceLimits::default())
                    .unwrap()
                    .span_sum,
                0,
                "suffix={suffix:?}, offset={offset}"
            );
            haystack[index] = saved;
        }
    }

    let repeat = FixedAbsoluteDomainPlan::build_whole_byte_repeat(
        b'a',
        2,
        5,
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for length in 0..=7 {
        let mut haystack = vec![b'a'; length];
        let expected = u64::from((2..=5).contains(&length));
        assert_eq!(
            repeat
                .count(&haystack, FixedAbsoluteDomainReduceLimits::default())
                .unwrap()
                .count(),
            Some(expected),
            "length={length}"
        );
        for mismatch in 0..length {
            haystack[mismatch] = b'b';
            assert_eq!(
                repeat
                    .count(&haystack, FixedAbsoluteDomainReduceLimits::default())
                    .unwrap()
                    .count(),
                Some(0),
                "length={length}, mismatch={mismatch}"
            );
            haystack[mismatch] = b'a';
        }
    }

    let one = FixedAbsoluteDomainPlan::build_end_one_byte_mask(
        singleton(b'a'),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_eq!(
        one.span_sum_in(
            b"aa",
            Window::new(1, 2),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .span_sum,
        1
    );
    assert_eq!(
        one.span_sum_in(
            b"aa",
            Window::new(0, 1),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .span_sum,
        0
    );

    let words = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
        2,
        5,
        [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for window in [Window::new(0, 1), Window::new(1, 2)] {
        let result = words
            .count_in(b"aa", window, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(result.count(), Some(0));
        assert_eq!(result.accounting.actual.source_accesses, 0);
    }

    let scalar = FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
        249,
        1,
        [(0, 0x10_FFFF)].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for window in [Window::new(0, 248), Window::new(1, 249)] {
        let result = scalar
            .count_in(
                &vec![b'a'; 249],
                window,
                FixedAbsoluteDomainReduceLimits::default(),
            )
            .unwrap();
        assert_eq!(
            result.outcome,
            FixedAbsoluteDomainCountOutcome::Complete { count: 0 }
        );
        assert_eq!(result.accounting.actual.source_accesses, 0);
    }
}

#[test]
fn endpoint_scalar_envelope_is_rejection_only_and_selects_residual_before_source() {
    let plan = FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
        249,
        1,
        [(0, 0x10_FFFF)].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.descriptor_identity(),
        FixedAbsoluteDomainDescriptorIdentity::WholeScalarEnvelope {
            scalars: 249,
            minimum_bytes: 249,
            maximum_bytes: 996,
        }
    );
    for length in [0, 248, 997, 1_000] {
        let haystack = vec![b'x'; length];
        let result = plan
            .count(&haystack, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(
            result.outcome,
            FixedAbsoluteDomainCountOutcome::Complete { count: 0 }
        );
        assert_eq!(result.accounting.actual.source_accesses, 0);
        assert_eq!(result.accounting.actual.allocations, 0);
    }
    for length in [249, 250, 995, 996] {
        let admission = plan
            .preflight(
                length,
                Window::new(0, length),
                FixedAbsoluteDomainOperation::Count,
                FixedAbsoluteDomainReduceLimits::default(),
            )
            .unwrap();
        assert_eq!(
            admission.disposition(),
            FixedAbsoluteDomainDisposition::PrepublishedContinuation
        );
        let result = plan.count_admitted(&vec![b'x'; length], admission).unwrap();
        assert_eq!(
            result.outcome,
            FixedAbsoluteDomainCountOutcome::PrepublishedContinuation,
            "guard never infers acceptance"
        );
        assert_eq!(result.accounting.actual.source_accesses, 0);
    }
}

#[test]
fn endpoint_build_exact_limits_succeed_and_every_one_below_refuses_before_allocation() {
    let baseline = FixedAbsoluteDomainPlan::build_end_mask_sequence(
        masks(b"abc"),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let upper = baseline.build_accounting().prospective;
    let exact = FixedAbsoluteDomainBuildLimits {
        max_items: upper.items,
        max_payload_bytes: upper.payload_bytes,
        max_identity_bytes: upper.identity_bytes,
        max_copied_bytes: upper.copied_bytes,
        max_allocations: upper.allocations,
        max_initialized_bytes: upper.initialized_bytes,
        max_build_work: upper.build_work,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    };
    let exact_plan =
        FixedAbsoluteDomainPlan::build_end_mask_sequence(masks(b"abc"), exact).unwrap();
    assert_eq!(exact_plan.build_accounting().prospective, upper);
    assert!(exact_plan.build_accounting().actual.published);

    let mut below = Vec::new();
    let mut limits = exact;
    limits.max_items = limits.max_items.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_payload_bytes = limits.max_payload_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_identity_bytes = limits.max_identity_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_copied_bytes = limits.max_copied_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_allocations = limits.max_allocations.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_initialized_bytes = limits.max_initialized_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_build_work = limits.max_build_work.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_persistent_bytes = limits.max_persistent_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_peak_bytes = limits.max_peak_bytes.checked_sub(1).unwrap();
    below.push(limits);
    for limits in below {
        let error = FixedAbsoluteDomainPlan::build_end_mask_sequence(masks(b"abc"), limits)
            .expect_err("every one-below build limit must refuse");
        assert!(matches!(
            error.kind,
            FixedAbsoluteDomainBuildErrorKind::ResourceLimit { .. }
        ));
        assert_eq!(error.prospective, Some(upper));
        assert_eq!(error.actual.allocations, 0);
        assert_eq!(error.actual.initialized_bytes, 0);
        assert!(!error.actual.published);
    }
}

#[test]
fn endpoint_run_exact_limits_succeed_and_every_one_below_refuses_before_source() {
    let plan = FixedAbsoluteDomainPlan::build_end_mask_sequence(
        masks(b"abc"),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let baseline = plan
        .span_sum(b"xabc", FixedAbsoluteDomainReduceLimits::default())
        .unwrap();
    let upper = baseline.accounting.prospective;
    let exact = exact_reduce_limits(upper);
    let exact_result = plan.span_sum(b"xabc", exact).unwrap();
    assert_eq!(exact_result.span_sum, 3);
    assert!(exact_result.accounting.actual.fits(upper));

    let mut below = Vec::new();
    let mut limits = exact;
    limits.max_byte_probes = limits.max_byte_probes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_branch_checks = limits.max_branch_checks.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_match_events = limits.max_match_events.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_count = limits.max_count.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_span_sum = limits.max_span_sum.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_reducer_steps = limits.max_reducer_steps.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_total_work = limits.max_total_work.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_persistent_bytes = limits.max_persistent_bytes.checked_sub(1).unwrap();
    below.push(limits);
    let mut limits = exact;
    limits.max_peak_bytes = limits.max_peak_bytes.checked_sub(1).unwrap();
    below.push(limits);
    for limits in below {
        let error = plan
            .span_sum(b"xabc", limits)
            .expect_err("every positive one-below run limit must refuse");
        assert!(matches!(
            error.kind,
            FixedAbsoluteDomainReduceErrorKind::ResourceLimit { .. }
        ));
        assert_eq!(error.receipt.prospective, Some(upper));
        assert_eq!(error.receipt.actual.source_accesses, 0);
        assert_eq!(error.receipt.actual.allocations, 0);
    }
}

#[test]
fn endpoint_every_descriptor_has_exact_and_every_positive_one_below_run_fences() {
    let end_masks = FixedAbsoluteDomainPlan::build_end_mask_sequence(
        masks(b"ab"),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "end-mask-sequence",
        &end_masks,
        3,
        FixedAbsoluteDomainOperation::SpanSum,
    );

    let end_one = FixedAbsoluteDomainPlan::build_end_one_byte_mask(
        singleton(b'a'),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "end-one-byte-mask",
        &end_one,
        1,
        FixedAbsoluteDomainOperation::SpanSum,
    );

    let repeat = FixedAbsoluteDomainPlan::build_whole_byte_repeat(
        b'a',
        2,
        5,
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "whole-byte-repeat",
        &repeat,
        5,
        FixedAbsoluteDomainOperation::Count,
    );

    let words = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
        2,
        5,
        [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "whole-ordered-words",
        &words,
        3,
        FixedAbsoluteDomainOperation::Count,
    );

    let prefix = FixedAbsoluteDomainPlan::build_start_ordered_prefix(
        b"zbc",
        [b'd', b'e'].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "start-ordered-prefix",
        &prefix,
        8,
        FixedAbsoluteDomainOperation::SpanSum,
    );

    let scalar = FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
        249,
        1,
        [(0, 0x10_FFFF)].into_iter(),
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    assert_every_run_fence(
        "whole-scalar-envelope",
        &scalar,
        249,
        FixedAbsoluteDomainOperation::Count,
    );
}
