#![forbid(unsafe_code)]

use fre_kernels::{
    FIXED_ABSOLUTE_DOMAIN_SPANS_OPERATION_ID, FixedAbsoluteDomainBuildErrorKind,
    FixedAbsoluteDomainBuildLimits, FixedAbsoluteDomainBuildResource, FixedAbsoluteDomainByteMask,
    FixedAbsoluteDomainDescriptorIdentity, FixedAbsoluteDomainDescriptorKind,
    FixedAbsoluteDomainOperation, FixedAbsoluteDomainPlan, FixedAbsoluteDomainReduceErrorKind,
    FixedAbsoluteDomainReduceLimits, FixedAbsoluteDomainReduceResource, Window,
};

fn lowercase() -> FixedAbsoluteDomainByteMask {
    FixedAbsoluteDomainByteMask::inclusive(b'a', b'z')
}

fn exact_build_limits(
    upper: fre_kernels::FixedAbsoluteDomainBuildProspective,
) -> FixedAbsoluteDomainBuildLimits {
    FixedAbsoluteDomainBuildLimits {
        max_items: upper.items,
        max_payload_bytes: upper.payload_bytes,
        max_identity_bytes: upper.identity_bytes,
        max_copied_bytes: upper.copied_bytes,
        max_allocations: upper.allocations,
        max_initialized_bytes: upper.initialized_bytes,
        max_build_work: upper.build_work,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    }
}

fn exact_run_limits(
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

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table proves every construction fence refuses before source retention"
)]
fn terminal_greedy_build_has_owner_local_identity_and_every_exact_fence() {
    let baseline = FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
        lowercase(),
        b"XYZ",
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let upper = baseline.build_accounting().prospective;
    assert_eq!(
        baseline.descriptor_identity(),
        FixedAbsoluteDomainDescriptorIdentity::EndGreedyClassLiteral { suffix_bytes: 3 }
    );
    assert_eq!(
        baseline.span_sum_identity().descriptor.kind(),
        FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
    );
    assert!(baseline.span_sum_identity().original_haystack_anchors);
    assert!(baseline.span_sum_identity().non_overlapping);
    assert_ne!(
        baseline.span_sum_identity().content_digest,
        FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
            lowercase(),
            b"XYQ",
            FixedAbsoluteDomainBuildLimits::default(),
        )
        .unwrap()
        .span_sum_identity()
        .content_digest
    );
    assert_ne!(
        baseline.span_sum_identity().content_digest,
        FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
            FixedAbsoluteDomainByteMask::inclusive(b'A', b'Z'),
            b"XYZ",
            FixedAbsoluteDomainBuildLimits::default(),
        )
        .unwrap()
        .span_sum_identity()
        .content_digest
    );

    let exact = exact_build_limits(upper);
    let exact_plan =
        FixedAbsoluteDomainPlan::build_end_greedy_class_literal(lowercase(), b"XYZ", exact)
            .unwrap();
    assert_eq!(exact_plan.build_accounting().prospective, upper);
    assert_eq!(exact_plan.build_accounting().actual.allocations, 1);
    assert!(exact_plan.build_accounting().actual.published);

    let refusals = [
        (
            FixedAbsoluteDomainBuildResource::Items,
            FixedAbsoluteDomainBuildLimits {
                max_items: upper.items - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PayloadBytes,
            FixedAbsoluteDomainBuildLimits {
                max_payload_bytes: upper.payload_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::IdentityBytes,
            FixedAbsoluteDomainBuildLimits {
                max_identity_bytes: upper.identity_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::CopiedBytes,
            FixedAbsoluteDomainBuildLimits {
                max_copied_bytes: upper.copied_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::Allocations,
            FixedAbsoluteDomainBuildLimits {
                max_allocations: upper.allocations - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::InitializedBytes,
            FixedAbsoluteDomainBuildLimits {
                max_initialized_bytes: upper.initialized_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::Work,
            FixedAbsoluteDomainBuildLimits {
                max_build_work: upper.build_work - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PersistentBytes,
            FixedAbsoluteDomainBuildLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PeakBytes,
            FixedAbsoluteDomainBuildLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact
            },
        ),
    ];
    for (resource, limits) in refusals {
        let error =
            FixedAbsoluteDomainPlan::build_end_greedy_class_literal(lowercase(), b"XYZ", limits)
                .expect_err("one-below construction fence must refuse");
        assert!(matches!(
            error.kind,
            FixedAbsoluteDomainBuildErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
        assert_eq!(error.prospective, Some(upper));
        assert_eq!(error.actual.allocations, 0);
        assert_eq!(error.actual.initialized_bytes, 0);
        assert!(!error.actual.published);
    }
}

#[test]
fn terminal_greedy_execution_preserves_eof_greed_ranges_and_full_source_envelope() {
    let plan = FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
        lowercase(),
        b"XYZ",
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for (haystack, expected) in [
        (b"XYZ".as_slice(), 3),
        (b"abcXYZ".as_slice(), 6),
        (b"!abcXYZ".as_slice(), 6),
        (b"ab!abcXYZ".as_slice(), 6),
        (b"abcXY".as_slice(), 0),
        (b"abcXYZ!".as_slice(), 0),
    ] {
        let result = plan
            .span_sum(haystack, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(result.span_sum, expected, "{haystack:?}");
        assert_eq!(result.accounting.prospective.byte_probes, haystack.len());
        assert_eq!(
            result.accounting.prospective.span_sum,
            u64::try_from(haystack.len()).unwrap()
        );
        assert_eq!(result.accounting.actual.allocations, 0);
        assert_eq!(result.accounting.actual.scratch_bytes, 0);
        assert!(result.accounting.actual.fits(result.accounting.prospective));
    }

    let haystack = b"!xabcXYZ";
    let included = plan
        .span_sum_in(
            haystack,
            Window::new(2, haystack.len()),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap();
    assert_eq!(included.span_sum, 6);
    let excluded = plan
        .span_sum_in(
            haystack,
            Window::new(0, haystack.len() - 1),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap();
    assert_eq!(excluded.span_sum, 0);
    assert_eq!(excluded.accounting.actual.source_accesses, 0);

    for length in [1_024_usize, 2_048, 4_096] {
        let suffix_start = length.checked_sub(3).unwrap();
        let mut all_class = vec![b'a'; length];
        all_class[suffix_start..].copy_from_slice(b"XYZ");
        let result = plan
            .span_sum(&all_class, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        let expected_work = length.checked_add(2).unwrap();
        assert_eq!(result.span_sum, u64::try_from(length).unwrap());
        assert_eq!(result.accounting.prospective.byte_probes, length);
        assert_eq!(result.accounting.prospective.total_work, expected_work);
        assert_eq!(result.accounting.actual.source_accesses, length);
        assert_eq!(result.accounting.actual.total_work, expected_work);
        assert_eq!(result.accounting.actual.allocations, 0);
    }
}

#[test]
fn terminal_greedy_emits_the_exact_complete_span_without_a_second_scan() {
    let plan = FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
        lowercase(),
        b"XYZ",
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    for (haystack, expected) in [
        (b"XYZ".as_slice(), Some((0, 3))),
        (b"abcXYZ".as_slice(), Some((0, 6))),
        (b"!abcXYZ".as_slice(), Some((1, 7))),
        (b"ab!abcXYZ".as_slice(), Some((3, 9))),
        (b"abcXY".as_slice(), None),
        (b"abcXYZ!".as_slice(), None),
    ] {
        let result = plan
            .spans(haystack, FixedAbsoluteDomainReduceLimits::default())
            .unwrap();
        assert_eq!(
            result.span.map(|span| (span.start(), span.end())),
            expected,
            "{haystack:?}"
        );
        assert_eq!(
            result.accounting.actual.span_sum,
            expected.map_or(0, |(start, end)| {
                u64::try_from(end.checked_sub(start).unwrap()).unwrap()
            })
        );
        assert_eq!(
            result.accounting.identity.operation,
            FixedAbsoluteDomainOperation::Spans
        );
        assert_eq!(
            result.accounting.identity.operation_id,
            FIXED_ABSOLUTE_DOMAIN_SPANS_OPERATION_ID
        );
        assert!(result.accounting.actual.fits(result.accounting.prospective));
        assert_eq!(
            plan.spans_value_success(haystack, FixedAbsoluteDomainReduceLimits::default())
                .unwrap()
                .span()
                .map(|span| (span.start(), span.end())),
            expected
        );
    }

    let haystack = b"!xabcXYZ";
    let included = plan
        .spans_in(
            haystack,
            Window::new(2, haystack.len()),
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap();
    assert_eq!(
        included.span.map(|span| (span.start(), span.end())),
        Some((2, 8))
    );

    let span_sum_upper = plan
        .preflight(
            haystack.len(),
            Window::full(haystack),
            FixedAbsoluteDomainOperation::SpanSum,
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .prospective();
    let spans_upper = plan
        .preflight(
            haystack.len(),
            Window::full(haystack),
            FixedAbsoluteDomainOperation::Spans,
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .prospective();
    assert_eq!(spans_upper, span_sum_upper);
}

#[test]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "every subtraction is guarded by a positive prospective field"
)]
fn terminal_greedy_run_exact_limits_succeed_and_every_one_below_refuses_pre_source() {
    let plan = FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
        lowercase(),
        b"XYZ",
        FixedAbsoluteDomainBuildLimits::default(),
    )
    .unwrap();
    let haystack = b"!abcXYZ";
    let upper = plan
        .preflight(
            haystack.len(),
            Window::full(haystack),
            FixedAbsoluteDomainOperation::SpanSum,
            FixedAbsoluteDomainReduceLimits::default(),
        )
        .unwrap()
        .prospective();
    let exact = exact_run_limits(upper);
    assert_eq!(plan.span_sum(haystack, exact).unwrap().span_sum, 6);

    let refusals = [
        (
            FixedAbsoluteDomainReduceResource::ByteProbes,
            FixedAbsoluteDomainReduceLimits {
                max_byte_probes: upper.byte_probes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::BranchChecks,
            FixedAbsoluteDomainReduceLimits {
                max_branch_checks: upper.branch_checks - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::MatchEvents,
            FixedAbsoluteDomainReduceLimits {
                max_match_events: upper.match_events - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::Count,
            FixedAbsoluteDomainReduceLimits {
                max_count: upper.count - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::SpanSum,
            FixedAbsoluteDomainReduceLimits {
                max_span_sum: upper.span_sum - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::ReducerSteps,
            FixedAbsoluteDomainReduceLimits {
                max_reducer_steps: upper.reducer_steps - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::TotalWork,
            FixedAbsoluteDomainReduceLimits {
                max_total_work: upper.total_work - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::PersistentBytes,
            FixedAbsoluteDomainReduceLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::PeakBytes,
            FixedAbsoluteDomainReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact
            },
        ),
    ];
    for (resource, limits) in refusals {
        let error = plan
            .span_sum(haystack, limits)
            .expect_err("one-below run fence must refuse before source");
        assert!(matches!(
            error.kind,
            FixedAbsoluteDomainReduceErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
        assert_eq!(error.receipt.prospective, Some(upper));
        assert_eq!(error.receipt.actual.source_accesses, 0);
        assert_eq!(error.receipt.actual.allocations, 0);
    }

    let error = plan
        .count(haystack, FixedAbsoluteDomainReduceLimits::default())
        .expect_err("span-only descriptor must reject count");
    assert!(matches!(
        error.kind,
        FixedAbsoluteDomainReduceErrorKind::OperationMismatch {
            descriptor: FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral,
            operation: FixedAbsoluteDomainOperation::Count,
        }
    ));
    assert_eq!(error.receipt.actual.source_accesses, 0);
}
