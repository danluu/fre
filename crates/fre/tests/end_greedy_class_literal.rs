#![forbid(unsafe_code)]

use fre::{
    AggregateBuildError, AggregateBuildLimits, AggregateBuilder, AggregateExecutionDetails,
    AggregateExecutionSource, AggregateFixedAbsoluteDomainExecutionDetails, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, FixedAbsoluteDomainBuildLimits,
    FixedAbsoluteDomainBuildResource, FixedAbsoluteDomainDescriptorKind,
    FixedAbsoluteDomainReduceLimits, FixedAbsoluteDomainReduceResource,
};

const PATTERN: &str = r"[a-z]*XYZ$";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(fre::RustProfile::rebar_1_12_4())
        .unicode(false)
}

fn direct() -> fre::AggregateSpanSumRegex {
    builder(PATTERN).build_span_sum().unwrap()
}

fn exact_build_limits(
    upper: fre::FixedAbsoluteDomainBuildProspective,
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

fn exact_run_limits(upper: fre::FixedAbsoluteDomainProspective) -> FixedAbsoluteDomainReduceLimits {
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
fn terminal_greedy_facade_is_closed_differential_and_pointwise_ready_at_one_kib() {
    let regex = direct();
    let report = regex.build_report();
    assert_eq!(report.plan, AggregatePlanKind::FixedAbsoluteDomain);
    assert!(report.has_closed_fixed_absolute_domain_identity());
    let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = report.plan_identity else {
        panic!("terminal greedy route lacks fixed identity");
    };
    assert_eq!(
        identity.kernel.descriptor.kind(),
        FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
    );
    assert!(identity.kernel.original_haystack_anchors);
    assert!(identity.kernel.non_overlapping);
    assert!(identity.residual.is_none());
    assert!(identity.residual_strategy.is_none());
    assert!(report.authenticates_fixed_absolute_domain_identity(identity));

    let oracle = builder(PATTERN)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    for haystack in [
        b"".as_slice(),
        b"XYZ",
        b"abcXYZ",
        b"!abcXYZ",
        b"ab!abcXYZ",
        b"abcXY",
        b"abcXYZ!",
        b"abcXYZ\n",
        b"\xffabcXYZ",
    ] {
        assert_eq!(
            regex
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            oracle
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            "{haystack:?}"
        );
    }

    let mut one_kib = vec![b'a'; 1_024];
    one_kib[1_021..].copy_from_slice(b"XYZ");
    let first = regex
        .span_sum(&one_kib, AggregateRunLimits::default())
        .unwrap();
    let steady = regex
        .span_sum(&one_kib, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(first.value(), 1_024);
    assert_eq!(first.report().identity, steady.report().identity);
    assert_eq!(
        first.report().cache_identity(),
        steady.report().cache_identity()
    );
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = &first.report().details
    else {
        panic!("terminal greedy execution lacks fixed guard receipt");
    };
    assert_eq!(guard.prospective.byte_probes, one_kib.len());
    assert_eq!(
        guard.prospective.span_sum,
        u64::try_from(one_kib.len()).unwrap()
    );
    assert_eq!(guard.actual.source_accesses, one_kib.len());
    assert_eq!(guard.actual.allocations, 0);
    assert_eq!(guard.actual.scratch_bytes, 0);
    assert!(guard.actual.fits(guard.prospective));
}

#[test]
fn terminal_greedy_transparent_captures_and_suffix_class_overlap_preserve_semantics() {
    let captured_pattern = r"(?P<run>[a-z])*(?P<suffix>XYZ)$";
    let captured = builder(captured_pattern).build_span_sum().unwrap();
    let captured_oracle = builder(captured_pattern)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    assert_eq!(captured.build_report().captures_erased, 2);
    let AggregatePlanIdentity::FixedAbsoluteDomain(captured_identity) =
        captured.build_report().plan_identity
    else {
        panic!("transparent captures displaced the terminal greedy route");
    };
    assert_eq!(
        captured_identity.kernel.descriptor.kind(),
        FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
    );
    assert_eq!(
        captured
            .span_sum_value(b"!abcXYZ", AggregateRunLimits::default())
            .unwrap(),
        captured_oracle
            .span_sum_value(b"!abcXYZ", AggregateRunLimits::default())
            .unwrap()
    );

    let overlapping_suffix_class = builder(r"[A-Z]*XYZ$").build_span_sum().unwrap();
    assert_eq!(
        overlapping_suffix_class
            .span_sum_value(b"ABCXYZ", AggregateRunLimits::default())
            .unwrap(),
        6
    );
}

#[test]
fn terminal_greedy_near_shapes_are_rejected_without_displacing_incumbent_routes() {
    for pattern in [
        r"[a-z]*?XYZ$",
        r"[a-z]+XYZ$",
        r"[a-z]{0,3}XYZ$",
        r"[a-z]*XYZ",
        r"[a-z]*XY[ZQ]$",
    ] {
        let regex = builder(pattern).build_span_sum().unwrap();
        if let AggregatePlanIdentity::FixedAbsoluteDomain(identity) =
            regex.build_report().plan_identity
        {
            assert_ne!(
                identity.kernel.descriptor.kind(),
                FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral,
                "{pattern}"
            );
        }
    }

    for retained in ["[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$", r"\w$", r"^zbc(d|e)"] {
        let regex = builder(retained).build_span_sum().unwrap();
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{retained}"
        );
        let AggregatePlanIdentity::FixedAbsoluteDomain(identity) =
            regex.build_report().plan_identity
        else {
            panic!("retained route lost fixed identity: {retained}");
        };
        assert_ne!(
            identity.kernel.descriptor.kind(),
            FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral,
            "{retained}"
        );
        assert!(
            regex
                .build_report()
                .has_closed_fixed_absolute_domain_identity()
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table proves every owner-inclusive construction fence"
)]
fn terminal_greedy_facade_forwards_exact_and_every_one_below_build_fence() {
    let baseline = direct();
    let build = baseline
        .build_report()
        .fixed_absolute_domain_build_accounting()
        .expect("terminal greedy route lacks construction accounting");
    let upper = build.guard_with_owner.prospective;
    let exact = exact_build_limits(upper);
    let exact_regex = builder(PATTERN)
        .limits(AggregateBuildLimits {
            fixed_absolute: exact,
            ..AggregateBuildLimits::default()
        })
        .build_span_sum()
        .unwrap();
    assert_eq!(
        exact_regex.build_report().plan_identity,
        baseline.build_report().plan_identity
    );

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
    for (resource, fixed_absolute) in refusals {
        let error = builder(PATTERN)
            .limits(AggregateBuildLimits {
                fixed_absolute,
                ..AggregateBuildLimits::default()
            })
            .build_span_sum()
            .expect_err("one-below construction fence must refuse");
        let AggregateBuildError::FixedAbsoluteDomainBuild { source, .. } = error else {
            panic!("one-below construction fence escaped the fixed route: {resource:?}");
        };
        assert_eq!(source.prospective, Some(upper));
        assert_eq!(source.actual.allocations, 0);
        assert_eq!(source.actual.initialized_bytes, 0);
        assert!(!source.actual.published);
        assert!(matches!(
            source.kind,
            fre::FixedAbsoluteDomainBuildErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table proves every full-haystack pre-source execution fence"
)]
fn terminal_greedy_facade_forwards_exact_and_every_one_below_run_fence() {
    let regex = direct();
    let haystack = b"!abcXYZ";
    let baseline = regex
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = &baseline.report().details
    else {
        panic!("terminal greedy baseline lacks fixed guard receipt");
    };
    let upper = guard.prospective;
    let exact = exact_run_limits(upper);
    assert_eq!(
        regex
            .span_sum(
                haystack,
                AggregateRunLimits {
                    fixed_absolute: exact,
                    ..AggregateRunLimits::default()
                },
            )
            .unwrap()
            .value(),
        6
    );

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
    for (resource, fixed_absolute) in refusals {
        let error = regex
            .span_sum(
                haystack,
                AggregateRunLimits {
                    fixed_absolute,
                    ..AggregateRunLimits::default()
                },
            )
            .expect_err("one-below run fence must refuse before source");
        assert!(error.has_closed_fixed_attempt());
        assert!(matches!(
            error.source,
            AggregateExecutionSource::FixedAbsoluteDomain
        ));
        let receipt = error
            .fixed_absolute_domain_receipt()
            .expect("one-below run refusal lacks authenticated receipt");
        let guard = receipt
            .guard_error()
            .expect("one-below run refusal lacks typed guard error");
        assert_eq!(guard.receipt.prospective, Some(upper));
        assert_eq!(guard.receipt.actual.source_accesses, 0);
        assert_eq!(guard.receipt.actual.allocations, 0);
        assert!(matches!(
            guard.kind,
            fre::FixedAbsoluteDomainReduceErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
    }
}
