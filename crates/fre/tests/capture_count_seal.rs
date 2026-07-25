use fre::{
    AGGREGATE_CONTINUATION_ACCOUNTING_VERSION, AGGREGATE_CONTINUATION_ALGORITHM_VERSION,
    AggregateExecutionAccounting, AggregateOperationAttemptKind, AggregateOperationLimits,
    AggregateOperationPhysicalRoute, AggregateOperationPrepublicationFallback,
    AggregateOperationProspective, AggregateOperationWorkMode, AggregateResource,
    AggregateStrategy, CAPTURE_COUNT_ACCOUNTING_VERSION, CAPTURE_COUNT_ALGORITHM_VERSION,
    CaptureAggregateLimits, CaptureBuildLimits, CaptureBuilder, CaptureCountActual,
    CaptureCountBranch, CaptureCountDeclaredFallback, CaptureCountPrepublicationFallback,
    CaptureCountProspective, CaptureCountTerminal, CaptureExecutionSource, CapturePlanKind,
    CaptureResource, CaptureRunLimits, CaptureSearchError, PrefixClassUniformParticipationActual,
    PrefixClassUniformParticipationLimits,
};

const DENSE_PATTERN: &str = r"fn is_(\w+)|fn as_(\w+)";
const DENSE_HAYSTACK: &[u8] = b"fn is_even fn as_byte";

const fn exact_selector_limits(
    prospective: &AggregateOperationProspective,
) -> AggregateOperationLimits {
    AggregateOperationLimits {
        max_boundaries: prospective.boundaries,
        max_table_cells: prospective.table_cells,
        max_random_access_bytes: prospective.random_access_bytes,
        max_scratch_bytes: prospective.scratch_bytes,
        max_log_bytes: prospective.log_bytes,
        max_sequential_bytes: prospective.sequential_bytes,
        max_match_events: prospective.match_events,
        max_output_matches: prospective.output_matches,
        max_output_bytes: prospective.output_bytes,
        max_span_sum: prospective.span_sum,
        max_peak_bytes: prospective.peak_bytes,
        max_work: prospective.work_bound,
    }
}

const fn exact_direct_limits(
    prospective: fre::PrefixClassUniformParticipationProspective,
) -> PrefixClassUniformParticipationLimits {
    PrefixClassUniformParticipationLimits {
        max_work: prospective.work,
        max_first_finder_bytes: prospective.first_finder_bytes,
        max_second_finder_bytes: prospective.second_finder_bytes,
        max_prefix_candidates: prospective.prefix_candidates,
        max_start_arbitrations: prospective.start_arbitrations,
        max_first_class_probes: prospective.first_class_probes,
        max_greedy_extension_reads: prospective.greedy_extension_reads,
        max_results: prospective.results,
        max_capture_count: prospective.capture_count,
        max_capture_events: prospective.capture_events,
        max_operation_allocations: prospective.operation_allocations,
        max_operation_bytes: prospective.operation_bytes,
        max_scratch_bytes: prospective.scratch_bytes,
        max_peak_bytes: prospective.peak_bytes,
    }
}

fn selector_builder() -> fre::CaptureBuilder {
    CaptureBuilder::new(DENSE_PATTERN)
        .unicode(false)
        .limits(CaptureBuildLimits {
            max_prefix_class_participation_planner_work: 0,
            ..CaptureBuildLimits::default()
        })
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one identity audit intentionally names every nested U0-A selector field and construction-provenance invariant"
)]
fn selector_owner_is_immutable_and_binds_the_complete_u0a_identity() {
    assert_eq!(AGGREGATE_CONTINUATION_ACCOUNTING_VERSION, 4);
    assert_eq!(CAPTURE_COUNT_ALGORITHM_VERSION, 3);
    let regex = selector_builder().build().expect("selector Count build");
    let cloned = regex.clone();
    let limits = CaptureRunLimits::default();
    let eager = regex
        .cache_identity(limits)
        .count_seal
        .expect("eager selector owner seal");
    let first = regex
        .count_captures(DENSE_HAYSTACK, limits)
        .expect("first selector Count");
    let steady = regex
        .count_captures(DENSE_HAYSTACK, limits)
        .expect("steady selector Count");
    let cloned_steady = cloned
        .count_captures(DENSE_HAYSTACK, limits)
        .expect("cloned selector Count");

    for report in [&first, &steady, &cloned_steady] {
        assert!(report.has_closed_count_attempt());
        assert_eq!(
            report
                .count_receipt
                .as_ref()
                .expect("outer receipt")
                .terminal,
            CaptureCountTerminal::Success
        );
    }
    let seal = first
        .identity
        .count_seal
        .as_ref()
        .expect("selector owner seal");
    assert_eq!(seal, &eager);
    assert_eq!(steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(cloned_steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(first.count_receipt, steady.count_receipt);
    assert_eq!(first.count_receipt, cloned_steady.count_receipt);

    let route = seal.route_identity();
    assert_eq!(route.plan, regex.build_report().plan_identity);
    assert_eq!(route.build_limits, first.identity.build_limits);
    assert_eq!(
        route.build_limits,
        CaptureBuildLimits {
            max_prefix_class_participation_planner_work: 0,
            ..CaptureBuildLimits::default()
        }
    );
    assert_eq!(
        route.plan.plan,
        CapturePlanKind::LinearSelectorUniformParticipation
    );
    assert_eq!(
        route.branch,
        CaptureCountBranch::SelectorUniformParticipation
    );
    assert_eq!(
        route.selector_route.physical_route,
        AggregateOperationPhysicalRoute::DenseRows
    );
    assert_eq!(
        route.selector_route.algorithm_version,
        AGGREGATE_CONTINUATION_ALGORITHM_VERSION
    );
    assert_eq!(
        route.selector_route.accounting_version,
        AGGREGATE_CONTINUATION_ACCOUNTING_VERSION
    );
    assert_eq!(
        route.selector_route.prepublication_fallback,
        AggregateOperationPrepublicationFallback::None
    );
    assert_eq!(
        route.selector_strategy,
        AggregateStrategy::ReverseSequentialRows
    );
    assert_eq!(
        route.selector_operation,
        AggregateOperationAttemptKind::Count
    );
    assert_eq!(
        route.selector_work_mode,
        AggregateOperationWorkMode::Observed
    );
    assert_eq!(route.minimum_match_bytes, 7);
    assert_eq!(route.participating_captures_per_match, 2);
    assert_eq!(route.capture_schema_entries_per_match, 3);
    assert_eq!(route.retained_fallback_bytes, 0);
    assert_eq!(route.algorithm_version, CAPTURE_COUNT_ALGORITHM_VERSION);
    assert_eq!(route.accounting_version, CAPTURE_COUNT_ACCOUNTING_VERSION);
    assert_eq!(
        route.declared_prepublication_fallback,
        CaptureCountPrepublicationFallback::None
    );
    assert_eq!(route.declared_fallback, CaptureCountDeclaredFallback::None);

    let selector = first
        .selector_receipt
        .as_ref()
        .expect("nested selector receipt");
    assert_eq!(
        selector.identity.physical_route,
        Some(AggregateOperationPhysicalRoute::DenseRows)
    );
    assert_eq!(
        selector.identity.algorithm_version,
        AGGREGATE_CONTINUATION_ALGORITHM_VERSION
    );
    assert_eq!(
        selector.identity.accounting_version,
        AGGREGATE_CONTINUATION_ACCOUNTING_VERSION
    );
    assert_eq!(
        selector.identity.prepublication_fallback,
        AggregateOperationPrepublicationFallback::None
    );
    let mut effective_selector_limits = limits.selector;
    effective_selector_limits.max_peak_bytes = effective_selector_limits
        .max_peak_bytes
        .min(limits.max_combined_peak_bytes);
    assert!(
        selector
            .identity
            .authenticates_limits(effective_selector_limits)
    );

    let separate = selector_builder()
        .build()
        .expect("separate selector build")
        .count_captures(DENSE_HAYSTACK, limits)
        .expect("separate selector Count");
    assert_ne!(separate.identity.count_seal, first.identity.count_seal);
    let mut spliced = first.clone();
    spliced.identity.count_seal = separate.identity.count_seal;
    assert!(!spliced.has_closed_count_attempt());
}

#[test]
fn terminal_frontier_is_bound_before_source_and_declares_no_fallback() {
    let pattern = r"cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)[\\/]";
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("terminal-frontier build");
    let report = regex
        .count_captures(
            b"cargo/registry/src/hash/name-1.2.3/",
            CaptureRunLimits::default(),
        )
        .expect("terminal-frontier Count");
    assert!(report.has_closed_count_attempt());
    let seal = report
        .identity
        .count_seal
        .as_ref()
        .expect("terminal-frontier seal");
    assert_eq!(
        seal.route_identity().selector_route.physical_route,
        AggregateOperationPhysicalRoute::TerminalFrontierRows
    );
    assert_eq!(
        seal.route_identity().declared_prepublication_fallback,
        CaptureCountPrepublicationFallback::None
    );
    assert_eq!(
        seal.route_identity().declared_fallback,
        CaptureCountDeclaredFallback::None
    );
    let receipt = report.count_receipt.as_ref().expect("outer receipt");
    assert!(
        receipt
            .prospective
            .expect("outer prospective")
            .selector
            .terminal_frontier
    );
    assert!(receipt.closes(seal));
}

#[test]
fn direct_owner_is_distinct_and_retains_u3_prepublication_fallback() {
    let regex = CaptureBuilder::new(DENSE_PATTERN)
        .unicode(false)
        .build()
        .expect("direct Count build");
    let cloned = regex.clone();
    let eager = regex
        .cache_identity(CaptureRunLimits::default())
        .count_seal
        .expect("eager direct owner seal");
    let first = regex
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("first direct Count");
    let steady = regex
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("steady direct Count");
    let cloned_steady = cloned
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("cloned direct Count");

    for report in [&first, &steady, &cloned_steady] {
        assert!(report.has_closed_count_attempt());
        assert!(report.selector_receipt.is_none());
        assert!(report.prefix_class_participation_receipt.is_some());
        let receipt = report.count_receipt.as_ref().expect("direct owner receipt");
        assert!(receipt.selector.is_none());
        assert_eq!(
            receipt.direct.as_ref(),
            report.prefix_class_participation_receipt.as_ref()
        );
        let prospective = receipt.prospective.expect("direct owner P");
        assert!(prospective.direct.is_some());
        assert!(!prospective.selector.terminal_frontier);
    }
    let seal = first
        .identity
        .count_seal
        .as_ref()
        .expect("direct owner seal");
    assert_eq!(seal, &eager);
    assert_eq!(steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(cloned_steady.identity.count_seal.as_ref(), Some(seal));
    let route = seal.route_identity();
    assert_eq!(route.build_limits, first.identity.build_limits);
    assert_eq!(
        route.plan.plan,
        CapturePlanKind::UniformPrefixClassParticipation
    );
    assert_eq!(
        route.branch,
        CaptureCountBranch::DirectPrefixClassParticipation
    );
    assert_eq!(
        route.selector_route.physical_route,
        AggregateOperationPhysicalRoute::DenseRows
    );
    assert_eq!(
        route.declared_prepublication_fallback,
        CaptureCountPrepublicationFallback::SelectorUniformParticipation
    );
    assert_eq!(route.declared_fallback, CaptureCountDeclaredFallback::None);
    assert!(route.retained_fallback_bytes > 0);
    let direct = route
        .plan
        .prefix_class_participation
        .expect("direct route identity");
    assert_eq!(
        direct.declared_prepublication_fallback,
        CapturePlanKind::LinearSelectorUniformParticipation
    );
    assert_eq!(
        direct.kernel.algorithm_version,
        fre::PREFIX_CLASS_UNIFORM_PARTICIPATION_ALGORITHM_VERSION
    );
    assert_eq!(
        direct.kernel.accounting_version,
        fre::PREFIX_CLASS_UNIFORM_PARTICIPATION_ACCOUNTING_VERSION
    );

    let separate = CaptureBuilder::new(DENSE_PATTERN)
        .unicode(false)
        .build()
        .expect("separate direct build")
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("separate direct Count");
    assert_ne!(separate.identity.count_seal, first.identity.count_seal);
    let mut spliced = first.clone();
    spliced.identity.count_seal = separate.identity.count_seal;
    assert!(!spliced.has_closed_count_attempt());
}

fn assert_report_cache_identity_mutations_are_rejected(report: &fre::CaptureExecutionReport) {
    let mut tampered = report.clone();
    tampered.identity.plan.plan = CapturePlanKind::LinearSelectorPersistentHistory;
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    tampered.identity.build_limits.max_hir_work =
        tampered.identity.build_limits.max_hir_work.wrapping_add(1);
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    tampered.identity.run_limits.max_combined_peak_bytes = tampered
        .identity
        .run_limits
        .max_combined_peak_bytes
        .wrapping_add(1);
    assert!(!tampered.has_closed_count_attempt());
}

fn assert_error_cache_identity_mutations_are_rejected(error: &mut fre::CaptureExecutionError) {
    assert!(error.has_closed_count_attempt());

    let original_plan = error.identity.plan.clone();
    error.identity.plan.plan = CapturePlanKind::LinearSelectorPersistentHistory;
    assert!(!error.has_closed_count_attempt());
    error.identity.plan = original_plan;
    assert!(error.has_closed_count_attempt());

    let original_build_limits = error.identity.build_limits;
    error.identity.build_limits.max_hir_work =
        error.identity.build_limits.max_hir_work.wrapping_add(1);
    assert!(!error.has_closed_count_attempt());
    error.identity.build_limits = original_build_limits;
    assert!(error.has_closed_count_attempt());

    let original_run_limits = error.identity.run_limits;
    error.identity.run_limits.max_combined_peak_bytes = error
        .identity
        .run_limits
        .max_combined_peak_bytes
        .wrapping_add(1);
    assert!(!error.has_closed_count_attempt());
    error.identity.run_limits = original_run_limits;
    assert!(error.has_closed_count_attempt());

    let published = error
        .count_receipt
        .as_ref()
        .expect("sealed failure receipt")
        .prospective;
    assert!(published.is_some());
    error
        .count_receipt
        .as_mut()
        .expect("sealed failure receipt")
        .prospective = None;
    assert!(!error.has_closed_count_attempt());
    error
        .count_receipt
        .as_mut()
        .expect("sealed failure receipt")
        .prospective = published;
    assert!(error.has_closed_count_attempt());
}

fn assert_selector_certificate_mutations_are_rejected(report: &fre::CaptureExecutionReport) {
    let mut tampered = report.clone();
    let certificate = tampered
        .selector_certificate
        .as_mut()
        .expect("selector certificate");
    let published_range = certificate.range.clone();
    certificate.range = published_range.end..published_range.start;
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    let certificate = tampered
        .selector_certificate
        .as_mut()
        .expect("selector certificate");
    certificate.work_bound = certificate.work_bound.wrapping_add(1);
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    let certificate = tampered
        .selector_certificate
        .as_mut()
        .expect("selector certificate");
    certificate.table_cells = certificate.table_cells.wrapping_add(1);
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    tampered
        .selector_certificate
        .as_mut()
        .expect("selector certificate")
        .prospective_allocations ^= 1;
    assert!(!tampered.has_closed_count_attempt());

    let mut tampered = report.clone();
    tampered
        .selector_certificate
        .as_mut()
        .expect("selector certificate")
        .actual_allocations ^= 1;
    assert!(!tampered.has_closed_count_attempt());
}

#[test]
fn public_identity_certificate_provenance_and_publication_mutations_fail_closed() {
    let selector = selector_builder().build().expect("selector Count build");
    let selector_report = selector
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("selector Count");
    assert_report_cache_identity_mutations_are_rejected(&selector_report);
    assert_selector_certificate_mutations_are_rejected(&selector_report);
    let selector_actual_work = selector_report
        .selector_receipt
        .as_ref()
        .expect("selector receipt")
        .actual
        .work;
    assert!(selector_actual_work > 0);
    let mut selector_one_below = CaptureRunLimits::default();
    selector_one_below.selector.max_work = selector_actual_work - 1;
    let mut selector_error = selector
        .count_captures(DENSE_HAYSTACK, selector_one_below)
        .expect_err("selector one-below");
    assert_error_cache_identity_mutations_are_rejected(&mut selector_error);
    let original_source = selector_error.source.clone();
    selector_error.source = CaptureExecutionSource::CombinedPeak {
        needed: 1,
        limit: 0,
    };
    assert!(!selector_error.has_closed_count_attempt());
    selector_error.source = original_source;
    assert!(selector_error.has_closed_count_attempt());

    let direct = CaptureBuilder::new(DENSE_PATTERN)
        .unicode(false)
        .build()
        .expect("direct Count build");
    let direct_report = direct
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("direct Count");
    assert_report_cache_identity_mutations_are_rejected(&direct_report);
    let mut relabeled_success = direct_report
        .count_receipt
        .clone()
        .expect("direct success receipt");
    relabeled_success.terminal = CaptureCountTerminal::Failure;
    let forged_failure = fre::CaptureExecutionError {
        identity: direct_report.identity.clone(),
        source: CaptureExecutionSource::CombinedPeak {
            needed: direct_report.combined_peak_bytes,
            limit: direct_report.combined_peak_bytes - 1,
        },
        selector_receipt: None,
        prefix_class_participation_receipt: direct_report.prefix_class_participation_receipt,
        count_receipt: Some(relabeled_success),
    };
    assert!(!forged_failure.has_closed_count_attempt());
    let direct_prospective = direct_report
        .count_receipt
        .as_ref()
        .and_then(|receipt| receipt.prospective)
        .and_then(|prospective| prospective.direct)
        .expect("direct P");
    let mut direct_one_below = CaptureRunLimits::default();
    direct_one_below.prefix_class_participation.max_work = direct_prospective.work - 1;
    let mut direct_error = direct
        .count_captures(DENSE_HAYSTACK, direct_one_below)
        .expect_err("direct one-below");
    assert_error_cache_identity_mutations_are_rejected(&mut direct_error);

    let direct_receipt = direct_error
        .prefix_class_participation_receipt
        .as_mut()
        .expect("direct failure receipt");
    let prospective = direct_receipt.prospective.expect("direct failure P");
    assert!(prospective.first_finder_bytes > 0);
    assert!(prospective.work > 0);
    let mut partial_actual = direct_receipt.actual;
    partial_actual.first_finder_bytes = 1;
    partial_actual.work = 1;
    direct_receipt.actual = partial_actual;
    let outer = direct_error
        .count_receipt
        .as_mut()
        .expect("direct outer failure receipt");
    outer
        .direct
        .as_mut()
        .expect("nested direct failure receipt")
        .actual = partial_actual;
    outer.actual.direct = Some(partial_actual);
    assert!(direct_error.has_closed_count_attempt());
    direct_error.source = CaptureExecutionSource::CombinedPeak {
        needed: direct_report.combined_peak_bytes,
        limit: direct_report.combined_peak_bytes - 1,
    };
    assert!(!direct_error.has_closed_count_attempt());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the selector owner gate names every positive public prospective dimension"
)]
fn selector_exact_limits_accept_and_one_below_refuses_with_zero_actual() {
    let regex = selector_builder().build().expect("selector Count build");
    let baseline = regex
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("baseline selector Count");
    let prospective = baseline
        .count_receipt
        .as_ref()
        .and_then(|receipt| receipt.prospective)
        .expect("whole selector P");
    assert!(prospective.direct.is_none());
    let exact_limits = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_results: prospective.matches,
            max_capture_count: prospective.capture_count,
            max_capture_events: prospective.capture_events,
            ..CaptureAggregateLimits::default()
        },
        selector: exact_selector_limits(&prospective.selector),
        max_combined_peak_bytes: prospective.combined_peak_bytes,
        prefix_class_participation: PrefixClassUniformParticipationLimits::default(),
    };
    let exact = regex
        .count_captures(DENSE_HAYSTACK, exact_limits)
        .expect("exact selector owner limits");
    assert!(exact.has_closed_count_attempt());
    assert_eq!(
        exact
            .identity
            .count_seal
            .as_ref()
            .expect("exact seal")
            .run_limits(),
        exact_limits
    );

    macro_rules! assert_owner_one_below {
        ($field:ident, $required:expr, $resource:expr) => {{
            let required = $required;
            if required > 0 {
                let mut one_below = exact_limits;
                one_below.aggregate.$field = required - 1;
                let error = regex
                    .count_captures(DENSE_HAYSTACK, one_below)
                    .expect_err("owner one-below must refuse");
                assert_eq!(
                    error.source,
                    CaptureExecutionSource::History(CaptureSearchError::Resource {
                        kind: $resource,
                        required,
                        limit: required - 1,
                    })
                );
                assert_selector_zero_effect_refusal(&error, &prospective);
            }
        }};
    }
    assert_owner_one_below!(max_results, prospective.matches, CaptureResource::Results);
    assert_owner_one_below!(
        max_capture_count,
        prospective.capture_count,
        CaptureResource::CaptureCount
    );
    assert_owner_one_below!(
        max_capture_events,
        prospective.capture_events,
        CaptureResource::CaptureEvents
    );

    macro_rules! assert_selector_one_below {
        ($limit:ident, $field:ident, $resource:expr) => {{
            let required = prospective.selector.$field;
            if required > 0 {
                let mut one_below = exact_limits;
                one_below.selector.$limit = required - 1;
                let error = regex
                    .count_captures(DENSE_HAYSTACK, one_below)
                    .expect_err("selector one-below must refuse");
                assert!(matches!(
                    error.source,
                    CaptureExecutionSource::Selector(
                        fre::AggregateEngineError::ResourceLimit {
                            resource,
                            required: observed,
                            limit,
                        }
                    ) if resource == $resource && observed == required && limit == required - 1
                ));
                assert_selector_zero_effect_refusal(&error, &prospective);
            }
        }};
    }
    assert_selector_one_below!(max_boundaries, boundaries, AggregateResource::Boundaries);
    assert_selector_one_below!(max_table_cells, table_cells, AggregateResource::TableCells);
    assert_selector_one_below!(
        max_random_access_bytes,
        random_access_bytes,
        AggregateResource::RandomAccessBytes
    );
    assert_selector_one_below!(
        max_scratch_bytes,
        scratch_bytes,
        AggregateResource::ScratchBytes
    );
    assert_selector_one_below!(max_log_bytes, log_bytes, AggregateResource::LogBytes);
    assert_selector_one_below!(
        max_sequential_bytes,
        sequential_bytes,
        AggregateResource::SequentialBytes
    );
    assert_selector_one_below!(
        max_match_events,
        match_events,
        AggregateResource::MatchEvents
    );
    assert_selector_one_below!(
        max_output_matches,
        output_matches,
        AggregateResource::OutputMatches
    );
    assert_selector_one_below!(
        max_output_bytes,
        output_bytes,
        AggregateResource::OutputBytes
    );
    assert_selector_one_below!(max_span_sum, span_sum, AggregateResource::SpanSum);
    assert_selector_one_below!(max_peak_bytes, peak_bytes, AggregateResource::PeakBytes);

    // Selector Count observes work. Falling below the conservative bound can
    // still succeed, but one below the successful actual must fail closed
    // with the bounded partial receipt accumulated before refusal.
    let actual_work = exact
        .selector_receipt
        .as_ref()
        .expect("exact selector receipt")
        .actual
        .work;
    assert!(actual_work > 0);
    let mut one_below_work = exact_limits;
    one_below_work.selector.max_work = actual_work - 1;
    let error = regex
        .count_captures(DENSE_HAYSTACK, one_below_work)
        .expect_err("observed selector work one below actual must refuse");
    assert!(error.has_closed_count_attempt());
    assert!(matches!(
        error.source,
        CaptureExecutionSource::Selector(fre::AggregateEngineError::ResourceLimit {
            resource: AggregateResource::ExecutionWork,
            required,
            limit,
        }) if required > limit && limit == actual_work - 1
    ));
    let selector_receipt = error
        .selector_receipt
        .as_ref()
        .expect("bounded partial selector receipt");
    let observed_prospective = selector_receipt
        .prospective
        .expect("observed-work prospective");
    assert_eq!(observed_prospective.work_bound, actual_work - 1);
    assert!(selector_receipt.actual.work < actual_work);
    assert!(selector_receipt.actual_allocations <= observed_prospective.allocations);

    if prospective.combined_peak_bytes > 0 {
        let mut one_below = exact_limits;
        one_below.max_combined_peak_bytes = prospective.combined_peak_bytes - 1;
        let error = regex
            .count_captures(DENSE_HAYSTACK, one_below)
            .expect_err("combined-peak one-below must refuse");
        assert!(matches!(
            error.source,
            CaptureExecutionSource::Selector(
                fre::AggregateEngineError::ResourceLimit {
                    resource: AggregateResource::PeakBytes,
                    required,
                    limit,
                }
            ) if required == prospective.combined_peak_bytes
                && limit == prospective.combined_peak_bytes - 1
        ));
        assert_selector_zero_effect_refusal(&error, &prospective);
    }
}

fn assert_selector_zero_effect_refusal(
    error: &fre::CaptureExecutionError,
    prospective: &CaptureCountProspective,
) {
    assert!(error.has_closed_count_attempt());
    assert!(error.prefix_class_participation_receipt.is_none());
    let selector = error.selector_receipt.as_ref().expect("selector receipt");
    assert_eq!(selector.actual, AggregateExecutionAccounting::default());
    assert_eq!(selector.actual_allocations, 0);
    let receipt = error.count_receipt.as_ref().expect("outer receipt");
    assert_eq!(receipt.terminal, CaptureCountTerminal::Failure);
    assert_eq!(receipt.prospective.as_ref(), Some(prospective));
    assert_eq!(receipt.actual, CaptureCountActual::default());
    assert!(
        receipt.closes(
            error
                .identity
                .count_seal
                .as_ref()
                .expect("failure owner seal")
        )
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one direct audit keeps exact admission and each U4/U3/owner one-below terminal beside the same published P"
)]
fn direct_exact_and_one_below_paths_retain_closed_owner_receipts() {
    let regex = CaptureBuilder::new(DENSE_PATTERN)
        .unicode(false)
        .build()
        .expect("direct Count build");
    let baseline = regex
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("baseline direct Count");
    let prospective = baseline
        .count_receipt
        .as_ref()
        .and_then(|receipt| receipt.prospective)
        .expect("whole direct P");
    let direct = prospective.direct.expect("nested direct P");
    let exact_limits = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_results: prospective.matches,
            max_capture_count: prospective.capture_count,
            max_capture_events: prospective.capture_events,
            ..CaptureAggregateLimits::default()
        },
        selector: exact_selector_limits(&prospective.selector),
        max_combined_peak_bytes: prospective.combined_peak_bytes,
        prefix_class_participation: exact_direct_limits(direct),
    };
    let exact = regex
        .count_captures(DENSE_HAYSTACK, exact_limits)
        .expect("exact direct owner limits");
    assert!(exact.has_closed_count_attempt());
    assert_eq!(
        exact
            .count_receipt
            .as_ref()
            .and_then(|receipt| receipt.prospective),
        Some(prospective)
    );

    let mut direct_one_below = exact_limits;
    direct_one_below.prefix_class_participation.max_work = direct.work - 1;
    let direct_error = regex
        .count_captures(DENSE_HAYSTACK, direct_one_below)
        .expect_err("direct one-below");
    assert!(matches!(
        direct_error.source,
        CaptureExecutionSource::PrefixClassParticipation(
            fre::PrefixClassUniformParticipationError::WorkLimit { .. }
        )
    ));
    assert_direct_zero_effect_refusal(&direct_error, &prospective);

    let mut aggregate_one_below = exact_limits;
    aggregate_one_below.aggregate.max_capture_count = prospective.capture_count - 1;
    let aggregate_error = regex
        .count_captures(DENSE_HAYSTACK, aggregate_one_below)
        .expect_err("aggregate one-below");
    assert!(matches!(
        aggregate_error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::CaptureCount,
            ..
        })
    ));
    assert_direct_zero_effect_refusal(&aggregate_error, &prospective);

    let mut control_one_below = exact_limits;
    control_one_below.selector.max_work = prospective.selector.work_bound - 1;
    let control = regex
        .count_captures(DENSE_HAYSTACK, control_one_below)
        .expect("inactive U3 control work does not block selected U4");
    assert!(control.has_closed_count_attempt());
    assert_eq!(control.accounting, exact.accounting);
    assert_eq!(control.capture_events, exact.capture_events);
    assert!(control.selector_receipt.is_none());

    let mut combined_one_below = exact_limits;
    combined_one_below.max_combined_peak_bytes = prospective.combined_peak_bytes - 1;
    let combined_error = regex
        .count_captures(DENSE_HAYSTACK, combined_one_below)
        .expect_err("combined one-below");
    assert_eq!(
        combined_error.source,
        CaptureExecutionSource::CombinedPeak {
            needed: prospective.combined_peak_bytes,
            limit: prospective.combined_peak_bytes - 1,
        }
    );
    assert_direct_zero_effect_refusal(&combined_error, &prospective);

    let fallback = selector_builder()
        .build()
        .expect("direct construction refusal retains U3")
        .count_captures(DENSE_HAYSTACK, CaptureRunLimits::default())
        .expect("fallback selector Count");
    assert_eq!(
        fallback.identity.plan.plan,
        CapturePlanKind::LinearSelectorUniformParticipation
    );
    assert_eq!(
        fallback
            .identity
            .count_seal
            .as_ref()
            .expect("fallback owner")
            .route_identity()
            .branch,
        CaptureCountBranch::SelectorUniformParticipation
    );
    assert!(fallback.has_closed_count_attempt());
}

fn assert_direct_zero_effect_refusal(
    error: &fre::CaptureExecutionError,
    prospective: &CaptureCountProspective,
) {
    assert!(error.has_closed_count_attempt());
    assert!(error.selector_receipt.is_none());
    let direct = error
        .prefix_class_participation_receipt
        .as_ref()
        .expect("direct receipt");
    assert_eq!(
        direct.actual,
        PrefixClassUniformParticipationActual::default()
    );
    assert_eq!(direct.actual_allocations, 0);
    let receipt = error.count_receipt.as_ref().expect("outer receipt");
    assert_eq!(receipt.terminal, CaptureCountTerminal::Failure);
    assert_eq!(receipt.prospective.as_ref(), Some(prospective));
    assert_eq!(
        receipt.actual.direct,
        Some(PrefixClassUniformParticipationActual::default())
    );
    assert_eq!(
        receipt.actual.combined_peak_bytes,
        error
            .identity
            .count_seal
            .as_ref()
            .expect("direct failure seal")
            .route_identity()
            .retained_fallback_bytes
    );
}

#[test]
fn nullable_and_history_count_routes_remain_outside_the_owner_seal() {
    let history = CaptureBuilder::new(r"(a)(b)?")
        .unicode(false)
        .build()
        .expect("history build");
    assert_eq!(
        history.build_report().plan_identity.plan,
        CapturePlanKind::LinearSelectorPersistentHistory
    );
    let history_report = history
        .count_captures(b"ab a", CaptureRunLimits::default())
        .expect("history Count");
    assert!(history_report.identity.count_seal.is_none());
    assert!(history_report.count_receipt.is_none());
    assert!(!history_report.has_closed_count_attempt());

    let nullable = CaptureBuilder::new(r"(a*)")
        .unicode(false)
        .build()
        .expect("nullable uniform build");
    let error = nullable
        .count_captures(b"ba", CaptureRunLimits::default())
        .expect_err("nonempty reducer refusal");
    assert!(error.identity.count_seal.is_none());
    assert!(error.count_receipt.is_none());
    assert!(!error.has_closed_count_attempt());
}

#[test]
fn retained_suffix_and_candidate_capture_routes_close_exact_and_one_below_work() {
    let cases = [
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/",
            b"xcargo/registry/src/hash/name-1.2.3/ nope cargo/registry/src/x/bad/".as_slice(),
            AggregateOperationPhysicalRoute::Candidate,
            3,
        ),
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/|cargo\\registry\\src\\[^\\]+\\([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\",
            b"cargo\\registry\\src\\hash\\win-2.0.1\\ cargo/registry/src/hash/unix-1.2.3/ \xFF",
            AggregateOperationPhysicalRoute::Candidate,
            6,
        ),
    ];
    for (pattern, haystack, route, expected) in cases {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("bounded uniform capture build");
        let baseline = regex
            .count_captures(haystack, CaptureRunLimits::default())
            .expect("bounded uniform capture baseline");
        assert!(baseline.has_closed_count_attempt());
        assert_eq!(baseline.accounting.count, expected);
        let seal = baseline
            .identity
            .count_seal
            .as_ref()
            .expect("positive-width capture owner");
        assert_eq!(seal.route_identity().selector_route.physical_route, route);
        let prospective = baseline
            .count_receipt
            .as_ref()
            .and_then(|receipt| receipt.prospective)
            .expect("whole-operation capture prospective");
        let actual_work = baseline
            .selector_receipt
            .as_ref()
            .expect("nested selector receipt")
            .actual
            .work;
        assert!(actual_work > 0);

        let mut selector = exact_selector_limits(&prospective.selector);
        selector.max_work = actual_work;
        let exact_limits = CaptureRunLimits {
            aggregate: CaptureAggregateLimits {
                max_results: prospective.matches,
                max_capture_count: prospective.capture_count,
                max_capture_events: prospective.capture_events,
                ..CaptureAggregateLimits::default()
            },
            selector,
            max_combined_peak_bytes: prospective.combined_peak_bytes,
            prefix_class_participation: PrefixClassUniformParticipationLimits::default(),
        };
        let exact = regex
            .count_captures(haystack, exact_limits)
            .expect("exact observed work admits");
        assert!(exact.has_closed_count_attempt());
        assert_eq!(exact.accounting, baseline.accounting);
        assert_eq!(
            exact
                .selector_receipt
                .as_ref()
                .expect("exact nested receipt")
                .identity
                .physical_route,
            Some(route)
        );

        let mut one_below = exact_limits;
        one_below.selector.max_work = actual_work - 1;
        let failure = regex
            .count_captures(haystack, one_below)
            .expect_err("one-below observed work refuses");
        assert!(failure.has_closed_count_attempt());
        assert!(matches!(
            failure.source,
            CaptureExecutionSource::Selector(
                fre::AggregateEngineError::ResourceLimit {
                    resource: AggregateResource::ExecutionWork,
                    required,
                    limit,
                }
            ) if required == actual_work && limit == actual_work - 1
        ));
        let nested = failure
            .selector_receipt
            .as_ref()
            .expect("bounded partial selector receipt");
        assert_eq!(nested.identity.physical_route, Some(route));
        assert_eq!(
            nested
                .prospective
                .expect("published one-below prospective")
                .work_bound,
            actual_work - 1
        );
        assert!(nested.actual.work < actual_work);
    }
}
