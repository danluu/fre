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
    let regex = selector_builder().build().expect("selector Count build");
    let cloned = regex.clone();
    let limits = CaptureRunLimits::default();
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
    assert_eq!(steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(cloned_steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(first.count_receipt, steady.count_receipt);
    assert_eq!(first.count_receipt, cloned_steady.count_receipt);

    let route = seal.route_identity();
    assert_eq!(route.plan, regex.build_report().plan_identity);
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
        AggregateOperationWorkMode::ConservativeAdmission
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
    assert_eq!(steady.identity.count_seal.as_ref(), Some(seal));
    assert_eq!(cloned_steady.identity.count_seal.as_ref(), Some(seal));
    let route = seal.route_identity();
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
    assert_selector_one_below!(max_work, work_bound, AggregateResource::ExecutionWork);

    if prospective.combined_peak_bytes > 0 {
        let mut one_below = exact_limits;
        one_below.max_combined_peak_bytes = prospective.combined_peak_bytes - 1;
        let error = regex
            .count_captures(DENSE_HAYSTACK, one_below)
            .expect_err("combined-peak one-below must refuse");
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
    let control_error = regex
        .count_captures(DENSE_HAYSTACK, control_one_below)
        .expect_err("U3 control one-below");
    assert!(matches!(
        control_error.source,
        CaptureExecutionSource::Selector(fre::AggregateEngineError::ResourceLimit {
            resource: AggregateResource::ExecutionWork,
            ..
        })
    ));
    assert_direct_zero_effect_refusal(&control_error, &prospective);

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
