use core::mem::size_of;

use fre::{
    CAPTURE_ITERATION_ACCOUNTING_VERSION, CAPTURE_ITERATION_ALGORITHM_VERSION,
    CaptureAggregateLimits, CaptureBuilder, CaptureGroupRecord, CaptureIterationActual,
    CaptureIterationBackend, CaptureIterationDeclaredFallback, CaptureIterationOperation,
    CaptureIterationPlanKind, CaptureIterationTerminal, CaptureRecord, CaptureResource,
    CaptureSearchLimits, CaptureWindow,
};

fn exact_limits(report: &fre::CaptureIterationReport) -> CaptureAggregateLimits {
    let prospective = report
        .session_receipt
        .prospective
        .expect("session prospective")
        .engine;
    CaptureAggregateLimits {
        per_search: CaptureSearchLimits {
            max_state_visits: prospective.largest_search.state_visits,
            max_slot_copies: 0,
            max_history_nodes: prospective.largest_search.history_nodes,
            max_history_walk: prospective.largest_search.history_walk,
            max_scratch_bytes: prospective.largest_search.scratch_bytes,
        },
        max_searches: prospective.searches,
        max_results: prospective.results,
        max_total_state_visits: prospective.total_state_visits,
        max_total_slot_copies: prospective.total_slot_copies,
        max_total_history_nodes: prospective.total_history_nodes,
        max_total_history_walk: prospective.total_history_walk,
        max_capture_events: prospective.capture_events,
        // Capture Count is a different operation and cannot constrain or
        // identify this capture-valued session.
        max_capture_count: 0,
        max_retained_output_bytes: prospective.retained_output_bytes,
        max_combined_peak_bytes: prospective.combined_peak_bytes,
    }
}

#[test]
fn capture_array_owner_is_distinct_immutable_and_closed() {
    assert_eq!(CAPTURE_ITERATION_ALGORITHM_VERSION, 2);
    assert_eq!(CAPTURE_ITERATION_ACCOUNTING_VERSION, 2);
    let regex = CaptureBuilder::new(r"(?P<left>a)|(b)")
        .unicode(false)
        .build()
        .expect("capture-array build");
    let clone = regex.clone();
    let limits = CaptureAggregateLimits::default();
    let first = regex
        .captures_iter(b"ab", limits)
        .expect("first capture array");
    let steady = regex
        .captures_iter(b"ab", limits)
        .expect("steady capture array");
    let cloned = clone
        .captures_iter(b"ab", limits)
        .expect("cloned capture array");

    for report in [&first, &steady, &cloned] {
        assert!(report.has_closed_session_attempt());
        assert_eq!(
            report.session_receipt.terminal,
            CaptureIterationTerminal::Success
        );
        assert!(
            report
                .session_receipt
                .prospective
                .expect("prospective")
                .contains(report.session_receipt.actual)
        );
        assert_eq!(
            report.identity.plan,
            CaptureIterationPlanKind::RestartedPersistentHistory
        );
    }
    assert_eq!(first.identity.session_seal, steady.identity.session_seal);
    assert_eq!(first.identity.session_seal, cloned.identity.session_seal);
    assert_eq!(first.session_receipt, steady.session_receipt);
    assert_eq!(first.session_receipt, cloned.session_receipt);

    let route = first.identity.session_seal.route_identity();
    assert_eq!(route.syntax, regex.build_report().plan_identity.syntax);
    assert_eq!(
        route.operation,
        CaptureIterationOperation::MaterializeCaptureArray
    );
    assert_eq!(
        route.plan,
        CaptureIterationPlanKind::RestartedPersistentHistory
    );
    assert_eq!(route.backend, CaptureIterationBackend::PersistentHistory);
    assert_eq!(route.engine_shape.groups, 3);
    assert_eq!(route.engine_shape.name_payload_bytes, "left".len());
    assert_eq!(route.minimum_match_bytes, 1);
    assert_eq!(route.algorithm_version, CAPTURE_ITERATION_ALGORITHM_VERSION);
    assert_eq!(
        route.accounting_version,
        CAPTURE_ITERATION_ACCOUNTING_VERSION
    );
    assert_eq!(
        route.declared_fallback,
        CaptureIterationDeclaredFallback::None
    );

    let separately_built = CaptureBuilder::new(r"(?P<left>a)|(b)")
        .unicode(false)
        .build()
        .expect("second construction");
    let separate = separately_built
        .captures_iter(b"ab", limits)
        .expect("separate capture array");
    assert_ne!(first.identity.session_seal, separate.identity.session_seal);
}

#[test]
fn named_output_logical_bytes_and_combined_peak_are_exact() {
    let regex = CaptureBuilder::new(r"(?P<left>a)|(b)")
        .unicode(false)
        .build()
        .expect("capture-array build");
    let report = regex
        .captures_iter(b"ab", CaptureAggregateLimits::default())
        .expect("capture array");
    let route = report.identity.session_seal.route_identity();
    let shape = route.engine_shape;
    let prospective = report
        .session_receipt
        .prospective
        .expect("session prospective")
        .engine;
    let actual = report.session_receipt.actual;
    let materialized_record_bytes = 3 * size_of::<CaptureGroupRecord>() + "left".len();
    let retained_record_bytes = size_of::<CaptureRecord>() + materialized_record_bytes;
    assert_eq!(
        shape.materialized_record_bytes(),
        Ok(materialized_record_bytes)
    );
    assert_eq!(shape.retained_record_bytes(), Ok(retained_record_bytes));
    assert_eq!(
        prospective.retained_output_bytes,
        prospective.results * retained_record_bytes
    );
    assert_eq!(
        prospective.combined_peak_bytes,
        prospective.retained_output_bytes + prospective.largest_search.scratch_bytes
    );
    assert_eq!(actual.results, 2);
    assert_eq!(actual.materialized_records, 2);
    assert_eq!(actual.retained_output_bytes, 2 * retained_record_bytes);

    let first_scratch = shape
        .search_prospective(CaptureWindow { start: 0, end: 2 }, 0)
        .expect("first search P")
        .scratch_bytes;
    let second_scratch = shape
        .search_prospective(CaptureWindow { start: 0, end: 2 }, 1)
        .expect("second search P")
        .scratch_bytes;
    let miss_scratch = shape
        .search_prospective(CaptureWindow { start: 0, end: 2 }, 2)
        .expect("miss search P")
        .scratch_bytes;
    let expected_peak = [
        first_scratch,
        materialized_record_bytes + first_scratch,
        retained_record_bytes,
        retained_record_bytes + second_scratch,
        retained_record_bytes + materialized_record_bytes + second_scratch,
        2 * retained_record_bytes,
        2 * retained_record_bytes + miss_scratch,
    ]
    .into_iter()
    .max()
    .expect("combined candidates");
    assert_eq!(actual.combined_peak_bytes, expected_peak);
    assert!(actual.combined_peak_bytes <= prospective.combined_peak_bytes);
    assert_eq!(report.retained_output_bytes, actual.retained_output_bytes);
    assert_eq!(report.combined_peak_bytes, actual.combined_peak_bytes);
    assert!(report.has_closed_session_attempt());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the owner gate names every positive public session dimension"
)]
fn exact_and_every_positive_one_below_are_pre_source_terminal_receipts() {
    let regex = CaptureBuilder::new(r"(?P<first>ab)|(?P<second>c)")
        .unicode(false)
        .build()
        .expect("capture-array build");
    let haystack = b"abcab";
    let baseline = regex
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .expect("baseline capture array");
    let prospective = baseline
        .session_receipt
        .prospective
        .expect("whole-session prospective");
    let exact = exact_limits(&baseline);
    let exact_report = regex
        .captures_iter(haystack, exact)
        .expect("exact session limits");
    assert!(exact_report.has_closed_session_attempt());
    assert_eq!(exact_report.session_receipt.prospective, Some(prospective));
    assert_eq!(exact_report.identity.session_seal.run_limits(), exact);
    assert_eq!(
        exact_report.session_receipt.terminal,
        CaptureIterationTerminal::Success
    );
    assert!(
        prospective.contains(exact_report.session_receipt.actual),
        "terminal success must retain exact A≤P"
    );

    macro_rules! assert_per_search_one_below {
        ($field:ident, $required:expr, $resource:expr) => {{
            let required = $required;
            if required > 0 {
                let mut below = exact;
                below.per_search.$field = required - 1;
                let error = regex
                    .captures_iter(haystack, below)
                    .expect_err("per-search one-below must refuse");
                assert_eq!(
                    error.source,
                    fre::CaptureSearchError::Resource {
                        kind: $resource,
                        required,
                        limit: required - 1,
                    }
                );
                assert_zero_effect_failure(&error, prospective);
            }
        }};
    }
    assert_per_search_one_below!(
        max_state_visits,
        prospective.engine.largest_search.state_visits,
        CaptureResource::StateVisits
    );
    assert_per_search_one_below!(
        max_history_nodes,
        prospective.engine.largest_search.history_nodes,
        CaptureResource::HistoryNodes
    );
    assert_per_search_one_below!(
        max_history_walk,
        prospective.engine.largest_search.history_walk,
        CaptureResource::HistoryWalk
    );
    assert_per_search_one_below!(
        max_scratch_bytes,
        prospective.engine.largest_search.scratch_bytes,
        CaptureResource::ScratchBytes
    );

    macro_rules! assert_session_one_below {
        ($field:ident, $required:expr, $resource:expr) => {{
            let required = $required;
            if required > 0 {
                let mut below = exact;
                below.$field = required - 1;
                let error = regex
                    .captures_iter(haystack, below)
                    .expect_err("session one-below must refuse");
                assert_eq!(
                    error.source,
                    fre::CaptureSearchError::Resource {
                        kind: $resource,
                        required,
                        limit: required - 1,
                    }
                );
                assert_zero_effect_failure(&error, prospective);
            }
        }};
    }
    assert_session_one_below!(
        max_searches,
        prospective.engine.searches,
        CaptureResource::Searches
    );
    assert_session_one_below!(
        max_results,
        prospective.engine.results,
        CaptureResource::Results
    );
    assert_session_one_below!(
        max_total_state_visits,
        prospective.engine.total_state_visits,
        CaptureResource::AggregateStateVisits
    );
    assert_session_one_below!(
        max_total_history_nodes,
        prospective.engine.total_history_nodes,
        CaptureResource::AggregateHistoryNodes
    );
    assert_session_one_below!(
        max_total_history_walk,
        prospective.engine.total_history_walk,
        CaptureResource::AggregateHistoryWalk
    );
    assert_session_one_below!(
        max_capture_events,
        prospective.engine.capture_events,
        CaptureResource::CaptureEvents
    );
    assert_session_one_below!(
        max_retained_output_bytes,
        prospective.engine.retained_output_bytes,
        CaptureResource::RetainedOutputBytes
    );
    assert_session_one_below!(
        max_combined_peak_bytes,
        prospective.engine.combined_peak_bytes,
        CaptureResource::CombinedPeakBytes
    );
}

fn assert_zero_effect_failure(
    error: &fre::CaptureIterationError,
    prospective: fre::CaptureIterationProspective,
) {
    assert!(error.has_closed_session_attempt());
    assert_eq!(
        error.session_receipt.terminal,
        CaptureIterationTerminal::Failure
    );
    assert_eq!(error.session_receipt.prospective, Some(prospective));
    assert_eq!(
        error.session_receipt.actual,
        CaptureIterationActual::default()
    );
    assert!(error.session_receipt.closes(&error.identity.session_seal));
}

#[test]
fn nullable_empty_progress_and_windows_retain_capture_valued_receipts() {
    let regex = CaptureBuilder::new(r"a|()")
        .unicode(false)
        .build()
        .expect("nullable capture-array build");
    let report = regex
        .captures_iter_window(
            b"za",
            CaptureWindow { start: 1, end: 2 },
            CaptureAggregateLimits::default(),
        )
        .expect("windowed nullable capture array");
    assert!(report.has_closed_session_attempt());
    let route = report.identity.session_seal.route_identity();
    assert_eq!(route.minimum_match_bytes, 0);
    let prospective = report
        .session_receipt
        .prospective
        .expect("nullable prospective");
    assert_eq!(
        prospective.engine.window,
        CaptureWindow { start: 1, end: 2 }
    );
    assert!(
        report.session_receipt.actual.materialized_records >= report.session_receipt.actual.results
    );
    assert_eq!(report.session_receipt.actual.materialized_records, 2);
    assert_eq!(report.session_receipt.actual.results, 1);
    assert_eq!(
        report.session_receipt.actual.capture_events,
        report.session_receipt.actual.materialized_records * route.engine_shape.groups
    );
    assert_eq!(
        report.session_receipt.actual.retained_output_bytes,
        report.session_receipt.actual.results
            * route
                .engine_shape
                .retained_record_bytes()
                .expect("retained record bytes")
    );
    let shape = route.engine_shape;
    let materialized_record_bytes = shape
        .materialized_record_bytes()
        .expect("materialized record bytes");
    let retained_record_bytes = shape
        .retained_record_bytes()
        .expect("retained record bytes");
    let first_scratch = shape
        .search_prospective(CaptureWindow { start: 1, end: 2 }, 1)
        .expect("nullable first search P")
        .scratch_bytes;
    let terminal_scratch = shape
        .search_prospective(CaptureWindow { start: 1, end: 2 }, 2)
        .expect("nullable terminal search P")
        .scratch_bytes;
    let expected_peak = [
        first_scratch,
        materialized_record_bytes + first_scratch,
        retained_record_bytes,
        retained_record_bytes + terminal_scratch,
        retained_record_bytes + materialized_record_bytes + terminal_scratch,
    ]
    .into_iter()
    .max()
    .expect("nullable combined candidates");
    assert_eq!(
        report.session_receipt.actual.combined_peak_bytes, expected_peak,
        "the suppressed current record must overlap the charged search scratch"
    );
    assert!(prospective.contains(report.session_receipt.actual));

    let error = regex
        .captures_iter_window(
            b"za",
            CaptureWindow { start: 2, end: 1 },
            CaptureAggregateLimits::default(),
        )
        .expect_err("invalid window must be terminal");
    assert_eq!(error.source, fre::CaptureSearchError::InvalidWindow);
    assert!(error.has_closed_session_attempt());
    assert_eq!(error.session_receipt.prospective, None);
    assert_eq!(
        error.session_receipt.actual,
        CaptureIterationActual::default()
    );
}
