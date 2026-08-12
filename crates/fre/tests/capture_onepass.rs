#![forbid(unsafe_code)]

use fre::{
    CaptureBuildLimits, CaptureBuilder, CaptureEngineBuildLimits, CaptureSearchLimits, CaptureSpan,
    CaptureWindow,
};
use fre_capture_lab::{CandidateKind, ResourceKind, SearchError};

#[test]
fn eligible_exact_captures_use_the_construction_complete_onepass_plan() {
    let regex = CaptureBuilder::new(r"(?P<run>a+)(b)")
        .unicode(false)
        .build()
        .expect("capture build");
    let onepass = regex
        .build_report()
        .onepass_capture
        .expect("one-pass sidecar");
    assert!(onepass.states > 0);
    assert_eq!(onepass.transitions, onepass.states * onepass.byte_classes);
    assert_eq!(
        regex.build_report().onepass_capture_compile_work,
        onepass.compile_work
    );
    let exact_identity = &regex.build_report().exact_replay_identity;
    let onepass_identity = exact_identity.onepass.expect("one-pass identity");
    assert_eq!(onepass_identity.program_bytes, onepass.program_bytes);
    assert_ne!(onepass_identity.algorithm_version, 0);
    assert_ne!(onepass_identity.accounting_version, 0);
    let rebuilt = CaptureBuilder::new(r"(?P<run>a+)(b)")
        .unicode(false)
        .build()
        .expect("equivalent capture build");
    assert_eq!(regex.build_report(), rebuilt.build_report());

    let haystack = b"xxaaabyy";
    let span = CaptureSpan { start: 2, end: 6 };
    let outcome = regex
        .captures_exact_window(
            haystack,
            CaptureWindow::all(haystack),
            span,
            CaptureSearchLimits::default(),
        )
        .expect("one-pass exact replay");
    assert_eq!(outcome.report.candidate, CandidateKind::OnePassCapture);
    assert_eq!(outcome.report.state_visits, 5);
    assert_eq!(outcome.report.bytes_examined, 4);
    assert_eq!(outcome.report.history_nodes, 0);
    assert_eq!(outcome.report.history_walk, 0);
    assert_eq!(outcome.report.peak_threads, 1);
    let captures = outcome.captures.expect("exact winner");
    assert_eq!(captures.overall(), Some(span));
    assert_eq!(
        captures.groups[1].span,
        Some(CaptureSpan { start: 2, end: 5 })
    );
    assert_eq!(
        captures.groups[2].span,
        Some(CaptureSpan { start: 5, end: 6 })
    );

    let nonmatch_span = CaptureSpan { start: 2, end: 5 };
    let nonmatch = regex
        .captures_exact_window(
            haystack,
            CaptureWindow::all(haystack),
            nonmatch_span,
            CaptureSearchLimits::default(),
        )
        .expect("ordinary exact nonmatch");
    assert_eq!(nonmatch.report.candidate, CandidateKind::OnePassCapture);
    assert!(nonmatch.captures.is_none());

    let history_compatible = CaptureSearchLimits {
        max_slot_copies: 0,
        ..CaptureSearchLimits::default()
    };
    let history = regex
        .captures_exact_window(
            haystack,
            CaptureWindow::all(haystack),
            span,
            history_compatible,
        )
        .expect("one-pass-specific slot refusal preserves history behavior");
    assert_eq!(history.report.candidate, CandidateKind::PersistentHistory);
    assert!(history.captures.is_some());
}

#[test]
fn onepass_exact_preserves_assertion_context_and_offset_windows() {
    let regex = CaptureBuilder::new(r"(?m:^(a+))")
        .unicode(false)
        .build()
        .expect("asserted capture build");
    assert!(regex.build_report().onepass_capture.is_some());
    let haystack = b"x\naaa\n";
    let window = CaptureWindow { start: 2, end: 5 };
    let span = CaptureSpan { start: 2, end: 5 };
    let outcome = regex
        .captures_exact_window(haystack, window, span, CaptureSearchLimits::default())
        .expect("asserted exact replay");
    assert_eq!(outcome.report.candidate, CandidateKind::OnePassCapture);
    let captures = outcome.captures.expect("asserted exact winner");
    assert_eq!(captures.overall(), Some(span));
    assert_eq!(captures.groups[1].span, Some(span));
}

#[test]
fn facade_mirrors_assertion_work_admission_before_onepass_replay() {
    let regex = CaptureBuilder::new(r"\A(?m:^)(?-u:\b{start-half})(a)(?-u:\b{end-half})(?m:$)\z")
        .unicode(false)
        .build()
        .expect("assertion-heavy capture build");
    let onepass = regex
        .build_report()
        .onepass_capture
        .expect("assertion-heavy one-pass sidecar");
    assert!(onepass.max_action_assertions > 0);
    let haystack = b"a";
    let span = CaptureSpan { start: 0, end: 1 };
    let admitted_state_visits = 2 * (1 + onepass.max_action_assertions);
    let exact = CaptureSearchLimits {
        max_state_visits: admitted_state_visits,
        ..CaptureSearchLimits::default()
    };
    let accelerated = regex
        .captures_exact_window(haystack, CaptureWindow::all(haystack), span, exact)
        .expect("exact assertion admission");
    assert_eq!(accelerated.report.candidate, CandidateKind::OnePassCapture);
    assert!(accelerated.captures.is_some());

    let one_below = CaptureSearchLimits {
        max_state_visits: admitted_state_visits - 1,
        ..CaptureSearchLimits::default()
    };
    let fallback = regex
        .captures_exact_window(haystack, CaptureWindow::all(haystack), span, one_below)
        .expect_err("history authority retains its independent larger visit bound");
    assert!(matches!(
        fallback,
        SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required,
            limit,
        } if required > admitted_state_visits && limit == admitted_state_visits - 1
    ));
}

#[test]
fn graph_and_resource_refusals_preserve_exact_history_semantics() {
    let ambiguous = CaptureBuilder::new(r"(a*)(a)")
        .unicode(false)
        .build()
        .expect("ambiguous capture build");
    assert!(ambiguous.build_report().onepass_capture.is_none());
    assert!(ambiguous.build_report().onepass_capture_compile_work > 0);
    assert!(
        ambiguous
            .build_report()
            .exact_replay_identity
            .onepass
            .is_none()
    );
    let haystack = b"aaa";
    let span = CaptureSpan { start: 0, end: 3 };
    let outcome = ambiguous
        .captures_exact_window(
            haystack,
            CaptureWindow::all(haystack),
            span,
            CaptureSearchLimits::default(),
        )
        .expect("persistent-history fallback");
    assert_eq!(outcome.report.candidate, CandidateKind::PersistentHistory);
    let captures = outcome.captures.expect("fallback winner");
    assert_eq!(
        captures.groups[1].span,
        Some(CaptureSpan { start: 0, end: 2 })
    );
    assert_eq!(
        captures.groups[2].span,
        Some(CaptureSpan { start: 2, end: 3 })
    );

    let eligible = CaptureBuilder::new(r"(a+)(b)")
        .unicode(false)
        .build()
        .expect("eligible baseline");
    let report = eligible.build_report();
    let onepass_work = report
        .onepass_capture
        .expect("baseline one-pass sidecar")
        .compile_work;
    let combined_work = report
        .engine
        .compile_work
        .checked_add(onepass_work)
        .expect("combined compile work");
    let defaults = CaptureBuildLimits::default();
    let resource_refused = CaptureBuilder::new(r"(a+)(b)")
        .unicode(false)
        .limits(CaptureBuildLimits {
            engine: CaptureEngineBuildLimits {
                max_compile_work: combined_work - 1,
                ..defaults.engine
            },
            ..defaults
        })
        .build()
        .expect("optional one-pass resource refusal");
    assert!(resource_refused.build_report().onepass_capture.is_none());
    assert_eq!(
        resource_refused.build_report().onepass_capture_compile_work,
        onepass_work - 1
    );
    assert_eq!(
        resource_refused.build_report().engine.compile_work
            + resource_refused.build_report().onepass_capture_compile_work,
        combined_work - 1
    );
    assert!(
        resource_refused
            .build_report()
            .exact_replay_identity
            .onepass
            .is_none()
    );
    let fallback_haystack = b"aaab";
    let fallback = resource_refused
        .captures_exact_window(
            fallback_haystack,
            CaptureWindow::all(fallback_haystack),
            CaptureSpan { start: 0, end: 4 },
            CaptureSearchLimits::default(),
        )
        .expect("resource-refused exact fallback");
    assert_eq!(fallback.report.candidate, CandidateKind::PersistentHistory);
    assert!(fallback.captures.is_some());
}
