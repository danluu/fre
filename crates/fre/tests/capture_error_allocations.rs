#![forbid(unsafe_code)]

use core::mem::size_of;
use std::alloc::System;

use fre::{
    CaptureBuildLimits, CaptureBuilder, CaptureExecutionError, CaptureExecutionSource,
    CaptureRunLimits, CaptureStreamDomains, PrefixClassUniformParticipationError,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    let region = Region::new(GLOBAL);
    let value = operation();
    let change = region.change();
    assert_eq!(change.allocations, 0, "unexpected allocation: {change:?}");
    assert_eq!(
        change.reallocations, 0,
        "unexpected reallocation: {change:?}"
    );
    assert_eq!(
        change.deallocations, 0,
        "unexpected deallocation: {change:?}"
    );
    value
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one allocator census keeps all prebuilt direct terminal variants under the same global measurement boundary"
)]
fn direct_terminal_packaging_has_a_zero_allocation_census() {
    // The complete inline cache identity, ordered-root proof slot, route
    // receipt, owner receipt, composed selector accounting, inline fused-
    // stream terminal, and the two expanded aggregate construction receipts
    // remain bounded without restoring an error-path Box.
    assert_eq!(size_of::<CaptureExecutionError>(), 7_720);

    let pattern = r"fn is_(\w+)|fn as_(\w+)";
    let haystack = b"fn is_alpha fn as_beta";
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("direct capture build");
    let baseline_limits = CaptureRunLimits::default();
    let baseline = regex
        .count_captures(haystack, baseline_limits)
        .expect("direct capture baseline");
    assert!(baseline.has_closed_count_attempt());
    let prospective = baseline
        .prefix_class_participation
        .expect("direct accounting")
        .prospective;
    let success_receipt = baseline
        .prefix_class_participation_receipt
        .expect("direct receipt");

    let mut direct_one_below = baseline_limits;
    direct_one_below.prefix_class_participation.max_work = prospective.work - 1;
    let direct_error = without_allocations(|| {
        regex
            .count_captures(haystack, direct_one_below)
            .expect_err("direct one-below must refuse")
    });
    assert!(matches!(
        direct_error.source,
        CaptureExecutionSource::PrefixClassParticipation(
            PrefixClassUniformParticipationError::WorkLimit { .. }
        )
    ));
    assert!(direct_error.has_closed_count_attempt());
    assert_eq!(
        direct_error
            .prefix_class_participation_receipt
            .as_ref()
            .and_then(|receipt| receipt.prospective),
        Some(prospective)
    );

    let control = CaptureBuilder::new(pattern)
        .unicode(false)
        .limits(CaptureBuildLimits {
            max_prefix_class_participation_planner_work: 0,
            ..CaptureBuildLimits::default()
        })
        .build()
        .expect("U3 control build");
    let control_prospective = control
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("U3 control count")
        .selector_receipt
        .and_then(|receipt| receipt.prospective)
        .expect("U3 control prospective");
    let mut control_one_below = baseline_limits;
    control_one_below.selector.max_work = control_prospective.work_bound - 1;
    let direct_with_inactive_control_limit = without_allocations(|| {
        regex
            .count_captures(haystack, control_one_below)
            .expect("inactive U3 ExecutionWork must not refuse direct U4")
    });
    assert!(direct_with_inactive_control_limit.has_closed_count_attempt());
    assert_eq!(
        direct_with_inactive_control_limit.accounting,
        baseline.accounting
    );
    assert_eq!(
        direct_with_inactive_control_limit
            .prefix_class_participation_receipt
            .as_ref()
            .and_then(|receipt| receipt.prospective),
        Some(prospective)
    );

    let mut combined_one_below = baseline_limits;
    combined_one_below.max_combined_peak_bytes = baseline.combined_peak_bytes - 1;
    let combined_error = without_allocations(|| {
        regex
            .count_captures(haystack, combined_one_below)
            .expect_err("combined peak one-below must refuse")
    });
    assert!(matches!(
        combined_error.source,
        CaptureExecutionSource::CombinedPeak { .. }
    ));
    assert!(combined_error.has_closed_count_attempt());

    let identity = regex.cache_identity(baseline_limits);
    let injected_attempt =
        without_allocations(|| fre::PrefixClassUniformParticipationAttemptError {
            source: PrefixClassUniformParticipationError::ArithmeticOverflow {
                computation: "injected post-source terminal",
            },
            receipt: success_receipt,
        });
    assert_eq!(injected_attempt.receipt.actual, success_receipt.actual);
    let mut prepublication_receipt = success_receipt;
    prepublication_receipt.prospective = None;
    prepublication_receipt.actual = fre::PrefixClassUniformParticipationActual::default();
    prepublication_receipt.actual_allocations = 0;
    let prepublication = without_allocations(|| CaptureExecutionError {
        identity: identity.clone(),
        source: CaptureExecutionSource::PrefixClassParticipation(
            PrefixClassUniformParticipationError::InvalidSchema,
        ),
        selector_receipt: None,
        prefix_class_participation_receipt: Some(prepublication_receipt),
        count_receipt: None,
    });
    assert!(
        prepublication
            .prefix_class_participation_receipt
            .as_ref()
            .expect("prepublication receipt")
            .retains_bounded_actual()
    );
    let injected = without_allocations(|| CaptureExecutionError {
        identity: identity.clone(),
        source: CaptureExecutionSource::PrefixClassParticipation(
            PrefixClassUniformParticipationError::ArithmeticOverflow {
                computation: "injected post-source terminal",
            },
        ),
        selector_receipt: None,
        prefix_class_participation_receipt: Some(success_receipt),
        count_receipt: None,
    });
    assert_eq!(
        injected
            .prefix_class_participation_receipt
            .as_ref()
            .expect("injected direct receipt")
            .actual,
        success_receipt.actual
    );
}

#[test]
fn prepared_capture_count_values_have_a_zero_allocation_census() {
    let regex = CaptureBuilder::new(r"(?:(a())|(a))")
        .unicode(false)
        .build()
        .expect("fused capture build");
    let mut session = regex
        .prepare_capture_stream_session(2, CaptureRunLimits::default(), CaptureStreamDomains::Whole)
        .expect("fused capture preparation")
        .expect("fused capture session");

    for (haystack, expected) in [
        (b"aa".as_slice(), 6),
        (b"bb".as_slice(), 0),
        (b"ab".as_slice(), 3),
        (b"ba".as_slice(), 3),
    ] {
        let count = without_allocations(|| {
            session
                .count_value(haystack)
                .expect("prepared capture count")
        });
        assert_eq!(count, expected);
    }

    let error = without_allocations(|| {
        session
            .count_value(b"a")
            .expect_err("mismatched source must replay without allocation")
    });
    assert_eq!(
        error.source,
        CaptureExecutionSource::Stream(fre::CaptureStreamError::SourceLength {
            expected: 2,
            actual: 1,
        })
    );
    assert_eq!(
        without_allocations(|| session.count_value(b"aa").expect("reuse after refusal")),
        6
    );
}
