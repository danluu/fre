#![forbid(unsafe_code)]

use fre::{
    AggregateBuildError, AggregateBuildLimits, AggregateBuilder, AggregateExecutionDetails,
    AggregateFixedAbsoluteDomainExecutionDetails, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateRunLimits, FixedAbsoluteDomainDescriptorIdentity,
};

const TARGET: &str = r"^.bc(d|e)";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(fre::RustProfile::rebar_1_12_4())
        .unicode(false)
}

fn direct(pattern: &str) -> fre::AggregateSpanSumRegex {
    builder(pattern).build_span_sum().unwrap()
}

fn continuation(pattern: &str) -> fre::AggregateSpanSumRegex {
    builder(pattern)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap()
}

#[test]
fn absolute_start_mask_sequence_matches_continuation_on_bytes_and_malformed_input() {
    let direct = direct(TARGET);
    let oracle = continuation(TARGET);
    let cases: &[&[u8]] = &[
        b"",
        b"abc",
        b"abcd",
        b"abce-tail",
        b"xbcd-tail",
        b"abcf",
        b"xabcd",
        b"\xffbcd-tail",
        b"\xffbce-tail",
    ];
    for &haystack in cases {
        let actual = direct
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap();
        let expected = oracle
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(actual, expected, "{haystack:?}");
    }
    assert_eq!(
        direct
            .span_sum_value(b"\xffbcd-tail", AggregateRunLimits::default())
            .unwrap(),
        4
    );
}

#[test]
fn route_is_hir_owned_and_excludes_multiline_empty_and_variable_width_look_cases() {
    for pattern in [TARGET, r"\A.bc[de]", r"^.[b-d][c-e][de]", r"\Aabc"] {
        let regex = direct(pattern);
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{pattern}"
        );
        assert!(
            regex
                .build_report()
                .has_closed_fixed_absolute_domain_identity()
        );
    }

    for pattern in [r"(?m:^.bc[de])", r"\A", r"\A.bc[de]*", r"\A.bc(?:de|d)"] {
        assert_ne!(
            direct(pattern).build_report().plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{pattern}"
        );
    }

    let anchored = direct(TARGET);
    assert_eq!(
        anchored
            .span_sum_value(b"x\nabcd", AggregateRunLimits::default())
            .unwrap(),
        0
    );
    let multiline = continuation(r"(?m:^.bc[de])");
    assert_eq!(
        multiline
            .span_sum_value(b"x\nabcd", AggregateRunLimits::default())
            .unwrap(),
        4
    );
}

#[test]
fn identity_receipt_and_repeated_operation_stay_owner_exact() {
    let regex = direct(TARGET);
    let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = regex.build_report().plan_identity
    else {
        panic!("target did not retain the fixed absolute-domain identity");
    };
    assert_eq!(
        identity.kernel.descriptor,
        FixedAbsoluteDomainDescriptorIdentity::StartMaskSequence { width: 4 }
    );
    assert!(
        regex
            .build_report()
            .authenticates_fixed_absolute_domain_identity(identity)
    );

    let first = regex
        .span_sum(b"abcd-tail", AggregateRunLimits::default())
        .unwrap();
    let steady = regex
        .span_sum(b"abcd-tail", AggregateRunLimits::default())
        .unwrap();
    assert_eq!(first.value(), 4);
    assert_eq!(steady.value(), 4);
    assert_eq!(first.report(), steady.report());
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = first.report().details()
    else {
        panic!("target execution did not publish the direct fixed guard");
    };
    assert_eq!(guard.actual.span_sum, 4);
    assert_eq!(guard.actual.match_events, 1);
    assert_eq!(guard.actual.source_accesses, 4);
    assert_eq!(guard.prospective.span_sum, 4);
}

#[test]
fn planner_and_runtime_one_below_refuse_without_changing_the_exact_route() {
    let regex = direct(TARGET);
    let work = usize::try_from(regex.build_report().fixed_absolute_planner_work).unwrap();
    assert!(work > 0);
    let exact = AggregateBuildLimits {
        max_fixed_absolute_planner_work: work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(TARGET)
            .limits(exact)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );

    let below = AggregateBuildLimits {
        max_fixed_absolute_planner_work: work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        builder(TARGET).limits(below).build_span_sum().unwrap_err(),
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            ..
        } if needed == work && limit == work - 1
    ));

    let prospective = regex
        .fixed_absolute_domain_full_window_prospective(9)
        .unwrap()
        .expect("target publishes a fixed guard prospective");
    assert!(prospective.total_work > 0);
    let mut limits = AggregateRunLimits::default();
    limits.fixed_absolute.max_total_work = prospective.total_work - 1;
    assert!(regex.span_sum(b"abcd-tail", limits).is_err());
}
