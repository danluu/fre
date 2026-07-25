#![forbid(unsafe_code)]

use std::sync::Arc;

use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuildReport,
    AggregateBuilder, AggregateCacheIdentity, AggregateCompileAttemptKind,
    AggregateConstructionAttemptError, AggregateConstructionReceipt, AggregateEngineError,
    AggregateExecutionDetails, AggregateExecutionSource,
    AggregateFixedAbsoluteDomainExecutionDetails, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateResource, AggregateRunLimits, CompatibilityProfile,
    FixedAbsoluteDomainBuildLimits, FixedAbsoluteDomainBuildResource,
    FixedAbsoluteDomainReduceLimits, FixedAbsoluteDomainReduceResource,
};
use fre_syntax::AdmissionStatus;

fn byte_count(pattern: &str) -> fre::AggregateCountRegex {
    rebar_builder(pattern).unicode(false).build_count().unwrap()
}

fn byte_span_sum(pattern: &str) -> fre::AggregateSpanSumRegex {
    rebar_builder(pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap()
}

fn rebar_builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(fre::RustProfile::rebar_1_12_4())
}

fn endpoint_fixture(length: usize, suffix: &[u8]) -> Vec<u8> {
    assert!(length >= suffix.len());
    let mut haystack = vec![b'!'; length];
    let start = length.checked_sub(suffix.len()).unwrap();
    haystack[start..].copy_from_slice(suffix);
    haystack
}

fn assert_bounded_fixed_optional_miss(report: &AggregateBuildReport) {
    assert_ne!(report.plan, AggregatePlanKind::FixedAbsoluteDomain);
    let work = usize::try_from(report.fixed_absolute_planner_work).unwrap();
    assert!(work > 0);
    assert!(work <= AggregateBuildLimits::default().max_fixed_absolute_planner_work);
}

#[test]
fn endpoint_public_error_and_audited_success_sizes_remain_bounded() {
    assert_eq!(core::mem::size_of::<fre::AggregateExecutionIdentity>(), 8);
    assert_eq!(
        core::mem::size_of::<fre::AggregateOperationCertificate>(),
        168
    );
    assert_eq!(fre::AGGREGATE_CONTINUATION_MAX_ALLOCATIONS, 9);
    // Schema 36 keeps the fixed-capacity construction ledger, full request,
    // typed source, terminal receipt, and exact inline terminal authentication
    // snapshots. These gates make a post-failure Box or an unreviewed further
    // inline copy visible rather than moving it outside construction accounting.
    assert_eq!(core::mem::size_of::<AggregateBuildError>(), 800);
    assert_eq!(
        core::mem::size_of::<AggregateConstructionAttemptError>(),
        7_928
    );
    assert_eq!(core::mem::size_of::<AggregateConstructionReceipt>(), 6_312);
    assert_eq!(core::mem::size_of::<AggregateCacheIdentity>(), 9_096);
    assert_eq!(core::mem::size_of::<fre::AggregateExecutionError>(), 2_496);
    assert_eq!(core::mem::size_of::<fre::AggregateBuildReport>(), 9_688);
    assert_eq!(core::mem::size_of::<fre::AggregateBuildAccounting>(), 304);
    assert_eq!(core::mem::size_of::<fre::AggregatePlanIdentity>(), 216);
    // Exact success retains the independent kernel receipt beside accounting;
    // this is the public allocation-free ceiling for the enlarged enum.
    assert_eq!(core::mem::size_of::<fre::AggregateExecutionDetails>(), 728);
    assert_eq!(core::mem::size_of::<fre::AggregateExecutionSource>(), 64);
    // Full public build/run provenance plus the closed construction
    // evidence remains fixed-size and adds no operation-time allocation.
    assert_eq!(core::mem::size_of::<fre::AggregateCountResult>(), 9_832);
    assert_eq!(core::mem::size_of::<fre::AggregateSpanSumResult>(), 9_832);
}

#[test]
fn endpoint_all_seven_canonical_hir_shapes_select_the_closed_route() {
    let span_patterns = [
        "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$",
        "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$",
        r"\w$",
        r"[a-z]*XYZ$",
        r"^zbc(d|e)",
    ];
    for pattern in span_patterns {
        let regex = byte_span_sum(pattern);
        let report = regex.build_report();
        assert_eq!(
            report.plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{pattern}"
        );
        assert!(report.has_closed_fixed_absolute_domain_identity());
        let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = report.plan_identity else {
            panic!("{pattern} lacks fixed-domain identity");
        };
        assert!(report.authenticates_fixed_absolute_domain_identity(identity));
        assert!(identity.residual.is_none());
        assert!(identity.residual_strategy.is_none());
    }

    for pattern in [r"^a{2,5}$", r"^((aaa)|(aa))$"] {
        let regex = byte_count(pattern);
        let report = regex.build_report();
        assert_eq!(
            report.plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{pattern}"
        );
        assert!(report.has_closed_fixed_absolute_domain_identity());
        assert!(matches!(
            report.build,
            AggregateBuildAccounting::FixedAbsoluteDomain(_)
        ));
    }

    let scalar = rebar_builder(r"^.{249}$").build_count().unwrap();
    let report = scalar.build_report();
    assert_eq!(report.plan, AggregatePlanKind::FixedAbsoluteDomain);
    assert!(report.has_closed_fixed_absolute_domain_identity());
    let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = report.plan_identity else {
        panic!("scalar route lacks fixed-domain identity");
    };
    assert!(identity.residual.is_some());
    assert_eq!(identity.residual_strategy, report.continuation_strategy);
    let build = report
        .fixed_absolute_domain_build_accounting()
        .expect("scalar route lacks composite accounting");
    assert!(build.residual.is_some());
    assert_eq!(
        build.actual.persistent_bytes,
        report.retained_capacity_bytes
    );
}

#[test]
fn endpoint_built_artifact_publishes_exact_authenticated_length_only_guard_p() {
    let count = byte_count(r"^((aaa)|(aa))$");
    let count_p = count
        .fixed_absolute_domain_full_window_prospective(3)
        .unwrap()
        .expect("fixed count artifact must authenticate its guard");
    let count_result = count.count(b"aaa", AggregateRunLimits::default()).unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = count_result.report().details()
    else {
        panic!("fixed count execution lost its guard receipt");
    };
    assert_eq!(count_p, guard.prospective);

    let span_sum = byte_span_sum(r"^zbc((e)|(d)|(d))");
    let span_sum_p = span_sum
        .fixed_absolute_domain_full_window_prospective(9)
        .unwrap()
        .expect("fixed span-sum artifact must authenticate its guard");
    let span_sum_result = span_sum
        .span_sum(b"zbcd-tail", AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = span_sum_result.report().details()
    else {
        panic!("fixed span-sum execution lost its guard receipt");
    };
    assert_eq!(span_sum_p, guard.prospective);

    let continuation = rebar_builder("unbounded.*continuation")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        continuation
            .fixed_absolute_domain_full_window_prospective(128)
            .unwrap(),
        None
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven audit binds all thirteen exact benchmark rows to first/steady route identity"
)]
fn endpoint_explicit_thirteen_row_mapping_has_one_eager_first_and_steady_identity() {
    const MEDIUM: &str = "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$";
    const EASY_19: &str = "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$";
    let endpoint_rows = [
        (
            "imported/rsc/medium-1mb@rust/regex::steady-public-operation",
            MEDIUM,
            b"XABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice(),
            1 << 20,
        ),
        (
            "imported/rsc/medium-1mb@rust/regex::first-public-operation",
            MEDIUM,
            b"YABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice(),
            1 << 20,
        ),
        (
            "imported/rsc/easy1-1mb@rust/regex::steady-public-operation",
            EASY_19,
            b"AABBCCDDEEFFGGHHIIJ".as_slice(),
            1 << 20,
        ),
        (
            "imported/rsc/easy1-1mb@rust/regex::first-public-operation",
            EASY_19,
            b"ABBCCDDEEFFGGHHIIJJ".as_slice(),
            1 << 20,
        ),
        (
            "opt/reverse-anchored/word-end@rust/regex::steady-public-operation",
            r"\w$",
            b"_".as_slice(),
            1 << 20,
        ),
        (
            "imported/rsc/medium-32k@rust/regex::steady-public-operation",
            MEDIUM,
            b"ZABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice(),
            32 << 10,
        ),
        (
            "imported/rsc/easy1-32k@rust/regex::steady-public-operation",
            EASY_19,
            b"AABBCCDDEEFFGGHHIIJ".as_slice(),
            32 << 10,
        ),
        (
            "imported/rsc/medium-1k@rust/regex::steady-public-operation",
            MEDIUM,
            b"XABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice(),
            1 << 10,
        ),
        (
            "imported/rsc/easy1-1k@rust/regex::steady-public-operation",
            EASY_19,
            b"ABBCCDDEEFFGGHHIIJJ".as_slice(),
            1 << 10,
        ),
    ];
    for (name, pattern, suffix, length) in endpoint_rows {
        let regex = byte_span_sum(pattern);
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{name}"
        );
        let haystack = endpoint_fixture(length, suffix);
        let limits = AggregateRunLimits::default();
        let expected_identity = regex.cache_identity(limits);
        let first = regex.span_sum(&haystack, limits).unwrap();
        let steady = regex.span_sum(&haystack, limits).unwrap();
        assert_eq!(
            first.value(),
            u64::try_from(suffix.len()).unwrap(),
            "{name}"
        );
        assert_eq!(steady.value(), first.value(), "{name}");
        assert_eq!(first.report().cache_identity(), expected_identity, "{name}");
        assert_eq!(
            steady.report().cache_identity(),
            expected_identity,
            "{name}"
        );
        assert_eq!(
            steady.report().details(),
            first.report().details(),
            "{name}"
        );
        assert!(Arc::ptr_eq(
            &expected_identity.syntax_key,
            &first.report().cache_identity().syntax_key
        ));
        let AggregateExecutionDetails::FixedAbsoluteDomain(
            AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
        ) = first.report().details()
        else {
            panic!("{name} did not execute the direct fixed route")
        };
        assert_eq!(guard.window.start(), 0, "{name}");
        assert_eq!(guard.window.end(), haystack.len(), "{name}");
        assert_eq!(guard.haystack_len, haystack.len(), "{name}");
        assert_eq!(guard.actual.span_sum, u64::try_from(suffix.len()).unwrap());
        assert_eq!(guard.actual.match_events, 1, "{name}");
    }

    let count_rows = [
        (
            "opt/fixed-length/go33484-1@rust/regex::steady-public-operation",
            r"^a{2,5}$",
            10_000,
        ),
        (
            "opt/fixed-length/go33484-2@rust/regex::steady-public-operation",
            r"^((aaa)|(aa))$",
            10_000,
        ),
    ];
    for (name, pattern, length) in count_rows {
        let regex = byte_count(pattern);
        let haystack = vec![b'x'; length];
        let limits = AggregateRunLimits::default();
        let expected_identity = regex.cache_identity(limits);
        let first = regex.count(&haystack, limits).unwrap();
        let steady = regex.count(&haystack, limits).unwrap();
        assert_eq!(first.value(), 0, "{name}");
        assert_eq!(
            steady.report().cache_identity(),
            expected_identity,
            "{name}"
        );
        assert_eq!(steady.report(), first.report(), "{name}");
    }

    let scalar_name = "opt/fixed-length/go33484-3@rust/regex::steady-public-operation";
    let scalar = rebar_builder(r"^.{249}$").build_count().unwrap();
    let scalar_haystack = vec![b'x'; 1_000];
    let scalar_first = scalar
        .count(&scalar_haystack, AggregateRunLimits::default())
        .unwrap();
    let scalar_steady = scalar
        .count(&scalar_haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(scalar_first.value(), 0, "{scalar_name}");
    assert_eq!(
        scalar_steady.report(),
        scalar_first.report(),
        "{scalar_name}"
    );

    let anchored_name =
        "imported/rsc/anchored-literal-long-non-match@rust/regex::steady-public-operation";
    let anchored = byte_span_sum(r"^zbc(d|e)");
    let anchored_haystack = vec![b'x'; 390];
    let anchored_first = anchored
        .span_sum(&anchored_haystack, AggregateRunLimits::default())
        .unwrap();
    let anchored_steady = anchored
        .span_sum(&anchored_haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(anchored_first.value(), 0, "{anchored_name}");
    assert_eq!(
        anchored_steady.report(),
        anchored_first.report(),
        "{anchored_name}"
    );
    assert_eq!(endpoint_rows.len() + count_rows.len() + 2, 13);
}

#[test]
fn endpoint_direct_descriptors_match_forced_continuation_and_never_rebase_anchors() {
    let count_cases: [(&str, &[&[u8]]); 2] = [
        (
            r"^a{2,5}$",
            &[b"", b"a", b"aa", b"aaaaa", b"aaaaaa", b"aaba"],
        ),
        (r"^((aaa)|(aa))$", &[b"", b"aa", b"aaa", b"aaaa", b"ab"]),
    ];
    for (pattern, haystacks) in count_cases {
        let direct = byte_count(pattern);
        let oracle = rebar_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap();
        for &haystack in haystacks {
            assert_eq!(
                direct
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                oracle
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                "{pattern} on {haystack:?}"
            );
        }
    }

    let span_cases: [(&str, &[&[u8]]); 4] = [
        (
            "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$",
            &[
                b"XABCDEFGHIJKLMNOPQRSTUVWXYZ",
                b"YABCDEFGHIJKLMNOPQRSTUVWXYZx",
                b"short",
            ],
        ),
        (r"\w$", &[b"a", b"_", b"!", b"two words"]),
        (
            r"[a-z]*XYZ$",
            &[b"XYZ", b"abcXYZ", b"!abcXYZ", b"abcXY", b"abcXYZ\n"],
        ),
        (
            r"^zbc(d|e)",
            &[b"zbcd-tail", b"zbce-tail", b"xzbcd", b"zbcf"],
        ),
    ];
    for (pattern, haystacks) in span_cases {
        let direct = byte_span_sum(pattern);
        let oracle = rebar_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_span_sum()
            .unwrap();
        for &haystack in haystacks {
            assert_eq!(
                direct
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                oracle
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                "{pattern} on {haystack:?}"
            );
        }
    }
}

#[test]
fn endpoint_start_prefix_preserves_canonical_hir_ordinals_and_rejects_wider_branches() {
    for pattern in [r"^zbc(e|d)", r"^zbc(d|d|e)"] {
        let direct = byte_span_sum(pattern);
        assert_eq!(
            direct.build_report().plan,
            AggregatePlanKind::FixedAbsoluteDomain,
            "{pattern}"
        );
        let oracle = rebar_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_span_sum()
            .unwrap();
        for haystack in [
            b"zbcd".as_slice(),
            b"zbce".as_slice(),
            b"zbcf".as_slice(),
            b"xzbcd".as_slice(),
        ] {
            assert_eq!(
                direct
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                oracle
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                "{pattern} on {haystack:?}"
            );
        }
    }

    let ordered = byte_span_sum(r"^zbc((e)|(d)|(d))");
    assert_eq!(
        ordered.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    for (haystack, expected_ordinal) in [
        (b"zbce-tail".as_slice(), Some(0)),
        (b"zbcd-tail".as_slice(), Some(1)),
        (b"zbcf-tail".as_slice(), None),
    ] {
        let result = ordered
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        let AggregateExecutionDetails::FixedAbsoluteDomain(
            AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
        ) = result.report().details()
        else {
            panic!("ordered-prefix route lost direct guard details");
        };
        assert_eq!(guard.actual.selected_branch_ordinal, expected_ordinal);
        assert_eq!(guard.actual.source_accesses, 4);
    }

    let wider = byte_span_sum(r"^zbc(dd|e)");
    assert_ne!(
        wider.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
}

#[test]
fn endpoint_start_prefix_unicode_ascii_guard_charges_the_last_range_check() {
    let eligible_pattern = r"^x(?u:[a-c])";
    let eligible = rebar_builder(eligible_pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        eligible.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let eligible_work =
        usize::try_from(eligible.build_report().fixed_absolute_planner_work).unwrap();
    assert_eq!(eligible_work, 26);
    let exact = rebar_builder(eligible_pattern)
        .unicode(false)
        .limits(AggregateBuildLimits {
            max_fixed_absolute_planner_work: eligible_work,
            ..AggregateBuildLimits::default()
        })
        .build_span_sum()
        .unwrap();
    assert_eq!(
        exact.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let one_below = rebar_builder(eligible_pattern)
        .unicode(false)
        .limits(AggregateBuildLimits {
            max_fixed_absolute_planner_work: eligible_work - 1,
            ..AggregateBuildLimits::default()
        })
        .build_span_sum()
        .unwrap_err();
    assert!(matches!(
        one_below,
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            consumed,
            ..
        } if needed == eligible_work
            && limit == eligible_work - 1
            && consumed > 0
            && consumed <= limit
    ));
}

#[test]
fn endpoint_scalar_guard_is_direct_outside_envelope_and_nested_inside() {
    let direct = rebar_builder(r"^.{249}$").build_count().unwrap();
    let oracle = rebar_builder(r"^.{249}$")
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let mut ascii_with_lf = vec![b'a'; 249];
    ascii_with_lf[100] = b'\n';
    let cases = vec![
        vec![b'a'; 248],
        vec![b'a'; 249],
        vec![b'a'; 996],
        vec![b'a'; 997],
        vec![b'a'; 1_000],
        vec![0xFF; 249],
        ascii_with_lf,
        "é".repeat(249).into_bytes(),
        "€".repeat(249).into_bytes(),
        "🦀".repeat(249).into_bytes(),
        [b'a', 0xF0, 0x9F, b'b'].repeat(83),
    ];
    for haystack in cases {
        let expected = oracle
            .count_value(&haystack, AggregateRunLimits::default())
            .unwrap();
        let result = direct
            .count(&haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(result.value(), expected, "len={}", haystack.len());
        match result.report().details() {
            AggregateExecutionDetails::FixedAbsoluteDomain(
                AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
            ) => {
                assert!(haystack.len() < 249 || haystack.len() > 996);
                assert_eq!(guard.actual.source_accesses, 0);
            }
            AggregateExecutionDetails::FixedAbsoluteDomain(
                AggregateFixedAbsoluteDomainExecutionDetails::Residual { composite },
            ) => {
                assert!((249..=996).contains(&haystack.len()));
                assert!(composite.actual.total_work <= composite.prospective.total_work);
                assert!(composite.actual.allocations <= composite.prospective.allocations);
                assert!(
                    composite.actual.persistent_bytes <= composite.prospective.persistent_bytes
                );
                assert!(composite.actual.peak_bytes <= composite.prospective.peak_bytes);
                assert!(composite.continuation_actual.work <= composite.prospective.total_work);
            }
            other => panic!("unexpected scalar execution details: {other:?}"),
        }
        assert_eq!(
            direct
                .count_value(&haystack, AggregateRunLimits::default())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn endpoint_complete_spans_are_exact_for_every_descriptor_witness() {
    type ByteCase<'a> = (&'a str, &'a [u8], &'a [(usize, usize)]);
    let byte_cases: [ByteCase<'_>; 6] = [
        (
            "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$",
            b"prefix-XABCDEFGHIJKLMNOPQRSTUVWXYZ",
            &[(7, 34)],
        ),
        (
            "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$",
            b"--AABBCCDDEEFFGGHHIIJ",
            &[(2, 21)],
        ),
        (r"\w$", b"!!_", &[(2, 3)]),
        (r"^zbc(d|e)", b"zbcd-tail", &[(0, 4)]),
        (r"^a{2,5}$", b"aaaa", &[(0, 4)]),
        (r"^((aaa)|(aa))$", b"aaa", &[(0, 3)]),
    ];
    for (pattern, haystack, expected) in byte_cases {
        let spans = rebar_builder(pattern)
            .unicode(false)
            .build_spans()
            .unwrap()
            .spans(haystack, AggregateRunLimits::default())
            .unwrap();
        let actual: Vec<_> = spans
            .iter()
            .map(|span| (span.start(), span.end()))
            .collect();
        assert_eq!(actual, expected, "{pattern}");
        let expected_sum = expected
            .iter()
            .map(|(start, end)| end - start)
            .sum::<usize>();
        if matches!(pattern, r"^a{2,5}$" | r"^((aaa)|(aa))$") {
            assert_eq!(
                byte_count(pattern)
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                1
            );
        } else {
            assert_eq!(
                byte_span_sum(pattern)
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                u64::try_from(expected_sum).unwrap(),
                "{pattern}"
            );
        }
    }

    let scalar = rebar_builder(r"^.{249}$").build_spans().unwrap();
    for haystack in [
        vec![b'a'; 249],
        "é".repeat(249).into_bytes(),
        "€".repeat(249).into_bytes(),
        "🦀".repeat(249).into_bytes(),
    ] {
        let spans = scalar
            .spans(&haystack, AggregateRunLimits::default())
            .unwrap();
        let actual: Vec<_> = spans
            .iter()
            .map(|span| (span.start(), span.end()))
            .collect();
        assert_eq!(actual, [(0, haystack.len())]);
    }
    let mut with_lf = vec![b'a'; 249];
    with_lf[17] = b'\n';
    assert!(
        scalar
            .spans(&with_lf, AggregateRunLimits::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn endpoint_plan_retains_no_haystack_state_and_is_arc_concurrent() {
    const PATTERN: &str = "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$";
    const SUFFIX: &[u8] = b"AABBCCDDEEFFGGHHIIJ";
    let regex = Arc::new(byte_span_sum(PATTERN));
    let mut haystack = endpoint_fixture(32 << 10, SUFFIX);
    let first = regex
        .span_sum(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(first.value(), 19);
    let mutation = haystack.len() - 2;
    haystack[mutation] = b'!';
    assert_eq!(
        regex
            .span_sum_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        0
    );
    haystack[mutation] = SUFFIX[SUFFIX.len() - 2];
    let restored = regex
        .span_sum(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(restored.value(), first.value());
    assert_eq!(restored.report(), first.report());

    let haystack = Arc::new(haystack);
    let expected = first.report().clone();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let regex = Arc::clone(&regex);
            let haystack = Arc::clone(&haystack);
            std::thread::spawn(move || {
                regex
                    .span_sum(&haystack, AggregateRunLimits::default())
                    .unwrap()
            })
        })
        .collect();
    for thread in threads {
        let result = thread.join().unwrap();
        assert_eq!(result.value(), 19);
        assert_eq!(result.report(), &expected);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the test keeps exact planner success, one-below refusal and optional-miss regressions together"
)]
fn endpoint_fixed_planner_limit_is_independent_and_terminal_after_selection() {
    let baseline = byte_span_sum(r"^zbc(d|e)");
    let work = usize::try_from(baseline.build_report().fixed_absolute_planner_work).unwrap();
    assert!(work > 0);
    let exact = AggregateBuildLimits {
        max_fixed_absolute_planner_work: work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        rebar_builder(r"^zbc(d|e)")
            .unicode(false)
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
        rebar_builder(r"^zbc(d|e)")
            .unicode(false)
            .limits(below)
            .build_span_sum()
            .unwrap_err(),
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            consumed,
            ..
        } if needed == work && limit == work - 1 && consumed < needed && consumed <= limit
    ));

    let scalar = rebar_builder(r"^.{249}$").build_count().unwrap();
    let scalar_work = usize::try_from(scalar.build_report().fixed_absolute_planner_work).unwrap();
    assert!(scalar_work > 0);
    let exact = AggregateBuildLimits {
        max_fixed_absolute_planner_work: scalar_work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        usize::try_from(
            rebar_builder(r"^.{249}$")
                .limits(exact)
                .build_count()
                .unwrap()
                .build_report()
                .fixed_absolute_planner_work
        )
        .unwrap(),
        scalar_work
    );
    let below = AggregateBuildLimits {
        max_fixed_absolute_planner_work: scalar_work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        rebar_builder(r"^.{249}$")
            .limits(below)
            .build_count()
            .unwrap_err(),
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            consumed,
            ..
        } if needed == scalar_work
            && limit == scalar_work - 1
            && consumed < needed
            && consumed <= limit
    ));

    let mask_pattern = r"[\x00-\xFF]$";
    let mask = byte_span_sum(mask_pattern);
    let mask_work = usize::try_from(mask.build_report().fixed_absolute_planner_work).unwrap();
    assert!(mask_work >= 256);
    let exact = AggregateBuildLimits {
        max_fixed_absolute_planner_work: mask_work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        usize::try_from(
            rebar_builder(mask_pattern)
                .unicode(false)
                .limits(exact)
                .build_span_sum()
                .unwrap()
                .build_report()
                .fixed_absolute_planner_work
        )
        .unwrap(),
        mask_work
    );
    let below = AggregateBuildLimits {
        max_fixed_absolute_planner_work: mask_work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        rebar_builder(mask_pattern)
            .unicode(false)
            .limits(below)
            .build_span_sum()
            .unwrap_err(),
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            consumed,
            ..
        } if needed == mask_work
            && limit == mask_work - 1
            && consumed < needed
            && consumed <= limit
    ));

    let nested = |word: &str| format!("{}{}{}", "(".repeat(12), word, ")".repeat(12));
    let words_pattern = format!(r"^(?:{}|{})$", nested("aaa"), nested("aa"));
    let words = rebar_builder(&words_pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        words.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let words_work = usize::try_from(words.build_report().fixed_absolute_planner_work).unwrap();
    assert!(words_work > 0);
    let exact = AggregateBuildLimits {
        max_fixed_absolute_planner_work: words_work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        usize::try_from(
            rebar_builder(&words_pattern)
                .unicode(false)
                .limits(exact)
                .build_count()
                .unwrap()
                .build_report()
                .fixed_absolute_planner_work
        )
        .unwrap(),
        words_work
    );
    let below = AggregateBuildLimits {
        max_fixed_absolute_planner_work: words_work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        rebar_builder(&words_pattern)
            .unicode(false)
            .limits(below)
            .build_count()
            .unwrap_err(),
        AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
            needed,
            limit,
            consumed,
            ..
        } if needed == words_work
            && limit == words_work - 1
            && consumed < needed
            && consumed <= limit
    ));
}

#[test]
fn endpoint_over_cap_fixed_ineligible_shape_preserves_incumbent_continuation() {
    let long = "a".repeat(4_090);
    let pattern = format!(r"^(?:{long}|b+)$");
    let regex = rebar_builder(&pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert!(regex.build_report().fixed_absolute_planner_work > 0);
    assert!(
        usize::try_from(regex.build_report().fixed_absolute_planner_work).unwrap()
            <= AggregateBuildLimits::default().max_fixed_absolute_planner_work
    );
    assert_eq!(
        regex
            .count_value(long.as_bytes(), AggregateRunLimits::default())
            .unwrap(),
        1
    );
    assert_eq!(
        regex
            .count_value(b"bbbb", AggregateRunLimits::default())
            .unwrap(),
        1
    );
    assert_eq!(
        regex
            .count_value(b"ab", AggregateRunLimits::default())
            .unwrap(),
        0
    );
}

#[test]
fn endpoint_oversized_possible_shapes_fall_back_with_bounded_fixed_planner_work() {
    let long_start = "a".repeat(5_000);
    let long_start_pattern = format!("^{long_start}[bc]");
    let long_start_regex = rebar_builder(&long_start_pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_bounded_fixed_optional_miss(long_start_regex.build_report());
    let mut long_start_haystack = long_start.into_bytes();
    long_start_haystack.extend_from_slice(b"b-tail");
    assert_eq!(
        long_start_regex
            .span_sum(&long_start_haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        5_001
    );

    let first_word = "d".repeat(2_100);
    let second_word = "e".repeat(2_100);
    let ordered_words_pattern = format!("^({first_word}|{second_word})$");
    let ordered_words = rebar_builder(&ordered_words_pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_bounded_fixed_optional_miss(ordered_words.build_report());
    assert_eq!(
        ordered_words
            .count(second_word.as_bytes(), AggregateRunLimits::default())
            .unwrap()
            .value(),
        1
    );

    let very_long_end = "f".repeat(5_000);
    let very_long_end_pattern = format!("{very_long_end}$");
    let very_long_end_regex = rebar_builder(&very_long_end_pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_bounded_fixed_optional_miss(very_long_end_regex.build_report());
    let very_long_end_haystack = format!("prefix-{very_long_end}");
    assert_eq!(
        very_long_end_regex
            .span_sum(
                very_long_end_haystack.as_bytes(),
                AggregateRunLimits::default(),
            )
            .unwrap()
            .value(),
        5_000
    );

    let mut over_repeat_limits = AggregateBuildLimits::default();
    over_repeat_limits.continuation.max_repeat_bound = 1_001;
    let byte_repeat = rebar_builder(r"^a{1001}$")
        .unicode(false)
        .limits(over_repeat_limits)
        .build_count()
        .unwrap();
    assert_bounded_fixed_optional_miss(byte_repeat.build_report());
    assert_eq!(
        byte_repeat
            .count(&vec![b'a'; 1_001], AggregateRunLimits::default())
            .unwrap()
            .value(),
        1
    );

    let scalar_repeat = rebar_builder(r"^.{1001}$")
        .limits(over_repeat_limits)
        .build_count()
        .unwrap();
    assert_bounded_fixed_optional_miss(scalar_repeat.build_report());
    assert_eq!(
        scalar_repeat
            .count(&vec![b'x'; 1_001], AggregateRunLimits::default())
            .unwrap()
            .value(),
        1
    );

    let over_item_end = "g".repeat(2_000);
    let over_item_end_pattern = format!("{over_item_end}$");
    let over_item_end_regex = rebar_builder(&over_item_end_pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_bounded_fixed_optional_miss(over_item_end_regex.build_report());
    assert_eq!(
        over_item_end_regex
            .span_sum(over_item_end.as_bytes(), AggregateRunLimits::default())
            .unwrap()
            .value(),
        2_000
    );
}

#[test]
fn endpoint_possible_fixed_shape_exhaustion_is_an_accounted_optional_miss() {
    let payload = "a".repeat(256);
    let mut branches: Vec<String> = (0..17)
        .map(|ordinal| format!("({payload}{ordinal:02})"))
        .collect();
    branches.push("(b+)".to_owned());
    let pattern = format!("^(?:{})$", branches.join("|"));
    let regex = rebar_builder(&pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert!(regex.build_report().fixed_absolute_planner_work > 0);
    assert!(
        usize::try_from(regex.build_report().fixed_absolute_planner_work).unwrap()
            <= AggregateBuildLimits::default().max_fixed_absolute_planner_work
    );
    let consumed = usize::try_from(regex.build_report().fixed_absolute_planner_work).unwrap();
    let exact = rebar_builder(&pattern)
        .unicode(false)
        .limits(AggregateBuildLimits {
            max_fixed_absolute_planner_work: consumed,
            ..AggregateBuildLimits::default()
        })
        .build_count()
        .unwrap();
    assert_eq!(
        exact.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        usize::try_from(exact.build_report().fixed_absolute_planner_work).unwrap(),
        consumed
    );
    if consumed > 0 {
        let one_below = rebar_builder(&pattern)
            .unicode(false)
            .limits(AggregateBuildLimits {
                max_fixed_absolute_planner_work: consumed - 1,
                ..AggregateBuildLimits::default()
            })
            .build_count()
            .unwrap();
        assert_eq!(
            one_below.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );
        assert!(
            usize::try_from(one_below.build_report().fixed_absolute_planner_work).unwrap()
                < consumed
        );
    }
    let first = format!("{payload}00");
    assert_eq!(
        regex
            .count_value(first.as_bytes(), AggregateRunLimits::default())
            .unwrap(),
        1
    );
    assert_eq!(
        regex
            .count_value(b"bbbb", AggregateRunLimits::default())
            .unwrap(),
        1
    );
}

#[test]
fn endpoint_compile_spans_force_and_profile_variants_do_not_select_fixed_domain() {
    let compile = rebar_builder(r"^a{2,5}$")
        .unicode(false)
        .build_compile()
        .unwrap();
    assert_ne!(
        compile.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let spans = rebar_builder(r"^a{2,5}$")
        .unicode(false)
        .build_spans()
        .unwrap();
    assert_ne!(
        spans.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let forced = rebar_builder(r"^a{2,5}$")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_eq!(
        forced.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );

    let profile_mismatch = AggregateBuilder::new(r"^a{2,5}$")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_ne!(
        profile_mismatch.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
}

#[test]
fn endpoint_u1_limits_remain_exact_in_every_full_cache_identity() {
    let mut changed_build = AggregateBuildLimits::default();
    changed_build.fixed_absolute_residual.max_work = 0;
    changed_build.fixed_absolute_residual.max_allocations = 0;
    changed_build.fixed_absolute_residual.max_persistent_bytes = 0;
    changed_build.fixed_absolute_residual.max_peak_bytes = 0;
    for (pattern, selection) in [
        (r"^a{2,5}$", AggregatePlanSelection::Auto),
        ("a+", AggregatePlanSelection::ForceContinuation),
    ] {
        let baseline = rebar_builder(pattern)
            .unicode(false)
            .plan_selection(selection)
            .build_count()
            .unwrap();
        let changed = rebar_builder(pattern)
            .unicode(false)
            .plan_selection(selection)
            .limits(changed_build)
            .build_count()
            .unwrap();
        assert_eq!(baseline.build_report().plan, changed.build_report().plan);
        assert_eq!(
            baseline.build_report().plan_identity,
            changed.build_report().plan_identity
        );
        assert_eq!(baseline.build_report().build, changed.build_report().build);
        assert_eq!(
            baseline.build_report().retained_capacity_bytes,
            changed.build_report().retained_capacity_bytes
        );
        assert!(baseline.build_report().has_closed_construction_attempt());
        assert!(changed.build_report().has_closed_construction_attempt());
        assert_eq!(
            baseline.build_report().build_limits,
            AggregateBuildLimits::default()
        );
        assert_eq!(changed.build_report().build_limits, changed_build);
        assert_ne!(
            baseline.build_report().build_limits,
            changed.build_report().build_limits
        );
        if baseline.build_report().plan == AggregatePlanKind::FixedAbsoluteDomain {
            assert!(
                baseline
                    .build_report()
                    .has_closed_fixed_absolute_domain_identity()
            );
            assert!(
                changed
                    .build_report()
                    .has_closed_fixed_absolute_domain_identity()
            );
        }
        // The whole-construction request authenticates every caller-supplied
        // build limit even when the selected route does not consume one
        // route-specific sub-envelope.
        assert_ne!(baseline.build_report(), changed.build_report());

        let default_run = AggregateRunLimits::default();
        let mut changed_run = default_run;
        changed_run.fixed_absolute_residual.max_work = 0;
        changed_run.fixed_absolute_residual.max_allocations = 0;
        changed_run.fixed_absolute_residual.max_persistent_bytes = 0;
        changed_run.fixed_absolute_residual.max_peak_bytes = 0;
        let baseline_identity = baseline.cache_identity(default_run);
        let changed_identity = changed.cache_identity(changed_run);
        let haystack = b"aaaa";
        let first = baseline.count(haystack, default_run).unwrap();
        let second = changed.count(haystack, changed_run).unwrap();
        assert_eq!(first.value(), second.value());
        assert_eq!(first.report().cache_identity(), baseline_identity);
        assert_eq!(second.report().cache_identity(), changed_identity);
        assert_ne!(baseline_identity, changed_identity);
        assert_ne!(first.report().identity(), second.report().identity());
        assert_eq!(first.report().details(), second.report().details());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the mutation matrix exhaustively checks every public fixed-route discriminator and receipt field"
)]
fn endpoint_fixed_report_seal_rejects_public_discriminator_and_receipt_mutation() {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "each mutated report is deliberately consumed so no later assertion can reuse the rejected certificate"
    )]
    fn rejected(report: AggregateBuildReport) {
        assert!(!report.has_closed_fixed_absolute_domain_identity());
    }

    #[inline(never)]
    fn rejected_mutation(
        report: &AggregateBuildReport,
        mutate: impl FnOnce(&mut AggregateBuildReport),
    ) {
        let mut changed = report.clone();
        mutate(&mut changed);
        rejected(changed);
    }

    fn rejected_build(
        report: &AggregateBuildReport,
        mutate: impl FnOnce(&mut fre::AggregateFixedAbsoluteDomainBuildSummary),
    ) {
        rejected_mutation(report, |changed| {
            let AggregateBuildAccounting::FixedAbsoluteDomain(mut build) = changed.build else {
                panic!("fixed report lost its build receipt");
            };
            mutate(&mut build);
            changed.build = AggregateBuildAccounting::FixedAbsoluteDomain(build);
        });
    }

    let report = rebar_builder(r"^((aaa)|(aa))$")
        .unicode(false)
        .build_count()
        .unwrap()
        .build_report()
        .clone();
    assert!(report.has_closed_fixed_absolute_domain_identity());

    rejected_mutation(&report, |changed| {
        changed.schema_version = changed.schema_version.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        changed.selection = AggregatePlanSelection::ForceContinuation;
    });
    rejected_mutation(&report, |changed| {
        changed.admission = match changed.admission {
            AdmissionStatus::UpstreamOraclePending => AdmissionStatus::QuotaChecked,
            AdmissionStatus::QuotaChecked => AdmissionStatus::UpstreamOraclePending,
        };
    });
    rejected_mutation(&report, |changed| {
        changed.syntax.hir_nodes = changed.syntax.hir_nodes.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        let key = Arc::make_mut(&mut changed.syntax_key);
        let CompatibilityProfile::RustBytes(profile) = &mut key.profile else {
            panic!("fixed route must retain Rust bytes profile identity");
        };
        profile.options.unicode = !profile.options.unicode;
    });
    rejected_mutation(&report, |changed| {
        changed.fixed_absolute_planner_work =
            changed.fixed_absolute_planner_work.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        changed.capture_erasure_work = changed.capture_erasure_work.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        changed.captures_erased = changed.captures_erased.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        changed.finite_planner_work = 1;
    });
    rejected_mutation(&report, |changed| {
        changed.operation = fre::AggregateOperation::SpanSum;
    });
    rejected_mutation(&report, |changed| {
        changed.plan = AggregatePlanKind::ContinuationProgram;
    });
    rejected_mutation(&report, |changed| {
        changed.continuation_strategy = Some(fre::AggregateStrategy::ReverseSequentialRows);
    });
    rejected_mutation(&report, |changed| {
        changed.retained_capacity_bytes = changed.retained_capacity_bytes.checked_add(1).unwrap();
    });
    rejected_mutation(&report, |changed| {
        let AggregatePlanIdentity::FixedAbsoluteDomain(mut identity) = changed.plan_identity else {
            panic!("fixed report lost its identity");
        };
        identity.kernel.algorithm_version =
            identity.kernel.algorithm_version.checked_add(1).unwrap();
        changed.plan_identity = AggregatePlanIdentity::FixedAbsoluteDomain(identity);
    });
    rejected_mutation(&report, |changed| {
        let AggregatePlanIdentity::FixedAbsoluteDomain(mut identity) = changed.plan_identity else {
            panic!("fixed report lost its identity");
        };
        identity.kernel.accounting_version =
            identity.kernel.accounting_version.checked_add(1).unwrap();
        changed.plan_identity = AggregatePlanIdentity::FixedAbsoluteDomain(identity);
    });
    rejected_mutation(&report, |changed| {
        let AggregatePlanIdentity::FixedAbsoluteDomain(mut identity) = changed.plan_identity else {
            panic!("fixed report lost its identity");
        };
        identity.kernel.residual = fre::FixedAbsoluteDomainResidual::PrepublishedContinuation;
        changed.plan_identity = AggregatePlanIdentity::FixedAbsoluteDomain(identity);
    });
    rejected_build(&report, |build| {
        build.has_residual = true;
    });
    rejected_build(&report, |build| {
        build.actual.published = false;
    });
    rejected_build(&report, |build| {
        build.actual.persistent_bytes = build.actual.persistent_bytes.checked_add(1).unwrap();
    });
    rejected_build(&report, |build| {
        build.actual.peak_bytes = build.actual.peak_bytes.checked_add(1).unwrap();
    });

    let scalar = rebar_builder(r"^.{249}$")
        .build_count()
        .unwrap()
        .build_report()
        .clone();
    assert!(scalar.has_closed_fixed_absolute_domain_identity());

    rejected_mutation(&scalar, |changed| {
        changed.continuation_strategy = None;
    });
    rejected_mutation(&scalar, |changed| {
        let AggregatePlanIdentity::FixedAbsoluteDomain(mut identity) = changed.plan_identity else {
            panic!("scalar report lost its identity");
        };
        identity.residual = None;
        changed.plan_identity = AggregatePlanIdentity::FixedAbsoluteDomain(identity);
    });
    rejected_mutation(&scalar, |changed| {
        let AggregatePlanIdentity::FixedAbsoluteDomain(mut identity) = changed.plan_identity else {
            panic!("scalar report lost its identity");
        };
        identity.residual_strategy = None;
        changed.plan_identity = AggregatePlanIdentity::FixedAbsoluteDomain(identity);
    });
    rejected_build(&scalar, |build| {
        build.has_residual = false;
    });

    rejected_build(&scalar, |build| {
        build.prospective.work = build.prospective.work.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.prospective.allocations = build.prospective.allocations.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.prospective.persistent_bytes =
            build.prospective.persistent_bytes.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.prospective.peak_bytes = build.prospective.peak_bytes.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.actual.work = build.actual.work.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.actual.allocations = build.actual.allocations.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.actual.persistent_bytes = build.actual.persistent_bytes.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| {
        build.actual.peak_bytes = build.actual.peak_bytes.checked_add(1).unwrap();
    });
    rejected_build(&scalar, |build| build.actual.published = false);

    rejected_build(&scalar, |build| {
        build.has_residual = false;
    });
}

#[test]
fn endpoint_scalar_residual_compile_failure_nests_guard_and_partial_compile_receipts() {
    let pattern = r"^.{249}$";
    let baseline = rebar_builder(pattern).build_count().unwrap();
    let expected_planner_work =
        usize::try_from(baseline.build_report().fixed_absolute_planner_work).unwrap();
    assert!(expected_planner_work > 0);
    let mut limits = AggregateBuildLimits::default();
    limits.continuation.max_program_states = 0;
    let error = rebar_builder(pattern)
        .limits(limits)
        .build_count()
        .unwrap_err();
    let AggregateBuildError::FixedAbsoluteDomainResidualCompile {
        operation,
        selection,
        planner_work,
        strategy: _,
        guard,
        source,
        composite,
    } = error
    else {
        panic!("scalar residual refusal lost its composite build receipt");
    };
    assert_eq!(operation, fre::AggregateOperation::Count);
    assert_eq!(selection, AggregatePlanSelection::Auto);
    assert_eq!(planner_work, expected_planner_work);
    assert!(guard.actual.published);
    assert!(composite.contains_actual());
    assert!(!composite.actual.published);
    assert_eq!(guard.actual.items, guard.prospective.items);
    assert_eq!(guard.actual.payload_bytes, guard.prospective.payload_bytes);
    assert_eq!(
        guard.actual.persistent_bytes,
        guard.prospective.persistent_bytes
    );
    assert_eq!(source.receipt.prospective, limits.continuation);
    assert_eq!(
        source.receipt.identity.kind,
        AggregateCompileAttemptKind::EraseCapturesForWholeMatch
    );
    assert!(source.receipt.contains_actual());
    assert!(!source.receipt.published);
    assert!(source.receipt.actual.hir_nodes > 0);
    assert!(
        source.receipt.live_construction_bytes <= source.receipt.actual.construction_peak_bytes
    );
    assert!(matches!(
        source.source,
        AggregateEngineError::ResourceLimit {
            resource: AggregateResource::ProgramStates,
            required: 1,
            limit: 0,
        }
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table-driven cap proof keeps exact success and every composite one-below refusal adjacent"
)]
fn endpoint_scalar_composite_build_caps_are_exact_and_prefail_every_one_below() {
    let pattern = r"^.{249}$";
    let baseline = rebar_builder(pattern).build_count().unwrap();
    let AggregateBuildAccounting::FixedAbsoluteDomain(build) = baseline.build_report().build else {
        panic!("scalar route lost its composite build accounting");
    };
    let expected_planner_work =
        usize::try_from(baseline.build_report().fixed_absolute_planner_work).unwrap();
    assert!(expected_planner_work > 0);
    assert!(build.has_residual);

    let full_build = baseline
        .build_report()
        .fixed_absolute_domain_build_accounting()
        .expect("scalar route lost its complete owner-local build receipt");
    let owner_bytes = full_build.guard_with_owner.prospective.persistent_bytes
        - full_build.kernel.prospective.persistent_bytes;
    let owner_work = full_build.guard_with_owner.prospective.build_work
        - full_build.kernel.prospective.build_work;
    assert_eq!(full_build.guard_with_owner.prospective.allocations, 1);
    let continuation = AggregateBuildLimits::default().continuation;
    assert_eq!(
        full_build.prospective.work,
        full_build.kernel.prospective.build_work
            + u64::try_from(continuation.max_work).unwrap()
            + owner_work
    );
    assert_eq!(
        full_build.prospective.persistent_bytes,
        full_build.kernel.prospective.persistent_bytes
            + continuation.max_program_bytes
            + owner_bytes
    );
    let residual = full_build
        .residual
        .expect("scalar route lost its residual compile receipt");
    assert_eq!(
        full_build.actual.work,
        full_build.kernel.actual.build_work + u64::try_from(residual.work).unwrap() + owner_work
    );
    assert_eq!(
        full_build.actual.persistent_bytes,
        full_build.kernel.actual.persistent_bytes + residual.program_bytes + owner_bytes
    );
    let guard_prospective = full_build.guard_with_owner.prospective;
    let mut guard_one_below = AggregateBuildLimits::default();
    guard_one_below.fixed_absolute.max_items = guard_prospective.items - 1;
    let guard_failure = rebar_builder(pattern)
        .limits(guard_one_below)
        .build_count()
        .unwrap_err();
    let AggregateBuildError::FixedAbsoluteDomainResidualGuardBuild {
        planner_work,
        source,
        composite,
        ..
    } = guard_failure
    else {
        panic!("scalar fixed guard refusal lost its cumulative outer receipt");
    };
    assert_eq!(planner_work, expected_planner_work);
    assert_eq!(source.prospective, Some(guard_prospective));
    assert_eq!(composite.prospective, build.prospective);
    assert_eq!(
        composite.actual,
        fre::AggregateFixedAbsoluteDomainResidualBuildActual::default()
    );
    assert!(matches!(
        source.kind,
        fre::FixedAbsoluteDomainBuildErrorKind::ResourceLimit {
            resource: FixedAbsoluteDomainBuildResource::Items,
            needed,
            limit,
        } if needed == u64::try_from(guard_prospective.items).unwrap()
            && limit == u64::try_from(guard_prospective.items - 1).unwrap()
    ));

    let mut exact = AggregateBuildLimits::default();
    exact.fixed_absolute_residual.max_work = build.prospective.work;
    exact.fixed_absolute_residual.max_allocations = build.prospective.allocations;
    exact.fixed_absolute_residual.max_persistent_bytes = build.prospective.persistent_bytes;
    exact.fixed_absolute_residual.max_peak_bytes = build.prospective.peak_bytes;
    let rebuilt = rebar_builder(pattern).limits(exact).build_count().unwrap();
    let AggregateBuildAccounting::FixedAbsoluteDomain(rebuilt_build) = rebuilt.build_report().build
    else {
        panic!("exact composite limits changed the selected route");
    };
    assert_eq!(rebuilt_build, build);

    macro_rules! assert_one_below {
        ($limit_field:ident, $prospective_field:ident, $resource:expr) => {{
            if build.prospective.$prospective_field > 0 {
                let mut one_below = exact;
                one_below.fixed_absolute_residual.$limit_field =
                    build.prospective.$prospective_field - 1;
                let failure = rebar_builder(pattern)
                    .limits(one_below)
                    .build_count()
                    .unwrap_err();
                let AggregateBuildError::FixedAbsoluteDomainResidualPreflight {
                    planner_work,
                    resource,
                    needed,
                    limit,
                    receipt,
                    ..
                } = failure
                else {
                    panic!("composite build one-below escaped its scalar preflight");
                };
                let expected = u64::try_from(build.prospective.$prospective_field).unwrap();
                assert_eq!(planner_work, expected_planner_work);
                assert_eq!(resource, $resource);
                assert_eq!(needed, expected);
                assert_eq!(limit, expected - 1);
                assert_eq!(receipt.prospective, build.prospective);
                assert_eq!(receipt.actual, Default::default());
                assert_eq!(receipt.actual.allocations, 0);
                assert!(!receipt.actual.published);
                assert!(receipt.contains_actual());
            }
        }};
    }
    assert_one_below!(
        max_work,
        work,
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::Work
    );
    assert_one_below!(
        max_allocations,
        allocations,
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::Allocations
    );
    assert_one_below!(
        max_persistent_bytes,
        persistent_bytes,
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::PersistentBytes
    );
    assert_one_below!(
        max_peak_bytes,
        peak_bytes,
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::PeakBytes
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the guard-build forwarding proof checks every resource dimension at exact and one-below limits"
)]
fn endpoint_facade_forwards_exact_and_every_one_below_fixed_guard_build_limits() {
    let pattern = r"^((aaa)|(aa))$";
    let baseline = byte_count(pattern);
    let build = baseline
        .build_report()
        .fixed_absolute_domain_build_accounting()
        .expect("whole ordered words did not select fixed domain");
    let expected_planner_work =
        usize::try_from(baseline.build_report().fixed_absolute_planner_work).unwrap();
    assert!(expected_planner_work > 0);
    let kernel_p = build.kernel.prospective;
    let p = build.guard_with_owner.prospective;
    assert_eq!(p.items, kernel_p.items + 1);
    assert_eq!(p.allocations, kernel_p.allocations + 1);
    assert!(p.persistent_bytes > kernel_p.persistent_bytes);
    assert!(p.build_work > kernel_p.build_work);
    let exact = FixedAbsoluteDomainBuildLimits {
        max_items: p.items,
        max_payload_bytes: p.payload_bytes,
        max_identity_bytes: p.identity_bytes,
        max_copied_bytes: p.copied_bytes,
        max_allocations: p.allocations,
        max_initialized_bytes: p.initialized_bytes,
        max_build_work: p.build_work,
        max_persistent_bytes: p.persistent_bytes,
        max_peak_bytes: p.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        fixed_absolute: exact,
        ..AggregateBuildLimits::default()
    };
    let exact_regex = rebar_builder(pattern)
        .unicode(false)
        .limits(exact_limits)
        .build_count()
        .unwrap();
    assert_eq!(
        exact_regex.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );

    let refusals = [
        (
            FixedAbsoluteDomainBuildResource::Items,
            FixedAbsoluteDomainBuildLimits {
                max_items: p.items - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PayloadBytes,
            FixedAbsoluteDomainBuildLimits {
                max_payload_bytes: p.payload_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::IdentityBytes,
            FixedAbsoluteDomainBuildLimits {
                max_identity_bytes: p.identity_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::CopiedBytes,
            FixedAbsoluteDomainBuildLimits {
                max_copied_bytes: p.copied_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::Allocations,
            FixedAbsoluteDomainBuildLimits {
                max_allocations: p.allocations - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::InitializedBytes,
            FixedAbsoluteDomainBuildLimits {
                max_initialized_bytes: p.initialized_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::Work,
            FixedAbsoluteDomainBuildLimits {
                max_build_work: p.build_work - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PersistentBytes,
            FixedAbsoluteDomainBuildLimits {
                max_persistent_bytes: p.persistent_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainBuildResource::PeakBytes,
            FixedAbsoluteDomainBuildLimits {
                max_peak_bytes: p.peak_bytes - 1,
                ..exact
            },
        ),
    ];
    for (resource, fixed_absolute) in refusals {
        let limits = AggregateBuildLimits {
            fixed_absolute,
            ..AggregateBuildLimits::default()
        };
        let error = rebar_builder(pattern)
            .unicode(false)
            .limits(limits)
            .build_count()
            .unwrap_err();
        let AggregateBuildError::FixedAbsoluteDomainBuild {
            planner_work,
            source,
            ..
        } = error
        else {
            panic!("one-below fixed build limit fell through: {resource:?}");
        };
        assert_eq!(planner_work, expected_planner_work);
        assert_eq!(source.prospective, Some(p));
        assert_eq!(
            source.actual,
            fre::FixedAbsoluteDomainBuildActual::default()
        );
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
    reason = "the guard-run forwarding proof checks every positive resource dimension at exact and one-below limits"
)]
fn endpoint_facade_forwards_exact_and_every_positive_one_below_fixed_run_limits() {
    let regex = byte_span_sum(r"^zbc((e)|(d)|(d))");
    let haystack = b"zbcd-tail";
    let baseline = regex
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
    ) = baseline.report().details()
    else {
        panic!("ordered-prefix baseline lacks fixed guard receipt");
    };
    let p = guard.prospective;
    let exact = FixedAbsoluteDomainReduceLimits {
        max_byte_probes: p.byte_probes,
        max_branch_checks: p.branch_checks,
        max_match_events: p.match_events,
        max_count: p.count,
        max_span_sum: p.span_sum,
        max_reducer_steps: p.reducer_steps,
        max_total_work: p.total_work,
        max_scratch_bytes: p.scratch_bytes,
        max_persistent_bytes: p.persistent_bytes,
        max_peak_bytes: p.peak_bytes,
    };
    regex
        .span_sum(
            haystack,
            AggregateRunLimits {
                fixed_absolute: exact,
                ..AggregateRunLimits::default()
            },
        )
        .unwrap();

    let refusals = [
        (
            FixedAbsoluteDomainReduceResource::ByteProbes,
            FixedAbsoluteDomainReduceLimits {
                max_byte_probes: p.byte_probes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::BranchChecks,
            FixedAbsoluteDomainReduceLimits {
                max_branch_checks: p.branch_checks - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::MatchEvents,
            FixedAbsoluteDomainReduceLimits {
                max_match_events: p.match_events - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::Count,
            FixedAbsoluteDomainReduceLimits {
                max_count: p.count - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::SpanSum,
            FixedAbsoluteDomainReduceLimits {
                max_span_sum: p.span_sum - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::ReducerSteps,
            FixedAbsoluteDomainReduceLimits {
                max_reducer_steps: p.reducer_steps - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::TotalWork,
            FixedAbsoluteDomainReduceLimits {
                max_total_work: p.total_work - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::PersistentBytes,
            FixedAbsoluteDomainReduceLimits {
                max_persistent_bytes: p.persistent_bytes - 1,
                ..exact
            },
        ),
        (
            FixedAbsoluteDomainReduceResource::PeakBytes,
            FixedAbsoluteDomainReduceLimits {
                max_peak_bytes: p.peak_bytes - 1,
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
            .unwrap_err();
        assert!(
            error.identity.as_fixed_absolute_domain().is_some(),
            "direct fixed refusal lost its compact identity"
        );
        assert!(error.has_closed_fixed_attempt());
        assert!(matches!(
            &error.source,
            AggregateExecutionSource::FixedAbsoluteDomain
        ));
        let source = error
            .fixed_absolute_domain_receipt()
            .expect("direct fixed refusal lost its one authoritative receipt");
        assert_eq!(
            source.kind(),
            fre::AggregateFixedAbsoluteDomainAttemptKind::Guard
        );
        assert_eq!(source.fixed_absolute_limits(), fixed_absolute);
        assert_eq!(
            source.fixed_absolute_residual_limits(),
            AggregateRunLimits::default().fixed_absolute_residual
        );
        assert_eq!(
            source.continuation_limits(),
            AggregateRunLimits::default().continuation
        );
        let guard = source
            .guard_error()
            .expect("guard refusal lost its typed error");
        assert_eq!(guard.receipt.prospective, Some(p));
        assert!(matches!(
            guard.kind,
            fre::FixedAbsoluteDomainReduceErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
    }
}

#[test]
fn endpoint_scalar_residual_publishes_one_p_before_every_positive_limit_refusal() {
    let regex = rebar_builder(r"^.{249}$").build_count().unwrap();
    let haystack = [b'a'; 249];
    let baseline = regex
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Residual { composite },
    ) = baseline.report().details()
    else {
        panic!("scalar baseline did not select its eager residual");
    };
    assert!(composite.contains_actual());
    let mut limits = AggregateRunLimits::default();
    limits.continuation.max_work = 0;
    let failure = regex.count(&haystack, limits).unwrap_err();
    let repeated = regex.count(&haystack, limits).unwrap_err();
    assert_eq!(failure, repeated);
    assert!(failure.has_closed_fixed_attempt());
    assert!(matches!(
        &failure.source,
        AggregateExecutionSource::FixedAbsoluteDomainResidual
    ));
    let token = failure
        .fixed_absolute_domain_receipt()
        .expect("scalar refusal lost its one authoritative receipt");
    assert_eq!(
        token.kind(),
        fre::AggregateFixedAbsoluteDomainAttemptKind::Residual
    );
    assert_eq!(token.fixed_absolute_limits(), limits.fixed_absolute);
    assert_eq!(
        token.fixed_absolute_residual_limits(),
        limits.fixed_absolute_residual
    );
    assert_eq!(token.continuation_limits(), limits.continuation);
    let (continuation, receipt) = token
        .residual_error()
        .expect("scalar refusal lost its typed continuation and composite receipt");
    assert_eq!(receipt.prospective, composite.prospective);
    assert!(receipt.contains_actual_with(&continuation.receipt));
    assert!(matches!(
        continuation.source,
        AggregateEngineError::ResourceLimit {
            resource: AggregateResource::ExecutionWork,
            limit: 0,
            ..
        }
    ));
}

#[test]
fn endpoint_scalar_outer_run_caps_are_exact_and_prefail_every_one_below() {
    let regex = rebar_builder(r"^.{249}$").build_count().unwrap();
    let haystack = [b'a'; 249];
    let prospective = regex
        .fixed_absolute_domain_full_window_composite_prospective(haystack.len())
        .unwrap()
        .expect("scalar residual window must publish a composite P");
    let mut exact = AggregateRunLimits::default();
    exact.fixed_absolute_residual.max_work = prospective.total_work;
    exact.fixed_absolute_residual.max_allocations = prospective.allocations;
    exact.fixed_absolute_residual.max_persistent_bytes = prospective.persistent_bytes;
    exact.fixed_absolute_residual.max_peak_bytes = prospective.peak_bytes;
    let success = regex.count(&haystack, exact).unwrap();
    let AggregateExecutionDetails::FixedAbsoluteDomain(
        AggregateFixedAbsoluteDomainExecutionDetails::Residual { composite, .. },
    ) = success.report().details()
    else {
        panic!("exact outer limits changed the scalar route");
    };
    assert_eq!(composite.prospective, prospective);
    assert!(composite.contains_actual());

    macro_rules! assert_one_below {
        ($limit_field:ident, $prospective_field:ident, $resource:expr) => {{
            if prospective.$prospective_field > 0 {
                let mut limits = exact;
                limits.fixed_absolute_residual.$limit_field = prospective.$prospective_field - 1;
                let failure = regex.count(&haystack, limits).unwrap_err();
                let value_failure = regex.count_value(&haystack, limits).unwrap_err();
                assert_ne!(failure.identity, value_failure.identity);
                assert_eq!(failure.source, value_failure.source);
                assert_ne!(
                    failure.fixed_absolute_domain_receipt(),
                    value_failure.fixed_absolute_domain_receipt()
                );
                for error in [&failure, &value_failure] {
                    if error.identity.as_fixed_absolute_domain().is_none() {
                        panic!("outer scalar refusal lost its compact identity");
                    }
                    assert!(error.has_closed_fixed_attempt());
                    assert!(matches!(
                        &error.source,
                        AggregateExecutionSource::FixedAbsoluteDomainResidual
                    ));
                    let token = error
                        .fixed_absolute_domain_receipt()
                        .expect("outer refusal lost its one authoritative receipt");
                    assert_eq!(
                        token.kind(),
                        fre::AggregateFixedAbsoluteDomainAttemptKind::Residual
                    );
                    assert_eq!(token.fixed_absolute_limits(), limits.fixed_absolute);
                    assert_eq!(
                        token.fixed_absolute_residual_limits(),
                        limits.fixed_absolute_residual
                    );
                    assert_eq!(token.continuation_limits(), limits.continuation);
                    let (continuation, receipt) = token
                        .residual_error()
                        .expect("outer refusal lost its exact composite receipt");
                    assert_eq!(receipt.prospective, prospective);
                    assert!(receipt.contains_actual_with(&continuation.receipt));
                }
            }
        }};
    }
    assert_one_below!(max_work, total_work, AggregateResource::ExecutionWork);
    assert_one_below!(max_allocations, allocations, AggregateResource::Allocations);
    assert_one_below!(
        max_persistent_bytes,
        persistent_bytes,
        AggregateResource::ProgramBytes
    );
    assert_one_below!(max_peak_bytes, peak_bytes, AggregateResource::PeakBytes);
}

#[test]
fn endpoint_scalar_complete_guard_has_no_hypothetical_composite_p() {
    let regex = rebar_builder(r"^.{3}$").build_count().unwrap();
    let haystack = vec![b'a'; 1_000];
    assert_eq!(
        regex
            .fixed_absolute_domain_full_window_composite_prospective(haystack.len())
            .unwrap(),
        None
    );
    let mut limits = AggregateRunLimits::default();
    limits.fixed_absolute_residual.max_work = 0;
    limits.fixed_absolute_residual.max_allocations = 0;
    limits.fixed_absolute_residual.max_persistent_bytes = 0;
    limits.fixed_absolute_residual.max_peak_bytes = 0;
    let result = regex.count(&haystack, limits).unwrap();
    assert_eq!(result.value(), 0);
    assert!(matches!(
        result.report().details(),
        AggregateExecutionDetails::FixedAbsoluteDomain(
            AggregateFixedAbsoluteDomainExecutionDetails::Direct { .. }
        )
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the closure proof exercises direct, scalar and cross-owner terminal receipt invariants together"
)]
fn endpoint_fixed_error_owner_and_single_receipt_closure_are_exact() {
    fn scalar_outer_work_failure(pattern: &str, haystack: &[u8]) -> fre::AggregateExecutionError {
        let regex = rebar_builder(pattern).build_count().unwrap();
        let prospective = regex
            .fixed_absolute_domain_full_window_composite_prospective(haystack.len())
            .unwrap()
            .expect("fixture must invoke its scalar residual");
        let mut limits = AggregateRunLimits::default();
        limits.fixed_absolute_residual.max_work = prospective.total_work - 1;
        regex.count(haystack, limits).unwrap_err()
    }

    fn direct_failure(pattern: &str, haystack: &[u8]) -> fre::AggregateExecutionError {
        let regex = byte_span_sum(pattern);
        let prospective = regex
            .fixed_absolute_domain_full_window_prospective(haystack.len())
            .unwrap()
            .expect("direct fixture must publish guard P");
        let mut limits = AggregateRunLimits::default();
        limits.fixed_absolute.max_total_work = prospective.total_work - 1;
        regex.span_sum(haystack, limits).unwrap_err()
    }

    let haystack = [b'a'; 249];
    let failure = scalar_outer_work_failure(r"^.{249}$", &haystack);
    assert!(failure.identity.as_fixed_absolute_domain().is_some());
    assert!(failure.has_closed_fixed_attempt());

    let other_haystack = [b'a'; 248];
    let other_shape = scalar_outer_work_failure(r"^.{248}$", &other_haystack);
    assert_ne!(failure.identity, other_shape.identity);
    assert_ne!(
        failure.fixed_absolute_domain_receipt(),
        other_shape.fixed_absolute_domain_receipt()
    );

    let lower = scalar_outer_work_failure(r"^[a-z]{249}$", &haystack);
    let upper_haystack = [b'A'; 249];
    let upper = scalar_outer_work_failure(r"^[A-Z]{249}$", &upper_haystack);
    assert_ne!(lower.identity, upper.identity);
    assert_ne!(
        lower.fixed_absolute_domain_receipt(),
        upper.fixed_absolute_domain_receipt()
    );

    let scalar_owner = rebar_builder(r"^.{249}$").build_count().unwrap();
    let scalar_p = scalar_owner
        .fixed_absolute_domain_full_window_composite_prospective(haystack.len())
        .unwrap()
        .expect("same-owner scalar fixture must invoke its residual");
    let mut scalar_work_limits = AggregateRunLimits::default();
    scalar_work_limits.fixed_absolute_residual.max_work = scalar_p.total_work - 1;
    let scalar_work = scalar_owner
        .count(&haystack, scalar_work_limits)
        .unwrap_err();
    let mut scalar_peak_limits = AggregateRunLimits::default();
    scalar_peak_limits.fixed_absolute_residual.max_peak_bytes = scalar_p.peak_bytes - 1;
    let scalar_peak = scalar_owner
        .count(&haystack, scalar_peak_limits)
        .unwrap_err();
    assert!(scalar_work.has_closed_fixed_attempt());
    assert!(scalar_peak.has_closed_fixed_attempt());
    assert_eq!(scalar_work.source, scalar_peak.source);
    assert_ne!(scalar_work.identity, scalar_peak.identity);
    assert_ne!(
        scalar_work.fixed_absolute_domain_receipt(),
        scalar_peak.fixed_absolute_domain_receipt()
    );
    assert_eq!(
        scalar_work
            .fixed_absolute_domain_receipt()
            .unwrap()
            .fixed_absolute_residual_limits(),
        scalar_work_limits.fixed_absolute_residual
    );
    assert_eq!(
        scalar_peak
            .fixed_absolute_domain_receipt()
            .unwrap()
            .fixed_absolute_residual_limits(),
        scalar_peak_limits.fixed_absolute_residual
    );

    let direct_ab = direct_failure("[ab]$", b"a");
    let direct_cd = direct_failure("[cd]$", b"c");
    assert!(direct_ab.has_closed_fixed_attempt());
    assert!(direct_cd.has_closed_fixed_attempt());
    assert_ne!(direct_ab.identity, direct_cd.identity);
    assert_ne!(
        direct_ab.fixed_absolute_domain_receipt(),
        direct_cd.fixed_absolute_domain_receipt()
    );

    let direct_plain = direct_failure("a$", b"a");
    let direct_captured = direct_failure("(a)$", b"a");
    assert_ne!(direct_plain.identity, direct_captured.identity);

    // Structurally identical, separately built artifacts retain equal receipts
    // but distinct owner provenance because owner equality is Arc::ptr_eq.
    let separately_built_a = direct_failure("[ab]$", b"a");
    let separately_built_b = direct_failure("[ab]$", b"a");
    assert!(separately_built_a.has_closed_fixed_attempt());
    assert!(separately_built_b.has_closed_fixed_attempt());
    assert_eq!(separately_built_a.source, separately_built_b.source);
    assert_eq!(
        separately_built_a.fixed_absolute_domain_receipt(),
        separately_built_b.fixed_absolute_domain_receipt()
    );
    assert_ne!(separately_built_a.identity, separately_built_b.identity);

    let direct_owner = byte_span_sum("[ab]$");
    let direct_p = direct_owner
        .fixed_absolute_domain_full_window_prospective(1)
        .unwrap()
        .expect("same-owner direct fixture must publish guard P");
    let mut direct_work_limits = AggregateRunLimits::default();
    direct_work_limits.fixed_absolute.max_total_work = direct_p.total_work - 1;
    let direct_work = direct_owner.span_sum(b"a", direct_work_limits).unwrap_err();
    let mut direct_peak_limits = AggregateRunLimits::default();
    direct_peak_limits.fixed_absolute.max_peak_bytes = direct_p.peak_bytes - 1;
    let direct_peak = direct_owner.span_sum(b"a", direct_peak_limits).unwrap_err();
    assert!(direct_work.has_closed_fixed_attempt());
    assert!(direct_peak.has_closed_fixed_attempt());
    assert_eq!(direct_work.source, direct_peak.source);
    assert_ne!(direct_work.identity, direct_peak.identity);
    assert_ne!(
        direct_work.fixed_absolute_domain_receipt(),
        direct_peak.fixed_absolute_domain_receipt()
    );
    let direct_attempt = direct_work
        .identity
        .as_fixed_absolute_domain_attempt()
        .expect("direct refusal lost its opaque owner/receipt pair");
    assert!(core::ptr::eq(
        direct_attempt.receipt(),
        direct_work.fixed_absolute_domain_receipt().unwrap()
    ));
    assert!(core::ptr::eq(
        direct_attempt.owner_identity(),
        direct_work.identity.as_fixed_absolute_domain().unwrap()
    ));
    assert_eq!(
        direct_attempt.owner_build_accounting(),
        direct_owner
            .build_report()
            .fixed_absolute_domain_build_accounting()
            .unwrap()
    );

    // The source is only a unit terminal tag. The one full receipt lives in the
    // identity, and constructing the error does not add post-terminal P/A work.
    assert!(
        core::mem::size_of::<AggregateExecutionSource>()
            < core::mem::size_of::<fre::AggregateFixedAbsoluteDomainAttemptReceipt>()
    );
    assert!(!include_str!("../src/aggregate.rs").contains("continuation.clone()"));
    let guard = direct_work
        .fixed_absolute_domain_receipt()
        .unwrap()
        .guard_error()
        .expect("direct refusal lost its typed guard error");
    assert_eq!(
        guard.receipt.actual,
        fre::FixedAbsoluteDomainActual::default()
    );

    let wrong_guard_kind = fre::AggregateExecutionError {
        identity: direct_work.identity,
        source: AggregateExecutionSource::FixedAbsoluteDomainResidual,
    };
    assert!(!wrong_guard_kind.has_closed_fixed_attempt());
    assert!(std::error::Error::source(&wrong_guard_kind).is_some());
    assert!(std::error::Error::source(&wrong_guard_kind.source).is_none());
    assert!(wrong_guard_kind.to_string().contains("execution failed:"));
    let wrong_residual_kind = fre::AggregateExecutionError {
        identity: scalar_work.identity,
        source: AggregateExecutionSource::FixedAbsoluteDomain,
    };
    assert!(!wrong_residual_kind.has_closed_fixed_attempt());
    assert!(std::error::Error::source(&wrong_residual_kind).is_some());
    assert!(std::error::Error::source(&wrong_residual_kind.source).is_none());
    assert!(
        wrong_residual_kind
            .to_string()
            .contains("execution failed:")
    );
}
