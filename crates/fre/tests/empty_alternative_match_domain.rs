#![forbid(unsafe_code)]

use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregateEngineError, AggregateExecutionDetails,
    AggregateExecutionSource, AggregateImpossibleMatchReason, AggregateOperation,
    AggregatePlanKind, AggregateResource, AggregateRunLimits, AggregateSpanSumWorkspace,
    RustProfile,
};

fn builder(pattern: &str, unicode: bool) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(unicode)
        .case_insensitive(false)
}

fn oracle(pattern: &str, unicode: bool, haystack: &[u8]) -> (u64, u64) {
    let regex = regex::bytes::RegexBuilder::new(pattern)
        .unicode(unicode)
        .case_insensitive(false)
        .build()
        .unwrap_or_else(|error| panic!("oracle rejected {pattern:?}: {error}"));
    regex.find_iter(haystack).fold((0, 0), |(count, sum), m| {
        (count + 1, sum + u64::try_from(m.len()).unwrap())
    })
}

fn assert_fast_paths(pattern: &str, haystack: &[u8], nonempty_minimum: usize) {
    let expected = oracle(pattern, false, haystack);
    assert_eq!(expected, (u64::try_from(haystack.len()).unwrap() + 1, 0));
    let count = builder(pattern, false).build_count().unwrap();
    let span_sum = builder(pattern, false).build_span_sum().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );

    let mut limits = AggregateRunLimits::default();
    // The terminal proof charges two constant structural predicates, not a
    // haystack-length-dependent continuation sweep.
    limits.continuation.max_work = 2;
    let counted = count.count(haystack, limits).unwrap();
    let summed = span_sum.span_sum(haystack, limits).unwrap();
    assert_eq!(counted.value(), expected.0);
    assert_eq!(summed.value(), expected.1);
    for (operation, report) in [
        (AggregateOperation::Count, counted.report()),
        (AggregateOperation::SpanSum, summed.report()),
    ] {
        assert!(report.has_closed_impossible_match_domain_attempt());
        assert!(matches!(
            report.details(),
            AggregateExecutionDetails::ImpossibleMatchDomain(_)
        ));
        let receipt = report
            .impossible_match_domain_receipt()
            .expect("source-free empty-alternative receipt");
        assert_eq!(receipt.operation(), operation);
        assert_eq!(receipt.input_bytes(), haystack.len());
        assert_eq!(receipt.minimum_match_bytes(), Some(0));
        assert_eq!(
            receipt.empty_alternative_nonempty_minimum_bytes(),
            Some(nonempty_minimum)
        );
        assert_eq!(
            receipt.reason(),
            AggregateImpossibleMatchReason::NonemptyAlternativesBelowMinimumBytes
        );
        assert_eq!(receipt.branch_checks(), 2);
        assert_eq!(receipt.operation_work(), 2);
        assert_eq!(receipt.empty_match_count(), haystack.len() + 1);
        assert_eq!(receipt.source_bytes_read(), 0);
        assert_eq!(receipt.operation_allocations(), 0);
        assert_eq!(
            receipt.value(),
            if operation == AggregateOperation::Count {
                expected.0
            } else {
                0
            }
        );
    }

    assert_eq!(count.count_value(haystack, limits).unwrap(), expected.0);
    assert_eq!(
        span_sum.span_sum_value(haystack, limits).unwrap(),
        expected.1
    );
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut span_sum_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(haystack, limits, &mut count_workspace)
            .unwrap(),
        expected.0
    );
    assert_eq!(
        span_sum
            .span_sum_value_with_workspace(haystack, limits, &mut span_sum_workspace)
            .unwrap(),
        expected.1
    );
    let counted = count.count_value_with_counters(haystack, limits).unwrap();
    let summed = span_sum
        .span_sum_value_with_counters(haystack, limits)
        .unwrap();
    assert_eq!(counted.value(), expected.0);
    assert_eq!(summed.value(), expected.1);
    assert!(counted.continuation_receipt().is_none());
    assert!(summed.continuation_receipt().is_none());
}

#[test]
fn large_repeated_nonempty_arms_leave_only_empty_matches_below_minimum() {
    assert_fast_paths(r"(?:A+){100}|", &[b'A'; 99], 100);
    assert_fast_paths(r"(?:A+){200}|", &[b'A'; 198], 200);
    assert_fast_paths(r"(?:A{101}|B{103}|)", &[b'B'; 100], 101);
    assert_fast_paths(r"(?:(?:A{100})|(?P<empty>))", &[0xFF; 99], 100);
}

fn enumerate_haystacks(alphabet: &[u8], maximum_len: usize, mut visit: impl FnMut(&[u8])) {
    fn recurse(
        alphabet: &[u8],
        remaining: usize,
        buffer: &mut Vec<u8>,
        visit: &mut dyn FnMut(&[u8]),
    ) {
        visit(buffer);
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            buffer.push(byte);
            recurse(alphabet, remaining - 1, buffer, visit);
            buffer.pop();
        }
    }
    recurse(alphabet, maximum_len, &mut Vec::new(), &mut visit);
}

#[test]
fn byte_mode_empty_alternative_proof_is_exhaustive_below_the_nonempty_minimum() {
    for pattern in [
        r"a{3}|",
        r"|a{3}",
        r"(?:a{3}|b{4}|)",
        r"(?P<root>(?:a{3}|(?P<empty>)))",
    ] {
        let count = builder(pattern, false).build_count().unwrap();
        let span_sum = builder(pattern, false).build_span_sum().unwrap();
        enumerate_haystacks(&[b'a', b'b', 0xFF], 2, |haystack| {
            let expected = oracle(pattern, false, haystack);
            let counted = count
                .count(haystack, AggregateRunLimits::default())
                .unwrap();
            let summed = span_sum
                .span_sum(haystack, AggregateRunLimits::default())
                .unwrap();
            assert_eq!(counted.value(), expected.0, "{pattern:?} {haystack:?}");
            assert_eq!(summed.value(), expected.1, "{pattern:?} {haystack:?}");
            assert!(
                counted
                    .report()
                    .has_closed_impossible_match_domain_attempt()
            );
            assert!(summed.report().has_closed_impossible_match_domain_attempt());
        });
    }
}

#[test]
fn proof_stops_at_threshold_and_rejects_other_nullable_arms_and_unicode_mode() {
    for (pattern, unicode, haystack) in [
        (r"a{3}|", false, b"aaa".as_slice()),
        (r"(?:^|a{3}|)", false, b"aa".as_slice()),
        (r"(?:a?|b{3}|)", false, b"bb".as_slice()),
        (r"(?:a{3}|)", true, b"aa".as_slice()),
    ] {
        let expected = oracle(pattern, unicode, haystack);
        let count = builder(pattern, unicode).build_count().unwrap();
        let span_sum = builder(pattern, unicode).build_span_sum().unwrap();
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        let summed = span_sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(counted.value(), expected.0, "{pattern:?}");
        assert_eq!(summed.value(), expected.1, "{pattern:?}");
        assert!(
            counted.report().impossible_match_domain_receipt().is_none(),
            "{pattern:?}"
        );
        assert!(
            summed.report().impossible_match_domain_receipt().is_none(),
            "{pattern:?}"
        );
    }
}

#[test]
fn exact_empty_match_resource_limits_admit_and_refuse_one_below() {
    let count = builder(r"a{5}|", false).build_count().unwrap();
    let haystack = b"bbbb";
    let mut exact = AggregateRunLimits::default();
    exact.continuation.max_boundaries = 5;
    exact.continuation.max_match_events = 5;
    exact.continuation.max_output_matches = 5;
    exact.continuation.max_work = 2;
    assert_eq!(count.count_value(haystack, exact).unwrap(), 5);

    for (expected_resource, limits) in [
        (
            AggregateResource::Boundaries,
            AggregateRunLimits {
                continuation: fre::AggregateOperationLimits {
                    max_boundaries: 4,
                    ..exact.continuation
                },
                ..exact
            },
        ),
        (
            AggregateResource::MatchEvents,
            AggregateRunLimits {
                continuation: fre::AggregateOperationLimits {
                    max_match_events: 4,
                    max_work: usize::MAX,
                    ..exact.continuation
                },
                ..exact
            },
        ),
        (
            AggregateResource::OutputMatches,
            AggregateRunLimits {
                continuation: fre::AggregateOperationLimits {
                    max_output_matches: 4,
                    max_match_events: usize::MAX,
                    max_work: usize::MAX,
                    ..exact.continuation
                },
                ..exact
            },
        ),
        (
            AggregateResource::ExecutionWork,
            AggregateRunLimits {
                continuation: fre::AggregateOperationLimits {
                    max_boundaries: usize::MAX,
                    max_match_events: usize::MAX,
                    max_output_matches: usize::MAX,
                    max_work: 1,
                    ..exact.continuation
                },
                ..exact
            },
        ),
    ] {
        let error = count.count_value(haystack, limits).unwrap_err();
        assert!(error.continuation_receipt().is_some());
        assert!(
            matches!(
                error.source,
                AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
                    resource,
                    ..
                }) if resource == expected_resource
            ),
            "expected {expected_resource:?}, error={error:?}"
        );
    }
}
