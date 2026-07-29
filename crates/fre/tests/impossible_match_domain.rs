#![forbid(unsafe_code)]

use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregateExecutionDetails,
    AggregateImpossibleMatchReason, AggregateMatchDomainExecutionReceipt, AggregatePlanKind,
    AggregateRunLimits, AggregateSpanSumWorkspace, RustProfile,
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
        (count + 1, sum + u64::try_from(m.end() - m.start()).unwrap())
    })
}

fn assert_receipt(
    receipt: &AggregateMatchDomainExecutionReceipt,
    operation: fre::AggregateOperation,
    input_bytes: usize,
    minimum: Option<usize>,
    maximum: Option<usize>,
    absolute_whole_input: bool,
    reason: AggregateImpossibleMatchReason,
    branch_checks: u8,
) {
    assert_eq!(receipt.operation(), operation);
    assert_eq!(receipt.input_bytes(), input_bytes);
    assert_eq!(receipt.minimum_match_bytes(), minimum);
    assert_eq!(receipt.maximum_match_bytes(), maximum);
    assert_eq!(receipt.absolute_whole_input(), absolute_whole_input);
    assert_eq!(receipt.reason(), reason);
    assert_eq!(receipt.branch_checks(), branch_checks);
    assert_eq!(receipt.source_bytes_read(), 0);
    assert_eq!(receipt.operation_allocations(), 0);
}

fn assert_zero_across_public_paths(
    pattern: &str,
    unicode: bool,
    haystack: &[u8],
    minimum: Option<usize>,
    maximum: Option<usize>,
    absolute_whole_input: bool,
    reason: AggregateImpossibleMatchReason,
    branch_checks: u8,
) {
    assert_eq!(oracle(pattern, unicode, haystack), (0, 0));
    let count = builder(pattern, unicode).build_count().unwrap();
    let span_sum = builder(pattern, unicode).build_span_sum().unwrap();
    let mut limits = AggregateRunLimits::default();
    limits.continuation.max_work = 0;

    let counted = count.count(haystack, limits).unwrap();
    assert_eq!(counted.value(), 0);
    assert!(
        counted
            .report()
            .has_closed_impossible_match_domain_attempt()
    );
    assert!(!counted.report().has_closed_direct_attempt());
    let count_receipt = counted
        .report()
        .impossible_match_domain_receipt()
        .expect("count impossible-domain receipt");
    assert_receipt(
        count_receipt,
        fre::AggregateOperation::Count,
        haystack.len(),
        minimum,
        maximum,
        absolute_whole_input,
        reason,
        branch_checks,
    );
    assert!(matches!(
        counted.report().details(),
        AggregateExecutionDetails::ImpossibleMatchDomain(_)
    ));

    let summed = span_sum.span_sum(haystack, limits).unwrap();
    assert_eq!(summed.value(), 0);
    assert!(summed.report().has_closed_impossible_match_domain_attempt());
    assert!(!summed.report().has_closed_direct_attempt());
    assert_receipt(
        summed
            .report()
            .impossible_match_domain_receipt()
            .expect("span-sum impossible-domain receipt"),
        fre::AggregateOperation::SpanSum,
        haystack.len(),
        minimum,
        maximum,
        absolute_whole_input,
        reason,
        branch_checks,
    );

    assert_eq!(count.count_value(haystack, limits).unwrap(), 0);
    assert_eq!(span_sum.span_sum_value(haystack, limits).unwrap(), 0);

    let mut count_workspace = AggregateCountWorkspace::new();
    let mut span_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(haystack, limits, &mut count_workspace)
            .unwrap(),
        0
    );
    assert_eq!(
        span_sum
            .span_sum_value_with_workspace(haystack, limits, &mut span_workspace)
            .unwrap(),
        0
    );
    let counted = count.count_value_with_counters(haystack, limits).unwrap();
    let summed = span_sum
        .span_sum_value_with_counters(haystack, limits)
        .unwrap();
    assert_eq!(counted.value(), 0);
    assert_eq!(summed.value(), 0);
    assert!(counted.continuation_receipt().is_none());
    assert!(summed.continuation_receipt().is_none());
}

fn minimum_byte_domain_terminates_every_count_and_span_sum_api_body() {
    assert_zero_across_public_paths(
        r"\w{10,}",
        false,
        b"abcdef",
        Some(10),
        None,
        false,
        AggregateImpossibleMatchReason::BelowMinimumBytes,
        1,
    );
    assert_zero_across_public_paths(
        r"[\p{math}&&\u{10000}-\u{10FFFF}]{10,}",
        true,
        &[0xFF; 36],
        Some(40),
        None,
        false,
        AggregateImpossibleMatchReason::BelowMinimumBytes,
        1,
    );
}

fn absolute_maximum_byte_domain_covers_ascii_unicode_and_invalid_utf8_body() {
    assert_zero_across_public_paths(
        r"^\w{30}$",
        false,
        &[b'a'; 52],
        Some(30),
        Some(30),
        true,
        AggregateImpossibleMatchReason::AboveAbsoluteMaximumBytes,
        2,
    );
    assert_zero_across_public_paths(
        r"^\w{10}$",
        true,
        &[0xFF; 44],
        Some(10),
        Some(40),
        true,
        AggregateImpossibleMatchReason::AboveAbsoluteMaximumBytes,
        2,
    );
    assert_zero_across_public_paths(
        r"^.{249}$",
        true,
        &[0xFF; 1_000],
        Some(249),
        Some(996),
        true,
        AggregateImpossibleMatchReason::AboveAbsoluteMaximumBytes,
        2,
    );
    assert_zero_across_public_paths(
        r"^a{2,5}$",
        false,
        &[b'a'; 10_000],
        Some(2),
        Some(5),
        true,
        AggregateImpossibleMatchReason::AboveAbsoluteMaximumBytes,
        2,
    );
}

fn line_and_one_sided_anchors_do_not_establish_a_whole_input_domain_body() {
    for (pattern, haystack) in [
        (r"a{2,5}", b"aaaaaa".as_slice()),
        (r"^a{2,5}", b"aaaaaa".as_slice()),
        (r"a{2,5}$", b"aaaaaa".as_slice()),
        (r"(?m:^a{2,5}$)", b"aaaaa\n".as_slice()),
        (r"(?:^aa$|bbb$)", b"xxxxbbb".as_slice()),
        (r"(?:^aa$|^bbb)", b"bbbxxxx".as_slice()),
    ] {
        let expected = oracle(pattern, false, haystack);
        assert_ne!(expected, (0, 0), "test witness must contain a match");
        let count = builder(pattern, false).build_count().unwrap();
        let span_sum = builder(pattern, false).build_span_sum().unwrap();
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        let summed = span_sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(counted.value(), expected.0, "pattern={pattern:?}");
        assert_eq!(summed.value(), expected.1, "pattern={pattern:?}");
        assert!(
            counted.report().impossible_match_domain_receipt().is_none(),
            "pattern={pattern:?}"
        );
        assert!(
            summed.report().impossible_match_domain_receipt().is_none(),
            "pattern={pattern:?}"
        );
    }
}

fn absolute_anchors_must_cover_every_alternation_arm_body() {
    assert_zero_across_public_paths(
        r"(?:^aa$|^bbb$)",
        false,
        b"bbbb",
        Some(2),
        Some(3),
        true,
        AggregateImpossibleMatchReason::AboveAbsoluteMaximumBytes,
        2,
    );
}

fn empty_language_terminates_without_source_access_body() {
    assert_zero_across_public_paths(
        r"[\p{any}&&\P{any}]",
        true,
        b"\xFFarbitrary",
        None,
        None,
        false,
        AggregateImpossibleMatchReason::EmptyLanguage,
        1,
    );
}

fn terminal_preflight_is_independent_of_selected_engine_limits_body() {
    let pattern = r"^a{2,5}$";
    let haystack = &[b'a'; 100];
    let count = builder(pattern, false).build_count().unwrap();
    let span_sum = builder(pattern, false).build_span_sum().unwrap();

    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let mut limits = AggregateRunLimits::default();
    limits.exact_literal.max_linear_terms = 0;
    limits.fixed_absolute.max_total_work = 0;
    limits.continuation.max_work = 0;
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut span_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(count.count(haystack, limits).unwrap().value(), 0);
    assert_eq!(count.count_value(haystack, limits).unwrap(), 0);
    assert_eq!(
        count
            .count_value_with_workspace(haystack, limits, &mut count_workspace)
            .unwrap(),
        0
    );
    assert_eq!(
        count
            .count_value_with_counters(haystack, limits)
            .unwrap()
            .value(),
        0
    );
    assert_eq!(span_sum.span_sum(haystack, limits).unwrap().value(), 0);
    assert_eq!(span_sum.span_sum_value(haystack, limits).unwrap(), 0);
    assert_eq!(
        span_sum
            .span_sum_value_with_workspace(haystack, limits, &mut span_workspace)
            .unwrap(),
        0
    );
    assert_eq!(
        span_sum
            .span_sum_value_with_counters(haystack, limits)
            .unwrap()
            .value(),
        0
    );
}

fn compile_verification_keeps_compile_identity_and_uses_no_aggregate_receipt_body() {
    let compiled = builder(r"^a{2,5}$", false).build_compile().unwrap();
    assert_eq!(
        compiled.build_report().operation,
        fre::AggregateOperation::Compile
    );
    let result = compiled
        .verify_count(&[b'a'; 100], AggregateRunLimits::default())
        .unwrap();
    assert_eq!(result.value(), 0);
    assert!(result.report().impossible_match_domain_receipt().is_none());
    assert!(!result.report().has_closed_impossible_match_domain_attempt());
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

fn exhaustive_small_byte_domains_match_rust_regex_body() {
    for &(pattern, unicode) in &[
        (r"a{2,4}", false),
        (r"^a{2,4}$", false),
        (r"(?m:^a{2,4}$)", false),
        (r"^(?:ab|baa)$", false),
        (r"^.{2}$", true),
        (r"^[\u{10000}-\u{10FFFF}]{2}$", true),
    ] {
        let count = builder(pattern, unicode).build_count().unwrap();
        let span_sum = builder(pattern, unicode).build_span_sum().unwrap();
        enumerate_haystacks(&[b'a', b'b', b'\n', 0xFF], 4, |haystack| {
            let expected = oracle(pattern, unicode, haystack);
            assert_eq!(
                count
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                expected.0,
                "count pattern={pattern:?}, haystack={haystack:?}"
            );
            assert_eq!(
                span_sum
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                expected.1,
                "span-sum pattern={pattern:?}, haystack={haystack:?}"
            );
        });
    }
}

fn run_on_large_stack(name: &str, test: fn()) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn minimum_byte_domain_terminates_every_count_and_span_sum_api() {
    run_on_large_stack(
        "minimum-byte-domain",
        minimum_byte_domain_terminates_every_count_and_span_sum_api_body,
    );
}

#[test]
fn absolute_maximum_byte_domain_covers_ascii_unicode_and_invalid_utf8() {
    run_on_large_stack(
        "absolute-maximum-byte-domain",
        absolute_maximum_byte_domain_covers_ascii_unicode_and_invalid_utf8_body,
    );
}

#[test]
fn line_and_one_sided_anchors_do_not_establish_a_whole_input_domain() {
    run_on_large_stack(
        "line-and-one-sided-anchors",
        line_and_one_sided_anchors_do_not_establish_a_whole_input_domain_body,
    );
}

#[test]
fn absolute_anchors_must_cover_every_alternation_arm() {
    run_on_large_stack(
        "absolute-anchor-alternation",
        absolute_anchors_must_cover_every_alternation_arm_body,
    );
}

#[test]
fn empty_language_terminates_without_source_access() {
    run_on_large_stack(
        "empty-language-domain",
        empty_language_terminates_without_source_access_body,
    );
}

#[test]
fn terminal_preflight_is_independent_of_selected_engine_limits() {
    run_on_large_stack(
        "match-domain-limit-independence",
        terminal_preflight_is_independent_of_selected_engine_limits_body,
    );
}

#[test]
fn compile_verification_keeps_compile_identity_and_uses_no_aggregate_receipt() {
    run_on_large_stack(
        "compile-verification-identity",
        compile_verification_keeps_compile_identity_and_uses_no_aggregate_receipt_body,
    );
}

#[test]
fn exhaustive_small_byte_domains_match_rust_regex() {
    run_on_large_stack(
        "exhaustive-small-byte-domains",
        exhaustive_small_byte_domains_match_rust_regex_body,
    );
}
