use fre::{
    AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION, AggregateEngineError, AggregateManyBuildError,
    AggregateManyBuildLimits, AggregateManyBuilder, AggregateManyExecutionDetails,
    AggregateManyExecutionSource, AggregateManyOperation, AggregateManyOutput,
    AggregateManyPlanKind, AggregateManyRegex, AggregateManyRunLimits, AggregateResource,
    AggregateStrategy, CompatibilityProfile, RustProfile,
};
use regex::bytes::RegexBuilder;

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn compile_artifact_preserves_order_profile_and_priority_before_verification() {
    let longer_first = patterns(&[r"a+", "a"]);
    let shorter_first = patterns(&["a", r"a+"]);
    let limits = AggregateManyRunLimits::unlimited();

    let longer = AggregateManyBuilder::new(&longer_first)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .build_compile()
        .unwrap();
    let shorter = AggregateManyBuilder::new(&shorter_first)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .build_compile()
        .unwrap();
    let fresh_again = AggregateManyBuilder::new(&longer_first)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .build_compile()
        .unwrap();

    assert_eq!(
        AggregateManyOperation::Compile,
        longer.build_report().operation
    );
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        longer.build_report().plan
    );
    assert_eq!(longer.build_report(), fresh_again.build_report());
    assert!(!core::ptr::eq(
        longer.build_report().patterns.as_ptr(),
        fresh_again.build_report().patterns.as_ptr()
    ));
    assert_eq!(1, longer.verify_count(b"aa", limits).unwrap().value());
    assert_eq!(2, shorter.verify_count(b"aa", limits).unwrap().value());
    for (ordinal, report) in longer.build_report().patterns.iter().enumerate() {
        assert_eq!(ordinal, report.ordinal);
        assert_eq!(
            longer_first[ordinal].as_bytes(),
            report.syntax_key.pattern.as_bytes()
        );
        assert_eq!(
            CompatibilityProfile::RustBytes(longer.build_report().profile.clone()),
            report.syntax_key.profile
        );
    }
}

#[test]
fn compile_artifact_keeps_unicode_and_resource_refusals_before_publication() {
    let unicode_nonliteral = patterns(&["snow", r"\w+"]);
    assert!(matches!(
        AggregateManyBuilder::new(&unicode_nonliteral)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .build_compile(),
        Err(AggregateManyBuildError::UnicodeNonLiteral { pattern: 1 })
    ));

    let malformed_second = patterns(&["a", "("]);
    let limits = AggregateManyBuildLimits {
        max_patterns: 1,
        ..AggregateManyBuildLimits::default()
    };
    assert!(matches!(
        AggregateManyBuilder::new(&malformed_second)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .limits(limits)
            .build_compile(),
        Err(AggregateManyBuildError::PatternLimit {
            needed: 2,
            limit: 1
        })
    ));

    let nosey_repeat = patterns(&[r"[A-Za-z0-9_-]{20,1024}", "never"]);
    assert!(matches!(
        AggregateManyBuilder::new(&nosey_repeat)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .build_compile(),
        Err(AggregateManyBuildError::ContinuationCompile {
            operation: AggregateManyOperation::Compile,
            source: AggregateEngineError::ResourceLimit {
                resource: AggregateResource::RepeatBound,
                ..
            },
            ..
        })
    ));
}

#[test]
fn ordered_pattern_priority_changes_the_selected_sequence() {
    let longer_first = patterns(&[r"a+", "a"]);
    let shorter_first = patterns(&["a", r"a+"]);
    let limits = AggregateManyRunLimits::unlimited();

    let longer = AggregateManyBuilder::new(&longer_first)
        .unicode(false)
        .build_count()
        .unwrap();
    let shorter = AggregateManyBuilder::new(&shorter_first)
        .unicode(false)
        .build_count()
        .unwrap();

    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        longer.build_report().plan
    );
    assert_eq!(1, longer.count_value(b"aa", limits).unwrap());
    assert_eq!(2, shorter.count_value(b"aa", limits).unwrap());
}

#[test]
fn ordered_literal_priority_is_not_set_or_longest_match_semantics() {
    let longer_first = patterns(&["ab", "a"]);
    let shorter_first = patterns(&["a", "ab"]);
    let limits = AggregateManyRunLimits::unlimited();

    let longer = AggregateManyBuilder::new(&longer_first)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    let shorter = AggregateManyBuilder::new(&shorter_first)
        .unicode(false)
        .build_span_sum()
        .unwrap();

    assert_eq!(
        AggregateManyPlanKind::OrderedLiteral,
        longer.build_report().plan
    );
    assert_eq!(2, longer.span_sum_value(b"ab", limits).unwrap());
    assert_eq!(1, shorter.span_sum_value(b"ab", limits).unwrap());
}

#[test]
fn empty_progress_and_absolute_context_survive_successive_windows() {
    let empty_first = patterns(&["", "a"]);
    let consuming_first = patterns(&["a", ""]);
    let anchored = patterns(&[r"\Aaa", "."]);
    let limits = AggregateManyRunLimits::unlimited();

    let empty = AggregateManyBuilder::new(&empty_first)
        .unicode(false)
        .build_count()
        .unwrap();
    let consuming = AggregateManyBuilder::new(&consuming_first)
        .unicode(false)
        .build_count()
        .unwrap();
    let anchored = AggregateManyBuilder::new(&anchored)
        .unicode(false)
        .build_count()
        .unwrap();

    assert_eq!(2, empty.count_value(b"a", limits).unwrap());
    assert_eq!(1, consuming.count_value(b"a", limits).unwrap());
    assert_eq!(3, anchored.count_value(b"baa", limits).unwrap());
}

#[test]
fn preflight_refuses_cardinality_before_parsing_or_plan_allocation() {
    let malformed_second = patterns(&["a", "("]);
    let build_limits = AggregateManyBuildLimits {
        max_patterns: 1,
        ..AggregateManyBuildLimits::default()
    };
    let error = AggregateManyBuilder::new(&malformed_second)
        .unicode(false)
        .limits(build_limits)
        .build_count()
        .unwrap_err();
    assert!(matches!(
        error,
        AggregateManyBuildError::PatternLimit {
            needed: 2,
            limit: 1
        }
    ));
}

#[test]
fn complete_spans_dispatch_while_capture_output_remains_a_typed_preflight_refusal() {
    let values = patterns(&["(a)", "b"]);
    let AggregateManyRegex::Spans(regex) = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_output(AggregateManyOutput::Spans)
        .unwrap()
    else {
        panic!("span output published a different operation wrapper");
    };
    assert_eq!(
        AggregateManyOperation::Spans,
        regex.build_report().operation
    );
    assert_eq!(1, regex.build_report().captures_erased);

    let error = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_output(AggregateManyOutput::CaptureCount)
        .unwrap_err();
    assert!(matches!(
        error,
        AggregateManyBuildError::UnsupportedOutput {
            requested: AggregateManyOutput::CaptureCount
        }
    ));
}

#[test]
fn complete_spans_match_pinned_ordered_alternation_exhaustively() {
    let pattern_sets = [
        patterns(&["ab", "a"]),
        patterns(&["a", "ab"]),
        patterns(&["", "a"]),
        patterns(&[r"\Aab", r"."]),
        patterns(&["(a+)", "b"]),
        patterns(&[r"a+?", "a"]),
    ];
    let haystacks = byte_strings(3, &[b'a', b'b', 0xFF]);

    for values in pattern_sets {
        let combined = values
            .iter()
            .map(|pattern| format!("(?:{pattern})"))
            .collect::<Vec<_>>()
            .join("|");
        let upstream = RegexBuilder::new(&combined).unicode(false).build().unwrap();
        for strategy in [
            AggregateStrategy::FullTable,
            AggregateStrategy::ReverseSequentialRows,
        ] {
            let fre = AggregateManyBuilder::new(&values)
                .unicode(false)
                .strategy(strategy)
                .build_spans()
                .unwrap();
            assert_eq!(
                AggregateManyPlanKind::ContinuationProgram,
                fre.build_report().plan
            );
            assert_eq!(Some(strategy), fre.build_report().strategy);

            for haystack in &haystacks {
                let expected = upstream
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                let admitted = fre
                    .spans(haystack, AggregateManyRunLimits::unlimited())
                    .unwrap();
                let actual = admitted
                    .iter()
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                assert_eq!(expected, actual, "{combined:?}/{strategy:?}/{haystack:?}");
                assert_eq!(expected.len(), admitted.len());
                assert_eq!(expected.is_empty(), admitted.is_empty());
            }
        }
    }
}

#[test]
fn complete_spans_preserve_unicode_literal_boundaries_and_schema_identity() {
    let values = patterns(&["雪", "s"]);
    let regex = AggregateManyBuilder::new(&values)
        .unicode(true)
        .build_spans()
        .unwrap();
    assert_eq!(2, AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION);
    assert_eq!(
        AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION,
        regex.build_report().schema_version
    );
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        regex.build_report().plan
    );

    let actual = regex
        .spans("x雪ss".as_bytes(), AggregateManyRunLimits::unlimited())
        .unwrap()
        .iter()
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    assert_eq!(vec![(1, 4), (4, 5), (5, 6)], actual);
}

#[test]
fn complete_spans_enforce_output_admission_before_publication() {
    let values = patterns(&["ab", "a"]);
    let regex = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_spans()
        .unwrap();
    let haystack = b"ababa";
    let baseline = regex
        .spans(haystack, AggregateManyRunLimits::unlimited())
        .unwrap();
    let AggregateManyExecutionDetails::Continuation { certificate, .. } = baseline.details() else {
        panic!("complete spans must retain continuation accounting");
    };
    assert!(certificate.output_matches > 0);

    let mut exact = AggregateManyRunLimits::unlimited();
    exact.continuation.max_output_matches = certificate.output_matches;
    assert_eq!(baseline.len(), regex.spans(haystack, exact).unwrap().len());

    exact.continuation.max_output_matches -= 1;
    let error = regex.spans(haystack, exact).unwrap_err();
    assert!(matches!(
        error.source,
        AggregateManyExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputMatches,
            ..
        })
    ));
}

#[test]
fn complete_spans_publish_an_exact_operation_specific_scratch_limit() {
    let values = patterns(&["ab", "a"]);
    let baseline = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_spans()
        .unwrap();
    let scratch_bytes = baseline.build_report().composition.scratch_bytes;
    assert!(scratch_bytes > 0);
    assert_eq!(
        0,
        baseline
            .build_report()
            .composition
            .literal_view_capacity_bytes
    );

    let exact_limits = AggregateManyBuildLimits {
        max_composition_scratch_bytes: scratch_bytes,
        ..AggregateManyBuildLimits::default()
    };
    let exact = AggregateManyBuilder::new(&values)
        .unicode(false)
        .limits(exact_limits)
        .build_spans()
        .unwrap();
    assert_eq!(
        scratch_bytes,
        exact.build_report().composition.scratch_bytes
    );

    let below_limits = AggregateManyBuildLimits {
        max_composition_scratch_bytes: scratch_bytes - 1,
        ..AggregateManyBuildLimits::default()
    };
    assert!(matches!(
        AggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(below_limits)
            .build_spans(),
        Err(AggregateManyBuildError::CompositionScratchLimit {
            needed,
            limit
        }) if needed == scratch_bytes && limit == scratch_bytes - 1
    ));

    assert!(matches!(
        AggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(exact_limits)
            .build_count(),
        Err(AggregateManyBuildError::CompositionScratchLimit { needed, limit })
            if needed > limit && limit == scratch_bytes
    ));
}

fn byte_strings(max_len: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                next.push(value);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

#[test]
fn continuation_value_paths_match_diagnostic_values_and_refusals() {
    let pattern_sets = [
        patterns(&[r"a+", "b"]),
        patterns(&["", r"a+"]),
        patterns(&[r"(ab|a)", r"b?"]),
    ];
    let haystacks = byte_strings(3, &[b'a', b'b', 0xFF]);

    for values in pattern_sets {
        for strategy in [
            AggregateStrategy::FullTable,
            AggregateStrategy::ReverseSequentialRows,
        ] {
            let count = AggregateManyBuilder::new(&values)
                .unicode(false)
                .strategy(strategy)
                .build_count()
                .unwrap();
            let span_sum = AggregateManyBuilder::new(&values)
                .unicode(false)
                .strategy(strategy)
                .build_span_sum()
                .unwrap();
            assert_eq!(
                AggregateManyPlanKind::ContinuationProgram,
                count.build_report().plan
            );
            assert_eq!(
                AggregateManyPlanKind::ContinuationProgram,
                span_sum.build_report().plan
            );

            for haystack in &haystacks {
                let limits = AggregateManyRunLimits::unlimited();
                assert_eq!(
                    count.count(haystack, limits).unwrap().value(),
                    count.count_value(haystack, limits).unwrap(),
                    "count parity for {values:?}/{strategy:?}/{haystack:?}"
                );
                assert_eq!(
                    span_sum.span_sum(haystack, limits).unwrap().value(),
                    span_sum.span_sum_value(haystack, limits).unwrap(),
                    "span-sum parity for {values:?}/{strategy:?}/{haystack:?}"
                );
            }

            let mut refused = AggregateManyRunLimits::unlimited();
            refused.continuation.max_boundaries = 0;
            assert_eq!(
                count.count(b"a", refused).unwrap_err(),
                count.count_value(b"a", refused).unwrap_err()
            );
            assert_eq!(
                span_sum.span_sum(b"a", refused).unwrap_err(),
                span_sum.span_sum_value(b"a", refused).unwrap_err()
            );
        }
    }
}

#[test]
fn every_pattern_keeps_its_ordinal_source_and_profile_identity() {
    let values = patterns(&["ab", "a"]);
    let regex = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_count()
        .unwrap();
    let reports = &regex.build_report().patterns;

    assert_eq!(2, reports.len());
    assert_eq!(0, reports[0].ordinal);
    assert_eq!(1, reports[1].ordinal);
    assert_eq!(b"ab", reports[0].syntax_key.pattern.as_bytes());
    assert_eq!(b"a", reports[1].syntax_key.pattern.as_bytes());
    assert_ne!(reports[0].syntax_key, reports[1].syntax_key);
}

#[test]
fn unicode_many_requires_the_nonempty_utf8_literal_proof() {
    let literal_values = patterns(&["snow", "雪"]);
    let regex = AggregateManyBuilder::new(&literal_values)
        .unicode(true)
        .build_count()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::OrderedLiteral,
        regex.build_report().plan
    );
    assert_eq!(
        2,
        regex
            .count_value("雪snow".as_bytes(), AggregateManyRunLimits::unlimited())
            .unwrap()
    );

    let nonliteral = patterns(&["snow", r"\w+"]);
    assert!(matches!(
        AggregateManyBuilder::new(&nonliteral)
            .unicode(true)
            .build_count()
            .unwrap_err(),
        AggregateManyBuildError::UnicodeNonLiteral { pattern: 1 }
    ));
}
