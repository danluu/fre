use fre::{
    AggregateManyBuildError, AggregateManyBuildLimits, AggregateManyBuilder, AggregateManyOutput,
    AggregateManyOperation, AggregateManyPlanKind, AggregateManyRunLimits, CompatibilityProfile,
    RustProfile,
};

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

    assert_eq!(AggregateManyOperation::Compile, longer.build_report().operation);
    assert_eq!(AggregateManyPlanKind::ContinuationProgram, longer.build_report().plan);
    assert_eq!(1, longer.verify_count(b"aa", limits).unwrap().value());
    assert_eq!(2, shorter.verify_count(b"aa", limits).unwrap().value());
    for (ordinal, report) in longer.build_report().patterns.iter().enumerate() {
        assert_eq!(ordinal, report.ordinal);
        assert_eq!(longer_first[ordinal].as_bytes(), report.syntax_key.pattern.as_bytes());
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
fn unsupported_whole_span_and_capture_outputs_are_typed_preflight_refusals() {
    let values = patterns(&["(a)", "b"]);
    for output in [
        AggregateManyOutput::Spans,
        AggregateManyOutput::CaptureCount,
    ] {
        let error = AggregateManyBuilder::new(&values)
            .unicode(false)
            .build_output(output)
            .unwrap_err();
        assert!(matches!(
            error,
            AggregateManyBuildError::UnsupportedOutput { requested }
                if requested == output
        ));
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
