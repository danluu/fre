use fre::{
    AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID, AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION,
    AGGREGATE_MANY_TOTAL_BYTE_COVER_SPAN_SUM_ALGORITHM_ID, AggregateEngineError,
    AggregateManyBuildAccounting, AggregateManyBuildError, AggregateManyBuildLimits,
    AggregateManyBuilder, AggregateManyCaptureIneligibility, AggregateManyCaptureRunLimits,
    AggregateManyCaptureSemantics, AggregateManyExecutionDetails, AggregateManyExecutionSource,
    AggregateManyOperation, AggregateManyOutput, AggregateManyPlanIdentity, AggregateManyPlanKind,
    AggregateManyRegex, AggregateManyRunLimits, AggregateResource, AggregateStrategy,
    AggregateOperationAttemptKind, CompatibilityProfile, RustProfile,
};
use regex::bytes::RegexBuilder;
use regex_automata::{Input, meta::Regex as MetaRegex};

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn meta_regex(patterns: &[String]) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false)
                .case_insensitive(false),
        )
        .build_many(patterns)
        .unwrap()
}

fn meta_count_and_span_sum(regex: &MetaRegex, haystack: &[u8]) -> (u64, u64) {
    regex
        .find_iter(haystack)
        .try_fold((0_u64, 0_u64), |(count, span_sum), matched| {
            Some((
                count.checked_add(1)?,
                span_sum.checked_add(
                    u64::try_from(matched.end().checked_sub(matched.start())?).ok()?,
                )?,
            ))
        })
        .unwrap()
}

fn meta_capture_count(patterns: &[String], haystack: &[u8]) -> u64 {
    let regex = MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false)
                .case_insensitive(false),
        )
        .build_many(patterns)
        .unwrap();
    let mut input = Input::new(haystack);
    let mut captures = regex.create_captures();
    let mut count = 0_u64;
    loop {
        regex.search_captures(&input, &mut captures);
        let Some(matched) = captures.get_match() else {
            break;
        };
        assert!(matched.end() > input.start());
        for index in 0..captures.group_len() {
            count = count
                .checked_add(u64::from(captures.get_group(index).is_some()))
                .unwrap();
        }
        input.set_start(matched.end());
    }
    count
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
fn complete_spans_and_uniform_capture_count_dispatch_to_typed_wrappers() {
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
        AggregateManyBuildError::CaptureIneligible {
            pattern: 1,
            reason: AggregateManyCaptureIneligibility::CaptureCountNotOne
        }
    ));

    let captured = patterns(&["(a)", "(b)"]);
    let AggregateManyRegex::CaptureCount(regex) = AggregateManyBuilder::new(&captured)
        .unicode(false)
        .build_output(AggregateManyOutput::CaptureCount)
        .unwrap()
    else {
        panic!("capture output published a different operation wrapper");
    };
    assert_eq!(
        AggregateManyOperation::CaptureCount,
        regex.build_report().operation
    );
    assert_eq!(
        Some(AggregateManyCaptureSemantics::UniformSingleWholeMatchCaptureNonempty),
        regex.build_report().capture_semantics
    );
    assert_eq!(
        Some(1),
        regex.build_report().participating_captures_per_match
    );
    assert_eq!(
        4,
        regex
            .count_captures_value(b"ab", AggregateManyCaptureRunLimits::unlimited())
            .unwrap()
    );
}

#[test]
fn uniform_capture_count_preserves_ordered_pattern_priority() {
    let longer_first = patterns(&["(a+)", "(a)"]);
    let shorter_first = patterns(&["(a)", "(a+)"]);
    let limits = AggregateManyCaptureRunLimits::unlimited();

    let longer = AggregateManyBuilder::new(&longer_first)
        .unicode(false)
        .build_capture_count()
        .unwrap();
    let shorter = AggregateManyBuilder::new(&shorter_first)
        .unicode(false)
        .build_capture_count()
        .unwrap();

    let longer_result = longer.count_captures(b"aa", limits).unwrap();
    assert_eq!(1, longer_result.matches());
    assert_eq!(2, longer_result.capture_events());
    assert_eq!(2, longer_result.value());
    assert_eq!(4, shorter.count_captures_value(b"aa", limits).unwrap());
}

#[test]
fn capture_count_requires_one_nonempty_whole_match_capture_per_pattern() {
    let cases = [
        (
            patterns(&["(a)", "b"]),
            1,
            AggregateManyCaptureIneligibility::CaptureCountNotOne,
        ),
        (
            patterns(&["(a)", "((b))"]),
            1,
            AggregateManyCaptureIneligibility::CaptureCountNotOne,
        ),
        (
            patterns(&["(a)", "(?:b(c))"]),
            1,
            AggregateManyCaptureIneligibility::CaptureNotAtRoot,
        ),
        (
            patterns(&["(a)", "(b?)"]),
            1,
            AggregateManyCaptureIneligibility::EmptyMatchPossible,
        ),
    ];
    for (values, pattern, reason) in cases {
        let error = AggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count()
            .unwrap_err();
        assert!(matches!(
            error,
            AggregateManyBuildError::CaptureIneligible {
                pattern: actual_pattern,
                reason: actual_reason,
            } if actual_pattern == pattern && actual_reason == reason
        ));
    }
}

#[test]
fn capture_count_admits_result_only_after_exact_reducer_limits() {
    let values = patterns(&["(a+)", "(b)"]);
    let regex = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_capture_count()
        .unwrap();
    let baseline = regex
        .count_captures(b"aabb", AggregateManyCaptureRunLimits::unlimited())
        .unwrap();
    assert_eq!(6, baseline.value());
    assert_eq!(6, baseline.capture_events());

    let mut selector_refused = AggregateManyCaptureRunLimits::unlimited();
    selector_refused.selector.continuation.max_boundaries = 0;
    assert_eq!(
        regex
            .count_captures(b"aabb", selector_refused)
            .unwrap_err(),
        regex
            .count_captures_value(b"aabb", selector_refused)
            .unwrap_err()
    );

    let mut exact = AggregateManyCaptureRunLimits::unlimited();
    exact.max_capture_events = baseline.capture_events();
    exact.max_capture_count = baseline.value();
    assert_eq!(baseline, regex.count_captures(b"aabb", exact).unwrap());
    assert_eq!(
        baseline.value(),
        regex.count_captures_value(b"aabb", exact).unwrap()
    );

    exact.max_capture_events -= 1;
    assert!(matches!(
        regex.count_captures(b"aabb", exact).unwrap_err().source,
        AggregateManyExecutionSource::CaptureEventsLimit {
            needed: 6,
            limit: 5
        }
    ));
    assert!(matches!(
        regex
            .count_captures_value(b"aabb", exact)
            .unwrap_err()
            .source,
        AggregateManyExecutionSource::CaptureEventsLimit {
            needed: 6,
            limit: 5
        }
    ));
    exact.max_capture_events += 1;
    exact.max_capture_count -= 1;
    assert!(matches!(
        regex.count_captures(b"aabb", exact).unwrap_err().source,
        AggregateManyExecutionSource::CaptureCountLimit {
            needed: 6,
            limit: 5
        }
    ));
    assert!(matches!(
        regex
            .count_captures_value(b"aabb", exact)
            .unwrap_err()
            .source,
        AggregateManyExecutionSource::CaptureCountLimit {
            needed: 6,
            limit: 5
        }
    ));
}

#[test]
fn uniform_capture_count_matches_pinned_build_many_exhaustively() {
    let pattern_sets = [
        patterns(&["(a+)", "(a)"]),
        patterns(&["(a)", "(a+)"]),
        patterns(&["(ab)", "(a)", "(.)"]),
        patterns(&["(a|b)", "([^ab]+)"]),
        patterns(&[r"(\xFF+)", "(.)"]),
    ];
    let haystacks = byte_strings(4, &[b'a', b'b', 0xFF]);

    for values in pattern_sets {
        for strategy in [
            AggregateStrategy::FullTable,
            AggregateStrategy::ReverseSequentialRows,
        ] {
            let fre = AggregateManyBuilder::new(&values)
                .unicode(false)
                .strategy(strategy)
                .build_capture_count()
                .unwrap();
            for haystack in &haystacks {
                assert_eq!(
                    meta_capture_count(&values, haystack),
                    fre.count_captures_value(haystack, AggregateManyCaptureRunLimits::unlimited())
                        .unwrap(),
                    "{values:?}/{strategy:?}/{haystack:?}"
                );
            }
        }
    }
}

#[test]
fn byte_unit_cover_capture_session_preserves_assertions_priority_and_binding() {
    let values = patterns(&[
        r"(\balways_comb\b)",
        r"([A-Za-z_][A-Za-z0-9_]*)",
        r"(\r\n|\r|\n)",
        r"(.)",
    ]);
    let regex = AggregateManyBuilder::new(&values)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_capture_count()
        .unwrap();
    let proof = regex
        .build_report()
        .byte_unit_cover
        .expect("the final dot is a complete look-free byte witness");
    assert_eq!(
        AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID,
        proof.algorithm
    );
    assert_eq!(values.len(), proof.patterns);
    assert_eq!(values.len(), proof.nonnullable_patterns);
    assert!(proof.look_free_patterns < proof.patterns);
    assert_eq!(256, proof.covered_bytes);
    assert!(!proof.unicode);
    assert_eq!(0, proof.allocations);
    assert_eq!(
        u64::try_from(proof.work).unwrap(),
        regex.build_report().composition.byte_unit_cover_proof_work
    );

    let sources: [&[u8]; 3] = [b"always_comb!", b"alpha_\xff beta", b"\xff\xfe !?\tvalue!"];
    assert!(
        sources
            .iter()
            .all(|source| source.len() == sources[0].len())
    );
    let limits = AggregateManyCaptureRunLimits::unlimited();
    let footprint = regex
        .cached_count_session_footprint(sources[0].len())
        .unwrap()
        .expect("source-free byte session footprint");
    assert!(footprint.allocations > 0);
    assert!(footprint.retained_bytes >= footprint.boundary_bytes);
    let mut session = regex
        .prepare_cached_count_session(sources[0].len(), limits)
        .unwrap()
        .expect("proved byte session");
    assert_eq!(footprint, session.footprint());

    for source in sources.into_iter().cycle().take(12) {
        assert_eq!(
            meta_capture_count(&values, source),
            regex
                .count_captures_value_with_session(&mut session, source, limits)
                .unwrap(),
            "{source:?}"
        );
    }

    assert!(matches!(
        regex
            .count_captures_value_with_session(&mut session, b"short", limits)
            .unwrap_err()
            .source,
        AggregateManyExecutionSource::CaptureSessionHaystackLengthMismatch { .. }
    ));
    let mut other_limits = limits;
    other_limits.max_capture_count -= 1;
    assert!(matches!(
        regex
            .count_captures_value_with_session(&mut session, sources[0], other_limits)
            .unwrap_err()
            .source,
        AggregateManyExecutionSource::CaptureSessionLimitsMismatch
    ));

    let mut reordered = values.clone();
    reordered.swap(0, 1);
    let other = AggregateManyBuilder::new(&reordered)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_capture_count()
        .unwrap();
    assert!(matches!(
        other
            .count_captures_value_with_session(&mut session, sources[0], limits)
            .unwrap_err()
            .source,
        AggregateManyExecutionSource::CaptureSessionPlanMismatch
    ));

    assert_eq!(
        meta_capture_count(&values, sources[1]),
        regex
            .count_captures_value_with_session(&mut session, sources[1], limits)
            .unwrap(),
        "binding refusals must not poison reusable state"
    );
}

#[test]
fn byte_unit_cover_capture_session_refuses_incomplete_or_wrong_strategy_plans() {
    let incomplete = patterns(&[r"(\bword\b)", r"([a-z]+)"]);
    let regex = AggregateManyBuilder::new(&incomplete)
        .unicode(false)
        .build_capture_count()
        .unwrap();
    assert!(regex.build_report().byte_unit_cover.is_none());
    assert_eq!(
        0,
        regex.build_report().composition.byte_unit_cover_proof_work
    );
    assert!(regex.cached_count_session_footprint(64).unwrap().is_none());

    let covered = patterns(&[r"(\bword\b)", r"(\n)", r"(.)"]);
    let full_table = AggregateManyBuilder::new(&covered)
        .unicode(false)
        .strategy(AggregateStrategy::FullTable)
        .build_capture_count()
        .unwrap();
    assert!(full_table.build_report().byte_unit_cover.is_some());
    assert!(
        full_table
            .prepare_cached_count_session(64, AggregateManyCaptureRunLimits::unlimited())
            .unwrap()
            .is_none()
    );
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
fn complete_span_visit_matches_materialized_single_multi_and_nullable_sequences() {
    let cases = [
        (patterns(&[r"a+"]), b"zaaa za".as_slice()),
        (patterns(&["ab", "a"]), b"ababa".as_slice()),
        (patterns(&["", "a"]), b"aa".as_slice()),
    ];

    for (values, haystack) in cases {
        for strategy in [
            AggregateStrategy::FullTable,
            AggregateStrategy::ReverseSequentialRows,
        ] {
            let regex = AggregateManyBuilder::new(&values)
                .unicode(false)
                .strategy(strategy)
                .build_spans()
                .unwrap();
            let limits = AggregateManyRunLimits::unlimited();
            let expected = regex.spans(haystack, limits).unwrap();
            let mut visited = Vec::new();
            let visit = regex
                .visit_spans(haystack, limits, |matched| visited.push(matched))
                .unwrap();
            let expected = expected.iter().collect::<Vec<_>>();

            assert_eq!(visited, expected, "{values:?}/{strategy:?}");
            assert_eq!(visit.len(), expected.len());
            assert_eq!(visit.is_empty(), expected.is_empty());
            assert_eq!(
                visit.span_sum(),
                expected.iter().map(|matched| matched.len()).sum()
            );
            let AggregateManyExecutionDetails::Continuation {
                certificate,
                accounting,
            } = visit.details()
            else {
                panic!("span visit lost its continuation identity");
            };
            let AggregateManyPlanIdentity::Continuation(plan_id) =
                regex.build_report().plan_identity
            else {
                panic!("span visit build lost its continuation plan identity");
            };
            assert_eq!(certificate.regex_plan_id, plan_id);
            assert_eq!(certificate.operation, AggregateOperationAttemptKind::SpanVisit);
            assert_eq!(certificate.strategy, strategy);
            assert_eq!(certificate.range, 0..haystack.len());
            assert!(certificate.authenticates_limits(limits.continuation));
            assert_eq!(certificate.output_bytes, 0);
            assert_eq!(accounting.output_bytes, 0);
            assert_eq!(accounting.emitted_matches, visit.len());
        }
    }
}

#[test]
fn complete_span_visit_preserves_priority_and_refuses_before_callback() {
    let limits = AggregateManyRunLimits::unlimited();
    let longer_first = patterns(&[r"a+", "a"]);
    let shorter_first = patterns(&["a", r"a+"]);
    let longer = AggregateManyBuilder::new(&longer_first)
        .unicode(false)
        .build_spans()
        .unwrap();
    let shorter = AggregateManyBuilder::new(&shorter_first)
        .unicode(false)
        .build_spans()
        .unwrap();
    let mut longer_spans = Vec::new();
    let mut shorter_spans = Vec::new();
    longer
        .visit_spans(b"aa", limits, |matched| longer_spans.push(matched))
        .unwrap();
    shorter
        .visit_spans(b"aa", limits, |matched| shorter_spans.push(matched))
        .unwrap();
    assert_eq!(
        longer_spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        [(0, 2)]
    );
    assert_eq!(
        shorter_spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        [(0, 1), (1, 2)]
    );

    let mut baseline_callbacks = 0_usize;
    let baseline = shorter
        .visit_spans(b"aaa", limits, |_| baseline_callbacks += 1)
        .unwrap();
    let AggregateManyExecutionDetails::Continuation { certificate, .. } = baseline.details() else {
        panic!("span visit lost its continuation prospective");
    };
    assert!(certificate.output_matches > 0);
    assert_eq!(baseline_callbacks, baseline.len());

    let mut exact = limits;
    exact.continuation.max_output_matches = certificate.output_matches;
    assert_eq!(baseline.len(), shorter.visit_spans(b"aaa", exact, |_| {}).unwrap().len());

    exact.continuation.max_output_matches -= 1;
    let mut refused_callbacks = 0_usize;
    let refusal = shorter
        .visit_spans(b"aaa", exact, |_| refused_callbacks += 1)
        .unwrap_err();
    assert_eq!(refused_callbacks, 0);
    assert!(matches!(
        refusal.source,
        AggregateManyExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputMatches,
            required,
            limit,
        }) if required == certificate.output_matches
            && limit == certificate.output_matches - 1
    ));
}

#[test]
fn complete_spans_preserve_unicode_literal_boundaries_and_schema_identity() {
    let values = patterns(&["雪", "s"]);
    let regex = AggregateManyBuilder::new(&values)
        .unicode(true)
        .build_spans()
        .unwrap();
    assert_eq!(6, AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION);
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

fn total_byte_cover_patterns() -> Vec<String> {
    patterns(&[
        r"(?:ab|a)",
        r"(?:\r\n|\r|\n)",
        r"(?-u:[\x00-\x09\x0B-\xFF])",
    ])
}

#[test]
fn total_byte_cover_span_sum_is_source_independent_and_matches_meta() {
    let base = total_byte_cover_patterns();
    let mut reordered = base.clone();
    reordered.rotate_left(1);
    let mut with_unrelated_look = base.clone();
    with_unrelated_look.insert(0, r"\bword\b".to_owned());
    let haystacks = byte_strings(3, &[0x00, b'\n', b'\r', b'a', b'b', 0xFF]);

    for values in [base, reordered, with_unrelated_look] {
        let oracle = meta_regex(&values);
        let span_sum = AggregateManyBuilder::new(&values)
            .unicode(false)
            .build_span_sum()
            .unwrap();
        assert_eq!(
            AggregateManyPlanKind::TotalByteCoverSpanSum,
            span_sum.build_report().plan
        );
        assert_eq!(None, span_sum.build_report().strategy);
        let AggregateManyPlanIdentity::TotalByteCoverSpanSum(identity) =
            span_sum.build_report().plan_identity
        else {
            panic!("total byte cover must publish its structural identity");
        };
        assert_eq!(
            AGGREGATE_MANY_TOTAL_BYTE_COVER_SPAN_SUM_ALGORITHM_ID,
            identity.algorithm
        );
        assert_eq!(values.len(), identity.patterns);
        assert_eq!(values.len(), identity.nonnullable_patterns);
        assert_eq!(256, identity.covered_bytes);
        assert!(!identity.unicode);

        let count = AggregateManyBuilder::new(&values)
            .unicode(false)
            .build_count()
            .unwrap();
        assert_eq!(
            AggregateManyPlanKind::ContinuationProgram,
            count.build_report().plan,
            "the span-sum theorem does not imply a count shortcut"
        );

        for haystack in &haystacks {
            let (_, expected_span_sum) = meta_count_and_span_sum(&oracle, haystack);
            assert_eq!(u64::try_from(haystack.len()).unwrap(), expected_span_sum);
            let result = span_sum
                .span_sum(haystack, AggregateManyRunLimits::unlimited())
                .unwrap();
            assert_eq!(expected_span_sum, result.value());
            let AggregateManyExecutionDetails::TotalByteCover {
                upper_bounds,
                actual,
            } = result.details()
            else {
                panic!("total byte cover must publish exact execution accounting");
            };
            assert_eq!(0, actual.logical_source_bytes);
            assert_eq!(1, actual.work);
            assert_eq!(0, actual.match_events);
            assert_eq!(0, actual.output_matches);
            assert_eq!(haystack.len(), actual.span_sum);
            assert_eq!(haystack.len(), upper_bounds.match_events);
            assert_eq!(haystack.len(), upper_bounds.output_matches);
        }
    }
}

#[test]
fn total_byte_cover_requires_nonnullable_look_free_complete_witnesses() {
    let mut missing_lf = patterns(&[r"(?:ab|a)", r"(?:\r\n|\r)", r"(?-u:[\x00-\x09\x0B-\xFF])"]);
    let span_sum = AggregateManyBuilder::new(&missing_lf)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        span_sum.build_report().plan
    );

    missing_lf[1] = r"(?-u:\A\n)".to_owned();
    let span_sum = AggregateManyBuilder::new(&missing_lf)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        span_sum.build_report().plan,
        "a looked one-byte witness cannot contribute to the cover"
    );

    let mut nullable = total_byte_cover_patterns();
    nullable.push(String::new());
    let span_sum = AggregateManyBuilder::new(&nullable)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        span_sum.build_report().plan,
        "every pattern must be nonnullable"
    );
}

#[test]
fn total_byte_cover_precedes_the_literal_span_sum_plan_and_enforces_limits() {
    let literals = (u8::MIN..=u8::MAX)
        .map(|byte| format!(r"(?-u:\x{byte:02X})"))
        .collect::<Vec<_>>();
    let baseline = AggregateManyBuilder::new(&literals)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::TotalByteCoverSpanSum,
        baseline.build_report().plan
    );
    let AggregateManyBuildAccounting::TotalByteCoverSpanSum(build) = baseline.build_report().build
    else {
        panic!("total byte cover must publish build accounting");
    };
    assert_eq!(256, build.patterns);
    assert_eq!(256, build.nonnullable_patterns);
    assert_eq!(256, build.covered_bytes);
    assert_eq!(0, build.allocations);
    assert!(build.work > 0);
    assert!(build.persistent_bytes > 0);

    let mut exact_build = AggregateManyBuildLimits::default();
    exact_build.continuation.max_work = build.work;
    exact_build.continuation.max_program_bytes = build.persistent_bytes;
    AggregateManyBuilder::new(&literals)
        .unicode(false)
        .limits(exact_build)
        .build_span_sum()
        .unwrap();

    exact_build.continuation.max_work = build.work - 1;
    assert!(matches!(
        AggregateManyBuilder::new(&literals)
            .unicode(false)
            .limits(exact_build)
            .build_span_sum()
            .unwrap_err(),
        AggregateManyBuildError::TotalByteCoverBuild {
            source: AggregateEngineError::ResourceLimit {
                resource: AggregateResource::CompileWork,
                required,
                limit,
            },
        } if required == build.work && limit == build.work - 1
    ));

    let mut refused = AggregateManyRunLimits::unlimited();
    refused.continuation.max_work = 0;
    assert!(matches!(
        baseline.span_sum_value(b"x", refused).unwrap_err().source,
        AggregateManyExecutionSource::TotalByteCover(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::ExecutionWork,
            required: 1,
            limit: 0,
        })
    ));
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
#[ignore = "requires the sealed Rebar Veryl pattern and haystack inputs"]
fn sealed_veryl_count_span_sum_and_captures_fit_default_execution_work() {
    let pattern_path = std::env::var("FRE_QUALIFICATION_VERYL_PATTERNS")
        .expect("qualification must bind the sealed Veryl pattern path");
    let haystack_path = std::env::var("FRE_QUALIFICATION_VERYL_HAYSTACK")
        .expect("qualification must bind the sealed Veryl haystack path");
    let pattern_text = std::fs::read_to_string(pattern_path).unwrap();
    let patterns = pattern_text.lines().map(str::to_owned).collect::<Vec<_>>();
    let haystack = std::fs::read(haystack_path).unwrap();
    assert_eq!(88, patterns.len());
    assert_eq!(150_600, haystack.len());

    let oracle = MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false)
                .case_insensitive(false),
        )
        .build_many(&patterns)
        .unwrap();
    let (oracle_count, oracle_span_sum) = oracle
        .find_iter(&haystack)
        .try_fold((0_u64, 0_u64), |(count, span_sum), matched| {
            Some((
                count.checked_add(1)?,
                span_sum.checked_add(
                    u64::try_from(matched.end().checked_sub(matched.start())?).ok()?,
                )?,
            ))
        })
        .unwrap();
    assert_eq!((62_400, 150_600), (oracle_count, oracle_span_sum));

    let count = AggregateManyBuilder::new(&patterns)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .unwrap();
    let span_sum = AggregateManyBuilder::new(&patterns)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_span_sum()
        .unwrap();
    let captures = AggregateManyBuilder::new(&patterns)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_capture_count()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        count.build_report().plan
    );
    assert_eq!(
        AggregateManyPlanKind::TotalByteCoverSpanSum,
        span_sum.build_report().plan
    );
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        captures.build_report().plan
    );
    let proof = captures
        .build_report()
        .byte_unit_cover
        .expect("Veryl capture patterns retain the complete byte-unit cover");
    assert_eq!(88, proof.patterns);
    assert_eq!(88, proof.nonnullable_patterns);
    assert_eq!(256, proof.covered_bytes);
    assert_eq!(
        oracle_count,
        count
            .count_value(&haystack, AggregateManyRunLimits::default())
            .unwrap()
    );
    assert_eq!(
        oracle_span_sum,
        span_sum
            .span_sum_value(&haystack, AggregateManyRunLimits::default())
            .unwrap()
    );
    assert_eq!(
        124_800,
        captures
            .count_captures_value(&haystack, AggregateManyCaptureRunLimits::default())
            .unwrap()
    );
    let capture_limits = AggregateManyCaptureRunLimits::default();
    let mut session = captures
        .prepare_cached_count_session(haystack.len(), capture_limits)
        .unwrap()
        .expect("Veryl byte-unit cover admits its caller-owned session");
    assert_eq!(
        124_800,
        captures
            .count_captures_value_with_session(&mut session, &haystack, capture_limits)
            .unwrap()
    );
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
