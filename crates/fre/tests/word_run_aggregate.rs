use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateWordRunSemantics,
    FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID, FIXED_CLASS_CHUNKS_PLAN_ID,
    FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID, RustProfile, WORD_RUN_COUNT_OPERATION_ID,
    WORD_RUN_SPAN_SUM_OPERATION_ID, WordRunBuildLimits, WordRunReduceError, WordRunReduceLimits,
    WordRunTopology,
};
use regex::bytes::RegexBuilder;

const WORD_RUN: &str = r"\b\w{12,}\b";
const ASCII_WORD_RUN: &str = r"(?-u:\b\w{12,}\b)";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .case_insensitive(false)
}

fn byte_builder(pattern: &str) -> AggregateBuilder {
    builder(pattern).unicode(false)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let spans: Vec<_> = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| matched.start()..matched.end())
        .collect();
    let count = u64::try_from(spans.len()).unwrap();
    let span_sum = spans
        .into_iter()
        .map(|span| u64::try_from(span.end.checked_sub(span.start).unwrap()).unwrap())
        .sum();
    (count, span_sum)
}

fn byte_oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let spans: Vec<_> = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| matched.start()..matched.end())
        .collect();
    let count = u64::try_from(spans.len()).unwrap();
    let span_sum = spans
        .into_iter()
        .map(|span| u64::try_from(span.end.checked_sub(span.start).unwrap()).unwrap())
        .sum();
    (count, span_sum)
}

fn durable_sibling_fixture() -> Vec<u8> {
    let mut haystack = "z".repeat(839);
    haystack.push(' ');
    haystack.push_str(&"α".repeat(1_313));
    haystack.push('a');
    haystack.into_bytes()
}

#[test]
fn durable_unicode_and_ascii_targets_select_operation_owned_word_runs() {
    let haystack = durable_sibling_fixture();
    for (pattern, expected, expected_unicode) in
        [(WORD_RUN, 3_466, true), (ASCII_WORD_RUN, 839, false)]
    {
        let regex = builder(pattern).build_span_sum().unwrap();
        assert_eq!(regex.build_report().plan, AggregatePlanKind::WordRun);
        let AggregatePlanIdentity::WordRun(identity) = regex.build_report().plan_identity else {
            panic!("target selected another aggregate identity");
        };
        assert_eq!(identity.kernel.minimum_scalars, 12);
        assert_eq!(identity.kernel.unicode, expected_unicode);
        assert_eq!(
            identity.kernel.topology,
            WordRunTopology::CompleteWordBoundaries
        );
        assert!(identity.kernel.complete_word_boundaries);
        assert_eq!(identity.kernel.operation_id, WORD_RUN_SPAN_SUM_OPERATION_ID);
        assert_eq!(
            identity.semantics,
            if expected_unicode {
                AggregateWordRunSemantics::UnicodeWordScalarsInvalidBytesNonWord
            } else {
                AggregateWordRunSemantics::AsciiWordBytes
            }
        );
        assert_eq!(
            regex
                .span_sum_value(&haystack, AggregateRunLimits::default())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn one_pass_reduction_matches_rust_across_boundaries_and_invalid_bytes() {
    let unicode = [
        b'!', 0xFF, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'-',
        0xCE, 0xB1, 0xCE, 0xB2, 0xCE, 0xB3, 0xCE, 0xB4, 0xCE, 0xB5, 0xCE, 0xB6, 0xCE, 0xB7, 0xCE,
        0xB8, 0xCE, 0xB9, 0xCE, 0xBA, 0xCE, 0xBB, 0xCE, 0xBC, b'?', 0xC3,
    ];
    for (pattern, haystack) in [
        (WORD_RUN, unicode.as_slice()),
        (
            ASCII_WORD_RUN,
            b"__abcdefghijkl--1234567890123--\xffword".as_slice(),
        ),
    ] {
        let expected = oracle(pattern, haystack);
        let count = builder(pattern).build_count().unwrap();
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(counted.value(), expected.0);
        let AggregateExecutionDetails::WordRun(accounting) = counted.report().details() else {
            panic!("count executed another family");
        };
        assert_eq!(accounting.actual.source_reads, haystack.len());
        assert!(accounting.actual.units <= accounting.upper_bounds.unit_events);
        assert!(accounting.actual.runs <= accounting.upper_bounds.run_events);
        assert!(accounting.actual.matches <= accounting.upper_bounds.match_events);
        assert!(accounting.actual.work <= accounting.upper_bounds.work);
        assert_eq!(accounting.actual.scratch_bytes, 0);

        let span_sum = builder(pattern).build_span_sum().unwrap();
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.1
        );
    }
}

#[test]
fn planner_and_build_fences_are_exact() {
    let baseline = builder(WORD_RUN).build_span_sum().unwrap();
    let report = baseline.build_report();
    let planner_work = report.word_run_planner_work;
    let AggregateBuildAccounting::WordRun(build) = report.build else {
        panic!("word-run retained another build receipt");
    };
    assert!(planner_work > 0);
    let exact_build = WordRunBuildLimits {
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        max_word_run_planner_work: planner_work,
        word_run: exact_build,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(WORD_RUN)
            .limits(exact_limits)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::WordRun
    );
    assert!(matches!(
        builder(WORD_RUN)
            .limits(AggregateBuildLimits {
                max_word_run_planner_work: planner_work - 1,
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::WordRunPlannerWorkLimit { needed, limit, .. })
            if needed == planner_work && limit == planner_work - 1
    ));
    assert!(matches!(
        builder(WORD_RUN)
            .limits(AggregateBuildLimits {
                word_run: WordRunBuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact_build
                },
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::WordRunBuild { .. })
    ));
}

#[test]
fn execution_fences_are_exact_and_preflighted() {
    let haystack = b"abcdefghijkl--short--mnopqrstuvwx";
    let baseline = builder(WORD_RUN).build_span_sum().unwrap();
    let baseline = baseline
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("word-run executed another family");
    };
    let upper = accounting.upper_bounds;
    let exact_run = WordRunReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_unit_events: upper.unit_events,
        max_run_events: upper.run_events,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    };
    let exact = AggregateRunLimits {
        word_run: exact_run,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        builder(WORD_RUN)
            .build_span_sum()
            .unwrap()
            .span_sum_value(haystack, exact)
            .unwrap(),
        24
    );
    let error = builder(WORD_RUN)
        .build_span_sum()
        .unwrap()
        .span_sum(
            haystack,
            AggregateRunLimits {
                word_run: WordRunReduceLimits {
                    max_work: upper.work - 1,
                    ..exact_run
                },
                ..exact
            },
        )
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
    ));
}

fn assert_count_value_success_and_replay(label: &str, builder: AggregateBuilder, haystack: &[u8]) {
    let regex = builder.build_count().unwrap();
    let baseline = regex
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(
        regex
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        baseline.value(),
        "count value for {label}",
    );
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("{label} executed another family");
    };
    let upper = accounting.upper_bounds;
    let work_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.count_value(haystack, work_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt(), "{label}");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
    ));

    let dual_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_input_bytes: upper.input_bytes - 1,
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.count_value(haystack, dual_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt(), "{label}");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::InputBytesLimit { needed, limit })
            if needed == upper.input_bytes && limit == upper.input_bytes - 1
    ));
}

fn assert_span_sum_value_success_and_replay(
    label: &str,
    builder: AggregateBuilder,
    haystack: &[u8],
) {
    let regex = builder.build_span_sum().unwrap();
    let baseline = regex
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(
        regex
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        baseline.value(),
        "span-sum value for {label}",
    );
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("{label} executed another family");
    };
    let upper = accounting.upper_bounds;
    let work_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.span_sum_value(haystack, work_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt(), "{label}");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
    ));

    let dual_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_input_bytes: upper.input_bytes - 1,
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.span_sum_value(haystack, dual_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt(), "{label}");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::InputBytesLimit { needed, limit })
            if needed == upper.input_bytes && limit == upper.input_bytes - 1
    ));
}

#[test]
fn fixed_chunk_compact_count_replays_word_run_fences() {
    assert_count_value_success_and_replay(
        "fixed-chunk target",
        byte_builder(r"[0-9A-Za-z_]{65}"),
        &[b'a'; 2 * 65 + 17],
    );
}

#[test]
fn fixed_chunk_compact_span_sum_replays_word_run_fences() {
    assert_span_sum_value_success_and_replay(
        "fixed-chunk target",
        byte_builder(r"[0-9A-Za-z_]{65}"),
        &[b'a'; 2 * 65 + 17],
    );
}

#[test]
fn unicode_count_remains_on_authoritative_route() {
    assert_count_value_success_and_replay(
        "Unicode non-target",
        builder(WORD_RUN),
        "abcdefghijkl--aα中_7ζηθικλμ--short".as_bytes(),
    );
}

#[test]
fn unicode_span_sum_remains_on_authoritative_route() {
    assert_span_sum_value_success_and_replay(
        "Unicode non-target",
        builder(WORD_RUN),
        "abcdefghijkl--aα中_7ζηθικλμ--short".as_bytes(),
    );
}

#[test]
fn ascii_compact_count_replays_word_run_fences() {
    let haystack = b"abcdefghijkl--short--mnopqrstuvwx";
    let regex = builder(ASCII_WORD_RUN).build_count().unwrap();
    let baseline = regex
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(
        regex
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        baseline.value(),
    );
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("ASCII word-run executed another family");
    };
    let upper = accounting.upper_bounds;
    let work_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.count_value(haystack, work_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
    ));

    let precedence_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_input_bytes: upper.input_bytes - 1,
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.count_value(haystack, precedence_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::InputBytesLimit { needed, limit })
            if needed == upper.input_bytes && limit == upper.input_bytes - 1
    ));
}

#[test]
fn ascii_compact_span_sum_replays_word_run_fences() {
    let haystack = b"abcdefghijkl--short--mnopqrstuvwx";
    let regex = builder(ASCII_WORD_RUN).build_span_sum().unwrap();
    let baseline = regex
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(
        regex
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        baseline.value(),
    );
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("ASCII word-run executed another family");
    };
    let upper = accounting.upper_bounds;
    let work_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.span_sum_value(haystack, work_refusal).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
    ));

    let precedence_refusal = AggregateRunLimits {
        word_run: WordRunReduceLimits {
            max_input_bytes: upper.input_bytes - 1,
            max_work: upper.work - 1,
            ..WordRunReduceLimits::unlimited()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex
        .span_sum_value(haystack, precedence_refusal)
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::InputBytesLimit { needed, limit })
            if needed == upper.input_bytes && limit == upper.input_bytes - 1
    ));
}

#[test]
fn captures_compile_and_near_misses_remain_explicit() {
    let captured = builder(r"((\b)(\w{12,})(\b))").build_count().unwrap();
    assert_eq!(captured.build_report().plan, AggregatePlanKind::WordRun);
    assert_eq!(captured.build_report().captures_erased, 4);
    let AggregatePlanIdentity::WordRun(identity) = captured.build_report().plan_identity else {
        panic!("captured word-run retained another identity");
    };
    assert_eq!(identity.kernel.operation_id, WORD_RUN_COUNT_OPERATION_ID);

    let compiled = builder(WORD_RUN).build_compile().unwrap();
    assert_eq!(compiled.build_report().plan, AggregatePlanKind::WordRun);
    assert_eq!(
        compiled
            .verify_count(b"abcdefghijkl--mnopqrstuvwx", AggregateRunLimits::default())
            .unwrap()
            .value(),
        2
    );

    for pattern in [
        r"\b\w{12,}?\b",
        r"\b\w{12,20}\b",
        r"\b\w{12,}",
        r"\w{12,}\b",
        r"\B\w{12,}\B",
    ] {
        assert_ne!(
            builder(pattern).build_count().unwrap().build_report().plan,
            AggregatePlanKind::WordRun,
            "pattern={pattern:?}"
        );
    }
    assert_ne!(
        builder(WORD_RUN)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::WordRun
    );
    assert_ne!(
        builder(WORD_RUN)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::WordRun
    );
    assert_eq!(
        builder(WORD_RUN)
            .build_spans()
            .unwrap()
            .build_report()
            .operation,
        AggregateOperation::Spans
    );
}

#[test]
fn exact_byte_class_repetitions_emit_every_leftmost_chunk() {
    const WIDTH: usize = 65;
    const PATTERN: &str = r"[\x00-\x02a-c\x80-\x82\xff]{65}";
    let mut haystack = vec![b'a'; 2 * WIDTH + 7];
    haystack.push(b'x');
    haystack.extend(core::iter::repeat_n(0xFF, 3 * WIDTH + 1));
    haystack.push(b'x');
    haystack.extend([0x80; WIDTH - 1]);
    let expected = byte_oracle(PATTERN, &haystack);
    assert_eq!(expected, (5, u64::try_from(5 * WIDTH).unwrap()));

    let count = byte_builder(PATTERN).build_count().unwrap();
    assert_eq!(count.build_report().plan, AggregatePlanKind::WordRun);
    let AggregatePlanIdentity::WordRun(identity) = count.build_report().plan_identity else {
        panic!("fixed byte-class chunks retained another identity");
    };
    assert_eq!(
        identity.semantics,
        AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks
    );
    assert_eq!(identity.kernel.plan_id, FIXED_CLASS_CHUNKS_PLAN_ID);
    assert_eq!(
        identity.kernel.operation_id,
        FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID
    );
    assert_eq!(identity.kernel.minimum_scalars, 0);
    assert_eq!(identity.kernel.fixed_chunk_bytes, Some(WIDTH));
    assert!(!identity.kernel.unicode);
    assert_eq!(identity.kernel.topology, WordRunTopology::FixedClassChunks);
    assert!(!identity.kernel.complete_word_boundaries);
    assert!(!identity.kernel.invalid_bytes_are_non_word);
    assert!(identity.kernel.arbitrary_bytes_are_classified);
    assert!(identity.kernel.non_overlapping);
    assert_ne!(identity.kernel.canonical_class_words, [0; 4]);
    let counted = count
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), expected.0);
    let AggregateExecutionDetails::WordRun(accounting) = counted.report().details() else {
        panic!("fixed byte-class count executed another family");
    };
    assert_eq!(accounting.actual.source_reads, haystack.len());
    assert_eq!(
        accounting.actual.matches,
        usize::try_from(expected.0).unwrap()
    );
    assert_eq!(accounting.actual.scratch_bytes, 0);
    assert!(accounting.actual.work <= accounting.upper_bounds.work);

    let span_sum = byte_builder(PATTERN).build_span_sum().unwrap();
    let AggregatePlanIdentity::WordRun(identity) = span_sum.build_report().plan_identity else {
        panic!("fixed byte-class span sum retained another identity");
    };
    assert_eq!(
        identity.kernel.operation_id,
        FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID
    );
    assert_eq!(
        span_sum
            .span_sum_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.1
    );
}

#[test]
fn fixed_class_chunks_erase_captures_and_preserve_incumbent_short_width_routes() {
    let captured = byte_builder(r"((?:[a-c\xff]{65}))")
        .build_span_sum()
        .unwrap();
    assert_eq!(captured.build_report().plan, AggregatePlanKind::WordRun);
    assert_eq!(captured.build_report().captures_erased, 1);
    let AggregatePlanIdentity::WordRun(identity) = captured.build_report().plan_identity else {
        panic!("captured chunks retained another identity");
    };
    assert_eq!(
        identity.semantics,
        AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks
    );
    assert_eq!(identity.kernel.topology, WordRunTopology::FixedClassChunks);
    let mut haystack = vec![0xFF; 130];
    haystack.push(b'x');
    haystack.extend([b'a'; 65]);
    assert_eq!(
        captured
            .span_sum_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        195
    );

    let width_one = byte_builder(r"[a-c\xff]{1}").build_count().unwrap();
    if let AggregatePlanIdentity::WordRun(identity) = width_one.build_report().plan_identity {
        assert_ne!(
            identity.semantics,
            AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks,
            "the new fallback must not steal incumbent <=64 routes"
        );
    }
    assert_eq!(
        width_one
            .count_value(b"abx\xff", AggregateRunLimits::default())
            .unwrap(),
        3
    );
}

#[test]
fn fixed_class_chunk_bounds_scale_for_n_2n_and_4n_without_scratch() {
    const WIDTH: usize = 65;
    let plan = byte_builder(r"[a-z]{65}").build_count().unwrap();
    let mut prior_work = 0;
    for factor in [1, 2, 4] {
        let haystack = vec![b'a'; factor * WIDTH];
        let result = plan
            .count(&haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(result.value(), u64::try_from(factor).unwrap());
        let AggregateExecutionDetails::WordRun(accounting) = result.report().details() else {
            panic!("scaled chunks executed another family");
        };
        assert_eq!(accounting.actual.source_reads, haystack.len());
        assert_eq!(accounting.actual.units, haystack.len());
        assert_eq!(accounting.actual.matches, factor);
        assert_eq!(accounting.actual.scratch_bytes, 0);
        assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
        assert_eq!(
            accounting.upper_bounds.count,
            u64::try_from(factor).unwrap()
        );
        assert!(accounting.actual.work > prior_work);
        prior_work = accounting.actual.work;
    }
}

#[test]
fn fixed_class_chunk_planner_build_and_execution_fences_are_exact() {
    std::thread::Builder::new()
        .name("fixed-class-chunk-fences".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(fixed_class_chunk_planner_build_and_execution_fences_body)
        .unwrap()
        .join()
        .unwrap();
}

#[allow(
    clippy::too_many_lines,
    reason = "one fence audit keeps the exact build and execution prospective dimensions adjacent"
)]
fn fixed_class_chunk_planner_build_and_execution_fences_body() {
    const PATTERN: &str = r"[0-9A-Za-z_]{256}";
    let baseline = byte_builder(PATTERN).build_span_sum().unwrap();
    let report = baseline.build_report();
    let planner_work = report.word_run_planner_work;
    let AggregateBuildAccounting::WordRun(build) = report.build else {
        panic!("fixed-class chunks retained another build receipt");
    };
    let exact_build = WordRunBuildLimits {
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        max_word_run_planner_work: planner_work,
        word_run: exact_build,
        ..AggregateBuildLimits::default()
    };
    let planner_one_below = planner_work.checked_sub(1).unwrap();
    assert_eq!(
        byte_builder(PATTERN)
            .limits(exact_limits)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::WordRun
    );
    assert!(matches!(
        byte_builder(PATTERN)
            .limits(AggregateBuildLimits {
                max_word_run_planner_work: planner_one_below,
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::WordRunPlannerWorkLimit { needed, limit, .. })
            if needed == planner_work && limit == planner_one_below
    ));

    macro_rules! assert_build_one_below {
        ($build_field:ident, $limit_field:ident) => {
            if build.$build_field > 0 {
                let mut one_below = exact_build;
                one_below.$limit_field = build.$build_field - 1;
                assert!(matches!(
                    byte_builder(PATTERN)
                        .limits(AggregateBuildLimits {
                            word_run: one_below,
                            ..exact_limits
                        })
                        .build_span_sum(),
                    Err(AggregateBuildError::WordRunBuild { .. })
                ));
            }
        };
    }
    assert_build_one_below!(work_upper_bound, max_build_work);
    assert_build_one_below!(persistent_bytes, max_persistent_bytes);
    assert_build_one_below!(peak_bytes, max_peak_bytes);

    let haystack = vec![b'b'; 2 * 256 + 17];
    let baseline = baseline
        .span_sum(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details() else {
        panic!("fixed-class chunks executed another family");
    };
    let upper = accounting.upper_bounds;
    let exact_run = WordRunReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_unit_events: upper.unit_events,
        max_run_events: upper.run_events,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    };
    let exact = AggregateRunLimits {
        word_run: exact_run,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        byte_builder(PATTERN)
            .build_span_sum()
            .unwrap()
            .span_sum_value(&haystack, exact)
            .unwrap(),
        512
    );

    macro_rules! assert_run_one_below {
        ($upper_field:ident, $limit_field:ident, $variant:ident) => {
            if upper.$upper_field > 0 {
                let mut one_below = exact_run;
                one_below.$limit_field = upper.$upper_field - 1;
                let error = byte_builder(PATTERN)
                    .build_span_sum()
                    .unwrap()
                    .span_sum(
                        &haystack,
                        AggregateRunLimits {
                            word_run: one_below,
                            ..exact
                        },
                    )
                    .unwrap_err();
                assert!(error.has_closed_direct_attempt());
                assert!(matches!(
                    error.source,
                    AggregateExecutionSource::WordRun(WordRunReduceError::$variant {
                        needed,
                        limit
                    }) if needed == upper.$upper_field && limit == upper.$upper_field - 1
                ));
            }
        };
    }
    assert_run_one_below!(input_bytes, max_input_bytes, InputBytesLimit);
    assert_run_one_below!(source_reads, max_source_reads, SourceReadsLimit);
    assert_run_one_below!(work, max_work, WorkLimit);
    assert_run_one_below!(unit_events, max_unit_events, UnitEventsLimit);
    assert_run_one_below!(run_events, max_run_events, RunEventsLimit);
    assert_run_one_below!(match_events, max_match_events, MatchEventsLimit);
    assert_run_one_below!(count, max_count, CountLimit);
    assert_run_one_below!(span_sum, max_span_sum, SpanSumLimit);
    assert_run_one_below!(persistent_bytes, max_persistent_bytes, PersistentLimit);
    assert_run_one_below!(peak_bytes, max_peak_bytes, PeakLimit);

    let receipt = report
        .construction_attempt_receipt()
        .expect("fixed-class chunk construction receipt");
    let selected = receipt
        .ledger
        .iter()
        .find(|entry| {
            entry.stage == fre::AggregateConstructionStage::WordRun
                && entry.disposition == fre::AggregateConstructionStageDisposition::Published
        })
        .expect("selected fixed-class chunk construction effect");
    let incumbent = byte_builder(ASCII_WORD_RUN).build_span_sum().unwrap();
    let incumbent_effect = incumbent
        .build_report()
        .construction_attempt_receipt()
        .expect("incumbent word-run construction receipt")
        .ledger
        .iter()
        .find(|entry| {
            entry.stage == fre::AggregateConstructionStage::WordRun
                && entry.disposition == fre::AggregateConstructionStageDisposition::Published
        })
        .expect("selected incumbent word-run construction effect")
        .effect;
    assert_eq!(selected.effect.allocations, 1);
    assert_eq!(incumbent_effect.allocations, 2);
    assert!(
        incumbent_effect.allocated_bytes > selected.effect.allocated_bytes,
        "the ASCII incumbent additionally retains its exact run-scanner owner"
    );
}
