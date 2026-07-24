use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateWordRunSemantics,
    RustProfile, WORD_RUN_COUNT_OPERATION_ID, WORD_RUN_SPAN_SUM_OPERATION_ID, WordRunBuildLimits,
    WordRunReduceError, WordRunReduceLimits,
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
        let AggregateExecutionDetails::WordRun(accounting) = &counted.report().details else {
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
    let AggregateExecutionDetails::WordRun(accounting) = baseline.report().details else {
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
    assert!(matches!(
        error.source,
        AggregateExecutionSource::WordRun(WordRunReduceError::WorkLimit { needed, limit })
            if needed == upper.work && limit == upper.work - 1
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
