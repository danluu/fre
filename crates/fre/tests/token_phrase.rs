use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateRunLimits, AggregateTokenPhraseSemantics, RustProfile,
    TOKEN_PHRASE_COUNT_OPERATION_ID, TOKEN_PHRASE_SPAN_SUM_OPERATION_ID, TokenPhraseBuildLimits,
    TokenPhraseReduceError, TokenPhraseReduceLimits, TokenPhraseTopology, TokenPhraseUpperBounds,
};
use regex::bytes::RegexBuilder;

const ASSERTED: &str = r"\b\w+\s+Holmes\s+\w+\b";
const UNASSERTED: &str = r"\w+\s+Holmes\s+\w+";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |sum, matched| {
            (
                sum.0.checked_add(1).unwrap(),
                sum.1
                    .checked_add(u64::try_from(matched.len()).unwrap())
                    .unwrap(),
            )
        })
}

#[test]
fn asserted_and_unasserted_shapes_select_operation_owned_leaf() {
    let haystack = b"Sherlock Holmes wat--A Holmes B; C X Holmes Y; Mycroft  Holmes \t too\xff";
    for (pattern, asserted) in [(ASSERTED, true), (UNASSERTED, false)] {
        let expected = oracle(pattern, haystack);
        let count = builder(pattern).build_count().unwrap();
        assert_eq!(count.build_report().plan, AggregatePlanKind::TokenPhrase);
        assert_eq!(count.build_report().schema_version, 37);
        let AggregatePlanIdentity::TokenPhrase(count_identity) = count.build_report().plan_identity
        else {
            panic!("token phrase count selected another identity");
        };
        assert_eq!(
            count_identity.semantics,
            AggregateTokenPhraseSemantics::UnicodeOffAsciiWordSpaceTokens
        );
        assert_eq!(
            count_identity.kernel.topology,
            TokenPhraseTopology::WordSpaceLiteralSpaceWord
        );
        assert_eq!(count_identity.kernel.literal_bytes, 6);
        assert_eq!(count_identity.kernel.outer_word_assertions, asserted);
        assert_eq!(
            count_identity.kernel.operation_id,
            TOKEN_PHRASE_COUNT_OPERATION_ID
        );
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.0
        );

        let span_sum = builder(pattern).build_span_sum().unwrap();
        let AggregatePlanIdentity::TokenPhrase(span_identity) =
            span_sum.build_report().plan_identity
        else {
            panic!("token phrase span sum selected another identity");
        };
        assert_eq!(
            span_identity.kernel.operation_id,
            TOKEN_PHRASE_SPAN_SUM_OPERATION_ID
        );
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.1
        );

        let compiled = builder(pattern).build_compile().unwrap();
        assert_eq!(compiled.build_report().plan, AggregatePlanKind::TokenPhrase);
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected.0
        );
    }
}

#[test]
fn captures_are_transparent_and_nearby_profiles_do_not_claim_the_leaf() {
    let captured = builder(r"(\b)((\w+))(\s+)(Holmes)(\s+)((\w+))(\b)")
        .build_span_sum()
        .unwrap();
    assert_eq!(captured.build_report().plan, AggregatePlanKind::TokenPhrase);
    assert_eq!(captured.build_report().captures_erased, 9);
    assert_eq!(
        captured
            .span_sum_value(b"Sherlock Holmes wat", AggregateRunLimits::default())
            .unwrap(),
        19
    );

    for pattern in [
        r"\b[A-Za-z]+\s+Holmes\s+\w+\b",
        r"\b\w+ +Holmes\s+\w+\b",
        r"\b\w*\s+Holmes\s+\w+\b",
        r"\b\w+?\s+Holmes\s+\w+\b",
        r"\b\w+\s+Hol-mes\s+\w+\b",
        r"\b\w+\s+Holmes\s+\w+",
    ] {
        assert_ne!(
            builder(pattern).build_count().unwrap().build_report().plan,
            AggregatePlanKind::TokenPhrase,
            "pattern={pattern:?}"
        );
    }
    assert_ne!(
        builder(ASSERTED)
            .unicode(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::TokenPhrase
    );
    assert_ne!(
        builder(ASSERTED)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::TokenPhrase
    );
    assert_eq!(
        builder(ASSERTED).build_spans().unwrap().build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        builder(ASSERTED)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn planner_build_and_execution_fences_are_exact() {
    let baseline = builder(ASSERTED).build_span_sum().unwrap();
    let report = baseline.build_report();
    let planner_work = report.token_phrase_planner_work;
    let AggregateBuildAccounting::TokenPhrase(build) = report.build else {
        panic!("token phrase retained another build receipt");
    };
    let exact_build = TokenPhraseBuildLimits {
        max_literal_bytes: build.literal_bytes,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        max_token_phrase_planner_work: planner_work,
        token_phrase: exact_build,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(ASSERTED)
            .limits(exact_limits)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::TokenPhrase
    );
    assert!(matches!(
        builder(ASSERTED)
            .limits(AggregateBuildLimits {
                max_token_phrase_planner_work: planner_work - 1,
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::TokenPhrasePlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));
    assert!(matches!(
        builder(ASSERTED)
            .limits(AggregateBuildLimits {
                token_phrase: TokenPhraseBuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact_build
                },
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::TokenPhraseBuild { .. })
    ));

    let haystack = b"Sherlock Holmes wat and Mycroft Holmes too";
    let result = baseline
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::TokenPhrase(accounting) = result.report().details() else {
        panic!("token phrase executed another family");
    };
    let upper = accounting.upper_bounds;
    let exact_run = exact_run_limits(upper);
    let exact_run_limits = AggregateRunLimits {
        token_phrase: exact_run,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        baseline.span_sum_value(haystack, exact_run_limits).unwrap(),
        37
    );
    let error = baseline
        .span_sum(
            haystack,
            AggregateRunLimits {
                token_phrase: TokenPhraseReduceLimits {
                    max_work: upper.work - 1,
                    ..exact_run
                },
                ..exact_run_limits
            },
        )
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::TokenPhrase(TokenPhraseReduceError::WorkLimit {
            needed,
            limit
        }) if needed == upper.work && limit == upper.work - 1
    ));
}

fn exact_run_limits(upper: TokenPhraseUpperBounds) -> TokenPhraseReduceLimits {
    TokenPhraseReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_classifications: upper.classifications,
        max_literal_comparisons: upper.literal_comparisons,
        max_token_events: upper.token_events,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    }
}
