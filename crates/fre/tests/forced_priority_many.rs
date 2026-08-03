use core::mem::size_of;

use fre::{
    AggregateManyBuilder, AggregateManyPlanKind, CaptureBuilder,
    PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID, PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
    PriorityAggregateManyBuildError, PriorityAggregateManyBuildLimits,
    PriorityAggregateManyBuilder, PriorityAggregateManyCaptureBuildLimits,
    PriorityAggregateManyCaptureBuildResource, PriorityAggregateManyCaptureRunLimits,
    PriorityAggregateManyRunFailure, PriorityAggregateManyRunLimits,
};
use fre_automata::{
    ActionCapabilities, DirectReduceLimits, ForcedExecution, PreparationLimits, PriorityTarget,
    ReduceError, TAGGED_MANY_ACCOUNTING_ID, TaggedManyBuildError, TaggedManyBuildLimits,
    TaggedManyExecutionClass,
};
use fre_syntax::RustProfile;
use regex_automata::meta::Regex as MetaRegex;

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn build_count(values: &[String]) -> fre::PriorityAggregateManyCountRegex {
    PriorityAggregateManyBuilder::new(values)
        .unicode(false)
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap()
}

fn traced_ids(trace: &fre::PriorityAggregateManyTraceReceipt) -> Vec<(u32, usize, usize)> {
    trace
        .matches()
        .iter()
        .map(|matched| (matched.ordinal().get(), matched.start(), matched.end()))
        .collect()
}

fn rebar_byte_profile() -> RustProfile {
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = false;
    profile
}

fn assert_count_and_span_trace_with_profile(
    values: &[&str],
    haystack: &[u8],
    profile: RustProfile,
    expected: &[(u32, usize, usize)],
) {
    let values = patterns(values);
    let expected_count = u64::try_from(expected.len()).unwrap();
    let expected_span_sum = expected.iter().try_fold(0_u64, |total, &(_, start, end)| {
        total.checked_add(u64::try_from(end.checked_sub(start)?).ok()?)
    });
    let expected_span_sum = expected_span_sum.unwrap();
    let expected_empty = expected
        .iter()
        .filter(|(_, start, end)| start == end)
        .count();
    let expected_ordinal_sum = expected.iter().try_fold(0_u64, |total, &(ordinal, _, _)| {
        total.checked_add(u64::from(ordinal))
    });
    let expected_ordinal_sum = expected_ordinal_sum.unwrap();
    let limits = PriorityAggregateManyRunLimits::unlimited();

    let count = PriorityAggregateManyBuilder::new(&values)
        .profile(profile.clone())
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let count_trace = count.count_trace(haystack, limits).unwrap();
    let count_receipt = count_trace.execution();
    assert_eq!(
        expected,
        traced_ids(&count_trace),
        "{values:?}/{haystack:?}"
    );
    assert_eq!(expected_count, count_receipt.value());
    assert_eq!(haystack.len(), count_receipt.actual().source_bytes);
    assert_eq!(
        haystack.len().checked_add(1).unwrap(),
        count_receipt.actual().boundary_rows
    );
    assert_eq!(expected.len(), count_receipt.actual().match_events);
    assert_eq!(expected_empty, count_receipt.actual().empty_match_events);
    assert_eq!(
        expected_span_sum,
        count_receipt.actual().selected_span_bytes
    );
    assert_eq!(
        expected_ordinal_sum,
        count_receipt.actual().selected_ordinal_sum
    );
    assert!(count_receipt.closes());
    assert!(count_trace.closes());

    let span_sum = PriorityAggregateManyBuilder::new(&values)
        .profile(profile)
        .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let span_trace = span_sum.span_sum_trace(haystack, limits).unwrap();
    let span_receipt = span_trace.execution();
    assert_eq!(expected, traced_ids(&span_trace), "{values:?}/{haystack:?}");
    assert_eq!(expected_span_sum, span_receipt.value());
    assert_eq!(count_receipt.actual(), span_receipt.actual());
    assert!(span_receipt.closes());
    assert!(span_trace.closes());
}

fn assert_count_and_span_trace(values: &[&str], haystack: &[u8], expected: &[(u32, usize, usize)]) {
    assert_count_and_span_trace_with_profile(values, haystack, rebar_byte_profile(), expected);
}

#[test]
fn forced_shared_automaton_preserves_priority_greediness_and_ids() {
    let greedy = patterns(&[r"a+", "a"]);
    let lazy = patterns(&["a", r"a+"]);
    let duplicate = patterns(&["a", "a", "ab"]);

    let greedy = build_count(&greedy);
    let lazy = build_count(&lazy);
    let duplicate = build_count(&duplicate);
    let limits = PriorityAggregateManyRunLimits::unlimited();

    let greedy_trace = greedy.count_trace(b"aa", limits).unwrap();
    let greedy_receipt = greedy_trace.execution();
    assert_eq!(1, greedy_receipt.value());
    assert_eq!(vec![(0, 0, 2)], traced_ids(&greedy_trace));
    assert_eq!(0, greedy_receipt.actual().selected_ordinal_sum);
    assert!(greedy_receipt.closes());
    assert!(greedy_trace.closes());

    let lazy_trace = lazy.count_trace(b"aa", limits).unwrap();
    let lazy_receipt = lazy_trace.execution();
    assert_eq!(2, lazy_receipt.value());
    assert_eq!(vec![(0, 0, 1), (0, 1, 2)], traced_ids(&lazy_trace));
    assert!(lazy_receipt.closes());
    assert!(lazy_trace.closes());

    let duplicate_trace = duplicate.count_trace(b"ab", limits).unwrap();
    assert_eq!(vec![(0, 0, 1)], traced_ids(&duplicate_trace));
    assert!(duplicate_trace.closes());
    assert!(duplicate.build_report().closes());
    assert_eq!(3, duplicate.build_report().patterns().len());
    assert_eq!(2, duplicate.build_report().patterns()[2].ordinal);
}

#[test]
fn forced_shared_automaton_preserves_start_generation_and_delayed_failure() {
    assert_count_and_span_trace(&["b", r"a.*b"], b"aab", &[(1, 0, 3)]);
    assert_count_and_span_trace(&["abx", "b"], b"ab", &[(1, 1, 2)]);
    assert_count_and_span_trace(
        &["abc", "ab", "."],
        b"abxabc",
        &[(1, 0, 2), (2, 2, 3), (0, 3, 6)],
    );
}

#[test]
fn forced_shared_automaton_preserves_internal_alternation_and_greedy_endpoints() {
    assert_count_and_span_trace(&[r"(?:a|ab)", "."], b"ab", &[(0, 0, 1), (1, 1, 2)]);
    assert_count_and_span_trace(&[r"(?:ab|a)", "."], b"ab", &[(0, 0, 2)]);
    assert_count_and_span_trace(
        &[r"a.*?b", "."],
        b"a1b2b",
        &[(0, 0, 3), (1, 3, 4), (1, 4, 5)],
    );
    assert_count_and_span_trace(&[r"a.*b", "."], b"a1b2b", &[(0, 0, 5)]);
}

#[test]
fn forced_shared_automaton_preserves_duplicate_and_merged_suffix_provenance() {
    assert_count_and_span_trace(
        &["z", "ab", "ab", "a"],
        b"ababa",
        &[(1, 0, 2), (1, 2, 4), (3, 4, 5)],
    );
    assert_count_and_span_trace(&["ab", "b"], b"b ab", &[(1, 0, 1), (0, 2, 4)]);
}

#[test]
fn forced_shared_automaton_preserves_empty_suppression_and_invalid_byte_progress() {
    assert_count_and_span_trace(&["a", ""], b"ab", &[(0, 0, 1), (1, 2, 2)]);
    assert_count_and_span_trace(
        &["", "", "a"],
        &[0xFF, b'a'],
        &[(0, 0, 0), (0, 1, 1), (0, 2, 2)],
    );
    assert_count_and_span_trace(&[r"a*?", "a"], b"a", &[(0, 0, 0), (0, 1, 1)]);
    assert_count_and_span_trace(&[r"a*", ""], b"aa", &[(0, 0, 2)]);
}

#[test]
fn forced_shared_automaton_preserves_absolute_line_word_and_end_context() {
    assert_count_and_span_trace(&[r"\Aab", "ab"], b"zab", &[(1, 1, 3)]);
    assert_count_and_span_trace(&[r"(?m:^ab)", "ab"], b"z\nab", &[(0, 2, 4)]);
    assert_count_and_span_trace(&[r"(?m:ab$)", "ab"], b"ab\nabx", &[(0, 0, 2), (1, 3, 5)]);
    assert_count_and_span_trace(&[r"\bcat", "cat"], b"xcat cat", &[(1, 1, 4), (0, 5, 8)]);
    assert_count_and_span_trace(&[r"ab\z", "ab"], b"abxab", &[(1, 0, 2), (0, 3, 5)]);
}

#[test]
fn forced_shared_automaton_preserves_case_folding_and_inline_ungreedy() {
    let mut case_insensitive = rebar_byte_profile();
    case_insensitive.options.case_insensitive = true;
    assert_count_and_span_trace_with_profile(
        &["ab", "A"],
        b"ABa",
        case_insensitive,
        &[(0, 0, 2), (1, 2, 3)],
    );

    assert_count_and_span_trace(&[r"(?U:a+)", "a"], b"aa", &[(0, 0, 1), (0, 1, 2)]);
}

#[test]
fn forced_sparse_empty_progress_suppresses_adjacent_empty_after_consuming_match() {
    let consuming_first = patterns(&["a", ""]);
    let empty_first = patterns(&["", "a"]);
    let consuming_first = build_count(&consuming_first);
    let empty_first = build_count(&empty_first);
    let limits = PriorityAggregateManyRunLimits::unlimited();

    let consuming_trace = consuming_first.count_trace(b"a", limits).unwrap();
    let consuming = consuming_trace.execution();
    assert_eq!(1, consuming.value());
    assert_eq!(vec![(0, 0, 1)], traced_ids(&consuming_trace));
    assert!(consuming_trace.closes());

    let empty_trace = empty_first.count_trace(b"a", limits).unwrap();
    let empty = empty_trace.execution();
    assert_eq!(2, empty.value());
    assert_eq!(vec![(0, 0, 0), (0, 1, 1)], traced_ids(&empty_trace));
    assert!(empty_trace.closes());
}

#[test]
fn forced_shared_automaton_reduces_span_sum_without_losing_pattern_ids() {
    let values = patterns(&[r"a+", "a", ""]);
    let regex = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let trace = regex
        .span_sum_trace(b"aa", PriorityAggregateManyRunLimits::unlimited())
        .unwrap();
    let receipt = trace.execution();

    assert_eq!(2, receipt.value());
    assert_eq!(vec![(0, 0, 2)], traced_ids(&trace));
    assert!(receipt.closes());
    assert!(trace.closes());
    assert!(regex.build_report().closes());
}

#[test]
fn forced_shared_automaton_preserves_earliest_start_and_anchor_context() {
    let values = patterns(&[r"\Aaa", "bc", "a"]);
    let regex = build_count(&values);
    let trace = regex
        .count_trace(b"bcaa", PriorityAggregateManyRunLimits::unlimited())
        .unwrap();
    let result = trace.execution();
    assert_eq!(3, result.value());
    assert_eq!(vec![(1, 0, 2), (2, 2, 3), (2, 3, 4)], traced_ids(&trace));
    assert!(trace.closes());
}

#[test]
fn forced_shared_automaton_matches_pinned_ordered_pattern_id_sequence_exhaustively() {
    let pattern_sets = [
        patterns(&["ab", "a"]),
        patterns(&["a", "ab"]),
        patterns(&["", "a"]),
        patterns(&["a", ""]),
        patterns(&[r"\Aab", "."]),
        patterns(&[r"a+", "a"]),
        patterns(&[r"a+?", "a"]),
        patterns(&["a", "a", "ab"]),
    ];
    let haystacks = byte_strings(3, &[b'a', b'b', 0xFF]);

    for values in pattern_sets {
        let upstream = MetaRegex::builder()
            .configure(MetaRegex::config().utf8_empty(false))
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .utf8(false)
                    .unicode(false),
            )
            .build_many(&values)
            .unwrap();
        let fre = build_count(&values);
        for haystack in &haystacks {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| (matched.pattern().as_usize(), matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let trace = fre
                .count_trace(haystack, PriorityAggregateManyRunLimits::unlimited())
                .unwrap();
            let receipt = trace.execution();
            let actual = trace
                .matches()
                .iter()
                .map(|matched| {
                    (
                        usize::try_from(matched.ordinal().get()).unwrap(),
                        matched.start(),
                        matched.end(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(expected, actual, "{values:?}/{haystack:?}");
            assert_eq!(u64::try_from(expected.len()).unwrap(), receipt.value());
            assert!(receipt.closes());
            assert!(trace.closes());
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact build and trace one-below fences share one immutable baseline"
)]
fn forced_build_and_run_admit_exact_limits_and_refuse_one_below() {
    let values = patterns(&[r"a+", "b", ""]);
    let baseline = build_count(&values);
    let build = baseline.build_report();
    let exact_build = PriorityAggregateManyBuildLimits {
        max_composition_scratch_bytes: build.composition().preflight_scratch_bytes,
        max_persistent_bytes: build.composition().preflight_persistent_bytes,
        ..PriorityAggregateManyBuildLimits::default()
    };
    let exact = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .limits(exact_build)
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert!(exact.build_report().closes());

    let exact_allocation = PriorityAggregateManyBuildLimits {
        max_composition_allocation_attempts: 19,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert_eq!(19, build.composition().allocation_attempts);
    assert!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(exact_allocation)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
            .build_report()
            .closes()
    );
    let below_allocation = PriorityAggregateManyBuildLimits {
        max_composition_allocation_attempts: 18,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(below_allocation)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::CompositionAllocationAttemptsLimit { needed, limit })
            if needed == 19 && limit == 18
    ));

    let below_build = PriorityAggregateManyBuildLimits {
        max_composition_scratch_bytes: build.composition().preflight_scratch_bytes - 1,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(below_build)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::CompositionScratchLimit { needed, limit })
            if needed == build.composition().preflight_scratch_bytes
                && limit + 1 == build.composition().preflight_scratch_bytes
    ));

    let haystack = b"aabba";
    let probe = baseline
        .count(haystack, PriorityAggregateManyRunLimits::unlimited())
        .unwrap();
    let prospective = probe.prospective();
    let exact_execution = DirectReduceLimits {
        max_work: prospective.work_upper_bound,
        max_scratch_bytes: prospective.scratch_bytes,
        max_boundary_rows: prospective.boundary_rows,
        max_match_events: prospective.match_events_upper_bound,
        max_dfa_states: prospective.dfa_states_capacity,
        max_dfa_cells: prospective.dfa_cells_capacity,
        max_subset_items: prospective.subset_items_capacity,
        max_tagged_dispatch_states: prospective.tagged_dispatch_states_capacity,
        max_tagged_dispatch_cells: prospective.tagged_dispatch_cells_capacity,
        max_tagged_candidate_items: prospective.tagged_candidate_items_capacity,
        max_tagged_cache_cells: prospective.tagged_cache_cells_capacity,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    let exact_run = PriorityAggregateManyRunLimits {
        execution: exact_execution,
        max_output: u64::try_from(haystack.len() + 1).unwrap(),
    };
    assert_eq!(probe, baseline.count(haystack, exact_run).unwrap());
    let below_run = PriorityAggregateManyRunLimits {
        execution: DirectReduceLimits {
            max_work: exact_execution.max_work - 1,
            ..exact_execution
        },
        ..exact_run
    };
    assert!(matches!(
        baseline.count(haystack, below_run).unwrap_err().source,
        PriorityAggregateManyRunFailure::Execution(ReduceError::WorkLimit { .. })
    ));

    let below_scratch = PriorityAggregateManyRunLimits {
        execution: DirectReduceLimits {
            max_scratch_bytes: exact_execution.max_scratch_bytes - 1,
            ..exact_execution
        },
        ..exact_run
    };
    assert!(matches!(
        baseline.count(haystack, below_scratch).unwrap_err().source,
        PriorityAggregateManyRunFailure::Execution(ReduceError::ScratchLimit { .. })
    ));

    let trace_probe = baseline
        .count_trace(haystack, PriorityAggregateManyRunLimits::unlimited())
        .unwrap();
    let trace_prospective = trace_probe.execution().prospective();
    assert_eq!(haystack.len() + 1, trace_probe.trace_capacity());
    assert_eq!(
        Some(
            probe.prospective().scratch_bytes
                + (haystack.len() + 1) * size_of::<fre_automata::PriorityMatch>(),
        ),
        Some(trace_prospective.scratch_bytes)
    );
    assert_eq!(
        probe.prospective().allocation_attempts + 1,
        trace_prospective.allocation_attempts
    );
    assert_eq!(
        probe.prospective().work_upper_bound + u64::try_from(haystack.len() + 2).unwrap(),
        trace_prospective.work_upper_bound
    );
    let exact_trace = PriorityAggregateManyRunLimits {
        execution: DirectReduceLimits {
            max_work: trace_prospective.work_upper_bound,
            max_scratch_bytes: trace_prospective.scratch_bytes,
            max_boundary_rows: trace_prospective.boundary_rows,
            max_match_events: trace_prospective.match_events_upper_bound,
            max_dfa_states: trace_prospective.dfa_states_capacity,
            max_dfa_cells: trace_prospective.dfa_cells_capacity,
            max_subset_items: trace_prospective.subset_items_capacity,
            max_tagged_dispatch_states: trace_prospective.tagged_dispatch_states_capacity,
            max_tagged_dispatch_cells: trace_prospective.tagged_dispatch_cells_capacity,
            max_tagged_candidate_items: trace_prospective.tagged_candidate_items_capacity,
            max_tagged_cache_cells: trace_prospective.tagged_cache_cells_capacity,
            max_allocation_attempts: trace_prospective.allocation_attempts,
        },
        ..exact_run
    };
    assert_eq!(
        trace_probe,
        baseline.count_trace(haystack, exact_trace).unwrap()
    );
    let below_trace_scratch = PriorityAggregateManyRunLimits {
        execution: DirectReduceLimits {
            max_scratch_bytes: trace_prospective.scratch_bytes - 1,
            ..exact_trace.execution
        },
        ..exact_trace
    };
    assert!(matches!(
        baseline
            .count_trace(haystack, below_trace_scratch)
            .unwrap_err()
            .source,
        PriorityAggregateManyRunFailure::Execution(ReduceError::ScratchLimit { .. })
    ));
    let below_trace_allocation = PriorityAggregateManyRunLimits {
        execution: DirectReduceLimits {
            max_allocation_attempts: trace_prospective.allocation_attempts - 1,
            ..exact_trace.execution
        },
        ..exact_trace
    };
    assert!(matches!(
        baseline
            .count_trace(haystack, below_trace_allocation)
            .unwrap_err()
            .source,
        PriorityAggregateManyRunFailure::Execution(ReduceError::AllocationAttemptsLimit { .. })
    ));
}

#[test]
fn forced_builder_refuses_pattern_admission_before_parsing() {
    let values = patterns(&["a", "("]);
    let limits = PriorityAggregateManyBuildLimits {
        max_patterns: 1,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(limits)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::PatternLimit {
            needed: 2,
            limit: 1
        })
    ));

    let allocation_before_parse = PriorityAggregateManyBuildLimits {
        max_composition_allocation_attempts: 18,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(allocation_before_parse)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(
            PriorityAggregateManyBuildError::CompositionAllocationAttemptsLimit {
                needed: 19,
                limit: 18,
            }
        )
    ));

    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .profile(RustProfile::default())
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::UnsupportedBuildManyProfile)
    ));

    let missing_build_many = PriorityTarget {
        actions: ActionCapabilities::MATCH.union(ActionCapabilities::DIRECT_REDUCE),
        ..PriorityTarget::portable()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_count(ForcedExecution::Sparse, missing_build_many),
        Err(PriorityAggregateManyBuildError::UnsupportedTarget)
    ));
}

#[test]
fn forced_shared_automaton_preserves_unicode_crlf_and_invalid_byte_boundaries() {
    let unicode = RustProfile::rebar_1_12_4();
    assert!(unicode.options.unicode);

    assert_count_and_span_trace_with_profile(
        &[r"(?i:é)", "β", ""],
        "Éβé".as_bytes(),
        unicode.clone(),
        &[(0, 0, 2), (1, 2, 4), (0, 4, 6)],
    );
    assert_count_and_span_trace_with_profile(
        &[r"(?mR:^β$)", "β"],
        "x\r\nβ\r\nβ".as_bytes(),
        unicode.clone(),
        &[(0, 3, 5), (0, 7, 9)],
    );
    assert_count_and_span_trace_with_profile(
        &["é", ""],
        &[0xFF, 0xC3, 0xA9],
        unicode,
        &[(1, 0, 0), (0, 1, 3)],
    );
}

#[test]
fn forced_shared_capture_count_projects_cardinality_masks_and_history() {
    let values = patterns(&[r"(\Aa)", "(?:a|(ab))c", "(?:(d)|(e))f", "(?P<g>g)"]);
    assert_eq!(
        None,
        CaptureBuilder::new("(?:a|(ab))c")
            .unicode(false)
            .build()
            .unwrap()
            .build_report()
            .uniform_participating_captures
    );
    let regex = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert!(regex.build_report().closes());
    assert_eq!(4, regex.build_report().sidecars().len());
    assert!(matches!(
        regex.whole_required_literal_build_receipt(),
        fre::PriorityAggregateManyWholeRequiredLiteralBuildReceipt::Built { .. }
    ));
    assert_eq!(
        Some(1),
        regex
            .capture_build_report(0)
            .unwrap()
            .uniform_participating_captures
    );
    assert_eq!(
        None,
        regex
            .capture_build_report(1)
            .unwrap()
            .uniform_participating_captures
    );
    assert_eq!(
        Some(1),
        regex
            .capture_build_report(2)
            .unwrap()
            .uniform_participating_captures
    );
    assert_eq!(
        Some(1),
        regex
            .capture_build_report(3)
            .unwrap()
            .uniform_participating_captures
    );
    let result = regex
        .count_captures(b"aabcdfg", PriorityAggregateManyCaptureRunLimits::default())
        .unwrap();
    assert_eq!(4, regex.patterns());
    assert_eq!(4, result.matches());
    assert_eq!(8, result.value());
    assert_eq!(3, result.cardinality_matches());
    assert_eq!(1, result.mask_matches());
    assert_eq!(0, result.persistent_history_matches());
    assert!(result.trace().is_none());
    assert!(result.selector_receipt().is_some_and(|receipt| {
        receipt.closes() && receipt.execution().actual().allocation_attempts == 0
    }));
    assert_eq!(
        vec![(0, 0, 1), (1, 1, 4), (2, 4, 6), (3, 6, 7)],
        traced_ids(
            &regex
                .selector_trace(b"aabcdfg", PriorityAggregateManyRunLimits::default())
                .unwrap()
        )
    );
    assert!(result.closes());

    let ambiguous = format!("{}z", "(?:(a))?".repeat(64));
    let history_values = patterns(&[ambiguous.as_str(), "x"]);
    let history = PriorityAggregateManyBuilder::new(&history_values)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap()
        .count_captures(b"z", PriorityAggregateManyCaptureRunLimits::default())
        .unwrap();
    assert_eq!(1, history.matches());
    assert_eq!(1, history.value());
    assert_eq!(0, history.cardinality_matches());
    assert_eq!(0, history.mask_matches());
    assert_eq!(1, history.persistent_history_matches());
    assert!(history.closes());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact-cap, one-below, and mixed-source bridge ledger checks share one audited baseline"
)]
fn forced_capture_build_receipt_binds_sidecars_and_literal_preflight() {
    let values = patterns(&["([a-z])", "([0-9])"]);
    let baseline = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert!(baseline.build_report().closes());
    assert_eq!(2, baseline.build_report().sidecars().len());
    assert!(
        baseline
            .whole_required_literal_build_receipt()
            .parser_work()
            > 0
    );
    let bridge_allocations = baseline
        .construction_accounting()
        .whole_literal_bridge_allocations;
    assert_eq!(5, bridge_allocations, "two nonempty ordinal copies");

    let exact_union_bridge = PriorityAggregateManyBuildLimits {
        capture_build: PriorityAggregateManyCaptureBuildLimits {
            max_whole_literal_bridge_allocations: bridge_allocations,
            ..PriorityAggregateManyCaptureBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(exact_union_bridge)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
            .build_report()
            .closes()
    );

    let singleton = patterns(&["(a?)"]);
    let no_proof = PriorityAggregateManyBuilder::new(&singleton)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert!(matches!(
        no_proof.whole_required_literal_build_receipt(),
        fre::PriorityAggregateManyWholeRequiredLiteralBuildReceipt::NoProof { .. }
    ));
    assert!(no_proof.build_report().closes());

    let no_table = PriorityAggregateManyBuildLimits {
        capture_build: PriorityAggregateManyCaptureBuildLimits {
            max_sidecar_table_allocations: 0,
            ..PriorityAggregateManyCaptureBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(no_table)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::CaptureConstructionLimit {
            resource: PriorityAggregateManyCaptureBuildResource::SidecarTableAllocations,
            needed: 1,
            limit: 0,
        })
    ));

    let no_literal_parse = PriorityAggregateManyBuildLimits {
        capture_build: PriorityAggregateManyCaptureBuildLimits {
            max_whole_literal_parser_work: 0,
            ..PriorityAggregateManyCaptureBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(no_literal_parse)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::WholeRequiredLiteralParserWorkLimit {
            needed,
            limit: 0,
        }) if needed > 0
    ));

    let no_union_bridge = PriorityAggregateManyBuildLimits {
        capture_build: PriorityAggregateManyCaptureBuildLimits {
            max_whole_literal_bridge_allocations: bridge_allocations - 1,
            ..PriorityAggregateManyCaptureBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(no_union_bridge)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::CaptureConstructionLimit {
            resource: PriorityAggregateManyCaptureBuildResource::WholeLiteralBridgeAllocations,
            needed,
            limit,
        })
        if needed == bridge_allocations && limit == bridge_allocations - 1
    ));

    let mixed = patterns(&["", "([a-z])"]);
    let mixed = PriorityAggregateManyBuilder::new(&mixed)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert_eq!(
        4,
        mixed
            .construction_accounting()
            .whole_literal_bridge_allocations,
        "only the nonempty ordinal source reserves a temporary copy"
    );
    assert!(mixed.build_report().closes());
}

#[test]
fn forced_shared_capture_session_reuses_exact_workspaces_and_literal_gate() {
    let values = patterns(&[r"(?:a|(ab))c", r"(?:(d)|(e))f", r"(?P<g>g)"]);
    let regex = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert!(regex.whole_required_literal_build_report().is_some());

    let mut session = regex
        .prepare_capture_session(
            b"abcdfg".len(),
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .unwrap();
    let first = session.count_captures(b"abcdfg").unwrap();
    let second = session.count_captures(b"abcdfg").unwrap();
    assert_eq!(first.value(), second.value());
    assert_eq!(first.capture_accounting(), second.capture_accounting());
    assert_eq!(0, first.capture_accounting().allocations);
    assert_eq!(0, second.capture_accounting().allocations);
    assert_eq!(Some(true), first.required_literal_candidate());
    assert!(!first.selector_skipped_by_required_literal());
    assert!(first.trace().is_none());
    assert!(
        first
            .selector_receipt()
            .is_some_and(fre::PriorityAggregateManyCaptureSelectorReceipt::closes)
    );
    assert!(
        second
            .selector_receipt()
            .is_some_and(fre::PriorityAggregateManyCaptureSelectorReceipt::closes)
    );

    let absent = regex
        .count_captures(b"zzzz", PriorityAggregateManyCaptureRunLimits::default())
        .unwrap();
    assert_eq!(0, absent.value());
    assert_eq!(0, absent.matches());
    assert_eq!(Some(false), absent.required_literal_candidate());
    assert!(absent.selector_skipped_by_required_literal());
    assert!(absent.trace().is_none());
    assert!(absent.closes());
}

#[test]
fn forced_shared_capture_generated_sixteen_pattern_prefix_density_holdout() {
    let mut values = Vec::new();
    let mut haystack = Vec::new();
    for ordinal in 0..16 {
        let prefix = format!("shared-prefix-{ordinal:02}");
        values.push(format!("{prefix}(?:a|(b))"));
        haystack.extend_from_slice(prefix.as_bytes());
        haystack.push(b'a');
        haystack.extend_from_slice(prefix.as_bytes());
        haystack.push(b'b');
    }
    let regex = PriorityAggregateManyBuilder::new(&values)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let mut session = regex
        .prepare_capture_session(
            haystack.len(),
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .unwrap();
    let result = session.count_captures(&haystack).unwrap();
    assert_eq!(32, result.matches());
    assert_eq!(48, result.value());
    assert_eq!(0, result.cardinality_matches());
    assert_eq!(32, result.mask_matches());
    assert_eq!(0, result.persistent_history_matches());
    assert_eq!(0, result.capture_accounting().allocations);
    assert!(result.trace().is_none());
    assert!(
        result
            .selector_receipt()
            .is_some_and(fre::PriorityAggregateManyCaptureSelectorReceipt::closes)
    );
    assert!(result.closes());
}

#[test]
fn forced_shared_capture_preserves_unicode_crlf_and_invalid_byte_spans() {
    let unicode = RustProfile::rebar_1_12_4();
    let unicode_values = patterns(&[r"(?i:(é))", r"(β)"]);
    let unicode_result = PriorityAggregateManyBuilder::new(&unicode_values)
        .profile(unicode.clone())
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap()
        .count_captures(
            "Éβé".as_bytes(),
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .unwrap();
    assert_eq!(3, unicode_result.matches());
    assert_eq!(6, unicode_result.value());
    assert!(unicode_result.closes());

    let crlf_values = patterns(&[r"(?mR:^(β)$)", r"(β)"]);
    let crlf_result = PriorityAggregateManyBuilder::new(&crlf_values)
        .profile(unicode.clone())
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap()
        .count_captures(
            "x\r\nβ\r\nβ".as_bytes(),
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .unwrap();
    assert_eq!(2, crlf_result.matches());
    assert_eq!(4, crlf_result.value());
    assert!(crlf_result.closes());

    let invalid_values = patterns(&["(é)", ""]);
    let invalid_result = PriorityAggregateManyBuilder::new(&invalid_values)
        .profile(unicode)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap()
        .count_captures(
            &[0xFF, 0xC3, 0xA9],
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .unwrap();
    assert_eq!(2, invalid_result.matches());
    assert_eq!(3, invalid_result.value());
    assert!(invalid_result.closes());
}

#[test]
fn forced_parser_and_source_owner_are_admitted_before_each_source_stage() {
    let valid = patterns(&["a"]);
    let baseline = build_count(&valid);
    let pattern = &baseline.build_report().patterns()[0];
    let owner = pattern.source_owner;
    assert!(pattern.syntax_receipt.identity.has_stable_source_owner());
    assert!(pattern.syntax_receipt.authenticates_canonical());
    assert!(baseline.build_report().composition().parser_work > 0);
    assert!(
        baseline.build_report().composition().parser_work
            <= baseline
                .build_report()
                .composition()
                .parser_work_reservation
    );
    assert!(baseline.build_report().closes());

    let exact_owner = PriorityAggregateManyBuildLimits {
        source_owner: fre::PriorityAggregateManySourceOwnerLimits {
            max_allocation_bytes: owner.allocation_bytes(),
            max_handle_bytes: owner.handle_bytes(),
            max_allocation_attempts: owner.allocation_attempts(),
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(
        PriorityAggregateManyBuilder::new(&valid)
            .unicode(false)
            .limits(exact_owner)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
            .build_report()
            .closes()
    );

    let malformed_second = patterns(&["a", "("]);
    let parser_minimum = PriorityAggregateManyBuildLimits {
        max_parser_work: 1,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&malformed_second)
            .unicode(false)
            .limits(parser_minimum)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::ParserWorkLimit {
            needed: 2,
            limit: 1,
        })
    ));

    let owner_before_parse = PriorityAggregateManyBuildLimits {
        source_owner: fre::PriorityAggregateManySourceOwnerLimits {
            max_allocation_bytes: owner.allocation_bytes() - 1,
            max_handle_bytes: owner.handle_bytes(),
            max_allocation_attempts: owner.allocation_attempts(),
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&malformed_second)
            .unicode(false)
            .limits(owner_before_parse)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::SourceOwnerResourceLimit { .. })
    ));

    let source_identity_before_parse = PriorityAggregateManyBuildLimits {
        max_source_identity_allocation_attempts: 1,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&malformed_second)
            .unicode(false)
            .limits(source_identity_before_parse)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(
            PriorityAggregateManyBuildError::SourceIdentityAllocationAttemptsLimit {
                needed: 2,
                limit: 1,
            }
        )
    ));

    let same_shape_valid = patterns(&["a", "b"]);
    let scratch_probe = build_count(&same_shape_valid);
    let scratch_before_parse = PriorityAggregateManyBuildLimits {
        max_composition_scratch_bytes: scratch_probe
            .build_report()
            .composition()
            .preflight_scratch_bytes
            - 1,
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&malformed_second)
            .unicode(false)
            .limits(scratch_before_parse)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::CompositionScratchLimit { .. })
    ));
}

#[test]
fn forced_build_many_does_not_change_the_default_aggregate_many_planner() {
    let values = patterns(&[r"a+", "a"]);
    let default = AggregateManyBuilder::new(&values)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        AggregateManyPlanKind::ContinuationProgram,
        default.build_report().plan
    );
    assert_eq!(
        1,
        default
            .count_value(b"aa", fre::AggregateManyRunLimits::unlimited())
            .unwrap()
    );
    assert_eq!(
        1,
        build_count(&values)
            .count(b"aa", PriorityAggregateManyRunLimits::unlimited())
            .unwrap()
            .value()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one immutable baseline supplies every exact and one-below tagged construction dimension"
)]
fn forced_build_many_pattern_count_and_composition_limits_are_exact() {
    let values = (0..32)
        .map(|index| format!("shared-prefix-{index:02}x?"))
        .collect::<Vec<_>>();
    let baseline = build_count(&values);
    let accounting = baseline.build_report().composition();
    let tagged = accounting.tagged_build;
    let stats = accounting.tagged_stats;
    assert_eq!(32, accounting.patterns);
    assert_eq!(32, baseline.build_report().preparation().pattern_terminals);
    assert_eq!(accounting.patterns, stats.patterns());
    assert_eq!(accounting.source_states, stats.source_states());
    assert_eq!(accounting.source_edges, stats.source_edges());
    assert_eq!(accounting.composed_states, stats.states());
    assert_eq!(accounting.composed_edges, stats.edges());
    assert_eq!(accounting.source_states, stats.owner_state_memberships());
    assert_eq!(accounting.source_edges, stats.owner_edge_memberships());
    assert_eq!(accounting.composition_work, tagged.actual_work);
    assert_eq!(
        accounting.composed_raw_capacity_bytes,
        tagged.persistent_bytes
    );
    assert_eq!(0, accounting.action_capacity_bytes);
    assert!(tagged.actual_work <= tagged.prospective_work);
    assert!(tagged.closes(baseline.build_report().tagged_limits()));
    assert!(accounting.scratch_bytes <= accounting.preflight_scratch_bytes);
    assert!(tagged.prospective_work <= accounting.preflight_composition_work);
    assert!(
        baseline.build_report().retained_capacity_bytes() <= accounting.preflight_persistent_bytes
    );

    let exact = PriorityAggregateManyBuildLimits {
        max_composition_work: tagged.prospective_work,
        max_lowered_states: accounting.source_states,
        max_lowered_edges: accounting.source_edges,
        tagged: TaggedManyBuildLimits {
            max_work: tagged.prospective_work,
            ..TaggedManyBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(exact)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
            .build_report()
            .closes()
    );
    let membership_sum = stats
        .owner_state_memberships()
        .checked_add(stats.owner_edge_memberships())
        .unwrap();
    let exact_memberships = PriorityAggregateManyBuildLimits {
        preparation: PreparationLimits {
            max_subset_items: membership_sum,
            ..PreparationLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(exact_memberships)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
            .build_report()
            .closes()
    );
    let below_memberships = PriorityAggregateManyBuildLimits {
        preparation: PreparationLimits {
            max_subset_items: membership_sum - 1,
            ..PreparationLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(below_memberships)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::PreparationSubsetItemsLimit { needed, limit })
            if needed == membership_sum && limit + 1 == needed
    ));

    let below = PriorityAggregateManyBuildLimits {
        max_composition_work: tagged.prospective_work - 1,
        tagged: TaggedManyBuildLimits {
            max_work: tagged.prospective_work - 1,
            ..TaggedManyBuildLimits::default()
        },
        ..PriorityAggregateManyBuildLimits::default()
    };
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .limits(below)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::Tagged(TaggedManyBuildError::WorkLimit {
            needed,
            limit,
        })) if needed == tagged.prospective_work && limit + 1 == needed
    ));

    let too_many = (0..129).map(|_| "a".to_owned()).collect::<Vec<_>>();
    assert!(matches!(
        PriorityAggregateManyBuilder::new(&too_many)
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable()),
        Err(PriorityAggregateManyBuildError::PatternLimit {
            needed: 129,
            limit: 128
        })
    ));
}

#[test]
fn fixed_program_no_match_and_dense_match_work_bounds_scale_linearly_with_input() {
    let values = patterns(&[r"(?:ab|ac)+", r"b+", r"c?"]);
    let regex = build_count(&values);
    let no_match = [vec![b'z'; 64], vec![b'z'; 128], vec![b'z'; 256]];
    let dense = [b"ab".repeat(32), b"ab".repeat(64), b"ab".repeat(128)];
    for haystacks in [&no_match, &dense] {
        let reports = haystacks
            .iter()
            .map(|haystack| {
                regex
                    .count(haystack, PriorityAggregateManyRunLimits::unlimited())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(65, reports[0].prospective().boundary_rows);
        assert_eq!(129, reports[1].prospective().boundary_rows);
        assert_eq!(257, reports[2].prospective().boundary_rows);
        assert!(
            reports[1].prospective().work_upper_bound
                <= reports[0].prospective().work_upper_bound.saturating_mul(2)
        );
        assert!(
            reports[2].prospective().work_upper_bound
                <= reports[1].prospective().work_upper_bound.saturating_mul(2)
        );
        assert!(
            reports
                .iter()
                .all(fre::PriorityAggregateManyExecutionReceipt::closes)
        );
    }
}

#[test]
fn identical_nonliteral_patterns_share_one_composed_graph_across_cardinality() {
    const SOURCE: &str = r"shared-prefix-(?:[a-z]+|[0-9]+)-suffix";
    const HAYSTACK: &[u8] = b"shared-prefix-letters-suffix";
    let mut baseline = None::<(usize, usize, usize, usize)>;

    for count in [8_usize, 16, 32, 64] {
        let values = vec![SOURCE.to_owned(); count];
        let regex = build_count(&values);
        let composition = regex.build_report().composition();
        assert_eq!(count, composition.patterns);
        assert_eq!(count, regex.build_report().patterns().len());
        assert!(
            regex
                .build_report()
                .patterns()
                .iter()
                .enumerate()
                .all(|(ordinal, report)| report.ordinal == ordinal)
        );
        assert_eq!(0, composition.source_states % count);
        assert_eq!(0, composition.source_edges % count);
        let dimensions = (
            composition.composed_states,
            composition.composed_edges,
            composition.source_states / count,
            composition.source_edges / count,
        );
        if let Some(expected) = baseline {
            assert_eq!(
                expected, dimensions,
                "identical nonliteral graph changed at {count} patterns"
            );
        } else {
            baseline = Some(dimensions);
        }

        let trace = regex
            .count_trace(HAYSTACK, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        assert_eq!(
            vec![(0, 0, HAYSTACK.len())],
            traced_ids(&trace),
            "{count} duplicate patterns"
        );
        assert!(trace.closes());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the four public APIs share one owner-cardinality matrix and exact class-specific P/A equations"
)]
fn shared_frontier_public_receipts_close_for_all_four_facade_apis() {
    const INPUT_BYTES: usize = 256;
    let haystack = vec![b'a'; INPUT_BYTES];
    let no_match = vec![b'!'; INPUT_BYTES];
    let limits = PriorityAggregateManyRunLimits::unlimited();

    for owners in [1_usize, 8, 128] {
        let depth = 1_usize;
        let values = vec!["[a-z]".to_owned(); owners];
        let count = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let span = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        for build in [count.build_report(), span.build_report()] {
            assert!(build.closes());
            assert_eq!(
                PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
                build.schema_version()
            );
            assert_eq!(PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID, build.accounting_id());
            assert_eq!(
                TAGGED_MANY_ACCOUNTING_ID,
                build.tagged_build().accounting_id
            );
            assert_eq!(
                TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
                    depth,
                    byte_start: b'a',
                    byte_end: b'z',
                },
                build.automaton().execution_class()
            );
            assert_eq!(owners, build.tagged_build().classification_owner_checks);
            assert_eq!(depth + 1, build.tagged_build().classification_state_checks);
            assert_eq!(depth, build.tagged_build().classification_edge_checks);
        }

        let expected_matches = INPUT_BYTES / depth;
        let expected_count = u64::try_from(expected_matches).unwrap();
        let expected_span = u64::try_from(expected_matches * depth).unwrap();
        let expected_trace = (0..expected_matches)
            .map(|index| (0, index * depth, (index + 1) * depth))
            .collect::<Vec<_>>();
        let boundary_rows = INPUT_BYTES + 1;

        let count_receipt = count.count(&haystack, limits).unwrap();
        assert!(count_receipt.closes());
        assert_eq!(
            PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
            count_receipt.schema_version()
        );
        assert_eq!(
            PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID,
            count_receipt.accounting_id()
        );
        assert_eq!(expected_count, count_receipt.value());
        assert_eq!(
            u64::try_from(2 * INPUT_BYTES + 1).unwrap(),
            count_receipt.prospective().work_upper_bound
        );
        assert_eq!(
            u64::try_from(INPUT_BYTES + expected_matches).unwrap(),
            count_receipt.actual().work
        );
        assert_eq!(INPUT_BYTES, count_receipt.actual().tagged_state_evaluations);
        assert_eq!(INPUT_BYTES, count_receipt.actual().tagged_edge_visits);
        assert_eq!(0, count_receipt.prospective().tagged_map_capacity);
        assert_eq!(0, count_receipt.prospective().tagged_group_capacity);
        assert_eq!(
            Some(count_receipt.tagged_stats().execution_class()),
            count_receipt.prospective().tagged_execution_class
        );

        let count_trace = count.count_trace(&haystack, limits).unwrap();
        assert!(count_trace.closes());
        assert_eq!(expected_trace, traced_ids(&count_trace));
        let upstream = MetaRegex::builder()
            .configure(MetaRegex::config().utf8_empty(false))
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .utf8(false)
                    .unicode(false),
            )
            .build_many(&values)
            .unwrap();
        assert_eq!(
            upstream
                .find_iter(&haystack)
                .map(|matched| {
                    (
                        u32::try_from(matched.pattern().as_usize()).unwrap(),
                        matched.start(),
                        matched.end(),
                    )
                })
                .collect::<Vec<_>>(),
            traced_ids(&count_trace)
        );
        assert_eq!(
            u64::try_from(3 * INPUT_BYTES + 3).unwrap(),
            count_trace.execution().prospective().work_upper_bound
        );
        assert_eq!(
            u64::try_from(INPUT_BYTES + 2 * expected_matches + 1).unwrap(),
            count_trace.execution().actual().work
        );
        assert_eq!(
            boundary_rows * size_of::<fre_automata::PriorityMatch>(),
            count_trace.execution().prospective().scratch_bytes
        );
        assert_eq!(1, count_trace.execution().prospective().allocation_attempts);

        let span_receipt = span.span_sum(&haystack, limits).unwrap();
        assert!(span_receipt.closes());
        assert_eq!(expected_span, span_receipt.value());
        assert_eq!(count_receipt.actual(), span_receipt.actual());

        let span_trace = span.span_sum_trace(&haystack, limits).unwrap();
        assert!(span_trace.closes());
        assert_eq!(expected_trace, traced_ids(&span_trace));
        assert_eq!(expected_span, span_trace.execution().value());
        assert_eq!(
            count_trace.execution().actual(),
            span_trace.execution().actual()
        );

        let empty = count.count(&no_match, limits).unwrap();
        assert!(empty.closes());
        assert_eq!(0, empty.value());
        assert_eq!(u64::try_from(INPUT_BYTES).unwrap(), empty.actual().work);
        assert_eq!(0, empty.actual().match_events);
    }
}

#[test]
fn generic_fallback_priority_and_failure_boundaries_match_ordered_oracle() {
    let values = patterns(&[r"[a-z]", r"[a-z]", r"[b-z]"]);
    let haystacks = [
        Vec::new(),
        vec![b'a'; 1],
        vec![b'a'; 2],
        [vec![b'!'], vec![b'a'; 3], vec![b'!'], vec![b'a'; 1]].concat(),
    ];
    let upstream = MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false),
        )
        .build_many(&values)
        .unwrap();
    let fre = build_count(&values);
    assert_eq!(
        TaggedManyExecutionClass::Generic,
        fre.build_report().automaton().execution_class()
    );

    for haystack in haystacks {
        let expected = upstream
            .find_iter(&haystack)
            .map(|matched| {
                (
                    u32::try_from(matched.pattern().as_usize()).unwrap(),
                    matched.start(),
                    matched.end(),
                )
            })
            .collect::<Vec<_>>();
        let actual = fre
            .count_trace(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        assert_eq!(expected, traced_ids(&actual));
        assert!(actual.closes());
    }
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
