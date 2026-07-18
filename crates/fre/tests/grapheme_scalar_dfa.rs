use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateGraphemeScalarDfaSemantics,
    AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits,
    GraphemeScalarDfaBuildError, GraphemeScalarDfaBuildLimits, GraphemeScalarDfaOperation,
    GraphemeScalarDfaReduceError, GraphemeScalarDfaReduceLimits, RustProfile,
};

const GRAPHEME: &str = r"(?x)
\p{gcb=CR} \p{gcb=LF}
|
\p{gcb=Control}
|
\p{gcb=Prepend}*
(
  (
    (\p{gcb=L}* (\p{gcb=V}+ | \p{gcb=LV} \p{gcb=V}* | \p{gcb=LVT}) \p{gcb=T}*)
    |
    \p{gcb=L}+
    |
    \p{gcb=T}+
  )
  |
  \p{gcb=RI} \p{gcb=RI}
  |
  \p{Extended_Pictographic} (\p{gcb=Extend}* \p{gcb=ZWJ} \p{Extended_Pictographic})*
  |
  [^\p{gcb=Control} \p{gcb=CR} \p{gcb=LF}]
)
[\p{gcb=Extend} \p{gcb=ZWJ} \p{gcb=SpacingMark}]*
|
\p{Any}
";

fn candidate() -> fre::AggregateCountRegex {
    AggregateBuilder::new(GRAPHEME)
        .profile(RustProfile::rebar_1_12_4())
        .build_count()
        .unwrap()
}

fn oracle_count(haystack: &[u8]) -> u64 {
    let regex = regex::bytes::RegexBuilder::new(GRAPHEME)
        .unicode(true)
        .build()
        .unwrap();
    u64::try_from(regex.find_iter(haystack).count()).unwrap()
}

fn one_below(value: usize) -> usize {
    value.checked_sub(1).unwrap()
}

fn one_below_u64(value: u64) -> u64 {
    value.checked_sub(1).unwrap()
}

#[test]
fn selected_count_plan_matches_pinned_oracle_on_ordering_traps() {
    let candidate = candidate();
    assert_eq!(
        candidate.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    assert!(matches!(
        candidate.build_report().plan_identity,
        AggregatePlanIdentity::GraphemeScalarDfa(identity)
            if identity.semantics
                == AggregateGraphemeScalarDfaSemantics::UnicodeOnOrderedScalarGrammarUtf8False
                && identity.kernel.operation == GraphemeScalarDfaOperation::Count
    ));

    let cases: &[&[u8]] = &[
        "\r\n\u{0300}".as_bytes(),
        "\u{1F1E6}\u{1F1E7}\u{1F1E8}".as_bytes(),
        "\u{1F1E6}\u{0300}\u{1F1E7}".as_bytes(),
        "\u{1F600}\u{0903}\u{200D}\u{1F600}".as_bytes(),
        "\u{1F600}\u{200D}\u{200D}\u{1F600}".as_bytes(),
        "\u{0300}\u{200D}\u{0903}".as_bytes(),
        "\u{AC00}\u{AC00}".as_bytes(),
        "\u{1161}\u{AC00}".as_bytes(),
        "\u{1100}\u{11A8}".as_bytes(),
        "\u{0600}".as_bytes(),
        "\u{0600}\0".as_bytes(),
    ];
    for haystack in cases {
        let result = candidate
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(result.value(), oracle_count(haystack), "{haystack:?}");
    }
}

#[test]
fn malformed_bytes_resynchronize_exactly_like_regex_bytes() {
    let candidate = candidate();
    let cases: &[&[u8]] = &[
        b"a\xFFb",
        b"\x80a",
        b"a\xC2",
        b"a\xE0\x80\x80b",
        b"a\xED\xA0\x80b",
        b"a\xF4\x90\x80\x80b",
    ];
    for haystack in cases {
        assert_eq!(
            candidate
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            oracle_count(haystack),
            "{haystack:?}"
        );
    }
}

#[test]
fn non_count_operations_remain_on_the_existing_plan() {
    let compiled = AggregateBuilder::new(GRAPHEME)
        .profile(RustProfile::rebar_1_12_4())
        .build_compile()
        .unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn admission_is_exact_to_hir_profile_model_and_selection() {
    let near_miss_pattern = GRAPHEME.replacen(r"\p{Any}", "a", 1);
    let near_miss = AggregateBuilder::new(&near_miss_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .build_count()
        .unwrap();
    assert_ne!(
        near_miss.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );

    let high_level = AggregateBuilder::new(GRAPHEME).build_count().unwrap();
    assert_ne!(
        high_level.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );

    let forced = AggregateBuilder::new(GRAPHEME)
        .profile(RustProfile::rebar_1_12_4())
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_ne!(
        forced.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );

    for plan in [
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .build_compile()
            .unwrap()
            .build_report()
            .plan,
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
    ] {
        assert_ne!(plan, AggregatePlanKind::GraphemeScalarDfa);
    }

    for builder in [
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false),
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .case_insensitive(true),
    ] {
        if let Ok(regex) = builder.build_count() {
            assert_ne!(
                regex.build_report().plan,
                AggregatePlanKind::GraphemeScalarDfa
            );
        }
    }
}

#[test]
fn ineligible_inspection_work_survives_fallback_with_exact_limits() {
    let near_miss_pattern = GRAPHEME.replacen(r"\p{Any}", "a", 1);
    let near_miss = AggregateBuilder::new(&near_miss_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .build_count()
        .unwrap();
    let near_miss_work = near_miss.build_report().grapheme_scalar_dfa_planner_work;
    assert!(near_miss_work > 0);

    let exact_near_miss = AggregateBuildLimits {
        max_grapheme_scalar_dfa_planner_work: near_miss_work,
        ..AggregateBuildLimits::default()
    };
    let exact_near_miss_report = AggregateBuilder::new(&near_miss_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .limits(exact_near_miss)
        .build_count()
        .unwrap();
    assert_eq!(
        exact_near_miss_report
            .build_report()
            .grapheme_scalar_dfa_planner_work,
        near_miss_work
    );

    let one_below = one_below(near_miss_work);
    let one_below_near_miss = AggregateBuildLimits {
        max_grapheme_scalar_dfa_planner_work: one_below,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        AggregateBuilder::new(&near_miss_pattern)
            .profile(RustProfile::rebar_1_12_4())
            .limits(one_below_near_miss)
            .build_count()
            .unwrap_err(),
        AggregateBuildError::GraphemeScalarDfaPlannerWorkLimit {
            needed,
            limit,
            ..
        } if needed == near_miss_work && limit == one_below
    ));

    let malformed_pattern = GRAPHEME.replacen(r"\p{gcb=RI} \p{gcb=RI}", r"\p{gcb=RI}", 1);
    let malformed = AggregateBuilder::new(&malformed_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .build_count()
        .unwrap();
    assert_ne!(
        malformed.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    assert!(malformed.build_report().grapheme_scalar_dfa_planner_work > 0);
}

#[derive(Clone, Copy, Debug)]
enum BuildGate {
    Ranges,
    Events,
    Segments,
    SortComparisons,
    Allocations,
    EventWrites,
    SegmentWrites,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn build_gate_matches(gate: BuildGate, error: &AggregateBuildError) -> bool {
    let AggregateBuildError::GraphemeScalarDfaBuild { source, .. } = error else {
        return false;
    };
    matches!(
        (gate, source),
        (
            BuildGate::Ranges,
            GraphemeScalarDfaBuildError::RangeLimit { .. }
        ) | (
            BuildGate::Events,
            GraphemeScalarDfaBuildError::EventLimit { .. }
        ) | (
            BuildGate::Segments,
            GraphemeScalarDfaBuildError::SegmentLimit { .. }
        ) | (
            BuildGate::SortComparisons,
            GraphemeScalarDfaBuildError::SortComparisonsLimit { .. }
        ) | (
            BuildGate::Allocations,
            GraphemeScalarDfaBuildError::AllocationLimit { .. }
        ) | (
            BuildGate::EventWrites,
            GraphemeScalarDfaBuildError::EventWritesLimit { .. }
        ) | (
            BuildGate::SegmentWrites,
            GraphemeScalarDfaBuildError::SegmentWritesLimit { .. }
        ) | (
            BuildGate::Work,
            GraphemeScalarDfaBuildError::WorkLimit { .. }
        ) | (
            BuildGate::Scratch,
            GraphemeScalarDfaBuildError::ScratchLimit { .. }
        ) | (
            BuildGate::Persistent,
            GraphemeScalarDfaBuildError::PersistentLimit { .. }
        ) | (
            BuildGate::Peak,
            GraphemeScalarDfaBuildError::PeakLimit { .. }
        )
    )
}

#[test]
fn facade_propagates_exact_and_one_below_build_limits() {
    let baseline = candidate();
    let report = baseline.build_report();
    let AggregateBuildAccounting::GraphemeScalarDfa(build) = report.build else {
        panic!("expected grapheme build accounting")
    };
    let exact = AggregateBuildLimits {
        max_grapheme_scalar_dfa_planner_work: report.grapheme_scalar_dfa_planner_work,
        grapheme_scalar_dfa: GraphemeScalarDfaBuildLimits {
            max_source_ranges: build.source_ranges,
            max_events: build.events,
            max_segments: build.segment_capacity,
            max_sort_comparisons: build.sort_comparisons_upper,
            max_allocations: build.allocations,
            max_event_writes: build.event_capacity,
            max_segment_writes: build.segment_capacity,
            max_build_work: build.work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        },
        ..AggregateBuildLimits::default()
    };
    AggregateBuilder::new(GRAPHEME)
        .profile(RustProfile::rebar_1_12_4())
        .limits(exact)
        .build_count()
        .unwrap();

    let mut planner_limited = exact;
    planner_limited.max_grapheme_scalar_dfa_planner_work =
        one_below(report.grapheme_scalar_dfa_planner_work);
    assert!(matches!(
        AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .limits(planner_limited)
            .build_count()
            .unwrap_err(),
        AggregateBuildError::GraphemeScalarDfaPlannerWorkLimit { .. }
    ));

    for gate in [
        BuildGate::Ranges,
        BuildGate::Events,
        BuildGate::Segments,
        BuildGate::SortComparisons,
        BuildGate::Allocations,
        BuildGate::EventWrites,
        BuildGate::SegmentWrites,
        BuildGate::Work,
        BuildGate::Scratch,
        BuildGate::Persistent,
        BuildGate::Peak,
    ] {
        let mut limited = exact;
        match gate {
            BuildGate::Ranges => {
                limited.grapheme_scalar_dfa.max_source_ranges = one_below(build.source_ranges);
            }
            BuildGate::Events => {
                limited.grapheme_scalar_dfa.max_events = one_below(build.events);
            }
            BuildGate::Segments => {
                limited.grapheme_scalar_dfa.max_segments = one_below(build.segment_capacity);
            }
            BuildGate::SortComparisons => {
                limited.grapheme_scalar_dfa.max_sort_comparisons =
                    one_below(build.sort_comparisons_upper);
            }
            BuildGate::Allocations => {
                limited.grapheme_scalar_dfa.max_allocations = one_below(build.allocations);
            }
            BuildGate::EventWrites => {
                limited.grapheme_scalar_dfa.max_event_writes = one_below(build.event_capacity);
            }
            BuildGate::SegmentWrites => {
                limited.grapheme_scalar_dfa.max_segment_writes = one_below(build.segment_capacity);
            }
            BuildGate::Work => {
                limited.grapheme_scalar_dfa.max_build_work = one_below(build.work);
            }
            BuildGate::Scratch => {
                limited.grapheme_scalar_dfa.max_scratch_bytes = one_below(build.scratch_bytes);
            }
            BuildGate::Persistent => {
                limited.grapheme_scalar_dfa.max_persistent_bytes =
                    one_below(build.persistent_bytes);
            }
            BuildGate::Peak => {
                limited.grapheme_scalar_dfa.max_peak_bytes = one_below(build.peak_bytes);
            }
        }
        let error = AggregateBuilder::new(GRAPHEME)
            .profile(RustProfile::rebar_1_12_4())
            .limits(limited)
            .build_count()
            .unwrap_err();
        assert!(build_gate_matches(gate, &error), "{gate:?}: {error:?}");
    }
}

#[derive(Clone, Copy, Debug)]
enum ReduceGate {
    Input,
    Decode,
    Classifications,
    RangeComparisons,
    ScannerSteps,
    RoleProbes,
    BranchChecks,
    RepetitionTests,
    MatchEvents,
    Count,
    Work,
    Scratch,
    Peak,
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all count quota dimensions remain adjacent to their typed expected error"
)]
fn facade_propagates_exact_and_one_below_count_limits() {
    let candidate = candidate();
    let haystack = "A\r\n\u{1F1E6}\u{1F1E7}\u{0300}".as_bytes();
    let baseline = candidate
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::GraphemeScalarDfa(accounting) = &baseline.report().details
    else {
        panic!("expected grapheme execution accounting")
    };
    let upper = accounting.upper_bounds;
    let exact_kernel = GraphemeScalarDfaReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_decode_byte_checks: upper.decode_byte_checks,
        max_classifications: upper.classifications,
        max_range_comparisons: upper.range_comparisons,
        max_scanner_steps: upper.scanner_steps,
        max_role_probes: upper.role_probes,
        max_branch_checks: upper.branch_checks,
        max_repetition_tests: upper.repetition_tests,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_work: upper.work,
        max_scratch_bytes: upper.scratch_bytes,
        max_peak_bytes: upper.peak_bytes,
    };
    let exact = AggregateRunLimits {
        grapheme_scalar_dfa: exact_kernel,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        candidate.count_value(haystack, exact).unwrap(),
        baseline.value()
    );

    for gate in [
        ReduceGate::Input,
        ReduceGate::Decode,
        ReduceGate::Classifications,
        ReduceGate::RangeComparisons,
        ReduceGate::ScannerSteps,
        ReduceGate::RoleProbes,
        ReduceGate::BranchChecks,
        ReduceGate::RepetitionTests,
        ReduceGate::MatchEvents,
        ReduceGate::Count,
        ReduceGate::Work,
        ReduceGate::Scratch,
        ReduceGate::Peak,
    ] {
        let mut limited = exact;
        match gate {
            ReduceGate::Input => {
                limited.grapheme_scalar_dfa.max_input_bytes = one_below(upper.input_bytes);
            }
            ReduceGate::Decode => {
                limited.grapheme_scalar_dfa.max_decode_byte_checks =
                    one_below(upper.decode_byte_checks);
            }
            ReduceGate::Classifications => {
                limited.grapheme_scalar_dfa.max_classifications = one_below(upper.classifications);
            }
            ReduceGate::RangeComparisons => {
                limited.grapheme_scalar_dfa.max_range_comparisons =
                    one_below(upper.range_comparisons);
            }
            ReduceGate::ScannerSteps => {
                limited.grapheme_scalar_dfa.max_scanner_steps = one_below(upper.scanner_steps);
            }
            ReduceGate::RoleProbes => {
                limited.grapheme_scalar_dfa.max_role_probes = one_below(upper.role_probes);
            }
            ReduceGate::BranchChecks => {
                limited.grapheme_scalar_dfa.max_branch_checks = one_below(upper.branch_checks);
            }
            ReduceGate::RepetitionTests => {
                limited.grapheme_scalar_dfa.max_repetition_tests =
                    one_below(upper.repetition_tests);
            }
            ReduceGate::MatchEvents => {
                limited.grapheme_scalar_dfa.max_match_events = one_below(upper.match_events);
            }
            ReduceGate::Count => {
                limited.grapheme_scalar_dfa.max_count = one_below_u64(upper.count);
            }
            ReduceGate::Work => {
                limited.grapheme_scalar_dfa.max_work = one_below(upper.work);
            }
            ReduceGate::Scratch => {
                limited.grapheme_scalar_dfa.max_scratch_bytes = one_below(upper.scratch_bytes);
            }
            ReduceGate::Peak => {
                limited.grapheme_scalar_dfa.max_peak_bytes = one_below(upper.peak_bytes);
            }
        }
        let error = candidate.count_value(haystack, limited).unwrap_err();
        let AggregateExecutionSource::GraphemeScalarDfa(source) = error.source else {
            panic!("{gate:?}: unexpected source {error:?}")
        };
        let source_debug = format!("{source:?}");
        let matches = matches!(
            (gate, source),
            (
                ReduceGate::Input,
                GraphemeScalarDfaReduceError::InputBytesLimit { .. }
            ) | (
                ReduceGate::Decode,
                GraphemeScalarDfaReduceError::DecodeByteChecksLimit { .. }
            ) | (
                ReduceGate::Classifications,
                GraphemeScalarDfaReduceError::ClassificationsLimit { .. }
            ) | (
                ReduceGate::RangeComparisons,
                GraphemeScalarDfaReduceError::RangeComparisonsLimit { .. }
            ) | (
                ReduceGate::ScannerSteps,
                GraphemeScalarDfaReduceError::ScannerStepsLimit { .. }
            ) | (
                ReduceGate::RoleProbes,
                GraphemeScalarDfaReduceError::RoleProbesLimit { .. }
            ) | (
                ReduceGate::BranchChecks,
                GraphemeScalarDfaReduceError::BranchChecksLimit { .. }
            ) | (
                ReduceGate::RepetitionTests,
                GraphemeScalarDfaReduceError::RepetitionTestsLimit { .. }
            ) | (
                ReduceGate::MatchEvents,
                GraphemeScalarDfaReduceError::MatchEventsLimit { .. }
            ) | (
                ReduceGate::Count,
                GraphemeScalarDfaReduceError::CountLimit { .. }
            ) | (
                ReduceGate::Work,
                GraphemeScalarDfaReduceError::WorkLimit { .. }
            ) | (
                ReduceGate::Scratch,
                GraphemeScalarDfaReduceError::ScratchLimit { .. }
            ) | (
                ReduceGate::Peak,
                GraphemeScalarDfaReduceError::PeakLimit { .. }
            )
        );
        assert!(matches, "{gate:?}: {source_debug}");
    }
}
