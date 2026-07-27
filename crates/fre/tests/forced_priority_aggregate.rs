// The package's Rust 1.74 baseline cannot parse lint `reason` metadata.
#![allow(clippy::allow_attributes_without_reason)]

use fre::{
    AggregateBuilder, AggregateOperationCounterValue, AggregatePlanKind, AggregatePlanSelection,
    AggregateRunLimits, PRIORITY_AGGREGATE_ACCOUNTING_ID, PRIORITY_AGGREGATE_SCHEMA_VERSION,
    PriorityAggregateBridgeLimits, PriorityAggregateBridgeResource, PriorityAggregateBuildError,
    PriorityAggregateBuildLimits, PriorityAggregateBuilder, PriorityAggregateCountRegex,
    PriorityAggregateOperation, PriorityAggregateRunFailure, PriorityAggregateRunLimits,
    PriorityAggregateSourceOwnerLimits, PriorityAggregateSourceOwnerResource,
    PriorityAggregateSpanSumRegex, RustProfile,
};
use fre_automata::{
    ActionCapabilities, DirectReduceLimits, EmptyMatchProgress, ExecutionProspective,
    ForcedExecution, PreparationError, PreparationLimits, PreparationProspective,
    PreparationResource, PriorityExecutionKernel, PriorityTarget, ReduceError,
};
use fre_lower::{FactError, FactLimits, FactOptionalProofs, FactResource};
use regex::bytes::RegexBuilder;

fn forced_count(pattern: &str, execution: ForcedExecution) -> PriorityAggregateCountRegex {
    PriorityAggregateBuilder::new(pattern)
        .build_count(execution, PriorityTarget::portable())
        .unwrap_or_else(|error| {
            panic!("failed to build {execution:?} Count for {pattern:?}: {error}")
        })
}

fn forced_span_sum(pattern: &str, execution: ForcedExecution) -> PriorityAggregateSpanSumRegex {
    PriorityAggregateBuilder::new(pattern)
        .build_span_sum(execution, PriorityTarget::portable())
        .unwrap_or_else(|error| {
            panic!("failed to build {execution:?} SpanSum for {pattern:?}: {error}")
        })
}

fn assert_sparse_values(pattern: &str, haystack: &[u8], count: u64, span_sum: u64) {
    let count_regex = forced_count(pattern, ForcedExecution::Sparse);
    let count_receipt = count_regex
        .count(haystack, PriorityAggregateRunLimits::default())
        .unwrap();
    assert_eq!(count_receipt.value(), count, "{pattern:?} Count");
    assert!(count_receipt.closes(), "{pattern:?} Count receipt");

    let span_sum_regex = forced_span_sum(pattern, ForcedExecution::Sparse);
    let span_sum_receipt = span_sum_regex
        .span_sum(haystack, PriorityAggregateRunLimits::default())
        .unwrap();
    assert_eq!(span_sum_receipt.value(), span_sum, "{pattern:?} SpanSum");
    assert!(span_sum_receipt.closes(), "{pattern:?} SpanSum receipt");
}

fn one_below_usize(value: usize) -> usize {
    value.checked_sub(1).expect("positive exact limit")
}

fn one_below_u64(value: u64) -> u64 {
    value.checked_sub(1).expect("positive exact limit")
}

#[test]
fn forced_priority_receipt_schema_identity_is_current() {
    assert_eq!(PRIORITY_AGGREGATE_SCHEMA_VERSION, 6);
    assert_eq!(
        PRIORITY_AGGREGATE_ACCOUNTING_ID,
        "fre.priority-aggregate.facade.v6"
    );
}

fn exact_preparation_limits(prospective: PreparationProspective) -> PreparationLimits {
    PreparationLimits {
        max_pattern_terminals: prospective.pattern_terminals,
        max_dfa_states: prospective.dfa_states,
        max_transition_cells: prospective.transition_cells,
        max_subset_items: prospective.subset_items,
        max_tagged_dispatch_states: prospective.tagged_dispatch_states,
        max_tagged_dispatch_cells: prospective.tagged_dispatch_cells,
        max_tagged_candidate_items: prospective.tagged_candidate_items,
        max_work: prospective.work,
        max_persistent_bytes: prospective.persistent_bytes,
        max_peak_bytes: prospective.peak_bytes,
        max_allocation_attempts: prospective.allocation_attempts,
    }
}

fn exact_execution_limits(prospective: ExecutionProspective) -> DirectReduceLimits {
    DirectReduceLimits {
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
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegexBytesOracle {
    count: u64,
    span_sum: u64,
    empty_matches: usize,
}

fn pinned_regex_bytes_oracle(pattern: &str, haystack: &[u8]) -> RegexBytesOracle {
    let regex = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .unwrap_or_else(|error| panic!("pinned bytes regex {pattern:?}: {error}"));
    let mut oracle = RegexBytesOracle {
        count: 0,
        span_sum: 0,
        empty_matches: 0,
    };
    // The forced facade's direct reducer restarts a selected empty match at
    // the next raw byte and still visits the terminal boundary once. Re-drive
    // the pinned matcher with that rule instead of using `find_iter`, whose
    // generic iterator suppresses the empty match immediately after a
    // consuming match.
    let mut start = 0;
    while let Some(matched) = regex.find_at(haystack, start) {
        oracle.count = oracle
            .count
            .checked_add(1)
            .expect("small pinned bytes match count");
        oracle.span_sum = oracle
            .span_sum
            .checked_add(u64::try_from(matched.len()).expect("small pinned bytes span"))
            .expect("small pinned bytes span sum");
        if matched.is_empty() {
            oracle.empty_matches = oracle
                .empty_matches
                .checked_add(1)
                .expect("small pinned bytes empty-match count");
        }
        if matched.is_empty() {
            if matched.end() == haystack.len() {
                break;
            }
            start = matched
                .end()
                .checked_add(1)
                .expect("small pinned bytes empty-match restart");
        } else {
            start = matched.end();
        }
    }
    oracle
}

fn assert_receipt_matches_oracle(
    receipt: &fre::PriorityAggregateExecutionReceipt,
    expected: RegexBytesOracle,
    expected_kernel: PriorityExecutionKernel,
    context: &str,
) {
    assert_eq!(receipt.kernel(), expected_kernel, "{context} kernel");
    assert_eq!(
        receipt.actual().match_events,
        usize::try_from(expected.count).expect("small pinned bytes match count"),
        "{context} events"
    );
    assert_eq!(
        receipt.actual().empty_match_events,
        expected.empty_matches,
        "{context} empty events"
    );
    assert_eq!(
        receipt.actual().selected_span_bytes,
        expected.span_sum,
        "{context} selected spans"
    );
    assert_eq!(
        receipt.actual().selected_ordinal_sum,
        0,
        "{context} ordinal"
    );
    assert!(receipt.closes(), "{context} receipt");
}

fn assert_nullable_target_rejects_undeclared_tagged_kernel(
    pattern: &str,
    execution: ForcedExecution,
    expected_kernel: PriorityExecutionKernel,
) {
    let mut target = PriorityTarget::portable();
    target.sparse = false;
    let error = PriorityAggregateBuilder::new(pattern)
        .build_count(execution, target)
        .expect_err("nullable forced route must reject an undeclared tagged substrate");
    match error {
        PriorityAggregateBuildError::Preparation(PreparationError::UnsupportedTargetKernel {
            execution: actual_execution,
            kernel: actual_kernel,
        }) => {
            assert_eq!(actual_execution, execution, "{pattern:?} target execution");
            assert_eq!(actual_kernel, expected_kernel, "{pattern:?} target kernel");
        }
        other => panic!("unexpected nullable target failure for {pattern:?}: {other:?}"),
    }
}

#[test]
#[ignore = "requires the authenticated expanded Rebar pattern directory"]
fn date_envelope_closes_all_routes_at_exact_fact_work_and_refuses_one_below() {
    let root = std::env::var_os("FRE_EXPANDED_REBAR_DIR")
        .expect("FRE_EXPANDED_REBAR_DIR points at the authenticated expansion");
    let path = std::path::Path::new(&root)
        .join("blobs")
        .join("sha256-97cd171850089efa20adec84678649a72ccf0d75170baaff15a5219042b0e46d.pattern");
    let pattern = std::fs::read_to_string(path).expect("Date pattern is UTF-8");
    let sample = b"Mon Jan 02 03:04:05 2006; 2019-01-02; invalid 2019-99-99";
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = true;
    profile.options.case_insensitive = true;
    let mut expected = None;
    for execution in [
        ForcedExecution::Sparse,
        ForcedExecution::FiniteHorizon,
        ForcedExecution::FullDfa,
        ForcedExecution::LazyDfa,
    ] {
        let built = PriorityAggregateBuilder::new(pattern.clone())
            .profile(profile.clone())
            .build_span_sum(execution, PriorityTarget::portable())
            .unwrap_or_else(|error| panic!("default Date {execution:?} build: {error}"));
        let expected_kernel = match execution {
            ForcedExecution::Sparse => PriorityExecutionKernel::SparseReverse,
            ForcedExecution::FiniteHorizon => PriorityExecutionKernel::InputBoundedReverse,
            ForcedExecution::FullDfa => PriorityExecutionKernel::FullTaggedReverse,
            ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyTaggedReverse,
            _ => unreachable!("test covers explicit forced routes only"),
        };
        assert_eq!(built.build_report().kernel(), expected_kernel);
        if execution == ForcedExecution::FiniteHorizon {
            assert!(matches!(
                built.build_report().route_proof(),
                fre::PriorityAggregateRouteProof::InputBoundedHorizon
            ));
        }
        assert!(built.build_report().closes(), "default Date {execution:?}");
        let prospective = built.build_report().facts().prospective();
        assert!(prospective.work() > 0, "Date {execution:?} fact work");
        let receipt = built
            .span_sum(sample, PriorityAggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("Date {execution:?} execution: {error}"));
        assert!(receipt.closes(), "Date {execution:?} receipt");
        assert_eq!(receipt.kernel(), expected_kernel);
        let expected_value = expected.get_or_insert(receipt.value());
        assert_eq!(receipt.value(), *expected_value, "Date {execution:?}");

        let exact = PriorityAggregateBuilder::new(pattern.clone())
            .profile(profile.clone())
            .limits(PriorityAggregateBuildLimits {
                facts: FactLimits {
                    max_work: prospective.work(),
                    ..FactLimits::default()
                },
                ..PriorityAggregateBuildLimits::default()
            })
            .build_span_sum(execution, PriorityTarget::portable())
            .unwrap_or_else(|error| panic!("exact Date {execution:?} fact work: {error}"));
        assert!(exact.build_report().closes(), "exact Date {execution:?}");

        let below = one_below_u64(prospective.work());
        let error = PriorityAggregateBuilder::new(pattern.clone())
            .profile(profile.clone())
            .limits(PriorityAggregateBuildLimits {
                facts: FactLimits {
                    max_work: below,
                    ..FactLimits::default()
                },
                ..PriorityAggregateBuildLimits::default()
            })
            .build_span_sum(execution, PriorityTarget::portable())
            .expect_err("one-below Date fact work must fail before lowering");
        assert!(matches!(
            error,
            PriorityAggregateBuildError::Facts(FactError::ResourceLimit {
                resource: FactResource::Work,
                needed,
                limit,
            }) if needed == prospective.work() && limit == below
        ));
    }
}

#[test]
fn valid_literal_count_and_span_sum_publish_all_four_forced_routes() {
    let haystack = b"zababxab";
    for execution in [
        ForcedExecution::Sparse,
        ForcedExecution::FiniteHorizon,
        ForcedExecution::FullDfa,
        ForcedExecution::LazyDfa,
    ] {
        let count = forced_count("ab", execution);
        assert_eq!(count.build_report().execution(), execution);
        assert_eq!(
            count.build_report().operation(),
            PriorityAggregateOperation::Count
        );
        assert_eq!(count.build_report().pattern_action().ordinal().get(), 0);
        assert_eq!(
            count.build_report().pattern_action().capabilities(),
            ActionCapabilities::MATCH.union(ActionCapabilities::DIRECT_REDUCE)
        );
        assert_eq!(
            count.build_report().empty_progress(),
            EmptyMatchProgress::Byte
        );
        assert!(
            count
                .build_report()
                .facts()
                .identity()
                .authenticates_current()
        );
        let expected_optional_proofs = match execution {
            ForcedExecution::Sparse => FactOptionalProofs::CoreOnly,
            ForcedExecution::FiniteHorizon => FactOptionalProofs::AssertionContext,
            ForcedExecution::FullDfa | ForcedExecution::LazyDfa => {
                FactOptionalProofs::AssertionContext
            }
            _ => unreachable!("test covers explicit forced routes only"),
        };
        assert_eq!(
            count.build_report().facts().operation().optional_proofs(),
            expected_optional_proofs
        );
        let expected_kernel = match execution {
            ForcedExecution::Sparse => PriorityExecutionKernel::SparseReverse,
            ForcedExecution::FiniteHorizon => PriorityExecutionKernel::FiniteHorizonReverse,
            ForcedExecution::FullDfa => PriorityExecutionKernel::FullDfa,
            ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyDfa,
            _ => unreachable!("test covers explicit forced routes only"),
        };
        assert_eq!(count.build_report().kernel(), expected_kernel);
        assert!(count.build_report().closes());
        let count_receipt = count
            .count(haystack, PriorityAggregateRunLimits::default())
            .unwrap();
        assert_eq!(count_receipt.execution(), execution);
        assert_eq!(count_receipt.kernel(), expected_kernel);
        assert_eq!(count_receipt.value(), 3);
        assert!(count_receipt.closes());

        let span_sum = forced_span_sum("ab", execution);
        assert_eq!(span_sum.build_report().execution(), execution);
        assert_eq!(
            span_sum.build_report().operation(),
            PriorityAggregateOperation::SpanSum
        );
        assert!(span_sum.build_report().closes());
        let span_sum_receipt = span_sum
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .unwrap();
        assert_eq!(span_sum_receipt.execution(), execution);
        assert_eq!(span_sum_receipt.kernel(), expected_kernel);
        assert_eq!(span_sum_receipt.value(), 6);
        assert!(span_sum_receipt.closes());
    }
}

#[test]
fn captured_priority_pattern_erases_captures_and_closes_every_forced_route() {
    let pattern = r"b|((?:a|(b)))";
    let haystack = b"zababxab";
    for execution in [
        ForcedExecution::Sparse,
        ForcedExecution::FiniteHorizon,
        ForcedExecution::FullDfa,
        ForcedExecution::LazyDfa,
    ] {
        let count = forced_count(pattern, execution);
        let count_facts = count.build_report().facts();
        assert_eq!(count_facts.capture_count(), 0, "{execution:?} Count");
        assert!(
            count_facts.capture_erasure_permitted(),
            "{execution:?} Count"
        );
        assert!(count_facts.identity().authenticates_current());
        assert!(count.build_report().closes(), "{execution:?} Count build");
        let count_receipt = count
            .count(haystack, PriorityAggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("{execution:?} Count failed: {error}"));
        assert_eq!(count_receipt.value(), 6, "{execution:?} Count");
        assert!(count_receipt.closes(), "{execution:?} Count receipt");

        let span_sum = forced_span_sum(pattern, execution);
        let span_facts = span_sum.build_report().facts();
        assert_eq!(span_facts.capture_count(), 0, "{execution:?} SpanSum");
        assert!(
            span_facts.capture_erasure_permitted(),
            "{execution:?} SpanSum"
        );
        assert!(
            span_sum.build_report().closes(),
            "{execution:?} SpanSum build"
        );
        let span_receipt = span_sum
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("{execution:?} SpanSum failed: {error}"));
        assert_eq!(span_receipt.value(), 6, "{execution:?} SpanSum");
        assert!(span_receipt.closes(), "{execution:?} SpanSum receipt");
    }

    let sparse = forced_count(pattern, ForcedExecution::Sparse);
    let facts = sparse.build_report().facts();
    let prospective = facts.prospective();
    let exact = PriorityAggregateBuilder::new(pattern)
        .limits(PriorityAggregateBuildLimits {
            facts: FactLimits {
                max_work: prospective.work(),
                ..FactLimits::default()
            },
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .expect("exact sparse fact prospective passes");
    assert!(exact.build_report().closes());

    let below = one_below_u64(prospective.work());
    let error = PriorityAggregateBuilder::new(pattern)
        .limits(PriorityAggregateBuildLimits {
            facts: FactLimits {
                max_work: below,
                ..FactLimits::default()
            },
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .expect_err("one-below sparse fact prospective fails before lowering");
    assert!(matches!(
        error,
        PriorityAggregateBuildError::Facts(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit,
        }) if needed == prospective.work() && limit == below
    ));
}

#[test]
fn sparse_facade_preserves_priority_greediness_laziness_and_empty_progress() {
    assert_sparse_values("a|ab", b"abab", 2, 2);
    assert_sparse_values("ab|a", b"abab", 2, 4);
    assert_sparse_values("a+", b"aaa", 1, 3);
    assert_sparse_values("a+?", b"aaa", 3, 3);
    assert_sparse_values("a*", b"b", 2, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the nullable tagged facade matrix keeps the pinned oracle, route authentication, target denial, and exact construction/execution envelopes together"
)]
fn nullable_tagged_full_lazy_facade_matrix_closes_semantics_resources_and_targets() {
    let resource_haystack = b"aa";
    let byte_progress_haystack = b"\xC3\xA9";
    let fixtures = [
        ("a*", "greedy-star"),
        ("a*?", "lazy-star"),
        ("a{0,3}", "bounded-nullable"),
        ("(?:|a)", "nullable-alternation"),
    ];

    // Keep the observable greedy/lazy difference explicit before comparing
    // every tagged route to the pinned bytes-regex and sparse references.
    assert_eq!(
        pinned_regex_bytes_oracle("a*", resource_haystack),
        RegexBytesOracle {
            count: 2,
            span_sum: 2,
            empty_matches: 1,
        }
    );
    assert_eq!(
        pinned_regex_bytes_oracle("a*?", resource_haystack),
        RegexBytesOracle {
            count: 3,
            span_sum: 0,
            empty_matches: 3,
        }
    );

    for (pattern, label) in fixtures {
        // `Regex::bytes` advances a nullable iterator one byte at a time,
        // including between the two UTF-8 code units here. The facade must
        // authenticate that same Byte progress, not Unicode-scalar progress.
        assert_eq!(
            pinned_regex_bytes_oracle(pattern, byte_progress_haystack),
            RegexBytesOracle {
                count: 3,
                span_sum: 0,
                empty_matches: 3,
            },
            "{label} pinned byte progress"
        );

        let sparse_count = forced_count(pattern, ForcedExecution::Sparse);
        let sparse_span_sum = forced_span_sum(pattern, ForcedExecution::Sparse);
        for (execution, expected_kernel) in [
            (
                ForcedExecution::FullDfa,
                PriorityExecutionKernel::FullTaggedReverse,
            ),
            (
                ForcedExecution::LazyDfa,
                PriorityExecutionKernel::LazyTaggedReverse,
            ),
        ] {
            let count = forced_count(pattern, execution);
            let span_sum = forced_span_sum(pattern, execution);
            for report in [count.build_report(), span_sum.build_report()] {
                assert_eq!(report.kernel(), expected_kernel, "{label}/{execution:?}");
                assert_eq!(
                    report.route_proof(),
                    fre::PriorityAggregateRouteProof::AssertionContext { minimum_bytes: 0 },
                    "{label}/{execution:?}"
                );
                assert_eq!(report.empty_progress(), EmptyMatchProgress::Byte);
                assert!(report.closes(), "{label}/{execution:?}");
            }

            let preparation = count.build_report().preparation();
            assert_eq!(preparation, span_sum.build_report().preparation());
            let exact_build_count = PriorityAggregateBuilder::new(pattern)
                .limits(PriorityAggregateBuildLimits {
                    preparation: exact_preparation_limits(preparation.prospective),
                    ..PriorityAggregateBuildLimits::default()
                })
                .build_count(execution, PriorityTarget::portable())
                .unwrap_or_else(|error| {
                    panic!("exact nullable {label}/{execution:?} preparation: {error}")
                });
            let exact_build_span_sum = PriorityAggregateBuilder::new(pattern)
                .limits(PriorityAggregateBuildLimits {
                    preparation: exact_preparation_limits(preparation.prospective),
                    ..PriorityAggregateBuildLimits::default()
                })
                .build_span_sum(execution, PriorityTarget::portable())
                .unwrap_or_else(|error| {
                    panic!("exact nullable {label}/{execution:?} SpanSum preparation: {error}")
                });
            assert_eq!(
                exact_build_count.build_report().preparation(),
                preparation,
                "{label}/{execution:?} exact Count preparation"
            );
            assert_eq!(
                exact_build_count.build_report().kernel(),
                expected_kernel,
                "{label}/{execution:?} exact Count kernel"
            );
            assert!(
                exact_build_count.build_report().closes(),
                "{label}/{execution:?} exact Count build"
            );
            assert_eq!(
                exact_build_span_sum.build_report().preparation(),
                preparation,
                "{label}/{execution:?} exact SpanSum preparation"
            );
            assert_eq!(
                exact_build_span_sum.build_report().kernel(),
                expected_kernel,
                "{label}/{execution:?} exact SpanSum kernel"
            );
            assert!(
                exact_build_span_sum.build_report().closes(),
                "{label}/{execution:?} exact SpanSum build"
            );

            assert_nullable_target_rejects_undeclared_tagged_kernel(
                pattern,
                execution,
                expected_kernel,
            );

            for (haystack_label, haystack) in [
                ("empty", b"".as_slice()),
                ("ascii", resource_haystack.as_slice()),
                ("prefix-miss", b"baaa".as_slice()),
                ("byte-progress", byte_progress_haystack.as_slice()),
            ] {
                let expected = pinned_regex_bytes_oracle(pattern, haystack);
                let expected_count = sparse_count
                    .count(haystack, PriorityAggregateRunLimits::default())
                    .unwrap_or_else(|error| panic!("sparse {label} Count: {error}"));
                assert_eq!(
                    expected_count.value(),
                    expected.count,
                    "{label}/{haystack_label}"
                );
                assert_receipt_matches_oracle(
                    &expected_count,
                    expected,
                    PriorityExecutionKernel::SparseReverse,
                    &format!("sparse {label}/Count/{haystack_label}"),
                );
                let actual_count = count
                    .count(haystack, PriorityAggregateRunLimits::default())
                    .unwrap_or_else(|error| {
                        panic!("{label}/{execution:?} Count/{haystack_label}: {error}")
                    });
                assert_eq!(
                    actual_count.value(),
                    expected_count.value(),
                    "{label}/{execution:?}/Count/{haystack_label}"
                );
                assert_receipt_matches_oracle(
                    &actual_count,
                    expected,
                    expected_kernel,
                    &format!("{label}/{execution:?}/Count/{haystack_label}"),
                );

                let expected_span_sum = sparse_span_sum
                    .span_sum(haystack, PriorityAggregateRunLimits::default())
                    .unwrap_or_else(|error| panic!("sparse {label} SpanSum: {error}"));
                assert_eq!(
                    expected_span_sum.value(),
                    expected.span_sum,
                    "{label}/{haystack_label}"
                );
                assert_receipt_matches_oracle(
                    &expected_span_sum,
                    expected,
                    PriorityExecutionKernel::SparseReverse,
                    &format!("sparse {label}/SpanSum/{haystack_label}"),
                );
                let actual_span_sum = span_sum
                    .span_sum(haystack, PriorityAggregateRunLimits::default())
                    .unwrap_or_else(|error| {
                        panic!("{label}/{execution:?} SpanSum/{haystack_label}: {error}")
                    });
                assert_eq!(
                    actual_span_sum.value(),
                    expected_span_sum.value(),
                    "{label}/{execution:?}/SpanSum/{haystack_label}"
                );
                assert_receipt_matches_oracle(
                    &actual_span_sum,
                    expected,
                    expected_kernel,
                    &format!("{label}/{execution:?}/SpanSum/{haystack_label}"),
                );
            }

            let count_probe = count
                .count(resource_haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("{label}/{execution:?} Count probe: {error}"));
            assert!(
                count_probe.prospective().tagged_dispatch_states_capacity > 0,
                "{label}/{execution:?}"
            );
            let exact_execution = exact_execution_limits(count_probe.prospective());
            let exact_count_limits = PriorityAggregateRunLimits {
                execution: exact_execution,
                max_output: u64::try_from(resource_haystack.len() + 1)
                    .expect("small Count output bound"),
            };
            let exact_count = count
                .count(resource_haystack, exact_count_limits)
                .unwrap_or_else(|error| panic!("exact {label}/{execution:?} Count: {error}"));
            assert_eq!(exact_count.prospective(), count_probe.prospective());
            assert_eq!(exact_count.actual(), count_probe.actual());
            assert_eq!(exact_count.kernel(), expected_kernel);
            assert_eq!(exact_count.value(), count_probe.value());
            assert!(exact_count.closes());

            let span_probe = span_sum
                .span_sum(resource_haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("{label}/{execution:?} SpanSum probe: {error}"));
            assert_eq!(span_probe.prospective(), count_probe.prospective());
            let exact_span_sum = span_sum
                .span_sum(
                    resource_haystack,
                    PriorityAggregateRunLimits {
                        execution: exact_execution,
                        max_output: u64::try_from(resource_haystack.len())
                            .expect("small SpanSum output bound"),
                    },
                )
                .unwrap_or_else(|error| panic!("exact {label}/{execution:?} SpanSum: {error}"));
            assert_eq!(exact_span_sum.prospective(), count_probe.prospective());
            assert_eq!(exact_span_sum.actual(), span_probe.actual());
            assert_eq!(exact_span_sum.kernel(), expected_kernel);
            assert_eq!(exact_span_sum.value(), span_probe.value());
            assert!(exact_span_sum.closes());
        }
    }
}

#[test]
fn value_facts_erase_source_captures_before_priority_analysis() {
    let pattern = r"(?:a|(ab))c";
    let haystack = b"acabc";
    let count = forced_count(pattern, ForcedExecution::Sparse);
    assert_eq!(count.build_report().syntax().summary().captures, 1);
    assert_eq!(count.build_report().facts().capture_count(), 0);
    assert!(count.build_report().facts().operation().erases_captures());
    assert_eq!(count.build_report().lowering().erased_captures(), 1);
    assert!(count.build_report().closes());
    let receipt = count
        .count(haystack, PriorityAggregateRunLimits::default())
        .expect("capture-erased sparse Count");
    assert_eq!(receipt.value(), 2);
    assert_eq!(
        receipt.actual().suffix_reducer_steps,
        receipt.prospective().boundary_rows
    );
    assert!(receipt.closes());

    let span_sum = forced_span_sum(pattern, ForcedExecution::Sparse);
    let receipt = span_sum
        .span_sum(haystack, PriorityAggregateRunLimits::default())
        .expect("capture-erased sparse SpanSum");
    assert_eq!(receipt.value(), 5);
    assert!(receipt.closes());
}

#[test]
fn capture_erasure_feeds_exact_width_full_and_lazy_routes() {
    let haystack = b"zabab";
    for execution in [ForcedExecution::FullDfa, ForcedExecution::LazyDfa] {
        let count = forced_count("(ab)", execution);
        assert_eq!(count.build_report().syntax().summary().captures, 1);
        assert_eq!(count.build_report().facts().capture_count(), 0);
        assert_eq!(
            count
                .count(haystack, PriorityAggregateRunLimits::default())
                .expect("capture-erased deterministic Count")
                .value(),
            2
        );

        let span_sum = forced_span_sum("(ab)", execution);
        assert_eq!(
            span_sum
                .span_sum(haystack, PriorityAggregateRunLimits::default())
                .expect("capture-erased deterministic SpanSum")
                .value(),
            4
        );
        assert!(span_sum.build_report().closes());
    }
}

#[test]
fn finite_horizon_retains_unicode_word_assertion_context() {
    let pattern = r"\b(?:cat|cater)\b";
    let haystack = "cat cater scat caté cat".as_bytes();
    let count = forced_count(pattern, ForcedExecution::FiniteHorizon);
    let decision_horizon_bytes = match count.build_report().route_proof() {
        fre::PriorityAggregateRouteProof::FiniteHorizon { maximum_bytes } => maximum_bytes,
        other => panic!("unexpected finite route proof: {other:?}"),
    };
    let retention_bytes = count
        .build_report()
        .static_reducer_retention_bytes()
        .expect("finite route has a static ring");
    assert!(retention_bytes >= 5);
    assert!(decision_horizon_bytes > retention_bytes);
    assert_eq!(
        count
            .count(haystack, PriorityAggregateRunLimits::default())
            .expect("finite Unicode-word Count")
            .value(),
        3
    );
    assert!(count.build_report().closes());

    let span_sum = forced_span_sum(pattern, ForcedExecution::FiniteHorizon);
    assert_eq!(
        span_sum
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .expect("finite Unicode-word SpanSum")
            .value(),
        11
    );
    assert!(span_sum.build_report().closes());
}

#[test]
fn finite_horizon_assertion_cap_refusals_preserve_stream_end_projection() {
    macro_rules! assert_projection {
        (
            $pattern:expr,
            $build:ident,
            $expected_route:pat,
            $expected_refusal:path,
            $label:literal
        ) => {{
            let baseline = PriorityAggregateBuilder::new($pattern)
                .$build(ForcedExecution::FiniteHorizon, PriorityTarget::portable())
                .unwrap_or_else(|error| panic!("{} baseline: {error}", $label));
            let assertions = baseline.build_report().facts().prospective().assertions();
            assert!(assertions > 0, "{} fixture has assertions", $label);

            let exact = PriorityAggregateBuilder::new($pattern)
                .limits(PriorityAggregateBuildLimits {
                    facts: FactLimits {
                        max_assertions: assertions,
                        ..FactLimits::default()
                    },
                    ..PriorityAggregateBuildLimits::default()
                })
                .$build(ForcedExecution::FiniteHorizon, PriorityTarget::portable())
                .unwrap_or_else(|error| panic!("{} exact assertion cap: {error}", $label));
            assert!(matches!(
                exact.build_report().route_proof(),
                $expected_route
            ));
            assert!(exact.build_report().closes(), "{} exact cap closes", $label);

            let below = one_below_usize(assertions);
            let error = PriorityAggregateBuilder::new($pattern)
                .limits(PriorityAggregateBuildLimits {
                    facts: FactLimits {
                        max_assertions: below,
                        ..FactLimits::default()
                    },
                    ..PriorityAggregateBuildLimits::default()
                })
                .$build(ForcedExecution::FiniteHorizon, PriorityTarget::portable())
                .expect_err("one-below assertion cap must be a route refusal");
            assert!(matches!(
                error,
                PriorityAggregateBuildError::MissingRouteProof {
                    execution: ForcedExecution::FiniteHorizon,
                    proof: $expected_refusal,
                }
            ));
        }};
    }

    let non_stream = r"\b(?:cat|cater)\b";
    assert_projection!(
        non_stream,
        build_count,
        fre::PriorityAggregateRouteProof::FiniteHorizon { .. },
        fre::PriorityAggregateProofRefusal::FiniteDecisionHorizon,
        "finite non-stream Count"
    );
    assert_projection!(
        non_stream,
        build_span_sum,
        fre::PriorityAggregateRouteProof::FiniteHorizon { .. },
        fre::PriorityAggregateProofRefusal::FiniteDecisionHorizon,
        "finite non-stream SpanSum"
    );

    let stream_end = r"a{1,3}\z";
    assert_projection!(
        stream_end,
        build_count,
        fre::PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
            maximum_match_bytes: 3
        },
        fre::PriorityAggregateProofRefusal::AssertionContext,
        "finite stream-end Count"
    );
    assert_projection!(
        stream_end,
        build_span_sum,
        fre::PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
            maximum_match_bytes: 3
        },
        fre::PriorityAggregateProofRefusal::AssertionContext,
        "finite stream-end SpanSum"
    );

    let input_bounded = r"a*\z";
    assert_projection!(
        input_bounded,
        build_count,
        fre::PriorityAggregateRouteProof::InputBoundedHorizon,
        fre::PriorityAggregateProofRefusal::AssertionContext,
        "input-bounded Count"
    );
    assert_projection!(
        input_bounded,
        build_span_sum,
        fre::PriorityAggregateRouteProof::InputBoundedHorizon,
        fre::PriorityAggregateProofRefusal::AssertionContext,
        "input-bounded SpanSum"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn finite_width_stream_end_uses_a_non_streaming_static_ring() {
    let pattern = r"a{1,3}\z";
    let finite_count = forced_count(pattern, ForcedExecution::FiniteHorizon);
    assert_eq!(
        finite_count.build_report().kernel(),
        PriorityExecutionKernel::FiniteHorizonReverse
    );
    assert!(matches!(
        finite_count.build_report().route_proof(),
        fre::PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
            maximum_match_bytes: 3
        }
    ));
    assert_eq!(
        finite_count.build_report().static_reducer_retention_bytes(),
        Some(3)
    );
    assert_eq!(
        finite_count
            .build_report()
            .facts()
            .finite_decision_horizon(),
        fre::PriorityAggregateUsizeProof::Unknown
    );
    assert!(finite_count.build_report().closes());

    let finite_span_sum = forced_span_sum(pattern, ForcedExecution::FiniteHorizon);
    for haystack in [b"".as_slice(), b"a", b"aaa", b"baaa", b"aaaa", b"aaab"] {
        let sparse_count = forced_count(pattern, ForcedExecution::Sparse)
            .count(haystack, PriorityAggregateRunLimits::default())
            .expect("sparse finite-width stream-end Count");
        let finite_count_receipt = finite_count
            .count(haystack, PriorityAggregateRunLimits::default())
            .expect("finite-width stream-end Count");
        assert_eq!(
            finite_count_receipt.value(),
            sparse_count.value(),
            "{haystack:?}"
        );
        assert!(finite_count_receipt.closes(), "{haystack:?} Count receipt");
        assert_eq!(
            finite_count_receipt.static_reducer_retention_bytes(),
            Some(3),
            "{haystack:?} Count retention"
        );

        let sparse_span_sum = forced_span_sum(pattern, ForcedExecution::Sparse)
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .expect("sparse finite-width stream-end SpanSum");
        let finite_span_sum_receipt = finite_span_sum
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .expect("finite-width stream-end SpanSum");
        assert_eq!(
            finite_span_sum_receipt.value(),
            sparse_span_sum.value(),
            "{haystack:?}"
        );
        assert!(
            finite_span_sum_receipt.closes(),
            "{haystack:?} SpanSum receipt"
        );
    }

    let long_haystack = vec![b'a'; 64];
    let sparse = forced_count(pattern, ForcedExecution::Sparse)
        .count(&long_haystack, PriorityAggregateRunLimits::default())
        .expect("sparse long finite-width stream-end Count");
    let finite = finite_count
        .count(&long_haystack, PriorityAggregateRunLimits::default())
        .expect("finite long finite-width stream-end Count");
    assert_eq!(finite.value(), sparse.value());
    // Both routes scan every source boundary; only the finite route's
    // retained suffix ring is width-bounded.
    assert_eq!(finite.prospective().boundary_rows, long_haystack.len() + 1);
    assert_eq!(sparse.prospective().boundary_rows, long_haystack.len() + 1);
    assert!(finite.prospective().scratch_bytes < sparse.prospective().scratch_bytes);

    let prospective = finite.prospective();
    let exact = PriorityAggregateRunLimits {
        execution: DirectReduceLimits {
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
        },
        max_output: u64::try_from(long_haystack.len() + 1).expect("small output bound"),
    };
    let exact_receipt = finite_count
        .count(&long_haystack, exact)
        .expect("exact finite-width stream-end limits");
    assert_eq!(exact_receipt.value(), finite.value());
    assert!(exact_receipt.closes());

    // The two capture-erased `u64` reducers share the same internal P
    // envelope; only their public output cap/value differs.
    let span_exact_receipt = finite_span_sum
        .span_sum(
            &long_haystack,
            PriorityAggregateRunLimits {
                execution: exact.execution,
                max_output: u64::try_from(long_haystack.len()).expect("small output bound"),
            },
        )
        .expect("exact finite-width stream-end SpanSum limits");
    assert_eq!(span_exact_receipt.prospective(), prospective);
    assert!(span_exact_receipt.closes());

    let scratch_below = one_below_usize(prospective.scratch_bytes);
    let error = finite_count
        .count(
            &long_haystack,
            PriorityAggregateRunLimits {
                execution: DirectReduceLimits {
                    max_scratch_bytes: scratch_below,
                    ..exact.execution
                },
                ..exact
            },
        )
        .expect_err("one-below static-ring scratch must fail before source");
    assert!(matches!(
        error.source,
        PriorityAggregateRunFailure::Execution(ReduceError::ScratchLimit { needed, limit })
            if needed == prospective.scratch_bytes && limit == scratch_below
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn finite_width_stream_end_matrix_matches_sparse_and_pinned_oracle() {
    for (pattern, maximum_match_bytes, samples) in [
        (
            r"ab\z",
            2,
            [
                ("no-match", b"zz".as_slice()),
                ("ends-at-eof", b"zzab".as_slice()),
                ("candidate-followed-by-byte", b"zzabx".as_slice()),
            ],
        ),
        (
            r"a{1,3}\z",
            3,
            [
                ("no-match", b"b".as_slice()),
                ("ends-at-eof", b"baaa".as_slice()),
                ("candidate-followed-by-byte", b"aaab".as_slice()),
            ],
        ),
    ] {
        let finite_count = forced_count(pattern, ForcedExecution::FiniteHorizon);
        let finite_span_sum = forced_span_sum(pattern, ForcedExecution::FiniteHorizon);
        for report in [finite_count.build_report(), finite_span_sum.build_report()] {
            assert_eq!(
                report.kernel(),
                PriorityExecutionKernel::FiniteHorizonReverse
            );
            assert_eq!(
                report.route_proof(),
                fre::PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                    maximum_match_bytes,
                },
                "{pattern:?}"
            );
            assert_eq!(
                report.static_reducer_retention_bytes(),
                Some(maximum_match_bytes),
                "{pattern:?}"
            );
            assert_eq!(
                report.facts().finite_decision_horizon(),
                fre::PriorityAggregateUsizeProof::Unknown,
                "{pattern:?}"
            );
            assert!(report.closes(), "{pattern:?}");
        }

        let sparse_count = forced_count(pattern, ForcedExecution::Sparse);
        let sparse_span_sum = forced_span_sum(pattern, ForcedExecution::Sparse);
        for (sample_label, haystack) in samples {
            let expected = pinned_regex_bytes_oracle(pattern, haystack);
            let sparse_count_receipt = sparse_count
                .count(haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("sparse Count {pattern:?}/{sample_label}: {error}"));
            assert_eq!(
                sparse_count_receipt.value(),
                expected.count,
                "sparse Count {pattern:?}/{sample_label}"
            );
            assert_receipt_matches_oracle(
                &sparse_count_receipt,
                expected,
                PriorityExecutionKernel::SparseReverse,
                &format!("sparse Count {pattern:?}/{sample_label}"),
            );
            let finite_count_receipt = finite_count
                .count(haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("finite Count {pattern:?}/{sample_label}: {error}"));
            assert_eq!(
                finite_count_receipt.value(),
                expected.count,
                "finite Count {pattern:?}/{sample_label}"
            );
            assert_eq!(
                finite_count_receipt.value(),
                sparse_count_receipt.value(),
                "Count sparse parity {pattern:?}/{sample_label}"
            );
            assert_eq!(
                finite_count_receipt.static_reducer_retention_bytes(),
                Some(maximum_match_bytes),
                "Count retention {pattern:?}/{sample_label}"
            );
            assert_receipt_matches_oracle(
                &finite_count_receipt,
                expected,
                PriorityExecutionKernel::FiniteHorizonReverse,
                &format!("finite Count {pattern:?}/{sample_label}"),
            );

            let sparse_span_receipt = sparse_span_sum
                .span_sum(haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| {
                    panic!("sparse SpanSum {pattern:?}/{sample_label}: {error}")
                });
            assert_eq!(
                sparse_span_receipt.value(),
                expected.span_sum,
                "sparse SpanSum {pattern:?}/{sample_label}"
            );
            assert_receipt_matches_oracle(
                &sparse_span_receipt,
                expected,
                PriorityExecutionKernel::SparseReverse,
                &format!("sparse SpanSum {pattern:?}/{sample_label}"),
            );
            let finite_span_receipt = finite_span_sum
                .span_sum(haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| {
                    panic!("finite SpanSum {pattern:?}/{sample_label}: {error}")
                });
            assert_eq!(
                finite_span_receipt.value(),
                expected.span_sum,
                "finite SpanSum {pattern:?}/{sample_label}"
            );
            assert_eq!(
                finite_span_receipt.value(),
                sparse_span_receipt.value(),
                "SpanSum sparse parity {pattern:?}/{sample_label}"
            );
            assert_eq!(
                finite_span_receipt.static_reducer_retention_bytes(),
                Some(maximum_match_bytes),
                "SpanSum retention {pattern:?}/{sample_label}"
            );
            assert_receipt_matches_oracle(
                &finite_span_receipt,
                expected,
                PriorityExecutionKernel::FiniteHorizonReverse,
                &format!("finite SpanSum {pattern:?}/{sample_label}"),
            );
        }
    }
}

#[test]
fn input_bounded_sparse_fallback_retains_end_context_and_exact_preflight() {
    let pattern = r"a*\z";
    let haystack = b"baaa";
    let count = forced_count(pattern, ForcedExecution::FiniteHorizon);
    assert_eq!(
        count.build_report().kernel(),
        PriorityExecutionKernel::InputBoundedReverse
    );
    assert!(matches!(
        count.build_report().route_proof(),
        fre::PriorityAggregateRouteProof::InputBoundedHorizon
    ));
    assert!(count.build_report().closes());

    let sparse = forced_count(pattern, ForcedExecution::Sparse)
        .count(haystack, PriorityAggregateRunLimits::default())
        .expect("sparse end-anchored Count");
    let receipt = count
        .count(haystack, PriorityAggregateRunLimits::default())
        .expect("input-bounded end-anchored Count");
    assert_eq!(receipt.value(), sparse.value());
    // The complete tail is selected first, followed by the byte-progressed
    // empty end match at the final boundary.
    assert_eq!(receipt.value(), 2);
    assert!(receipt.closes());
    assert_eq!(receipt.input_bounded_source_bytes(), Some(haystack.len()));
    assert_eq!(receipt.static_reducer_retention_bytes(), None);

    let prospective = receipt.prospective();
    let exact = PriorityAggregateRunLimits {
        execution: DirectReduceLimits {
            max_work: prospective.work_upper_bound,
            max_scratch_bytes: prospective.scratch_bytes,
            max_boundary_rows: prospective.boundary_rows,
            max_match_events: prospective.match_events_upper_bound,
            max_dfa_states: 0,
            max_dfa_cells: 0,
            max_subset_items: 0,
            max_tagged_dispatch_states: 0,
            max_tagged_dispatch_cells: 0,
            max_tagged_candidate_items: 0,
            max_tagged_cache_cells: 0,
            max_allocation_attempts: prospective.allocation_attempts,
        },
        ..PriorityAggregateRunLimits::default()
    };
    let exact_receipt = count
        .count(haystack, exact)
        .expect("exact input-bounded preflight");
    assert!(exact_receipt.closes());
    assert_eq!(exact_receipt.value(), receipt.value());

    let scratch_below = one_below_usize(prospective.scratch_bytes);
    let error = count
        .count(
            haystack,
            PriorityAggregateRunLimits {
                execution: DirectReduceLimits {
                    max_scratch_bytes: scratch_below,
                    ..exact.execution
                },
                ..exact
            },
        )
        .expect_err("one-below input-bounded scratch must fail before source");
    assert!(matches!(
        error.source,
        PriorityAggregateRunFailure::Execution(ReduceError::ScratchLimit { needed, limit })
            if needed == prospective.scratch_bytes && limit == scratch_below
    ));
}

#[test]
fn facade_rejects_legacy_route_bits_without_the_selected_kernel() {
    let mut missing_input_bounded_sparse = PriorityTarget::portable();
    missing_input_bounded_sparse.sparse = false;
    let error = PriorityAggregateBuilder::new(r"a*\z")
        .build_count(ForcedExecution::FiniteHorizon, missing_input_bounded_sparse)
        .expect_err("finite request must not publish an undeclared sparse fallback");
    assert!(matches!(
        error,
        PriorityAggregateBuildError::Preparation(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::FiniteHorizon,
            kernel: PriorityExecutionKernel::InputBoundedReverse,
        })
    ));

    let mut missing_full_tagged_sparse = PriorityTarget::portable();
    missing_full_tagged_sparse.sparse = false;
    let error = PriorityAggregateBuilder::new("a*")
        .build_count(ForcedExecution::FullDfa, missing_full_tagged_sparse)
        .expect_err("FullDfa request must not publish an undeclared tagged kernel");
    assert!(matches!(
        error,
        PriorityAggregateBuildError::Preparation(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::FullDfa,
            kernel: PriorityExecutionKernel::FullTaggedReverse,
        })
    ));

    let mut missing_lazy_tagged_sparse = PriorityTarget::portable();
    missing_lazy_tagged_sparse.sparse = false;
    let error = PriorityAggregateBuilder::new("a*?")
        .build_count(ForcedExecution::LazyDfa, missing_lazy_tagged_sparse)
        .expect_err("LazyDfa request must not publish an undeclared tagged kernel");
    assert!(matches!(
        error,
        PriorityAggregateBuildError::Preparation(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::LazyDfa,
            kernel: PriorityExecutionKernel::LazyTaggedReverse,
        })
    ));

    let portable = PriorityAggregateBuilder::new(r"a*\z")
        .build_count(ForcedExecution::FiniteHorizon, PriorityTarget::portable())
        .expect("portable target declares the selected sparse fallback");
    assert!(portable.build_report().closes());
    assert!(
        portable
            .count(b"baaa", PriorityAggregateRunLimits::default())
            .expect("portable fallback executes")
            .closes()
    );
}

#[test]
fn tagged_full_lazy_assertion_cap_refusals_remain_assertion_context() {
    let pattern = r"\b(?:cat|cater)\b";
    for (execution, expected_kernel) in [
        (
            ForcedExecution::FullDfa,
            PriorityExecutionKernel::FullTaggedReverse,
        ),
        (
            ForcedExecution::LazyDfa,
            PriorityExecutionKernel::LazyTaggedReverse,
        ),
    ] {
        let count = forced_count(pattern, execution);
        let span_sum = forced_span_sum(pattern, execution);
        let assertions = count.build_report().facts().prospective().assertions();
        assert!(assertions > 0, "{execution:?} fixture assertions");
        assert_eq!(
            assertions,
            span_sum.build_report().facts().prospective().assertions(),
            "{execution:?} Count/SpanSum assertions"
        );
        for report in [count.build_report(), span_sum.build_report()] {
            assert_eq!(report.kernel(), expected_kernel, "{execution:?}");
            assert!(matches!(
                report.route_proof(),
                fre::PriorityAggregateRouteProof::AssertionContext { .. }
            ));
            assert!(report.closes(), "{execution:?}");
        }

        let exact_facts = FactLimits {
            max_assertions: assertions,
            ..FactLimits::default()
        };
        let exact_count = PriorityAggregateBuilder::new(pattern)
            .limits(PriorityAggregateBuildLimits {
                facts: exact_facts,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_count(execution, PriorityTarget::portable())
            .expect("exact tagged Count assertion context must build");
        let exact_span_sum = PriorityAggregateBuilder::new(pattern)
            .limits(PriorityAggregateBuildLimits {
                facts: exact_facts,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_span_sum(execution, PriorityTarget::portable())
            .expect("exact tagged SpanSum assertion context must build");
        for report in [exact_count.build_report(), exact_span_sum.build_report()] {
            assert_eq!(
                report.limits().facts.max_assertions,
                assertions,
                "{execution:?} exact assertion cap"
            );
            assert_eq!(report.kernel(), expected_kernel, "{execution:?}");
            assert!(matches!(
                report.route_proof(),
                fre::PriorityAggregateRouteProof::AssertionContext { .. }
            ));
            assert!(report.closes(), "{execution:?} exact assertion cap");
        }

        let facts = FactLimits {
            max_assertions: one_below_usize(assertions),
            ..FactLimits::default()
        };
        let count_error = PriorityAggregateBuilder::new(pattern)
            .limits(PriorityAggregateBuildLimits {
                facts,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_count(execution, PriorityTarget::portable())
            .expect_err("one-below tagged Count assertion context must soft-refuse");
        let span_sum_error = PriorityAggregateBuilder::new(pattern)
            .limits(PriorityAggregateBuildLimits {
                facts,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_span_sum(execution, PriorityTarget::portable())
            .expect_err("one-below tagged SpanSum assertion context must soft-refuse");
        for error in [count_error, span_sum_error] {
            assert!(matches!(
                error,
                PriorityAggregateBuildError::MissingRouteProof {
                    execution: actual_execution,
                    proof: fre::PriorityAggregateProofRefusal::AssertionContext,
                } if actual_execution == execution
            ));
        }
    }
}

#[test]
fn certified_nullable_repetition_normalization_remains_authenticated() {
    let pattern = r"(?:a*)*";
    let haystack = b"aaab";
    let expected_count = forced_count("a*", ForcedExecution::Sparse)
        .count(haystack, PriorityAggregateRunLimits::default())
        .expect("normalized reference Count")
        .value();
    let expected_span_sum = forced_span_sum("a*", ForcedExecution::Sparse)
        .span_sum(haystack, PriorityAggregateRunLimits::default())
        .expect("normalized reference SpanSum")
        .value();

    let count = forced_count(pattern, ForcedExecution::Sparse);
    assert_eq!(
        count
            .build_report()
            .lowering()
            .normalized_nullable_repetitions(),
        1
    );
    assert!(count.build_report().closes());
    assert_eq!(
        count
            .count(haystack, PriorityAggregateRunLimits::default())
            .expect("normalized sparse Count")
            .value(),
        expected_count
    );

    let span_sum = forced_span_sum(pattern, ForcedExecution::Sparse);
    assert_eq!(
        span_sum
            .span_sum(haystack, PriorityAggregateRunLimits::default())
            .expect("normalized sparse SpanSum")
            .value(),
        expected_span_sum
    );
}

#[test]
fn sparse_facade_preserves_assertions_and_the_configured_line_terminator() {
    let haystack = b"ab~ab";
    let pattern = r"(?m:^ab$)";

    let default_count = forced_count(pattern, ForcedExecution::Sparse);
    assert_eq!(
        default_count
            .count(haystack, PriorityAggregateRunLimits::default())
            .unwrap()
            .value(),
        0
    );

    let mut profile = RustProfile::default();
    profile.options.line_terminator = b'~';
    let count = PriorityAggregateBuilder::new(pattern)
        .profile(profile.clone())
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let count_receipt = count
        .count(haystack, PriorityAggregateRunLimits::default())
        .unwrap();
    assert_eq!(count_receipt.value(), 2);
    assert!(count_receipt.closes());

    let span_sum = PriorityAggregateBuilder::new(pattern)
        .profile(profile)
        .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    let span_sum_receipt = span_sum
        .span_sum(haystack, PriorityAggregateRunLimits::default())
        .unwrap();
    assert_eq!(span_sum_receipt.value(), 4);
    assert!(span_sum_receipt.closes());
}

#[test]
fn sparse_unicode_class_skips_invalid_utf8_without_changing_scalar_spans() {
    let haystack = b"\xFF\xCE\xB1\xFE\xCE\xB2";
    assert_sparse_values(r"\p{Greek}+", haystack, 2, 4);
}

#[test]
fn bridge_limits_accept_the_exact_ledger() {
    let baseline = forced_count("ab", ForcedExecution::Sparse);
    let bridge = baseline.build_report().bridge();
    let prospective = bridge.prospective();
    assert_eq!(
        prospective.work,
        u64::try_from(baseline.build_report().automaton().states())
            .unwrap()
            .checked_mul(2)
            .unwrap()
    );
    assert_eq!(
        (
            bridge.work(),
            bridge.action_bytes(),
            bridge.peak_bytes(),
            bridge.pattern_terminals(),
            bridge.allocation_attempts(),
        ),
        (
            prospective.work,
            prospective.action_bytes,
            prospective.peak_bytes,
            prospective.pattern_terminals,
            prospective.allocation_attempts,
        )
    );

    let exact_bridge = PriorityAggregateBridgeLimits {
        max_work: prospective.work,
        max_action_bytes: prospective.action_bytes,
        max_peak_bytes: prospective.peak_bytes,
        max_pattern_terminals: prospective.pattern_terminals,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    let exact_limits = PriorityAggregateBuildLimits {
        bridge: exact_bridge,
        ..PriorityAggregateBuildLimits::default()
    };
    let exact = PriorityAggregateBuilder::new("ab")
        .limits(exact_limits)
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert_eq!(exact.build_report().bridge(), bridge);
    assert!(exact.build_report().closes());
}

#[test]
fn bridge_limits_refuse_every_one_below_before_allocation() {
    let baseline = forced_count("ab", ForcedExecution::Sparse);
    let prospective = baseline.build_report().bridge().prospective();
    let exact_bridge = PriorityAggregateBridgeLimits {
        max_work: prospective.work,
        max_action_bytes: prospective.action_bytes,
        max_peak_bytes: prospective.peak_bytes,
        max_pattern_terminals: prospective.pattern_terminals,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    let one_below = one_below_usize(prospective.action_bytes);
    let error = PriorityAggregateBuilder::new("ab")
        .limits(PriorityAggregateBuildLimits {
            bridge: PriorityAggregateBridgeLimits {
                max_action_bytes: one_below,
                ..exact_bridge
            },
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap_err();
    assert!(matches!(
        error,
        PriorityAggregateBuildError::BridgeResourceLimit {
            resource: PriorityAggregateBridgeResource::ActionBytes,
            needed,
            limit,
        } if needed == u64::try_from(prospective.action_bytes).unwrap()
            && limit == u64::try_from(one_below).unwrap()
    ));

    let one_below_work = one_below_u64(prospective.work);
    let error = PriorityAggregateBuilder::new("ab")
        .limits(PriorityAggregateBuildLimits {
            bridge: PriorityAggregateBridgeLimits {
                max_work: one_below_work,
                ..exact_bridge
            },
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap_err();
    assert!(matches!(
        error,
        PriorityAggregateBuildError::BridgeResourceLimit {
            resource: PriorityAggregateBridgeResource::Work,
            needed,
            limit,
        } if needed == prospective.work && limit == one_below_work
    ));

    for (resource, limits, expected_limit) in [
        (
            PriorityAggregateBridgeResource::PeakBytes,
            PriorityAggregateBridgeLimits {
                max_peak_bytes: one_below_usize(prospective.peak_bytes),
                ..exact_bridge
            },
            u64::try_from(one_below_usize(prospective.peak_bytes)).unwrap(),
        ),
        (
            PriorityAggregateBridgeResource::PatternTerminals,
            PriorityAggregateBridgeLimits {
                max_pattern_terminals: one_below_usize(prospective.pattern_terminals),
                ..exact_bridge
            },
            u64::try_from(one_below_usize(prospective.pattern_terminals)).unwrap(),
        ),
        (
            PriorityAggregateBridgeResource::AllocationAttempts,
            PriorityAggregateBridgeLimits {
                max_allocation_attempts: one_below_usize(prospective.allocation_attempts),
                ..exact_bridge
            },
            u64::try_from(one_below_usize(prospective.allocation_attempts)).unwrap(),
        ),
    ] {
        let error = PriorityAggregateBuilder::new("ab")
            .limits(PriorityAggregateBuildLimits {
                bridge: limits,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap_err();
        assert!(matches!(
            error,
            PriorityAggregateBuildError::BridgeResourceLimit {
                resource: actual,
                needed,
                limit,
            } if actual == resource && needed > limit && limit == expected_limit
        ));
    }
}

#[test]
fn source_owner_limits_accept_exact_and_refuse_each_one_below() {
    let baseline = forced_count("ab", ForcedExecution::Sparse);
    let owner = baseline.build_report().syntax().source_owner();
    let exact_owner = PriorityAggregateSourceOwnerLimits {
        max_allocation_bytes: owner.allocation_bytes(),
        max_handle_bytes: owner.handle_bytes(),
        max_allocation_attempts: owner.allocation_attempts(),
    };
    let exact = PriorityAggregateBuilder::new("ab")
        .limits(PriorityAggregateBuildLimits {
            source_owner: exact_owner,
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .unwrap();
    assert_eq!(exact.build_report().syntax().source_owner(), owner);
    assert!(exact.build_report().closes());

    for (resource, limits, expected_limit) in [
        (
            PriorityAggregateSourceOwnerResource::AllocationBytes,
            PriorityAggregateSourceOwnerLimits {
                max_allocation_bytes: one_below_usize(owner.allocation_bytes()),
                ..exact_owner
            },
            one_below_usize(owner.allocation_bytes()),
        ),
        (
            PriorityAggregateSourceOwnerResource::HandleBytes,
            PriorityAggregateSourceOwnerLimits {
                max_handle_bytes: one_below_usize(owner.handle_bytes()),
                ..exact_owner
            },
            one_below_usize(owner.handle_bytes()),
        ),
        (
            PriorityAggregateSourceOwnerResource::AllocationAttempts,
            PriorityAggregateSourceOwnerLimits {
                max_allocation_attempts: one_below_usize(owner.allocation_attempts()),
                ..exact_owner
            },
            one_below_usize(owner.allocation_attempts()),
        ),
    ] {
        let error = PriorityAggregateBuilder::new("ab")
            .limits(PriorityAggregateBuildLimits {
                source_owner: limits,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap_err();
        assert!(matches!(
            error,
            PriorityAggregateBuildError::SourceOwnerResourceLimit {
                resource: actual,
                needed,
                limit,
            } if actual == resource && needed > limit && limit == expected_limit
        ));
    }
}

#[test]
fn preparation_limits_accept_the_exact_ledger_and_refuse_one_below() {
    let baseline = forced_count("ab", ForcedExecution::FullDfa);
    let preparation = baseline.build_report().preparation();
    let prospective = preparation.prospective;
    assert_eq!(
        (
            preparation.pattern_terminals,
            preparation.dfa_states,
            preparation.transition_cells,
            preparation.subset_items,
            preparation.work,
            preparation.persistent_bytes,
            preparation.peak_bytes,
            preparation.allocation_attempts,
        ),
        (
            prospective.pattern_terminals,
            prospective.dfa_states,
            prospective.transition_cells,
            prospective.subset_items,
            prospective.work,
            prospective.persistent_bytes,
            prospective.peak_bytes,
            prospective.allocation_attempts,
        )
    );

    let exact_preparation = PreparationLimits {
        max_pattern_terminals: prospective.pattern_terminals,
        max_dfa_states: prospective.dfa_states,
        max_transition_cells: prospective.transition_cells,
        max_subset_items: prospective.subset_items,
        max_tagged_dispatch_states: prospective.tagged_dispatch_states,
        max_tagged_dispatch_cells: prospective.tagged_dispatch_cells,
        max_tagged_candidate_items: prospective.tagged_candidate_items,
        max_work: prospective.work,
        max_persistent_bytes: prospective.persistent_bytes,
        max_peak_bytes: prospective.peak_bytes,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    let exact_limits = PriorityAggregateBuildLimits {
        preparation: exact_preparation,
        ..PriorityAggregateBuildLimits::default()
    };
    let exact = PriorityAggregateBuilder::new("ab")
        .limits(exact_limits)
        .build_count(ForcedExecution::FullDfa, PriorityTarget::portable())
        .unwrap();
    assert_eq!(exact.build_report().preparation(), preparation);
    assert!(exact.build_report().closes());

    let one_below = one_below_usize(prospective.persistent_bytes);
    let error = PriorityAggregateBuilder::new("ab")
        .limits(PriorityAggregateBuildLimits {
            preparation: PreparationLimits {
                max_persistent_bytes: one_below,
                ..exact_preparation
            },
            ..PriorityAggregateBuildLimits::default()
        })
        .build_count(ForcedExecution::FullDfa, PriorityTarget::portable())
        .unwrap_err();
    assert!(matches!(
        error,
        PriorityAggregateBuildError::Preparation(PreparationError::ResourceLimit {
            resource: PreparationResource::PersistentBytes,
            needed,
            limit,
        }) if needed > limit
            && needed <= prospective.persistent_bytes
            && limit == one_below
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression deliberately verifies every tagged preparation and runtime resource at exact and one-below limits"
)]
fn tagged_full_lazy_facade_resources_close_and_refuse_every_one_below() {
    let pattern = r"\b(?:a|ab)\b";
    let haystack = b"a ab xab a";
    for (execution, expected_kernel) in [
        (
            ForcedExecution::FullDfa,
            PriorityExecutionKernel::FullTaggedReverse,
        ),
        (
            ForcedExecution::LazyDfa,
            PriorityExecutionKernel::LazyTaggedReverse,
        ),
    ] {
        let baseline = forced_count(pattern, execution);
        assert_eq!(baseline.build_report().kernel(), expected_kernel);
        assert!(baseline.build_report().closes());
        let preparation = baseline.build_report().preparation();
        let prospective_preparation = preparation.prospective;
        assert_eq!(preparation.dfa_states, 0, "{execution:?}");
        assert_eq!(preparation.transition_cells, 0, "{execution:?}");
        assert_eq!(preparation.subset_items, 0, "{execution:?}");
        assert!(preparation.tagged_dispatch_states > 0, "{execution:?}");
        assert!(preparation.tagged_dispatch_cells > 0, "{execution:?}");
        assert!(preparation.tagged_candidate_items > 0, "{execution:?}");
        assert_eq!(
            preparation.tagged_dispatch_states, prospective_preparation.tagged_dispatch_states,
            "{execution:?}"
        );
        assert_eq!(
            preparation.tagged_dispatch_cells, prospective_preparation.tagged_dispatch_cells,
            "{execution:?}"
        );
        assert_eq!(
            preparation.tagged_candidate_items, prospective_preparation.tagged_candidate_items,
            "{execution:?}"
        );

        let exact_preparation = PreparationLimits {
            max_pattern_terminals: prospective_preparation.pattern_terminals,
            max_dfa_states: prospective_preparation.dfa_states,
            max_transition_cells: prospective_preparation.transition_cells,
            max_subset_items: prospective_preparation.subset_items,
            max_tagged_dispatch_states: prospective_preparation.tagged_dispatch_states,
            max_tagged_dispatch_cells: prospective_preparation.tagged_dispatch_cells,
            max_tagged_candidate_items: prospective_preparation.tagged_candidate_items,
            max_work: prospective_preparation.work,
            max_persistent_bytes: prospective_preparation.persistent_bytes,
            max_peak_bytes: prospective_preparation.peak_bytes,
            max_allocation_attempts: prospective_preparation.allocation_attempts,
        };
        let exact = PriorityAggregateBuilder::new(pattern)
            .limits(PriorityAggregateBuildLimits {
                preparation: exact_preparation,
                ..PriorityAggregateBuildLimits::default()
            })
            .build_count(execution, PriorityTarget::portable())
            .unwrap_or_else(|error| panic!("exact {execution:?} tagged preparation: {error}"));
        assert_eq!(exact.build_report().preparation(), preparation);
        assert!(exact.build_report().closes());

        for (resource, limited, expected_limit) in [
            (
                PreparationResource::TaggedDispatchStates,
                PreparationLimits {
                    max_tagged_dispatch_states: one_below_usize(
                        exact_preparation.max_tagged_dispatch_states,
                    ),
                    ..exact_preparation
                },
                one_below_usize(exact_preparation.max_tagged_dispatch_states),
            ),
            (
                PreparationResource::TaggedDispatchCells,
                PreparationLimits {
                    max_tagged_dispatch_cells: one_below_usize(
                        exact_preparation.max_tagged_dispatch_cells,
                    ),
                    ..exact_preparation
                },
                one_below_usize(exact_preparation.max_tagged_dispatch_cells),
            ),
            (
                PreparationResource::TaggedCandidateItems,
                PreparationLimits {
                    max_tagged_candidate_items: one_below_usize(
                        exact_preparation.max_tagged_candidate_items,
                    ),
                    ..exact_preparation
                },
                one_below_usize(exact_preparation.max_tagged_candidate_items),
            ),
        ] {
            let error = PriorityAggregateBuilder::new(pattern)
                .limits(PriorityAggregateBuildLimits {
                    preparation: limited,
                    ..PriorityAggregateBuildLimits::default()
                })
                .build_count(execution, PriorityTarget::portable())
                .expect_err("one-below tagged preparation must refuse");
            assert!(matches!(
                error,
                PriorityAggregateBuildError::Preparation(PreparationError::ResourceLimit {
                    resource: actual,
                    needed,
                    limit,
                }) if actual == resource && needed > limit && limit == expected_limit
            ));
        }

        let probe = baseline
            .count(haystack, PriorityAggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("{execution:?} tagged probe: {error}"));
        let prospective = probe.prospective();
        assert_eq!(
            prospective.tagged_dispatch_states_capacity, preparation.tagged_dispatch_states,
            "{execution:?}"
        );
        assert_eq!(
            prospective.tagged_dispatch_cells_capacity, preparation.tagged_dispatch_cells,
            "{execution:?}"
        );
        assert_eq!(
            prospective.tagged_candidate_items_capacity, preparation.tagged_candidate_items,
            "{execution:?}"
        );
        if execution == ForcedExecution::FullDfa {
            assert_eq!(prospective.tagged_cache_cells_capacity, 0, "{execution:?}");
        } else {
            assert!(
                prospective.tagged_cache_cells_capacity > 0,
                "{execution:?} cache shape"
            );
        }

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
        let exact_run = PriorityAggregateRunLimits {
            execution: exact_execution,
            max_output: u64::try_from(haystack.len() + 1).unwrap(),
        };
        let receipt = baseline
            .count(haystack, exact_run)
            .unwrap_or_else(|error| panic!("exact {execution:?} tagged run: {error}"));
        assert_eq!(receipt.value(), 3, "{execution:?}");
        assert_eq!(receipt.kernel(), expected_kernel);
        assert!(receipt.closes(), "{execution:?}");
        assert_eq!(
            receipt.actual().tagged_dispatch_states,
            prospective.tagged_dispatch_states_capacity,
            "{execution:?}"
        );
        assert_eq!(
            receipt.actual().tagged_dispatch_cells,
            prospective.tagged_dispatch_cells_capacity,
            "{execution:?}"
        );
        assert_eq!(
            receipt.actual().tagged_candidate_items,
            prospective.tagged_candidate_items_capacity,
            "{execution:?}"
        );
        assert_eq!(
            receipt.actual().tagged_cache_cells,
            prospective.tagged_cache_cells_capacity,
            "{execution:?}"
        );

        for (limited, assertion) in [
            (
                DirectReduceLimits {
                    max_tagged_dispatch_states: one_below_usize(
                        exact_execution.max_tagged_dispatch_states,
                    ),
                    ..exact_execution
                },
                0_u8,
            ),
            (
                DirectReduceLimits {
                    max_tagged_dispatch_cells: one_below_usize(
                        exact_execution.max_tagged_dispatch_cells,
                    ),
                    ..exact_execution
                },
                1_u8,
            ),
            (
                DirectReduceLimits {
                    max_tagged_candidate_items: one_below_usize(
                        exact_execution.max_tagged_candidate_items,
                    ),
                    ..exact_execution
                },
                2_u8,
            ),
        ] {
            let error = baseline
                .count(
                    haystack,
                    PriorityAggregateRunLimits {
                        execution: limited,
                        max_output: exact_run.max_output,
                    },
                )
                .expect_err("one-below tagged execution must refuse before source");
            assert!(match (assertion, error.source) {
                (
                    0,
                    PriorityAggregateRunFailure::Execution(
                        ReduceError::TaggedDispatchStatesLimit { needed, limit },
                    ),
                ) => needed > limit && limit == limited.max_tagged_dispatch_states,
                (
                    1,
                    PriorityAggregateRunFailure::Execution(ReduceError::TaggedDispatchCellsLimit {
                        needed,
                        limit,
                    }),
                ) => needed > limit && limit == limited.max_tagged_dispatch_cells,
                (
                    2,
                    PriorityAggregateRunFailure::Execution(
                        ReduceError::TaggedCandidateItemsLimit { needed, limit },
                    ),
                ) => needed > limit && limit == limited.max_tagged_candidate_items,
                _ => false,
            });
        }

        if execution == ForcedExecution::LazyDfa {
            let reduced_cache = DirectReduceLimits {
                max_tagged_cache_cells: one_below_usize(exact_execution.max_tagged_cache_cells),
                ..exact_execution
            };
            let reduced = baseline
                .count(
                    haystack,
                    PriorityAggregateRunLimits {
                        execution: reduced_cache,
                        max_output: exact_run.max_output,
                    },
                )
                .expect("positive reduced lazy tagged cache remains a valid bounded route");
            assert_eq!(reduced.value(), 3, "{execution:?} reduced cache");
            assert!(reduced.closes(), "{execution:?} reduced cache");
            assert_eq!(
                reduced.prospective().tagged_cache_cells_capacity,
                reduced_cache.max_tagged_cache_cells,
                "{execution:?} reduced cache P"
            );
            assert_eq!(
                reduced.actual().tagged_cache_cells,
                reduced_cache.max_tagged_cache_cells,
                "{execution:?} reduced cache A"
            );
            assert_eq!(
                reduced.actual().tagged_cache_inserts,
                reduced.actual().tagged_cache_misses,
                "{execution:?} reduced cache inserts"
            );
            assert!(
                reduced.actual().tagged_cache_evictions <= reduced.actual().tagged_cache_inserts,
                "{execution:?} reduced cache evictions"
            );

            let no_cache = DirectReduceLimits {
                max_tagged_cache_cells: 0,
                ..exact_execution
            };
            let error = baseline
                .count(
                    haystack,
                    PriorityAggregateRunLimits {
                        execution: no_cache,
                        max_output: exact_run.max_output,
                    },
                )
                .expect_err("zero lazy tagged cache must refuse before source");
            assert!(matches!(
                error.source,
                PriorityAggregateRunFailure::Execution(ReduceError::TaggedCacheCellsLimit {
                    needed,
                    limit,
                }) if needed == 1 && limit == no_cache.max_tagged_cache_cells
            ));
        }
    }
}

#[test]
fn tagged_full_lazy_receipts_close_without_a_consuming_candidate() {
    // The variable-width suffix forces the tagged routes. An empty or
    // incompatible source performs no matching consuming transition, but the
    // static tagged program and state walker still execute and are
    // authenticated by the receipt.
    for execution in [ForcedExecution::FullDfa, ForcedExecution::LazyDfa] {
        let count = PriorityAggregateBuilder::new("ab?")
            .build_count(execution, PriorityTarget::portable())
            .unwrap_or_else(|error| panic!("{execution:?} tagged build: {error}"));
        for haystack in [b"".as_slice(), b"z".as_slice()] {
            let receipt = count
                .count(haystack, PriorityAggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("{execution:?}/{haystack:?} tagged run: {error}"));
            assert_eq!(receipt.value(), 0, "{execution:?}/{haystack:?}");
            assert!(receipt.closes(), "{execution:?}/{haystack:?}");
            assert!(
                receipt.actual().tagged_state_evaluations > 0,
                "{execution:?}/{haystack:?}"
            );
        }
    }
}

#[test]
fn runtime_limits_accept_the_exact_prospective_and_refuse_one_below() {
    let haystack = b"zababxab";
    let count = forced_count("ab", ForcedExecution::Sparse);
    let probe = count
        .count(haystack, PriorityAggregateRunLimits::default())
        .unwrap();
    let prospective = probe.prospective();
    let exact = DirectReduceLimits {
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
    let exact_run = PriorityAggregateRunLimits {
        execution: exact,
        max_output: u64::try_from(haystack.len() + 1).unwrap(),
    };
    let exact_receipt = count.count(haystack, exact_run).unwrap();
    assert_eq!(exact_receipt.prospective(), prospective);
    assert_eq!(exact_receipt.value(), 3);
    assert!(exact_receipt.closes());

    let one_below = one_below_u64(prospective.work_upper_bound);
    let below_limits = DirectReduceLimits {
        max_work: one_below,
        ..exact
    };
    let below_run = PriorityAggregateRunLimits {
        execution: below_limits,
        max_output: exact_run.max_output,
    };
    let error = count.count(haystack, below_run).unwrap_err();
    assert_eq!(error.operation, PriorityAggregateOperation::Count);
    assert_eq!(error.execution, ForcedExecution::Sparse);
    assert_eq!(error.limits, below_run);
    assert!(matches!(
        error.source,
        PriorityAggregateRunFailure::Execution(ReduceError::WorkLimit {
            consumed: 0,
            requested,
            limit,
        }) if requested == prospective.work_upper_bound && limit == one_below
    ));
}

#[test]
fn operation_typed_output_bound_accepts_exact_and_refuses_one_below_pre_source() {
    let haystack = b"zababxab";
    let count = forced_count("ab", ForcedExecution::Sparse);
    let count_bound = u64::try_from(haystack.len() + 1).unwrap();
    let count_exact = PriorityAggregateRunLimits {
        max_output: count_bound,
        ..PriorityAggregateRunLimits::default()
    };
    assert!(count.count(haystack, count_exact).unwrap().closes());
    let count_error = count
        .count(
            haystack,
            PriorityAggregateRunLimits {
                max_output: count_bound - 1,
                ..count_exact
            },
        )
        .unwrap_err();
    assert!(matches!(
        count_error.source,
        PriorityAggregateRunFailure::OutputLimit {
            operation: PriorityAggregateOperation::Count,
            needed,
            limit,
        } if needed == count_bound && limit == count_bound - 1
    ));

    let span_sum = forced_span_sum("ab", ForcedExecution::Sparse);
    let span_bound = u64::try_from(haystack.len()).unwrap();
    let span_exact = PriorityAggregateRunLimits {
        max_output: span_bound,
        ..PriorityAggregateRunLimits::default()
    };
    let span_receipt = span_sum.span_sum(haystack, span_exact).unwrap();
    assert_eq!(
        span_receipt.value(),
        span_receipt.actual().selected_span_bytes
    );
    assert!(span_receipt.closes());
    let span_error = span_sum
        .span_sum(
            haystack,
            PriorityAggregateRunLimits {
                max_output: span_bound - 1,
                ..span_exact
            },
        )
        .unwrap_err();
    assert!(matches!(
        span_error.source,
        PriorityAggregateRunFailure::OutputLimit {
            operation: PriorityAggregateOperation::SpanSum,
            needed,
            limit,
        } if needed == span_bound && limit == span_bound - 1
    ));
}

#[test]
fn explicit_priority_facade_does_not_change_forced_continuation_selection() {
    let haystack = b"zababxab";
    let count = AggregateBuilder::new("ab")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    let ordinary_count = count
        .count_value(haystack, AggregateRunLimits::default())
        .unwrap();
    let counter_count = count
        .count_value_with_counters(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(ordinary_count, 3);
    assert_eq!(counter_count.value(), ordinary_count);
    let count_receipt = counter_count
        .continuation_receipt()
        .expect("forced continuation Count receipt");
    assert!(count_receipt.closes());
    assert_eq!(
        count_receipt.value,
        AggregateOperationCounterValue::Count(3)
    );

    let span_sum = AggregateBuilder::new("ab")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    let ordinary_span_sum = span_sum
        .span_sum_value(haystack, AggregateRunLimits::default())
        .unwrap();
    let counter_span_sum = span_sum
        .span_sum_value_with_counters(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(ordinary_span_sum, 6);
    assert_eq!(counter_span_sum.value(), ordinary_span_sum);
    let span_sum_receipt = counter_span_sum
        .continuation_receipt()
        .expect("forced continuation SpanSum receipt");
    assert!(span_sum_receipt.closes());
    assert_eq!(
        span_sum_receipt.value,
        AggregateOperationCounterValue::SpanSum(6)
    );
}
