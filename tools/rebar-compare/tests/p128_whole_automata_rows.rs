use std::{
    fs,
    path::Path,
    sync::{Condvar, Mutex, OnceLock},
};

use fre::{
    DirectReduceLimits, ForcedExecution, PriorityAggregateBridgeLimits,
    PriorityAggregateBridgeResource, PriorityAggregateBuildError, PriorityAggregateBuildLimits,
    PriorityAggregateBuildReport, PriorityAggregateBuilder, PriorityAggregateExecutionReceipt,
    PriorityAggregateOperation, PriorityAggregateProofRefusal, PriorityAggregateRouteProof,
    PriorityAggregateRunFailure, PriorityAggregateRunLimits, PriorityAggregateSourceOwnerLimits,
    PriorityAggregateSourceOwnerResource, PriorityExecutionKernel, PriorityTarget, ReduceError,
    RustProfile,
};
use fre_automata::{
    CompileLimits, ExecutionProspective, PreparationError, PreparationLimits, PreparationResource,
};
use fre_lower::{
    FactError, FactLimits, FactOptionalProofs, FactOutput, FactResource, LowerError, LowerLimits,
    LowerResource,
};
use rebar_compare::p128_forced_priority::{
    P128ForcedPriorityLimits, p128_forced_priority_lifecycle,
};
use regex::bytes::RegexBuilder;
use sha2::{Digest, Sha256};

struct ExactPatternCase {
    point_ids: &'static [&'static str],
    blob: &'static str,
    sha256: &'static str,
    syntax: PatternSyntax,
    finite_kernel: PriorityExecutionKernel,
    sample: &'static [u8],
    held_out: &'static [u8],
}

#[derive(Clone, Copy)]
enum PatternSyntax {
    Bytes,
    Unicode,
    UnicodeCaseInsensitive,
}

const CASES: &[ExactPatternCase] = &[
    ExactPatternCase {
        point_ids: &["24b511d8247f02cf384a62cb"],
        blob: "sha256-97cd171850089efa20adec84678649a72ccf0d75170baaff15a5219042b0e46d.pattern",
        sha256: "97cd171850089efa20adec84678649a72ccf0d75170baaff15a5219042b0e46d",
        syntax: PatternSyntax::UnicodeCaseInsensitive,
        finite_kernel: PriorityExecutionKernel::InputBoundedReverse,
        sample: b"Mon Jan 02 03:04:05 2006; 2019-01-02; invalid 2019-99-99",
        // Same length as `sample`, so one retained P128 lifecycle can bind
        // both a basic input and an adversarial input exactly.
        held_out: b"2024-02-29T23:59:59.1Z 07:05 pm utcutc 31st Dec x nope!!",
    },
    ExactPatternCase {
        point_ids: &["649c49fc2e4a6694bd7f2288"],
        blob: "sha256-cf42fe5cc6401813225674f9f2b17ac6be29b2b4b367cf75b9a5b00cdbe1cb61.pattern",
        sha256: "cf42fe5cc6401813225674f9f2b17ac6be29b2b4b367cf75b9a5b00cdbe1cb61",
        syntax: PatternSyntax::Bytes,
        finite_kernel: PriorityExecutionKernel::InputBoundedReverse,
        sample: b"aaaaaaaa=bbbbbbbb\nno delimiter here",
        held_out: b"=lead\nleft=middle=right\nx\ntrailing=",
    },
    ExactPatternCase {
        point_ids: &["70d256e2a7435f68152107da", "b8e43885d4cbe69186ebaec0"],
        blob: "sha256-5c0fecf3644d990b543dd28f0164ab0e42873b5e2def121262804512e443cecf.pattern",
        sha256: "5c0fecf3644d990b543dd28f0164ab0e42873b5e2def121262804512e443cecf",
        syntax: PatternSyntax::Unicode,
        finite_kernel: PriorityExecutionKernel::FiniteHorizonReverse,
        sample: b"fn pub struct _fn async await match loop self Self crate super",
        held_out: b"_fn fn! Selfish Self r#match async i128 usize true false.....!",
    },
    ExactPatternCase {
        point_ids: &["b03e3093606ac9d5e76e1f4a", "883273af5a2acfe7e1535cd8"],
        blob: "sha256-5ae6784e8f547c8c5c453d2710c0bdc7aa1c82362a8897cab7ea5b6eb7dcd34a.pattern",
        sha256: "5ae6784e8f547c8c5c453d2710c0bdc7aa1c82362a8897cab7ea5b6eb7dcd34a",
        syntax: PatternSyntax::Unicode,
        finite_kernel: PriorityExecutionKernel::FiniteHorizonReverse,
        sample: b"fn pub struct _fn async await match loop self Self crate super",
        held_out: b"_fn fn! Selfish Self r#match async i128 usize true false.....!",
    },
];

/// Limit expanded-fixture construction concurrency to the four independently
/// scheduled Cargo workers used by the authenticated fixture gate.
struct ExactCasePermit;

fn exact_case_gate() -> &'static (Mutex<usize>, Condvar) {
    static GATE: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();
    GATE.get_or_init(|| (Mutex::new(4), Condvar::new()))
}

fn exact_case_permit() -> ExactCasePermit {
    let (available, wake) = exact_case_gate();
    let mut available = available
        .lock()
        .expect("expanded-case gate is not poisoned");
    while *available == 0 {
        available = wake
            .wait(available)
            .expect("expanded-case gate is not poisoned");
    }
    *available = (*available)
        .checked_sub(1)
        .expect("expanded-case gate has an available worker permit");
    ExactCasePermit
}

impl Drop for ExactCasePermit {
    fn drop(&mut self) {
        let (available, wake) = exact_case_gate();
        let mut available = available
            .lock()
            .expect("expanded-case gate is not poisoned");
        *available = available
            .checked_add(1)
            .expect("expanded-case worker permits remain bounded");
        wake.notify_one();
    }
}

fn profile(case: &ExactPatternCase) -> RustProfile {
    let mut profile = RustProfile::rebar_1_12_4();
    (profile.options.unicode, profile.options.case_insensitive) = match case.syntax {
        PatternSyntax::Bytes => (false, false),
        PatternSyntax::Unicode => (true, false),
        PatternSyntax::UnicodeCaseInsensitive => (true, true),
    };
    profile
}

fn expected_values(case: &ExactPatternCase, pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let profile = profile(case);
    let mut count = 0u64;
    let mut span_sum = 0u64;
    for found in RegexBuilder::new(pattern)
        .unicode(profile.options.unicode)
        .case_insensitive(profile.options.case_insensitive)
        .size_limit(256 * 1024 * 1024)
        .dfa_size_limit(256 * 1024 * 1024)
        .build()
        .expect("pinned regex oracle construction")
        .find_iter(haystack)
    {
        count = count.checked_add(1).expect("sample match count fits u64");
        span_sum = span_sum
            .checked_add(u64::try_from(found.len()).expect("sample span fits u64"))
            .expect("sample span sum fits u64");
    }
    (count, span_sum)
}

fn expected_kernel(case: &ExactPatternCase, execution: ForcedExecution) -> PriorityExecutionKernel {
    match execution {
        ForcedExecution::Sparse => PriorityExecutionKernel::SparseReverse,
        ForcedExecution::FiniteHorizon => case.finite_kernel,
        ForcedExecution::FullDfa => PriorityExecutionKernel::FullTaggedReverse,
        ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyTaggedReverse,
        _ => unreachable!("test covers explicit forced routes only"),
    }
}

fn assert_route_evidence(
    case: &ExactPatternCase,
    execution: ForcedExecution,
    report: &PriorityAggregateBuildReport,
) {
    assert_eq!(report.kernel(), expected_kernel(case, execution));
    assert!(report.closes());
    assert_eq!(
        report.facts().operation().optional_proofs(),
        match execution {
            ForcedExecution::Sparse => FactOptionalProofs::CoreOnly,
            ForcedExecution::FiniteHorizon
            | ForcedExecution::FullDfa
            | ForcedExecution::LazyDfa => FactOptionalProofs::AssertionContext,
            _ => unreachable!("test covers explicit forced routes only"),
        }
    );
    match execution {
        ForcedExecution::Sparse => {
            assert_eq!(report.route_proof(), PriorityAggregateRouteProof::Sparse);
        }
        ForcedExecution::FiniteHorizon
            if case.finite_kernel == PriorityExecutionKernel::InputBoundedReverse =>
        {
            assert_eq!(
                report.route_proof(),
                PriorityAggregateRouteProof::InputBoundedHorizon
            );
            assert_eq!(report.static_reducer_retention_bytes(), None);
        }
        ForcedExecution::FiniteHorizon => match report.route_proof() {
            PriorityAggregateRouteProof::FiniteHorizon { maximum_bytes } => {
                let retention_bytes = report
                    .static_reducer_retention_bytes()
                    .expect("finite static route must bind reducer retention");
                assert!(maximum_bytes > 0 && retention_bytes > 0);
                assert!(retention_bytes <= maximum_bytes);
            }
            PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                maximum_match_bytes,
            } => {
                assert_eq!(
                    report.static_reducer_retention_bytes(),
                    Some(maximum_match_bytes),
                    "stream-end routes retain the finite complete-match suffix"
                );
            }
            proof => panic!(
                "finite route must publish a static-horizon or stream-end-retention proof, got {proof:?}"
            ),
        },
        ForcedExecution::FullDfa | ForcedExecution::LazyDfa => {
            assert!(matches!(
                report.route_proof(),
                PriorityAggregateRouteProof::AssertionContext { .. }
            ));
        }
        _ => unreachable!("test covers explicit forced routes only"),
    }
}

fn exact_build_limits(report: &PriorityAggregateBuildReport) -> PriorityAggregateBuildLimits {
    // Admission and syntax safety are fixed policy identities, not artifacts
    // with a lowerable construction P/A ledger. Preserve precisely the policy
    // that authenticated this report, then replace every derived resource
    // envelope with its exact published accounting.
    let mut limits = report.limits();
    let source_owner = report.syntax().source_owner();
    let facts = report.facts().prospective();
    let lowering = report.lowering();
    let automaton = report.automaton();
    let bridge = report.bridge().prospective();
    let preparation = report.preparation().prospective;
    limits.source_owner = PriorityAggregateSourceOwnerLimits {
        max_allocation_bytes: source_owner.allocation_bytes(),
        max_handle_bytes: source_owner.handle_bytes(),
        max_allocation_attempts: source_owner.allocation_attempts(),
    };
    limits.facts = FactLimits {
        max_work: facts.work(),
        max_stack_items: facts.peak_stack_items(),
        max_hir_nodes: facts.hir_nodes(),
        max_retained_bytes: facts.retained_bytes(),
        max_temporary_bytes: facts.temporary_bytes(),
        max_peak_bytes: facts.peak_bytes(),
        max_allocation_attempts: facts.allocation_attempts(),
        max_finite_strings: facts.finite_strings(),
        max_finite_string_bytes: facts.finite_string_bytes(),
        max_required_groups: facts.required_groups(),
        max_required_alternatives: facts.required_alternatives(),
        max_required_bytes: facts.required_bytes(),
        max_assertions: facts.assertions(),
        max_deterministic_states: facts.deterministic_states(),
    };
    limits.lowering = LowerLimits {
        max_work: lowering.work(),
        max_stack_items: lowering.peak_stack_items(),
        automata: CompileLimits {
            max_states: automaton.states(),
            max_edges: automaton.edges(),
            max_storage_bytes: automaton.storage_bytes(),
            max_validation_work: automaton.validation_work(),
        },
    };
    limits.bridge = PriorityAggregateBridgeLimits {
        max_work: bridge.work,
        max_action_bytes: bridge.action_bytes,
        max_peak_bytes: bridge.peak_bytes,
        max_pattern_terminals: bridge.pattern_terminals,
        max_allocation_attempts: bridge.allocation_attempts,
    };
    limits.preparation = PreparationLimits {
        max_pattern_terminals: preparation.pattern_terminals,
        max_dfa_states: preparation.dfa_states,
        max_transition_cells: preparation.transition_cells,
        max_subset_items: preparation.subset_items,
        max_tagged_dispatch_states: preparation.tagged_dispatch_states,
        max_tagged_dispatch_cells: preparation.tagged_dispatch_cells,
        max_tagged_candidate_items: preparation.tagged_candidate_items,
        max_work: preparation.work,
        max_persistent_bytes: preparation.persistent_bytes,
        max_peak_bytes: preparation.peak_bytes,
        max_allocation_attempts: preparation.allocation_attempts,
    };
    limits
}

fn exact_run_limits(
    prospective: ExecutionProspective,
    max_output: u64,
) -> PriorityAggregateRunLimits {
    PriorityAggregateRunLimits {
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
        max_output,
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the fixture needs the unboxed typed construction terminal for every exact one-below assertion"
)]
fn construction_result(
    pattern: &str,
    case: &ExactPatternCase,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    limits: &PriorityAggregateBuildLimits,
) -> Result<(), PriorityAggregateBuildError> {
    match operation {
        PriorityAggregateOperation::Count => PriorityAggregateBuilder::new(pattern)
            .profile(profile(case))
            .limits(*limits)
            .build_count(execution, PriorityTarget::portable())
            .map(|_| ()),
        PriorityAggregateOperation::SpanSum => PriorityAggregateBuilder::new(pattern)
            .profile(profile(case))
            .limits(*limits)
            .build_span_sum(execution, PriorityTarget::portable())
            .map(|_| ()),
        _ => unreachable!("fixture validates only Count and SpanSum operations"),
    }
}

fn construction_error(
    pattern: &str,
    case: &ExactPatternCase,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    limits: &PriorityAggregateBuildLimits,
) -> PriorityAggregateBuildError {
    construction_result(pattern, case, operation, execution, limits)
        .expect_err("one-below construction limit must refuse")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionalFactLimitExpectation {
    Admits,
    MissingRouteProof(PriorityAggregateProofRefusal),
}

fn assertion_cap_expectation(
    route_proof: PriorityAggregateRouteProof,
) -> OptionalFactLimitExpectation {
    match route_proof {
        // These routes consume assertion context directly, so a one-below
        // optional cap has one exact facade terminal.
        PriorityAggregateRouteProof::InputBoundedHorizon
        | PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd { .. }
        | PriorityAggregateRouteProof::AssertionContext { .. } => {
            OptionalFactLimitExpectation::MissingRouteProof(
                PriorityAggregateProofRefusal::AssertionContext,
            )
        }
        // A streamable finite route consumes the finite decision-horizon
        // certificate; an assertion-cap soft refusal must therefore retain
        // that distinct route-proof terminal.
        PriorityAggregateRouteProof::FiniteHorizon { .. } => {
            OptionalFactLimitExpectation::MissingRouteProof(
                PriorityAggregateProofRefusal::FiniteDecisionHorizon,
            )
        }
        // Sparse asks facts for CoreOnly, and any non-fixture route with a
        // zero prospective is skipped rather than manufacturing one-below
        // bounds from zero.
        _ => OptionalFactLimitExpectation::Admits,
    }
}

fn optional_fact_limit_outcome(
    pattern: &str,
    case: &ExactPatternCase,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    limits: &PriorityAggregateBuildLimits,
    expectation: OptionalFactLimitExpectation,
) {
    match (
        expectation,
        construction_result(pattern, case, operation, execution, limits),
    ) {
        // A cap for an optional proof that this route does not consume is a
        // successful fallback, not a hard fact resource failure.
        (OptionalFactLimitExpectation::Admits, Ok(())) => {}
        // Direct assertion-context consumers retain their exact facade
        // terminal rather than accepting an arbitrary proof refusal.
        (
            OptionalFactLimitExpectation::MissingRouteProof(expected_proof),
            Err(PriorityAggregateBuildError::MissingRouteProof {
                execution: actual_execution,
                proof: actual_proof,
            }),
        ) => {
            assert_eq!(actual_execution, execution);
            assert_eq!(actual_proof, expected_proof);
        }
        (
            _,
            Err(PriorityAggregateBuildError::Facts(FactError::ResourceLimit {
                resource,
                needed,
                limit,
            })),
        ) => panic!(
            "optional proof cap must soft-refuse or fall back, not hard-fail {resource:?}: {needed} > {limit}"
        ),
        (OptionalFactLimitExpectation::Admits, Err(error)) => {
            panic!("unconsumed optional proof cap must preserve the route, got {error}")
        }
        (OptionalFactLimitExpectation::MissingRouteProof(expected_proof), Ok(())) => {
            panic!(
                "optional proof cap must soft-refuse {expected_proof:?}, but construction succeeded"
            )
        }
        (OptionalFactLimitExpectation::MissingRouteProof(expected_proof), Err(error)) => {
            panic!("optional proof cap must soft-refuse {expected_proof:?}, got {error}")
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps each artifact-derived construction resource and its typed one-below refusal adjacent"
)]
fn assert_one_below_construction(
    pattern: &str,
    case: &ExactPatternCase,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    route_proof: PriorityAggregateRouteProof,
    exact: &PriorityAggregateBuildLimits,
) {
    let exact = *exact;
    construction_result(pattern, case, operation, execution, &exact)
        .expect("exact construction limit must admit the authenticated route");
    macro_rules! assert_source_owner_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.source_owner.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive source-owner limit");
                let mut below = exact;
                below.source_owner.$field = limit;
                let error = construction_error(pattern, case, operation, execution, &below);
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::SourceOwnerResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    } if resource == $resource && actual_needed == needed && actual_limit == limit
                ));
            }
        }};
    }
    assert_source_owner_limit!(
        max_allocation_bytes,
        PriorityAggregateSourceOwnerResource::AllocationBytes
    );
    assert_source_owner_limit!(
        max_handle_bytes,
        PriorityAggregateSourceOwnerResource::HandleBytes
    );
    assert_source_owner_limit!(
        max_allocation_attempts,
        PriorityAggregateSourceOwnerResource::AllocationAttempts
    );

    let fact_limit = exact
        .facts
        .max_work
        .checked_sub(1)
        .expect("positive fact work");
    let fact_error = construction_error(
        pattern,
        case,
        operation,
        execution,
        &PriorityAggregateBuildLimits {
            facts: FactLimits {
                max_work: fact_limit,
                ..exact.facts
            },
            ..exact
        },
    );
    assert!(matches!(
        fact_error,
        PriorityAggregateBuildError::Facts(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit,
        }) if needed == exact.facts.max_work && limit == fact_limit
    ));

    macro_rules! assert_fact_usize_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.facts.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive fact limit");
                let error = construction_error(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        facts: FactLimits {
                            $field: limit,
                            ..exact.facts
                        },
                        ..exact
                    },
                );
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::Facts(FactError::ResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    }) if resource == $resource
                        && actual_needed > actual_limit
                        && actual_limit == u64::try_from(limit).expect("small fact limit")
                ));
            }
        }};
    }
    assert_fact_usize_limit!(max_stack_items, FactResource::StackItems);
    assert_fact_usize_limit!(max_hir_nodes, FactResource::HirNodes);
    assert_fact_usize_limit!(max_retained_bytes, FactResource::RetainedBytes);
    assert_fact_usize_limit!(max_temporary_bytes, FactResource::TemporaryBytes);
    assert_fact_usize_limit!(max_peak_bytes, FactResource::PeakBytes);
    assert_fact_usize_limit!(max_allocation_attempts, FactResource::AllocationAttempts);

    macro_rules! assert_optional_fact_soft_limit {
        ($field:ident, $expected_refusal:expr) => {{
            let needed = exact.facts.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive optional proof cap");
                optional_fact_limit_outcome(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        facts: FactLimits {
                            $field: limit,
                            ..exact.facts
                        },
                        ..exact
                    },
                    $expected_refusal,
                );
            }
        }};
    }
    // Optional-proof caps intentionally publish typed refusals. A route must
    // either reject the missing proof or take its explicit successful
    // fallback; none is a hard `FactError::ResourceLimit` expectation.
    assert_optional_fact_soft_limit!(max_finite_strings, OptionalFactLimitExpectation::Admits);
    assert_optional_fact_soft_limit!(
        max_finite_string_bytes,
        OptionalFactLimitExpectation::Admits
    );
    assert_optional_fact_soft_limit!(max_required_groups, OptionalFactLimitExpectation::Admits);
    assert_optional_fact_soft_limit!(
        max_required_alternatives,
        OptionalFactLimitExpectation::Admits
    );
    assert_optional_fact_soft_limit!(max_required_bytes, OptionalFactLimitExpectation::Admits);
    assert_optional_fact_soft_limit!(max_assertions, assertion_cap_expectation(route_proof));
    assert_optional_fact_soft_limit!(
        max_deterministic_states,
        OptionalFactLimitExpectation::Admits
    );

    let lowering_work_limit = exact
        .lowering
        .max_work
        .checked_sub(1)
        .expect("positive lowering work");
    let lowering_work_error = construction_error(
        pattern,
        case,
        operation,
        execution,
        &PriorityAggregateBuildLimits {
            lowering: LowerLimits {
                max_work: lowering_work_limit,
                ..exact.lowering
            },
            ..exact
        },
    );
    assert!(matches!(
        lowering_work_error,
        PriorityAggregateBuildError::Lower(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == lowering_work_limit
    ));

    macro_rules! assert_lowering_usize_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.lowering.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive lowering limit");
                let error = construction_error(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        lowering: LowerLimits {
                            $field: limit,
                            ..exact.lowering
                        },
                        ..exact
                    },
                );
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::Lower(LowerError::ResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    }) if resource == $resource
                        && actual_needed > actual_limit
                        && actual_limit == u64::try_from(limit).expect("small lowering limit")
                ));
            }
        }};
    }
    assert_lowering_usize_limit!(max_stack_items, LowerResource::StackItems);

    macro_rules! assert_automata_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.lowering.automata.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive automata limit");
                let error = construction_error(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        lowering: LowerLimits {
                            automata: CompileLimits {
                                $field: limit,
                                ..exact.lowering.automata
                            },
                            ..exact.lowering
                        },
                        ..exact
                    },
                );
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::Lower(LowerError::ResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    }) if resource == $resource
                        && actual_needed > actual_limit
                        && actual_limit == u64::try_from(limit).expect("small automata limit")
                ));
            }
        }};
    }
    assert_automata_limit!(max_states, LowerResource::States);
    assert_automata_limit!(max_edges, LowerResource::Edges);
    assert_automata_limit!(max_storage_bytes, LowerResource::StorageBytes);
    assert_automata_limit!(max_validation_work, LowerResource::ValidationWork);

    let bridge_work_limit = exact
        .bridge
        .max_work
        .checked_sub(1)
        .expect("positive bridge work");
    let bridge_work_error = construction_error(
        pattern,
        case,
        operation,
        execution,
        &PriorityAggregateBuildLimits {
            bridge: PriorityAggregateBridgeLimits {
                max_work: bridge_work_limit,
                ..exact.bridge
            },
            ..exact
        },
    );
    assert!(matches!(
        bridge_work_error,
        PriorityAggregateBuildError::BridgeResourceLimit {
            resource: PriorityAggregateBridgeResource::Work,
            needed,
            limit,
        } if needed == exact.bridge.max_work && limit == bridge_work_limit
    ));

    macro_rules! assert_bridge_usize_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.bridge.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive bridge limit");
                let error = construction_error(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        bridge: PriorityAggregateBridgeLimits {
                            $field: limit,
                            ..exact.bridge
                        },
                        ..exact
                    },
                );
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::BridgeResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    } if resource == $resource
                        && actual_needed == u64::try_from(needed).expect("small bridge limit")
                        && actual_limit == u64::try_from(limit).expect("small bridge limit")
                ));
            }
        }};
    }
    assert_bridge_usize_limit!(
        max_action_bytes,
        PriorityAggregateBridgeResource::ActionBytes
    );
    assert_bridge_usize_limit!(max_peak_bytes, PriorityAggregateBridgeResource::PeakBytes);
    assert_bridge_usize_limit!(
        max_pattern_terminals,
        PriorityAggregateBridgeResource::PatternTerminals
    );
    assert_bridge_usize_limit!(
        max_allocation_attempts,
        PriorityAggregateBridgeResource::AllocationAttempts
    );

    let preparation_work_limit = exact
        .preparation
        .max_work
        .checked_sub(1)
        .expect("positive preparation work");
    let preparation_work_error = construction_error(
        pattern,
        case,
        operation,
        execution,
        &PriorityAggregateBuildLimits {
            preparation: PreparationLimits {
                max_work: preparation_work_limit,
                ..exact.preparation
            },
            ..exact
        },
    );
    assert!(matches!(
        preparation_work_error,
        PriorityAggregateBuildError::Preparation(PreparationError::WorkLimit {
            needed,
            limit,
        }) if needed > limit && limit == preparation_work_limit
    ));

    macro_rules! assert_preparation_usize_limit {
        ($field:ident, $resource:expr) => {{
            let needed = exact.preparation.$field;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive preparation limit");
                let error = construction_error(
                    pattern,
                    case,
                    operation,
                    execution,
                    &PriorityAggregateBuildLimits {
                        preparation: PreparationLimits {
                            $field: limit,
                            ..exact.preparation
                        },
                        ..exact
                    },
                );
                assert!(matches!(
                    error,
                    PriorityAggregateBuildError::Preparation(PreparationError::ResourceLimit {
                        resource,
                        needed: actual_needed,
                        limit: actual_limit,
                    }) if resource == $resource
                        && actual_needed > actual_limit
                        && actual_limit == limit
                ));
            }
        }};
    }
    assert_preparation_usize_limit!(max_pattern_terminals, PreparationResource::PatternTerminals);
    assert_preparation_usize_limit!(max_dfa_states, PreparationResource::DfaStates);
    assert_preparation_usize_limit!(max_transition_cells, PreparationResource::TransitionCells);
    assert_preparation_usize_limit!(max_subset_items, PreparationResource::SubsetItems);
    assert_preparation_usize_limit!(
        max_tagged_dispatch_states,
        PreparationResource::TaggedDispatchStates
    );
    assert_preparation_usize_limit!(
        max_tagged_dispatch_cells,
        PreparationResource::TaggedDispatchCells
    );
    assert_preparation_usize_limit!(
        max_tagged_candidate_items,
        PreparationResource::TaggedCandidateItems
    );
    assert_preparation_usize_limit!(max_persistent_bytes, PreparationResource::PersistentBytes);
    assert_preparation_usize_limit!(max_peak_bytes, PreparationResource::PeakBytes);
    assert_preparation_usize_limit!(
        max_allocation_attempts,
        PreparationResource::AllocationAttempts
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "each pre-source runtime resource retains its exact typed one-below terminal beside the authenticated fixture call"
)]
fn assert_one_below_runtime(
    operation: PriorityAggregateOperation,
    prospective: ExecutionProspective,
    exact: PriorityAggregateRunLimits,
    output_upper_bound: u64,
    execute: impl Fn(PriorityAggregateRunLimits) -> Result<(), fre::PriorityAggregateRunError>,
) {
    assert!(
        output_upper_bound > 0,
        "fixture has a positive operation-specific output bound"
    );
    macro_rules! assert_usize_limit {
        ($field:ident, $needed:expr, $variant:ident) => {{
            let needed = $needed;
            if needed > 0 {
                let limit = needed.checked_sub(1).expect("positive exact limit");
                let error = execute(PriorityAggregateRunLimits {
                    execution: DirectReduceLimits {
                        $field: limit,
                        ..exact.execution
                    },
                    max_output: exact.max_output,
                })
                .expect_err(concat!("one-below ", stringify!($field), " must refuse"));
                assert_eq!(
                    error.source,
                    PriorityAggregateRunFailure::Execution(ReduceError::$variant { needed, limit })
                );
            }
        }};
    }

    let work_limit = prospective
        .work_upper_bound
        .checked_sub(1)
        .expect("positive exact work");
    let work_error = execute(PriorityAggregateRunLimits {
        execution: DirectReduceLimits {
            max_work: work_limit,
            ..exact.execution
        },
        max_output: exact.max_output,
    })
    .expect_err("one-below work must refuse before source");
    assert_eq!(
        work_error.source,
        PriorityAggregateRunFailure::Execution(ReduceError::WorkLimit {
            consumed: 0,
            requested: prospective.work_upper_bound,
            limit: work_limit,
        })
    );
    assert_usize_limit!(max_scratch_bytes, prospective.scratch_bytes, ScratchLimit);
    assert_usize_limit!(
        max_boundary_rows,
        prospective.boundary_rows,
        BoundaryRowsLimit
    );
    assert_usize_limit!(
        max_match_events,
        prospective.match_events_upper_bound,
        MatchEventsLimit
    );
    assert_usize_limit!(
        max_dfa_states,
        prospective.dfa_states_capacity,
        DfaStatesLimit
    );
    assert_usize_limit!(max_dfa_cells, prospective.dfa_cells_capacity, DfaCellsLimit);
    assert_usize_limit!(
        max_subset_items,
        prospective.subset_items_capacity,
        SubsetItemsLimit
    );
    assert_usize_limit!(
        max_tagged_dispatch_states,
        prospective.tagged_dispatch_states_capacity,
        TaggedDispatchStatesLimit
    );
    assert_usize_limit!(
        max_tagged_dispatch_cells,
        prospective.tagged_dispatch_cells_capacity,
        TaggedDispatchCellsLimit
    );
    assert_usize_limit!(
        max_tagged_candidate_items,
        prospective.tagged_candidate_items_capacity,
        TaggedCandidateItemsLimit
    );
    assert_usize_limit!(
        max_allocation_attempts,
        prospective.allocation_attempts,
        AllocationAttemptsLimit
    );

    // A positive lazy tagged cache is deliberately evictable: one below stays
    // sound, while zero is the hard pre-source refusal boundary.
    if prospective.tagged_cache_cells_capacity > 0 {
        let cache_limit = prospective
            .tagged_cache_cells_capacity
            .checked_sub(1)
            .expect("positive lazy tagged cache capacity");
        execute(PriorityAggregateRunLimits {
            execution: DirectReduceLimits {
                max_tagged_cache_cells: cache_limit,
                ..exact.execution
            },
            max_output: exact.max_output,
        })
        .expect("one-below lazy tagged cache remains semantically sound");
        let error = execute(PriorityAggregateRunLimits {
            execution: DirectReduceLimits {
                max_tagged_cache_cells: 0,
                ..exact.execution
            },
            max_output: exact.max_output,
        })
        .expect_err("zero lazy tagged cache must refuse before source");
        assert_eq!(
            error.source,
            PriorityAggregateRunFailure::Execution(ReduceError::TaggedCacheCellsLimit {
                needed: 1,
                limit: 0,
            })
        );
    }

    let output_limit = output_upper_bound
        .checked_sub(1)
        .expect("positive exact output");
    let output_error = execute(PriorityAggregateRunLimits {
        execution: exact.execution,
        max_output: output_limit,
    })
    .expect_err("one-below output must refuse");
    assert_eq!(
        output_error.source,
        PriorityAggregateRunFailure::OutputLimit {
            operation,
            needed: output_upper_bound,
            limit: output_limit,
        }
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the theorem intentionally keeps each operation's report, exact envelope, and direct receipt together"
)]
fn assert_count_span_resource_parity(
    case: &ExactPatternCase,
    execution: ForcedExecution,
    count_report: &PriorityAggregateBuildReport,
    span_sum_report: &PriorityAggregateBuildReport,
    count_exact_build: &PriorityAggregateBuildLimits,
    span_sum_exact_build: &PriorityAggregateBuildLimits,
    count_receipt: &PriorityAggregateExecutionReceipt,
    span_sum_receipt: &PriorityAggregateExecutionReceipt,
) {
    assert_eq!(count_report.operation(), PriorityAggregateOperation::Count);
    assert_eq!(
        span_sum_report.operation(),
        PriorityAggregateOperation::SpanSum
    );
    assert_eq!(count_report.execution(), execution);
    assert_eq!(span_sum_report.execution(), execution);
    assert_eq!(count_report.target(), span_sum_report.target());

    // The only operation-specific fact identity is the public output. Every
    // proof projection and P/A counter must remain structurally identical.
    let count_facts = count_report.facts();
    let span_sum_facts = span_sum_report.facts();
    assert_eq!(count_facts.identity(), span_sum_facts.identity());
    assert_eq!(count_facts.operation().output(), FactOutput::Count);
    assert_eq!(span_sum_facts.operation().output(), FactOutput::SpanSum);
    assert_eq!(
        count_facts.operation().capture_semantics(),
        span_sum_facts.operation().capture_semantics()
    );
    assert_eq!(
        count_facts.operation().optional_proofs(),
        span_sum_facts.operation().optional_proofs()
    );
    assert_eq!(count_facts.width(), span_sum_facts.width());
    assert_eq!(count_facts.capture_count(), span_sum_facts.capture_count());
    assert_eq!(
        count_facts.capture_erasure_permitted(),
        span_sum_facts.capture_erasure_permitted()
    );
    assert_eq!(
        count_facts.finite_decision_horizon(),
        span_sum_facts.finite_decision_horizon()
    );
    assert_eq!(
        count_facts.static_retention_width_bytes(),
        span_sum_facts.static_retention_width_bytes()
    );
    assert_eq!(
        count_facts.subset_determinism(),
        span_sum_facts.subset_determinism()
    );
    assert_eq!(
        count_facts.assertion_context(),
        span_sum_facts.assertion_context()
    );
    assert_eq!(count_facts.prospective(), span_sum_facts.prospective());
    assert_eq!(count_facts.actual(), span_sum_facts.actual());

    assert_eq!(count_report.lowering(), span_sum_report.lowering());
    assert_eq!(count_report.automaton(), span_sum_report.automaton());
    assert_eq!(count_report.bridge(), span_sum_report.bridge());
    assert_eq!(
        count_report.pattern_action(),
        span_sum_report.pattern_action()
    );
    assert_eq!(
        count_report.empty_progress(),
        span_sum_report.empty_progress()
    );
    assert_eq!(
        count_report.line_terminator(),
        span_sum_report.line_terminator()
    );
    assert_eq!(
        count_report.declared_match_length(),
        span_sum_report.declared_match_length()
    );
    assert_eq!(count_report.route_proof(), span_sum_report.route_proof());
    assert_eq!(count_report.kernel(), span_sum_report.kernel());
    assert_eq!(
        count_report.static_reducer_retention_bytes(),
        span_sum_report.static_reducer_retention_bytes()
    );
    assert_eq!(count_report.preparation(), span_sum_report.preparation());
    assert_eq!(
        count_exact_build, span_sum_exact_build,
        "Count/SpanSum construction envelope {:?}/{execution:?}",
        case.point_ids
    );

    assert_eq!(count_receipt.operation(), PriorityAggregateOperation::Count);
    assert_eq!(
        span_sum_receipt.operation(),
        PriorityAggregateOperation::SpanSum
    );
    assert_eq!(count_receipt.execution(), execution);
    assert_eq!(span_sum_receipt.execution(), execution);
    assert_eq!(count_receipt.kernel(), span_sum_receipt.kernel());
    assert_eq!(
        count_receipt.limits().execution,
        span_sum_receipt.limits().execution
    );
    assert_eq!(count_receipt.preparation(), span_sum_receipt.preparation());
    assert_eq!(count_receipt.prospective(), span_sum_receipt.prospective());
    assert_eq!(count_receipt.actual(), span_sum_receipt.actual());
    assert_eq!(
        count_receipt.input_bounded_source_bytes(),
        span_sum_receipt.input_bounded_source_bytes()
    );
    assert_eq!(
        count_receipt.static_reducer_retention_bytes(),
        span_sum_receipt.static_reducer_retention_bytes()
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "one independently scheduled authenticated case keeps all forced-route, operation, lifecycle, and exact one-below checks visible together"
)]
fn run_exact_case_route(case_index: usize, requested_execution: ForcedExecution) {
    let _permit = exact_case_permit();
    let case = &CASES[case_index];
    let root = std::env::var_os("FRE_EXPANDED_REBAR_DIR")
        .expect("FRE_EXPANDED_REBAR_DIR points at the authenticated expansion");
    let blobs = Path::new(&root).join("blobs");
    let bytes = fs::read(blobs.join(case.blob)).expect("authenticated pattern blob");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), case.sha256);
    let pattern = std::str::from_utf8(&bytes).expect("canonical pattern UTF-8");
    assert_eq!(
        case.sample.len(),
        case.held_out.len(),
        "P128 lifecycle holds one exact source-length binding per fixture"
    );
    let (sample_count, sample_span_sum) = expected_values(case, pattern, case.sample);
    let (held_out_count, held_out_span_sum) = expected_values(case, pattern, case.held_out);
    assert!(
        sample_count > 0 && sample_span_sum > 0,
        "{:?}",
        case.point_ids
    );
    assert!(
        held_out_count > 0 && held_out_span_sum > 0,
        "held-out {:?}",
        case.point_ids
    );
    let execution = requested_execution;
    let span_sum_regex = PriorityAggregateBuilder::new(pattern)
        .profile(profile(case))
        .build_span_sum(execution, PriorityTarget::portable())
        .unwrap_or_else(|error| {
            panic!(
                "forced route {execution:?} refused points {:?}: {error}",
                case.point_ids
            )
        });
    assert_route_evidence(case, execution, span_sum_regex.build_report());
    let span_sum_receipt = span_sum_regex
        .span_sum(case.sample, PriorityAggregateRunLimits::default())
        .unwrap_or_else(|error| {
            panic!(
                "forced route {execution:?} failed points {:?}: {error}",
                case.point_ids
            )
        });
    assert!(span_sum_receipt.closes());
    assert_eq!(span_sum_receipt.kernel(), expected_kernel(case, execution));
    assert_eq!(
        span_sum_receipt.value(),
        sample_span_sum,
        "{:?}/{execution:?}",
        case.point_ids
    );
    let held_out_span_sum_receipt = span_sum_regex
        .span_sum(case.held_out, PriorityAggregateRunLimits::default())
        .unwrap_or_else(|error| {
            panic!(
                "held-out forced route {execution:?} failed points {:?}: {error}",
                case.point_ids
            )
        });
    assert_eq!(
        held_out_span_sum_receipt.value(),
        held_out_span_sum,
        "held-out {:?}/{execution:?}",
        case.point_ids
    );

    let span_sum_prospective = span_sum_receipt.prospective();
    let span_sum_exact_build = exact_build_limits(span_sum_regex.build_report());
    let span_sum_output_bound = u64::try_from(case.sample.len()).expect("sample length fits u64");
    let span_sum_exact_run = exact_run_limits(span_sum_prospective, span_sum_output_bound);
    let exact_span_sum_receipt = span_sum_regex
        .span_sum(case.sample, span_sum_exact_run)
        .unwrap_or_else(|error| {
            panic!(
                "exact SpanSum resource route {execution:?} failed points {:?}: {error}",
                case.point_ids
            )
        });
    assert!(exact_span_sum_receipt.closes());
    assert_eq!(exact_span_sum_receipt.value(), sample_span_sum);
    assert_one_below_runtime(
        PriorityAggregateOperation::SpanSum,
        span_sum_prospective,
        span_sum_exact_run,
        span_sum_output_bound,
        |limits| span_sum_regex.span_sum(case.sample, limits).map(|_| ()),
    );

    let count_regex = PriorityAggregateBuilder::new(pattern)
        .profile(profile(case))
        .build_count(execution, PriorityTarget::portable())
        .unwrap_or_else(|error| {
            panic!(
                "Count forced route {execution:?} refused points {:?}: {error}",
                case.point_ids
            )
        });
    assert_route_evidence(case, execution, count_regex.build_report());
    let count_receipt = count_regex
        .count(case.sample, PriorityAggregateRunLimits::default())
        .unwrap_or_else(|error| {
            panic!(
                "Count forced route {execution:?} failed points {:?}: {error}",
                case.point_ids
            )
        });
    assert!(count_receipt.closes());
    assert_eq!(count_receipt.kernel(), expected_kernel(case, execution));
    assert_eq!(count_receipt.value(), sample_count);
    assert_eq!(
        count_regex
            .count(case.held_out, PriorityAggregateRunLimits::default())
            .expect("held-out Count forced route")
            .value(),
        held_out_count,
        "held-out {:?}/{execution:?}",
        case.point_ids
    );
    let count_output_bound = u64::try_from(case.sample.len())
        .expect("sample length fits u64")
        .checked_add(1)
        .expect("sample count cap fits u64");
    let count_prospective = count_receipt.prospective();
    let count_exact_build = exact_build_limits(count_regex.build_report());
    let count_exact_run = exact_run_limits(count_prospective, count_output_bound);
    let exact_count_receipt = count_regex
        .count(case.sample, count_exact_run)
        .expect("exact Count resource route");
    assert!(exact_count_receipt.closes());
    assert_eq!(exact_count_receipt.value(), sample_count);
    assert_count_span_resource_parity(
        case,
        execution,
        count_regex.build_report(),
        span_sum_regex.build_report(),
        &count_exact_build,
        &span_sum_exact_build,
        &exact_count_receipt,
        &exact_span_sum_receipt,
    );
    assert_one_below_construction(
        pattern,
        case,
        PriorityAggregateOperation::SpanSum,
        execution,
        span_sum_regex.build_report().route_proof(),
        &span_sum_exact_build,
    );
    assert_one_below_construction(
        pattern,
        case,
        PriorityAggregateOperation::Count,
        execution,
        count_regex.build_report().route_proof(),
        &count_exact_build,
    );
    assert_one_below_runtime(
        PriorityAggregateOperation::Count,
        count_prospective,
        count_exact_run,
        count_output_bound,
        |limits| count_regex.count(case.sample, limits).map(|_| ()),
    );

    let wrapper_span_run = exact_run_limits(span_sum_prospective, span_sum_output_bound);
    let span_sum_lifecycle = p128_forced_priority_lifecycle(
        pattern,
        profile(case),
        PriorityAggregateOperation::SpanSum,
        case.sample.len(),
        execution,
        PriorityTarget::portable(),
        P128ForcedPriorityLimits {
            construction: span_sum_exact_build,
            execution: wrapper_span_run,
        },
    )
    .unwrap_or_else(|error| {
        panic!(
            "P128 lifecycle {execution:?} refused points {:?}: {error}",
            case.point_ids
        )
    });
    assert_eq!(
        span_sum_lifecycle.limits().construction,
        span_sum_exact_build
    );
    assert_eq!(span_sum_lifecycle.limits().execution, wrapper_span_run);
    assert_route_evidence(case, execution, span_sum_lifecycle.build_report());
    let lifecycle_receipt = span_sum_lifecycle
        .execute(case.sample)
        .unwrap_or_else(|error| {
            panic!(
                "P128 SpanSum lifecycle {execution:?} failed points {:?}: {error}",
                case.point_ids
            )
        });
    assert!(lifecycle_receipt.closes());
    assert_eq!(lifecycle_receipt.kernel(), expected_kernel(case, execution));
    assert!(lifecycle_receipt.native_receipt().closes());
    assert_eq!(
        lifecycle_receipt.native_receipt().kernel(),
        expected_kernel(case, execution)
    );
    assert_eq!(
        lifecycle_receipt.value(),
        sample_span_sum,
        "{:?}/{execution:?}",
        case.point_ids
    );
    assert_eq!(
        span_sum_lifecycle
            .execute(case.held_out)
            .expect("held-out P128 SpanSum lifecycle")
            .value(),
        held_out_span_sum,
        "held-out {:?}/{execution:?}",
        case.point_ids
    );

    let wrapper_count_run = exact_run_limits(count_prospective, count_output_bound);
    let count_lifecycle = p128_forced_priority_lifecycle(
        pattern,
        profile(case),
        PriorityAggregateOperation::Count,
        case.sample.len(),
        execution,
        PriorityTarget::portable(),
        P128ForcedPriorityLimits {
            construction: count_exact_build,
            execution: wrapper_count_run,
        },
    )
    .unwrap_or_else(|error| {
        panic!(
            "P128 Count lifecycle {execution:?} refused points {:?}: {error}",
            case.point_ids
        )
    });
    assert_eq!(count_lifecycle.limits().construction, count_exact_build);
    assert_eq!(count_lifecycle.limits().execution, wrapper_count_run);
    assert_route_evidence(case, execution, count_lifecycle.build_report());
    let count_lifecycle_receipt = count_lifecycle
        .execute(case.sample)
        .expect("P128 Count lifecycle");
    assert!(count_lifecycle_receipt.closes());
    assert_eq!(
        count_lifecycle_receipt.kernel(),
        expected_kernel(case, execution)
    );
    assert!(count_lifecycle_receipt.native_receipt().closes());
    assert_eq!(
        count_lifecycle_receipt.native_receipt().kernel(),
        expected_kernel(case, execution)
    );
    assert_eq!(count_lifecycle_receipt.value(), sample_count);
    assert_eq!(
        count_lifecycle
            .execute(case.held_out)
            .expect("held-out P128 Count lifecycle")
            .value(),
        held_out_count,
        "held-out {:?}/{execution:?}",
        case.point_ids
    );

    let p128_output_below = p128_forced_priority_lifecycle(
        pattern,
        profile(case),
        PriorityAggregateOperation::SpanSum,
        case.sample.len(),
        execution,
        PriorityTarget::portable(),
        P128ForcedPriorityLimits {
            construction: span_sum_exact_build,
            execution: PriorityAggregateRunLimits {
                max_output: span_sum_output_bound
                    .checked_sub(1)
                    .expect("positive SpanSum output bound"),
                ..span_sum_exact_run
            },
        },
    )
    .expect("P128 one-below output construction stays closed");
    let error = p128_output_below
        .execute(case.sample)
        .expect_err("P128 one-below output must refuse");
    assert!(
        error.to_string().contains("output bound"),
        "P128 wrapper retains the native output boundary: {error}"
    );

    let p128_count_output_below = p128_forced_priority_lifecycle(
        pattern,
        profile(case),
        PriorityAggregateOperation::Count,
        case.sample.len(),
        execution,
        PriorityTarget::portable(),
        P128ForcedPriorityLimits {
            construction: count_exact_build,
            execution: PriorityAggregateRunLimits {
                max_output: count_output_bound
                    .checked_sub(1)
                    .expect("positive Count output bound"),
                ..count_exact_run
            },
        },
    )
    .expect("P128 Count one-below output construction stays closed");
    let count_error = p128_count_output_below
        .execute(case.sample)
        .expect_err("P128 Count one-below output must refuse");
    assert!(
        count_error.to_string().contains("output bound"),
        "P128 wrapper retains the Count output boundary: {count_error}"
    );

    assert!(
        span_sum_prospective.scratch_bytes > 0,
        "{:?}/{execution:?}",
        case.point_ids
    );
}

macro_rules! exact_case_route_test {
    ($name:ident, $case_index:expr, $execution:expr) => {
        #[test]
        #[ignore = "requires the authenticated expanded Rebar pattern directory"]
        fn $name() {
            run_exact_case_route($case_index, $execution);
        }
    };
}

exact_case_route_test!(exact_workstream_b_date_sparse, 0, ForcedExecution::Sparse);
exact_case_route_test!(
    exact_workstream_b_date_finite_horizon,
    0,
    ForcedExecution::FiniteHorizon
);
exact_case_route_test!(
    exact_workstream_b_date_full_dfa,
    0,
    ForcedExecution::FullDfa
);
exact_case_route_test!(
    exact_workstream_b_date_lazy_dfa,
    0,
    ForcedExecution::LazyDfa
);
exact_case_route_test!(
    exact_workstream_b_cloudflare_sparse,
    1,
    ForcedExecution::Sparse
);
exact_case_route_test!(
    exact_workstream_b_cloudflare_finite_horizon,
    1,
    ForcedExecution::FiniteHorizon
);
exact_case_route_test!(
    exact_workstream_b_cloudflare_full_dfa,
    1,
    ForcedExecution::FullDfa
);
exact_case_route_test!(
    exact_workstream_b_cloudflare_lazy_dfa,
    1,
    ForcedExecution::LazyDfa
);
exact_case_route_test!(
    exact_workstream_b_i787_5c0fec_sparse,
    2,
    ForcedExecution::Sparse
);
exact_case_route_test!(
    exact_workstream_b_i787_5c0fec_finite_horizon,
    2,
    ForcedExecution::FiniteHorizon
);
exact_case_route_test!(
    exact_workstream_b_i787_5c0fec_full_dfa,
    2,
    ForcedExecution::FullDfa
);
exact_case_route_test!(
    exact_workstream_b_i787_5c0fec_lazy_dfa,
    2,
    ForcedExecution::LazyDfa
);
exact_case_route_test!(
    exact_workstream_b_i787_5ae678_sparse,
    3,
    ForcedExecution::Sparse
);
exact_case_route_test!(
    exact_workstream_b_i787_5ae678_finite_horizon,
    3,
    ForcedExecution::FiniteHorizon
);
exact_case_route_test!(
    exact_workstream_b_i787_5ae678_full_dfa,
    3,
    ForcedExecution::FullDfa
);
exact_case_route_test!(
    exact_workstream_b_i787_5ae678_lazy_dfa,
    3,
    ForcedExecution::LazyDfa
);
