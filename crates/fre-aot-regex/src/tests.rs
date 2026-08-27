use std::fmt::Write as _;

use fre_automata::{
    Automaton, CompileLimits as AutomatonCompileLimits, EdgeKind, K0ResumeSet, K0Workspace,
    RawPlan, SearchError as AutomatonSearchError, StateRole, WorkspaceLimits,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource,
    ContextDfaResource, CpuFeature, DeterminizationResource, DeterminizationStage,
    DeterminizeLimits, EngineKind, EngineSelectionReason, EntryAbi,
    ExactFiniteGrepCountCompileError, FeatureSet, IndependentExistsBatchCompileError,
    PreparedAggregateExports, PreparedAggregateStrategy,
    PreparedBulkStrategy, DirectExistsBatchStrategy, PREPARED_CAPABILITY_ORDERED_NFA_V15,
    MAX_STABLE_DFA_BUILD_WORK, MatchResult, OperatingSystem, OptimizationPass, OutputContract,
    ObjectError, ObjectFormat, SearchWindow, SectionKind, SlowAotLimits, StartAccelerator, Target,
    compile,
    compile_with_exact_finite_selected_end_grep_count, compile_with_independent_exists_batch,
    compile_with_independent_matching_lf_line_witness,
    compile_with_prepared_aggregate_exports, compile_with_slow_aot_limits, emit_object,
    independent_exists_batch_append_outcome, independent_exists_batch_object_outcome,
    independent_exact_singleton_first_candidate_append_outcome,
    independent_exact_singleton_first_candidate_object_outcome,
    independent_matching_lf_line_witness_append_outcome,
    independent_matching_lf_line_witness_object_outcome,
};
use crate::{COMPILER_VERSION, OPTIMIZER_VERSION};

fn generated_wide_finite_pattern(count: usize) -> String {
    (0..count)
        .map(|index| format!("word{index:05}"))
        .collect::<Vec<_>>()
        .join("|")
}

fn compile_pre_wide_finite_prepared_incumbent(
    request: CompileRequest,
    exports: PreparedAggregateExports,
    slow_aot_limits: SlowAotLimits,
) -> crate::CompiledRegex {
    let target = request.target;
    let mode = request.mode;
    let max_object_bytes = request.limits.max_object_bytes;
    let _recipe = crate::module::complete_span_reduce_recipe_scope(
        exports == PreparedAggregateExports::COUNT,
    );
    let compiled = compile_with_slow_aot_limits(request, slow_aot_limits)
        .expect("compile exact pre-wide finite incumbent");
    crate::append_prepared_aggregate_exports_to_compiled(
        compiled,
        exports,
        target,
        mode,
        max_object_bytes,
        slow_aot_limits,
    )
    .expect("append exact pre-wide finite incumbent")
}

fn assert_same_compiled_artifact(left: &crate::CompiledRegex, right: &crate::CompiledRegex) {
    assert_eq!(left.object(), right.object());
    assert_eq!(left.module(), right.module());
    assert_eq!(left.receipt(), right.receipt());
    assert_eq!(
        left.program().serialize().expect("serialize left program"),
        right
            .program()
            .serialize()
            .expect("serialize right program"),
    );
}

#[test]
fn wide_finite_limit_relative_declines_replay_exact_incumbents() {
    for (count, target, exports) in [
        (65, Target::x86_64_linux(), PreparedAggregateExports::COUNT),
        (
            256,
            Target::aarch64_macos(),
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            4_096,
            Target::x86_64_macos(),
            PreparedAggregateExports::COUNT,
        ),
    ] {
        let request = CompileRequest::new(generated_wide_finite_pattern(count), target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span);
        let incumbent = compile_pre_wide_finite_prepared_incumbent(
            request.clone(),
            exports,
            SlowAotLimits::default(),
        );
        let actual = compile_with_prepared_aggregate_exports(request, exports)
            .expect("limit-relative decline compiles its untouched incumbent");
        assert_same_compiled_artifact(&actual, &incumbent);
    }

    let mut folded_profile = RustProfile::default();
    folded_profile.options.case_insensitive = true;
    let request = CompileRequest::new(generated_wide_finite_pattern(256), Target::aarch64_linux())
        .profile(folded_profile)
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Span);
    let incumbent = compile_pre_wide_finite_prepared_incumbent(
        request.clone(),
        PreparedAggregateExports::COUNT,
        SlowAotLimits::default(),
    );
    let actual = compile_with_prepared_aggregate_exports(request, PreparedAggregateExports::COUNT)
        .expect("case-expanded decline compiles its untouched incumbent");
    assert_same_compiled_artifact(&actual, &incumbent);
}

#[test]
fn wide_finite_ineligible_neighbors_replay_exact_incumbents() {
    let wide = generated_wide_finite_pattern(65);
    let cases = [
        (
            CompileRequest::new(generated_wide_finite_pattern(64), Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::COUNT,
        ),
        (
            CompileRequest::new(format!("^(?:{wide})"), Target::x86_64_macos())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            CompileRequest::new(format!("(?:{wide})+"), Target::aarch64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::COUNT,
        ),
        (
            CompileRequest::new(wide.clone(), Target::aarch64_macos())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
            PreparedAggregateExports::COUNT,
        ),
        (
            CompileRequest::new(wide, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM),
        ),
    ];
    for (request, exports) in cases {
        let incumbent = compile_pre_wide_finite_prepared_incumbent(
            request.clone(),
            exports,
            SlowAotLimits::default(),
        );
        let actual = compile_with_prepared_aggregate_exports(request, exports)
            .expect("ineligible neighbor compiles its untouched incumbent");
        assert_same_compiled_artifact(&actual, &incumbent);
    }
}

#[test]
fn wide_finite_above_resource_boundary_retains_closed_native_route() {
    let pattern = generated_wide_finite_pattern(16_384);
    let compiled = compile_with_prepared_aggregate_exports(
        CompileRequest::new(pattern, Target::x86_64_macos())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        PreparedAggregateExports::COUNT,
    )
    .expect("compile generated above-boundary wide finite Count");
    let report = compiled
        .module()
        .ordered_finite_language_aot_report()
        .expect("above-boundary finite report");
    assert_eq!(report.source_count, 16_384);
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeFused),
    );
    assert!(compiled.module().required_runtime_symbol().is_none());
    assert!(report.stored_transition_records <= report.transition_cells);
    if report.sparse_failure {
        assert_eq!(report.stored_transition_records, report.states - 1);
    }
    let haystack = b"xxword16383yy";
    assert_eq!(
        compiled
            .search(haystack, SearchWindow::full(haystack))
            .expect("above-boundary finite semantic search"),
        MatchResult::Span(Some((2, 11))),
    );
}

#[test]
fn wide_finite_dense_cell_boundary_is_exact_and_overflow_is_terminal() {
    assert!(!crate::wide_finite_crosses_dense_cell_boundary(17, 19, 323).unwrap());
    assert!(crate::wide_finite_crosses_dense_cell_boundary(17, 19, 322).unwrap());
    assert!(!crate::wide_finite_crosses_dense_cell_boundary(17, 19, 324).unwrap());
    assert!(matches!(
        crate::wide_finite_crosses_dense_cell_boundary(usize::MAX, 2, usize::MAX),
        Err(CompileError::InternalInvariant(
            "wide finite prospective dense-cell extent overflowed"
        ))
    ));
}

#[test]
fn wide_finite_compact_state_and_edge_rescue_boundaries_are_exact() {
    #[derive(Clone, Copy)]
    enum Resource {
        States,
        Edges,
    }

    fn set_limit(limits: &mut CompileLimitsV1, resource: Resource, value: usize) {
        match resource {
            Resource::States => limits.lower.automata.max_states = value,
            Resource::Edges => limits.lower.automata.max_edges = value,
        }
    }

    let pattern = generated_prefix_dictionary(64, 16);
    let parsed = parsed_rust_bytes(&pattern);
    let ordinary = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        fre_lower::LowerLimits::default(),
    )
    .expect("unconstrained rescue-boundary lowering")
    .into_plan();
    let candidate = crate::finite_language::NativeFiniteLanguageCandidate::analyze_for_wide_early(
        &parsed,
        OutputContract::Span,
    )
    .expect("checked rescue-boundary finite analysis")
    .expect("rescue-boundary finite candidate");
    let compact = candidate
        .priority_trie_raw_plan(fre_lower::LowerLimits::default())
        .expect("bounded rescue-boundary compact graph")
        .expect("priority-compatible rescue-boundary language");
    let no_dfa = DeterminizeLimits {
        max_states: 0,
        max_transitions: 0,
        max_work: 0,
    };
    let base_limits = CompileLimitsV1 {
        determinize: no_dfa,
        ..CompileLimitsV1::default()
    };
    let slow_limits = SlowAotLimits {
        determinize: no_dfa,
        ..SlowAotLimits::default()
    };

    for (resource, compact_needed, ordinary_needed) in [
        (Resource::States, compact.roles.len(), ordinary.roles.len()),
        (
            Resource::Edges,
            compact.edge_targets.len(),
            ordinary.edge_targets.len(),
        ),
    ] {
        assert!(compact_needed < ordinary_needed);

        let one_short = compact_needed
            .checked_sub(1)
            .expect("compact graph nonempty");
        let mut one_short_limits = base_limits;
        set_limit(&mut one_short_limits, resource, one_short);
        let expected = fre_lower::lower_raw_general(
            &parsed,
            fre_lower::OperationSemantics::CaptureFree,
            one_short_limits.lower,
        )
        .expect_err("ordinary graph exceeds a compact-minus-one ceiling");
        let actual = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            CompileRequest::new(&pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
                .limits(one_short_limits),
            PreparedAggregateExports::COUNT,
            slow_limits,
        )
        .expect_err("compact-minus-one ceiling preserves the ordinary error");
        assert_same_lower_resource_failure(expected, actual);

        for limit in [
            compact_needed,
            compact_needed.checked_add(1).expect("compact plus one"),
            ordinary_needed
                .checked_sub(1)
                .expect("ordinary graph nonempty"),
        ] {
            let mut limits = base_limits;
            set_limit(&mut limits, resource, limit);
            let rescued = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
                CompileRequest::new(&pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
                    .limits(limits),
                PreparedAggregateExports::COUNT,
                slow_limits,
            )
            .expect("compact-through-ordinary-minus-one ceiling rescues");
            assert_eq!(rescued.receipt().thompson_states, compact.roles.len());
            assert!(rescued.receipt().ordered_finite_language_aot.is_some());
            assert_eq!(
                rescued.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeFused),
            );
            assert!(rescued.module().required_runtime_symbol().is_none());
        }

        let mut at_needed_limits = base_limits;
        set_limit(&mut at_needed_limits, resource, ordinary_needed);
        let at_needed_request = CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(at_needed_limits);
        let at_needed_incumbent = compile_pre_wide_finite_prepared_incumbent(
            at_needed_request.clone(),
            PreparedAggregateExports::COUNT,
            slow_limits,
        );
        let at_needed = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            at_needed_request,
            PreparedAggregateExports::COUNT,
            slow_limits,
        )
        .expect("ordinary graph at needed ceiling compiles");
        assert_same_compiled_artifact(&at_needed, &at_needed_incumbent);

        let mut plus_one_limits = base_limits;
        set_limit(
            &mut plus_one_limits,
            resource,
            ordinary_needed.checked_add(1).expect("ordinary plus one"),
        );
        let plus_one_request = CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(plus_one_limits);
        let plus_one_incumbent = compile_pre_wide_finite_prepared_incumbent(
            plus_one_request.clone(),
            PreparedAggregateExports::COUNT,
            slow_limits,
        );
        let plus_one = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            plus_one_request,
            PreparedAggregateExports::COUNT,
            slow_limits,
        )
        .expect("ordinary graph above needed ceiling compiles");
        assert_same_compiled_artifact(&plus_one, &plus_one_incumbent);
    }
}

#[test]
fn wide_finite_early_fallback_classifier_never_swallows_hard_failures() {
    assert!(crate::wide_finite_early_numeric_decline(
        &CompileError::Resource {
            resource: CompileResource::ProgramBytes,
            limit: 31,
            required: 32,
        }
    ));
    assert!(crate::wide_finite_early_numeric_decline(
        &CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 31,
            required: 32,
        })
    ));
    assert!(!crate::wide_finite_early_numeric_decline(
        &CompileError::Object(ObjectError::Allocation(
            "synthetic early wide finite allocation",
        ))
    ));
    assert!(!crate::wide_finite_early_numeric_decline(
        &CompileError::Lower(fre_lower::LowerError::AllocationFailed {
            structure: "synthetic early wide finite proof",
            additional: 1,
        })
    ));
    assert!(!crate::wide_finite_early_numeric_decline(
        &CompileError::Object(ObjectError::ArithmeticOverflow(
            "synthetic early wide finite arithmetic",
        ))
    ));
    assert!(!crate::wide_finite_early_numeric_decline(
        &CompileError::Object(ObjectError::UnsupportedTarget)
    ));

    assert!(matches!(
        crate::wide_finite_forward_probe_promotes(crate::dfa::ForwardCostProbeOutcome::Complete {
            states: 3,
            transitions: 9,
            work_completed: 17,
            allocation_peak_bytes: 31,
        }),
        Ok(false)
    ));
    assert!(matches!(
        crate::wide_finite_forward_probe_promotes(
            crate::dfa::ForwardCostProbeOutcome::NumericDecline {
                resource: crate::DeterminizationResource::Work {
                    limit: 16,
                    required: 17,
                },
                work_completed: 16,
                states_completed: 2,
                transitions_completed: 6,
                allocation_peak_bytes: 29,
            }
        ),
        Ok(true)
    ));
    assert!(matches!(
        crate::wide_finite_forward_probe_promotes(
            crate::dfa::ForwardCostProbeOutcome::AllocationFailure {
                requested_elements: 8,
                element_size: 4,
            }
        ),
        Err(CompileError::Object(ObjectError::Allocation(
            "wide finite ordered forward cost probe"
        )))
    ));
}

#[test]
fn wide_finite_forward_probe_resources_are_exact_and_allocation_is_bounded() {
    let parsed = parsed_rust_bytes(&generated_wide_finite_pattern(65));
    let ordinary = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        fre_lower::LowerLimits::default(),
    )
    .expect("lower forward-probe fixture")
    .into_plan();
    let candidate = crate::finite_language::NativeFiniteLanguageCandidate::analyze_for_wide_early(
        &parsed,
        OutputContract::Span,
    )
    .expect("analyze forward-probe fixture")
    .expect("finite forward-probe fixture");
    let compact = candidate
        .priority_trie_raw_plan(fre_lower::LowerLimits::default())
        .expect("build forward-probe compact graph")
        .expect("priority-compatible forward-probe fixture");
    let classes = crate::dfa::current_graph_alphabet_class_count(&ordinary)
        .expect("census forward-probe alphabet")
        .expect("assertion-free forward-probe alphabet");
    let broad = DeterminizeLimits {
        max_states: compact.roles.len(),
        max_transitions: compact
            .roles
            .len()
            .checked_mul(classes)
            .expect("forward-probe transition extent"),
        max_work: fre_lower::LowerLimits::default().max_work,
    };
    let complete = crate::dfa::probe_ordered_forward_cost(
        &ordinary,
        broad,
        fre_lower::LowerLimits::default().automata.max_storage_bytes,
    )
    .expect("complete forward-cost probe");
    let crate::dfa::ForwardCostProbeOutcome::Complete {
        states,
        transitions,
        work_completed,
        allocation_peak_bytes,
    } = complete
    else {
        panic!("broad forward-cost probe declined: {complete:?}");
    };
    assert!(states > 0 && transitions > 0 && work_completed > 0);
    assert!(allocation_peak_bytes > 0);

    let state_short = crate::dfa::probe_ordered_forward_cost(
        &ordinary,
        DeterminizeLimits {
            max_states: states - 1,
            ..broad
        },
        fre_lower::LowerLimits::default().automata.max_storage_bytes,
    )
    .expect("state-short forward-cost probe");
    assert!(matches!(
        state_short,
        crate::dfa::ForwardCostProbeOutcome::NumericDecline {
            resource: crate::DeterminizationResource::States { .. },
            ..
        }
    ));
    for max_states in [states, states + 1] {
        assert!(matches!(
            crate::dfa::probe_ordered_forward_cost(
                &ordinary,
                DeterminizeLimits {
                    max_states,
                    ..broad
                },
                fre_lower::LowerLimits::default().automata.max_storage_bytes,
            )
            .expect("at-or-above state forward-cost probe"),
            crate::dfa::ForwardCostProbeOutcome::Complete { .. }
        ));
    }

    let work_short = crate::dfa::probe_ordered_forward_cost(
        &ordinary,
        DeterminizeLimits {
            max_work: work_completed - 1,
            ..broad
        },
        fre_lower::LowerLimits::default().automata.max_storage_bytes,
    )
    .expect("work-short forward-cost probe");
    assert!(matches!(
        work_short,
        crate::dfa::ForwardCostProbeOutcome::NumericDecline {
            resource: crate::DeterminizationResource::Work { .. },
            ..
        }
    ));

    let allocation_short =
        crate::dfa::probe_ordered_forward_cost(&ordinary, broad, allocation_peak_bytes - 1)
            .expect("allocation-short forward-cost probe");
    assert!(matches!(
        allocation_short,
        crate::dfa::ForwardCostProbeOutcome::NumericDecline {
            resource: crate::DeterminizationResource::Allocation { .. },
            ..
        }
    ));
    assert!(matches!(
        crate::dfa::probe_ordered_forward_cost(&ordinary, broad, allocation_peak_bytes)
            .expect("exact-allocation forward-cost probe"),
        crate::dfa::ForwardCostProbeOutcome::Complete { .. }
    ));
}

#[test]
fn independent_exists_batch_allocator_failure_is_terminal_at_both_optional_seams() {
    const APPEND_SITE: &str = "injected direct Exists batch append allocation";
    const OBJECT_SITE: &str = "injected direct Exists batch object allocation";

    assert!(matches!(
        independent_exists_batch_append_outcome(Err(ObjectError::Allocation(APPEND_SITE))),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(APPEND_SITE))
        ))
    ));
    assert!(matches!(
        independent_exists_batch_object_outcome(Err(ObjectError::Allocation(OBJECT_SITE))),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(OBJECT_SITE))
        ))
    ));

    // An object-byte resource report is not a generic optional-candidate
    // decline. It remains terminal at append and is authorized only after the
    // completed additive module reaches final object emission.
    assert!(matches!(
        independent_exists_batch_append_outcome(Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 31,
            required: 32,
        })),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                limit: 31,
                required: 32,
            })
        ))
    ));
    assert!(
        independent_exists_batch_object_outcome(Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 31,
            required: 32,
        }))
        .expect("final ObjectBytes cap is the sole optional resource decline")
        .is_none()
    );

    const ENDPOINT_APPEND_SITE: &str =
        "injected exact-singleton first-candidate append allocation";
    const ENDPOINT_OBJECT_SITE: &str =
        "injected exact-singleton first-candidate object allocation";
    assert!(matches!(
        independent_exact_singleton_first_candidate_append_outcome(Err(
            ObjectError::Allocation(ENDPOINT_APPEND_SITE)
        )),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(ENDPOINT_APPEND_SITE))
        ))
    ));
    assert!(matches!(
        independent_exact_singleton_first_candidate_object_outcome(Err(
            ObjectError::Allocation(ENDPOINT_OBJECT_SITE)
        )),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(ENDPOINT_OBJECT_SITE))
        ))
    ));
    assert!(independent_exact_singleton_first_candidate_object_outcome(Err(
        ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 63,
            required: 64,
        }
    ))
    .expect("final endpoint-only ObjectBytes cap retains the batch incumbent")
    .is_none());

    const LF_WITNESS_APPEND_SITE: &str =
        "injected matching-LF-line witness append allocation";
    const LF_WITNESS_OBJECT_SITE: &str =
        "injected matching-LF-line witness object allocation";
    assert!(matches!(
        independent_matching_lf_line_witness_append_outcome(Err(
            ObjectError::Allocation(LF_WITNESS_APPEND_SITE)
        )),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(LF_WITNESS_APPEND_SITE))
        ))
    ));
    assert!(matches!(
        independent_matching_lf_line_witness_append_outcome(Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 63,
            required: 64,
        })),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                limit: 63,
                required: 64,
            })
        ))
    ));
    assert!(matches!(
        independent_matching_lf_line_witness_object_outcome(Err(
            ObjectError::Allocation(LF_WITNESS_OBJECT_SITE)
        )),
        Err(IndependentExistsBatchCompileError::Compile(
            CompileError::Object(ObjectError::Allocation(LF_WITNESS_OBJECT_SITE))
        ))
    ));
    assert!(independent_matching_lf_line_witness_object_outcome(Err(
        ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 63,
            required: 64,
        }
    ))
    .expect("only final witness ObjectBytes may retain the exact batch incumbent")
    .is_none());
}

#[test]
fn independent_exists_batch_is_opt_in_authenticated_and_resource_atomic() {
    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        let request = CompileRequest::new("needle", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists);
        let ordinary = compile(request.clone()).expect("ordinary direct Exists artifact");
        assert!(ordinary.module().prepared_entry_symbol().is_none());
        assert!(ordinary.module().direct_exists_batch_symbol().is_none());
        let batched = compile_with_independent_exists_batch(request.clone())
            .expect("direct Exists batch artifact");
        let repeated = compile_with_independent_exists_batch(request.clone())
            .expect("deterministic direct Exists batch artifact");
        let expected_parent_module = ordinary
            .module()
            .clone()
            .append_direct_exists_batch(OutputContract::Exists)
            .expect("append established direct batch")
            .expect("established direct batch eligibility");
        let expected_parent_object = emit_object(
            &expected_parent_module,
            ObjectFormat::for_target(target),
            usize::MAX,
        )
        .expect("emit established direct batch object");
        assert_eq!(batched.module(), &expected_parent_module);
        assert_eq!(batched.object(), expected_parent_object);
        assert!(
            batched
                .module()
                .direct_matching_lf_line_witness_symbol()
                .is_none()
        );
        assert_eq!(batched.object(), repeated.object());
        assert_eq!(batched.module(), repeated.module());
        assert_eq!(
            batched.module().direct_exists_batch_strategy(),
            Some(DirectExistsBatchStrategy::NativeOrdinaryEntryLoop)
        );
        let batch_symbol = batched
            .module()
            .direct_exists_batch_symbol()
            .expect("handle-free direct batch symbol");
        assert!(batch_symbol.starts_with("fre_aot_regex_is_match_batch_v1_"));
        assert!(batched.module().prepared_exists_batch_symbol().is_none());
        assert!(batched.module().required_runtime_symbols().next().is_none());
        assert_eq!(batched.receipt().passes, ordinary.receipt().passes);
        assert_eq!(
            ordinary.program().serialize().expect("ordinary program bytes"),
            batched.program().serialize().expect("batched program bytes")
        );
        assert_eq!(
            ordinary.receipt().automaton_sha256,
            batched.receipt().automaton_sha256
        );
        assert_eq!(
            ordinary.receipt().program_sha256,
            batched.receipt().program_sha256
        );
        assert_eq!(
            ordinary.module().entry_symbol(),
            batched.module().entry_symbol()
        );

        let ordinary_text = ordinary
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("ordinary text");
        let batched_text = batched
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("batched text");
        let ordinary_entry = ordinary
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == ordinary.module().entry_symbol())
            .expect("ordinary entry extent");
        let entry_start = usize::try_from(ordinary_entry.offset).expect("entry start");
        let entry_size = usize::try_from(ordinary_entry.size).expect("entry size");
        let entry_end = entry_start.checked_add(entry_size).expect("entry end");
        assert_eq!(
            ordinary_text.bytes().get(entry_start..entry_end),
            batched_text.bytes().get(entry_start..entry_end),
            "additive batch changed the ordinary entry"
        );
        let ordinary_data = ordinary
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::ReadOnlyData)
            .expect("ordinary data");
        let batched_data = batched
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::ReadOnlyData)
            .expect("batched data");
        assert_eq!(ordinary_data.bytes(), batched_data.bytes());
        if let Some(mut expected) = ordinary.receipt().exact_single_literal_aot {
            expected.native_code_sha256 = Sha256::digest(batched_text.bytes()).into();
            assert_eq!(batched.receipt().exact_single_literal_aot, Some(expected));
        }

        let witnessed = compile_with_independent_matching_lf_line_witness(request.clone())
            .expect("explicit matching-LF-line witness artifact");
        assert!(
            witnessed
                .module()
                .direct_matching_lf_line_witness_symbol()
                .is_some()
        );
        assert!(witnessed.receipt().matching_lf_line_witness_aot.is_some());
        let witnessed_text = witnessed
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("witnessed text");
        assert_eq!(
            ordinary_text.bytes().get(entry_start..entry_end),
            witnessed_text.bytes().get(entry_start..entry_end),
            "explicit matching-line endpoint changed the ordinary entry",
        );

        let mut limits = CompileLimitsV1::default();
        limits.max_object_bytes = ordinary.object().len();
        let declined = compile_with_independent_exists_batch(request.limits(limits))
            .expect("optional batch object-byte decline");
        assert_eq!(declined.object(), ordinary.object());
        assert_eq!(declined.module(), ordinary.module());
        assert_eq!(declined.receipt().object_sha256, ordinary.receipt().object_sha256);
        assert!(declined.module().direct_exists_batch_symbol().is_none());
    }

    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        let request = CompileRequest::new("(?-u:a|b)", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists);
        let ordinary = compile(request.clone()).expect("exact byte-set Exists artifact");
        assert!(ordinary.receipt().exact_finite_exists_byte_set_aot.is_some());
        let declined = compile_with_independent_exists_batch(request)
            .expect("trusted-core-ineligible exact byte-set decline");
        assert_eq!(declined.object(), ordinary.object());
        assert_eq!(declined.module(), ordinary.module());
        assert_eq!(declined.receipt(), ordinary.receipt());
        assert!(declined.module().direct_exists_batch_symbol().is_none());
    }

    assert!(matches!(
        compile_with_independent_exists_batch(
            CompileRequest::new("needle", Target::x86_64_linux())
                .output(OutputContract::Span)
        ),
        Err(IndependentExistsBatchCompileError::RequiresExists {
            actual: OutputContract::Span
        })
    ));

    let nullable_request = CompileRequest::new("x*", Target::x86_64_linux())
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Exists);
    let nullable_batch = compile_with_independent_exists_batch(nullable_request.clone())
        .expect("established nullable batch");
    let nullable_witness = compile_with_independent_matching_lf_line_witness(nullable_request)
        .expect("nullable witness structurally declines");
    assert_eq!(nullable_witness.object(), nullable_batch.object());
    assert_eq!(nullable_witness.module(), nullable_batch.module());
    assert_eq!(nullable_witness.receipt(), nullable_batch.receipt());
}

#[test]
fn direct_exact_singleton_count_selects_for_every_supported_width_and_format() {
    for target in [Target::aarch64_linux(), Target::aarch64_macos()].map(|target| {
        target
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("valid AArch64 ASIMD target")
    }) {
        for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
            let pattern = "a".repeat(width);
            let ordinary = compile(
                CompileRequest::new(pattern.clone(), target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .expect("compile exact-singleton ordinary control");
            let none = compile_with_prepared_aggregate_exports(
                CompileRequest::new(pattern.clone(), target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
                PreparedAggregateExports::NONE,
            )
            .expect("compile exact-singleton NONE control");
            assert_eq!(ordinary.object(), none.object());
            assert_eq!(ordinary.program().serialize().unwrap(), none.program().serialize().unwrap());

            let compiled = compile_with_prepared_aggregate_exports(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
                PreparedAggregateExports::COUNT,
            )
            .expect("compile direct exact-singleton Count");
            assert!(
                !compiled.module().uses_direct_span_trusted_core_aggregate(),
                "the exact-singleton follow-on must retain its authenticated DirectOrdinary incumbent",
            );
            let report = compiled
                .module()
                .direct_exact_singleton_count_aot_report()
                .expect("direct exact-singleton Count selection");
            assert_eq!(usize::from(report.literal_bytes), width);
            assert_eq!(
                report.successor_mode,
                crate::DirectExactSingletonCountSuccessorMode::NonOverlapping,
            );
            let has_short_fallback = matches!(width, 2 | 4);
            assert_eq!(
                report.selection_basis,
                if has_short_fallback {
                    crate::DirectExactSingletonCountSelectionBasis::StructuralSingleScanDominanceWithShortIncumbent
                } else {
                    crate::DirectExactSingletonCountSelectionBasis::StructuralSingleScanDominance
                },
            );
            assert_eq!(
                report.short_fallback_max_bytes,
                has_short_fallback
                    .then_some(crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES),
            );
            assert_eq!(
                report.copied_incumbent_body_offset.is_some(),
                false,
            );
            assert_eq!(
                report.copied_incumbent_body_bytes.is_some(),
                false,
            );
            assert_eq!(report.cold_long_offset.is_some(), has_short_fallback);
            assert_eq!(report.cold_long_bytes.is_some(), has_short_fallback);
            assert_eq!(
                report.core_alignment_bytes,
                crate::direct_count_v3::DIRECT_EXACT_SINGLETON_COUNT_CORE_ALIGNMENT_BYTES,
            );
            assert!(
                report
                    .core_offset
                    .is_multiple_of(report.core_alignment_bytes),
            );
            assert_eq!(report.incumbent_cost.scan_passes, 1);
            assert_eq!(report.selected_cost.scan_passes, 1);
            assert_eq!(report.incumbent_cost.native_calls_per_match, 1);
            assert_eq!(report.selected_cost.native_calls_per_match, 0);
            assert_eq!(
                report.incumbent_cost.internal_span_publications_per_match,
                1,
            );
            assert_eq!(report.selected_cost.internal_span_publications_per_match, 0);
            assert_eq!(report.incumbent_cost.unresolved_runtime_helpers, 0);
            assert_eq!(report.selected_cost.unresolved_runtime_helpers, 0);
            assert!(report.core_bytes != 0);
            assert_eq!(compiled.receipt().prepared_aggregate_exports, PreparedAggregateExports::COUNT);
            assert_eq!(
                compiled.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeFused),
            );
            match target.operating_system {
                OperatingSystem::Linux => assert_eq!(&compiled.object()[..4], b"\x7fELF"),
                OperatingSystem::Macos => assert_eq!(&compiled.object()[..4], &0xfeed_facf_u32.to_le_bytes()),
            }
        }
    }
    let semantic_singleton = compile_with_prepared_aggregate_exports(
        CompileRequest::new(
            "a|a",
            direct_count_asimd_target(OperatingSystem::Linux),
        )
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Span),
        PreparedAggregateExports::COUNT,
    )
    .expect("compile semantic exact-singleton Count");
    assert_eq!(
        semantic_singleton
            .module()
            .direct_exact_singleton_count_aot_report()
            .map(|report| report.literal_bytes),
        Some(1),
    );
}

fn direct_count_asimd_target(operating_system: OperatingSystem) -> Target {
    let target = match operating_system {
        OperatingSystem::Linux => Target::aarch64_linux(),
        OperatingSystem::Macos => Target::aarch64_macos(),
    };
    target
        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .expect("valid AArch64 ASIMD target")
}

fn direct_count_request(
    pattern: impl Into<String>,
    target: Target,
    mode: CompileMode,
    max_object_bytes: usize,
) -> CompileRequest {
    let limits = CompileLimitsV1 {
        max_object_bytes,
        ..CompileLimitsV1::default()
    };
    CompileRequest::new(pattern, target)
        .mode(mode)
        .output(OutputContract::Span)
        .limits(limits)
}

fn compile_count_with_direct_candidate_declined(
    request: CompileRequest,
    exports: PreparedAggregateExports,
) -> crate::CompiledRegex {
    let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
        crate::direct_count_v3::DirectExactSingletonCountTestPreparation::Decline,
    );
    compile_with_prepared_aggregate_exports(request, exports)
        .expect("compile forced direct Count-v3 incumbent")
}

fn compile_span_sum_with_direct_candidate_declined(
    request: CompileRequest,
) -> crate::CompiledRegex {
    compile_span_sum_exports_with_direct_candidate_declined(
        request,
        PreparedAggregateExports::SPAN_SUM,
    )
}

fn compile_span_sum_exports_with_direct_candidate_declined(
    request: CompileRequest,
    exports: PreparedAggregateExports,
) -> crate::CompiledRegex {
    let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
        crate::direct_count_v3::DirectExactSingletonCountTestPreparation::Decline,
    );
    compile_with_prepared_aggregate_exports(request, exports)
        .expect("compile forced direct SpanSum incumbent")
}

#[test]
fn direct_exact_singleton_span_sum_declines_without_changing_ineligible_incumbents() {
    let asimd = direct_count_asimd_target(OperatingSystem::Linux);
    let default_cap = CompileLimitsV1::default().max_object_bytes;
    let cases = [
        (
            "a|b",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a?",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "^a",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a{33}",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a",
            Target::aarch64_linux(),
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a",
            Target::x86_64_linux(),
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a",
            asimd,
            CompileMode::Fast,
            PreparedAggregateExports::SPAN_SUM,
        ),
        (
            "a",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::SPAN_SUM.union(PreparedAggregateExports::COUNT),
        ),
    ];
    for (pattern, target, mode, exports) in cases {
        let request = direct_count_request(pattern, target, mode, default_cap);
        let incumbent = compile_span_sum_exports_with_direct_candidate_declined(
            request.clone(),
            exports,
        );
        let declined = compile_with_prepared_aggregate_exports(request, exports)
            .expect("compile ineligible direct SpanSum incumbent");
        assert_eq!(declined.object(), incumbent.object());
        assert_eq!(declined.module(), incumbent.module());
        assert!(declined
            .module()
            .direct_exact_singleton_span_sum_aot_report()
            .is_none());
    }
}

#[test]
fn direct_exact_singleton_span_sum_selects_with_the_count_gate_policy() {
    for target in [Target::aarch64_linux(), Target::aarch64_macos()].map(|target| {
        target
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("valid AArch64 ASIMD target")
    }) {
        let mut width_two_wrapper_bytes = None;
        for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
            let compiled = compile_with_prepared_aggregate_exports(
                direct_count_request(
                    "a".repeat(width),
                    target,
                    CompileMode::Optimizing,
                    CompileLimitsV1::default().max_object_bytes,
                ),
                PreparedAggregateExports::SPAN_SUM,
            )
            .expect("compile direct exact-singleton SpanSum");
            assert!(
                !compiled.module().uses_direct_span_trusted_core_aggregate(),
                "the exact-singleton SpanSum follow-on must retain its DirectOrdinary incumbent",
            );
            let report = compiled
                .module()
                .direct_exact_singleton_span_sum_aot_report()
                .expect("direct exact-singleton SpanSum selection");
            let gated = matches!(width, 2 | 4);
            assert_eq!(
                report.schema_version,
                crate::DIRECT_EXACT_SINGLETON_SPAN_SUM_AOT_SCHEMA_VERSION,
            );
            assert_eq!(usize::from(report.literal_bytes), width);
            assert_eq!(
                report.successor_mode,
                crate::DirectExactSingletonSpanSumSuccessorMode::NonOverlapping,
            );
            assert_eq!(
                report.selection_basis,
                if gated {
                    crate::DirectExactSingletonSpanSumSelectionBasis::ExactWidthCountCompositionWithShortIncumbent
                } else {
                    crate::DirectExactSingletonSpanSumSelectionBasis::ExactWidthCountComposition
                },
            );
            assert_eq!(
                report.short_fallback_max_bytes,
                gated.then_some(
                    crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES,
                ),
            );
            assert_eq!(report.cold_long_offset.is_some(), gated);
            assert_eq!(report.cold_long_bytes.is_some(), gated);
            if gated {
                assert_eq!(
                    report.cold_long_offset.unwrap() + report.cold_long_bytes.unwrap(),
                    report.wrapper_offset,
                );
            }
            let wrapper_end = report
                .wrapper_offset
                .checked_add(report.wrapper_bytes)
                .expect("SpanSum wrapper extent");
            assert_eq!(
                wrapper_end.checked_add(report.wrapper_to_core_padding_bytes),
                Some(report.core_offset),
            );
            assert_eq!(
                report.core_alignment_bytes,
                crate::DIRECT_EXACT_SINGLETON_SPAN_SUM_COUNT_CORE_ALIGNMENT_BYTES,
            );
            assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));
            assert!(report.wrapper_to_core_padding_bytes < report.core_alignment_bytes);
            assert!(report.wrapper_to_core_padding_bytes.is_multiple_of(4));
            let text = compiled
                .module()
                .sections()
                .iter()
                .find(|section| section.kind == SectionKind::Text)
                .expect("direct SpanSum text section");
            assert_eq!(
                usize::try_from(text.alignment).expect("text alignment"),
                report.text_section_alignment_bytes,
            );
            assert!(
                report
                    .text_section_alignment_bytes
                    .is_multiple_of(report.core_alignment_bytes),
            );
            assert!(
                text.bytes()[wrapper_end..report.core_offset]
                    .chunks_exact(4)
                    .all(|word| word == 0xd503_201f_u32.to_le_bytes()),
            );
            let wrapper = &text.bytes()[report.wrapper_offset..wrapper_end];
            assert!(wrapper.len().is_multiple_of(4));
            let wrapper_words = wrapper
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("AArch64 word")))
                .collect::<Vec<_>>();
            const UMULH_COUNT_WIDTH: u32 = 0x9bc9_7d0a; // UMULH X10,X8,X9
            const MUL_COUNT_WIDTH: u32 = 0x9b09_7d08; // MUL X8,X8,X9
            for product_word in [UMULH_COUNT_WIDTH, MUL_COUNT_WIDTH] {
                assert_eq!(
                    wrapper_words
                        .iter()
                        .filter(|&&word| word == product_word)
                        .count(),
                    if width == 1 { 0 } else { 1 },
                );
            }
            if width == 1 {
                assert!(
                    crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
                        1,
                        report.wrapper_offset,
                        report.core_offset,
                        wrapper,
                    )
                    .is_ok(),
                );
                assert!(
                    crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
                        2,
                        report.wrapper_offset,
                        report.core_offset,
                        wrapper,
                    )
                    .is_err(),
                );
            }
            if width == 2 {
                width_two_wrapper_bytes = Some(wrapper.len());
                assert!(
                    crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
                        2,
                        report.wrapper_offset,
                        report.core_offset,
                        wrapper,
                    )
                    .is_ok(),
                );
                assert!(
                    crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
                        3,
                        report.wrapper_offset,
                        report.core_offset,
                        wrapper,
                    )
                    .is_err(),
                    "equal-length wrappers must still bind the literal-width immediate",
                );
            }
            if width == 3 {
                assert_eq!(
                    width_two_wrapper_bytes,
                    Some(wrapper.len()),
                    "the width-2/width-3 rejection must exercise equal-length topology",
                );
            }
            assert_eq!(report.incumbent_strategy, PreparedAggregateStrategy::NativeFused);
            assert_eq!(report.incumbent_cost.scan_passes, 1);
            assert_eq!(report.selected_cost.scan_passes, 1);
            assert_eq!(report.incumbent_cost.native_scan_entries_per_operation, 1);
            assert_eq!(report.selected_cost.native_scan_entries_per_operation, 1);
            assert_eq!(report.incumbent_cost.native_calls_per_match, 1);
            assert_eq!(report.selected_cost.native_calls_per_match, 0);
            assert_eq!(report.incumbent_cost.internal_span_publications_per_match, 1);
            assert_eq!(report.selected_cost.internal_span_publications_per_match, 0);
            assert_eq!(report.incumbent_cost.unresolved_runtime_helpers, 0);
            assert_eq!(report.selected_cost.unresolved_runtime_helpers, 0);
            assert_ne!(report.wrapper_bytes, 0);
            assert_ne!(report.core_bytes, 0);
            assert!(compiled
                .module()
                .direct_exact_singleton_count_aot_report()
                .is_none());
            assert!(compiled.module().required_runtime_symbols().next().is_none());
            assert_eq!(
                compiled.receipt().prepared_aggregate_exports,
                PreparedAggregateExports::SPAN_SUM,
            );
            assert_eq!(
                compiled.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeFused),
            );
            match target.operating_system {
                OperatingSystem::Linux => assert_eq!(&compiled.object()[..4], b"\x7fELF"),
                OperatingSystem::Macos => assert_eq!(
                    &compiled.object()[..4],
                    &0xfeed_facf_u32.to_le_bytes(),
                ),
            }
        }
    }

    for target in [Target::x86_64_linux(), Target::x86_64_macos()] {
        let request = direct_count_request(
            "abcdefgh",
            target,
            CompileMode::Optimizing,
            CompileLimitsV1::default().max_object_bytes,
        );
        let incumbent = compile_span_sum_with_direct_candidate_declined(request.clone());
        let declined = compile_with_prepared_aggregate_exports(
            request,
            PreparedAggregateExports::SPAN_SUM,
        )
        .expect("compile x86 direct SpanSum decline");
        assert_eq!(declined.object(), incumbent.object());
        assert_eq!(declined.module(), incumbent.module());
        assert!(declined
            .module()
            .direct_exact_singleton_span_sum_aot_report()
            .is_none());
    }
}

#[test]
fn direct_exact_singleton_span_sum_object_cap_and_allocator_failure_are_fail_closed() {
    let target = direct_count_asimd_target(OperatingSystem::Linux);
    let default_cap = CompileLimitsV1::default().max_object_bytes;
    let request = direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        default_cap,
    );
    let incumbent = compile_span_sum_with_direct_candidate_declined(request.clone());
    let selected = compile_with_prepared_aggregate_exports(
        request,
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("compile selected direct SpanSum");
    assert!(selected.object().len() > incumbent.object().len());
    assert!(selected
        .module()
        .direct_exact_singleton_span_sum_aot_report()
        .is_some());

    let candidate_cap = selected.object().len() - 1;
    assert!(candidate_cap >= incumbent.object().len());
    let capped_request = direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        candidate_cap,
    );
    let capped_incumbent =
        compile_span_sum_with_direct_candidate_declined(capped_request.clone());
    let capped = compile_with_prepared_aggregate_exports(
        capped_request,
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("proven final direct SpanSum object cap rolls back");
    assert_eq!(capped.object(), capped_incumbent.object());
    assert_eq!(capped.module(), capped_incumbent.module());
    assert!(capped
        .module()
        .direct_exact_singleton_span_sum_aot_report()
        .is_none());

    let gated_request = direct_count_request(
        "aa",
        target,
        CompileMode::Optimizing,
        default_cap,
    );
    let gated_incumbent =
        compile_span_sum_with_direct_candidate_declined(gated_request.clone());
    let gated_selected = compile_with_prepared_aggregate_exports(
        gated_request,
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("compile selected gated direct SpanSum");
    assert!(gated_selected.object().len() > gated_incumbent.object().len());
    let gated_cap = gated_selected.object().len() - 1;
    assert!(gated_cap >= gated_incumbent.object().len());
    let capped_gated_request = direct_count_request(
        "aa",
        target,
        CompileMode::Optimizing,
        gated_cap,
    );
    let capped_gated_incumbent =
        compile_span_sum_with_direct_candidate_declined(capped_gated_request.clone());
    let capped_gated = compile_with_prepared_aggregate_exports(
        capped_gated_request,
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("proven final gated SpanSum object cap rolls back");
    assert_eq!(capped_gated.object(), capped_gated_incumbent.object());
    assert_eq!(capped_gated.module(), capped_gated_incumbent.module());
    assert!(capped_gated
        .module()
        .direct_exact_singleton_span_sum_aot_report()
        .is_none());

    let low_cap = incumbent.object().len() - 1;
    let error = compile_with_prepared_aggregate_exports(
        direct_count_request(
            "abcdefgh",
            target,
            CompileMode::Optimizing,
            low_cap,
        ),
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect_err("incumbent SpanSum object cap remains terminal");
    assert!(matches!(
        error,
        CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) if limit == low_cap && required == incumbent.object().len()
    ));

    {
        let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
            crate::direct_count_v3::DirectExactSingletonCountTestPreparation::AllocationFailure,
        );
        let error = compile_with_prepared_aggregate_exports(
            direct_count_request(
                "abcdefgh",
                target,
                CompileMode::Optimizing,
                default_cap,
            ),
            PreparedAggregateExports::SPAN_SUM,
        )
        .expect_err("direct SpanSum candidate allocator failure is terminal");
        assert!(matches!(
            error,
            CompileError::Object(ObjectError::Allocation(
                "injected direct Count-v3 candidate"
            ))
        ));
    }
    {
        let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
            crate::direct_count_v3::DirectExactSingletonCountTestPreparation::UnsupportedBackendFailure,
        );
        let error = compile_with_prepared_aggregate_exports(
            direct_count_request(
                "abcdefgh",
                target,
                CompileMode::Optimizing,
                default_cap,
            ),
            PreparedAggregateExports::SPAN_SUM,
        )
        .expect_err("direct SpanSum backend failure is terminal");
        assert!(matches!(
            error,
            CompileError::Object(ObjectError::InvalidModule(
                "direct Count-v3 backend rejected authenticated target tuple"
            ))
        ));
    }
}

#[test]
fn direct_exact_singleton_span_sum_authenticates_incumbent_wrapper_and_core() {
    let target = direct_count_asimd_target(OperatingSystem::Macos);
    let incumbent = compile_span_sum_with_direct_candidate_declined(direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        CompileLimitsV1::default().max_object_bytes,
    ));
    let literal = incumbent
        .program()
        .native_exact_singleton_count_literal()
        .expect("authenticated SpanSum singleton witness");
    let artifact_identity = incumbent.program().artifact_identity();
    let candidate = match crate::direct_count_v3::prepare_direct_exact_singleton_count(
        literal,
        artifact_identity,
        target,
        CompileLimitsV1::default().max_object_bytes,
    )
    .expect("prepare direct SpanSum Count-v3 core") {
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(candidate) => {
            candidate
        }
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Declined => {
            panic!("supported direct SpanSum Count-v3 core declined")
        }
    };

    let mut wrong_identity = incumbent.module().clone();
    assert!(wrong_identity
        .install_direct_exact_singleton_span_sum(literal, [7; 32], &candidate)
        .is_err());
    let wrong_candidate = match crate::direct_count_v3::prepare_direct_exact_singleton_count(
        literal,
        [7; 32],
        target,
        CompileLimitsV1::default().max_object_bytes,
    )
    .expect("prepare differently bound direct SpanSum Count-v3 core") {
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(candidate) => {
            candidate
        }
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Declined => {
            panic!("supported differently bound direct SpanSum core declined")
        }
    };
    let mut wrong_binding = incumbent.module().clone();
    assert!(wrong_binding
        .install_direct_exact_singleton_span_sum(
            literal,
            artifact_identity,
            &wrong_candidate,
        )
        .is_err());

    let span_sum = incumbent
        .module()
        .symbols()
        .iter()
        .find(|symbol| {
            symbol.binding == crate::SymbolBinding::Global
                && symbol.kind == crate::SymbolKind::Function
                && symbol
                    .name
                    .starts_with("fre_aot_regex_span_sum_exclusive_v1_")
        })
        .expect("incumbent SpanSum symbol");
    let symbol_start = usize::try_from(span_sum.offset).expect("SpanSum symbol start");
    let symbol_end = usize::try_from(span_sum.offset + span_sum.size)
        .expect("SpanSum symbol end");
    let mut tampered_incumbent = incumbent.module().clone();
    assert!(tampered_incumbent.test_flip_text_byte(symbol_end - 1));
    assert!(tampered_incumbent
        .install_direct_exact_singleton_span_sum(literal, artifact_identity, &candidate)
        .is_err());
    let mut tampered_relocation = incumbent.module().clone();
    assert!(tampered_relocation
        .test_flip_text_relocation_addend_in_range(symbol_start, symbol_end));
    assert!(tampered_relocation
        .install_direct_exact_singleton_span_sum(literal, artifact_identity, &candidate)
        .is_err());

    let mut selected = incumbent.module().clone();
    let rollback = selected
        .install_direct_exact_singleton_span_sum(literal, artifact_identity, &candidate)
        .expect("install authenticated direct SpanSum composition")
        .expect("selected direct SpanSum rollback checkpoint");
    let report = *selected
        .direct_exact_singleton_span_sum_aot_report()
        .expect("selected direct SpanSum report");
    let text_index = selected
        .sections()
        .iter()
        .position(|section| section.kind == SectionKind::Text)
        .expect("selected direct SpanSum text section");
    let text = selected.sections()[text_index].bytes();
    let wrapper_end = report
        .wrapper_offset
        .checked_add(report.wrapper_bytes)
        .expect("selected direct SpanSum wrapper extent");
    let core_end = report
        .core_offset
        .checked_add(report.core_bytes)
        .expect("selected direct SpanSum core extent");
    assert_eq!(
        wrapper_end.checked_add(report.wrapper_to_core_padding_bytes),
        Some(report.core_offset),
    );
    assert_eq!(
        report.core_alignment_bytes,
        crate::DIRECT_EXACT_SINGLETON_SPAN_SUM_COUNT_CORE_ALIGNMENT_BYTES,
    );
    assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));
    assert_eq!(
        usize::try_from(selected.sections()[text_index].alignment)
            .expect("selected text alignment"),
        report.text_section_alignment_bytes,
    );
    assert!(
        text[wrapper_end..report.core_offset]
            .chunks_exact(4)
            .all(|word| word == 0xd503_201f_u32.to_le_bytes()),
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&text[report.wrapper_offset..wrapper_end])),
        report.wrapper_sha256,
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&text[report.core_offset..core_end])),
        report.core_sha256,
    );
    candidate
        .authenticate_embedded(
            literal,
            report.core_offset,
            &text[report.core_offset..core_end],
        )
        .expect("authenticate final-offset direct SpanSum Count-v3 core");
    let mut tampered_core = text[report.core_offset..core_end].to_vec();
    tampered_core[0] ^= 1;
    assert!(candidate
        .authenticate_embedded(literal, report.core_offset, &tampered_core)
        .is_err());
    assert_eq!(
        crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
            report.literal_bytes,
            report.wrapper_offset,
            report.core_offset,
            &text[report.wrapper_offset..wrapper_end],
        )
        .expect("authenticate embedded direct SpanSum wrapper"),
        report.wrapper_sha256,
    );
    let mut tampered_wrapper = text[report.wrapper_offset..wrapper_end].to_vec();
    tampered_wrapper[0] ^= 1;
    assert!(
        crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
            report.literal_bytes,
            report.wrapper_offset,
            report.core_offset,
            &tampered_wrapper,
        )
        .is_err(),
    );
    assert!(selected.relocations().iter().all(|relocation| {
        usize::try_from(relocation.offset)
            .map_or(true, |offset| !(report.wrapper_offset..core_end).contains(&offset))
    }));
    assert!(selected.symbols().iter().all(|symbol| {
        symbol.section != Some(text_index)
            || usize::try_from(symbol.offset + symbol.size)
                .is_ok_and(|end| end <= report.wrapper_offset)
    }));
    selected
        .rollback_direct_exact_singleton_span_sum(rollback)
        .expect("restore exact ungated SpanSum incumbent");
    assert_eq!(&selected, incumbent.module());
}

#[test]
fn direct_exact_singleton_count_declines_without_changing_every_ineligible_incumbent() {
    let asimd = direct_count_asimd_target(OperatingSystem::Linux);
    let default_cap = CompileLimitsV1::default().max_object_bytes;
    let cases = [
        ("a|b", asimd, CompileMode::Optimizing, PreparedAggregateExports::COUNT),
        ("a?", asimd, CompileMode::Optimizing, PreparedAggregateExports::COUNT),
        ("^a", asimd, CompileMode::Optimizing, PreparedAggregateExports::COUNT),
        ("", asimd, CompileMode::Optimizing, PreparedAggregateExports::COUNT),
        (
            "a{33}",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::COUNT,
        ),
        (
            "a",
            Target::aarch64_linux(),
            CompileMode::Optimizing,
            PreparedAggregateExports::COUNT,
        ),
        (
            "a",
            Target::x86_64_linux(),
            CompileMode::Optimizing,
            PreparedAggregateExports::COUNT,
        ),
        ("a", asimd, CompileMode::Fast, PreparedAggregateExports::COUNT),
        (
            "a",
            asimd,
            CompileMode::Optimizing,
            PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM),
        ),
    ];
    for (pattern, target, mode, exports) in cases {
        let request = direct_count_request(pattern, target, mode, default_cap);
        let incumbent = compile_count_with_direct_candidate_declined(request.clone(), exports);
        let compiled = compile_with_prepared_aggregate_exports(request, exports)
            .expect("compile ineligible direct Count-v3 case");
        assert_eq!(compiled.object(), incumbent.object(), "pattern {pattern:?}");
        assert_eq!(compiled.module(), incumbent.module(), "pattern {pattern:?}");
        assert!(
            compiled
                .module()
                .direct_exact_singleton_count_aot_report()
                .is_none(),
            "pattern {pattern:?}",
        );
    }
}

#[test]
fn direct_exact_singleton_count_object_cap_decline_is_incumbent_exact_and_allocation_is_terminal() {
    let target = direct_count_asimd_target(OperatingSystem::Linux);
    let default_cap = CompileLimitsV1::default().max_object_bytes;
    let default_request =
        direct_count_request("abcdefgh", target, CompileMode::Optimizing, default_cap);
    let incumbent = compile_count_with_direct_candidate_declined(
        default_request.clone(),
        PreparedAggregateExports::COUNT,
    );
    let selected = compile_with_prepared_aggregate_exports(
        default_request,
        PreparedAggregateExports::COUNT,
    )
    .expect("compile selected direct Count-v3 control");
    assert!(selected.object().len() > incumbent.object().len());
    assert!(
        selected
            .module()
            .direct_exact_singleton_count_aot_report()
            .is_some(),
    );
    let exact_selected = compile_with_prepared_aggregate_exports(
        direct_count_request(
            "abcdefgh",
            target,
            CompileMode::Optimizing,
            selected.object().len(),
        ),
        PreparedAggregateExports::COUNT,
    )
    .expect("exact selected direct Count-v3 object cap");
    assert_eq!(exact_selected.object(), selected.object());

    let candidate_cap = selected.object().len() - 1;
    assert!(candidate_cap >= incumbent.object().len());
    let capped_request = direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        candidate_cap,
    );
    let capped_incumbent = compile_count_with_direct_candidate_declined(
        capped_request.clone(),
        PreparedAggregateExports::COUNT,
    );
    let capped_literal = capped_incumbent
        .program()
        .native_exact_singleton_count_literal()
        .expect("capped incumbent exact-singleton witness");
    assert!(matches!(
        crate::direct_count_v3::prepare_direct_exact_singleton_count(
            capped_literal,
            capped_incumbent.program().artifact_identity(),
            target,
            candidate_cap,
        )
        .expect("prepare candidate below its completed module cap"),
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(_),
    ));
    let capped = compile_with_prepared_aggregate_exports(
        capped_request,
        PreparedAggregateExports::COUNT,
    )
    .expect("final direct Count-v3 object cap declines to incumbent");
    assert_eq!(capped.object(), capped_incumbent.object());
    assert_eq!(capped.module(), capped_incumbent.module());
    assert!(
        capped
            .module()
            .direct_exact_singleton_count_aot_report()
            .is_none(),
    );

    let gated_request =
        direct_count_request("aa", target, CompileMode::Optimizing, default_cap);
    let gated_incumbent = compile_count_with_direct_candidate_declined(
        gated_request.clone(),
        PreparedAggregateExports::COUNT,
    );
    let gated_selected = compile_with_prepared_aggregate_exports(
        gated_request,
        PreparedAggregateExports::COUNT,
    )
    .expect("compile selected short-gated Count-v3 control");
    assert!(gated_selected
        .module()
        .direct_exact_singleton_count_aot_report()
        .is_some_and(|report| report.short_fallback_max_bytes.is_some()));
    let gated_cap = gated_selected.object().len() - 1;
    assert!(gated_cap >= gated_incumbent.object().len());
    let capped_gated_request =
        direct_count_request("aa", target, CompileMode::Optimizing, gated_cap);
    let capped_gated_incumbent = compile_count_with_direct_candidate_declined(
        capped_gated_request.clone(),
        PreparedAggregateExports::COUNT,
    );
    let capped_gated = compile_with_prepared_aggregate_exports(
        capped_gated_request,
        PreparedAggregateExports::COUNT,
    )
    .expect("short-gated Count-v3 object cap declines to incumbent");
    assert_eq!(capped_gated.object(), capped_gated_incumbent.object());
    assert_eq!(capped_gated.module(), capped_gated_incumbent.module());
    assert!(capped_gated
        .module()
        .direct_exact_singleton_count_aot_report()
        .is_none());

    let low_cap = incumbent.object().len() - 1;
    let low_request =
        direct_count_request("abcdefgh", target, CompileMode::Optimizing, low_cap);
    let low_error = compile_with_prepared_aggregate_exports(
        low_request,
        PreparedAggregateExports::COUNT,
    )
    .expect_err("incumbent object cap remains terminal");
    assert!(matches!(
        low_error,
        CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) if limit == low_cap && required == incumbent.object().len()
    ));

    let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
        crate::direct_count_v3::DirectExactSingletonCountTestPreparation::AllocationFailure,
    );
    let allocation_error = compile_with_prepared_aggregate_exports(
        direct_count_request("abcdefgh", target, CompileMode::Optimizing, default_cap),
        PreparedAggregateExports::COUNT,
    )
    .expect_err("candidate allocation failure must remain terminal");
    assert!(matches!(
        allocation_error,
        CompileError::Object(ObjectError::Allocation(
            "injected direct Count-v3 candidate"
        ))
    ));
}

#[test]
fn direct_count_final_object_decline_requires_a_proven_numeric_cap() {
    assert!(crate::is_proven_object_byte_limit(&ObjectError::Resource {
        resource: CompileResource::ObjectBytes,
        limit: 4095,
        required: 4096,
    }));
    assert!(!crate::is_proven_object_byte_limit(&ObjectError::Resource {
        resource: CompileResource::ObjectBytes,
        limit: 4096,
        required: 4096,
    }));
    assert!(!crate::is_proven_object_byte_limit(&ObjectError::Allocation(
        "object output bytes",
    )));
}

#[test]
fn direct_exact_singleton_count_backend_unsupported_is_terminal() {
    let target = direct_count_asimd_target(OperatingSystem::Linux);
    let request = direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        CompileLimitsV1::default().max_object_bytes,
    );
    let incumbent = compile_count_with_direct_candidate_declined(
        request.clone(),
        PreparedAggregateExports::COUNT,
    );
    assert!(!incumbent.object().is_empty());
    assert!(
        incumbent
            .module()
            .direct_exact_singleton_count_aot_report()
            .is_none(),
    );

    let _guard = crate::direct_count_v3::test_direct_exact_singleton_count_preparation(
        crate::direct_count_v3::DirectExactSingletonCountTestPreparation::UnsupportedBackendFailure,
    );
    let error = compile_with_prepared_aggregate_exports(
        request,
        PreparedAggregateExports::COUNT,
    )
    .expect_err("backend contract failure must not return the incumbent");
    assert!(matches!(
        error,
        CompileError::Object(ObjectError::InvalidModule(
            "direct Count-v3 backend rejected authenticated target tuple"
        ))
    ));
}

#[test]
fn direct_exact_singleton_count_authenticates_incumbent_core_and_symbol_surface() {
    let target = direct_count_asimd_target(OperatingSystem::Macos);
    let request = direct_count_request(
        "abcdefgh",
        target,
        CompileMode::Optimizing,
        CompileLimitsV1::default().max_object_bytes,
    );
    let incumbent = compile_count_with_direct_candidate_declined(
        request,
        PreparedAggregateExports::COUNT,
    );
    let literal = incumbent
        .program()
        .native_exact_singleton_count_literal()
        .expect("authenticated singleton witness");
    let artifact_identity = incumbent.program().artifact_identity();
    let mut candidate = match crate::direct_count_v3::prepare_direct_exact_singleton_count(
        literal,
        artifact_identity,
        target,
        CompileLimitsV1::default().max_object_bytes,
    )
    .expect("prepare audited direct Count-v3 core") {
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(candidate) => {
            candidate
        }
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Declined => {
            panic!("supported direct Count-v3 core declined")
        }
    };
    candidate
        .authenticate_embedded(literal, 0, &candidate.code)
        .expect("authenticate untouched direct Count-v3 core");
    assert!(
        candidate
            .authenticate_embedded(literal, 4, &candidate.code)
            .is_err(),
        "a byte-identical core at a merely instruction-aligned offset must fail",
    );
    let mut tampered_core = candidate.code.to_vec();
    tampered_core[0] ^= 1;
    assert!(
        candidate
            .authenticate_embedded(literal, 0, &tampered_core)
            .is_err(),
    );

    let canonical_strategy = candidate.canonical_recipe[13];
    candidate.canonical_recipe[13] = if canonical_strategy == 1 { 2 } else { 1 };
    let mut tampered_recipe_strategy = incumbent.module().clone();
    assert!(tampered_recipe_strategy
        .install_direct_exact_singleton_count(literal, artifact_identity, &candidate)
        .is_err());
    candidate.canonical_recipe[13] = canonical_strategy;

    candidate.recipe_identity[0] ^= 1;
    let mut tampered_recipe_identity = incumbent.module().clone();
    assert!(tampered_recipe_identity
        .install_direct_exact_singleton_count(literal, artifact_identity, &candidate)
        .is_err());
    candidate.recipe_identity[0] ^= 1;

    let mut wrong_identity = incumbent.module().clone();
    assert!(wrong_identity
        .install_direct_exact_singleton_count(literal, [7; 32], &candidate)
        .is_err());

    let wrong_candidate = match crate::direct_count_v3::prepare_direct_exact_singleton_count(
        literal,
        [7; 32],
        target,
        CompileLimitsV1::default().max_object_bytes,
    )
    .expect("prepare differently bound direct Count-v3 core") {
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(candidate) => {
            candidate
        }
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Declined => {
            panic!("supported differently bound direct Count-v3 core declined")
        }
    };
    let mut wrong_candidate_binding = incumbent.module().clone();
    assert!(wrong_candidate_binding
        .install_direct_exact_singleton_count(literal, artifact_identity, &wrong_candidate)
        .is_err());

    let mut tampered_incumbent = incumbent.module().clone();
    let count = tampered_incumbent
        .symbols()
        .iter()
        .find(|symbol| {
            symbol.binding == crate::SymbolBinding::Global
                && symbol.kind == crate::SymbolKind::Function
                && symbol.name.starts_with("fre_aot_regex_count_exclusive_v1_")
        })
        .expect("incumbent Count symbol");
    let tamper_offset = usize::try_from(count.offset + count.size - 1)
        .expect("incumbent Count tamper offset");
    assert!(tampered_incumbent.test_flip_text_byte(tamper_offset));
    assert!(tampered_incumbent
        .install_direct_exact_singleton_count(literal, artifact_identity, &candidate)
        .is_err());

    let mut selected = incumbent.module().clone();
    assert!(selected
        .install_direct_exact_singleton_count(literal, artifact_identity, &candidate)
        .expect("install authenticated direct Count-v3 core")
        .is_some());
    let report = *selected
        .direct_exact_singleton_count_aot_report()
        .expect("selected direct Count-v3 report");
    let text_index = selected
        .sections()
        .iter()
        .position(|section| section.kind == SectionKind::Text)
        .expect("selected text section index");
    let text = &selected.sections()[text_index];
    let core_end = report.core_offset + report.core_bytes;
    assert_eq!(
        report.core_alignment_bytes,
        crate::direct_count_v3::DIRECT_EXACT_SINGLETON_COUNT_CORE_ALIGNMENT_BYTES,
    );
    assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&text.bytes()[report.core_offset..core_end])),
        report.core_sha256,
    );
    assert!(selected.relocations().iter().all(|relocation| {
        usize::try_from(relocation.offset)
            .map_or(true, |offset| !(report.core_offset..core_end).contains(&offset))
    }));
    assert!(selected.symbols().iter().all(|symbol| {
        symbol.section != Some(text_index)
            || usize::try_from(symbol.offset + symbol.size)
                .is_ok_and(|end| end <= report.core_offset)
    }));
    assert!(selected.symbols().iter().all(|symbol| {
        !symbol.name.contains("fre_aot_count") && symbol.section.is_some()
    }));
}

#[test]
fn direct_exact_singleton_count_short_gate_preserves_the_hot_incumbent_layout() {
    fn signed_target(instruction_offset: usize, immediate: u32, bits: u32) -> usize {
        let shift = 64 - bits;
        let words = ((u64::from(immediate) << shift) as i64) >> shift;
        usize::try_from(
            i64::try_from(instruction_offset).expect("instruction offset fits i64")
                + words * 4,
        )
        .expect("local branch target is nonnegative")
    }

    let target = direct_count_asimd_target(OperatingSystem::Linux);
    let request = direct_count_request(
        "aa",
        target,
        CompileMode::Optimizing,
        CompileLimitsV1::default().max_object_bytes,
    );
    let incumbent = compile_count_with_direct_candidate_declined(
        request.clone(),
        PreparedAggregateExports::COUNT,
    );
    let selected = compile_with_prepared_aggregate_exports(
        request,
        PreparedAggregateExports::COUNT,
    )
    .expect("compile cold-long direct Count-v3");
    let report = selected
        .module()
        .direct_exact_singleton_count_aot_report()
        .expect("cold-long direct Count-v3 report");
    let short_max = report
        .short_fallback_max_bytes
        .expect("periodic width-two short fallback");
    assert_eq!(
        short_max,
        crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES,
    );
    assert_eq!(report.copied_incumbent_body_offset, None);
    assert_eq!(report.copied_incumbent_body_bytes, None);
    let cold_offset = report.cold_long_offset.expect("cold-long offset");
    let cold_bytes = report.cold_long_bytes.expect("cold-long bytes");

    let selected_text = selected
        .module()
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .expect("selected text")
        .bytes();
    let incumbent_text = incumbent
        .module()
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .expect("incumbent text")
        .bytes();
    assert_eq!(cold_offset, incumbent_text.len());
    assert_eq!(cold_offset + cold_bytes, report.core_offset);
    assert_eq!(
        report.core_alignment_bytes,
        crate::direct_count_v3::DIRECT_EXACT_SINGLETON_COUNT_CORE_ALIGNMENT_BYTES,
    );
    assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));
    assert_eq!(
        &selected_text[report.authenticated_wrapper_body_offset..cold_offset],
        &incumbent_text[report.authenticated_wrapper_body_offset..],
        "the established authenticated body must stay byte-for-byte in place",
    );

    let differences = selected_text[..cold_offset]
        .chunks_exact(4)
        .zip(incumbent_text.chunks_exact(4))
        .enumerate()
        .filter_map(|(index, (selected, incumbent))| {
            (selected != incumbent).then_some((index * 4, selected, incumbent))
        })
        .collect::<Vec<_>>();
    assert_eq!(differences.len(), 2, "only the signed-length pair changes");
    assert_eq!(differences[1].0, differences[0].0 + 4);
    let branch_offset = differences[1].0;
    let incumbent_compare =
        u32::from_le_bytes(differences[0].2.try_into().expect("incumbent compare"));
    let incumbent_branch =
        u32::from_le_bytes(differences[1].2.try_into().expect("incumbent branch"));
    assert_eq!(incumbent_compare, 0xf100_001f | (2 << 5));
    assert_eq!(incumbent_branch & 0xff00_001f, 0x5400_0004);

    let selected_compare =
        u32::from_le_bytes(differences[0].1.try_into().expect("selected compare"));
    let selected_branch =
        u32::from_le_bytes(differences[1].1.try_into().expect("selected branch"));
    let direct_min = short_max.checked_add(1).expect("short threshold successor");
    assert!(direct_min.is_multiple_of(1 << 12));
    assert_eq!(
        selected_compare,
        0xf140_001f | ((direct_min >> 12) << 10) | (2 << 5),
    );
    assert_eq!(selected_branch & 0xff00_001f, 0x5400_0002);
    assert_eq!(
        signed_target(branch_offset, (selected_branch >> 5) & 0x7ffff, 19),
        cold_offset,
    );

    let cold_words = selected_text[cold_offset..report.core_offset]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("cold instruction")))
        .collect::<Vec<_>>();
    assert_eq!(
        cold_words[0] & 0xfff8_001f,
        0xb7f8_0002,
        "cold path must reject bit-63 lengths first",
    );
    let direct_windows = cold_words
        .windows(4)
        .enumerate()
        .filter(|(_, words)| {
            words[0] == 0xaa01_03e0
                && words[1] == 0xaa02_03e1
                && words[2] == 0xaa03_03e2
                && words[3] & 0xfc00_0000 == 0x1400_0000
        })
        .collect::<Vec<_>>();
    assert_eq!(direct_windows.len(), 1, "one audited direct tail exists");
    let (direct_index, direct_words) = direct_windows[0];
    let direct_branch_offset = cold_offset + (direct_index + 3) * 4;
    assert_eq!(
        signed_target(
            direct_branch_offset,
            direct_words[3] & 0x03ff_ffff,
            26,
        ),
        report.core_offset,
    );

    let incumbent_relocations = incumbent.module().relocations();
    let selected_relocations = selected.module().relocations();
    assert_eq!(selected_relocations.len(), incumbent_relocations.len() + 2);
    assert_eq!(
        &selected_relocations[..incumbent_relocations.len()],
        incumbent_relocations,
    );
    let mut identity_symbols = selected
        .module()
        .symbols()
        .iter()
        .enumerate()
        .filter(|(_, symbol)| symbol.name == ".Lfre_aot_regex_prepared_aggregate_identity")
        .map(|(index, _)| index);
    let identity_symbol = identity_symbols
        .next()
        .expect("unique prepared aggregate identity symbol");
    assert!(identity_symbols.next().is_none());
    for (relocation, kind) in selected_relocations[incumbent_relocations.len()..]
        .iter()
        .zip([
            crate::RelocationKind::Aarch64Page21,
            crate::RelocationKind::Aarch64PageOff12,
        ])
    {
        assert_eq!(relocation.section, incumbent_relocations[0].section);
        assert_eq!(relocation.kind, kind);
        assert_eq!(relocation.symbol, identity_symbol);
        assert_eq!(relocation.addend, 0);
        assert!((cold_offset..report.core_offset).contains(
            &usize::try_from(relocation.offset).expect("cold relocation offset"),
        ));
    }

    let selected_count_name = selected
        .module()
        .prepared_count_symbol()
        .expect("selected Count symbol");
    let selected_count = selected
        .module()
        .symbols()
        .iter()
        .find(|symbol| symbol.name == selected_count_name)
        .expect("selected Count symbol record");
    let incumbent_count_name = incumbent
        .module()
        .prepared_count_symbol()
        .expect("incumbent Count symbol");
    let incumbent_count = incumbent
        .module()
        .symbols()
        .iter()
        .find(|symbol| symbol.name == incumbent_count_name)
        .expect("incumbent Count symbol record");
    assert_eq!(selected_count.offset, incumbent_count.offset);
    assert_eq!(
        selected_count.size,
        incumbent_count.size + u64::try_from(cold_bytes).expect("cold size"),
    );
    assert_eq!(
        usize::try_from(selected_count.offset + selected_count.size)
            .expect("selected Count extent"),
        report.core_offset,
    );
}

#[test]
fn direct_exact_singleton_span_sum_cold_gate_is_additive_authenticated_and_relocatable() {
    let target = direct_count_asimd_target(OperatingSystem::Linux);
    let request = direct_count_request(
        "aa",
        target,
        CompileMode::Optimizing,
        CompileLimitsV1::default().max_object_bytes,
    );
    let incumbent = compile_span_sum_with_direct_candidate_declined(request.clone());
    let selected = compile_with_prepared_aggregate_exports(
        request,
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("compile cold-long direct SpanSum");
    let report = selected
        .module()
        .direct_exact_singleton_span_sum_aot_report()
        .expect("cold-long direct SpanSum report");
    let cold_offset = report.cold_long_offset.expect("SpanSum cold-long offset");
    let cold_bytes = report.cold_long_bytes.expect("SpanSum cold-long bytes");
    assert_eq!(
        report.short_fallback_max_bytes,
        Some(crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES),
    );
    assert_eq!(cold_offset + cold_bytes, report.wrapper_offset);
    let wrapper_end = report
        .wrapper_offset
        .checked_add(report.wrapper_bytes)
        .expect("cold-gated SpanSum wrapper extent");
    assert_eq!(
        wrapper_end.checked_add(report.wrapper_to_core_padding_bytes),
        Some(report.core_offset),
    );
    assert_eq!(
        report.core_alignment_bytes,
        crate::DIRECT_EXACT_SINGLETON_SPAN_SUM_COUNT_CORE_ALIGNMENT_BYTES,
    );
    assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));

    let selected_text = selected
        .module()
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .expect("selected SpanSum text")
        .bytes();
    let incumbent_text = incumbent
        .module()
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .expect("incumbent SpanSum text")
        .bytes();
    assert_eq!(cold_offset, incumbent_text.len());
    assert_eq!(
        &selected_text[report.authenticated_wrapper_body_offset..cold_offset],
        &incumbent_text[report.authenticated_wrapper_body_offset..],
        "the established authenticated SpanSum body stays byte-for-byte in place",
    );
    let differences = selected_text[..cold_offset]
        .chunks_exact(4)
        .zip(incumbent_text.chunks_exact(4))
        .enumerate()
        .filter_map(|(index, (selected, incumbent))| {
            (selected != incumbent).then_some(index * 4)
        })
        .collect::<Vec<_>>();
    assert_eq!(differences.len(), 2, "only the signed-length pair changes");
    assert_eq!(differences[1], differences[0] + 4);

    let cold_words = selected_text[cold_offset..report.wrapper_offset]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("cold instruction")))
        .collect::<Vec<_>>();
    assert_eq!(
        cold_words[0] & 0xfff8_001f,
        0xb7f8_0002,
        "cold path must reject bit-63 lengths before output/identity",
    );
    let wrapper_branches = cold_words
        .iter()
        .enumerate()
        .filter(|(_, instruction)| **instruction & 0xfc00_0000 == 0x1400_0000)
        .collect::<Vec<_>>();
    assert_eq!(wrapper_branches.len(), 1);
    let (branch_index, branch) = wrapper_branches[0];
    assert_eq!(
        crate::module::aarch64_direct_branch_target(
            cold_offset + branch_index * 4,
            *branch,
        )
        .expect("decode cold SpanSum wrapper branch"),
        Some(report.wrapper_offset),
    );
    assert!(
        selected_text[wrapper_end..report.core_offset]
            .chunks_exact(4)
            .all(|word| word == 0xd503_201f_u32.to_le_bytes()),
    );
    assert_eq!(
        crate::module::authenticate_aarch64_direct_exact_singleton_span_sum_wrapper(
            report.literal_bytes,
            report.wrapper_offset,
            report.core_offset,
            &selected_text[report.wrapper_offset..wrapper_end],
        )
        .expect("authenticate embedded checked SpanSum wrapper"),
        report.wrapper_sha256,
    );
    let wrapper_words = selected_text[report.wrapper_offset..wrapper_end]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("wrapper instruction")))
        .collect::<Vec<_>>();
    assert!(wrapper_words.contains(&(0x9bc0_7c00 | (9 << 16) | (8 << 5) | 10)));
    assert!(wrapper_words.contains(&(0x9b00_7c00 | (9 << 16) | (8 << 5) | 8)));

    let incumbent_relocations = incumbent.module().relocations();
    let selected_relocations = selected.module().relocations();
    assert_eq!(selected_relocations.len(), incumbent_relocations.len() + 2);
    assert_eq!(
        &selected_relocations[..incumbent_relocations.len()],
        incumbent_relocations,
    );
    let mut identity_symbols = selected
        .module()
        .symbols()
        .iter()
        .enumerate()
        .filter(|(_, symbol)| symbol.name == ".Lfre_aot_regex_prepared_aggregate_identity")
        .map(|(index, _)| index);
    let identity_symbol = identity_symbols
        .next()
        .expect("unique prepared aggregate identity symbol");
    assert!(identity_symbols.next().is_none());
    for (relocation, kind) in selected_relocations[incumbent_relocations.len()..]
        .iter()
        .zip([
            crate::RelocationKind::Aarch64Page21,
            crate::RelocationKind::Aarch64PageOff12,
        ])
    {
        assert_eq!(relocation.kind, kind);
        assert_eq!(relocation.symbol, identity_symbol);
        assert_eq!(relocation.addend, 0);
        assert!((cold_offset..report.wrapper_offset).contains(
            &usize::try_from(relocation.offset).expect("cold relocation offset"),
        ));
    }

    let selected_name = selected
        .module()
        .prepared_span_sum_symbol()
        .expect("selected SpanSum symbol");
    let selected_symbol = selected
        .module()
        .symbols()
        .iter()
        .find(|symbol| symbol.name == selected_name)
        .expect("selected SpanSum symbol record");
    let incumbent_name = incumbent
        .module()
        .prepared_span_sum_symbol()
        .expect("incumbent SpanSum symbol");
    let incumbent_symbol = incumbent
        .module()
        .symbols()
        .iter()
        .find(|symbol| symbol.name == incumbent_name)
        .expect("incumbent SpanSum symbol record");
    assert_eq!(selected_symbol.offset, incumbent_symbol.offset);
    assert_eq!(
        selected_symbol.size,
        incumbent_symbol.size
            + u64::try_from(
                cold_bytes + report.wrapper_bytes + report.wrapper_to_core_padding_bytes,
            )
            .expect("selected size delta"),
    );
    assert_eq!(
        usize::try_from(selected_symbol.offset + selected_symbol.size)
            .expect("selected SpanSum extent"),
        report.core_offset,
    );

    let literal = incumbent
        .program()
        .native_exact_singleton_count_literal()
        .expect("authenticated SpanSum singleton witness");
    let artifact_identity = incumbent.program().artifact_identity();
    let candidate = match crate::direct_count_v3::prepare_direct_exact_singleton_count(
        literal,
        artifact_identity,
        target,
        CompileLimitsV1::default().max_object_bytes,
    )
    .expect("prepare direct SpanSum Count-v3 core") {
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Candidate(candidate) => {
            candidate
        }
        crate::direct_count_v3::DirectExactSingletonCountPreparation::Declined => {
            panic!("supported direct SpanSum Count-v3 core declined")
        }
    };
    let mut tampered = incumbent.module().clone();
    let tamper_offset = usize::try_from(incumbent_symbol.offset + incumbent_symbol.size - 1)
        .expect("incumbent SpanSum tamper offset");
    assert!(tampered.test_flip_text_byte(tamper_offset));
    assert!(tampered
        .install_direct_exact_singleton_span_sum(literal, artifact_identity, &candidate)
        .is_err());

    candidate
        .authenticate_embedded(
            literal,
            report.core_offset,
            &selected_text[report.core_offset..report.core_offset + report.core_bytes],
        )
        .expect("authenticate gated final-offset Count-v3 core");
    let mut rollback_module = incumbent.module().clone();
    let rollback = rollback_module
        .install_direct_exact_singleton_span_sum(literal, artifact_identity, &candidate)
        .expect("install gated direct SpanSum for rollback")
        .expect("gated direct SpanSum selected");
    rollback_module
        .rollback_direct_exact_singleton_span_sum(rollback)
        .expect("restore exact gated SpanSum incumbent");
    assert_eq!(&rollback_module, incumbent.module());
}

#[test]
fn direct_count_aarch64_relocation_covers_every_immediate_branch_family() {
    let fixtures = [
        (0x1400_0000_u32, 0x03ff_ffff_u32), // B.
        (0x9400_0000_u32, 0x03ff_ffff_u32), // BL.
        (0x5400_0001_u32, 0x00ff_ffe0_u32), // B.ne.
        (0x3400_0005_u32, 0x00ff_ffe0_u32), // CBZ w5.
        (0xb500_0006_u32, 0x00ff_ffe0_u32), // CBNZ x6.
        (0x3600_0007_u32, 0x0007_ffe0_u32), // TBZ w7.
        (0xb700_0008_u32, 0x0007_ffe0_u32), // TBNZ x8, #63.
    ];
    for (opcode, immediate_mask) in fixtures {
        let forward = crate::module::aarch64_relocate_direct_branch_instruction(
            0x100,
            0x180,
            opcode,
        )
        .expect("encode forward direct branch")
        .expect("forward branch is in range");
        assert_eq!(forward & !immediate_mask, opcode & !immediate_mask);
        assert_eq!(
            crate::module::aarch64_direct_branch_target(0x100, forward)
                .expect("decode forward direct branch"),
            Some(0x180),
        );

        let backward = crate::module::aarch64_relocate_direct_branch_instruction(
            0x280,
            0x180,
            forward,
        )
        .expect("encode backward direct branch")
        .expect("backward branch is in range");
        assert_eq!(backward & !immediate_mask, opcode & !immediate_mask);
        assert_eq!(
            crate::module::aarch64_direct_branch_target(0x280, backward)
                .expect("decode backward direct branch"),
            Some(0x180),
        );
    }
    assert!(
        crate::module::aarch64_relocate_direct_branch_instruction(
            0,
            1_usize << 30,
            0x1400_0000,
        )
        .expect("numeric branch range check")
        .is_none(),
    );
    assert!(crate::module::aarch64_is_pc_relative_address_or_literal(
        0x1000_0000,
    ));
    assert!(crate::module::aarch64_is_pc_relative_address_or_literal(
        0x9000_0000,
    ));
    assert!(crate::module::aarch64_is_pc_relative_address_or_literal(
        0x5800_0000,
    ));
    assert!(!crate::module::aarch64_is_pc_relative_address_or_literal(
        0xaa01_03e0,
    ));
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes all 32 direct exact-singleton SpanSum widths"]
#[allow(
    clippy::too_many_lines,
    reason = "one linked differential authenticates the public SpanSum wrapper, checked composition, Count-v3 core, and non-overlap semantics together"
)]
fn linked_host_direct_exact_singleton_span_sum_matches_generated_nonoverlap_oracle() {
    use std::{fs, process::Command, time::SystemTime};

    fn initializer(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",")
    }

    let operating_system = if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else {
        OperatingSystem::Macos
    };
    let target = direct_count_asimd_target(operating_system);
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-direct-span-sum-singleton-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create direct SpanSum linker directory");
    let mut source = format!(
        "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#define IDENTITY_OFFSET {}U\nstatic const uint8_t empty_hay[1]={{0}};\n",
        crate::FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
    );
    source.push_str(
        "static uint64_t reference_nonoverlap_span_sum_a(const uint8_t *hay,size_t len,size_t width){size_t offset=0U;uint64_t total=0U;while(offset+width<=len){size_t index=0U;while(index<width&&hay[offset+index]=='a')index++;if(index==width){total+=(uint64_t)width;offset+=width;}else{offset++;}}return total;}\n",
    );
    let mut objects = Vec::new();
    for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
        let pattern = format!("(?-u:{})", "\\x61".repeat(width));
        let compiled = compile_with_prepared_aggregate_exports(
            direct_count_request(
                pattern,
                target,
                CompileMode::Optimizing,
                CompileLimitsV1::default().max_object_bytes,
            ),
            PreparedAggregateExports::SPAN_SUM,
        )
        .expect("compile linked direct SpanSum width");
        let report = compiled
            .module()
            .direct_exact_singleton_span_sum_aot_report()
            .expect("linked width selected direct SpanSum");
        assert_eq!(usize::from(report.literal_bytes), width);
        assert_eq!(
            report.core_alignment_bytes,
            crate::DIRECT_EXACT_SINGLETON_SPAN_SUM_COUNT_CORE_ALIGNMENT_BYTES,
        );
        assert!(report.core_offset.is_multiple_of(report.core_alignment_bytes));
        assert!(compiled.module().required_runtime_symbols().next().is_none());
        let entry = compiled
            .module()
            .prepared_span_sum_symbol()
            .expect("linked direct SpanSum symbol");
        let object = directory.join(format!("span-sum-{width}.o"));
        fs::write(&object, compiled.object()).expect("write direct SpanSum object");
        objects.push(object);

        let identity = initializer(&compiled.program().artifact_identity());
        let negative = initializer(&vec![b'b'; width.saturating_mul(2).max(1)]);
        let mut early = vec![b'a'; width];
        early.push(b'b');
        let mut late = vec![b'b'; 7];
        late.extend(std::iter::repeat_n(b'a', width));
        let dense = vec![b'a'; width * 4 - 1];
        let overlap = vec![b'a'; width + 3];
        let early_initializer = initializer(&early);
        let late_initializer = initializer(&late);
        let dense_initializer = initializer(&dense);
        let overlap_initializer = initializer(&overlap);
        let overlap_sum = ((width + 3) / width) * width;
        write!(
            &mut source,
            r#"
extern uint32_t {entry}(void *,const uint8_t *,size_t,uint64_t *);
static const uint8_t identity_{width}[32]={{{identity}}};
static const uint8_t negative_{width}[]={{{negative}}};
static const uint8_t early_{width}[]={{{early_initializer}}};
static const uint8_t late_{width}[]={{{late_initializer}}};
static const uint8_t dense_{width}[]={{{dense_initializer}}};
static const uint8_t overlap_{width}[]={{{overlap_initializer}}};
static int check_span_sum_{width}(void){{
  uint8_t handle[IDENTITY_OFFSET+32U];
  uint8_t wrong[IDENTITY_OFFSET+32U];
  uint8_t misaligned[16];
  uint64_t out=99U;
  memset(handle,0,sizeof(handle));memset(wrong,0,sizeof(wrong));
  memcpy(handle+IDENTITY_OFFSET,identity_{width},32U);
  if({entry}(handle,empty_hay,0U,&out)!=0U||out!=0U)return 1;
  out=99U;if({entry}(handle,negative_{width},sizeof(negative_{width}),&out)!=0U||out!=0U)return 2;
  out=99U;if({entry}(handle,early_{width},sizeof(early_{width}),&out)!=0U||out!={width}U)return 3;
  out=99U;if({entry}(handle,late_{width},sizeof(late_{width}),&out)!=0U||out!={width}U)return 4;
  out=99U;if({entry}(handle,dense_{width},sizeof(dense_{width}),&out)!=0U||out!=3U*{width}U)return 5;
  out=99U;if({entry}(handle,overlap_{width},sizeof(overlap_{width}),&out)!=0U||out!={overlap_sum}U)return 6;
  if({width}U==1U){{
    out=99U;if({entry}(0,early_{width},sizeof(early_{width}),&out)!=5U||out!=99U)return 7;
    out=99U;if({entry}(wrong,early_{width},sizeof(early_{width}),&out)!=3U||out!=99U)return 8;
    out=99U;if({entry}(handle,0,sizeof(early_{width}),&out)!=2U||out!=99U)return 9;
    out=99U;if({entry}(handle,early_{width},(size_t)-1,&out)!=2U||out!=99U)return 10;
    if({entry}(handle,early_{width},sizeof(early_{width}),0)!=2U)return 11;
    if({entry}(handle,early_{width},sizeof(early_{width}),(uint64_t *)(void *)(misaligned+1))!=2U)return 12;
  }}
  uint8_t exhaustive[10];
  for(size_t exhaustive_len=0U;exhaustive_len<=sizeof(exhaustive);exhaustive_len++){{
    uint32_t combinations=1U<<(uint32_t)exhaustive_len;
    for(uint32_t mask=0U;mask<combinations;mask++){{
      for(size_t index=0U;index<exhaustive_len;index++)exhaustive[index]=((mask>>index)&1U)!=0U?'a':'b';
      uint64_t expected=reference_nonoverlap_span_sum_a(exhaustive,exhaustive_len,{width}U);
      out=99U;
      if({entry}(handle,exhaustive,exhaustive_len,&out)!=0U||out!=expected)return 13;
    }}
  }}
  return 0;
}}
"#,
        )
        .expect("write direct SpanSum C fixture");
    }
    source.push_str("int main(void){\n");
    for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
        write!(
            &mut source,
            "int status_{width}=check_span_sum_{width}();if(status_{width}!=0)return {width}*100+status_{width};\n",
        )
        .expect("write direct SpanSum C main");
    }
    source.push_str("return 0;}\n");
    let c_path = directory.join("direct-span-sum.c");
    let executable = directory.join("direct-span-sum");
    fs::write(&c_path, source).expect("write direct SpanSum C source");
    let mut linker = Command::new(if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    });
    linker.arg("-O2").arg(&c_path);
    linker.args(&objects).arg("-o").arg(&executable);
    let status = linker.status().expect("link direct SpanSum differential");
    assert!(status.success(), "direct SpanSum differential failed to link");
    let result = Command::new(&executable)
        .output()
        .expect("run direct SpanSum differential");
    assert!(
        result.status.success(),
        "direct SpanSum differential status={:?}, stdout={}, stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
    fs::remove_dir_all(directory).expect("remove direct SpanSum linker directory");
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes both direct SpanSum cold-gate routes"]
fn linked_host_direct_exact_singleton_span_sum_cold_gate_matches_oracle() {
    use std::{fs, process::Command, time::SystemTime};

    fn initializer(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",")
    }

    let operating_system = if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else {
        OperatingSystem::Macos
    };
    let target = direct_count_asimd_target(operating_system);
    let compiled = compile_with_prepared_aggregate_exports(
        direct_count_request(
            "(?-u:\\x61\\x61)",
            target,
            CompileMode::Optimizing,
            CompileLimitsV1::default().max_object_bytes,
        ),
        PreparedAggregateExports::SPAN_SUM,
    )
    .expect("compile linked cold-gate direct SpanSum");
    let report = compiled
        .module()
        .direct_exact_singleton_span_sum_aot_report()
        .expect("linked cold-gate direct SpanSum selected");
    let short_max = report
        .short_fallback_max_bytes
        .expect("linked SpanSum short threshold");
    assert_eq!(
        short_max,
        crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES,
    );
    assert!(compiled.module().required_runtime_symbols().next().is_none());
    let entry = compiled
        .module()
        .prepared_span_sum_symbol()
        .expect("linked direct SpanSum symbol");

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-direct-span-sum-cold-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create direct SpanSum linker directory");
    let object = directory.join("span-sum.o");
    fs::write(&object, compiled.object()).expect("write direct SpanSum object");
    let identity = initializer(&compiled.program().artifact_identity());
    let source = format!(
        r#"#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define IDENTITY_OFFSET {identity_offset}U
#define SHORT_MAX {short_max}U
extern uint32_t {entry}(void *,const uint8_t *,size_t,uint64_t *);
static const uint8_t identity[32]={{{identity}}};
static uint64_t reference_span_sum(const uint8_t *hay,size_t len){{
  size_t offset=0U;uint64_t total=0U;
  while(offset+2U<=len){{
    if(hay[offset]=='a'&&hay[offset+1U]=='a'){{total+=2U;offset+=2U;}}
    else offset++;
  }}
  return total;
}}
int main(void){{
  uint8_t handle[IDENTITY_OFFSET+32U];
  uint8_t wrong[IDENTITY_OFFSET+32U];
  uint8_t misaligned[16];
  static uint8_t hay[SHORT_MAX+3U];
  memset(handle,0,sizeof(handle));memset(wrong,0,sizeof(wrong));
  memcpy(handle+IDENTITY_OFFSET,identity,32U);
  for(size_t index=0U;index<sizeof(hay);index++)hay[index]=(index%7U)==3U?'b':'a';
  const size_t lengths[6]={{0U,1U,2U,SHORT_MAX,SHORT_MAX+1U,SHORT_MAX+2U}};
  for(size_t index=0U;index<6U;index++){{
    uint64_t out=UINT64_C(0x1122334455667788);
    uint64_t expected=reference_span_sum(hay,lengths[index]);
    if({entry}(handle,hay,lengths[index],&out)!=0U||out!=expected)return 1;
  }}
  uint64_t out=UINT64_C(0x1122334455667788);
  if({entry}(wrong,hay,SHORT_MAX,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 2;
  out=UINT64_C(0x1122334455667788);
  if({entry}(wrong,hay,SHORT_MAX+1U,&out)!=3U||out!=UINT64_C(0x1122334455667788))return 3;
  out=UINT64_C(0x1122334455667788);
  if({entry}(0,hay,SHORT_MAX+1U,&out)!=5U||out!=UINT64_C(0x1122334455667788))return 4;
  if({entry}(handle,hay,SHORT_MAX+1U,0)!=2U)return 5;
  if({entry}(handle,hay,SHORT_MAX+1U,(uint64_t *)(void *)(misaligned+1))!=2U)return 6;
  const size_t invalid[3]={{SIZE_MAX,((size_t)UINT64_C(1))<<63,((((size_t)UINT64_C(1))<<63)+SHORT_MAX)}};
  for(size_t index=0U;index<3U;index++){{
    out=UINT64_C(0x1122334455667788);
    if({entry}(wrong,hay,invalid[index],&out)!=2U||out!=UINT64_C(0x1122334455667788))return 7;
    if({entry}(handle,hay,invalid[index],0)!=2U)return 8;
  }}
  return 0;
}}
"#,
        identity_offset = crate::FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
    );
    let c_path = directory.join("direct-span-sum.c");
    let executable = directory.join("direct-span-sum");
    fs::write(&c_path, source).expect("write direct SpanSum C source");
    let mut linker = Command::new(if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    });
    let status = linker
        .arg("-O2")
        .arg(&c_path)
        .arg(&object)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("link direct SpanSum differential");
    assert!(status.success(), "direct SpanSum differential failed to link");
    let result = Command::new(&executable)
        .output()
        .expect("run direct SpanSum differential");
    assert!(
        result.status.success(),
        "direct SpanSum differential status={:?}, stdout={}, stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
    fs::remove_dir_all(directory).expect("remove direct SpanSum linker directory");
}


#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes all 32 direct exact-singleton Count widths"]
#[allow(
    clippy::too_many_lines,
    reason = "one linked differential authenticates the public wrapper, Count-v3 core, and non-overlap semantics together"
)]
fn linked_host_direct_exact_singleton_count_matches_generated_nonoverlap_oracle() {
    use std::{fs, process::Command, time::SystemTime};

    fn initializer(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",")
    }

    let operating_system = if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else {
        OperatingSystem::Macos
    };
    let target = direct_count_asimd_target(operating_system);
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-direct-count-singleton-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create direct Count linker directory");
    let mut source = format!(
        "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#define IDENTITY_OFFSET {}U\nstatic const uint8_t empty_hay[1]={{0}};\n",
        crate::FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
    );
    source.push_str(
        "static uint64_t reference_nonoverlap_a(const uint8_t *hay,size_t len,size_t width){size_t offset=0U;uint64_t count=0U;while(offset+width<=len){size_t index=0U;while(index<width&&hay[offset+index]=='a')index++;if(index==width){count++;offset+=width;}else{offset++;}}return count;}\n",
    );
    let mut objects = Vec::new();
    for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
        let pattern = format!("(?-u:{})", "\\x61".repeat(width));
        let compiled = compile_with_prepared_aggregate_exports(
            direct_count_request(
                pattern,
                target,
                CompileMode::Optimizing,
                CompileLimitsV1::default().max_object_bytes,
            ),
            PreparedAggregateExports::COUNT,
        )
        .expect("compile linked direct Count-v3 width");
        let report = compiled
            .module()
            .direct_exact_singleton_count_aot_report()
            .expect("linked width selected direct Count-v3");
        assert_eq!(usize::from(report.literal_bytes), width);
        assert!(compiled.module().required_runtime_symbols().next().is_none());
        let entry = compiled
            .module()
            .prepared_count_symbol()
            .expect("linked direct Count-v3 symbol");
        let object = directory.join(format!("count-{width}.o"));
        fs::write(&object, compiled.object()).expect("write direct Count-v3 object");
        objects.push(object);

        let identity = initializer(&compiled.program().artifact_identity());
        let negative = initializer(&vec![b'b'; width.saturating_mul(2).max(1)]);
        let mut early = vec![b'a'; width];
        early.push(b'b');
        let mut late = vec![b'b'; 7];
        late.extend(std::iter::repeat_n(b'a', width));
        let dense = vec![b'a'; width * 4 - 1];
        let overlap = vec![b'a'; width + 3];
        let early_initializer = initializer(&early);
        let late_initializer = initializer(&late);
        let dense_initializer = initializer(&dense);
        let overlap_initializer = initializer(&overlap);
        let overlap_count = (width + 3) / width;
        let short_max = crate::DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES;
        let boundary_bytes = short_max + 2;
        write!(
            &mut source,
            r#"
extern uint32_t {entry}(void *,const uint8_t *,size_t,uint64_t *);
static const uint8_t identity_{width}[32]={{{identity}}};
static const uint8_t negative_{width}[]={{{negative}}};
static const uint8_t early_{width}[]={{{early_initializer}}};
static const uint8_t late_{width}[]={{{late_initializer}}};
static const uint8_t dense_{width}[]={{{dense_initializer}}};
static const uint8_t overlap_{width}[]={{{overlap_initializer}}};
static int check_{width}(void){{
  uint8_t handle[IDENTITY_OFFSET+32U];
  uint8_t wrong[IDENTITY_OFFSET+32U];
  uint8_t misaligned[16];
  uint64_t out=99U;
  memset(handle,0,sizeof(handle));memset(wrong,0,sizeof(wrong));
  memcpy(handle+IDENTITY_OFFSET,identity_{width},32U);
  if({entry}(handle,empty_hay,0U,&out)!=0U||out!=0U)return 1;
  out=99U;if({entry}(handle,negative_{width},sizeof(negative_{width}),&out)!=0U||out!=0U)return 2;
  out=99U;if({entry}(handle,early_{width},sizeof(early_{width}),&out)!=0U||out!=1U)return 3;
  out=99U;if({entry}(handle,late_{width},sizeof(late_{width}),&out)!=0U||out!=1U)return 4;
  out=99U;if({entry}(handle,dense_{width},sizeof(dense_{width}),&out)!=0U||out!=3U)return 5;
  out=99U;if({entry}(handle,overlap_{width},sizeof(overlap_{width}),&out)!=0U||out!={overlap_count}U)return 6;
  if({width}U==1U||{width}U==2U||{width}U==4U){{
    out=99U;if({entry}(0,early_{width},sizeof(early_{width}),&out)!=5U||out!=99U)return 7;
    out=99U;if({entry}(wrong,early_{width},sizeof(early_{width}),&out)!=3U||out!=99U)return 8;
    out=99U;if({entry}(handle,0,sizeof(early_{width}),&out)!=2U||out!=99U)return 9;
    out=99U;if({entry}(handle,early_{width},(size_t)-1,&out)!=2U||out!=99U)return 10;
    if({entry}(handle,early_{width},sizeof(early_{width}),0)!=2U)return 11;
    if({entry}(handle,early_{width},sizeof(early_{width}),(uint64_t *)(void *)(misaligned+1))!=2U)return 12;
    const size_t invalid_lengths[3]={{SIZE_MAX,((size_t)UINT64_C(1))<<63,((((size_t)UINT64_C(1))<<63)+8191U)}};
    for(size_t invalid_index=0U;invalid_index<3U;invalid_index++){{
      out=99U;
      if({entry}(handle,early_{width},invalid_lengths[invalid_index],&out)!=2U||out!=99U)return 15;
      out=99U;
      if({entry}(wrong,early_{width},invalid_lengths[invalid_index],&out)!=2U||out!=99U)return 19;
    }}
  }}
  uint8_t exhaustive[10];
  for(size_t exhaustive_len=0U;exhaustive_len<=sizeof(exhaustive);exhaustive_len++){{
    uint32_t combinations=1U<<(uint32_t)exhaustive_len;
    for(uint32_t mask=0U;mask<combinations;mask++){{
      for(size_t index=0U;index<exhaustive_len;index++)exhaustive[index]=((mask>>index)&1U)!=0U?'a':'b';
      uint64_t expected=reference_nonoverlap_a(exhaustive,exhaustive_len,{width}U);
      out=99U;
      if({entry}(handle,exhaustive,exhaustive_len,&out)!=0U||out!=expected)return 13;
    }}
  }}
  uint8_t boundary[{boundary_bytes}U];
  for(size_t index=0U;index<sizeof(boundary);index++)boundary[index]=(index%7U)==3U?'b':'a';
  const size_t boundary_lengths[3]={{{short_max}U,{short_max}U+1U,{short_max}U+2U}};
  for(size_t index=0U;index<3U;index++){{
    size_t boundary_len=boundary_lengths[index];
    uint64_t expected=reference_nonoverlap_a(boundary,boundary_len,{width}U);
    out=99U;
    if({entry}(handle,boundary,boundary_len,&out)!=0U||out!=expected)return 14;
  }}
  if({width}U==2U||{width}U==4U){{
    out=99U;if({entry}(wrong,boundary,{short_max}U+1U,&out)!=3U||out!=99U)return 16;
    if({entry}(handle,boundary,{short_max}U+1U,0)!=2U)return 17;
    if({entry}(handle,boundary,{short_max}U+1U,(uint64_t *)(void *)(misaligned+1))!=2U)return 18;
  }}
  return 0;
}}
"#,
        )
        .expect("write direct Count-v3 C fixture");
    }
    source.push_str("int main(void){\n");
    for width in 1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES {
        write!(
            &mut source,
            "int status_{width}=check_{width}();if(status_{width}!=0)return {width}*100+status_{width};\n",
        )
        .expect("write direct Count-v3 C main");
    }
    source.push_str("return 0;}\n");
    let c_path = directory.join("direct-count.c");
    let executable = directory.join("direct-count");
    fs::write(&c_path, source).expect("write direct Count-v3 C source");
    let mut linker = Command::new(if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    });
    linker.arg("-O2").arg(&c_path);
    linker.args(&objects).arg("-o").arg(&executable);
    let status = linker.status().expect("link direct Count-v3 differential");
    assert!(status.success(), "direct Count-v3 differential failed to link");
    let result = Command::new(&executable)
        .output()
        .expect("run direct Count-v3 differential");
    assert!(
        result.status.success(),
        "direct Count-v3 differential status={:?}, stdout={}, stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
    fs::remove_dir_all(directory).expect("remove direct Count-v3 linker directory");
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes focused PeriodicRun staged wide paths"]
#[allow(
    clippy::too_many_lines,
    reason = "one linked fixture keeps all staged wide outcomes beside its independent non-overlap oracle"
)]
fn linked_host_direct_exact_singleton_count_periodic_wide_stage_matches_independent_oracle() {
    use std::{fs, process::Command, time::SystemTime};

    fn initializer(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte}U"))
            .collect::<Vec<_>>()
            .join(",")
    }

    let literal = b"aeaeaeaeae";
    let kernel = fre_kernel_ir::build_exact_aggregate::<fre_kernel_ir::Count>(
        literal,
        fre_kernel_ir::ValidateLimits::default(),
    )
    .expect("build focused periodic Count program");
    let optimized = fre_aot_optimizer::optimize_count_v3(
        &kernel,
        fre_aot_optimizer::CountV3TuningClass::GenericAarch64,
        fre_aot_optimizer::CountV3OptimizerLimits::default(),
    )
    .expect("optimize focused periodic Count program");
    assert_eq!(
        optimized.recipe().strategy(),
        fre_aot_optimizer::CountV3Strategy::PeriodicRun,
    );
    let filters = optimized.recipe().filter_offsets();
    assert_eq!(filters.len(), 2);
    let primary = literal[usize::from(filters[0])];
    let secondary = literal[usize::from(filters[1])];
    assert_ne!(primary, secondary);
    let absent = (0..=u8::MAX)
        .find(|byte| !literal.contains(byte))
        .expect("focused periodic literal omits a byte");

    let operating_system = if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else {
        OperatingSystem::Macos
    };
    let target = direct_count_asimd_target(operating_system);
    let pattern = format!(
        "(?-u:{})",
        literal
            .iter()
            .map(|byte| format!(r"\x{byte:02x}"))
            .collect::<String>(),
    );
    let compiled = compile_with_prepared_aggregate_exports(
        direct_count_request(
            pattern,
            target,
            CompileMode::Optimizing,
            CompileLimitsV1::default().max_object_bytes,
        ),
        PreparedAggregateExports::COUNT,
    )
    .expect("compile focused periodic direct Count-v3");
    let report = compiled
        .module()
        .direct_exact_singleton_count_aot_report()
        .expect("focused periodic direct Count-v3 selected");
    assert_eq!(usize::from(report.literal_bytes), literal.len());
    assert!(compiled.module().required_runtime_symbols().next().is_none());
    let entry = compiled
        .module()
        .prepared_count_symbol()
        .expect("focused periodic direct Count-v3 symbol");

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-direct-count-periodic-wide-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create focused periodic linker directory");
    let object = directory.join("count.o");
    fs::write(&object, compiled.object()).expect("write focused periodic Count-v3 object");

    let identity = initializer(&compiled.program().artifact_identity());
    let literal_initializer = initializer(literal);
    let source = format!(
        r#"#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define IDENTITY_OFFSET {identity_offset}U
extern uint32_t {entry}(void *,const uint8_t *,size_t,uint64_t *);
static const uint8_t identity[32]={{{identity}}};
static const uint8_t literal[]={{{literal_initializer}}};
static uint64_t reference_nonoverlap(const uint8_t *hay,size_t len){{
  size_t offset=0U;uint64_t count=0U;
  while(offset+sizeof(literal)<=len){{
    size_t index=0U;
    while(index<sizeof(literal)&&hay[offset+index]==literal[index])index++;
    if(index==sizeof(literal)){{count++;offset+=sizeof(literal);}}else{{offset++;}}
  }}
  return count;
}}
int main(void){{
  uint8_t handle[IDENTITY_OFFSET+32U];
  uint8_t primary_absent[384];
  uint8_t primary_only[384];
  uint8_t late_complete[384];
  uint64_t expected=0U;
  uint64_t out=99U;
  memset(handle,0,sizeof(handle));
  memcpy(handle+IDENTITY_OFFSET,identity,32U);
  memset(primary_absent,{absent}U,sizeof(primary_absent));
  memset(primary_only,{primary}U,sizeof(primary_only));
  memset(late_complete,{absent}U,sizeof(late_complete));
  memcpy(late_complete+150U,literal,sizeof(literal));
  memcpy(late_complete+150U+sizeof(literal),literal,sizeof(literal));
  expected=reference_nonoverlap(primary_absent,sizeof(primary_absent));
  if(expected!=0U)return 1;
  if({entry}(handle,primary_absent,sizeof(primary_absent),&out)!=0U||out!=expected)return 2;
  expected=reference_nonoverlap(primary_only,sizeof(primary_only));out=99U;
  if(expected!=0U)return 3;
  if({entry}(handle,primary_only,sizeof(primary_only),&out)!=0U||out!=expected)return 4;
  expected=reference_nonoverlap(late_complete,sizeof(late_complete));out=99U;
  if(expected!=2U)return 5;
  if({entry}(handle,late_complete,sizeof(late_complete),&out)!=0U||out!=expected)return 6;
  return 0;
}}
"#,
        identity_offset = crate::FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
    );
    let c_path = directory.join("periodic-wide.c");
    let executable = directory.join("periodic-wide");
    fs::write(&c_path, source).expect("write focused periodic Count-v3 C fixture");
    let mut linker = Command::new(if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    });
    let status = linker
        .arg("-O2")
        .arg(&c_path)
        .arg(&object)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("link focused periodic Count-v3 differential");
    assert!(
        status.success(),
        "focused periodic Count-v3 differential failed to link"
    );
    let result = Command::new(&executable)
        .output()
        .expect("run focused periodic Count-v3 differential");
    assert!(
        result.status.success(),
        "focused periodic Count-v3 differential status={:?}, stdout={}, stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
    fs::remove_dir_all(directory).expect("remove focused periodic linker directory");
}

fn generated_prefix_dictionary(roots: usize, children_per_root: usize) -> String {
    let mut pattern = String::from("(?-u:");
    let mut first = true;
    for root in 0..roots {
        if !first {
            pattern.push('|');
        }
        first = false;
        let root = u64::try_from(root).expect("test root fits u64");
        let scrambled_root = root.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let prefix = format!("{scrambled_root:016x}");
        pattern.push_str(&prefix);
        for child in 0..children_per_root {
            pattern.push('|');
            pattern.push_str(&prefix);
            let child = u64::try_from(child).expect("test child fits u64");
            let scrambled_child = root
                .wrapping_mul(0xd6e8_feb8_6659_fd93)
                .wrapping_add(child.wrapping_mul(0xa076_1d64_78bd_642f));
            write!(&mut pattern, "{scrambled_child:016x}")
                .expect("writing to a String cannot fail");
        }
    }
    pattern.push(')');
    pattern
}

fn generated_folded_captured_dictionary(arms: usize) -> String {
    let mut pattern = String::from("(?i-u:");
    for arm in 0..arms {
        if arm != 0 {
            pattern.push('|');
        }
        write!(&mut pattern, "(shared-prefix-{arm:04x})").expect("writing to a String cannot fail");
    }
    pattern.push(')');
    pattern
}

fn parsed_rust_bytes(pattern: &str) -> fre_syntax::RustParsed {
    let parsed = fre_syntax::parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(RustProfile::default()),
    ))
    .expect("parse generated Rust-byte fixture");
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        panic!("Rust-byte fixture produced another syntax tree");
    };
    parsed
}

fn assert_same_lower_resource_failure(expected: fre_lower::LowerError, actual: CompileError) {
    match (expected, actual) {
        (
            fre_lower::LowerError::ResourceLimit {
                resource: expected_resource,
                needed: expected_needed,
                limit: expected_limit,
            },
            CompileError::Lower(fre_lower::LowerError::ResourceLimit {
                resource,
                needed,
                limit,
            }),
        ) => {
            assert_eq!(resource, expected_resource);
            assert_eq!(needed, expected_needed);
            assert_eq!(limit, expected_limit);
        }
        (expected, actual) => {
            panic!("unexpected lower decline: expected {expected:?}, actual {actual:?}")
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end regression covers the ordinary, rescue, and decline contracts"
)]
fn lower_state_finite_dictionary_rescue_preserves_declines_and_ordinary_success() {
    let pattern = generated_prefix_dictionary(64, 16);
    let parsed = parsed_rust_bytes(&pattern);
    let ordinary = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        fre_lower::LowerLimits::default(),
    )
    .expect("unconstrained generated dictionary lowering")
    .into_plan();
    let candidate = crate::finite_language::NativeFiniteLanguageCandidate::analyze(
        &parsed,
        OutputContract::Span,
    )
    .expect("generated dictionary finite proof");
    let compact = candidate
        .priority_trie_raw_plan(fre_lower::LowerLimits::default())
        .expect("bounded generated dictionary trie")
        .expect("priority-compatible generated dictionary");
    assert!(
        compact.roles.len() < ordinary.roles.len(),
        "compact={}, ordinary={}",
        compact.roles.len(),
        ordinary.roles.len(),
    );

    let no_dfa = DeterminizeLimits {
        max_states: 0,
        max_transitions: 0,
        max_work: 0,
    };
    let baseline_limits = CompileLimitsV1 {
        determinize: no_dfa,
        ..CompileLimitsV1::default()
    };
    let slow_limits = SlowAotLimits {
        determinize: no_dfa,
        ..SlowAotLimits::default()
    };
    let baseline = compile_with_slow_aot_limits(
        CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(baseline_limits),
        slow_limits,
    )
    .expect("ordinary-success baseline");
    let mut exact_ordinary_limits = baseline_limits;
    exact_ordinary_limits.lower.automata.max_states = ordinary.roles.len();
    let exact_ordinary = compile_with_slow_aot_limits(
        CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(exact_ordinary_limits),
        slow_limits,
    )
    .expect("ordinary lowering at its exact state ceiling");
    assert_eq!(exact_ordinary.object(), baseline.object());
    assert_eq!(exact_ordinary.receipt(), baseline.receipt());
    assert_eq!(exact_ordinary.module(), baseline.module());
    assert_eq!(
        exact_ordinary.program().serialize().unwrap(),
        baseline.program().serialize().unwrap(),
    );

    let mut rescue_limits = baseline_limits;
    rescue_limits.lower.automata.max_states = compact.roles.len();
    let original = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        rescue_limits.lower,
    )
    .expect_err("ordinary dictionary lowering must exceed the compact ceiling");
    assert!(matches!(
        &original,
        fre_lower::LowerError::ResourceLimit {
            resource: fre_lower::LowerResource::States,
            ..
        }
    ));
    let rescued = compile_with_slow_aot_limits(
        CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(rescue_limits),
        slow_limits,
    )
    .expect("finite dictionary resource rescue");
    assert_eq!(rescued.receipt().thompson_states, compact.roles.len());
    assert!(rescued.receipt().ordered_finite_language_aot.is_some());
    assert!(!rescued.receipt().runtime_helper_required);
    assert!(
        !rescued
            .program()
            .native_finite_language_view()
            .expect("rescued exact finite sidecar")
            .has_dense_transitions(),
        "state rescue must not risk an optional dense-row allocation",
    );

    let fast_error = compile_with_slow_aot_limits(
        CompileRequest::new(&pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span)
            .limits(rescue_limits),
        slow_limits,
    )
    .expect_err("Fast mode must preserve the ordinary lower failure");
    assert_same_lower_resource_failure(original, fast_error);
}

#[test]
fn mixed_prefix_priority_rescue_returns_the_exact_ordinary_lower_failure() {
    let pattern = "(?-u:abx|a|aby)";
    let parsed = parsed_rust_bytes(pattern);
    let ordinary = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        fre_lower::LowerLimits::default(),
    )
    .expect("unconstrained mixed-priority lowering")
    .into_plan();
    let mut limits = CompileLimitsV1::default();
    limits.lower.automata.max_states = ordinary
        .roles
        .len()
        .checked_sub(1)
        .expect("mixed-priority plan is nonempty");
    let expected = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        limits.lower,
    )
    .expect_err("ordinary mixed-priority lowering must exceed the test ceiling");
    assert!(matches!(
        &expected,
        fre_lower::LowerError::ResourceLimit {
            resource: fre_lower::LowerResource::States,
            ..
        }
    ));
    let actual = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits),
    )
    .expect_err("mixed terminal priority must decline rescue");
    assert_same_lower_resource_failure(expected, actual);
}

#[test]
fn non_state_lower_resource_never_enters_finite_rescue() {
    let pattern = "(?-u:abc|def)";
    let parsed = parsed_rust_bytes(pattern);
    let mut limits = CompileLimitsV1::default();
    limits.lower.max_work = 0;
    let expected = fre_lower::lower_raw_general(
        &parsed,
        fre_lower::OperationSemantics::CaptureFree,
        limits.lower,
    )
    .expect_err("ordinary lowering must exceed the zero work ceiling");
    assert!(matches!(
        expected,
        fre_lower::LowerError::ResourceLimit {
            resource: fre_lower::LowerResource::Work,
            ..
        }
    ));
    let actual = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits),
    )
    .expect_err("a non-state lower limit must remain terminal");
    assert_same_lower_resource_failure(expected, actual);
}

#[test]
fn receipt_records_selected_workspace_optimizer_identity_v25() {
    assert_eq!(COMPILER_VERSION, 1);
    assert_eq!(OPTIMIZER_VERSION, 25);
    let compiled = compile(
        CompileRequest::new(r"[a-z]+Z", Target::x86_64_linux())
            .output(OutputContract::Span)
            .mode(CompileMode::Optimizing),
    )
    .expect("compile optimizer-identity fixture");
    assert_eq!(compiled.receipt().compiler_version, COMPILER_VERSION);
    assert_eq!(compiled.receipt().optimizer_version, OPTIMIZER_VERSION);
    assert_eq!(compiled.receipt().entry_abi, EntryAbi::SpanSearchV1);
}

fn streaming_resume_test_automaton() -> Automaton {
    Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            edge_offsets: vec![0, 1, 2, 3, 3],
            edge_targets: vec![1, 2, 3],
            edge_kinds: vec![EdgeKind::ByteRange; 3],
            byte_starts: vec![b'a', b'b', b'c'],
            byte_ends: vec![b'a', b'b', b'c'],
        },
        AutomatonCompileLimits::default(),
    )
    .expect("streaming-resume test automaton")
}

#[test]
fn exact_streaming_resume_constructor_matches_borrowed_frontiers() {
    let automaton = streaming_resume_test_automaton();
    let first = [0_u32, 1];
    let second = [2_u32];
    let mut borrowed = K0ResumeSet::new(
        &automaton,
        2,
        3,
        [(&first[..], false), (&second[..], true)],
    )
    .expect("borrowed resume set");
    // These ranges generate items directly. The constructor cannot borrow or
    // adopt a temporary frontier-item collection because none exists.
    let mut streamed = K0ResumeSet::new_from_exact_frontiers(
        &automaton,
        2,
        3,
        [(2, false, 0_u32..2), (1, true, 2_u32..3)],
    )
    .expect("streamed resume set");

    assert_eq!(streamed.retained_bytes(), borrowed.retained_bytes());
    assert!(streamed.is_bound_to(&automaton));
    assert_eq!(streamed.pending_mode(0).unwrap(), false);
    assert_eq!(streamed.pending_mode(1).unwrap(), true);
    let mut borrowed_workspace =
        K0Workspace::new_bidirectional(&automaton, WorkspaceLimits::unlimited()).unwrap();
    let mut streamed_workspace =
        K0Workspace::new_bidirectional(&automaton, WorkspaceLimits::unlimited()).unwrap();
    assert_eq!(
        borrowed_workspace.compiler_private_try_prefill_resume_caches(
            &automaton,
            &mut borrowed,
        ),
        streamed_workspace.compiler_private_try_prefill_resume_caches(
            &automaton,
            &mut streamed,
        )
    );
}

#[test]
fn exact_streaming_resume_constructor_rejects_malformed_item_extents() {
    let automaton = streaming_resume_test_automaton();
    assert!(matches!(
        K0ResumeSet::new_from_exact_frontiers(
            &automaton,
            1,
            2,
            [(2, false, 0_u32..1)],
        ),
        Err(AutomatonSearchError::InvalidResumeState {
            detail: "resume frontier iterator ended before its declared length",
        })
    ));
    assert!(matches!(
        K0ResumeSet::new_from_exact_frontiers(
            &automaton,
            1,
            1,
            [(1, false, 0_u32..2)],
        ),
        Err(AutomatonSearchError::InvalidResumeState {
            detail: "resume frontier iterator exceeds its declared length",
        })
    ));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn exact_streaming_resume_constructor_preserves_fallible_allocation_error() {
    let automaton = streaming_resume_test_automaton();
    let total_items = isize::MAX as usize / core::mem::size_of::<u32>() + 1;
    assert!(matches!(
        K0ResumeSet::new_from_exact_frontiers(
            &automaton,
            1,
            total_items,
            [(total_items, false, core::iter::empty::<u32>())],
        ),
        Err(AutomatonSearchError::ScratchAllocationFailed { .. })
    ));
}

#[test]
fn slow_aot_receipts_second_determinization_and_both_memory_caps() {
    let mut compile_limits = CompileLimitsV1::default();
    compile_limits.determinize.max_states = 0;
    let slow_limits = SlowAotLimits {
        max_native_data_bytes: usize::MAX,
        ..SlowAotLimits::default()
    };
    let compiled = compile_with_slow_aot_limits(
        CompileRequest::new(r"(?:a|b)*a(?:a|b){15}", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists)
            .limits(compile_limits),
        slow_limits,
    )
    .expect("bounded slow AOT compile");

    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert!(compiled.receipt().determinization.decline.is_some());
    let report = compiled
        .receipt()
        .slow_aot
        .as_ref()
        .expect("selected slow-AOT receipt");
    assert_eq!(report.requested_limits, slow_limits);
    assert_eq!(
        report.effective_native_data_limit_bytes,
        compile_limits.max_object_bytes
    );
    assert_eq!(report.determinization.decline, None);
    assert!(report.allocation_bytes <= slow_limits.max_allocation_bytes);
    assert!(report.native_data_bytes <= report.effective_native_data_limit_bytes);
    assert_eq!(report.native_data_bytes, compiled.receipt().data_bytes);
    assert!(!compiled.receipt().runtime_helper_required);

    let allocation_declined = compile_with_slow_aot_limits(
        CompileRequest::new(r"(?:a|b)*a(?:a|b){15}", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists)
            .limits(compile_limits),
        SlowAotLimits {
            max_allocation_bytes: 0,
            ..slow_limits
        },
    )
    .expect("ordinary prepared fallback after slow allocation decline");
    assert!(allocation_declined.receipt().slow_aot.is_none());
    assert!(allocation_declined.program().has_nfa_mandatory_cut());
    assert!(
        allocation_declined
            .program()
            .bit_parallel_exists_stats()
            .is_some()
    );
    assert!(allocation_declined.receipt().runtime_helper_required);
    assert!(allocation_declined.module().prepared_entry_symbol().is_some());

    let span = compile_with_slow_aot_limits(
        CompileRequest::new("[ab]+z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(compile_limits),
        slow_limits,
    )
    .expect("variable-width Span slow AOT compile");
    assert!(
        span.receipt()
            .slow_aot
            .as_ref()
            .is_some_and(|report| report.dfa.reverse_states != 0)
    );
    assert!(
        !span
            .receipt()
            .passes
            .contains(&OptimizationPass::RemoveUnusedReverseMachine)
    );
}

#[test]
fn slow_context_aot_receipt_is_distinct_and_only_names_an_installed_candidate() {
    let pattern = r"(?-u:\b)abc(?-u:\b)";
    let mut compile_limits = CompileLimitsV1::default();
    compile_limits.determinize.max_states = 0;
    let slow_limits = SlowAotLimits::default();
    let request = || {
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(compile_limits)
    };
    let compiled = compile_with_slow_aot_limits(request(), slow_limits)
        .expect("slow contextual native compile");

    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.receipt().engine_selection_reason,
        EngineSelectionReason::ContextAssertions
    );
    assert!(
        compiled
            .receipt()
            .context_determinization
            .as_ref()
            .is_some_and(|report| report.decline.is_some()),
        "semantic contextual decline must remain visible"
    );
    assert!(compiled.receipt().slow_aot.is_none());
    let report = compiled
        .receipt()
        .slow_context_aot
        .as_ref()
        .expect("installed slow contextual receipt");
    assert_eq!(report.requested_limits, slow_limits);
    assert_eq!(
        report.effective_native_data_limit_bytes,
        slow_limits
            .max_native_data_bytes
            .min(compile_limits.max_object_bytes)
            .min(crate::context_native::MAX_CONTEXT_NATIVE_DATA_BYTES)
    );
    assert!(report.dfa.forward_states > 0);
    assert!(report.allocation_bytes <= slow_limits.max_allocation_bytes);
    assert!(report.work_completed <= slow_limits.determinize.max_work);
    assert!(report.native_data_bytes <= report.effective_native_data_limit_bytes);
    assert_eq!(report.native_data_bytes, compiled.receipt().data_bytes);
    assert!(!compiled.receipt().runtime_helper_required);
    assert!(
        compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::UniversalOrderedTnfa)
    );
    assert!(
        compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::ContextOrderedDeterminization)
    );
    assert!(
        compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::ContextNativeLowering)
    );
    assert!(
        compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::ExactWidthStartRecovery)
    );
    assert!(
        !compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::ReverseStartRecovery)
    );
    assert!(
        !compiled
            .receipt()
            .passes
            .contains(&OptimizationPass::RuntimeAdapterLowering)
    );

    for declined_limits in [
        SlowAotLimits {
            max_allocation_bytes: 0,
            ..slow_limits
        },
        SlowAotLimits {
            max_native_data_bytes: 0,
            ..slow_limits
        },
        SlowAotLimits {
            determinize: crate::DeterminizeLimits {
                max_states: 0,
                ..slow_limits.determinize
            },
            ..slow_limits
        },
    ] {
        let declined = compile_with_slow_aot_limits(request(), declined_limits)
            .expect("ordinary fallback after optional slow-context decline");
        assert!(declined.receipt().slow_context_aot.is_none());
        assert!(declined.receipt().slow_aot.is_none());
        assert!(declined.receipt().runtime_helper_required);
        assert!(
            declined
                .receipt()
                .context_determinization
                .as_ref()
                .is_some_and(|semantic| semantic.decline.is_some())
        );
    }
}

#[test]
fn slow_context_object_size_fallback_clears_optimizer_only_provenance() {
    let pattern = r"(?-u:\b)(?:abc|def|ghi)(?-u:\b)";
    let target = Target::aarch64_macos()
        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .expect("ASIMD target");
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let request = |limits| {
        CompileRequest::new(pattern, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits)
    };
    let optimized = compile(request(limits)).expect("unbounded slow contextual object");
    let selected = optimized
        .receipt()
        .slow_context_aot
        .as_ref()
        .expect("selected slow contextual candidate");
    assert!(!optimized.receipt().runtime_helper_required);

    let fallback = crate::CompiledModule::lower(optimized.program(), target)
        .expect("ordinary contextual-fallback module");
    assert!(fallback.required_runtime_symbol().is_some());
    assert!(fallback.slow_context_aot_report().is_none());
    let fallback_object = emit_object(
        &fallback,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
    )
    .expect("ordinary contextual-fallback object");
    assert!(optimized.object().len() > fallback_object.len());

    limits.max_object_bytes = fallback_object.len().max(selected.native_data_bytes);
    assert!(limits.max_object_bytes < optimized.object().len());
    let constrained = compile(request(limits))
        .expect("ordinary module fits after slow contextual object refusal");
    assert_eq!(constrained.module(), &fallback);
    assert_eq!(constrained.object(), fallback_object);
    assert!(constrained.receipt().slow_context_aot.is_none());
    assert!(constrained.receipt().slow_aot.is_none());
    assert!(constrained.receipt().runtime_helper_required);
    assert!(
        constrained
            .receipt()
            .context_determinization
            .as_ref()
            .is_some_and(|report| report.decline.is_some()),
        "the final receipt must retain semantic decline provenance"
    );
}

#[test]
fn slow_decline_tries_k0_before_the_ordinary_runtime_route() {
    let mut compile_limits = CompileLimitsV1::default();
    compile_limits.determinize.max_states = 0;
    let request = || {
        CompileRequest::new(
            "a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
            Target::x86_64_linux(),
        )
        .mode(CompileMode::Optimizing)
        .output(OutputContract::SelectedEnd)
        .limits(compile_limits)
    };
    let k0 = compile_with_slow_aot_limits(
        request(),
        SlowAotLimits {
            max_allocation_bytes: 0,
            ..SlowAotLimits::default()
        },
    )
    .expect("K0 native fallback");
    assert!(k0.receipt().slow_aot.is_none());
    assert!(!k0.receipt().runtime_helper_required);

    let ordinary = compile_with_slow_aot_limits(
        request(),
        SlowAotLimits {
            max_allocation_bytes: 0,
            max_native_data_bytes: 0,
            ..SlowAotLimits::default()
        },
    )
    .expect("ordinary fallback after slow and K0 native-data declines");
    assert!(ordinary.receipt().slow_aot.is_none());
    assert!(ordinary.receipt().runtime_helper_required);
}

#[test]
fn program_byte_cap_rejects_before_canonical_serialization() {
    let mut limits = CompileLimitsV1::default();
    limits.max_program_bytes = 1;
    crate::program::reset_test_serialize_calls();
    let error = compile(
        CompileRequest::new(r"(?:foo|bar)+[0-9]{2}", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .limits(limits),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CompileError::Resource {
            resource: CompileResource::ProgramBytes,
            limit: 1,
            required,
        } if required > 1
    ));
    assert_eq!(
        crate::program::test_serialize_calls(),
        0,
        "the bounded artifact must not allocate/serialize before cap rejection"
    );
}

#[test]
fn compile_request_size_limit_is_native_and_last_setter_wins() {
    let target = Target::x86_64_linux();
    let default = CompileRequest::new("a", target);
    assert_eq!(default.limits.max_program_bytes, 10 * 1_048_576);
    let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } = default.profile.constructor
    else {
        panic!("default AOT request lost its Rust-like constructor stamp");
    };
    assert_eq!(size_limit, 10 * 1_048_576);

    let mut wide = CompileLimitsV1::default();
    wide.max_program_bytes = 23 * 1_048_576;
    let limits_last = CompileRequest::new("a", target).size_limit(17).limits(wide);
    assert_eq!(limits_last.limits.max_program_bytes, wide.max_program_bytes);
    let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
        limits_last.profile.constructor
    else {
        panic!("limits-last request lost its Rust-like constructor stamp");
    };
    assert_eq!(size_limit, u64::try_from(wide.max_program_bytes).unwrap());

    let size_last = CompileRequest::new("a", target).limits(wide).size_limit(17);
    assert_eq!(size_last.limits.max_program_bytes, 17);
    let rebar = CompileRequest::new("a", target)
        .size_limit(17)
        .profile(RustProfile::rebar_1_12_4());
    assert_eq!(
        rebar.limits.max_program_bytes,
        CompileLimitsV1::default().max_program_bytes
    );
}

#[test]
fn optimizing_object_cap_falls_back_to_the_bounded_module() {
    // Keep this cap-ordering fixture on the wider x86 table. The AArch64
    // byte-compact native object can now be smaller than its runtime adapter,
    // in which case no object-byte ceiling can admit only the adapter.
    let target = Target::x86_64_macos()
        .with_features(FeatureSet::of(CpuFeature::X86Sse2))
        .expect("x86-64 baseline target");
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let request = |limits| {
        CompileRequest::new("a+Q|[b-c][a-b]{1,5}(?:x+|y+)", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits)
    };
    let optimized = compile(request(limits)).expect("unbounded optimizing compile");
    assert_eq!(optimized.module().required_runtime_symbol(), None);
    assert!(optimized.receipt().slow_aot.is_some());

    let fallback = crate::CompiledModule::lower_without_endpoint_oracle(optimized.program(), target)
        .expect("bounded fallback lowering");
    assert!(fallback.required_runtime_symbol().is_some());
    let fallback_object = emit_object(
        &fallback,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
    )
    .expect("unbounded fallback object");
    assert!(optimized.object().len() > fallback_object.len());

    limits.max_object_bytes = fallback_object.len().max(
        optimized
            .receipt()
            .slow_aot
            .as_ref()
            .expect("slow-AOT receipt")
            .native_data_bytes,
    );
    assert!(limits.max_object_bytes < optimized.object().len());
    let constrained = compile(request(limits)).expect("K0 fits after the slow object cap");
    assert_ne!(constrained.module(), &fallback);
    assert!(!constrained.receipt().runtime_helper_required);
    assert!(constrained.receipt().slow_aot.is_none());
    assert!(constrained.receipt().object_bytes <= limits.max_object_bytes);

    limits.max_object_bytes = fallback_object.len();
    let ordinary = compile(request(limits)).expect("ordinary module fits its exact object cap");
    assert_eq!(ordinary.module(), &fallback);
    assert_eq!(ordinary.object(), fallback_object);
    assert!(ordinary.receipt().runtime_helper_required);
    assert!(ordinary.receipt().slow_aot.is_none());

    limits.max_object_bytes = fallback_object.len() - 1;
    assert!(matches!(
        compile(request(limits)),
        Err(CompileError::Object(crate::ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        })) if limit == limits.max_object_bytes && required > limit
    ));
}

#[test]
fn ordered_nfa_object_cap_has_native_and_incumbent_exact_boundaries() {
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(r"(?-u:[\x00-\xFF])\bfoo\b", target)
            .mode(CompileMode::Fast)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let native = compile(request(usize::MAX)).expect("unbounded Ordered-NFA object");
    assert!(!native.module().has_ordered_nfa_start_prefix());
    assert!(!native.module().has_ordered_nfa_start_closure_dispatch());
    assert_eq!(
        native.module().prepared_bulk_strategy(),
        Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
    );
    assert_eq!(
        native.receipt().required_prepare_capabilities,
        PREPARED_CAPABILITY_ORDERED_NFA_V15,
    );
    assert!(
        native
            .receipt()
            .passes
            .contains(&OptimizationPass::NativeOrderedTnfaLowering),
    );
    let native_data_extent = native
        .receipt()
        .data_bytes
        .checked_sub(native.receipt().program_bytes)
        .expect("Ordered-NFA native data follows its serialized program");
    let (data_exact, _) = crate::lower_ordinary_with_endpoint_oracle_object_retry(
        native.program(),
        target,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
        native_data_extent,
        true,
    )
    .expect("ordinary retry seam at exact Ordered-NFA native-data extent");
    assert_eq!(&data_exact, native.module());
    assert!(
        crate::selected_passes(native.program(), &data_exact)
            .contains(&OptimizationPass::NativeOrderedTnfaLowering),
    );
    let data_one_below = native_data_extent
        .checked_sub(1)
        .expect("nonempty Ordered-NFA native-data extent");
    let (data_declined, _) = crate::lower_ordinary_with_endpoint_oracle_object_retry(
        native.program(),
        target,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
        data_one_below,
        true,
    )
    .expect("ordinary retry seam one below Ordered-NFA native-data extent");
    assert_eq!(data_declined.required_prepare_capabilities(), 0);
    assert_eq!(
        data_declined.prepared_bulk_strategy(),
        Some(PreparedBulkStrategy::RuntimeHelper),
    );
    assert!(
        !crate::selected_passes(native.program(), &data_declined)
            .contains(&OptimizationPass::NativeOrderedTnfaLowering),
    );
    let incumbent = crate::CompiledModule::lower_without_ordered_nfa(
        native.program(),
        target,
        true,
    )
    .expect("Ordered-disabled incumbent module");
    let incumbent_object = emit_object(
        &incumbent,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
    )
    .expect("Ordered-disabled incumbent object");
    assert!(incumbent_object.len() < native.object().len());

    let exact_native = compile(request(native.object().len()))
        .expect("exact Ordered-NFA object boundary");
    assert_eq!(exact_native.object(), native.object());
    let native_one_below = native
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty Ordered-NFA object");
    assert!(incumbent_object.len() <= native_one_below);
    let declined = compile(request(native_one_below))
        .expect("native one-below soft fallback to incumbent");
    assert_eq!(declined.module(), &incumbent);
    assert_eq!(declined.object(), incumbent_object);
    assert_eq!(declined.receipt().required_prepare_capabilities, 0);
    assert!(!declined
        .receipt()
        .passes
        .contains(&OptimizationPass::NativeOrderedTnfaLowering));

    let exact_incumbent = compile(request(incumbent_object.len()))
        .expect("exact incumbent object boundary");
    assert_eq!(exact_incumbent.module(), &incumbent);
    assert_eq!(exact_incumbent.object(), incumbent_object);
    let incumbent_one_below = incumbent_object
        .len()
        .checked_sub(1)
        .expect("nonempty incumbent object");
    assert!(matches!(
        compile(request(incumbent_one_below)),
        Err(CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        })) if limit == incumbent_one_below && required > limit
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "ordinary and aggregate V3/V2/V1/incumbent boundaries form one cap transaction"
)]
fn ordered_nfa_accelerator_final_object_caps_preserve_v2_v1_before_incumbent() {
    const PATTERN: &str = concat!(
        r"(?-u:[\x00-\xFF])",
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}",
        r"(?-u:[\x80-\xFF])\b",
    );
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(PATTERN, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: crate::DeterminizeLimits {
                    max_states: 0,
                    ..crate::DeterminizeLimits::default()
                },
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let mut slow_limits = SlowAotLimits::default();
    slow_limits.determinize.max_states = 0;
    slow_limits.determinize.max_transitions = 0;
    slow_limits.determinize.max_work = 0;
    let format = crate::ObjectFormat::for_target(target);

    let v3 = compile_with_slow_aot_limits(request(usize::MAX), slow_limits)
        .expect("unbounded V3 final-object fixture");
    assert!(!v3.module().has_ordered_nfa_start_prefix());
    assert!(!v3.module().has_ordered_nfa_start_closure_dispatch());
    assert!(v3.module().has_ordered_nfa_terminal_range_object());
    assert!(v3.module().has_ordered_edge_dispatch_object());
    let v2_base = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators(
        v3.program(),
        target,
        false,
        true,
        true,
        false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route V2 lowering")
    .with_optimizing_fallbacks_may_continue(
        v3.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!v2_base.has_ordered_nfa_terminal_range_object());
    assert!(v2_base.has_ordered_edge_dispatch_object());
    assert_eq!(
        v2_base.required_prepare_capabilities(),
        PREPARED_CAPABILITY_ORDERED_NFA_V15,
    );
    let v2_base_object = emit_object(&v2_base, format, usize::MAX)
        .expect("unbounded V2 final object");
    assert!(v2_base_object.len() < v3.object().len());

    let scalar_base = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators(
        v3.program(),
        target,
        false,
        true,
        false,
        false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route scalar V1 lowering")
    .with_optimizing_fallbacks_may_continue(
        v3.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!scalar_base.has_ordered_nfa_terminal_range_object());
    assert!(!scalar_base.has_ordered_edge_dispatch_object());
    assert_eq!(
        scalar_base.required_prepare_capabilities(),
        PREPARED_CAPABILITY_ORDERED_NFA_V15,
    );
    let scalar_base_object = emit_object(&scalar_base, format, usize::MAX)
        .expect("unbounded scalar V1 final object");
    assert!(scalar_base_object.len() < v2_base_object.len());

    let exact_v3 = compile_with_slow_aot_limits(request(v3.object().len()), slow_limits)
        .expect("exact V3 final-object boundary");
    assert_eq!(exact_v3.module(), v3.module());
    assert_eq!(exact_v3.object(), v3.object());
    let v3_one_below = v3
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty V3 final object");
    assert!(v2_base_object.len() <= v3_one_below);
    let retried_v2 = compile_with_slow_aot_limits(request(v3_one_below), slow_limits)
        .expect("V3 final-object one-below retries V2");
    assert_eq!(retried_v2.module(), &v2_base);
    assert_eq!(retried_v2.object(), v2_base_object);

    let exact_v2 = compile_with_slow_aot_limits(request(v2_base_object.len()), slow_limits)
        .expect("exact V2 final-object boundary");
    assert_eq!(exact_v2.module(), &v2_base);
    assert_eq!(exact_v2.object(), v2_base_object);
    let v2_one_below = v2_base_object
        .len()
        .checked_sub(1)
        .expect("nonempty V2 final object");
    assert!(scalar_base_object.len() <= v2_one_below);
    let retried_v1 = compile_with_slow_aot_limits(request(v2_one_below), slow_limits)
        .expect("V2 final-object one-below retries scalar V1");
    assert_eq!(retried_v1.module(), &scalar_base);
    assert_eq!(retried_v1.object(), scalar_base_object);

    let exact_v1 = compile_with_slow_aot_limits(request(scalar_base_object.len()), slow_limits)
        .expect("exact scalar V1 final-object boundary");
    assert_eq!(exact_v1.module(), &scalar_base);
    assert_eq!(exact_v1.object(), scalar_base_object);
    let v1_one_below = scalar_base_object
        .len()
        .checked_sub(1)
        .expect("nonempty scalar V1 final object");
    let below_v1 = compile_with_slow_aot_limits(request(v1_one_below), slow_limits)
        .expect("scalar V1 one-below reaches an incumbent route");
    assert_eq!(below_v1.receipt().required_prepare_capabilities, 0);
    assert!(!below_v1.module().has_ordered_nfa_terminal_range_object());
    assert!(!below_v1.module().has_ordered_edge_dispatch_object());

    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    let v3_aggregate = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
        request(usize::MAX),
        exports,
        slow_limits,
    )
    .expect("unbounded V3 aggregate final object");
    assert!(v3_aggregate.module().has_ordered_nfa_terminal_range_object());
    assert!(v3_aggregate.module().has_ordered_edge_dispatch_object());
    let serialized = v3.program().serialize().expect("serialize V3 cap fixture");
    let v2_aggregate = v2_base
        .clone()
        .append_prepared_aggregate_exports(
            exports,
            v3.program().artifact_identity(),
            &serialized,
        )
        .expect("append V2 aggregate entries");
    let v2_aggregate_object = emit_object(&v2_aggregate, format, usize::MAX)
        .expect("unbounded V2 aggregate final object");
    assert!(v2_aggregate_object.len() < v3_aggregate.object().len());
    let scalar_aggregate = scalar_base
        .clone()
        .append_prepared_aggregate_exports(
            exports,
            v3.program().artifact_identity(),
            &serialized,
        )
        .expect("append scalar V1 aggregate entries");
    let scalar_aggregate_object = emit_object(&scalar_aggregate, format, usize::MAX)
        .expect("unbounded scalar V1 aggregate final object");
    assert!(scalar_aggregate_object.len() < v2_aggregate_object.len());

    let exact_v3_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(v3_aggregate.object().len()),
            exports,
            slow_limits,
        )
        .expect("exact V3 aggregate final-object boundary");
    assert_eq!(exact_v3_aggregate.module(), v3_aggregate.module());
    assert_eq!(exact_v3_aggregate.object(), v3_aggregate.object());
    let aggregate_v3_one_below = v3_aggregate
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty V3 aggregate final object");
    assert!(v2_aggregate_object.len() <= aggregate_v3_one_below);
    let retried_v2_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(aggregate_v3_one_below),
            exports,
            slow_limits,
        )
        .expect("V3 aggregate one-below retries V2");
    assert_eq!(retried_v2_aggregate.module(), &v2_aggregate);
    assert_eq!(retried_v2_aggregate.object(), v2_aggregate_object);
    assert_eq!(
        retried_v2_aggregate.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
    );

    let exact_v2_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(v2_aggregate_object.len()),
            exports,
            slow_limits,
        )
        .expect("exact V2 aggregate final-object boundary");
    assert_eq!(exact_v2_aggregate.module(), &v2_aggregate);
    assert_eq!(exact_v2_aggregate.object(), v2_aggregate_object);
    let aggregate_v2_one_below = v2_aggregate_object
        .len()
        .checked_sub(1)
        .expect("nonempty V2 aggregate final object");
    assert!(scalar_aggregate_object.len() <= aggregate_v2_one_below);
    let retried_v1_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(aggregate_v2_one_below),
            exports,
            slow_limits,
        )
        .expect("V2 aggregate one-below retries scalar V1");
    assert_eq!(retried_v1_aggregate.module(), &scalar_aggregate);
    assert_eq!(retried_v1_aggregate.object(), scalar_aggregate_object);

    let exact_v1_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(scalar_aggregate_object.len()),
            exports,
            slow_limits,
        )
        .expect("exact scalar V1 aggregate final-object boundary");
    assert_eq!(exact_v1_aggregate.module(), &scalar_aggregate);
    assert_eq!(exact_v1_aggregate.object(), scalar_aggregate_object);
    let aggregate_v1_one_below = scalar_aggregate_object
        .len()
        .checked_sub(1)
        .expect("nonempty scalar V1 aggregate final object");
    let below_v1_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(aggregate_v1_one_below),
            exports,
            slow_limits,
        )
        .expect("scalar V1 aggregate one-below reaches incumbent helpers");
    assert_eq!(
        below_v1_aggregate.receipt().required_prepare_capabilities,
        0,
    );
    assert_eq!(
        below_v1_aggregate.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::RuntimeHelper),
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "ordinary and aggregate compiler-text exact boundaries form one resource transaction"
)]
fn ordered_nfa_compiler_text_final_object_retries_preserve_exact_v3() {
    const PATTERN: &str = concat!(
        r"a?b?c?d?e?f?g?h?(?:a?|bc)",
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}",
        r"(?-u:[\x80-\xFF])\b",
    );
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(PATTERN, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: crate::DeterminizeLimits {
                    max_states: 0,
                    ..crate::DeterminizeLimits::default()
                },
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let mut slow_limits = SlowAotLimits::default();
    slow_limits.determinize.max_states = 0;
    slow_limits.determinize.max_transitions = 0;
    slow_limits.determinize.max_work = 0;
    let format = crate::ObjectFormat::for_target(target);

    let selected = compile_with_slow_aot_limits(request(usize::MAX), slow_limits)
        .expect("unbounded start-specialized V3 fixture");
    assert!(selected.module().has_ordered_nfa_start_prefix());
    assert!(selected.module().has_ordered_nfa_start_closure_dispatch());
    assert!(selected.module().has_ordered_nfa_terminal_range_object());
    assert!(selected.module().has_ordered_edge_dispatch_object());
    assert!(
        selected
            .receipt()
            .passes
            .contains(&OptimizationPass::AnchoredPrefixCandidateFilter),
    );
    let prefix_pass = selected
        .receipt()
        .passes
        .iter()
        .position(|pass| *pass == OptimizationPass::AnchoredPrefixCandidateFilter)
        .unwrap();
    let native_pass = selected
        .receipt()
        .passes
        .iter()
        .position(|pass| *pass == OptimizationPass::NativeOrderedTnfaLowering)
        .unwrap();
    assert!(prefix_pass < native_pass);
    let without_prefix = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix(
        selected.program(),
        target,
        false,
        true,
        true,
        true,
        true,
        false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route V3 lowering without prefix text")
    .with_optimizing_fallbacks_may_continue(
        selected.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!without_prefix.has_ordered_nfa_start_prefix());
    assert!(without_prefix.has_ordered_nfa_start_closure_dispatch());
    assert!(
        !crate::selected_passes(selected.program(), &without_prefix)
            .contains(&OptimizationPass::AnchoredPrefixCandidateFilter),
    );
    let without_start = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix(
        selected.program(),
        target,
        false,
        true,
        true,
        true,
        false,
        false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route V3 lowering without compiler text")
    .with_optimizing_fallbacks_may_continue(
        selected.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!without_start.has_ordered_nfa_start_prefix());
    assert!(!without_start.has_ordered_nfa_start_closure_dispatch());
    assert!(without_start.has_ordered_nfa_terminal_range_object());
    assert!(without_start.has_ordered_edge_dispatch_object());
    assert_eq!(
        selected.module().sections()[1].bytes(),
        without_prefix.sections()[1].bytes(),
        "compiler-only prefix text must not change V3 data",
    );
    assert_eq!(
        selected.module().sections()[1].bytes(),
        without_start.sections()[1].bytes(),
        "compiler-only text must not change V3 data",
    );
    let relocation_shapes = |module: &crate::CompiledModule| {
        module
            .relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.section,
                    relocation.kind,
                    relocation.symbol,
                    relocation.addend,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        relocation_shapes(selected.module()),
        relocation_shapes(&without_prefix),
        "compiler-only prefix text must not add relocation dependencies",
    );
    assert_eq!(
        relocation_shapes(selected.module()),
        relocation_shapes(&without_start),
        "compiler-only text must not add relocation dependencies",
    );
    let without_prefix_object = emit_object(&without_prefix, format, usize::MAX)
        .expect("unbounded V3 object without prefix text");
    let without_start_object = emit_object(&without_start, format, usize::MAX)
        .expect("unbounded V3 object without compiler text");
    assert!(without_prefix_object.len() < selected.object().len());
    assert!(without_start_object.len() < selected.object().len());
    assert!(without_start_object.len() < without_prefix_object.len());

    let exact = compile_with_slow_aot_limits(request(selected.object().len()), slow_limits)
        .expect("exact start-specialized V3 boundary");
    assert_eq!(exact.module(), selected.module());
    assert_eq!(exact.object(), selected.object());
    let selected_one_below = selected
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty start-specialized object");
    assert!(without_prefix_object.len() <= selected_one_below);
    let retried = compile_with_slow_aot_limits(request(selected_one_below), slow_limits)
        .expect("prefix-specialized one-below retries exact V3 without prefix text");
    assert_eq!(retried.module(), &without_prefix);
    assert_eq!(retried.object(), without_prefix_object);
    assert!(
        !retried
            .receipt()
            .passes
            .contains(&OptimizationPass::AnchoredPrefixCandidateFilter),
    );
    let prefix_one_below = without_prefix_object
        .len()
        .checked_sub(1)
        .expect("nonempty start-specialized object");
    assert!(without_start_object.len() <= prefix_one_below);
    let retried_without_start =
        compile_with_slow_aot_limits(request(prefix_one_below), slow_limits)
            .expect("start-specialized one-below retries exact V3 without compiler text");
    assert_eq!(retried_without_start.module(), &without_start);
    assert_eq!(retried_without_start.object(), without_start_object);

    let exports = PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM);
    let selected_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(usize::MAX),
            exports,
            slow_limits,
        )
        .expect("unbounded start-specialized V3 aggregate");
    let serialized = selected
        .program()
        .serialize()
        .expect("serialize start-specialized fixture");
    let without_prefix_aggregate = without_prefix
        .append_prepared_aggregate_exports(
            exports,
            selected.program().artifact_identity(),
            &serialized,
        )
        .expect("append V3 aggregate exports without prefix text");
    let without_prefix_aggregate_object =
        emit_object(&without_prefix_aggregate, format, usize::MAX)
            .expect("unbounded V3 aggregate object without prefix text");
    let without_start_aggregate = without_start
        .append_prepared_aggregate_exports(
            exports,
            selected.program().artifact_identity(),
            &serialized,
        )
        .expect("append V3 aggregate exports without compiler text");
    let without_start_aggregate_object =
        emit_object(&without_start_aggregate, format, usize::MAX)
            .expect("unbounded V3 aggregate object without compiler text");
    assert!(without_start_aggregate_object.len() < without_prefix_aggregate_object.len());
    let aggregate_one_below = selected_aggregate
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty start-specialized aggregate object");
    assert!(without_prefix_aggregate_object.len() <= aggregate_one_below);
    let retried_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(aggregate_one_below),
            exports,
            slow_limits,
        )
        .expect("aggregate one-below retries exact V3 without prefix text");
    assert_eq!(retried_aggregate.module(), &without_prefix_aggregate);
    assert_eq!(
        retried_aggregate.object(),
        without_prefix_aggregate_object,
    );
    assert!(
        !retried_aggregate
            .receipt()
            .passes
            .contains(&OptimizationPass::AnchoredPrefixCandidateFilter),
    );
    let aggregate_prefix_one_below = without_prefix_aggregate_object
        .len()
        .checked_sub(1)
        .expect("nonempty start-specialized aggregate object");
    assert!(without_start_aggregate_object.len() <= aggregate_prefix_one_below);
    let retried_aggregate_without_start =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(aggregate_prefix_one_below),
            exports,
            slow_limits,
        )
        .expect("aggregate start-specialized one-below retries without compiler text");
    assert_eq!(
        retried_aggregate_without_start.module(),
        &without_start_aggregate,
    );
    assert_eq!(
        retried_aggregate_without_start.object(),
        without_start_aggregate_object,
    );
}

const TERMINAL_EXACT_SET_PATTERN: &str = concat!(
    r"^[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,120}",
    r"[0-24-6]$",
);
const TERMINAL_EXACT_SET_AGGREGATE_PATTERN: &str = concat!(
    r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}",
    r"[0-24-6](?-u:\b)",
);

fn terminal_exact_set_slow_limits() -> SlowAotLimits {
    let mut limits = SlowAotLimits::default();
    limits.determinize.max_states = 0;
    limits.determinize.max_transitions = 0;
    limits.determinize.max_work = 0;
    limits
}

#[test]
fn ordered_nfa_terminal_exact_set_is_shared_entry_data_abi_and_relocation_inert_on_both_isas() {
    let mut compile_limits = CompileLimitsV1::default();
    compile_limits.determinize.max_states = 0;
    let compiled = compile_with_slow_aot_limits(
        CompileRequest::new(TERMINAL_EXACT_SET_PATTERN, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(compile_limits),
        terminal_exact_set_slow_limits(),
    )
    .expect("build fragmented terminal-set Ordered-NFA program");
    assert!(
        compiled
            .program()
            .native_ordered_nfa_view()
            .and_then(|view| view.terminal_exact_set)
            .is_some(),
    );

    let relocation_shapes = |module: &crate::CompiledModule| {
        module
            .relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.section,
                    relocation.kind,
                    relocation.symbol,
                    relocation.addend,
                )
            })
            .collect::<Vec<_>>()
    };
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let enabled = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width(
            compiled.program(), target, false, true, true, true, true, true, true, usize::MAX,
        )
        .expect("lower exact terminal-set module");
        let disabled = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
            compiled.program(), target, false, true, true, true, true, true, true, false,
            usize::MAX,
        )
        .expect("lower module without the exact terminal-set receipt");
        assert!(enabled.has_ordered_nfa_terminal_exact_set(), "{target:?}");
        assert!(!disabled.has_ordered_nfa_terminal_exact_set(), "{target:?}");
        assert_eq!(
            enabled.required_prepare_capabilities(),
            disabled.required_prepare_capabilities(),
            "capability drift for {target:?}",
        );
        assert_eq!(
            enabled.ordered_nfa_object_abi_and_flags(),
            disabled.ordered_nfa_object_abi_and_flags(),
            "object ABI/flag drift for {target:?}",
        );
        assert_eq!(
            enabled.sections()[1].bytes(),
            disabled.sections()[1].bytes(),
            "program/object data drift for {target:?}",
        );
        assert_eq!(
            relocation_shapes(&enabled),
            relocation_shapes(&disabled),
            "relocation dependency drift for {target:?}",
        );
        assert_eq!(
            enabled.sections()[0].bytes(),
            disabled.sections()[0].bytes(),
            "shared one-Span text drift for {target:?}",
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "ordinary inertness and the aggregate-only object-cap retry share one exact fixture"
)]
fn ordered_nfa_terminal_exact_set_is_ordinary_inert_and_retries_aggregate_text_first() {
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(TERMINAL_EXACT_SET_AGGREGATE_PATTERN, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: crate::DeterminizeLimits {
                    max_states: 0,
                    ..crate::DeterminizeLimits::default()
                },
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let slow_limits = terminal_exact_set_slow_limits();
    let selected = compile_with_slow_aot_limits(request(usize::MAX), slow_limits)
        .expect("unbounded exact terminal-set fixture");
    assert!(selected.module().has_ordered_nfa_terminal_exact_set());
    assert!(!selected.module().has_ordered_nfa_whole_window_width_gate());
    assert!(!selected.module().has_ordered_nfa_terminal_range_object());

    let without_exact = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
        selected.program(), target, false, true, true, true, true, true, true, false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route lowering without the terminal exact-set receipt")
    .with_optimizing_fallbacks_may_continue(
        selected.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!without_exact.has_ordered_nfa_terminal_exact_set());
    assert!(!without_exact.has_ordered_nfa_whole_window_width_gate());
    assert_eq!(
        selected.module().sections()[0].bytes(),
        without_exact.sections()[0].bytes(),
        "ordinary one-Span text must ignore the aggregate-only receipt",
    );
    assert_eq!(
        selected.module().sections()[1].bytes(),
        without_exact.sections()[1].bytes(),
        "the compiler-only receipt must not enter data",
    );

    let format = crate::ObjectFormat::for_target(target);
    let without_exact_object =
        emit_object(&without_exact, format, usize::MAX).expect("emit exact-set-disabled object");
    assert_eq!(
        selected.object(),
        without_exact_object,
        "ordinary objects must be byte-identical",
    );

    let exports = PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM);
    let selected_aggregate = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
        request(usize::MAX),
        exports,
        slow_limits,
    )
    .expect("unbounded exact terminal-set aggregate");
    assert!(
        selected_aggregate
            .module()
            .has_ordered_nfa_terminal_exact_set(),
    );
    let serialized = selected
        .program()
        .serialize()
        .expect("serialize exact terminal-set fixture");
    let without_exact_aggregate = without_exact
        .append_prepared_aggregate_exports(
            exports,
            selected.program().artifact_identity(),
            &serialized,
        )
        .expect("append aggregate exports without terminal exact-set text");
    let without_exact_aggregate_object = emit_object(&without_exact_aggregate, format, usize::MAX)
        .expect("emit exact-set-disabled aggregate object");
    assert!(
        without_exact_aggregate_object.len() < selected_aggregate.object().len(),
        "only Count/SpanSum wrappers should carry exact-set text",
    );

    let aggregate_one_below = selected_aggregate.object().len() - 1;
    assert!(without_exact_aggregate_object.len() <= aggregate_one_below);
    let retried_aggregate = crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
        request(aggregate_one_below),
        exports,
        slow_limits,
    )
    .expect("aggregate exact-set object one-below retries without its text");
    assert_eq!(retried_aggregate.module(), &without_exact_aggregate);
    assert_eq!(retried_aggregate.object(), without_exact_aggregate_object);
}

#[test]
fn ordered_nfa_ineligible_width_gate_is_exactly_byte_inert_on_both_isas() {
    let compiled = compile(
        CompileRequest::new(r"(?-u:(?:a.c|ab)\b)", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
    )
    .expect("build width-ineligible Ordered-NFA program");
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert!(
        compiled
            .program()
            .native_ordered_nfa_view()
            .unwrap()
            .whole_window_width_bounds
            .is_none(),
    );
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let enabled = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width(
            compiled.program(), target, false, true, true, true, true, true, true, usize::MAX,
        )
        .expect("lower width-ineligible module with gate allowed");
        let disabled = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width(
            compiled.program(), target, false, true, true, true, true, true, false, usize::MAX,
        )
        .expect("lower width-ineligible module with gate disabled");
        assert!(!enabled.has_ordered_nfa_whole_window_width_gate());
        assert_eq!(enabled, disabled, "no-gate module drift for {target:?}");
        assert_eq!(
            emit_object(&enabled, crate::ObjectFormat::for_target(target), usize::MAX)
                .expect("emit enabled width-ineligible object"),
            emit_object(&disabled, crate::ObjectFormat::for_target(target), usize::MAX)
                .expect("emit disabled width-ineligible object"),
            "no-gate object drift for {target:?}",
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "ordinary and aggregate exact width-gate cap rungs share one fixture"
)]
fn ordered_nfa_whole_window_width_gate_is_text_only_and_retries_first() {
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(r"^.{249}$", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: crate::DeterminizeLimits {
                    max_states: 0,
                    ..crate::DeterminizeLimits::default()
                },
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let mut slow_limits = SlowAotLimits::default();
    slow_limits.determinize.max_states = 0;
    slow_limits.determinize.max_transitions = 0;
    slow_limits.determinize.max_work = 0;
    let selected = compile_with_slow_aot_limits(request(usize::MAX), slow_limits)
        .expect("unbounded whole-window width fixture");
    assert!(selected.module().has_ordered_nfa_whole_window_width_gate());
    assert_eq!(
        selected
            .program()
            .native_ordered_nfa_view()
            .unwrap()
            .whole_window_width_bounds,
        Some(crate::ordered_nfa_native::WholeWindowWidthBounds {
            minimum: 249,
            maximum: 996,
        }),
    );
    let without_width = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width(
        selected.program(), target, false, true, true, true, true, true, false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route lowering without whole-window width gate")
    .with_optimizing_fallbacks_may_continue(
        selected.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!without_width.has_ordered_nfa_whole_window_width_gate());
    assert_eq!(
        selected.module().has_ordered_nfa_start_prefix(),
        without_width.has_ordered_nfa_start_prefix(),
    );
    assert_eq!(
        selected.module().has_ordered_nfa_start_closure_dispatch(),
        without_width.has_ordered_nfa_start_closure_dispatch(),
    );
    assert_eq!(
        selected.module().sections()[1].bytes(),
        without_width.sections()[1].bytes(),
        "width gate must not change Ordered-NFA object/program data",
    );
    assert!(
        selected.module().sections()[0].bytes().len()
            > without_width.sections()[0].bytes().len(),
    );
    let relocation_shapes = |module: &crate::CompiledModule| {
        module
            .relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.section,
                    relocation.kind,
                    relocation.symbol,
                    relocation.addend,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        relocation_shapes(selected.module()),
        relocation_shapes(&without_width),
    );
    let format = crate::ObjectFormat::for_target(target);
    let without_width_object = emit_object(&without_width, format, usize::MAX)
        .expect("emit object without width gate");
    assert!(without_width_object.len() < selected.object().len());
    let selected_one_below = selected
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty width-gated object");
    assert!(without_width_object.len() <= selected_one_below);
    let retried = compile_with_slow_aot_limits(request(selected_one_below), slow_limits)
        .expect("width-gated object one-below retries without width gate");
    assert_eq!(retried.module(), &without_width);
    assert_eq!(retried.object(), without_width_object);

    let exports = PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM);
    let selected_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(usize::MAX),
            exports,
            slow_limits,
        )
        .expect("unbounded width-gated aggregate");
    let serialized = selected
        .program()
        .serialize()
        .expect("serialize width-gate fixture");
    let without_width_aggregate = without_width
        .append_prepared_aggregate_exports(
            exports,
            selected.program().artifact_identity(),
            &serialized,
        )
        .expect("append aggregates without width gate");
    let without_width_aggregate_object =
        emit_object(&without_width_aggregate, format, usize::MAX)
            .expect("emit aggregate without width gate");
    assert!(without_width_aggregate_object.len() < selected_aggregate.object().len());
    let selected_aggregate_one_below = selected_aggregate
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty width-gated aggregate object");
    assert!(without_width_aggregate_object.len() <= selected_aggregate_one_below);
    let retried_aggregate =
        crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
            request(selected_aggregate_one_below),
            exports,
            slow_limits,
        )
        .expect("width-gated aggregate one-below retries without width gate");
    assert_eq!(retried_aggregate.module(), &without_width_aggregate);
    assert_eq!(
        retried_aggregate.object(),
        without_width_aggregate_object,
    );
}

#[test]
fn ordered_nfa_terminal_only_final_object_retry_preserves_scalar_v1() {
    let pattern = format!(
        "(?-u:[\\x00-\\xFF]){}(?-u:[\\x80-\\xFF])\\b",
        "a".repeat(80),
    );
    let target = Target::x86_64_linux();
    let request = |max_object_bytes| {
        CompileRequest::new(pattern.clone(), target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                determinize: crate::DeterminizeLimits {
                    max_states: 0,
                    ..crate::DeterminizeLimits::default()
                },
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let mut slow_limits = SlowAotLimits::default();
    slow_limits.determinize.max_states = 0;
    slow_limits.determinize.max_transitions = 0;
    slow_limits.determinize.max_work = 0;
    let format = crate::ObjectFormat::for_target(target);

    let v3 = compile_with_slow_aot_limits(request(usize::MAX), slow_limits)
        .expect("unbounded terminal-only V3 fixture");
    assert!(!v3.module().has_ordered_nfa_start_prefix());
    assert!(!v3.module().has_ordered_nfa_start_closure_dispatch());
    assert!(v3.module().has_ordered_nfa_terminal_range_object());
    assert!(!v3.module().has_ordered_edge_dispatch_object());
    let scalar = crate::CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators(
        v3.program(),
        target,
        false,
        true,
        false,
        false,
        slow_limits.max_native_data_bytes,
    )
    .expect("same-route scalar V1 lowering")
    .with_optimizing_fallbacks_may_continue(
        v3.module().optimizing_fallbacks_may_continue(),
    );
    assert!(!scalar.has_ordered_nfa_terminal_range_object());
    assert!(!scalar.has_ordered_edge_dispatch_object());
    let scalar_object = emit_object(&scalar, format, usize::MAX)
        .expect("unbounded terminal-only scalar V1 object");
    assert!(scalar_object.len() < v3.object().len());

    let v3_one_below = v3
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty terminal-only V3 object");
    assert!(scalar_object.len() <= v3_one_below);
    let retried = compile_with_slow_aot_limits(request(v3_one_below), slow_limits)
        .expect("terminal-only V3 one-below retries scalar V1");
    assert_eq!(retried.module(), &scalar);
    assert_eq!(retried.object(), scalar_object);

    let exact_v1 = compile_with_slow_aot_limits(request(scalar_object.len()), slow_limits)
        .expect("exact terminal-only scalar V1 boundary");
    assert_eq!(exact_v1.module(), &scalar);
    assert_eq!(exact_v1.object(), scalar_object);
    let v1_one_below = scalar_object
        .len()
        .checked_sub(1)
        .expect("nonempty terminal-only scalar V1 object");
    let incumbent = compile_with_slow_aot_limits(request(v1_one_below), slow_limits)
        .expect("terminal-only scalar V1 one-below reaches incumbent");
    assert_eq!(incumbent.receipt().required_prepare_capabilities, 0);
}

fn oracle(pattern: &str, haystack: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let regex = RegexBuilder::new(pattern).build().expect("oracle build");
    regex
        .find_at(&haystack[..end], start)
        .map(|matched| (matched.start(), matched.end()))
}

fn fixed_width_window_oracle(
    regex: &Regex,
    haystack: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    regex
        .find_at(haystack, start)
        .filter(|matched| matched.end() <= end)
        .map(|matched| (matched.start(), matched.end()))
}

#[test]
fn general_source_pipeline_matches_rust_across_structural_families() {
    let patterns = [
        "",
        "needle",
        "[A-Za-z_][A-Za-z0-9_]*",
        "(?:foo|bar|quux)+",
        "a+?",
        "(?:ab|a)+z",
        r"(?-u:[\x00-\x1f\x80-\xff]{2,5})",
        r"\p{Greek}+",
        r"(?m)^[A-Z][^\r\n]*$",
        r"\b(?:let|const|static)\b",
        r"\A(?:[0-9]{2}:){2}[0-9]{2}\z",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"needle",
        b"xxneedlezz",
        b"fooquuxbar!",
        b"aaaz",
        b"abaz",
        b"\x00\x80xx",
        "\u{03b1}\u{03b2} x".as_bytes(),
        b"x\nTitle here\nz",
        b"a const value",
        b"12:34:56",
    ];

    for pattern in patterns {
        let fast = compile(
            CompileRequest::new(pattern, Target::aarch64_macos())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .unwrap_or_else(|error| panic!("fast compilation failed for {pattern:?}: {error}"));
        let optimized = compile(
            CompileRequest::new(pattern, Target::aarch64_macos())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap_or_else(|error| panic!("optimizing compilation failed for {pattern:?}: {error}"));

        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                let end = haystack.len();
                let window = SearchWindow::new(start, end);
                let expected = MatchResult::Span(oracle(pattern, haystack, start, end));
                assert_eq!(
                    fast.search(haystack, window).unwrap(),
                    expected,
                    "fast: pattern={pattern:?}, start={start}, haystack={haystack:?}"
                );
                assert_eq!(
                    optimized.search(haystack, window).unwrap(),
                    expected,
                    "optimized: pattern={pattern:?}, start={start}, haystack={haystack:?}"
                );
            }
        }
    }
}

#[test]
fn embedded_literal_trie_matches_rust_across_modes_outputs_and_windows() {
    let fixtures: &[(&str, &[u8])] = &[
        (r"(?:zapper|z|zap|foo)q", b"zapq"),
        (r"(?:ing|thing|x)q", b"thingq"),
    ];

    for &(pattern, haystack) in fixtures {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(pattern, Target::aarch64_macos())
                        .mode(mode)
                        .output(output),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "compilation failed for pattern={pattern:?}, mode={mode:?}, \
                         output={output:?}: {error}"
                    )
                });

                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let span = oracle(pattern, haystack, start, end);
                        let expected = match output {
                            OutputContract::Exists => MatchResult::Exists(span.is_some()),
                            OutputContract::SelectedEnd => {
                                MatchResult::SelectedEnd(span.map(|(_, end)| end))
                            }
                            OutputContract::Span => MatchResult::Span(span),
                        };
                        assert_eq!(
                            compiled
                                .search(haystack, SearchWindow::new(start, end))
                                .unwrap(),
                            expected,
                            "pattern={pattern:?}, mode={mode:?}, output={output:?}, \
                             window={start}..{end}, haystack={haystack:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
#[ignore = "one generated 1,024-arm AOT receipt and object gate"]
fn generated_folded_byte_token_trie_emits_a_compact_authenticated_aot_object() {
    const ARMS: usize = 1_024;
    let pattern = generated_folded_captured_dictionary(ARMS);
    let compiled = compile(
        CompileRequest::new(&pattern, Target::aarch64_macos())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists),
    )
    .expect("generated folded-arm AOT compilation");
    let receipt = compiled.receipt();
    assert_eq!(receipt.source_bytes, pattern.len());
    assert!(receipt.thompson_states < 4_096, "{receipt:#?}");
    assert!(receipt.thompson_edges < 8_192, "{receipt:#?}");
    assert!(!compiled.object().is_empty());
    assert_eq!(receipt.object_bytes, compiled.object().len());
    let object_sha256: [u8; 32] = Sha256::digest(compiled.object()).into();
    assert_eq!(receipt.object_sha256, object_sha256);
    assert_eq!(
        compiled
            .search(
                b"xxSHARED-PREFIX-03FFyy",
                SearchWindow::full(b"xxSHARED-PREFIX-03FFyy"),
            )
            .expect("generated folded positive search"),
        MatchResult::Exists(true),
    );
    assert_eq!(
        compiled
            .search(
                b"xxshared-prefix-zzzz",
                SearchWindow::full(b"xxshared-prefix-zzzz"),
            )
            .expect("generated folded negative search"),
        MatchResult::Exists(false),
    );
}

#[test]
fn all_configured_line_terminators_match_rust_for_every_window() {
    let pattern = r"(?m:^a$)";
    let mut lf_digest = None;
    let mut semicolon_digest = None;

    for line_terminator in u8::MIN..=u8::MAX {
        let mut profile = RustProfile::default();
        profile.options.line_terminator = line_terminator;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .profile(profile)
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .unwrap_or_else(|error| {
            panic!("compilation failed for line terminator {line_terminator:#04x}: {error}")
        });

        assert_eq!(compiled.receipt().line_terminator, line_terminator);
        assert_eq!(compiled.program().line_terminator(), line_terminator);
        let serialized = compiled.program().serialize().unwrap();
        assert_eq!(u32::from_le_bytes(serialized[8..12].try_into().unwrap()), 4);
        assert_eq!(serialized[14], line_terminator);
        assert_eq!(serialized[15], 0);
        let restored = crate::CompiledProgram::deserialize(&serialized).unwrap();
        assert_eq!(restored.line_terminator(), line_terminator);
        assert_eq!(restored.serialize().unwrap(), serialized);

        if line_terminator == b'\n' {
            lf_digest = Some(compiled.receipt().automaton_sha256);
        } else if line_terminator == b';' {
            semicolon_digest = Some(compiled.receipt().automaton_sha256);
        }

        let oracle = RegexBuilder::new(pattern)
            .line_terminator(line_terminator)
            .build()
            .expect("bytes oracle accepts every byte line terminator");
        let haystacks = [
            Vec::new(),
            vec![line_terminator],
            vec![b'a'],
            vec![line_terminator, b'a', line_terminator],
            vec![b'x', line_terminator, b'a', line_terminator, b'y'],
            vec![b'a', line_terminator, b'a'],
        ];
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected =
                        MatchResult::Span(fixed_width_window_oracle(&oracle, haystack, start, end));
                    let window = SearchWindow::new(start, end);
                    assert_eq!(
                        compiled.search(haystack, window).unwrap(),
                        expected,
                        "compiled: terminator={line_terminator:#04x}, haystack={haystack:?}, \
                         window={start}..{end}"
                    );
                    assert_eq!(
                        restored.search(haystack, window).unwrap(),
                        expected,
                        "restored: terminator={line_terminator:#04x}, haystack={haystack:?}, \
                         window={start}..{end}"
                    );
                }
            }
        }
    }

    assert_ne!(lf_digest.unwrap(), semicolon_digest.unwrap());
}

#[test]
fn every_target_tuple_emits_the_same_semantic_program() {
    let targets = [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ];
    let pattern = r"(?:[A-Za-z_][A-Za-z0-9_]*::)+item";
    let mut digest = None;
    for target in targets {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
        assert!(!compiled.object().is_empty());
        assert_eq!(compiled.receipt().target.architecture, target.architecture);
        assert_eq!(
            compiled.receipt().target.operating_system,
            target.operating_system
        );
        if let Some(expected) = digest {
            assert_eq!(compiled.receipt().automaton_sha256, expected);
        } else {
            digest = Some(compiled.receipt().automaton_sha256);
        }
        match target.operating_system {
            OperatingSystem::Linux => {
                assert_eq!(&compiled.object()[..4], b"\x7fELF");
                let machine = u16::from_le_bytes([compiled.object()[18], compiled.object()[19]]);
                assert_eq!(
                    machine,
                    match target.architecture {
                        Architecture::X86_64 => 62,
                        Architecture::Aarch64 => 183,
                    }
                );
            }
            OperatingSystem::Macos => {
                assert_eq!(&compiled.object()[..4], &[0xcf, 0xfa, 0xed, 0xfe]);
                let cpu = u32::from_le_bytes([
                    compiled.object()[4],
                    compiled.object()[5],
                    compiled.object()[6],
                    compiled.object()[7],
                ]);
                assert_eq!(
                    cpu,
                    match target.architecture {
                        Architecture::X86_64 => 0x0100_0007,
                        Architecture::Aarch64 => 0x0100_000c,
                    }
                );
            }
        }
    }
}

#[test]
fn slow_aot_is_target_neutral_across_os_and_feature_tiers() {
    let x86_avx2 = Target::x86_64_linux()
        .with_features(FeatureSet::of(CpuFeature::X86Avx2))
        .expect("AVX2 target");
    let x86_avx512 = Target::x86_64_macos()
        .with_features(
            FeatureSet::of(CpuFeature::X86Avx512F)
                .with(CpuFeature::X86Avx512Bw)
                .with(CpuFeature::X86Avx512Vl),
        )
        .expect("AVX-512 target");
    let aarch64_asimd = Target::aarch64_macos()
        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .expect("ASIMD target");
    let aarch64_sve = Target::aarch64_linux()
        .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
        .expect("SVE target");
    let aarch64_sve2 = Target::aarch64_linux()
        .with_features(
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        )
        .expect("SVE2 target");
    let targets = [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        x86_avx2,
        x86_avx512,
        Target::aarch64_linux(),
        Target::aarch64_macos(),
        aarch64_asimd,
        aarch64_sve,
        aarch64_sve2,
    ];
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let mut program_digest = None;
    let mut slow_determinization = None;
    let mut slow_dfa = None;
    let mut slow_allocation = None;
    for target in targets {
        let compiled = compile(
            CompileRequest::new("a+Q|[b-c][a-b]{1,5}(?:x+|y+)", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(limits),
        )
        .unwrap_or_else(|error| panic!("slow AOT target {target:?}: {error}"));
        let report = compiled
            .receipt()
            .slow_aot
            .as_ref()
            .unwrap_or_else(|| panic!("slow candidate was not selected for {target:?}"));
        assert!(!compiled.receipt().runtime_helper_required, "{target:?}");
        assert_ne!(compiled.receipt().start_accelerator, StartAccelerator::None);
        assert!(report.native_data_bytes <= report.effective_native_data_limit_bytes);
        assert_eq!(
            compiled
                .search(b"xxcbbbbx", SearchWindow::full(b"xxcbbbbx"))
                .unwrap(),
            MatchResult::SelectedEnd(Some(8))
        );

        if let Some(expected) = program_digest {
            assert_eq!(compiled.receipt().program_sha256, expected, "{target:?}");
            assert_eq!(
                &report.determinization,
                slow_determinization.as_ref().unwrap(),
                "{target:?}"
            );
            assert_eq!(report.dfa, slow_dfa.unwrap(), "{target:?}");
            assert_eq!(report.allocation_bytes, slow_allocation.unwrap(), "{target:?}");
        } else {
            program_digest = Some(compiled.receipt().program_sha256);
            slow_determinization = Some(report.determinization.clone());
            slow_dfa = Some(report.dfa);
            slow_allocation = Some(report.allocation_bytes);
        }
    }
}

#[test]
fn compiler_invocation_does_not_depend_on_recipe_recognition() {
    let patterns = [
        "literal",
        "[ab]+z",
        "(?:ab|cd){2,7}",
        "(?:a+?b|c*d)e",
        r"(?m)^\w+\b",
        r"\p{Greek}{1,4}",
    ];
    for pattern in patterns {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux()).mode(CompileMode::Optimizing),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} was not generally compiled: {error}"));
        assert_ne!(compiled.receipt().thompson_states, 0, "{pattern:?}");
        assert!(!compiled.object().is_empty(), "{pattern:?}");
    }
}

#[test]
fn determinization_limit_changes_engine_not_compiler_eligibility() {
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let compiled = compile(
        CompileRequest::new("(?:ab|ac|ad)+z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .limits(limits),
    )
    .unwrap();
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.receipt().engine_selection_reason,
        EngineSelectionReason::DeterminizationResourceLimit
    );
    assert_eq!(
        compiled
            .search(b"xxabacadz", SearchWindow::full(b"xxabacadz"))
            .unwrap(),
        MatchResult::Span(Some((2, 9)))
    );
}

#[test]
fn compiled_regex_facade_executes_retained_rows_on_amortized_windows() {
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 8;
    let compiled = compile(
        CompileRequest::new(r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)", Target::aarch64_macos())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits),
    )
    .unwrap();
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.receipt().engine_selection_reason,
        EngineSelectionReason::DeterminizationResourceLimit
    );
    assert!(compiled.program().has_retained_partial_dfa());

    let mut haystack = vec![b'x'; 300];
    haystack.extend_from_slice(b"cbbbbx");
    let window = SearchWindow::full(&haystack);
    let expected = MatchResult::SelectedEnd(Some(haystack.len()));
    let mut workspace = compiled.prepare_workspace().unwrap();
    assert_eq!(
        compiled
            .search_with_workspace(&haystack, window, &mut workspace)
            .unwrap(),
        expected
    );
    assert_eq!(compiled.search(&haystack, window).unwrap(), expected);
}

#[test]
fn contextual_selected_end_reuses_authenticated_ordered_nfa_workspace() {
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let compiled = compile(
        CompileRequest::new(r"(?m)^(?:ab|a)", Target::aarch64_macos())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits),
    )
    .unwrap();
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        compiled.receipt().engine_selection_reason,
        EngineSelectionReason::ContextAssertions,
    );

    let mut haystack = vec![b'!'; 4096];
    haystack[..2].copy_from_slice(b"ab");
    let window = SearchWindow::full(&haystack);
    let expected = MatchResult::SelectedEnd(Some(2));
    let mut workspace = compiled.prepare_workspace().unwrap();
    assert_eq!(
        compiled
            .search_with_workspace(&haystack, window, &mut workspace)
            .unwrap(),
        expected,
    );
    assert_eq!(
        compiled
            .search_with_workspace(&haystack, window, &mut workspace)
            .unwrap(),
        expected,
    );
}

#[test]
fn stable_dfa_work_ceiling_and_effective_limits_are_explicit() {
    assert_eq!(
        crate::DeterminizeLimits::unlimited().max_work,
        MAX_STABLE_DFA_BUILD_WORK
    );

    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_work = u64::MAX;
    let compiled = compile(
        CompileRequest::new("abc", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits),
    )
    .unwrap();
    let report = &compiled.receipt().determinization;
    assert_eq!(report.requested_limits.max_work, u64::MAX);
    assert_eq!(report.effective_limits.max_work, MAX_STABLE_DFA_BUILD_WORK);
    assert!(report.decline.is_none());
    assert_eq!(
        report.work_completed,
        compiled.receipt().dfa.expect("complete DFA").build_work
    );
}

#[test]
fn graph_alphabet_construction_width_is_receipt_closed() {
    let compiled = compile(
        CompileRequest::new("(?:[a-z]|mX)+(?:[D-Z]q|!)?", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists),
    )
    .unwrap();
    let receipt = compiled.receipt();
    let stats = receipt.dfa.expect("complete DFA");
    assert!(stats.graph_classes < stats.boundary_classes);
    assert!(stats.alphabet_classes <= stats.graph_classes);
    assert_eq!(stats.reverse_states_before_minimization, 0);
    assert_eq!(
        receipt.determinization.transitions_completed,
        stats
            .forward_states_before_minimization
            .checked_mul(stats.graph_classes)
            .expect("small construction table")
    );
    assert_eq!(receipt.determinization.work_completed, stats.build_work);
    assert_eq!(receipt.determinization.decline, None);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all route and decline variants are compared in one receipt contract test"
)]
fn determinization_receipt_records_skips_completion_and_exact_declines() {
    let fast = compile(CompileRequest::new("abc", Target::x86_64_linux()).mode(CompileMode::Fast))
        .unwrap();
    let context = compile(
        CompileRequest::new(r"(?m)^abc", Target::x86_64_linux()).mode(CompileMode::Optimizing),
    )
    .unwrap();
    for skipped in [&fast, &context] {
        let report = &skipped.receipt().determinization;
        assert!(report.attempted_stages.is_empty());
        assert!(report.completed_stages.is_empty());
        assert_eq!(report.work_completed, 0);
        assert!(report.decline.is_none());
    }

    let completed = compile(
        CompileRequest::new("abc", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
    )
    .unwrap();
    let report = &completed.receipt().determinization;
    assert_eq!(report.attempted_stages, report.completed_stages);
    assert_eq!(
        report.attempted_stages.as_ref(),
        &[
            DeterminizationStage::AlphabetPartition,
            DeterminizationStage::ForwardSubsetConstruction,
            DeterminizationStage::DfaStateMinimization,
            DeterminizationStage::AlphabetColumnCoalescing,
        ]
    );
    assert!(report.decline.is_none());
    assert_eq!(completed.receipt().dfa.unwrap().reverse_states, 0);

    let compile_decline = |max_states, max_transitions, max_work| {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = max_states;
        limits.determinize.max_transitions = max_transitions;
        limits.determinize.max_work = max_work;
        compile(
            CompileRequest::new("abc", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(limits),
        )
        .unwrap()
    };

    let state = compile_decline(0, usize::MAX, MAX_STABLE_DFA_BUILD_WORK);
    let state_decline = state
        .receipt()
        .determinization
        .decline
        .expect("state decline");
    assert_eq!(
        state_decline.stage,
        DeterminizationStage::ForwardSubsetConstruction
    );
    assert!(matches!(
        state_decline.resource,
        DeterminizationResource::States {
            limit: 0,
            required: 1
        }
    ));
    assert!(
        state
            .receipt()
            .passes
            .contains(&OptimizationPass::AlphabetPartition)
    );
    assert!(
        !state
            .receipt()
            .passes
            .contains(&OptimizationPass::OrderedDeterminization)
    );

    let transition = compile_decline(usize::MAX, 0, MAX_STABLE_DFA_BUILD_WORK);
    let transition_decline = transition
        .receipt()
        .determinization
        .decline
        .expect("transition decline");
    assert_eq!(
        transition_decline.stage,
        DeterminizationStage::ForwardSubsetConstruction
    );
    assert!(matches!(
        transition_decline.resource,
        DeterminizationResource::Transitions {
            limit: 0,
            required
        } if required > 0
    ));

    let work = compile_decline(usize::MAX, usize::MAX, 0);
    let work_decline = work
        .receipt()
        .determinization
        .decline
        .expect("work decline");
    assert_eq!(work_decline.stage, DeterminizationStage::AlphabetPartition);
    assert_eq!(
        work_decline.resource,
        DeterminizationResource::Work {
            limit: 0,
            required: 1,
        }
    );
    assert_eq!(work_decline.work_completed, 0);
    assert!(work.receipt().determinization.completed_stages.is_empty());
}

#[test]
fn engine_selection_receipt_is_structural_and_explicit() {
    let fast =
        compile(CompileRequest::new("[ab]+z", Target::x86_64_linux()).mode(CompileMode::Fast))
            .unwrap();
    let optimized = compile(
        CompileRequest::new("[ab]+z", Target::x86_64_linux()).mode(CompileMode::Optimizing),
    )
    .unwrap();
    let asserted = compile(
        CompileRequest::new(r"(?m)^[ab]+z$", Target::x86_64_linux()).mode(CompileMode::Optimizing),
    )
    .unwrap();

    assert_eq!(
        fast.receipt().engine_selection_reason,
        EngineSelectionReason::FastMode
    );
    assert_eq!(
        optimized.receipt().engine_selection_reason,
        EngineSelectionReason::CompleteDfa
    );
    assert_eq!(
        asserted.receipt().engine_selection_reason,
        EngineSelectionReason::CompleteContextDfa
    );
    assert_eq!(
        fast.program().engine_selection_reason(),
        Some(EngineSelectionReason::FastMode)
    );
    assert_eq!(
        optimized.program().engine_selection_reason(),
        Some(EngineSelectionReason::CompleteDfa)
    );
    assert_eq!(asserted.receipt().engine, EngineKind::OrderedContextDfa);
    assert_eq!(
        asserted.program().engine_selection_reason(),
        Some(EngineSelectionReason::CompleteContextDfa)
    );

    let restored_fast =
        crate::CompiledProgram::deserialize(&fast.program().serialize().unwrap()).unwrap();
    let restored_optimized =
        crate::CompiledProgram::deserialize(&optimized.program().serialize().unwrap()).unwrap();
    assert_eq!(restored_fast.engine_selection_reason(), None);
    assert_eq!(
        restored_optimized.engine_selection_reason(),
        Some(EngineSelectionReason::CompleteDfa)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "direct, restored, resource-declined, and unsupported contextual routes form one contract"
)]
fn context_native_and_context_fallback_receipts_name_the_actual_routes() {
    let pattern = r"(?-u:\b(?:foo|bar)\b)";
    let direct = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
    )
    .unwrap();
    assert_eq!(direct.receipt().engine, EngineKind::OrderedContextDfa);
    assert_eq!(
        direct.receipt().engine_selection_reason,
        EngineSelectionReason::CompleteContextDfa
    );
    assert!(!direct.receipt().runtime_helper_required);
    assert_eq!(direct.module().required_runtime_symbol(), None);
    assert_eq!(direct.receipt().dfa, None);
    let complete = direct
        .receipt()
        .context_determinization
        .as_ref()
        .expect("fresh context report");
    let stats = complete.stats.expect("complete context stats");
    assert_eq!(complete.decline, None);
    assert_eq!(Some(stats), direct.program().context_dfa_stats());
    assert!(stats.forward_states > 0);
    assert!(stats.reverse_states > 0);
    assert!(
        direct
            .receipt()
            .passes
            .contains(&OptimizationPass::ContextOrderedDeterminization)
    );
    assert!(
        direct
            .receipt()
            .passes
            .contains(&OptimizationPass::ContextNativeLowering)
    );
    assert!(
        !direct
            .receipt()
            .passes
            .contains(&OptimizationPass::UniversalOrderedTnfa)
    );
    assert!(
        !direct
            .receipt()
            .passes
            .contains(&OptimizationPass::RuntimeAdapterLowering)
    );

    // Context sidecars and their receipts remain deliberately outside the
    // stable V2 wire format. Re-lowering a restored program truthfully takes
    // the universal runtime-backed route.
    let restored = crate::CompiledProgram::deserialize(&direct.program().serialize().unwrap())
        .expect("restore stable context artifact");
    assert_eq!(restored.engine_kind(), EngineKind::OrderedNfa);
    assert_eq!(restored.engine_selection_reason(), None);
    assert_eq!(restored.context_determinization_report(), None);
    let restored_module = crate::CompiledModule::lower(&restored, Target::x86_64_linux()).unwrap();
    assert!(restored_module.required_runtime_symbol().is_some());
    assert!(restored_module.prepared_entry_symbol().is_some());
    assert_eq!(
        restored_module.required_prepared_fallback_runtime_symbol(),
        Some("fre_aot_regex_runtime_search_exclusive_v1")
    );

    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_work = 0;
    // Refuse both the ordinary contextual attempt and the separately
    // budgeted slow-context retry. The latter can now recover this graph into
    // a self-contained native module, so constraining only the first attempt
    // no longer constructs the runtime-fallback route this test audits.
    let declined = compile_with_slow_aot_limits(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits),
        SlowAotLimits {
            determinize: crate::DeterminizeLimits {
                max_work: 0,
                ..crate::DeterminizeLimits::default()
            },
            ..SlowAotLimits::default()
        },
    )
    .unwrap();
    assert_eq!(declined.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        declined.receipt().engine_selection_reason,
        EngineSelectionReason::ContextAssertions
    );
    assert!(declined.receipt().slow_context_aot.is_none());
    assert!(declined.receipt().runtime_helper_required);
    assert!(declined.module().prepared_entry_symbol().is_some());
    assert_eq!(
        declined
            .module()
            .required_prepared_fallback_runtime_symbol(),
        Some("fre_aot_regex_runtime_search_exclusive_v1")
    );
    let decline = declined
        .receipt()
        .context_determinization
        .as_ref()
        .and_then(|report| report.decline)
        .expect("context work decline");
    assert_eq!(
        decline.resource,
        ContextDfaResource::Work {
            limit: 0,
            required: 1,
        }
    );
    assert!(
        declined
            .receipt()
            .passes
            .contains(&OptimizationPass::UniversalOrderedTnfa)
    );
    assert!(
        declined
            .receipt()
            .passes
            .contains(&OptimizationPass::RuntimeAdapterLowering)
    );
    assert!(
        !declined
            .receipt()
            .passes
            .contains(&OptimizationPass::ContextNativeLowering)
    );

    let unsupported = compile(
        CompileRequest::new(r"\bfoo\b", Target::x86_64_linux()).mode(CompileMode::Optimizing),
    )
    .unwrap();
    assert_eq!(unsupported.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        unsupported.receipt().engine_selection_reason,
        EngineSelectionReason::ContextAssertions
    );
    assert!(unsupported.receipt().runtime_helper_required);
    assert!(unsupported.module().prepared_entry_symbol().is_some());
    assert_eq!(
        unsupported
            .module()
            .required_prepared_fallback_runtime_symbol(),
        Some("fre_aot_regex_runtime_search_exclusive_v1")
    );
    assert!(
        unsupported
            .receipt()
            .passes
            .contains(&OptimizationPass::RuntimeAdapterLowering)
    );
    assert!(matches!(
        unsupported
            .receipt()
            .context_determinization
            .as_ref()
            .and_then(|report| report.decline)
            .map(|decline| decline.resource),
        Some(ContextDfaResource::UnsupportedAssertion(
            fre_automata::EdgeKind::AssertWordUnicode
        ))
    ));
}

#[test]
fn receipt_digests_exact_program_and_object_artifacts() {
    let compiled = compile(
        CompileRequest::new("(?:foo|bar)+[0-9]{2}", Target::aarch64_linux())
            .mode(CompileMode::Optimizing),
    )
    .unwrap();
    let program = compiled.program().serialize().unwrap();
    let expected_program: [u8; 32] = Sha256::digest(&program).into();
    let expected_object: [u8; 32] = Sha256::digest(compiled.object()).into();

    assert_eq!(compiled.receipt().program_sha256, expected_program);
    assert_eq!(compiled.receipt().object_sha256, expected_object);
    assert_eq!(
        compiled.program().serialized_sha256().unwrap(),
        expected_program
    );
}

#[test]
fn required_runtime_symbol_distinguishes_adapter_and_native_modules() {
    let fast =
        compile(CompileRequest::new("[ab]+z", Target::aarch64_macos()).mode(CompileMode::Fast))
            .unwrap();
    let optimized = compile(
        CompileRequest::new("[ab]+z", Target::aarch64_macos()).mode(CompileMode::Optimizing),
    )
    .unwrap();

    assert_eq!(
        fast.module().required_runtime_symbol(),
        Some(fast.module().runtime_symbol())
    );
    assert_eq!(
        optimized.module().runtime_symbol(),
        fast.module().runtime_symbol()
    );
    assert_eq!(optimized.module().required_runtime_symbol(), None);
    assert!(fast.receipt().runtime_helper_required);
    assert!(!optimized.receipt().runtime_helper_required);
}

#[test]
fn receipt_reports_actual_native_acceleration_and_data_extent() {
    let fast =
        compile(CompileRequest::new("[ab]+z", Target::x86_64_linux()).mode(CompileMode::Fast))
            .unwrap();
    let optimized = compile(
        CompileRequest::new("[ab]+z", Target::x86_64_linux()).mode(CompileMode::Optimizing),
    )
    .unwrap();

    // Fast mode retains the universal runtime route, but assertion-free
    // ordered NFAs can also publish a graph-derived prepared dynamic-row
    // entry. This fixture's dynamic root has the baseline x86 SSE2 scanner.
    assert_eq!(
        fast.receipt().start_accelerator,
        StartAccelerator::X86Sse2
    );
    assert_eq!(
        fast.receipt().anchored_prefix,
        optimized.receipt().anchored_prefix
    );
    assert!(fast.receipt().anchored_prefix.guaranteed_bytes >= 2);
    assert_eq!(fast.receipt().anchored_prefix_filter_bytes, 0);
    assert!(optimized.receipt().anchored_prefix_filter_bytes >= 2);
    assert!(
        fast.receipt()
            .passes
            .contains(&OptimizationPass::AnchoredPrefixAnalysis)
    );
    assert!(
        fast.receipt()
            .passes
            .contains(&OptimizationPass::RuntimeAdapterLowering)
    );
    assert!(
        !fast
            .receipt()
            .passes
            .contains(&OptimizationPass::StartStateScanAcceleration)
    );
    assert!(
        optimized
            .receipt()
            .passes
            .contains(&OptimizationPass::AnchoredPrefixCandidateFilter)
    );
    assert_eq!(
        optimized.receipt().start_accelerator,
        StartAccelerator::X86Sse2
    );
    assert!(
        optimized
            .receipt()
            .passes
            .contains(&OptimizationPass::StartStateScanAcceleration)
    );
    let expected_data_bytes = optimized
        .module()
        .sections()
        .iter()
        .filter(|section| section.kind == SectionKind::ReadOnlyData)
        .map(|section| section.data.len())
        .sum();
    assert_eq!(optimized.receipt().data_bytes, expected_data_bytes);
}

#[test]
fn objects_and_receipts_are_deterministic() {
    let request = || {
        CompileRequest::new("(?:foo|bar)+[0-9]{2}", Target::aarch64_linux())
            .mode(CompileMode::Optimizing)
    };
    let first = compile(request()).unwrap();
    let second = compile(request()).unwrap();
    assert_eq!(first.object(), second.object());
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first.module(), second.module());
    assert_eq!(first.receipt().line_terminator, b'\n');
    assert_eq!(first.program().line_terminator(), b'\n');
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one cross-target audit keeps proof admission, additive identity, local relocation, receipts, and exact-base decline together"
)]
fn exact_finite_selected_end_grep_count_is_authenticated_additive_and_resource_atomic() {
    let request = |target| {
        CompileRequest::new("alpha|alphabet|beta", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
    };
    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        let ordinary = compile(request(target)).expect("ordinary SelectedEnd object");
        assert!(
            ordinary
                .module()
                .exact_finite_selected_end_grep_count_aot_report()
                .is_none()
        );
        assert!(ordinary.module().prepared_grep_count_symbol().is_none());

        let compiled = compile_with_exact_finite_selected_end_grep_count(request(target))
            .expect("exact-finite line-jump GrepCount object");
        let repeated = compile_with_exact_finite_selected_end_grep_count(request(target))
            .expect("deterministic exact-finite line-jump GrepCount object");
        assert_eq!(compiled.object(), repeated.object());
        assert_eq!(compiled.module(), repeated.module());
        assert_eq!(compiled.receipt(), repeated.receipt());
        assert_eq!(
            compiled.program().serialize().expect("additive program"),
            ordinary.program().serialize().expect("ordinary program"),
        );
        assert_eq!(
            compiled.module().entry_symbol(),
            ordinary.module().entry_symbol()
        );
        assert_eq!(
            compiled.module().prepared_aggregate_exports(),
            PreparedAggregateExports::GREP_COUNT,
        );
        assert_eq!(
            compiled.module().prepared_aggregate_strategy(),
            Some(PreparedAggregateStrategy::NativeFused),
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_exports,
            PreparedAggregateExports::GREP_COUNT,
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeFused),
        );
        assert_eq!(compiled.receipt().required_prepare_capabilities, 0);
        assert!(!compiled.receipt().runtime_helper_required);
        assert!(
            compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(
            compiled
                .receipt()
                .passes
                .contains(&OptimizationPass::PreparedAggregateLowering)
        );

        let report = compiled
            .module()
            .exact_finite_selected_end_grep_count_aot_report()
            .copied()
            .expect("authenticated line-jump report");
        assert_eq!(
            report.artifact_identity,
            compiled.program().artifact_identity()
        );
        assert_eq!(report.output, OutputContract::SelectedEnd);
        assert_eq!(report.source_count, 3);
        assert_eq!(report.source_bytes, 17);
        assert_eq!(report.maximum_width, 8);

        let text = compiled
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("line-jump text");
        let ordinary_text = ordinary
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("ordinary text");
        let ordinary_entry = ordinary
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == ordinary.module().entry_symbol())
            .expect("ordinary entry record");
        let ordinary_start = usize::try_from(ordinary_entry.offset).expect("ordinary offset");
        let ordinary_size = usize::try_from(ordinary_entry.size).expect("ordinary size");
        let ordinary_end = ordinary_start
            .checked_add(ordinary_size)
            .expect("ordinary extent");
        assert_eq!(report.ordinary_entry_offset, ordinary_start);
        assert_eq!(
            text.bytes().get(ordinary_start..ordinary_end),
            ordinary_text.bytes().get(ordinary_start..ordinary_end),
            "additive reducer changed its local ordinary target",
        );
        assert_eq!(
            report.ordinary_entry_sha256,
            <[u8; 32]>::from(Sha256::digest(
                ordinary_text
                    .bytes()
                    .get(ordinary_start..ordinary_end)
                    .expect("ordinary entry bytes"),
            )),
        );

        let reducer_name = compiled
            .module()
            .prepared_grep_count_symbol()
            .expect("line-jump GrepCount symbol");
        let reducer = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == reducer_name)
            .expect("line-jump GrepCount record");
        let reducer_start = usize::try_from(reducer.offset).expect("reducer offset");
        let reducer_size = usize::try_from(reducer.size).expect("reducer size");
        let reducer_end = reducer_start
            .checked_add(reducer_size)
            .expect("reducer extent");
        assert_eq!(report.reducer_entry_offset, reducer_start);
        assert_eq!(
            report.reducer_code_sha256,
            <[u8; 32]>::from(Sha256::digest(
                text.bytes()
                    .get(reducer_start..reducer_end)
                    .expect("reducer bytes"),
            )),
        );
        assert!((reducer_start..reducer_end).contains(&report.local_call_offset));
        let local_target = match target.architecture {
            Architecture::X86_64 => {
                assert_eq!(text.bytes()[report.local_call_offset - 1], 0xe8);
                let displacement = i32::from_le_bytes(
                    text.bytes()[report.local_call_offset..report.local_call_offset + 4]
                        .try_into()
                        .expect("x86 local-call displacement"),
                );
                usize::try_from(
                    i64::try_from(report.local_call_offset + 4)
                        .expect("x86 call site")
                        .checked_add(i64::from(displacement))
                        .expect("x86 local-call target"),
                )
                .expect("non-negative x86 local-call target")
            }
            Architecture::Aarch64 => {
                let instruction = u32::from_le_bytes(
                    text.bytes()[report.local_call_offset..report.local_call_offset + 4]
                        .try_into()
                        .expect("AArch64 local-call instruction"),
                );
                assert_eq!(instruction & 0xfc00_0000, 0x9400_0000);
                let words = ((instruction << 6) as i32) >> 6;
                usize::try_from(
                    i64::try_from(report.local_call_offset)
                        .expect("AArch64 call site")
                        .checked_add(i64::from(words) * 4)
                        .expect("AArch64 local-call target"),
                )
                .expect("non-negative AArch64 local-call target")
            }
        };
        assert_eq!(local_target, ordinary_start);

        let identity_index = compiled
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == ".Lfre_aot_regex_exact_finite_grep_count_identity")
            .expect("line-jump identity symbol");
        let identity = &compiled.module().symbols()[identity_index];
        let identity_section = identity.section.expect("identity data section");
        let identity_start = usize::try_from(identity.offset).expect("identity offset");
        assert_eq!(
            &compiled.module().sections()[identity_section].data
                [identity_start..identity_start + 32],
            compiled.program().artifact_identity(),
        );
        let reducer_relocations = compiled
            .module()
            .relocations()
            .iter()
            .filter(|relocation| {
                relocation.section == reducer.section.expect("reducer text section")
                    && relocation.offset >= reducer.offset
                    && relocation.offset < reducer.offset + reducer.size
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reducer_relocations.len(),
            match target.architecture {
                Architecture::X86_64 => 1,
                Architecture::Aarch64 => 2,
            },
        );
        assert!(
            reducer_relocations
                .iter()
                .all(|relocation| relocation.symbol == identity_index)
        );

        let serialized = compiled.program().serialize().expect("preparation bytes");
        let (program_name, program_len) = compiled
            .module()
            .required_runtime_program()
            .expect("line-jump preparation program");
        assert_eq!(program_len, serialized.len());
        let program = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == program_name)
            .expect("preparation program record");
        let program_section = program.section.expect("preparation data section");
        let program_start = usize::try_from(program.offset).expect("program offset");
        assert_eq!(
            &compiled.module().sections()[program_section].data
                [program_start..program_start + program_len],
            serialized,
        );

        let mut limits = CompileLimitsV1::default();
        limits.max_object_bytes = ordinary.object().len();
        let capped_request = request(target).limits(limits);
        let capped_base = compile(capped_request.clone()).expect("capped exact base");
        let declined = compile_with_exact_finite_selected_end_grep_count(capped_request)
            .expect("optional line-jump object-byte decline");
        assert_eq!(declined.object(), capped_base.object());
        assert_eq!(declined.module(), capped_base.module());
        assert_eq!(declined.receipt(), capped_base.receipt());
        assert!(
            declined
                .module()
                .exact_finite_selected_end_grep_count_aot_report()
                .is_none()
        );
    }
}

#[test]
fn exact_finite_selected_end_grep_count_declines_closed_and_preserves_existing_apis() {
    let target = Target::x86_64_linux();
    for pattern in [
        r"alpha\nbeta",
        r"alpha\rbeta",
        "alpha+",
        "(?:alpha)?",
        "^alpha",
    ] {
        let request = CompileRequest::new(pattern, target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd);
        let ordinary = compile(request.clone()).expect("ordinary decline fixture");
        let declined = compile_with_exact_finite_selected_end_grep_count(request)
            .expect("structural line-jump decline");
        assert_eq!(declined.object(), ordinary.object(), "{pattern:?}");
        assert_eq!(declined.module(), ordinary.module(), "{pattern:?}");
        assert_eq!(declined.receipt(), ordinary.receipt(), "{pattern:?}");
    }

    let fast_request = CompileRequest::new("alpha|beta", target)
        .mode(CompileMode::Fast)
        .output(OutputContract::SelectedEnd);
    let fast = compile(fast_request.clone()).expect("ordinary Fast fixture");
    let fast_declined = compile_with_exact_finite_selected_end_grep_count(fast_request)
        .expect("Fast mode has no source-authenticated finite sidecar");
    assert_eq!(fast_declined.object(), fast.object());
    assert_eq!(fast_declined.module(), fast.module());

    let generic = compile_with_prepared_aggregate_exports(
        CompileRequest::new("alpha|beta", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd),
        PreparedAggregateExports::GREP_COUNT,
    )
    .expect("existing generic GrepCount API");
    assert!(
        generic
            .module()
            .exact_finite_selected_end_grep_count_aot_report()
            .is_none()
    );

    assert!(matches!(
        compile_with_exact_finite_selected_end_grep_count(
            CompileRequest::new("alpha", target).output(OutputContract::Exists),
        ),
        Err(ExactFiniteGrepCountCompileError::RequiresSelectedEnd {
            actual: OutputContract::Exists,
        }),
    ));
}

#[test]
fn exact_finite_grep_count_object_decline_does_not_swallow_failures() {
    assert_eq!(
        crate::classify_exact_finite_grep_count_object_attempt(Ok(vec![1, 2, 3]))
            .expect("successful optional object"),
        Some(vec![1, 2, 3]),
    );
    assert_eq!(
        crate::classify_exact_finite_grep_count_object_attempt(Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 10,
            required: 11,
        },))
        .expect("numeric object-byte decline"),
        None,
    );
    assert!(matches!(
        crate::classify_exact_finite_grep_count_object_attempt(Err(ObjectError::Allocation(
            "synthetic exact-finite GrepCount allocation"
        ),)),
        Err(CompileError::Object(ObjectError::Allocation(
            "synthetic exact-finite GrepCount allocation",
        ))),
    ));
    assert!(matches!(
        crate::classify_exact_finite_grep_count_object_attempt(Err(ObjectError::InvalidModule(
            "synthetic exact-finite GrepCount backend"
        ),)),
        Err(CompileError::Object(ObjectError::InvalidModule(
            "synthetic exact-finite GrepCount backend",
        ))),
    ));
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes the generated line-jump reducer against the real runtime"]
fn linked_host_exact_finite_selected_end_grep_count_matches_line_oracle() {
    use std::{fs, process::Command, time::SystemTime};

    let target = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        }
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
    } else {
        Target::aarch64_macos()
    };
    let compiled = compile_with_exact_finite_selected_end_grep_count(
        CompileRequest::new("alpha|beta", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd),
    )
    .expect("host line-jump artifact");
    let foreign = compile_with_exact_finite_selected_end_grep_count(
        CompileRequest::new("gamma|delta", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd),
    )
    .expect("foreign line-jump artifact");
    let reducer = compiled
        .module()
        .prepared_grep_count_symbol()
        .expect("host line-jump symbol");
    let (program, program_len) = compiled
        .module()
        .required_runtime_program()
        .expect("host preparation program");
    let (foreign_program, foreign_program_len) = foreign
        .module()
        .required_runtime_program()
        .expect("foreign preparation program");
    let source = format!(
        r#"#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef void *handle_t;
extern const unsigned char {program}[];
extern const unsigned char {foreign_program}[];
extern uint32_t {reducer}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(const unsigned char*,size_t,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
static const unsigned char empty_source[1]={{0}};
static const unsigned char negative[]={{'z','z','z'}};
static const unsigned char one[]={{'a','l','p','h','a'}};
static const unsigned char twice_one_line[]={{'a','l','p','h','a',' ','b','e','t','a'}};
static const unsigned char two_lines[]={{'a','l','p','h','a','\n','b','e','t','a','\n','z'}};
static const unsigned char crlf[]={{'z','\r','\n','a','l','p','h','a','\r','\n'}};
static const unsigned char empty_lines[]={{'\n','a','l','p','h','a','\n','\n','b','e','t','a'}};
static const unsigned char trailing_lf[]={{'b','e','t','a','\n'}};
static const unsigned char binary[]={{0xff,'a','l','p','h','a',0x80,'\n',0x00,'b','e','t','a',0xfe}};
#define CHECK(H,L,E,C) do{{uint64_t value=UINT64_C(0x1122334455667788);if({reducer}(right,(H),(L),&value)!=0U||value!=(uint64_t)(E))return (C);}}while(0)
int main(void){{
  handle_t right=0,wrong=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({program},{program_len}U,&right)!=0U)return 1;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({foreign_program},{foreign_program_len}U,&wrong)!=0U)return 2;
  CHECK(empty_source,0U,0U,3);
  CHECK(negative,sizeof(negative),0U,4);
  CHECK(one,sizeof(one),1U,5);
  CHECK(twice_one_line,sizeof(twice_one_line),1U,6);
  CHECK(two_lines,sizeof(two_lines),2U,7);
  CHECK(crlf,sizeof(crlf),1U,8);
  CHECK(empty_lines,sizeof(empty_lines),2U,9);
  CHECK(trailing_lf,sizeof(trailing_lf),1U,10);
  CHECK(binary,sizeof(binary),2U,11);
  uint64_t out=UINT64_C(0x8877665544332211);
  if({reducer}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out)!=3U||out!=UINT64_C(0x8877665544332211))return 12;
  if({reducer}((handle_t)0,(const unsigned char*)(uintptr_t)1,8U,&out)!=5U||out!=UINT64_C(0x8877665544332211))return 13;
  if({reducer}(right,(const unsigned char*)0,0U,&out)!=2U||out!=UINT64_C(0x8877665544332211))return 14;
  if({reducer}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x8877665544332211))return 15;
  unsigned char bytes[17];memset(bytes,0xa5,sizeof(bytes));
  if({reducer}(right,one,sizeof(one),(uint64_t*)(void*)(bytes+1))!=2U)return 16;
  for(size_t i=0;i<sizeof(bytes);i++)if(bytes[i]!=0xa5U)return 17;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U)return 18;
  if(fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U)return 19;
  return 0;
}}
"#,
    );
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-exact-finite-grep-count-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create line-jump linker directory");
    let object = directory.join("line-jump.o");
    let foreign_object = directory.join("foreign.o");
    let c_path = directory.join("line-jump.c");
    let executable = directory.join("line-jump");
    fs::write(&object, compiled.object()).expect("write line-jump object");
    fs::write(&foreign_object, foreign.object()).expect("write foreign object");
    fs::write(&c_path, source).expect("write line-jump C harness");
    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the linked runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let status = Command::new(compiler)
        .arg("-O0")
        .arg(&c_path)
        .arg(&object)
        .arg(&foreign_object)
        .arg(&static_runtime)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("link line-jump harness");
    assert!(status.success(), "line-jump harness failed to link");
    let output = Command::new(&executable)
        .output()
        .expect("execute line-jump harness");
    assert!(
        output.status.success(),
        "line-jump status={:?}, stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::remove_dir_all(&directory).expect("remove line-jump linker directory");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one cross-target audit keeps the additive object, receipt, symbol, code, and relocation invariants together"
)]
fn prepared_aggregate_exports_are_additive_authenticated_and_cross_target() {
    let request = |target| {
        CompileRequest::new("a+|bc", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
    };
    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        let ordinary = compile(request(target)).expect("ordinary Span object");
        let empty = compile_with_prepared_aggregate_exports(
            request(target),
            PreparedAggregateExports::NONE,
        )
        .expect("empty aggregate request");
        assert_eq!(empty.object(), ordinary.object());
        assert_eq!(empty.receipt(), ordinary.receipt());
        assert_eq!(empty.module(), ordinary.module());
        assert_eq!(
            empty.program().serialize().expect("empty request program"),
            ordinary.program().serialize().expect("ordinary program"),
        );
        assert_eq!(ordinary.module().prepared_count_symbol(), None);
        assert_eq!(ordinary.module().prepared_span_sum_symbol(), None);
        assert_eq!(ordinary.module().prepared_grep_count_symbol(), None);
        assert_eq!(ordinary.module().required_runtime_program(), None);
        assert!(ordinary.module().required_runtime_symbols().next().is_none());
        assert_eq!(
            ordinary.receipt().prepared_aggregate_exports,
            PreparedAggregateExports::NONE,
        );
        assert_eq!(ordinary.receipt().prepared_aggregate_strategy, None);

        let compiled = compile_with_prepared_aggregate_exports(
            request(target),
            PreparedAggregateExports::ALL,
        )
        .expect("Count + SpanSum + GrepCount object");
        let repeated = compile_with_prepared_aggregate_exports(
            request(target),
            PreparedAggregateExports::ALL,
        )
        .expect("deterministic Count + SpanSum + GrepCount object");
        assert_eq!(repeated.object(), compiled.object());
        assert_eq!(repeated.module(), compiled.module());
        assert_eq!(repeated.receipt(), compiled.receipt());
        assert_eq!(
            compiled.program().serialize().expect("aggregate program bytes"),
            ordinary.program().serialize().expect("ordinary program bytes"),
            "additive reducers must not change the semantic program",
        );
        assert_eq!(compiled.module().entry_symbol(), ordinary.module().entry_symbol());
        assert_ne!(compiled.object(), ordinary.object());
        assert_eq!(
            compiled.module().prepared_aggregate_exports(),
            PreparedAggregateExports::ALL,
        );
        assert_eq!(
            compiled.module().prepared_aggregate_strategy(),
            Some(PreparedAggregateStrategy::NativeFused),
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_exports,
            PreparedAggregateExports::ALL,
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeFused),
        );
        assert!(compiled.module().uses_direct_span_trusted_core_aggregate());
        assert!(!compiled.receipt().runtime_helper_required);
        let expected_runtime_program = compiled
            .program()
            .serialize()
            .expect("aggregate runtime program bytes");
        let (runtime_program_name, runtime_program_len) = compiled
            .module()
            .required_runtime_program()
            .expect("aggregate preparation program");
        assert_eq!(runtime_program_len, expected_runtime_program.len());
        let runtime_program = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == runtime_program_name)
            .expect("aggregate runtime program symbol");
        assert_eq!(runtime_program.binding, crate::SymbolBinding::Global);
        assert_eq!(runtime_program.kind, crate::SymbolKind::Object);
        let runtime_program_section = runtime_program
            .section
            .expect("aggregate runtime program section");
        let runtime_program_start =
            usize::try_from(runtime_program.offset).expect("runtime program offset");
        let runtime_program_end = runtime_program_start
            .checked_add(runtime_program_len)
            .expect("runtime program end");
        assert_eq!(
            &compiled.module().sections()[runtime_program_section].data
                [runtime_program_start..runtime_program_end],
            expected_runtime_program,
        );
        assert!(
            compiled
                .receipt()
                .passes
                .contains(&OptimizationPass::PreparedAggregateLowering),
        );
        let aggregate_pass = compiled
            .receipt()
            .passes
            .iter()
            .position(|pass| *pass == OptimizationPass::PreparedAggregateLowering)
            .expect("aggregate pass receipt");
        let layout_pass = compiled
            .receipt()
            .passes
            .iter()
            .position(|pass| *pass == OptimizationPass::PositionIndependentDataLayout)
            .expect("PIC layout receipt");
        assert!(aggregate_pass < layout_pass);
        let expected_object_sha256: [u8; 32] = Sha256::digest(compiled.object()).into();
        assert_eq!(compiled.receipt().object_sha256, expected_object_sha256);
        assert_eq!(compiled.receipt().code_bytes, compiled.module().code_bytes());
        assert_eq!(compiled.receipt().object_bytes, compiled.object().len());
        assert_eq!(
            compiled.receipt().data_bytes,
            compiled
                .module()
                .sections()
                .iter()
                .filter(|section| section.kind == SectionKind::ReadOnlyData)
                .map(|section| section.data.len())
                .sum(),
        );

        let required = compiled
            .module()
            .required_runtime_symbols()
            .collect::<Vec<_>>();
        assert!(!required.contains(
            &"fre_aot_regex_runtime_compiler_private_count_exclusive_v1"
        ));
        assert!(!required.contains(
            &"fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"
        ));
        assert!(!required.contains(
            &"fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"
        ));
        let identity_index = compiled
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == ".Lfre_aot_regex_prepared_aggregate_identity")
            .expect("aggregate artifact identity symbol");
        let identity = &compiled.module().symbols()[identity_index];
        let identity_section = identity.section.expect("aggregate identity section");
        let identity_start = usize::try_from(identity.offset).expect("identity offset");
        let identity_end = identity_start.checked_add(32).expect("identity end");
        assert_eq!(
            &compiled.module().sections()[identity_section].data[identity_start..identity_end],
            compiled.program().artifact_identity(),
        );
        let count_entry = compiled
            .module()
            .prepared_count_symbol()
            .expect("prepared Count symbol");
        let span_sum_entry = compiled
            .module()
            .prepared_span_sum_symbol()
            .expect("prepared SpanSum symbol");
        let grep_entry = compiled
            .module()
            .prepared_grep_count_symbol()
            .expect("prepared GrepCount symbol");
        assert_ne!(count_entry, span_sum_entry);
        assert_ne!(count_entry, grep_entry);
        assert_ne!(span_sum_entry, grep_entry);
        let ordinary_entry = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == compiled.module().entry_symbol())
            .expect("ordinary native entry");
        let ordinary_offset = usize::try_from(ordinary_entry.offset)
            .expect("ordinary native entry offset");
        for entry_name in [count_entry, span_sum_entry, grep_entry] {
            let entry = compiled
                .module()
                .symbols()
                .iter()
                .find(|symbol| symbol.name == entry_name)
                .expect("aggregate entry record");
            assert_eq!(entry.binding, crate::SymbolBinding::Global);
            assert_eq!(entry.kind, crate::SymbolKind::Function);
            let section_index = entry.section.expect("aggregate text section");
            let start = usize::try_from(entry.offset).expect("aggregate entry offset");
            let size = usize::try_from(entry.size).expect("aggregate entry size");
            let end = start.checked_add(size).expect("aggregate entry end");
            let symbol_end = entry
                .offset
                .checked_add(entry.size)
                .expect("aggregate symbol end");
            let code = &compiled.module().sections()[section_index].data[start..end];
            match target.architecture {
                Architecture::X86_64 => {
                    assert!(compiled.module().relocations().iter().any(|relocation| {
                        relocation.section == section_index
                            && relocation.offset >= entry.offset
                            && relocation.offset < symbol_end
                            && relocation.symbol == identity_index
                            && relocation.kind == crate::RelocationKind::X86PcRelative32
                            && relocation.addend == -4
                    }));
                    assert!(code.windows(5).enumerate().any(|(offset, instruction)| {
                        if instruction[0] != 0xe8 {
                            return false;
                        }
                        let displacement = i32::from_le_bytes(
                            instruction[1..5].try_into().expect("x86 call displacement"),
                        );
                        start
                            .checked_add(offset)
                            .and_then(|source| source.checked_add(5))
                            .and_then(|source| i64::try_from(source).ok())
                            .and_then(|source| source.checked_add(i64::from(displacement)))
                            .and_then(|target| usize::try_from(target).ok())
                            .is_some_and(|target| {
                                if entry_name == grep_entry {
                                    target == ordinary_offset
                                } else {
                                    (start..end).contains(&target)
                                }
                            })
                    }));
                }
                Architecture::Aarch64 => {
                    for kind in [
                        crate::RelocationKind::Aarch64Page21,
                        crate::RelocationKind::Aarch64PageOff12,
                    ] {
                        assert!(compiled.module().relocations().iter().any(|relocation| {
                            relocation.section == section_index
                                && relocation.offset >= entry.offset
                                && relocation.offset < symbol_end
                                && relocation.symbol == identity_index
                                && relocation.kind == kind
                                && relocation.addend == 0
                        }));
                    }
                    assert!(code.chunks_exact(4).enumerate().any(|(index, bytes)| {
                        let instruction = u32::from_le_bytes(
                            bytes.try_into().expect("AArch64 aggregate instruction"),
                        );
                        if instruction & 0xfc00_0000 != 0x9400_0000 {
                            return false;
                        }
                        let immediate = i32::from_le_bytes(
                            ((instruction & 0x03ff_ffff) << 6).to_le_bytes(),
                        ) >> 6;
                        index
                            .checked_mul(4)
                            .and_then(|offset| start.checked_add(offset))
                            .and_then(|source| i64::try_from(source).ok())
                            .and_then(|source| {
                                source.checked_add(i64::from(immediate).checked_mul(4)?)
                            })
                            .and_then(|target| usize::try_from(target).ok())
                            .is_some_and(|target| {
                                if entry_name == grep_entry {
                                    target == ordinary_offset
                                } else {
                                    (start..end).contains(&target)
                                }
                            })
                    }));
                }
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-target reducer audit keeps both ISAs, engine shapes, and local-call decoding in one matrix"
)]
fn direct_native_reducers_reenter_authenticated_span_core_cross_target() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    for pattern in ["[ab]+z", "(?:ab|a)+z"] {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let request = || {
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
            };
            let ordinary = compile(request()).expect("direct native Span module");
            assert_eq!(ordinary.receipt().engine, EngineKind::OrderedDfa);
            assert_eq!(ordinary.module().prepared_entry_symbol(), None);
            assert!(ordinary.module().required_runtime_symbols().next().is_none());

            let counted = compile_with_prepared_aggregate_exports(request(), exports)
                .expect("direct native Count and SpanSum module");
            assert_eq!(counted.receipt().engine, EngineKind::OrderedDfa);
            assert_eq!(
                counted.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeFused),
            );
            assert!(!counted.receipt().runtime_helper_required);
            assert!(counted.module().required_runtime_symbols().next().is_none());
            assert!(counted.module().required_runtime_program().is_some());
            assert_eq!(counted.module().entry_symbol(), ordinary.module().entry_symbol());
            assert!(
                counted.module().uses_direct_span_trusted_core_aggregate(),
                "pattern={pattern:?} target={target:?}",
            );
            let core_offset = counted
                .module()
                .direct_span_trusted_core_offset()
                .expect("authenticated direct Span core offset");

            let ordinary_entry = counted
                .module()
                .symbols()
                .iter()
                .find(|symbol| symbol.name == counted.module().entry_symbol())
                .expect("ordinary native entry symbol");
            let ordinary_offset = usize::try_from(ordinary_entry.offset)
                .expect("ordinary native entry offset");
            let ordinary_end = ordinary_offset
                .checked_add(usize::try_from(ordinary_entry.size).expect("ordinary size"))
                .expect("ordinary end");
            let counted_text = counted.module().sections()[0].bytes();
            let ordinary_text = ordinary.module().sections()[0].bytes();
            assert_eq!(
                counted_text.get(ordinary_offset..ordinary_end),
                ordinary_text.get(ordinary_offset..ordinary_end),
                "aggregate append changed the public ordinary entry",
            );
            for entry_name in [
                counted
                    .module()
                    .prepared_count_symbol()
                    .expect("native Count symbol"),
                counted
                    .module()
                    .prepared_span_sum_symbol()
                    .expect("native SpanSum symbol"),
            ] {
                let entry = counted
                    .module()
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == entry_name)
                    .expect("native scalar reducer entry symbol");
                let section = entry.section.expect("native scalar reducer text section");
                let start = usize::try_from(entry.offset)
                    .expect("native scalar reducer entry offset");
                let size = usize::try_from(entry.size)
                    .expect("native scalar reducer entry size");
                let end = start
                    .checked_add(size)
                    .expect("native scalar reducer entry end");
                assert_eq!(section, 0);
                let calls = generated_local_call_sites(
                    target.architecture,
                    counted_text,
                    start,
                    end,
                );
                assert_eq!(calls.len(), 1, "{pattern:?}/{target:?}/{entry_name}");
                let trampoline = calls[0].1;
                assert!((start..end).contains(&trampoline));
                assert_ne!(trampoline, ordinary_offset);
                match target.architecture {
                    Architecture::X86_64 => {
                        let jump_displacement = end.checked_sub(4)
                            .expect("x86 jump displacement");
                        assert_eq!(counted_text[jump_displacement - 1], 0xe9);
                        assert_eq!(
                            counted_text.get(jump_displacement - 3..jump_displacement - 1),
                            Some([0x31, 0xc0].as_slice()),
                        );
                        let displacement = i32::from_le_bytes(
                            counted_text[jump_displacement..end]
                                .try_into()
                                .expect("x86 core jump displacement"),
                        );
                        let target = (jump_displacement + 4)
                            .checked_add_signed(
                                isize::try_from(displacement)
                                    .expect("x86 core displacement fits isize"),
                            )
                            .expect("x86 core jump target");
                        assert_eq!(target, core_offset);
                    }
                    Architecture::Aarch64 => {
                        assert_eq!(end, trampoline + 8);
                        assert_eq!(
                            counted_text.get(trampoline..trampoline + 4),
                            Some(0xf100_001f_u32.to_le_bytes().as_slice()),
                        );
                        let branch = u32::from_le_bytes(
                            counted_text[trampoline + 4..end]
                                .try_into()
                                .expect("AArch64 core branch"),
                        );
                        assert_eq!(branch & 0xfc00_0000, 0x1400_0000);
                        assert_eq!(
                            crate::module::aarch64_direct_branch_target(trampoline + 4, branch)
                                .expect("decode AArch64 core branch"),
                            Some(core_offset),
                        );
                    }
                }
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-target one-shot reducer audit binds public-entry identity, local-call topology, and table provenance"
)]
fn direct_native_single_reducer_uses_authenticated_complete_span_scan_cross_target() {
    for pattern in ["[ab]+z", "(?:ab|a)+z", "(?:|a)", "a*"] {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let request = || {
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
            };
            let ordinary = compile(request()).expect("direct public Span module");
            assert_eq!(ordinary.receipt().engine, EngineKind::OrderedDfa);
            let exports = PreparedAggregateExports::COUNT;
            {
                let reduced = compile_with_prepared_aggregate_exports(request(), exports)
                    .expect("single direct native reducer");
                assert_eq!(reduced.receipt().engine, EngineKind::OrderedDfa);
                assert_eq!(
                    reduced.receipt().prepared_aggregate_strategy,
                    Some(PreparedAggregateStrategy::NativeFused),
                );
                assert!(!reduced.receipt().runtime_helper_required);
                assert!(reduced.module().required_runtime_symbols().next().is_none());
                assert!(reduced.module().uses_complete_span_reduce_aggregate());
                assert!(!reduced.module().uses_direct_span_trusted_core_aggregate());

                let ordinary_entry = reduced
                    .module()
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == reduced.module().entry_symbol())
                    .expect("ordinary entry");
                let ordinary_start = usize::try_from(ordinary_entry.offset).unwrap();
                let ordinary_end = ordinary_start
                    .checked_add(usize::try_from(ordinary_entry.size).unwrap())
                    .unwrap();
                assert_eq!(
                    reduced.module().sections()[0]
                        .bytes()
                        .get(ordinary_start..ordinary_end),
                    ordinary.module().sections()[0]
                        .bytes()
                        .get(ordinary_start..ordinary_end),
                    "{pattern:?}/{target:?}/{exports:?} changed public Span bytes",
                );
                let core_offset = reduced
                    .module()
                    .complete_span_reduce_core_offset()
                    .expect("authenticated complete reducer core");
                assert!(core_offset >= ordinary_end);
                let reducer_name = reduced.module().prepared_count_symbol().unwrap();
                let reducer = reduced
                    .module()
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == reducer_name)
                    .expect("single reducer symbol");
                let reducer_start = usize::try_from(reducer.offset).unwrap();
                let reducer_end = reducer_start
                    .checked_add(usize::try_from(reducer.size).unwrap())
                    .unwrap();
                let calls = generated_local_call_sites(
                    target.architecture,
                    reduced.module().sections()[0].bytes(),
                    reducer_start,
                    reducer_end,
                );
                assert_eq!(calls.len(), 1, "{pattern:?}/{target:?}/{exports:?}");
                assert_eq!(calls[0].1, core_offset);
                let core_text = &reduced.module().sections()[0].bytes()
                    [core_offset..reducer_start];
                match target.architecture {
                    Architecture::X86_64 => {
                        let validation = [
                            0x48, 0x8b, 0x4c, 0x24, 40, // full end from private frame
                            0x49, 0x39, 0xf2, // selected start >= requested start
                        ];
                        assert!(
                            core_text.windows(validation.len()).any(|bytes| {
                                bytes == validation
                            }),
                            "{pattern:?}/{target:?}/{exports:?} did not restore the x86 semantic end before matched-result validation",
                        );
                    }
                    Architecture::Aarch64 => {
                        const RESTORE_END: u32 = 0xf940_17e3; // ldr x3, [sp, #40]
                        const VALIDATE_START: u32 = 0xeb09_00df; // cmp x6, x9
                        let words = core_text
                            .chunks_exact(4)
                            .map(|bytes| {
                                u32::from_le_bytes(bytes.try_into().expect("AArch64 core word"))
                            })
                            .collect::<Vec<_>>();
                        assert!(
                            words.windows(2).any(|pair| {
                                pair == [RESTORE_END, VALIDATE_START]
                            }),
                            "{pattern:?}/{target:?}/{exports:?} did not restore the AArch64 semantic end before matched-result validation",
                        );
                    }
                }
                assert!(reduced.module().relocations().iter().any(|relocation| {
                    relocation.section == 0
                        && usize::try_from(relocation.offset)
                            .is_ok_and(|offset| offset >= core_offset && offset < reducer_start)
                        && relocation.symbol == 1
                }));
            }

            // SpanSum is deliberately outside the Count-only transaction.
            // Reconstruct the ce964 append from the ordinary module and bind
            // both the selected route and emitted bytes to that incumbent.
            let expected_span_sum = compile_ce964_style_prepared_aggregate(
                request(),
                PreparedAggregateExports::SPAN_SUM,
            )
            .expect("compile ce964 SpanSum incumbent");
            let span_sum = compile_with_prepared_aggregate_exports(
                request(),
                PreparedAggregateExports::SPAN_SUM,
            )
            .expect("Count-only candidate SpanSum incumbent");
            assert_eq!(span_sum.module(), expected_span_sum.module());
            assert_eq!(span_sum.object(), expected_span_sum.object());
            assert_eq!(span_sum.receipt(), expected_span_sum.receipt());
            assert!(span_sum.module().uses_direct_span_trusted_core_aggregate());
            assert!(!span_sum.module().uses_complete_span_reduce_aggregate());
            assert!(!span_sum.module().has_complete_span_reduce_source_for_test());
        }
    }
}

fn compile_ce964_style_prepared_aggregate(
    request: CompileRequest,
    exports: PreparedAggregateExports,
) -> Result<crate::CompiledRegex, CompileError> {
    let target = request.target;
    let mode = request.mode;
    let max_object_bytes = request.limits.max_object_bytes;
    let compiled = compile(request)?;
    crate::append_prepared_aggregate_exports_to_compiled(
        compiled,
        exports,
        target,
        mode,
        max_object_bytes,
        SlowAotLimits::default(),
    )
}

#[test]
fn complete_span_reduce_source_allocation_failure_is_terminal() {
    let failure = crate::module::complete_span_reduce_source_allocation::<()>(Err((
        fre_exact_alloc::CopyError::AllocationFailed,
        (),
    )));
    assert!(matches!(
        failure,
        Err(ObjectError::Allocation("complete Span reducer source")),
    ));
}

#[test]
fn complete_span_scan_excludes_context_mixed_and_exact_singleton_incumbents() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let context_request = || {
            CompileRequest::new(r"(?-u:\b(?:foo|bar)\b)", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
        };
        let context = compile_with_prepared_aggregate_exports(
            context_request(),
            PreparedAggregateExports::COUNT,
        )
        .expect("context Count incumbent");
        let expected_context = compile_ce964_style_prepared_aggregate(
            context_request(),
            PreparedAggregateExports::COUNT,
        )
        .expect("ce964 context Count reconstruction");
        assert_eq!(context.receipt().engine, EngineKind::OrderedContextDfa);
        assert!(!context.module().uses_complete_span_reduce_aggregate());
        assert_eq!(context.module(), expected_context.module());
        assert_eq!(context.object(), expected_context.object());
        assert_eq!(context.receipt(), expected_context.receipt());

        let mixed_request = || {
            CompileRequest::new("[ab]+z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
        };
        let mixed_exports =
            PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM);
        let mixed = compile_with_prepared_aggregate_exports(
            mixed_request(),
            mixed_exports,
        )
        .expect("mixed ce964 incumbent");
        let expected_mixed = compile_ce964_style_prepared_aggregate(
            mixed_request(),
            mixed_exports,
        )
        .expect("ce964 mixed-export reconstruction");
        assert!(mixed.module().uses_direct_span_trusted_core_aggregate());
        assert!(!mixed.module().uses_complete_span_reduce_aggregate());
        assert_eq!(mixed.module(), expected_mixed.module());
        assert_eq!(mixed.object(), expected_mixed.object());
        assert_eq!(mixed.receipt(), expected_mixed.receipt());

        for exports in [
            PreparedAggregateExports::GREP_COUNT,
            PreparedAggregateExports::COUNT.union(PreparedAggregateExports::GREP_COUNT),
            PreparedAggregateExports::ALL,
        ] {
            let grep_or_mixed = compile_with_prepared_aggregate_exports(
                CompileRequest::new("[ab]+z", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
                exports,
            )
            .expect("Grep or mixed-export incumbent");
            let expected = compile_ce964_style_prepared_aggregate(
                mixed_request(),
                exports,
            )
            .expect("ce964 Grep/mixed reconstruction");
            assert!(
                !grep_or_mixed
                    .module()
                    .uses_complete_span_reduce_aggregate(),
                "target={target:?} exports={exports:?}",
            );
            assert_eq!(grep_or_mixed.module(), expected.module());
            assert_eq!(grep_or_mixed.object(), expected.object());
            assert_eq!(grep_or_mixed.receipt(), expected.receipt());
        }

        for exports in [
            PreparedAggregateExports::COUNT,
            PreparedAggregateExports::SPAN_SUM,
        ] {
            let exact_request = || {
                CompileRequest::new("abc", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
            };
            let ordinary = compile(exact_request()).expect("exact-singleton ordinary source");
            let serialized = ordinary.program().serialize().unwrap();
            let expected = ordinary
                .module()
                .clone()
                .without_complete_span_reduce_for_aggregate()
                .expect("suppress generic exact-singleton recipe")
                .append_prepared_aggregate_exports(
                    exports,
                    ordinary.program().artifact_identity(),
                    &serialized,
                )
                .expect("append pre-feature exact-singleton incumbent");
            let expected_object = emit_object(
                &expected,
                crate::ObjectFormat::for_target(target),
                usize::MAX,
            )
            .expect("emit pre-feature exact-singleton incumbent");
            let exact = compile_with_prepared_aggregate_exports(
                exact_request(),
                exports,
            )
            .expect("exact-singleton incumbent");
            let expected_compiled = compile_ce964_style_prepared_aggregate(
                exact_request(),
                exports,
            )
            .expect("ce964 exact-singleton reconstruction");
            assert_eq!(exact.module(), &expected, "target={target:?} exports={exports:?}");
            assert_eq!(exact.object(), expected_object, "target={target:?} exports={exports:?}");
            assert_eq!(exact.module(), expected_compiled.module());
            assert_eq!(exact.object(), expected_compiled.object());
            assert_eq!(exact.receipt(), expected_compiled.receipt());
            assert!(!exact.module().uses_complete_span_reduce_aggregate());
            assert!(!exact.module().has_complete_span_reduce_source_for_test());
        }

        let asimd_target = target
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd));
        if let Ok(asimd_target) = asimd_target {
            let exact = compile_with_prepared_aggregate_exports(
                CompileRequest::new("abc", asimd_target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
                PreparedAggregateExports::COUNT,
            )
            .expect("eligible exact-singleton Count follow-on");
            assert!(exact.module().direct_exact_singleton_count_aot_report().is_some());
            assert!(!exact.module().uses_complete_span_reduce_aggregate());
            assert!(!exact.module().has_complete_span_reduce_source_for_test());
        }
    }
}

#[test]
fn complete_span_scan_authentication_rejects_public_entry_relocation_and_program_tamper() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let request = || {
            CompileRequest::new("[ab]+z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
        };
        let ordinary = crate::module::with_complete_span_reduce_recipe(|| {
            compile(request())
        })
        .expect("complete Span tamper source");
        assert!(ordinary.module().has_complete_span_reduce_source_for_test());
        let serialized = ordinary.program().serialize().expect("tamper source program");
        let identity = ordinary.program().artifact_identity();
        let entry = ordinary
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == ordinary.module().entry_symbol())
            .expect("tamper source entry");
        let entry_start = usize::try_from(entry.offset).expect("tamper entry start");
        let entry_end = entry_start
            .checked_add(usize::try_from(entry.size).expect("tamper entry size"))
            .expect("tamper entry end");

        let mut text = ordinary.module().clone();
        assert!(text.test_flip_text_byte(entry_end - 1));
        assert!(matches!(
            text.append_prepared_aggregate_exports(
                PreparedAggregateExports::COUNT,
                identity,
                &serialized,
            ),
            Err(ObjectError::InvalidModule(_)),
        ));

        let mut relocation = ordinary.module().clone();
        assert!(relocation.test_flip_text_relocation_addend_in_range(entry_start, entry_end));
        assert!(matches!(
            relocation.append_prepared_aggregate_exports(
                PreparedAggregateExports::COUNT,
                identity,
                &serialized,
            ),
            Err(ObjectError::InvalidModule(_)),
        ));

        let mut program = ordinary.module().clone();
        assert!(program.test_flip_program_byte(0));
        assert!(matches!(
            program.append_prepared_aggregate_exports(
                PreparedAggregateExports::COUNT,
                identity,
                &serialized,
            ),
            Err(ObjectError::InvalidModule(_)),
        ));
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-target reducer audit keeps both ISAs, engine shapes, and local-call decoding in one matrix"
)]
fn direct_native_context_reducers_retain_ordinary_entry_cross_target() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    for (pattern, expected_engine) in
        [(r"(?-u:\b(?:foo|bar)\b)", EngineKind::OrderedContextDfa)]
    {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let request = || {
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
            };
            let ordinary = compile(request()).expect("direct native Span module");
            assert_eq!(ordinary.receipt().engine, expected_engine);
            assert_eq!(ordinary.module().prepared_entry_symbol(), None);
            assert!(ordinary.module().required_runtime_symbols().next().is_none());

            let counted = compile_with_prepared_aggregate_exports(
                request(),
                exports,
            )
            .expect("direct native Count and SpanSum module");
            assert_eq!(counted.receipt().engine, expected_engine);
            assert_eq!(
                counted.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeFused),
            );
            assert!(!counted.receipt().runtime_helper_required);
            assert!(counted.module().required_runtime_symbols().next().is_none());
            assert!(counted.module().required_runtime_program().is_some());
            assert_eq!(counted.module().entry_symbol(), ordinary.module().entry_symbol());
            assert!(!counted.module().uses_direct_span_trusted_core_aggregate());

            let ordinary_entry = counted
                .module()
                .symbols()
                .iter()
                .find(|symbol| symbol.name == counted.module().entry_symbol())
                .expect("ordinary native entry symbol");
            let ordinary_offset = usize::try_from(ordinary_entry.offset)
                .expect("ordinary native entry offset");
            for entry_name in [
                counted
                    .module()
                    .prepared_count_symbol()
                    .expect("native Count symbol"),
                counted
                    .module()
                    .prepared_span_sum_symbol()
                    .expect("native SpanSum symbol"),
            ] {
                let entry = counted
                    .module()
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == entry_name)
                    .expect("native scalar reducer entry symbol");
                let section = entry.section.expect("native scalar reducer text section");
                let start = usize::try_from(entry.offset)
                    .expect("native scalar reducer entry offset");
                let size = usize::try_from(entry.size)
                    .expect("native scalar reducer entry size");
                let end = start
                    .checked_add(size)
                    .expect("native scalar reducer entry end");
                let code = &counted.module().sections()[section].data[start..end];
                let calls_ordinary = match target.architecture {
                    Architecture::X86_64 => {
                        code.windows(5).enumerate().any(|(offset, instruction)| {
                            if instruction[0] != 0xe8 {
                                return false;
                            }
                            let displacement = i32::from_le_bytes(
                                instruction[1..5]
                                    .try_into()
                                    .expect("x86 call displacement"),
                            );
                            start
                                .checked_add(offset)
                                .and_then(|source| source.checked_add(5))
                                .and_then(|source| i64::try_from(source).ok())
                                .and_then(|source| {
                                    source.checked_add(i64::from(displacement))
                                }) == i64::try_from(ordinary_offset).ok()
                        })
                    }
                    Architecture::Aarch64 => {
                        code.chunks_exact(4).enumerate().any(|(index, bytes)| {
                            let instruction = u32::from_le_bytes(
                                bytes.try_into().expect("AArch64 reducer instruction"),
                            );
                            if instruction & 0xfc00_0000 != 0x9400_0000 {
                                return false;
                            }
                            let immediate = i32::from_le_bytes(
                                ((instruction & 0x03ff_ffff) << 6).to_le_bytes(),
                            ) >> 6;
                            index
                                .checked_mul(4)
                                .and_then(|offset| start.checked_add(offset))
                                .and_then(|source| i64::try_from(source).ok())
                                .and_then(|source| {
                                    source.checked_add(i64::from(immediate).checked_mul(4)?)
                                }) == i64::try_from(ordinary_offset).ok()
                        })
                    }
                };
                assert!(calls_ordinary, "{pattern:?}/{target:?}/{entry_name}");
            }
        }
    }
}

#[test]
fn ordered_nfa_scalar_reducers_publish_native_v15_with_honest_compatibility_helpers() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    for target in [
        Target::x86_64_linux(),
        Target::x86_64_macos(),
        Target::aarch64_linux(),
        Target::aarch64_macos(),
    ] {
        let compiled = compile_with_prepared_aggregate_exports(
            CompileRequest::new(r"\bfoo\b", target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
            exports,
        )
        .expect("native OrderedNfa scalar reducers");
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
        );
        assert_eq!(
            compiled.module().prepared_bulk_strategy(),
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert_eq!(
            compiled.receipt().required_prepare_capabilities,
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert!(compiled.receipt().runtime_helper_required);
        let required = compiled
            .module()
            .required_runtime_symbols()
            .collect::<Vec<_>>();
        assert!(required.contains(
            &"fre_aot_regex_runtime_compiler_private_count_exclusive_v1"
        ));
        assert!(required.contains(
            &"fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"
        ));
    }
}

#[test]
fn prepared_aggregate_exports_reject_non_span_contracts() {
    for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
        let error = compile_with_prepared_aggregate_exports(
            CompileRequest::new("a+", Target::x86_64_linux()).output(output),
            PreparedAggregateExports::COUNT,
        )
        .expect_err("non-Span aggregate request must fail");
        assert!(matches!(
            error,
            CompileError::PreparedAggregateRequiresSpan { actual } if actual == output
        ));
    }
}

#[test]
fn prepared_aggregate_export_bits_publish_only_requested_entries() {
    for (exports, count, span_sum, grep_count) in [
        (PreparedAggregateExports::COUNT, true, false, false),
        (PreparedAggregateExports::SPAN_SUM, false, true, false),
        (PreparedAggregateExports::GREP_COUNT, false, false, true),
    ] {
        for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
            let request = || {
                CompileRequest::new("a+", target)
                    .mode(CompileMode::Fast)
                    .output(OutputContract::Span)
            };
            let ordinary = compile(request()).expect("runtime-backed base module");
            let ordinary_runtime_program = ordinary
                .module()
                .required_runtime_program()
                .expect("Fast Span module runtime program");
            let compiled = compile_with_prepared_aggregate_exports(
                request(),
                exports,
            )
            .expect("single aggregate export");
            assert_eq!(compiled.module().prepared_count_symbol().is_some(), count);
            assert_eq!(
                compiled.module().prepared_span_sum_symbol().is_some(),
                span_sum,
            );
            assert_eq!(
                compiled.module().prepared_grep_count_symbol().is_some(),
                grep_count,
            );
            assert_eq!(compiled.receipt().prepared_aggregate_exports, exports);
            assert_eq!(
                compiled.receipt().prepared_aggregate_strategy,
                Some(if grep_count {
                    PreparedAggregateStrategy::RuntimeHelper
                } else {
                    PreparedAggregateStrategy::NativeFusedWithRuntimeHelper
                }),
            );
            assert_eq!(
                compiled.module().required_runtime_program(),
                Some(ordinary_runtime_program),
                "an existing runtime program alias must be reused exactly",
            );
            assert_eq!(
                compiled.module().symbols().len(),
                ordinary
                    .module()
                    .symbols()
                    .len()
                    .checked_add(if grep_count { 3 } else { 2 })
                    .expect("one identity, optional helper, and entry symbol"),
                "one aggregate export must not duplicate the runtime program alias",
            );
            let required = compiled
                .module()
                .required_runtime_symbols()
                .collect::<Vec<_>>();
            assert!(!required
                .contains(&"fre_aot_regex_runtime_compiler_private_count_exclusive_v1"));
            assert!(!required.contains(
                &"fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"
            ));
            assert_eq!(
                required.contains(
                    &"fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"
                ),
                grep_count,
            );
        }
    }
}

#[test]
fn prepared_grep_count_export_is_legal_for_every_output_contract() {
    for output in [
        OutputContract::Exists,
        OutputContract::SelectedEnd,
        OutputContract::Span,
    ] {
        let compiled = compile_with_prepared_aggregate_exports(
            CompileRequest::new("a+", Target::x86_64_linux()).output(output),
            PreparedAggregateExports::GREP_COUNT,
        )
        .expect("grep-only export is output-independent");
        assert!(compiled.module().prepared_grep_count_symbol().is_some());
        assert_eq!(compiled.module().prepared_count_symbol(), None);
        assert_eq!(compiled.module().prepared_span_sum_symbol(), None);
        assert_eq!(
            compiled.receipt().prepared_aggregate_exports,
            PreparedAggregateExports::GREP_COUNT,
        );
    }
}

#[test]
fn prepared_v15_grep_count_is_native_fail_closed_and_cross_target() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let compiled = crate::compile_with_prepared_ordered_nfa_v15(
            CompileRequest::new(r"\b\w{12,}\b", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::GREP_COUNT,
        )
        .expect("explicit V15 GrepCount");
        assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
        );
        assert_eq!(
            compiled.receipt().required_prepare_capabilities,
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert_eq!(
            compiled.module().prepared_bulk_strategy(),
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert!(!compiled
            .module()
            .required_runtime_symbols()
            .any(|symbol| symbol
                == "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"));
        let reducer_name = compiled
            .module()
            .prepared_grep_count_symbol()
            .expect("native V15 GrepCount symbol");
        let reducer = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == reducer_name)
            .expect("native V15 GrepCount record");
        assert_eq!(reducer.binding, crate::SymbolBinding::Global);
        assert_eq!(reducer.kind, crate::SymbolKind::Function);
        let section = reducer.section.expect("native V15 GrepCount text");
        let end = reducer.offset.checked_add(reducer.size).expect("reducer end");
        let identity = compiled
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == ".Lfre_aot_regex_prepared_aggregate_identity")
            .expect("native V15 aggregate identity");
        let relocations = compiled
            .module()
            .relocations()
            .iter()
            .filter(|relocation| {
                relocation.section == section
                    && relocation.offset >= reducer.offset
                    && relocation.offset < end
            })
            .collect::<Vec<_>>();
        assert!(relocations.iter().any(|relocation| relocation.symbol == identity));
        assert!(relocations.iter().all(|relocation| {
            compiled.module().symbols()[relocation.symbol].section.is_some()
        }));
        assert!(reducer.size > 12, "native reducer must not be a helper thunk");
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the test decoder walks bounded generated reducer text",
)]
fn generated_local_call_sites(
    architecture: Architecture,
    text: &[u8],
    start: usize,
    end: usize,
) -> Vec<(usize, usize)> {
    match architecture {
        Architecture::X86_64 => (start..end.saturating_sub(4))
            .filter_map(|instruction| {
                if text[instruction] != 0xe8 {
                    return None;
                }
                let displacement = i32::from_le_bytes(
                    text[instruction + 1..instruction + 5]
                        .try_into()
                        .expect("x86 local-call displacement"),
                );
                let after = instruction + 5;
                let target = after.checked_add_signed(
                    isize::try_from(displacement).expect("x86 call displacement fits isize"),
                )?;
                Some((instruction, target))
            })
            .collect(),
        Architecture::Aarch64 => (start..end)
            .step_by(4)
            .filter_map(|instruction| {
                let word = u32::from_le_bytes(
                    text.get(instruction..instruction + 4)?
                        .try_into()
                        .expect("AArch64 local-call instruction"),
                );
                if word & 0xfc00_0000 != 0x9400_0000 {
                    return None;
                }
                let immediate = i32::try_from(word & 0x03ff_ffff)
                    .expect("AArch64 call immediate");
                let signed = (immediate << 6) >> 6;
                let displacement = isize::try_from(signed)
                    .expect("AArch64 call displacement fits isize")
                    .checked_mul(4)?;
                let target = instruction.checked_add_signed(displacement)?;
                Some((instruction, target))
            })
            .collect(),
    }
}

#[test]
fn prepared_v15_scalar_operation_is_one_closed_global_function_cross_isa() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        for export in [
            PreparedAggregateExports::COUNT,
            PreparedAggregateExports::SPAN_SUM,
            PreparedAggregateExports::GREP_COUNT,
        ] {
            let request = || {
                CompileRequest::new(r"\b\w{12,}\b", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
            };
            let legacy = crate::compile_with_prepared_ordered_nfa_v15(
                request(),
                export,
            )
            .expect("legacy V15 compatibility topology");
            assert_eq!(legacy.receipt().entry_abi, EntryAbi::SpanSearchV1);
            assert_eq!(
                legacy.module().prepared_bulk_strategy(),
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
            );
            assert!(legacy.module().prepared_entry_symbol().is_some());
            assert!(legacy.module().prepared_span_fill_symbol().is_some());
            assert!(legacy.module().required_runtime_symbols().next().is_some());

            let disposition =
                crate::compile_with_prepared_ordered_nfa_v15_scalar_operation_reported(
                    request(),
                    export,
                )
                .expect("closed V15 scalar operation compile");
            let compiled = disposition
                .into_compiled()
                .expect("eligible V15 scalar operation");
            let module = compiled.module();
            assert_eq!(compiled.receipt().entry_abi, EntryAbi::PreparedScalarReduceV1);
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
            assert_eq!(
                compiled.receipt().prepared_aggregate_strategy,
                Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
            );
            assert_eq!(module.prepared_bulk_strategy(), None);
            assert_eq!(module.prepared_entry_symbol(), None);
            assert_eq!(module.prepared_span_fill_symbol(), None);
            assert_eq!(
                compiled.receipt().required_prepare_capabilities,
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
            );
            assert!(!compiled.receipt().runtime_helper_required);
            assert!(module.required_runtime_symbols().next().is_none());
            assert!(module.required_runtime_program().is_some());
            let reducer = if export == PreparedAggregateExports::COUNT {
                module.prepared_count_symbol()
            } else if export == PreparedAggregateExports::SPAN_SUM {
                module.prepared_span_sum_symbol()
            } else {
                module.prepared_grep_count_symbol()
            };
            assert_eq!(reducer, Some(module.entry_symbol()));
            let global_functions = module
                .symbols()
                .iter()
                .filter(|symbol| {
                    symbol.binding == crate::SymbolBinding::Global
                        && symbol.kind == crate::SymbolKind::Function
                        && symbol.section.is_some()
                })
                .collect::<Vec<_>>();
            assert_eq!(global_functions.len(), 1);
            assert_eq!(global_functions[0].name, module.entry_symbol());
            let fragment = module
                .symbols()
                .iter()
                .find(|symbol| {
                    symbol.name == ".Lfre_aot_regex_ordered_nfa_operation_fragment_v1"
                })
                .expect("operation-only Ordered-NFA fragment symbol");
            let fragment_end = fragment
                .offset
                .checked_add(fragment.size)
                .expect("operation-only fragment extent");
            for internal_name in [
                ".Lfre_aot_regex_ordered_nfa_operation_fragment_v1",
                ".Lfre_aot_regex_ordered_nfa_operation_private_v1",
                ".Lfre_aot_regex_ordered_nfa_private_v1",
                ".Lfre_aot_regex_ordered_nfa_bulk_gate_v1",
            ] {
                let internal = module
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == internal_name)
                    .unwrap_or_else(|| panic!("missing operation-only symbol {internal_name}"));
                assert_eq!(internal.binding, crate::SymbolBinding::Local);
                assert_eq!(internal.kind, crate::SymbolKind::Function);
                assert_eq!(internal.section, fragment.section);
                assert!(internal.offset >= fragment.offset);
                assert!(
                    internal
                        .offset
                        .checked_add(internal.size)
                        .is_some_and(|end| end <= fragment_end),
                    "operation-only internal escaped its local fragment: {internal_name}",
                );
            }
            assert!(
                module.symbols().iter().all(|symbol| !symbol.name.contains("trusted")),
                "the trusted post-gate label must never become a symbol",
            );
            assert!(
                global_functions[0].offset >= fragment_end,
                "the only exported function must be the appended reducer",
            );

            let private = module
                .symbols()
                .iter()
                .find(|symbol| symbol.name == ".Lfre_aot_regex_ordered_nfa_private_v1")
                .expect("operation-only private search symbol");
            let gate = module
                .symbols()
                .iter()
                .find(|symbol| symbol.name == ".Lfre_aot_regex_ordered_nfa_bulk_gate_v1")
                .expect("operation-only bulk gate symbol");
            let reducer_start = usize::try_from(global_functions[0].offset)
                .expect("operation-only reducer start");
            let reducer_end = usize::try_from(
                global_functions[0]
                    .offset
                    .checked_add(global_functions[0].size)
                    .expect("operation-only reducer extent"),
            )
            .expect("operation-only reducer end");
            let calls = generated_local_call_sites(
                target.architecture,
                module.sections()[0].bytes(),
                reducer_start,
                reducer_end,
            );
            let calls_to = |target_offset: u64| {
                calls
                    .iter()
                    .filter_map(|&(site, target)| {
                        (u64::try_from(target).ok() == Some(target_offset)).then_some(site)
                    })
                    .collect::<Vec<_>>()
            };
            let gate_calls = calls_to(gate.offset);
            let private_calls = calls_to(private.offset);
            assert_eq!(
                gate_calls.len(),
                1,
                "one required gate call: {target:?}/{export:?}",
            );
            assert_eq!(
                private_calls.len(),
                1,
                "one private search call site: {target:?}/{export:?}",
            );
            assert!(
                gate_calls[0] < private_calls[0],
                "the private loop must be reachable only after its required gate",
            );
            assert!(module.relocations().iter().all(|relocation| {
                module
                    .symbols()
                    .get(relocation.symbol)
                    .is_some_and(|symbol| symbol.section.is_some())
            }));
        }
    }
}

#[test]
fn prepared_v15_scalar_operation_rejects_every_non_scalar_export_shape() {
    for exports in [
        PreparedAggregateExports::NONE,
        PreparedAggregateExports::COUNT.union(PreparedAggregateExports::SPAN_SUM),
        PreparedAggregateExports::ALL,
    ] {
        let error = crate::compile_with_prepared_ordered_nfa_v15_scalar_operation_reported(
            CompileRequest::new(r"\b\w{12,}\b", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            exports,
        )
        .expect_err("non-scalar V15 operation export shape");
        assert!(matches!(
            error,
            CompileError::PreparedScalarOperationRequiresSingleExport { actual }
                if actual == exports
        ));
    }
}

#[test]
fn prepared_aggregate_exports_enforce_the_final_object_limit() {
    let request = || {
        CompileRequest::new("a+|bc", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span)
    };
    let ordinary = compile(request()).expect("base object for exact size limit");
    let limits = CompileLimitsV1 {
        max_object_bytes: ordinary.object().len(),
        ..CompileLimitsV1::default()
    };
    let error = compile_with_prepared_aggregate_exports(
        request().limits(limits),
        PreparedAggregateExports::ALL,
    )
    .expect_err("aggregate wrappers must be checked against the final object size");
    assert!(matches!(
        error,
        CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) if limit == ordinary.object().len() && required > limit
    ));
}

#[test]
fn native_prepared_aggregate_object_limit_has_exact_boundary() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    let request = |limits| {
        CompileRequest::new("a+", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span)
            .limits(limits)
    };
    let baseline = compile_with_prepared_aggregate_exports(
        request(CompileLimitsV1::default()),
        exports,
    )
    .expect("native aggregate exact resource baseline");
    assert_eq!(
        baseline.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeFusedWithRuntimeHelper),
    );
    let exact_limits = CompileLimitsV1 {
        max_object_bytes: baseline.object().len(),
        ..CompileLimitsV1::default()
    };
    let exact = compile_with_prepared_aggregate_exports(request(exact_limits), exports)
        .expect("exact native aggregate object boundary");
    assert_eq!(exact.object(), baseline.object());
    assert_eq!(exact.receipt(), baseline.receipt());
    let one_below = CompileLimitsV1 {
        max_object_bytes: baseline
            .object()
            .len()
            .checked_sub(1)
            .expect("nonempty native aggregate object"),
        ..CompileLimitsV1::default()
    };
    let error = compile_with_prepared_aggregate_exports(request(one_below), exports)
        .expect_err("one below native aggregate object boundary");
    assert!(matches!(
        error,
        CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) if limit.checked_add(1) == Some(baseline.object().len())
            && required == baseline.object().len()
    ));
}

#[test]
fn ordered_nfa_aggregate_object_cap_rebuilds_the_whole_incumbent_transaction() {
    let target = Target::x86_64_linux();
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    let request = |max_object_bytes| {
        CompileRequest::new(r"(?-u:[\x00-\xFF])\bfoo\b", target)
            .mode(CompileMode::Fast)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let base = compile(request(usize::MAX)).expect("unbounded Ordered-NFA base object");
    let native = compile_with_prepared_aggregate_exports(request(usize::MAX), exports)
        .expect("unbounded Ordered-NFA aggregate object");
    assert!(!base.module().has_ordered_nfa_start_prefix());
    assert!(!native.module().has_ordered_nfa_start_prefix());
    assert_eq!(
        native.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeOrderedNfaFused),
    );
    assert_eq!(
        native.receipt().required_prepare_capabilities,
        PREPARED_CAPABILITY_ORDERED_NFA_V15,
    );
    assert!(base.object().len() < native.object().len());

    let serialized = native.program().serialize().expect("serialize aggregate fixture");
    let incumbent = crate::CompiledModule::lower_without_ordered_nfa(
        native.program(),
        target,
        true,
    )
    .expect("Ordered-disabled aggregate base")
    .append_prepared_aggregate_exports(
        exports,
        native.program().artifact_identity(),
        &serialized,
    )
    .expect("append incumbent aggregate helpers");
    let incumbent_object = emit_object(
        &incumbent,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
    )
    .expect("Ordered-disabled aggregate object");
    assert!(incumbent_object.len() < native.object().len());
    assert_eq!(
        incumbent.prepared_aggregate_strategy(),
        Some(PreparedAggregateStrategy::RuntimeHelper),
    );

    let exact_native = compile_with_prepared_aggregate_exports(
        request(native.object().len()),
        exports,
    )
    .expect("exact native aggregate object boundary");
    assert_eq!(exact_native.object(), native.object());
    let native_one_below = native
        .object()
        .len()
        .checked_sub(1)
        .expect("nonempty native aggregate object");
    assert!(base.object().len() <= native_one_below);
    assert!(incumbent_object.len() <= native_one_below);
    let declined = compile_with_prepared_aggregate_exports(
        request(native_one_below),
        exports,
    )
    .expect("native aggregate one-below soft fallback");
    assert_eq!(declined.module(), &incumbent);
    assert_eq!(declined.object(), incumbent_object);
    assert_eq!(declined.receipt().required_prepare_capabilities, 0);
    assert_eq!(
        declined.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::RuntimeHelper),
    );

    let exact_incumbent = compile_with_prepared_aggregate_exports(
        request(incumbent_object.len()),
        exports,
    )
    .expect("exact incumbent aggregate object boundary");
    assert_eq!(exact_incumbent.module(), &incumbent);
    assert_eq!(exact_incumbent.object(), incumbent_object);
    let incumbent_one_below = incumbent_object
        .len()
        .checked_sub(1)
        .expect("nonempty incumbent aggregate object");
    assert!(matches!(
        compile_with_prepared_aggregate_exports(
            request(incumbent_one_below),
            exports,
        ),
        Err(CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        })) if limit == incumbent_one_below && required > limit
    ));
}

#[test]
fn direct_native_aggregate_object_limit_has_exact_boundary() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    let request = |max_object_bytes| {
        CompileRequest::new("[ab]+z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(CompileLimitsV1 {
                max_object_bytes,
                ..CompileLimitsV1::default()
            })
    };
    let ordinary = compile(request(usize::MAX)).expect("direct native aggregate base");
    let serialized = ordinary
        .program()
        .serialize()
        .expect("serialize direct base");
    let incumbent = ordinary
        .module()
        .clone()
        .without_complete_span_reduce_for_aggregate()
        .expect("remove optional complete Span reducer recipe")
        .without_direct_span_trusted_core_for_aggregate()
        .expect("remove optional direct Span core receipt")
        .append_prepared_aggregate_exports(
            exports,
            ordinary.program().artifact_identity(),
            &serialized,
        )
        .expect("append DirectOrdinary incumbent wrappers");
    let incumbent_object = emit_object(
        &incumbent,
        crate::ObjectFormat::for_target(Target::x86_64_linux()),
        usize::MAX,
    )
    .expect("emit DirectOrdinary incumbent object");
    assert!(!incumbent.uses_direct_span_trusted_core_aggregate());

    let baseline = compile_with_prepared_aggregate_exports(request(usize::MAX), exports)
    .expect("direct native aggregate exact resource baseline");
    assert_eq!(baseline.receipt().engine, EngineKind::OrderedDfa);
    assert_eq!(
        baseline.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeFused),
    );
    assert_eq!(baseline.module().prepared_entry_symbol(), None);
    assert!(baseline.module().uses_direct_span_trusted_core_aggregate());
    assert!(incumbent_object.len() < baseline.object().len());

    let exact = compile_with_prepared_aggregate_exports(request(baseline.object().len()), exports)
        .expect("exact direct native aggregate object boundary");
    assert_eq!(exact.object(), baseline.object());
    assert_eq!(exact.receipt(), baseline.receipt());

    let candidate_one_below = baseline.object().len() - 1;
    assert!(incumbent_object.len() <= candidate_one_below);
    let declined = compile_with_prepared_aggregate_exports(request(candidate_one_below), exports)
        .expect("trusted-core text cap restores DirectOrdinary incumbent");
    assert_eq!(declined.module(), &incumbent);
    assert_eq!(declined.object(), incumbent_object);
    assert!(!declined.module().uses_direct_span_trusted_core_aggregate());

    let exact_incumbent =
        compile_with_prepared_aggregate_exports(request(incumbent_object.len()), exports)
            .expect("exact DirectOrdinary incumbent boundary");
    assert_eq!(exact_incumbent.module(), &incumbent);
    assert_eq!(exact_incumbent.object(), incumbent_object);

    let incumbent_one_below = incumbent_object.len() - 1;
    let incumbent_error = emit_object(
        &incumbent,
        crate::ObjectFormat::for_target(Target::x86_64_linux()),
        incumbent_one_below,
    )
    .expect_err("core-disabled incumbent must fail at the same boundary");
    let error = compile_with_prepared_aggregate_exports(request(incumbent_one_below), exports)
        .expect_err("one below DirectOrdinary incumbent remains terminal");
    let CompileError::Object(error) = error else {
        panic!("double ObjectBytes decline changed error class");
    };
    assert_eq!(error, incumbent_error);
}

#[test]
fn complete_span_reduce_object_limit_restores_each_exact_incumbent() {
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let exports = PreparedAggregateExports::COUNT;
        {
            let request = |max_object_bytes| {
                CompileRequest::new("[ab]+z", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span)
                    .limits(CompileLimitsV1 {
                        max_object_bytes,
                        ..CompileLimitsV1::default()
                    })
            };
            let ordinary = compile(request(usize::MAX)).expect("complete reducer base");
            let serialized = ordinary
                .program()
                .serialize()
                .expect("serialize complete reducer base");
            let identity = ordinary.program().artifact_identity();
            let trusted_incumbent = ordinary
                .module()
                .clone()
                .without_complete_span_reduce_for_aggregate()
                .expect("suppress complete reducer recipe")
                .append_prepared_aggregate_exports(exports, identity, &serialized)
                .expect("append trusted-core incumbent");
            let trusted_object = emit_object(
                &trusted_incumbent,
                crate::ObjectFormat::for_target(target),
                usize::MAX,
            )
            .expect("emit trusted-core incumbent");
            assert!(trusted_incumbent.uses_direct_span_trusted_core_aggregate());
            assert!(!trusted_incumbent.uses_complete_span_reduce_aggregate());

            let direct_incumbent = ordinary
                .module()
                .clone()
                .without_complete_span_reduce_for_aggregate()
                .expect("suppress complete reducer for DirectOrdinary")
                .without_direct_span_trusted_core_for_aggregate()
                .expect("suppress trusted core for DirectOrdinary")
                .append_prepared_aggregate_exports(exports, identity, &serialized)
                .expect("append DirectOrdinary incumbent");
            let direct_object = emit_object(
                &direct_incumbent,
                crate::ObjectFormat::for_target(target),
                usize::MAX,
            )
            .expect("emit DirectOrdinary incumbent");
            assert!(!direct_incumbent.uses_direct_span_trusted_core_aggregate());
            assert!(!direct_incumbent.uses_complete_span_reduce_aggregate());

            let selected = compile_with_prepared_aggregate_exports(
                request(usize::MAX),
                exports,
            )
            .expect("selected complete reducer");
            assert!(selected.module().uses_complete_span_reduce_aggregate());
            assert!(
                direct_object.len() <= trusted_object.len(),
                "DirectOrdinary object ({}) was larger than trusted-core object ({}) for {target:?} {exports:?}",
                direct_object.len(),
                trusted_object.len(),
            );
            assert!(
                trusted_object.len() < selected.object().len(),
                "trusted-core object ({}) was not smaller than complete-reducer object ({}) for {target:?} {exports:?}",
                trusted_object.len(),
                selected.object().len(),
            );

            let exact = compile_with_prepared_aggregate_exports(
                request(selected.object().len()),
                exports,
            )
            .expect("exact complete reducer object boundary");
            assert_eq!(exact.object(), selected.object());
            assert_eq!(exact.module(), selected.module());

            let trusted = compile_with_prepared_aggregate_exports(
                request(selected.object().len() - 1),
                exports,
            )
            .expect("complete reducer decline restores trusted core");
            assert_eq!(trusted.object(), trusted_object);
            assert_eq!(trusted.module(), &trusted_incumbent);

            if direct_object.len() < trusted_object.len() {
                let direct = compile_with_prepared_aggregate_exports(
                    request(trusted_object.len() - 1),
                    exports,
                )
                .expect("trusted-core decline restores DirectOrdinary");
                assert_eq!(direct.object(), direct_object);
                assert_eq!(direct.module(), &direct_incumbent);
            }

            let direct_one_below = direct_object.len() - 1;
            let expected = emit_object(
                &direct_incumbent,
                crate::ObjectFormat::for_target(target),
                direct_one_below,
            )
            .expect_err("DirectOrdinary one-below must remain terminal");
            let actual = compile_with_prepared_aggregate_exports(
                request(direct_one_below),
                exports,
            )
            .expect_err("complete reducer final incumbent cap remains terminal");
            let CompileError::Object(actual) = actual else {
                panic!("complete reducer final decline changed error class");
            };
            assert_eq!(actual, expected);
        }
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "links and executes generated aggregate wrappers against C ABI stubs"]
#[allow(
    clippy::too_many_lines,
    reason = "the linked-host ABI audit keeps generated object construction and its exact C harness in one test"
)]
fn linked_host_ordered_disabled_aggregate_wrappers_pass_authenticated_identity() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let target = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        }
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
    } else {
        Target::aarch64_macos()
    };
    let compiled = compile(
        CompileRequest::new(r"\bfoo\b", target)
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
    )
    .expect("Ordered-NFA semantic program");
    let serialized = compiled.program().serialize().expect("serialize helper fixture");
    let module = crate::CompiledModule::lower_without_ordered_nfa(
        compiled.program(),
        target,
        true,
    )
    .expect("Ordered-disabled runtime adapter")
    .append_prepared_aggregate_exports(
        PreparedAggregateExports::ALL,
        compiled.program().artifact_identity(),
        &serialized,
    )
    .expect("runtime-adapter aggregate object");
    let object_bytes = emit_object(
        &module,
        crate::ObjectFormat::for_target(target),
        usize::MAX,
    )
    .expect("emit runtime-adapter aggregate object");
    assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        module.prepared_aggregate_strategy(),
        Some(PreparedAggregateStrategy::RuntimeHelper),
    );
    let required = module.required_runtime_symbols().collect::<Vec<_>>();
    assert_eq!(
        required,
        [
            "fre_aot_regex_runtime_search_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_fill_spans_exclusive_v1",
            "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
            "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
            "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1",
        ],
    );
    let mut identity_initializer = String::new();
    for (index, byte) in compiled.program().artifact_identity().iter().enumerate() {
        if index != 0 {
            identity_initializer.push(',');
        }
        write!(identity_initializer, "{byte}U").expect("identity initializer");
    }
    let count_entry = module
        .prepared_count_symbol()
        .expect("host Count symbol");
    let span_sum_entry = module
        .prepared_span_sum_symbol()
        .expect("host SpanSum symbol");
    let grep_count_entry = module
        .prepared_grep_count_symbol()
        .expect("host GrepCount symbol");
    let source = format!(
        r"#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t (*reducer_t)(void *,const uint8_t *,size_t,uint64_t *);
extern uint32_t {count_entry}(void *,const uint8_t *,size_t,uint64_t *);
extern uint32_t {span_sum_entry}(void *,const uint8_t *,size_t,uint64_t *);
extern uint32_t {grep_count_entry}(void *,const uint8_t *,size_t,uint64_t *);
static const uint8_t expected_identity[32]={{{identity_initializer}}};
static const uint8_t haystack[4]={{'b','a','b','c'}};
static int owner,count_calls,sum_calls,grep_calls,search_calls;
uint32_t fre_aot_regex_runtime_search_v1(const uint8_t *program,const uint8_t *hay,size_t len,size_t start,size_t end,void *result){{
  (void)program;(void)hay;(void)len;(void)start;(void)end;(void)result;search_calls++;return 78U;
}}
uint32_t fre_aot_regex_runtime_search_exclusive_v1(void *handle,const uint8_t *hay,size_t len,size_t start,size_t end,void *result){{
  (void)handle;(void)hay;(void)len;(void)start;(void)end;(void)result;search_calls++;return 78U;
}}
uint32_t fre_aot_regex_runtime_fill_spans_exclusive_v1(void *handle,const uint8_t *hay,size_t len,void *state,void *results,size_t capacity,size_t *written){{
  (void)handle;(void)hay;(void)len;(void)state;(void)results;(void)capacity;(void)written;search_calls++;return 78U;
}}
static uint32_t check(void *handle,const uint8_t *hay,size_t len,uint64_t *out,const uint8_t *identity){{
  return handle==&owner&&hay==haystack&&len==sizeof(haystack)&&out!=0&&identity!=0&&memcmp(identity,expected_identity,32)==0?0U:77U;
}}
uint32_t fre_aot_regex_runtime_compiler_private_count_exclusive_v1(void *handle,const uint8_t *hay,size_t len,uint64_t *out,const uint8_t *identity){{
  uint32_t status=check(handle,hay,len,out,identity);count_calls++;if(status==0U)*out=11U;return status;
}}
uint32_t fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1(void *handle,const uint8_t *hay,size_t len,uint64_t *out,const uint8_t *identity){{
  uint32_t status=check(handle,hay,len,out,identity);sum_calls++;if(status==0U)*out=13U;return status;
}}
uint32_t fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1(void *handle,const uint8_t *hay,size_t len,uint64_t *out,const uint8_t *identity){{
  uint32_t status=check(handle,hay,len,out,identity);grep_calls++;if(status==0U)*out=17U;return status;
}}
int main(void){{
  uint64_t count=91U,sum=92U,grep=93U;
  if({count_entry}(&owner,haystack,sizeof(haystack),&count)!=0U||count!=11U||count_calls!=1||sum_calls!=0||grep_calls!=0||search_calls!=0)return 1;
  if({span_sum_entry}(&owner,haystack,sizeof(haystack),&sum)!=0U||sum!=13U||count_calls!=1||sum_calls!=1||grep_calls!=0||search_calls!=0)return 2;
  if({grep_count_entry}(&owner,haystack,sizeof(haystack),&grep)!=0U||grep!=17U||count_calls!=1||sum_calls!=1||grep_calls!=1||search_calls!=0)return 3;
  return 0;
}}
",
    );
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-prepared-aggregate-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create aggregate linker directory");
    let object = directory.join("aggregate.o");
    let c_path = directory.join("aggregate.c");
    let executable = directory.join("aggregate");
    fs::write(&object, object_bytes).expect("write aggregate object");
    fs::write(&c_path, source).expect("write aggregate C harness");
    let c_compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let status = Command::new(c_compiler)
        .arg("-O0")
        .arg(&c_path)
        .arg(&object)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("link aggregate C harness");
    assert!(status.success(), "aggregate harness failed to link");
    let result = Command::new(&executable)
        .output()
        .expect("execute aggregate C harness");
    assert!(
        result.status.success(),
        "aggregate wrapper status={:?}, stdout={}, stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
    fs::remove_dir_all(&directory).expect("remove aggregate linker directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links native fused reducers to the real runtime"]
#[allow(
    clippy::too_many_lines,
    reason = "the linked-host differential keeps native artifacts, independent regex oracles, and raw-boundary authentication checks together"
)]
fn linked_host_native_prepared_aggregates_match_regex_find_iter() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    const DIRECT_EXACT_START_PATTERN: &str =
        r"(?-u:[\x00-\x40])(?-u:[\x80-\xff])z";
    const DIRECT_EXACT_WIDTH_PATTERN: &str = r"(?-u:[\x00-\xff]{3})";
    const ORDERED_EDGE_DISPATCH_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x80-\xFF])\b";
    const ORDERED_TERMINAL_LOW_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x00-\x29])\b";
    const ORDERED_TERMINAL_SPARSE_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x01-\x08])\b";
    const ORDERED_TERMINAL_EXACT_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}[0-24-6](?-u:\b)";
    const ORDERED_TERMINAL_EXACT_BOUNDARIES_PATTERN: &str = concat!(
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}",
        r"(?-u:[\x00\x3F\x40\x7F\x80\xBF\xC0\xFF])(?-u:\b)",
    );
    const ORDERED_TERMINAL_EXACT_WIDTH_PATTERN: &str = concat!(
        r"^[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,120}",
        r"[0-24-6]$",
    );
    const ASSERTION_CACHE_PATTERN: &str =
        r"(?-u:(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))";
    const PLAIN_START_CLOSURE_PATTERN: &str =
        r"(?-u:(?:a?|bc)!(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))";
    const PREFIX_FLOW_PATTERN: &str = r"(?-u:a?a?a?a?a?a?a?a?(?:a.c|ab)\b)";
    const GUARDED_UNICODE_PREFIX_PATTERN: &str = r"\b\w{12,}\b";
    const ABSOLUTE_DOT_WIDTH_PATTERN: &str = r"^.{249}$";
    const ABSOLUTE_WORD_WIDTH_PATTERN: &str = r"^\w{10}$";
    let target = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        }
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("linked host ASIMD target")
    } else {
        Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("linked host ASIMD target")
    };
    let terminal_boundary_haystack = |byte| {
        let mut haystack = vec![b'A'; 100];
        haystack.push(byte);
        haystack.push(b'A');
        haystack
    };
    let fixtures = [
        (
            "[ab]+z",
            CompileMode::Optimizing,
            EngineKind::OrderedDfa,
            true,
            false,
            vec![
                Vec::new(),
                b"zz".to_vec(),
                b"xxabzyaaz".to_vec(),
                b"abzXbbzYa".to_vec(),
            ],
        ),
        (
            DIRECT_EXACT_START_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedDfa,
            true,
            false,
            vec![
                Vec::new(),
                vec![0x41, 0x80, b'z'],
                vec![0x40, 0x80, b'z', b'!', 0x00, 0xff, b'z'],
                vec![0x00, 0x80, b'x', 0x20, 0xc0, b'z', 0x41],
            ],
        ),
        (
            DIRECT_EXACT_WIDTH_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedDfa,
            true,
            false,
            vec![
                Vec::new(),
                vec![0x00, 0x01],
                vec![0x00, 0x01, 0x02],
                vec![0x00, 0x01, 0x02, 0x03, 0x80, 0xff, 0x7f],
            ],
        ),
        (
            "^a+$",
            CompileMode::Optimizing,
            EngineKind::OrderedContextDfa,
            true,
            false,
            vec![
                Vec::new(),
                b"\n".to_vec(),
                b"\r\n".to_vec(),
                b"a\r\nno\naa\n\n\ra\na\r".to_vec(),
                b"a\n".to_vec(),
                b"aaaaaaa\naaaaaaaa\naaaaaaaaa\r\naaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaa\r\n"
                    .to_vec(),
            ],
        ),
        (
            "(?:|a)",
            CompileMode::Optimizing,
            EngineKind::OrderedDfa,
            true,
            false,
            vec![
                Vec::new(),
                b"a".to_vec(),
                b"ba".to_vec(),
                b"aaa".to_vec(),
            ],
        ),
        (
            r"(?-u:\xFF+|a)",
            CompileMode::Optimizing,
            EngineKind::OrderedDfa,
            true,
            false,
            vec![
                vec![0xff],
                vec![b'a', 0xff, 0xff, b'b', 0x80, b'a'],
                vec![0x80, 0xfe],
            ],
        ),
        (
            r"(?-u:\b(?:foo|bar)\b)",
            CompileMode::Optimizing,
            EngineKind::OrderedContextDfa,
            true,
            false,
            vec![
                Vec::new(),
                b"foo bar".to_vec(),
                b"xfoo foo!barz bar".to_vec(),
                vec![0xff, b'f', b'o', b'o', 0xff, b'b', b'a', b'r', 0x80],
            ],
        ),
        (
            ASSERTION_CACHE_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                b"a b cc dd eee ffff ggggg h".to_vec(),
                b"za xb!ccz dd!eee ffff!ggggg".to_vec(),
                vec![0xff, b'a', b' ', b'b', 0x80, b'c', b'c', b' ', b'h'],
            ],
        ),
        (
            PLAIN_START_CLOSURE_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                b"!a".to_vec(),
                b"a!a".to_vec(),
                b"bc!a".to_vec(),
                b"zz!a a!b!cc bc!dd!eee".to_vec(),
                vec![0xff, b'!', b'a', 0x80, b'b', b'c', b'!', b'h'],
            ],
        ),
        (
            PREFIX_FLOW_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                b"zzaxc!".to_vec(),
                b"zzab!".to_vec(),
                b"zzabx".to_vec(),
                b"zzzz".to_vec(),
                vec![0xff, b'z', b'a', 0x80, b'c', b'!'],
            ],
        ),
        (
            ABSOLUTE_DOT_WIDTH_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                vec![b'a'; 248],
                vec![b'a'; 249],
                vec![b'a'; 250],
                "😀".repeat(249).into_bytes(),
                {
                    let mut bytes = vec![b'a'; 249];
                    bytes[248] = 0xff;
                    bytes
                },
            ],
        ),
        (
            ABSOLUTE_WORD_WIDTH_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                b"abcdefghi".to_vec(),
                b"abcdefghij".to_vec(),
                b"abcdefghijk".to_vec(),
                "Ж".repeat(10).into_bytes(),
                vec![b'a'; 44],
                vec![0xff; 10],
            ],
        ),
        (
            "a+|bc",
            CompileMode::Fast,
            EngineKind::OrderedNfa,
            false,
            false,
            vec![
                Vec::new(),
                b"zz".to_vec(),
                b"babcaa".to_vec(),
                b"aaaaXbcYaa".to_vec(),
            ],
        ),
        (
            r"(?:\b|ab)",
            CompileMode::Fast,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![Vec::new(), b"x".to_vec(), b"ab".to_vec(), b"zabz".to_vec()],
        ),
        (
            r"\b(?:Ж+|foo)\b",
            CompileMode::Fast,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                "Ж ЖЖ foo".as_bytes().to_vec(),
                vec![0xff, b'f', b'o', b'o', 0x80],
            ],
        ),
        (
            r"(?-u:\b(?:foo|bar)\b)",
            CompileMode::Fast,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                b"foo bar".to_vec(),
                vec![0xff, b'f', b'o', b'o', 0x80, b'b', b'a', b'r'],
            ],
        ),
        (
            ORDERED_EDGE_DISPATCH_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                vec![b'A'; 96],
                {
                    let mut haystack = vec![b'A'; 99];
                    haystack.extend_from_slice(&[0x80, b' ']);
                    haystack
                },
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.extend_from_slice(&[0x80, b'A']);
                    haystack
                },
                {
                    let mut haystack = vec![b'z'; 130];
                    haystack.extend_from_slice(&[0xff, b' ', b'Q', 0x80]);
                    haystack
                },
                {
                    let mut haystack = vec![0xff, 0xfe, b' '];
                    haystack.extend(std::iter::repeat_n(b'z', 100));
                    haystack.extend_from_slice(&[0x80, b'z', 0x81]);
                    haystack
                },
            ],
        ),
        (
            ORDERED_TERMINAL_LOW_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                vec![b'A'; 96],
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.extend_from_slice(&[0x20, b'A']);
                    haystack
                },
                {
                    let mut haystack = vec![0xff, 0xfe, b'Q'];
                    haystack.extend(std::iter::repeat_n(b'z', 100));
                    haystack.extend_from_slice(&[0x29, b'z', 0x80]);
                    haystack
                },
            ],
        ),
        (
            ORDERED_TERMINAL_SPARSE_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                vec![b'A'; 96],
                vec![b'A'; 4_096],
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.extend_from_slice(&[0x01, b'A']);
                    haystack
                },
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.extend_from_slice(&[0x08, b'A']);
                    haystack
                },
                {
                    let mut haystack = Vec::new();
                    for (index, padding) in [0_usize, 1, 15, 16, 17, 63, 64, 65]
                        .into_iter()
                        .enumerate()
                    {
                        haystack.extend(std::iter::repeat_n(b'!', padding));
                        haystack.extend(std::iter::repeat_n(b'A', 100));
                        haystack.push(1 + u8::try_from(index).unwrap());
                        haystack.extend_from_slice(b"A!");
                    }
                    haystack
                },
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.extend_from_slice(&[0x01, b'A', b'!']);
                    haystack.extend(std::iter::repeat_n(b'!', 128));
                    haystack.extend_from_slice(&[0x08, b'!']);
                    haystack
                },
            ],
        ),
        (
            ORDERED_TERMINAL_EXACT_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                vec![b'3'; 64],
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.push(b'0');
                    haystack
                },
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.push(b'0');
                    haystack.extend(std::iter::repeat_n(b'3', 63));
                    haystack
                },
                {
                    let mut haystack = vec![b'A'; 100];
                    haystack.push(b'0');
                    haystack.extend(std::iter::repeat_n(b'3', 64));
                    haystack
                },
                {
                    let mut haystack = vec![b'!'];
                    haystack.extend(std::iter::repeat_n(b'A', 100));
                    haystack.extend_from_slice(b"0!");
                    haystack
                },
                vec![b'3'; 257],
                {
                    let mut haystack = vec![b'!'];
                    haystack.extend(std::iter::repeat_n(b'A', 100));
                    haystack.extend_from_slice(b"0!");
                    haystack.extend(std::iter::repeat_n(b'3', 257));
                    haystack
                },
                {
                    let mut haystack = vec![b'!'];
                    haystack.extend(std::iter::repeat_n(b'A', 100));
                    haystack.push(b'0');
                    haystack.extend(std::iter::repeat_n(b'3', 63));
                    haystack.push(b'!');
                    haystack
                },
                {
                    let mut haystack = vec![b'!'];
                    haystack.extend(std::iter::repeat_n(b'A', 100));
                    haystack.push(b'0');
                    haystack.extend(std::iter::repeat_n(b'3', 64));
                    haystack.push(b'!');
                    haystack
                },
            ],
        ),
        (
            ORDERED_TERMINAL_EXACT_BOUNDARIES_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                terminal_boundary_haystack(0x00),
                terminal_boundary_haystack(0x3f),
                terminal_boundary_haystack(0x40),
                terminal_boundary_haystack(0x7f),
                terminal_boundary_haystack(0x80),
                terminal_boundary_haystack(0xbf),
                terminal_boundary_haystack(0xc0),
                terminal_boundary_haystack(0xff),
                terminal_boundary_haystack(0x3e),
                vec![b'A'; 4_096],
                {
                    let mut haystack = vec![b'A'; 101];
                    haystack.push(0x00);
                    haystack.extend(std::iter::repeat_n(b'A', 4_096));
                    haystack
                },
            ],
        ),
        (
            ORDERED_TERMINAL_EXACT_WIDTH_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![vec![b'A'; 99], {
                let mut haystack = vec![b'A'; 100];
                haystack.push(b'0');
                haystack
            }],
        ),
        (
            GUARDED_UNICODE_PREFIX_PATTERN,
            CompileMode::Optimizing,
            EngineKind::OrderedNfa,
            false,
            true,
            vec![
                Vec::new(),
                b"abcdefghijk".to_vec(),
                b"abcdefghijkl".to_vec(),
                b"!abcdefghijkl?".to_vec(),
                "Ж".repeat(11).into_bytes(),
                "Ж".repeat(12).into_bytes(),
                vec![b'['; 12],
                {
                    let mut haystack = vec![0xff];
                    haystack.extend_from_slice(b"abcdefghijkl");
                    haystack.push(0x80);
                    haystack
                },
            ],
        ),
    ];
    let exports = PreparedAggregateExports::ALL;
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-native-prepared-aggregate-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create native aggregate linker directory");
    let mut objects = Vec::new();
    let mut compiled = Vec::new();
    let mut source = String::from(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         typedef void *handle_t;\n\
         typedef uint32_t (*reducer_t)(handle_t,const unsigned char*,size_t,uint64_t*);\n\
         extern uint32_t fre_test_poison_reducer_stack(handle_t,const unsigned char*,size_t,uint64_t*,reducer_t);\n\
         typedef struct {size_t next_start;size_t last_match_end;uint32_t flags;uint32_t reserved;} iter_state_t;\n\
         typedef struct {size_t start;size_t end;} span_t;\n\
         typedef struct {uint32_t size;uint32_t version;uint64_t operations;uint64_t start_work;uint64_t grep_bytes;uint64_t reserved[4];} prepare_v2_t;\n\
         typedef struct {uint32_t size;uint32_t version;uint64_t operations;uint64_t start_work;uint64_t grep_bytes;uint64_t v2_reserved[4];uint64_t handle_bytes;uint64_t scratch_bytes;uint64_t setup_work;uint64_t required;uint64_t reserved[2];} prepare_v3_t;\n\
         extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(const unsigned char*,size_t,handle_t*);\n\
         extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v2(const unsigned char*,size_t,const prepare_v2_t*,handle_t*);\n\
         extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);\n\
         extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);\n",
    );
    for (fixture_index, (pattern, mode, expected_engine, direct, ordered_native, haystacks)) in
        fixtures.iter().enumerate()
    {
        let mut request = CompileRequest::new(*pattern, target)
            .mode(*mode)
            .output(OutputContract::Span);
        let terminal_prefilter_fixture = *pattern == ORDERED_EDGE_DISPATCH_PATTERN
            || *pattern == ORDERED_TERMINAL_LOW_PATTERN
            || *pattern == ORDERED_TERMINAL_SPARSE_PATTERN;
        let terminal_exact_set_trim_fixture = *pattern == ORDERED_TERMINAL_EXACT_PATTERN
            || *pattern == ORDERED_TERMINAL_EXACT_BOUNDARIES_PATTERN;
        let terminal_exact_set_width_fixture = *pattern == ORDERED_TERMINAL_EXACT_WIDTH_PATTERN;
        let terminal_exact_set_fixture =
            terminal_exact_set_trim_fixture || terminal_exact_set_width_fixture;
        let forced_ordered_graph_fixture = terminal_prefilter_fixture
            || terminal_exact_set_fixture
            || *pattern == ASSERTION_CACHE_PATTERN
            || *pattern == PLAIN_START_CLOSURE_PATTERN
            || *pattern == PREFIX_FLOW_PATTERN
            || *pattern == GUARDED_UNICODE_PREFIX_PATTERN
            || *pattern == ABSOLUTE_DOT_WIDTH_PATTERN
            || *pattern == ABSOLUTE_WORD_WIDTH_PATTERN;
        let artifact = if forced_ordered_graph_fixture {
            request.limits.determinize.max_states = 0;
            let mut slow_limits = SlowAotLimits::default();
            slow_limits.determinize.max_states = 0;
            slow_limits.determinize.max_transitions = 0;
            slow_limits.determinize.max_work = 0;
            crate::compile_with_prepared_aggregate_exports_and_slow_aot_limits(
                request,
                exports,
                slow_limits,
            )
        } else {
            compile_with_prepared_aggregate_exports(request, exports)
        }
        .expect("compile linked native aggregate fixture");
        assert_eq!(artifact.receipt().engine, *expected_engine, "{pattern:?}");
        assert_eq!(
            artifact.receipt().prepared_aggregate_strategy,
            Some(if *ordered_native {
                PreparedAggregateStrategy::NativeOrderedNfaFused
            } else if *direct {
                PreparedAggregateStrategy::NativeFused
            } else {
                PreparedAggregateStrategy::NativeFusedWithRuntimeHelper
            }),
            "{pattern:?}",
        );
        if *direct {
            assert_eq!(
                artifact.receipt().required_prepare_capabilities,
                0,
                "{pattern:?}",
            );
            assert!(
                artifact.module().required_runtime_symbols().next().is_none(),
                "{pattern:?}",
            );
            assert_eq!(
                artifact.module().prepared_entry_symbol(),
                None,
                "fixture {pattern:?} must exercise the direct ordinary loop",
            );
            if *pattern == DIRECT_EXACT_START_PATTERN {
                let view = artifact
                    .program()
                    .native_dfa_view()
                    .expect("exact-start fixture retains its direct DFA view");
                assert_eq!(view.exact_match_width, Some(3));
                assert!(!view.dfa.initial_pending);
                assert_ne!(
                    artifact.module().start_accelerator(),
                    StartAccelerator::None,
                    "exact-start fixture lost its selective primary",
                );
            } else if *pattern == DIRECT_EXACT_WIDTH_PATTERN {
                let view = artifact
                    .program()
                    .native_dfa_view()
                    .expect("exact-width fixture retains its direct DFA view");
                assert_eq!(view.exact_match_width, Some(3));
                assert!(!view.dfa.initial_pending);
                assert_eq!(
                    artifact.module().start_accelerator(),
                    StartAccelerator::None,
                    "unselective exact-width fixture unexpectedly gained a start scan",
                );
            } else if *pattern == "(?:|a)" {
                let view = artifact
                    .program()
                    .native_dfa_view()
                    .expect("initial-pending fixture retains its direct DFA view");
                assert!(view.dfa.initial_pending);
            } else if *pattern == "[ab]+z" {
                let view = artifact
                    .program()
                    .native_dfa_view()
                    .expect("variable-reverse fixture retains its direct DFA view");
                assert_eq!(view.exact_match_width, None);
                assert!(!view.dfa.initial_pending);
                assert!(view.dfa.reverse_initial.is_some());
                assert!(!view.dfa.reverse_cells.is_empty());
            }
            assert_eq!(
                artifact.module().uses_direct_span_trusted_core_aggregate(),
                *expected_engine == EngineKind::OrderedDfa,
                "fixture {pattern:?} changed its trusted-core eligibility",
            );
        } else {
            assert!(
                artifact.module().prepared_entry_symbol().is_some(),
                "fixture {pattern:?} must retain one prepared loop",
            );
        }
        if *ordered_native {
            assert_eq!(
                artifact.receipt().required_prepare_capabilities,
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
                "{pattern:?}",
            );
            assert_eq!(
                artifact.module().prepared_bulk_strategy(),
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                "{pattern:?}",
            );
            if terminal_prefilter_fixture {
                assert!(
                    artifact
                        .program()
                        .native_ordered_nfa_view()
                        .and_then(|view| view.ordered_edge_dispatch)
                        .is_some(),
                    "wide-row fixture lost its canonical dispatch",
                );
                assert_eq!(
                    artifact
                        .program()
                        .native_ordered_nfa_view()
                        .and_then(|view| view.terminal_range),
                    Some(crate::ordered_nfa_native::NativeOrderedNfaTerminalRangeV1 {
                        start: if *pattern == ORDERED_EDGE_DISPATCH_PATTERN {
                            0x80
                        } else if *pattern == ORDERED_TERMINAL_SPARSE_PATTERN {
                            0x01
                        } else {
                            0x00
                        },
                        end: if *pattern == ORDERED_EDGE_DISPATCH_PATTERN {
                            0xff
                        } else if *pattern == ORDERED_TERMINAL_SPARSE_PATTERN {
                            0x08
                        } else {
                            0x29
                        },
                        reverse_depth: 0,
                    }),
                    "wide-row fixture lost its terminal range",
                );
                assert!(artifact.module().has_ordered_nfa_terminal_range_object());
                assert!(artifact.module().has_ordered_edge_dispatch_object());
                if cfg!(target_arch = "aarch64")
                    && *pattern == ORDERED_TERMINAL_SPARSE_PATTERN
                {
                    let text = artifact
                        .module()
                        .sections()
                        .iter()
                        .find(|section| section.kind == SectionKind::Text)
                        .expect("sparse terminal fixture text");
                    assert!(text
                        .bytes()
                        .chunks_exact(4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                        .any(|word| word == 0x4c40_2198),
                        "linked sparse terminal fixture lost its four-vector LD1"
                    );
                }
                assert!(
                    artifact
                        .module()
                        .symbols()
                        .iter()
                        .any(|symbol| symbol.name == ".Lfre_aot_regex_ordered_nfa_object_v3"),
                    "wide-row fixture did not publish its composed V3 object",
                );
            }
            if terminal_exact_set_fixture {
                let view = artifact
                    .program()
                    .native_ordered_nfa_view()
                    .expect("fragmented terminal fixture retains its Ordered-NFA view");
                assert!(view.terminal_exact_set.is_some());
                assert!(view.terminal_range.is_none());
                assert!(artifact.module().has_ordered_nfa_terminal_exact_set());
                if terminal_exact_set_width_fixture {
                    assert!(view.whole_window_width_bounds.is_some());
                    assert!(artifact.module().has_ordered_nfa_whole_window_width_gate());
                } else {
                    assert!(view.whole_window_width_bounds.is_none());
                    assert!(
                        !artifact.module().has_ordered_nfa_whole_window_width_gate(),
                        "fragmented terminal linked fixture must exercise the aggregate trim",
                    );
                }
                assert!(!artifact.module().has_ordered_nfa_terminal_range_object());
                assert!(artifact.module().has_ordered_edge_dispatch_object());
            }
            if *pattern == ASSERTION_CACHE_PATTERN {
                let ordered_view = artifact
                    .program()
                    .native_ordered_nfa_view()
                    .expect("assertion-cache fixture retains its Ordered-NFA view");
                assert!(
                    ordered_view.start_prefix_first_set.is_some(),
                    "assertion-cache fixture lost its anchored first-byte proof",
                );
                let image = crate::ordered_nfa_native::NativeOrderedNfaObjectImage::try_build(
                    ordered_view,
                    usize::MAX,
                )
                .expect("build assertion-cache object")
                .expect("assertion-cache object remains native");
                assert!(
                    image.layout.cache_boundary_assertions,
                    "assertion-cache fixture lost its dense exact-kind reuse",
                );
                assert_eq!(
                    image.layout.assertion_kinds, 0x42,
                    "assertion-cache fixture lost its Nosey-shaped two-kind mask",
                );
                assert!(
                    image
                        .layout
                        .start_closure_dispatch
                        .is_some_and(|layout| layout.guarded),
                    "assertion-cache fixture lost its guarded start closure",
                );
                assert!(artifact.module().has_ordered_nfa_start_closure_dispatch());
                assert!(
                    image.layout.start_prefix.is_none(),
                    "cheap guarded closure must retain the incumbent root loop",
                );
                assert!(!artifact.module().has_ordered_nfa_start_prefix());
            }
            if *pattern == PLAIN_START_CLOSURE_PATTERN {
                assert!(
                    artifact
                        .program()
                        .native_ordered_nfa_view()
                        .and_then(|view| view.start_closure_dispatch)
                        .is_some_and(|program| !program.is_guarded()),
                    "plain fixture lost its start closure",
                );
                assert!(artifact.module().has_ordered_nfa_start_closure_dispatch());
            }
            if *pattern == PREFIX_FLOW_PATTERN {
                let image = crate::ordered_nfa_native::NativeOrderedNfaObjectImage::try_build(
                    artifact
                        .program()
                        .native_ordered_nfa_view()
                        .expect("prefix-flow fixture retains its Ordered-NFA view"),
                    usize::MAX,
                )
                .expect("build prefix-flow object")
                .expect("prefix-flow object remains native");
                assert_eq!(
                    image
                        .layout
                        .start_prefix
                        .expect("prefix-flow fixture selects its first-byte filter")
                        .ranges()
                        .iter()
                        .map(|range| (range.start, range.end))
                        .collect::<Vec<_>>(),
                    [(b'a', b'a')],
                );
                assert!(artifact.module().has_ordered_nfa_start_prefix());
            }
            if *pattern == GUARDED_UNICODE_PREFIX_PATTERN {
                let ordered_view = artifact
                    .program()
                    .native_ordered_nfa_view()
                    .expect("guarded Unicode-prefix fixture retains its Ordered-NFA view");
                let exact = ordered_view
                    .start_prefix_first_set
                    .expect("guarded Unicode-prefix fixture retains its exact first-byte set");
                assert_eq!(
                    exact.iter().map(|word| word.count_ones()).sum::<u32>(),
                    110,
                    "guarded Unicode-prefix fixture changed its exact first-byte set",
                );
                assert!(
                    ordered_view.start_closure_dispatch.is_none(),
                    "raw-only guarded prefix must not retain a start-closure program",
                );
                let image = crate::ordered_nfa_native::NativeOrderedNfaObjectImage::try_build(
                    ordered_view,
                    usize::MAX,
                )
                .expect("build guarded Unicode-prefix object")
                .expect("guarded Unicode-prefix object remains native");
                assert_eq!(
                    image
                        .layout
                        .start_prefix
                        .expect("guarded Unicode-prefix fixture selects its cover")
                        .ranges()
                        .iter()
                        .map(|range| (range.start, range.end))
                        .collect::<Vec<_>>(),
                    [(0x30, 0x7a), (0xc2, 0xed), (0xef, 0xf0), (0xf3, 0xf3)],
                );
                assert!(
                    image.layout.start_closure_dispatch.is_none(),
                    "guarded Unicode prefix must remain independent of closure lowering",
                );
                assert!(artifact.module().has_ordered_nfa_start_prefix());
                assert!(!artifact.module().has_ordered_nfa_start_closure_dispatch());
            }
            if *pattern == ABSOLUTE_DOT_WIDTH_PATTERN
                || *pattern == ABSOLUTE_WORD_WIDTH_PATTERN
            {
                assert!(artifact.module().has_ordered_nfa_whole_window_width_gate());
                assert_eq!(
                    artifact
                        .program()
                        .native_ordered_nfa_view()
                        .unwrap()
                        .whole_window_width_bounds,
                    Some(if *pattern == ABSOLUTE_DOT_WIDTH_PATTERN {
                        crate::ordered_nfa_native::WholeWindowWidthBounds {
                            minimum: 249,
                            maximum: 996,
                        }
                    } else {
                        crate::ordered_nfa_native::WholeWindowWidthBounds {
                            minimum: 10,
                            maximum: 40,
                        }
                    }),
                );
            }
        } else {
            assert_eq!(
                artifact.receipt().required_prepare_capabilities,
                0,
                "{pattern:?}",
            );
        }
        let (program_symbol, program_len) = artifact
            .module()
            .required_runtime_program()
            .expect("aggregate preparation program");
        let count_symbol = artifact
            .module()
            .prepared_count_symbol()
            .expect("linked Count symbol");
        let span_sum_symbol = artifact
            .module()
            .prepared_span_sum_symbol()
            .expect("linked SpanSum symbol");
        let grep_count_symbol = artifact
            .module()
            .prepared_grep_count_symbol()
            .expect("linked GrepCount symbol");
        let span_fill_symbol = (*ordered_native).then(|| {
            artifact
                .module()
                .prepared_span_fill_symbol()
                .expect("Ordered-NFA linked Span-fill symbol")
        });
        let prepared_search_symbol = (*ordered_native).then(|| {
            artifact
                .module()
                .prepared_entry_symbol()
                .expect("Ordered-NFA linked prepared-search symbol")
        });
        writeln!(source, "extern const unsigned char {program_symbol}[];")
            .expect("declare aggregate program");
        writeln!(
            source,
            "extern uint32_t {count_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);"
        )
        .expect("declare Count entry");
        writeln!(
            source,
            "extern uint32_t {span_sum_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);"
        )
        .expect("declare SpanSum entry");
        writeln!(
            source,
            "extern uint32_t {grep_count_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);"
        )
        .expect("declare GrepCount entry");
        if let Some(span_fill_symbol) = span_fill_symbol {
            writeln!(
                source,
                "extern uint32_t {span_fill_symbol}(handle_t,const unsigned char*,size_t,iter_state_t*,span_t*,size_t,size_t*);"
            )
            .expect("declare Ordered-NFA Span-fill entry");
        }
        if let Some(prepared_search_symbol) = prepared_search_symbol {
            writeln!(
                source,
                "extern uint32_t {prepared_search_symbol}(handle_t,const unsigned char*,size_t,size_t,size_t,span_t*);"
            )
            .expect("declare Ordered-NFA prepared-search entry");
        }
        let oracle = Regex::new(pattern).expect("independent bytes regex oracle");
        for (case_index, haystack) in haystacks.iter().enumerate() {
            let spans = oracle
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let count = u64::try_from(spans.len()).expect("oracle Count");
            let span_sum = spans.iter().try_fold(0_u64, |sum, &(start, end)| {
                sum.checked_add(u64::try_from(end - start).expect("oracle span width"))
            })
            .expect("oracle SpanSum");
            let mut grep_count = 0_u64;
            let mut line_start = 0_usize;
            while line_start < haystack.len() {
                let remainder = &haystack[line_start..];
                let lf = remainder.iter().position(|&byte| byte == b'\n');
                let mut line_end = lf.map_or(haystack.len(), |offset| line_start + offset);
                if lf.is_some()
                    && line_end > line_start
                    && haystack[line_end - 1] == b'\r'
                {
                    line_end -= 1;
                }
                if oracle.is_match(&haystack[line_start..line_end]) {
                    grep_count = grep_count.checked_add(1).expect("oracle GrepCount");
                }
                let Some(offset) = lf else {
                    break;
                };
                line_start = line_start
                    .checked_add(offset)
                    .and_then(|value| value.checked_add(1))
                    .expect("oracle line progress");
            }
            let window_start = usize::from(haystack.len() >= 3);
            let window_end = if haystack.len() >= 2 {
                haystack.len() - 1
            } else {
                haystack.len()
            };
            let window_match = if *pattern == ABSOLUTE_DOT_WIDTH_PATTERN
                || *pattern == ABSOLUTE_WORD_WIDTH_PATTERN
            {
                None
            } else if *pattern == PREFIX_FLOW_PATTERN || terminal_exact_set_fixture {
                fixed_width_window_oracle(&oracle, haystack, window_start, window_end)
            } else {
                oracle
                    .find_at(&haystack[..window_end], window_start)
                    .map(|matched| (matched.start(), matched.end()))
            };
            let initializer = if haystack.is_empty() {
                String::from("0")
            } else {
                haystack
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            writeln!(
                source,
                "static const unsigned char h{fixture_index}_{case_index}[]={{{initializer}}};"
            )
            .expect("write aggregate haystack");
            let span_fill_checks = if let Some(span_fill_symbol) = span_fill_symbol {
                let expected_initializer = if spans.is_empty() {
                    String::from("{0U,0U}")
                } else {
                    spans
                        .iter()
                        .map(|&(start, end)| format!("{{{start}U,{end}U}}"))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                writeln!(
                    source,
                    "static const span_t e{fixture_index}_{case_index}[]={{{expected_initializer}}};"
                )
                .expect("write aggregate Span-fill oracle");
                format!(
                    concat!(
                        "{{iter_state_t it={{0U,0U,0U,0U}};span_t spans[64];size_t w=(size_t)-1;",
                        "memset(spans,0xa5,sizeof(spans));",
                        "if({span_fill_symbol}(h,h{fixture_index}_{case_index},{length}U,&it,spans,64U,&w)!=0U||w!={span_count}U)return 9;",
                        "if((it.flags&4U)==0U||it.reserved!=0U)return 10;",
                        "for(size_t i=0;i<w;i++)if(spans[i].start!=e{fixture_index}_{case_index}[i].start||spans[i].end!=e{fixture_index}_{case_index}[i].end)return 11;",
                        "iter_state_t done=it;unsigned char frozen[sizeof(spans)];memcpy(frozen,spans,sizeof(spans));w=(size_t)-1;",
                        "if({span_fill_symbol}(h,h{fixture_index}_{case_index},{length}U,&it,spans,64U,&w)!=0U||w!=0U||memcmp(&it,&done,sizeof(it))!=0||memcmp(spans,frozen,sizeof(spans))!=0)return 12;}}"
                    ),
                    span_fill_symbol = span_fill_symbol,
                    fixture_index = fixture_index,
                    case_index = case_index,
                    length = haystack.len(),
                    span_count = spans.len(),
                )
            } else {
                String::new()
            };
            let native_search = if let Some(prepared_search_symbol) = prepared_search_symbol {
                let (expected_status, expected_start, expected_end) = match window_match {
                    Some((start, end)) => (1_u32, start, end),
                    None => (0_u32, 0, 0),
                };
                let (full_status, full_start, full_end) = match spans.first().copied() {
                    Some((start, end)) => (1_u32, start, end),
                    None => (0_u32, 0, 0),
                };
                format!(
                    concat!(
                        "{{span_t one={{UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0xbbbbbbbbbbbbbbbb)}};",
                        "uint32_t q={prepared_search_symbol}(h,h{fixture_index}_{case_index},{length}U,{window_start}U,{window_end}U,&one);",
                        "if(q!={expected_status}U||one.start!={expected_start}U||one.end!={expected_end}U)return 13;",
                        "one.start=UINT64_C(0xaaaaaaaaaaaaaaaa);one.end=UINT64_C(0xbbbbbbbbbbbbbbbb);",
                        "q={prepared_search_symbol}(h,h{fixture_index}_{case_index},{length}U,0U,{length}U,&one);",
                        "if(q!={full_status}U||one.start!={full_start}U||one.end!={full_end}U)return 14;}}"
                    ),
                    prepared_search_symbol = prepared_search_symbol,
                    fixture_index = fixture_index,
                    case_index = case_index,
                    length = haystack.len(),
                    window_start = window_start,
                    window_end = window_end,
                    expected_status = expected_status,
                    expected_start = expected_start,
                    expected_end = expected_end,
                    full_status = full_status,
                    full_start = full_start,
                    full_end = full_end,
                )
            } else {
                String::new()
            };
            let count_call = if *direct {
                format!(
                    "fre_test_poison_reducer_stack(h,h{fixture_index}_{case_index},{}U,&c,{count_symbol})",
                    haystack.len(),
                )
            } else {
                format!(
                    "{count_symbol}(h,h{fixture_index}_{case_index},{}U,&c)",
                    haystack.len(),
                )
            };
            let span_sum_call = if *direct {
                format!(
                    "fre_test_poison_reducer_stack(h,h{fixture_index}_{case_index},{}U,&s,{span_sum_symbol})",
                    haystack.len(),
                )
            } else {
                format!(
                    "{span_sum_symbol}(h,h{fixture_index}_{case_index},{}U,&s)",
                    haystack.len(),
                )
            };
            writeln!(
                source,
                concat!(
                    "static int run{fixture_index}_{case_index}(void){{",
                    "const prepare_v2_t v2={{64U,2U,UINT64_C(15),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}}}};",
                    "handle_t h=0;uint64_t c=UINT64_C(0xaaaaaaaaaaaaaaaa),s=UINT64_C(0xbbbbbbbbbbbbbbbb),g=UINT64_C(0xeeeeeeeeeeeeeeee);uint32_t gq;",
                    "if(fre_aot_regex_runtime_prepare_exclusive_v2({program_symbol},{program_len}U,&v2,&h)!=0U)return 1;",
                    "if({count_call}!=0U||c!=UINT64_C({count}))return 2;",
                    "if({span_sum_call}!=0U||s!=UINT64_C({span_sum}))return 3;",
                    "gq={grep_count_symbol}(h,h{fixture_index}_{case_index},{length}U,&g);",
                    "if(UINT64_C({required})==0U){{if(gq!=0U)return 21;if(g!=UINT64_C({grep_count}))return 24;}}else{{if(gq!=3U||g!=UINT64_C(0xeeeeeeeeeeeeeeee))return 22;}}",
                    "{legacy_fill}",
                    "if(fre_aot_regex_runtime_destroy_exclusive_v1(h)!=0U)return 4;",
                    "if(UINT64_C({required})!=0){{",
                    "const prepare_v3_t v3={{112U,3U,UINT64_C(15),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C({required}),{{0,0}}}};",
                    "h=0;c=UINT64_C(0xcccccccccccccccc);s=UINT64_C(0xdddddddddddddddd);g=UINT64_C(0xffffffffffffffff);",
                    "if(fre_aot_regex_runtime_prepare_exclusive_v3({program_symbol},{program_len}U,&v3,&h)!=0U)return 5;",
                    "if({count_call}!=0U||c!=UINT64_C({count}))return 6;",
                    "if({span_sum_call}!=0U||s!=UINT64_C({span_sum}))return 7;",
                    "if({grep_count_symbol}(h,h{fixture_index}_{case_index},{length}U,&g)!=0U||g!=UINT64_C({grep_count}))return 23;",
                    "{native_fill}",
                    "{native_search}",
                    "if(fre_aot_regex_runtime_destroy_exclusive_v1(h)!=0U)return 8;",
                    "}}return 0;}}"
                ),
                fixture_index = fixture_index,
                case_index = case_index,
                program_symbol = program_symbol,
                program_len = program_len,
                count_call = count_call,
                count = count,
                span_sum_call = span_sum_call,
                span_sum = span_sum,
                grep_count_symbol = grep_count_symbol,
                grep_count = grep_count,
                length = haystack.len(),
                required = artifact.receipt().required_prepare_capabilities,
                legacy_fill = span_fill_checks,
                native_fill = span_fill_checks,
                native_search = native_search,
            )
            .expect("write aggregate differential case");
        }
        let object = directory.join(format!("aggregate-{fixture_index}.o"));
        fs::write(&object, artifact.object()).expect("write native aggregate object");
        objects.push(object);
        compiled.push(artifact);
    }

    let first = compiled
        .iter()
        .find(|artifact| artifact.module().has_ordered_nfa_terminal_range_object())
        .expect("V3 terminal-range authentication fixture");
    let second = compiled
        .iter()
        .find(|artifact| {
            artifact.receipt().required_prepare_capabilities
                == PREPARED_CAPABILITY_ORDERED_NFA_V15
                && artifact.program().artifact_identity()
                    != first.program().artifact_identity()
        })
        .expect("foreign Ordered-NFA authentication fixture");
    let exact = compiled
        .iter()
        .find(|artifact| {
            artifact.module().has_ordered_nfa_terminal_exact_set()
                && !artifact.module().has_ordered_nfa_whole_window_width_gate()
        })
        .expect("terminal exact-set authentication fixture");
    let exact_width = compiled
        .iter()
        .find(|artifact| {
            artifact.module().has_ordered_nfa_terminal_exact_set()
                && artifact.module().has_ordered_nfa_whole_window_width_gate()
        })
        .expect("terminal exact-set plus width authentication fixture");
    let (first_program, first_program_len) = first
        .module()
        .required_runtime_program()
        .expect("first authentication program");
    let (second_program, second_program_len) = second
        .module()
        .required_runtime_program()
        .expect("second authentication program");
    let (exact_width_program, exact_width_program_len) = exact_width
        .module()
        .required_runtime_program()
        .expect("terminal exact-set plus width authentication program");
    let first_count = first
        .module()
        .prepared_count_symbol()
        .expect("first authentication Count");
    let first_span_sum = first
        .module()
        .prepared_span_sum_symbol()
        .expect("first authentication SpanSum");
    let first_grep_count = first
        .module()
        .prepared_grep_count_symbol()
        .expect("first authentication GrepCount");
    let exact_count = exact
        .module()
        .prepared_count_symbol()
        .expect("terminal exact-set authentication Count");
    let exact_span_sum = exact
        .module()
        .prepared_span_sum_symbol()
        .expect("terminal exact-set authentication SpanSum");
    let exact_width_count = exact_width
        .module()
        .prepared_count_symbol()
        .expect("terminal exact-set plus width authentication Count");
    let exact_width_span_sum = exact_width
        .module()
        .prepared_span_sum_symbol()
        .expect("terminal exact-set plus width authentication SpanSum");
    writeln!(
        source,
        concat!(
            "static int authenticate_before_source(void){{",
            "handle_t right=0,wrong=0,width=0;",
            "const prepare_v3_t v3={{112U,3U,UINT64_C(14),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};",
            "uint64_t out=UINT64_C(0x1122334455667788);",
            "static const unsigned char readable[8]={{0}};",
            "unsigned char bytes[17];uint32_t q;int authentication_failed=0;memset(bytes,0xa5,sizeof(bytes));",
            "if(fre_aot_regex_runtime_prepare_exclusive_v3({first_program},{first_program_len}U,&v3,&right)!=0U)return 1;",
            "if(fre_aot_regex_runtime_prepare_exclusive_v3({second_program},{second_program_len}U,&v3,&wrong)!=0U)return 2;",
            "if(fre_aot_regex_runtime_prepare_exclusive_v3({exact_width_program},{exact_width_program_len}U,&v3,&width)!=0U)return 3;",
            "q={first_count}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={first_span_sum}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={first_grep_count}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={exact_count}(right,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={exact_span_sum}(right,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={exact_width_count}(width,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=0U||out!=0U)authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={exact_width_span_sum}(width,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=0U||out!=0U)authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={first_count}(wrong,readable,sizeof(readable),&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={first_span_sum}(wrong,readable,sizeof(readable),&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "if(authentication_failed)return 3;",
            "if({first_count}((handle_t)0,(const unsigned char*)(uintptr_t)1,8U,&out)!=5U||out!=UINT64_C(0x1122334455667788))return 13;",
            "if({first_count}(right,(const unsigned char*)0,0U,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 14;",
            "if({first_count}(right,(const unsigned char*)\"a\",1U,(uint64_t*)(void*)(bytes+1))!=2U)return 15;",
            "for(size_t i=0;i<sizeof(bytes);i++)if(bytes[i]!=0xa5U)return 16;",
            "if({first_count}(right,(const unsigned char*)\"a\",1U,(uint64_t*)0)!=2U)return 17;",
            "if({first_grep_count}(right,(const unsigned char*)\"a\",1U,(uint64_t*)0)!=2U)return 21;",
            "out=UINT64_C(0x1122334455667788);",
            "if({first_count}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 18;",
            "out=UINT64_C(0x1122334455667788);",
            "if({first_span_sum}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 19;",
            "out=UINT64_C(0x1122334455667788);",
            "if({first_grep_count}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 22;",
            "if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U||fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U||fre_aot_regex_runtime_destroy_exclusive_v1(width)!=0U)return 20;",
            "return 0;}}",
        ),
        first_program = first_program,
        first_program_len = first_program_len,
        second_program = second_program,
        second_program_len = second_program_len,
        exact_width_program = exact_width_program,
        exact_width_program_len = exact_width_program_len,
        first_count = first_count,
        first_span_sum = first_span_sum,
        first_grep_count = first_grep_count,
        exact_count = exact_count,
        exact_span_sum = exact_span_sum,
        exact_width_count = exact_width_count,
        exact_width_span_sum = exact_width_span_sum,
    )
    .expect("write authentication-before-source checks");
    source.push_str("int main(void){int status;\n");
    for (fixture_index, (_, _, _, _, _, haystacks)) in fixtures.iter().enumerate() {
        for case_index in 0..haystacks.len() {
            writeln!(
                source,
                concat!(
                    "status=run{fixture_index}_{case_index}();",
                    "if(status){{fprintf(stderr,\"fixture {fixture_index} case {case_index}: status=%d\\n\",status);return 1;}}",
                ),
                fixture_index = fixture_index,
                case_index = case_index,
            )
            .expect("invoke aggregate differential case");
        }
    }
    source.push_str(
        "status=authenticate_before_source();if(status){fprintf(stderr,\"authentication: status=%d\\n\",status);return 1;}return 0;}\n",
    );

    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the linked runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let c_path = directory.join("native-aggregate.c");
    let assembly_path = directory.join("poison-reducer-stack.S");
    let executable = directory.join("native-aggregate");
    fs::write(&c_path, source).expect("write native aggregate C harness");
    let assembly_symbol = if cfg!(target_os = "macos") {
        "_fre_test_poison_reducer_stack"
    } else {
        "fre_test_poison_reducer_stack"
    };
    let assembly = if cfg!(target_arch = "x86_64") {
        format!(
            r#".text
.globl {assembly_symbol}
.p2align 4, 0x90
{assembly_symbol}:
    movq %r8, %r11
    subq $128, %rsp
    movabsq $0xa5a5a5a5a5a5a5a5, %rax
    movq %rax,   0(%rsp)
    movq %rax,   8(%rsp)
    movq %rax,  16(%rsp)
    movq %rax,  24(%rsp)
    movq %rax,  32(%rsp)
    movq %rax,  40(%rsp)
    movq %rax,  48(%rsp)
    movq %rax,  56(%rsp)
    movq %rax,  64(%rsp)
    movq %rax,  72(%rsp)
    movq %rax,  80(%rsp)
    movq %rax,  88(%rsp)
    movq %rax,  96(%rsp)
    movq %rax, 104(%rsp)
    movq %rax, 112(%rsp)
    movq %rax, 120(%rsp)
    addq $128, %rsp
    movabsq $0x5a5a5a5a5a5a5a5a, %r8
    movabsq $0xc3c3c3c3c3c3c3c3, %r9
    movabsq $0x3c3c3c3c3c3c3c3c, %r10
    jmp *%r11
"#,
        )
    } else {
        format!(
            r#".text
.globl {assembly_symbol}
.p2align 2
{assembly_symbol}:
    mov x16, x4
    sub sp, sp, #128
    movz x8, #0xa5a5
    movk x8, #0xa5a5, lsl #16
    movk x8, #0xa5a5, lsl #32
    movk x8, #0xa5a5, lsl #48
    stp x8, x8, [sp, #0]
    stp x8, x8, [sp, #16]
    stp x8, x8, [sp, #32]
    stp x8, x8, [sp, #48]
    stp x8, x8, [sp, #64]
    stp x8, x8, [sp, #80]
    stp x8, x8, [sp, #96]
    stp x8, x8, [sp, #112]
    add sp, sp, #128
    movz x5, #0x5a5a
    movk x5, #0x5a5a, lsl #16
    movk x5, #0x5a5a, lsl #32
    movk x5, #0x5a5a, lsl #48
    mov x6, x5
    mov x7, x5
    mov x8, x5
    mov x9, x5
    mov x10, x5
    mov x11, x5
    mov x12, x5
    mov x13, x5
    mov x14, x5
    mov x15, x5
    br x16
"#,
        )
    };
    fs::write(&assembly_path, assembly).expect("write deterministic stack-poison thunk");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let status = Command::new(compiler)
        .arg("-O0")
        .arg(&c_path)
        .arg(&assembly_path)
        .args(&objects)
        .arg(&static_runtime)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("link native aggregate real-runtime harness");
    assert!(status.success(), "native aggregate harness failed to link");
    let output = Command::new(&executable)
        .output()
        .expect("execute native aggregate harness");
    assert!(
        output.status.success(),
        "native aggregate status={:?}, stdout={}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::remove_dir_all(&directory).expect("remove native aggregate linker directory");
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
#[test]
#[ignore = "requires `cargo build -p fre-aot-regex-runtime --lib`; links the exact Count-only complete reducer to the real runtime"]
fn linked_host_complete_span_count_matches_regex_find_iter() {
    use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

    let target = if cfg!(target_arch = "x86_64") {
        if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        }
    } else if cfg!(target_os = "linux") {
        Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("linked host ASIMD target")
    } else {
        Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("linked host ASIMD target")
    };
    let fixtures = [
        (
            "[ab]+z",
            vec![
                Vec::new(),
                b"zz".to_vec(),
                b"zzabzyaaz".to_vec(),
                b"abzXbbzYa".to_vec(),
            ],
        ),
        (
            "(?:|a)",
            vec![Vec::new(), b"a".to_vec(), b"ba".to_vec(), b"aaa".to_vec()],
        ),
        (
            "a*",
            vec![
                Vec::new(),
                b"b".to_vec(),
                b"aa".to_vec(),
                b"baab".to_vec(),
            ],
        ),
        (
            r"(?-u:\xFF+|a)",
            vec![
                vec![0xff],
                vec![b'a', 0xff, 0xff, b'b', 0x80, b'a'],
                vec![0x80, 0xfe],
            ],
        ),
    ];
    let current_exe = std::env::current_exe().expect("current test executable");
    let profile_dir = current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("Cargo profile directory");
    let static_runtime = profile_dir.join("libfre_aot_regex_runtime.a");
    assert!(
        static_runtime.is_file(),
        "build the linked runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
        static_runtime.display(),
    );
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fre-aot-complete-span-reduce-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir_all(&directory).expect("create complete-reducer linker directory");

    let export_index = 0;
    let export = PreparedAggregateExports::COUNT;
    {
        let mut source = String::from(
            "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n\
             typedef void *handle_t;\n\
             typedef struct {uint32_t size;uint32_t version;uint64_t operations;uint64_t start_work;uint64_t grep_bytes;uint64_t reserved[4];} prepare_v2_t;\n\
             extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v2(const unsigned char*,size_t,const prepare_v2_t*,handle_t*);\n\
             extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);\n",
        );
        let mut objects = Vec::new();
        let mut case_functions = Vec::new();
        for (fixture_index, (pattern, haystacks)) in fixtures.iter().enumerate() {
            let artifact = compile_with_prepared_aggregate_exports(
                CompileRequest::new(*pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
                export,
            )
            .expect("compile exact complete Span reducer fixture");
            assert_eq!(artifact.receipt().engine, EngineKind::OrderedDfa, "{pattern:?}");
            assert!(
                artifact.module().uses_complete_span_reduce_aggregate(),
                "fixture {pattern:?}/{export:?} did not select CompleteSpanReduce",
            );
            assert_eq!(artifact.receipt().required_prepare_capabilities, 0);
            assert!(artifact.module().required_runtime_symbols().next().is_none());
            let (program_symbol, program_len) = artifact
                .module()
                .required_runtime_program()
                .expect("complete reducer preparation program");
            let reducer_symbol = artifact
                .module()
                .prepared_count_symbol()
                .expect("complete reducer Count symbol");
            writeln!(source, "extern const unsigned char {program_symbol}[];")
                .expect("declare complete reducer program");
            writeln!(
                source,
                "extern uint32_t {reducer_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);"
            )
            .expect("declare complete reducer export");
            let oracle = Regex::new(pattern).expect("complete reducer bytes oracle");
            for (case_index, haystack) in haystacks.iter().enumerate() {
                let spans = oracle
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                let expected =
                    u64::try_from(spans.len()).expect("complete reducer Count oracle");
                let initializer = if haystack.is_empty() {
                    String::from("0")
                } else {
                    haystack
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                writeln!(
                    source,
                    "static const unsigned char h{fixture_index}_{case_index}[]={{{initializer}}};"
                )
                .expect("write complete reducer haystack");
                let function = format!("run{fixture_index}_{case_index}");
                writeln!(
                    source,
                    concat!(
                        "static int {function}(void){{",
                        "const prepare_v2_t v2={{64U,2U,UINT64_C(15),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}}}};",
                        "handle_t h=0;uint64_t out=UINT64_C(0x1122334455667788);uint32_t q;",
                        "if(fre_aot_regex_runtime_prepare_exclusive_v2({program_symbol},{program_len}U,&v2,&h)!=0U)return 1;",
                        "q={reducer_symbol}(h,h{fixture_index}_{case_index},{length}U,&out);",
                        "if(q!=0U||out!=UINT64_C({expected}))return 2;",
                        "out=UINT64_C(0x1122334455667788);",
                        "q={reducer_symbol}(h,h{fixture_index}_{case_index},(size_t)-1,&out);",
                        "if(q!=2U||out!=UINT64_C(0x1122334455667788))return 3;",
                        "if(fre_aot_regex_runtime_destroy_exclusive_v1(h)!=0U)return 4;return 0;}}"
                    ),
                    function = function,
                    program_symbol = program_symbol,
                    program_len = program_len,
                    reducer_symbol = reducer_symbol,
                    fixture_index = fixture_index,
                    case_index = case_index,
                    length = haystack.len(),
                    expected = expected,
                )
                .expect("write complete reducer differential case");
                case_functions.push(function);
            }
            let object = directory.join(format!(
                "complete-{export_index}-{fixture_index}.o"
            ));
            fs::write(&object, artifact.object()).expect("write complete reducer object");
            objects.push(object);
        }
        source.push_str("int main(void){int status;\n");
        for function in &case_functions {
            writeln!(
                source,
                "status={function}();if(status){{fprintf(stderr,\"{function}: status=%d\\n\",status);return 1;}}"
            )
            .expect("invoke complete reducer case");
        }
        source.push_str("return 0;}\n");
        let c_path = directory.join(format!("complete-{export_index}.c"));
        let executable = directory.join(format!("complete-{export_index}"));
        fs::write(&c_path, source).expect("write complete reducer C harness");
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg(&static_runtime)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link complete reducer real-runtime harness");
        assert!(status.success(), "complete reducer harness failed to link");
        let output = Command::new(&executable)
            .output()
            .expect("execute complete reducer harness");
        assert!(
            output.status.success(),
            "complete reducer export={export:?} status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    fs::remove_dir_all(&directory).expect("remove complete-reducer linker directory");
}
