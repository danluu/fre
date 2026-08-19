use fre_automata::{
    Automaton, CompileLimits as AutomatonCompileLimits, EdgeKind, K0ResumeSet, K0Workspace,
    RawPlan, SearchError as AutomatonSearchError, StateRole, WorkspaceLimits,
};
use fre_syntax::RustProfile;
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource,
    ContextDfaResource, CpuFeature, DeterminizationResource, DeterminizationStage, EngineKind,
    EngineSelectionReason, FeatureSet, PreparedAggregateExports, PreparedAggregateStrategy,
    PreparedBulkStrategy, PREPARED_CAPABILITY_ORDERED_NFA_V15,
    MAX_STABLE_DFA_BUILD_WORK, MatchResult, OperatingSystem, OptimizationPass, OutputContract,
    ObjectError, SearchWindow, SectionKind, SlowAotLimits, StartAccelerator, Target, compile,
    compile_with_prepared_aggregate_exports, compile_with_slow_aot_limits, emit_object,
};
use crate::{COMPILER_VERSION, OPTIMIZER_VERSION};

#[test]
fn receipt_records_selected_workspace_optimizer_identity_v21() {
    assert_eq!(COMPILER_VERSION, 1);
    assert_eq!(OPTIMIZER_VERSION, 21);
    let compiled = compile(
        CompileRequest::new(r"[a-z]+Z", Target::x86_64_linux())
            .output(OutputContract::Span)
            .mode(CompileMode::Optimizing),
    )
    .expect("compile optimizer-identity fixture");
    assert_eq!(compiled.receipt().compiler_version, COMPILER_VERSION);
    assert_eq!(compiled.receipt().optimizer_version, OPTIMIZER_VERSION);
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
            Some(PreparedAggregateStrategy::NativeFusedWithRuntimeHelper),
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_exports,
            PreparedAggregateExports::ALL,
        );
        assert_eq!(
            compiled.receipt().prepared_aggregate_strategy,
            Some(PreparedAggregateStrategy::NativeFusedWithRuntimeHelper),
        );
        assert!(compiled.receipt().runtime_helper_required);
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
        assert!(required.contains(
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
        for entry_name in [count_entry, span_sum_entry] {
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
                            == i64::try_from(ordinary_offset).ok()
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
                            == i64::try_from(ordinary_offset).ok()
                    }));
                }
            }
        }
        let grep = compiled
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == grep_entry)
            .expect("GrepCount aggregate entry record");
        let grep_section = grep.section.expect("GrepCount text section");
        let grep_start = usize::try_from(grep.offset).expect("GrepCount entry offset");
        let grep_size = usize::try_from(grep.size).expect("GrepCount entry size");
        let grep_end = grep_start
            .checked_add(grep_size)
            .expect("GrepCount entry end");
        let grep_code =
            &compiled.module().sections()[grep_section].data[grep_start..grep_end];
        let grep_runtime_index = compiled
            .module()
            .symbols()
            .iter()
            .position(|symbol| {
                symbol.section.is_none()
                    && symbol.name
                        == "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"
            })
            .expect("undefined GrepCount runtime helper");
        assert!(compiled.module().relocations().iter().any(|relocation| {
            relocation.section == grep_section
                && relocation.symbol == grep_runtime_index
                && relocation.offset
                    == grep
                        .offset
                        .checked_add(8)
                        .expect("GrepCount runtime relocation offset")
        }));
        match target.architecture {
            Architecture::X86_64 => {
                assert_eq!(grep_code, [0x4c, 0x8d, 0x05, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
            }
            Architecture::Aarch64 => {
                let words = grep_code
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert_eq!(words, [0x9000_0004, 0x9100_0084, 0x1400_0000]);
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-target reducer audit keeps both ISAs, engine shapes, and local-call decoding in one matrix"
)]
fn direct_native_reducers_reuse_ordinary_byte_and_context_dfa_entries() {
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
    for (pattern, expected_engine) in [
        ("[ab]+z", EngineKind::OrderedDfa),
        (r"(?-u:\b(?:foo|bar)\b)", EngineKind::OrderedContextDfa),
    ] {
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
                    PreparedAggregateStrategy::NativeFused
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
        Some(PreparedAggregateStrategy::NativeFused),
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
    let request = |limits| {
        CompileRequest::new("[ab]+z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits)
    };
    let baseline = compile_with_prepared_aggregate_exports(
        request(CompileLimitsV1::default()),
        exports,
    )
    .expect("direct native aggregate exact resource baseline");
    assert_eq!(baseline.receipt().engine, EngineKind::OrderedDfa);
    assert_eq!(
        baseline.receipt().prepared_aggregate_strategy,
        Some(PreparedAggregateStrategy::NativeFused),
    );
    assert_eq!(baseline.module().prepared_entry_symbol(), None);
    let exact_limits = CompileLimitsV1 {
        max_object_bytes: baseline.object().len(),
        ..CompileLimitsV1::default()
    };
    let exact = compile_with_prepared_aggregate_exports(request(exact_limits), exports)
        .expect("exact direct native aggregate object boundary");
    assert_eq!(exact.object(), baseline.object());
    assert_eq!(exact.receipt(), baseline.receipt());
    let one_below = CompileLimitsV1 {
        max_object_bytes: baseline
            .object()
            .len()
            .checked_sub(1)
            .expect("nonempty direct native aggregate object"),
        ..CompileLimitsV1::default()
    };
    let error = compile_with_prepared_aggregate_exports(request(one_below), exports)
        .expect_err("one below direct native aggregate object boundary");
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

    const ORDERED_EDGE_DISPATCH_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x80-\xFF])\b";
    const ORDERED_TERMINAL_LOW_PATTERN: &str =
        r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x00-\x29])\b";
    const ASSERTION_CACHE_PATTERN: &str =
        r"(?-u:(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))";
    const PLAIN_START_CLOSURE_PATTERN: &str =
        r"(?-u:(?:a?|bc)!(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))";
    const PREFIX_FLOW_PATTERN: &str = r"(?-u:a?a?a?a?a?a?a?a?(?:a.c|ab)\b)";
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
    ];
    let exports = PreparedAggregateExports::COUNT
        .union(PreparedAggregateExports::SPAN_SUM);
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
        "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\
         typedef void *handle_t;\n\
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
            || *pattern == ORDERED_TERMINAL_LOW_PATTERN;
        let forced_ordered_graph_fixture = terminal_prefilter_fixture
            || *pattern == ASSERTION_CACHE_PATTERN
            || *pattern == PLAIN_START_CLOSURE_PATTERN
            || *pattern == PREFIX_FLOW_PATTERN;
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
            } else {
                PreparedAggregateStrategy::NativeFused
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
                        } else {
                            0x00
                        },
                        end: if *pattern == ORDERED_EDGE_DISPATCH_PATTERN {
                            0xff
                        } else {
                            0x29
                        },
                        reverse_depth: 0,
                    }),
                    "wide-row fixture lost its terminal range",
                );
                assert!(artifact.module().has_ordered_nfa_terminal_range_object());
                assert!(artifact.module().has_ordered_edge_dispatch_object());
                assert!(
                    artifact
                        .module()
                        .symbols()
                        .iter()
                        .any(|symbol| symbol.name == ".Lfre_aot_regex_ordered_nfa_object_v3"),
                    "wide-row fixture did not publish its composed V3 object",
                );
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
            let window_start = usize::from(haystack.len() >= 3);
            let window_end = if haystack.len() >= 2 {
                haystack.len() - 1
            } else {
                haystack.len()
            };
            let window_match = if *pattern == PREFIX_FLOW_PATTERN {
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
                format!(
                    concat!(
                        "{{span_t one={{UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0xbbbbbbbbbbbbbbbb)}};",
                        "uint32_t q={prepared_search_symbol}(h,h{fixture_index}_{case_index},{length}U,{window_start}U,{window_end}U,&one);",
                        "if(q!={expected_status}U||one.start!={expected_start}U||one.end!={expected_end}U)return 13;}}"
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
                )
            } else {
                String::new()
            };
            writeln!(
                source,
                concat!(
                    "static int run{fixture_index}_{case_index}(void){{",
                    "const prepare_v2_t v2={{64U,2U,UINT64_C(7),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}}}};",
                    "handle_t h=0;uint64_t c=UINT64_C(0xaaaaaaaaaaaaaaaa),s=UINT64_C(0xbbbbbbbbbbbbbbbb);",
                    "if(fre_aot_regex_runtime_prepare_exclusive_v2({program_symbol},{program_len}U,&v2,&h)!=0U)return 1;",
                    "if({count_symbol}(h,h{fixture_index}_{case_index},{length}U,&c)!=0U||c!=UINT64_C({count}))return 2;",
                    "if({span_sum_symbol}(h,h{fixture_index}_{case_index},{length}U,&s)!=0U||s!=UINT64_C({span_sum}))return 3;",
                    "{legacy_fill}",
                    "if(fre_aot_regex_runtime_destroy_exclusive_v1(h)!=0U)return 4;",
                    "if(UINT64_C({required})!=0){{",
                    "const prepare_v3_t v3={{112U,3U,UINT64_C(7),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C({required}),{{0,0}}}};",
                    "h=0;c=UINT64_C(0xcccccccccccccccc);s=UINT64_C(0xdddddddddddddddd);",
                    "if(fre_aot_regex_runtime_prepare_exclusive_v3({program_symbol},{program_len}U,&v3,&h)!=0U)return 5;",
                    "if({count_symbol}(h,h{fixture_index}_{case_index},{length}U,&c)!=0U||c!=UINT64_C({count}))return 6;",
                    "if({span_sum_symbol}(h,h{fixture_index}_{case_index},{length}U,&s)!=0U||s!=UINT64_C({span_sum}))return 7;",
                    "{native_fill}",
                    "{native_search}",
                    "if(fre_aot_regex_runtime_destroy_exclusive_v1(h)!=0U)return 8;",
                    "}}return 0;}}"
                ),
                fixture_index = fixture_index,
                case_index = case_index,
                program_symbol = program_symbol,
                program_len = program_len,
                count_symbol = count_symbol,
                count = count,
                span_sum_symbol = span_sum_symbol,
                span_sum = span_sum,
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
    let (first_program, first_program_len) = first
        .module()
        .required_runtime_program()
        .expect("first authentication program");
    let (second_program, second_program_len) = second
        .module()
        .required_runtime_program()
        .expect("second authentication program");
    let first_count = first
        .module()
        .prepared_count_symbol()
        .expect("first authentication Count");
    let first_span_sum = first
        .module()
        .prepared_span_sum_symbol()
        .expect("first authentication SpanSum");
    writeln!(
        source,
        concat!(
            "static int authenticate_before_source(void){{",
            "handle_t right=0,wrong=0;",
            "const prepare_v3_t v3={{112U,3U,UINT64_C(6),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C(1),{{0,0}}}};",
            "uint64_t out=UINT64_C(0x1122334455667788);",
            "static const unsigned char readable[8]={{0}};",
            "unsigned char bytes[17];uint32_t q;int authentication_failed=0;memset(bytes,0xa5,sizeof(bytes));",
            "if(fre_aot_regex_runtime_prepare_exclusive_v3({first_program},{first_program_len}U,&v3,&right)!=0U)return 1;",
            "if(fre_aot_regex_runtime_prepare_exclusive_v3({second_program},{second_program_len}U,&v3,&wrong)!=0U)return 2;",
            "q={first_count}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
            "out=UINT64_C(0x1122334455667788);",
            "q={first_span_sum}(wrong,(const unsigned char*)(uintptr_t)1,8U,&out);",
            "if(q!=3U||out!=UINT64_C(0x1122334455667788))authentication_failed=1;",
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
            "out=UINT64_C(0x1122334455667788);",
            "if({first_count}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 18;",
            "out=UINT64_C(0x1122334455667788);",
            "if({first_span_sum}(right,(const unsigned char*)(uintptr_t)1,(size_t)-1,&out)!=2U||out!=UINT64_C(0x1122334455667788))return 19;",
            "if(fre_aot_regex_runtime_destroy_exclusive_v1(right)!=0U||fre_aot_regex_runtime_destroy_exclusive_v1(wrong)!=0U)return 20;",
            "return 0;}}",
        ),
        first_program = first_program,
        first_program_len = first_program_len,
        second_program = second_program,
        second_program_len = second_program_len,
        first_count = first_count,
        first_span_sum = first_span_sum,
    )
    .expect("write authentication-before-source checks");
    source.push_str("int main(void){int status;\n");
    for (fixture_index, (_, _, _, _, _, haystacks)) in fixtures.iter().enumerate() {
        for case_index in 0..haystacks.len() {
            writeln!(
                source,
                "status=run{fixture_index}_{case_index}();if(status)return {}+status;",
                20 + fixture_index * 20 + case_index * 4,
            )
            .expect("invoke aggregate differential case");
        }
    }
    source.push_str("status=authenticate_before_source();if(status)return 200+status;return 0;}\n");

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
    let executable = directory.join("native-aggregate");
    fs::write(&c_path, source).expect("write native aggregate C harness");
    let compiler = if cfg!(target_os = "macos") {
        "clang"
    } else {
        "cc"
    };
    let status = Command::new(compiler)
        .arg("-O0")
        .arg(&c_path)
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
