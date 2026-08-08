use fre_syntax::RustProfile;
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource,
    ContextDfaResource, CpuFeature, DeterminizationResource, DeterminizationStage, EngineKind,
    EngineSelectionReason, FeatureSet,
    MAX_STABLE_DFA_BUILD_WORK, MatchResult, OperatingSystem, OptimizationPass, OutputContract,
    SearchWindow, SectionKind, SlowAotLimits, StartAccelerator, Target, compile,
    compile_with_slow_aot_limits, emit_object,
};

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
    .expect("ordinary runtime fallback after slow allocation decline");
    assert!(allocation_declined.receipt().slow_aot.is_none());
    assert!(allocation_declined.receipt().runtime_helper_required);

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

    let fallback = crate::CompiledModule::lower(optimized.program(), target)
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
