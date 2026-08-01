use fre_syntax::RustProfile;
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CompileLimitsV1, CompileMode, CompileRequest, ContextDfaResource,
    DeterminizationResource, DeterminizationStage, EngineKind, EngineSelectionReason,
    MAX_STABLE_DFA_BUILD_WORK, MatchResult, OperatingSystem, OptimizationPass, OutputContract,
    SearchWindow, SectionKind, StartAccelerator, Target, compile,
};

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
        assert_eq!(u32::from_le_bytes(serialized[8..12].try_into().unwrap()), 2);
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
            DeterminizationStage::ReverseSubsetConstruction,
            DeterminizationStage::DfaStateMinimization,
            DeterminizationStage::AlphabetColumnCoalescing,
        ]
    );
    assert!(report.decline.is_none());

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
    assert!(
        crate::CompiledModule::lower(&restored, Target::x86_64_linux())
            .unwrap()
            .required_runtime_symbol()
            .is_some()
    );

    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_work = 0;
    let declined = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits),
    )
    .unwrap();
    assert_eq!(declined.receipt().engine, EngineKind::OrderedNfa);
    assert_eq!(
        declined.receipt().engine_selection_reason,
        EngineSelectionReason::ContextAssertions
    );
    assert!(declined.receipt().runtime_helper_required);
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

    assert_eq!(fast.receipt().start_accelerator, StartAccelerator::None);
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
