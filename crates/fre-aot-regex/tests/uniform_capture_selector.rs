use fre_aot_regex::{
    CompileLimitsV1, CompileMode, CompileRequest, MatchResult, OutputContract, SearchWindow,
    Target, UniformCaptureAuthenticationError, UniformCaptureCompileDisposition,
    UniformCaptureCompileError, UniformCaptureCompileRequest, compile,
    compile_uniform_capture_selector,
};
use fre_lower::{
    LowerError, LowerLimits, UniformCaptureParticipationDecline, UniformCaptureParticipationError,
    UniformCaptureParticipationLimits, UniformCaptureParticipationResource,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};
use regex::bytes::Regex;

fn parse_rust(pattern: &str, profile: RustProfile) -> RustParsed {
    let parsed = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile),
    ))
    .unwrap_or_else(|error| panic!("failed to parse {pattern:?}: {error}"));
    match parsed.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
            panic!("Rust request returned another syntax family")
        }
    }
}

#[test]
fn paired_compile_preserves_the_complete_ordinary_selector_on_proof_and_decline() {
    for (pattern, expected_decline) in [
        (r"((a))|(b(c))", None),
        (
            r"(a)?b",
            Some(UniformCaptureParticipationDecline::NonUniform),
        ),
    ] {
        let target = Target::x86_64_linux();
        let profile = RustProfile::rebar_1_12_4();
        let ordinary = compile(
            CompileRequest::new(pattern, target)
                .profile(profile.clone())
                .output(OutputContract::Span)
                .mode(CompileMode::Optimizing),
        )
        .unwrap_or_else(|error| panic!("ordinary compile failed for {pattern:?}: {error}"));
        let parsed = parse_rust(pattern, profile.clone());
        let paired = compile_uniform_capture_selector(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), target).profile(profile),
        )
        .unwrap_or_else(|error| panic!("paired compile failed for {pattern:?}: {error}"));

        assert_eq!(
            paired.selector().receipt(),
            ordinary.receipt(),
            "{pattern:?}"
        );
        assert_eq!(paired.selector().module(), ordinary.module(), "{pattern:?}");
        assert_eq!(paired.selector().object(), ordinary.object(), "{pattern:?}");
        assert_eq!(
            paired.selector().program().serialize().unwrap(),
            ordinary.program().serialize().unwrap(),
            "{pattern:?}"
        );
        assert_eq!(
            paired.disposition().decline(),
            expected_decline,
            "{pattern:?}"
        );
        paired.authenticate().expect("fresh paired artifact closes");
        if let UniformCaptureCompileDisposition::Proven(receipt) = paired.disposition() {
            assert!(receipt.participation().identity().authenticates_current());
            assert_eq!(
                receipt.selector_automaton_sha256(),
                ordinary.receipt().automaton_sha256
            );
            assert_eq!(
                receipt.selector_program_sha256(),
                ordinary.receipt().program_sha256
            );
            assert_eq!(
                receipt.selector_object_sha256(),
                ordinary.receipt().object_sha256
            );
            receipt
                .authenticate(paired.selector())
                .expect("receipt authenticates exact selector");
        }
    }
}

#[test]
#[allow(
    clippy::field_reassign_with_default,
    reason = "the public profile exposes line and case semantics as checked mutable options"
)]
fn parsed_request_mirrors_profile_size_normalization_and_line_semantics() {
    let pattern = r"(a.+z)";
    let target = Target::x86_64_linux();
    let mut profile = RustProfile::default();
    profile.options.line_terminator = b'\r';
    profile.options.case_insensitive = true;
    let ordinary_request = CompileRequest::new(pattern, target)
        .profile(profile)
        .output(OutputContract::Span)
        .mode(CompileMode::Optimizing)
        .size_limit(32 * 1024 * 1024);
    let parsed = parse_rust(pattern, ordinary_request.profile.clone());
    let paired_request = UniformCaptureCompileRequest::new(pattern.len(), target)
        .profile(ordinary_request.profile.clone())
        .mode(ordinary_request.mode)
        .selector_limits(ordinary_request.limits);
    assert_eq!(
        paired_request.selector_limits.max_program_bytes,
        ordinary_request.limits.max_program_bytes
    );

    let ordinary = compile(ordinary_request).expect("ordinary custom-profile compile");
    let paired = compile_uniform_capture_selector(&parsed, paired_request)
        .expect("paired custom-profile compile");
    assert_eq!(paired.selector().receipt(), ordinary.receipt());
    assert_eq!(paired.selector().module(), ordinary.module());
    assert_eq!(paired.selector().object(), ordinary.object());
    let receipt = paired
        .disposition()
        .receipt()
        .expect("custom-profile fixture is uniform");
    assert_eq!(receipt.line_terminator(), b'\r');
    receipt
        .authenticate(paired.selector())
        .expect("custom-profile receipt closes");
}

#[test]
fn proof_lower_compile_and_native_route_failures_remain_terminal_and_typed() {
    let pattern = r"(ab)";
    let parsed = parse_rust(pattern, RustProfile::default());
    let target = Target::x86_64_linux();

    let proof_error = compile_uniform_capture_selector(
        &parsed,
        UniformCaptureCompileRequest::new(pattern.len(), target).participation_limits(
            UniformCaptureParticipationLimits {
                max_work: 0,
                max_stack_items: usize::MAX,
            },
        ),
    )
    .expect_err("proof work exhaustion is terminal");
    assert!(matches!(
        proof_error,
        UniformCaptureCompileError::Participation(
            UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::Work,
                limit: 0,
                ..
            }
        )
    ));

    let lower_limits = CompileLimitsV1 {
        lower: LowerLimits {
            max_work: 0,
            ..LowerLimits::default()
        },
        ..CompileLimitsV1::default()
    };
    let lower_error = compile_uniform_capture_selector(
        &parsed,
        UniformCaptureCompileRequest::new(pattern.len(), target).selector_limits(lower_limits),
    )
    .expect_err("selector lowering exhaustion is terminal");
    assert!(matches!(
        lower_error,
        UniformCaptureCompileError::Lower(LowerError::ResourceLimit { .. })
    ));

    let object_limits = CompileLimitsV1 {
        max_object_bytes: 0,
        ..CompileLimitsV1::default()
    };
    let compile_error = compile_uniform_capture_selector(
        &parsed,
        UniformCaptureCompileRequest::new(pattern.len(), target).selector_limits(object_limits),
    )
    .expect_err("object exhaustion is terminal");
    assert!(matches!(
        compile_error,
        UniformCaptureCompileError::Selector(_)
    ));

    let helper_pattern = r"((?:a|b)*a(?:a|b){15})";
    let helper_parsed = parse_rust(helper_pattern, RustProfile::default());
    let route_error = compile_uniform_capture_selector(
        &helper_parsed,
        UniformCaptureCompileRequest::new(helper_pattern.len(), target).mode(CompileMode::Fast),
    )
    .expect_err("runtime-backed Fast selector is not a native receipt");
    assert!(matches!(
        route_error,
        UniformCaptureCompileError::Authentication(
            UniformCaptureAuthenticationError::RuntimeDependency
        )
    ));
}

fn generated_haystacks(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
    fn extend(alphabet: &[u8], remaining: usize, prefix: &mut Vec<u8>, output: &mut Vec<Vec<u8>>) {
        output.push(prefix.clone());
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            prefix.push(byte);
            extend(alphabet, remaining.saturating_sub(1), prefix, output);
            prefix.pop();
        }
    }

    let mut output = Vec::new();
    extend(alphabet, maximum, &mut Vec::new(), &mut output);
    output
}

#[test]
fn generated_selectors_times_receipted_cardinality_equal_capture_oracle() {
    let patterns = [
        r"a(b)c",
        r"(a)|(b)",
        r"((a))|(b(c))",
        r"(a)+",
        r"((a)b){2,3}",
        r"(?:(a)){0}(b)",
    ];
    let haystacks = generated_haystacks(b"abcx", 5);
    for pattern in patterns {
        let parsed = parse_rust(pattern, RustProfile::default());
        let compiled = compile_uniform_capture_selector(
            &parsed,
            UniformCaptureCompileRequest::new(pattern.len(), Target::x86_64_linux()),
        )
        .unwrap_or_else(|error| panic!("uniform compile failed for {pattern:?}: {error}"));
        let receipt = compiled
            .disposition()
            .receipt()
            .unwrap_or_else(|| panic!("generated uniform fixture declined: {pattern:?}"));
        let groups_per_match = receipt
            .participation()
            .participating_groups_per_match()
            .get();
        let oracle = Regex::new(pattern).expect("generated oracle pattern");
        let mut workspace = compiled
            .selector()
            .prepare_workspace()
            .expect("selector workspace");

        for haystack in &haystacks {
            let expected_spans = oracle
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let expected_groups = oracle
                .captures_iter(haystack)
                .map(|captures| {
                    let participating = captures.iter().flatten().count();
                    assert_eq!(participating, groups_per_match, "{pattern:?} {haystack:?}");
                    participating
                })
                .sum::<usize>();

            let mut actual_spans = Vec::new();
            let mut start = 0;
            while start <= haystack.len() {
                let result = compiled
                    .selector()
                    .search_with_workspace(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        &mut workspace,
                    )
                    .unwrap_or_else(|error| {
                        panic!("selector failed for {pattern:?} {haystack:?}: {error}")
                    });
                let MatchResult::Span(span) = result else {
                    panic!("uniform selector returned a non-Span result")
                };
                let Some((matched_start, matched_end)) = span else {
                    break;
                };
                assert!(
                    matched_start < matched_end,
                    "positive-width proof was violated"
                );
                actual_spans.push((matched_start, matched_end));
                start = matched_end;
            }
            assert_eq!(actual_spans, expected_spans, "{pattern:?} {haystack:?}");
            assert_eq!(
                actual_spans.len().checked_mul(groups_per_match),
                Some(expected_groups),
                "{pattern:?} {haystack:?}"
            );
        }
    }
}
