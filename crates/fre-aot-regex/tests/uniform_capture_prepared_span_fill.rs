use fre_aot_regex::{
    CompileLimitsV1, EngineKind, PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports,
    PreparedBulkStrategy, Target, UniformCaptureCompileRequest,
    UniformCapturePreparedSpanFillCompileDisposition, UniformCapturePreparedSpanFillCompileError,
    compile_uniform_capture_prepared_span_fill_selector,
};
use fre_lower::{
    LowerError, LowerLimits, UniformCaptureParticipationDecline, UniformCaptureParticipationError,
    UniformCaptureParticipationLimits, UniformCaptureParticipationResource,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};

const PUBLIC_REBAR_ORDERED_NFA_FIXTURE: &str =
    r"\b(?:([\w&&\p{Cyrillic}]{6})|([\w&&\p{Cyrillic}]{5}))\b";

fn parse_rebar(pattern: &str) -> RustParsed {
    let profile = RustProfile::rebar_1_12_4();
    let parsed = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile),
    ))
    .unwrap_or_else(|error| panic!("failed to parse public fixture: {error}"));
    match parsed.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
            panic!("Rust request returned another syntax family")
        }
    }
}

fn request(source_bytes: usize, target: Target) -> UniformCaptureCompileRequest {
    UniformCaptureCompileRequest::new(source_bytes, target).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn public_ordered_nfa_fixture_selects_exact_capability_bound_span_fill() {
    let parsed = parse_rebar(PUBLIC_REBAR_ORDERED_NFA_FIXTURE);
    for target in [Target::x86_64_linux(), Target::aarch64_linux()] {
        let disposition = compile_uniform_capture_prepared_span_fill_selector(
            &parsed,
            request(PUBLIC_REBAR_ORDERED_NFA_FIXTURE.len(), target),
        )
        .unwrap_or_else(|error| panic!("prepared SpanFill compile failed for {target:?}: {error}"));
        let selected = disposition
            .selected()
            .unwrap_or_else(|| panic!("positive public fixture declined for {target:?}"));
        selected
            .authenticate()
            .unwrap_or_else(|error| panic!("fresh selected route failed to close: {error}"));
        let receipt = selected.receipt();
        assert_eq!(
            receipt
                .participation()
                .participating_groups_per_match()
                .get(),
            2,
        );
        assert_eq!(
            receipt.required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert_eq!(selected.selector().receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(
            selected.selector().module().prepared_bulk_strategy(),
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
        );
        assert_eq!(
            selected.selector().module().required_prepare_capabilities(),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
        );
        assert_eq!(
            selected.selector().module().prepared_aggregate_exports(),
            PreparedAggregateExports::NONE,
        );
        assert!(!selected.prepared_entry_symbol().is_empty());
        assert!(!selected.prepared_span_fill_symbol().is_empty());
        assert!(selected.selector().module().required_runtime_symbols().eq([
            "fre_aot_regex_runtime_search_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_fill_spans_exclusive_v1",
        ]));
    }
}

#[test]
fn semantic_decline_returns_before_any_selector_resource_attempt() {
    let pattern = r"(a)?b";
    let parsed = parse_rebar(pattern);
    let limits = CompileLimitsV1 {
        lower: LowerLimits {
            max_work: 0,
            ..LowerLimits::default()
        },
        max_object_bytes: 0,
        ..CompileLimitsV1::default()
    };
    let disposition = compile_uniform_capture_prepared_span_fill_selector(
        &parsed,
        request(pattern.len(), Target::x86_64_linux()).selector_limits(limits),
    )
    .expect("semantic decline precedes impossible selector envelope");
    assert!(matches!(
        disposition,
        UniformCapturePreparedSpanFillCompileDisposition::Declined(
            UniformCaptureParticipationDecline::NonUniform
        )
    ));
}

#[test]
fn positive_route_resource_and_authentication_failures_remain_terminal() {
    let parsed = parse_rebar(PUBLIC_REBAR_ORDERED_NFA_FIXTURE);
    let target = Target::x86_64_linux();

    let proof_error = compile_uniform_capture_prepared_span_fill_selector(
        &parsed,
        request(PUBLIC_REBAR_ORDERED_NFA_FIXTURE.len(), target).participation_limits(
            UniformCaptureParticipationLimits {
                max_work: 0,
                max_stack_items: usize::MAX,
            },
        ),
    )
    .expect_err("proof exhaustion is terminal");
    assert!(matches!(
        proof_error,
        UniformCapturePreparedSpanFillCompileError::Participation(
            UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::Work,
                limit: 0,
                ..
            }
        )
    ));

    let lower_error = compile_uniform_capture_prepared_span_fill_selector(
        &parsed,
        request(PUBLIC_REBAR_ORDERED_NFA_FIXTURE.len(), target).selector_limits(CompileLimitsV1 {
            lower: LowerLimits {
                max_work: 0,
                ..LowerLimits::default()
            },
            ..CompileLimitsV1::default()
        }),
    )
    .expect_err("lower exhaustion is terminal");
    assert!(matches!(
        lower_error,
        UniformCapturePreparedSpanFillCompileError::Lower(LowerError::ResourceLimit { .. })
    ));

    let object_error = compile_uniform_capture_prepared_span_fill_selector(
        &parsed,
        request(PUBLIC_REBAR_ORDERED_NFA_FIXTURE.len(), target).selector_limits(CompileLimitsV1 {
            max_object_bytes: 0,
            ..CompileLimitsV1::default()
        }),
    )
    .expect_err("object exhaustion is terminal");
    assert!(matches!(
        object_error,
        UniformCapturePreparedSpanFillCompileError::Selector(_)
    ));

    let other_pattern = r"(ab)";
    let other = parse_rebar(other_pattern);
    let route_error = compile_uniform_capture_prepared_span_fill_selector(
        &other,
        request(other_pattern.len(), target),
    )
    .expect_err("an unsupported explicit V15 route is terminal, not fallback permission");
    assert!(matches!(
        route_error,
        UniformCapturePreparedSpanFillCompileError::Selector(_)
    ));
}
