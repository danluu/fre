use fre_lower::{
    LowerError, LowerLimits, OperationSemantics, UniformCaptureLoweringError,
    UniformCaptureParticipationDecline, UniformCaptureParticipationDisposition,
    UniformCaptureParticipationError, UniformCaptureParticipationLimits,
    UniformCaptureParticipationReceipt, UniformCaptureParticipationResource,
    analyze_uniform_capture_participation, lower_raw_general,
    lower_raw_general_with_uniform_capture_participation,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};
use regex::bytes::Regex;
use regex_syntax::hir::{Capture, Hir};

fn parsed(pattern: &str) -> RustParsed {
    let record = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4()),
    ))
    .unwrap_or_else(|error| panic!("failed to parse {pattern:?}: {error}"));
    match record.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
            panic!("Rust request returned another syntax family")
        }
    }
}

fn transaction(
    parsed: &RustParsed,
    proof_limits: UniformCaptureParticipationLimits,
) -> Result<fre_lower::UniformCaptureLoweredRaw, UniformCaptureLoweringError> {
    lower_raw_general_with_uniform_capture_participation(
        parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
        proof_limits,
    )
}

fn proof(pattern: &str) -> UniformCaptureParticipationReceipt {
    transaction(
        &parsed(pattern),
        UniformCaptureParticipationLimits::default(),
    )
    .expect("paired lowering succeeds")
    .participation()
    .proof()
    .unwrap_or_else(|| panic!("expected a proof for {pattern:?}"))
}

fn decline(pattern: &str) -> UniformCaptureParticipationDecline {
    transaction(
        &parsed(pattern),
        UniformCaptureParticipationLimits::default(),
    )
    .expect("semantic decline retains selector lowering")
    .participation()
    .decline()
    .unwrap_or_else(|| panic!("expected a decline for {pattern:?}"))
}

#[test]
fn required_nested_and_capture_free_languages_publish_exact_counts() {
    let fixtures = [
        ("abc", 3, 0, 0),
        (r"a(b)c", 3, 1, 1),
        (r"(?P<outer>a(?P<inner>b)c)", 3, 2, 2),
        (r"((a))|(b(c))", 1, 2, 4),
        (r"(?:(a)){0}(b)", 1, 1, 1),
    ];
    for (pattern, minimum, participating, annotations) in fixtures {
        let proof = proof(pattern);
        assert!(proof.identity().authenticates_current(), "{pattern:?}");
        assert_eq!(proof.minimum_match_bytes().get(), minimum, "{pattern:?}");
        assert_eq!(
            proof.participating_user_captures(),
            participating,
            "{pattern:?}"
        );
        assert_eq!(
            proof.participating_groups_per_match().get(),
            participating.checked_add(1).expect("small fixture count"),
            "{pattern:?}"
        );
        assert_eq!(
            proof.canonical_capture_annotations(),
            annotations,
            "{pattern:?}"
        );
        assert!(proof.work() > 0, "{pattern:?}");
        assert!(proof.peak_stack_items() > 0, "{pattern:?}");
    }
}

#[test]
fn equal_cardinality_alternatives_and_stable_repetition_are_general() {
    let fixtures = [
        (r"(a)|(b)", 1),
        (r"((a))|(b(c))", 2),
        (r"(a)+", 1),
        (r"((a)b){2,4}", 2),
        (r"(?:(a)|(b)){1}", 1),
    ];
    for (pattern, participating) in fixtures {
        assert_eq!(
            proof(pattern).participating_user_captures(),
            participating,
            "{pattern:?}"
        );
    }
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
fn every_published_count_matches_pinned_captures_on_generated_inputs() {
    let patterns = [
        "abc",
        r"a(b)c",
        r"(a)|(b)",
        r"((a))|(b(c))",
        r"(a)+",
        r"((a)b){2,4}",
        r"(?:(a)|(b)){1}",
        r"(?:(a)){0}(b)",
    ];
    let haystacks = generated_haystacks(b"abcxy", 5);
    for pattern in patterns {
        let expected = proof(pattern).participating_user_captures();
        let oracle = Regex::new(pattern).expect("generated oracle pattern");
        for haystack in &haystacks {
            for captures in oracle.captures_iter(haystack) {
                let overall = captures.get(0).expect("capture zero");
                assert!(overall.start() < overall.end(), "{pattern:?} {haystack:?}");
                let actual = captures.iter().skip(1).flatten().count();
                assert_eq!(actual, expected, "{pattern:?} {haystack:?}");
            }
        }
    }
}

#[test]
fn optional_unequal_nullable_and_unstable_repetition_decline() {
    for pattern in [r"(a)?b", r"((a)?b)", r"(a)|b", r"(a)|(b(c))"] {
        assert_eq!(
            decline(pattern),
            UniformCaptureParticipationDecline::NonUniform,
            "{pattern:?}"
        );
    }
    for pattern in ["", r"(a*)"] {
        assert_eq!(
            decline(pattern),
            UniformCaptureParticipationDecline::Nullable,
            "{pattern:?}"
        );
    }
    assert_eq!(
        decline(r"((a)|(b))+"),
        UniformCaptureParticipationDecline::NonUniform
    );
}

#[test]
fn empty_language_and_noncanonical_capture_indices_fail_closed() {
    let empty = RustParsed { hir: Hir::fail() };
    assert_eq!(
        transaction(&empty, UniformCaptureParticipationLimits::default())
            .expect("empty language still lowers to an empty selector")
            .participation(),
        UniformCaptureParticipationDisposition::Declined(
            UniformCaptureParticipationDecline::EmptyLanguageOrUnknownMinimum
        )
    );

    let duplicate = RustParsed {
        hir: Hir::concat(vec![
            Hir::capture(Capture {
                index: 1,
                name: None,
                sub: Box::new(Hir::literal(*b"a")),
            }),
            Hir::capture(Capture {
                index: 1,
                name: None,
                sub: Box::new(Hir::literal(*b"b")),
            }),
        ]),
    };
    assert_eq!(
        transaction(&duplicate, UniformCaptureParticipationLimits::default())
            .expect("malformed capture identity declines without changing selector")
            .participation(),
        UniformCaptureParticipationDisposition::Declined(
            UniformCaptureParticipationDecline::NonCanonicalCaptureIndices
        )
    );
}

#[test]
fn paired_entry_preserves_incumbent_raw_plan_and_route_stats_on_every_disposition() {
    for pattern in [r"((a))|(b(c))", r"(a)?b", r"((a)|(b))+", r"(?:ab|a)*c"] {
        let parsed = parsed(pattern);
        let incumbent = lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("incumbent lowering failed for {pattern:?}: {error}"));
        let paired = transaction(&parsed, UniformCaptureParticipationLimits::default())
            .unwrap_or_else(|error| panic!("paired lowering failed for {pattern:?}: {error}"));
        assert_eq!(
            incumbent.plan(),
            paired.lowered().plan(),
            "RawPlan changed for {pattern:?}"
        );
        assert_eq!(
            incumbent.stats(),
            paired.lowered().stats(),
            "lowering route stats changed for {pattern:?}"
        );
    }
}

#[test]
fn proof_limits_are_terminal_and_distinct_from_semantic_declines_and_lowering_errors() {
    let fixture = parsed(r"((a))|(b(c))");
    let baseline = transaction(&fixture, UniformCaptureParticipationLimits::default())
        .expect("baseline proof");
    let proof = baseline.participation().proof().expect("positive fixture");

    transaction(
        &fixture,
        UniformCaptureParticipationLimits {
            max_work: proof.work(),
            max_stack_items: proof.peak_stack_items(),
        },
    )
    .expect("exact proof limits pass");

    let work_limit = proof.work().checked_sub(1).expect("positive proof work");
    assert!(matches!(
        transaction(
            &fixture,
            UniformCaptureParticipationLimits {
                max_work: work_limit,
                max_stack_items: proof.peak_stack_items(),
            },
        ),
        Err(UniformCaptureLoweringError::Participation(
            UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::Work,
                limit,
                ..
            }
        )) if limit == work_limit
    ));

    let stack_limit = proof
        .peak_stack_items()
        .checked_sub(1)
        .expect("positive proof stack");
    assert!(matches!(
        transaction(
            &fixture,
            UniformCaptureParticipationLimits {
                max_work: proof.work(),
                max_stack_items: stack_limit,
            },
        ),
        Err(UniformCaptureLoweringError::Participation(
            UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::StackItems,
                limit,
                ..
            }
        )) if limit == u64::try_from(stack_limit).expect("small stack fixture")
    ));

    let semantic = transaction(
        &parsed(r"(a)?b"),
        UniformCaptureParticipationLimits::default(),
    )
    .expect("semantic refusal is not terminal");
    assert_eq!(
        semantic.participation().decline(),
        Some(UniformCaptureParticipationDecline::NonUniform)
    );

    let lower_error = lower_raw_general_with_uniform_capture_participation(
        &fixture,
        OperationSemantics::CaptureFree,
        LowerLimits {
            max_work: 0,
            ..LowerLimits::default()
        },
        UniformCaptureParticipationLimits::default(),
    )
    .expect_err("incumbent lowering limit remains terminal");
    assert!(matches!(
        lower_error,
        UniformCaptureLoweringError::Lower(LowerError::ResourceLimit { .. })
    ));
}

#[test]
fn prospective_decline_precedes_fallible_selector_construction() {
    let fixture = parsed(r"(a)?b");
    assert_eq!(
        analyze_uniform_capture_participation(
            &fixture,
            UniformCaptureParticipationLimits::default(),
        )
        .expect("semantic preflight is not terminal"),
        UniformCaptureParticipationDisposition::Declined(
            UniformCaptureParticipationDecline::NonUniform,
        ),
    );

    let error = lower_raw_general_with_uniform_capture_participation(
        &fixture,
        OperationSemantics::CaptureFree,
        LowerLimits {
            max_work: 0,
            ..LowerLimits::default()
        },
        UniformCaptureParticipationLimits::default(),
    )
    .expect_err("paired construction still owns its selector failure");
    assert!(matches!(
        error,
        UniformCaptureLoweringError::Lower(LowerError::ResourceLimit { .. })
    ));
}

#[test]
fn prospective_proof_matches_the_paired_transaction_exactly() {
    let fixture = parsed(r"((a))|(b(c))");
    let prospective = analyze_uniform_capture_participation(
        &fixture,
        UniformCaptureParticipationLimits::default(),
    )
    .expect("prospective proof");
    let paired = transaction(&fixture, UniformCaptureParticipationLimits::default())
        .expect("paired construction");
    assert_eq!(prospective, paired.participation());
}

#[test]
fn prospective_resource_error_is_not_fallback_permission() {
    let fixture = parsed(r"((a))|(b(c))");
    let proof = analyze_uniform_capture_participation(
        &fixture,
        UniformCaptureParticipationLimits::default(),
    )
    .expect("baseline prospective")
    .proof()
    .expect("positive fixture");
    let limit = proof.work().checked_sub(1).expect("positive work");
    assert!(matches!(
        analyze_uniform_capture_participation(
            &fixture,
            UniformCaptureParticipationLimits {
                max_work: limit,
                max_stack_items: proof.peak_stack_items(),
            },
        ),
        Err(UniformCaptureParticipationError::ResourceLimit {
            resource: UniformCaptureParticipationResource::Work,
            limit: actual,
            ..
        }) if actual == limit
    ));
}
