use fre_lower::{
    CaptureParticipation, CheckedWidth, FactError, FactLimits, FactOperation, FactOptionalProofs,
    FactOutput, FactProof, FactRefusal, FactResource, HIR_FACT_ACCOUNTING_VERSION,
    HIR_FACT_ALGORITHM_VERSION, LowerLimits, OperationSemantics, StringEncoding, analyze_hir_facts,
    lower_hir_raw,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};
use regex::bytes::RegexBuilder;
use regex_syntax::hir::{
    Capture, Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind,
    Look, Repetition,
};

type LimitCase = (FactResource, fn(&mut FactLimits, usize), usize);

fn one_below_usize(value: usize) -> usize {
    value.checked_sub(1).expect("positive exact limit")
}

fn one_below_u64(value: u64) -> u64 {
    value.checked_sub(1).expect("positive exact work limit")
}

fn assert_exact_and_one_below_hard_limits(
    hir: &Hir,
    operation: FactOperation,
    base_limits: FactLimits,
    report: &fre_lower::HirFacts,
) {
    let prospective = report.prospective();
    let cases: &[LimitCase] = &[
        (
            FactResource::StackItems,
            |limits, value| limits.max_stack_items = value,
            prospective.peak_stack_items(),
        ),
        (
            FactResource::HirNodes,
            |limits, value| limits.max_hir_nodes = value,
            prospective.hir_nodes(),
        ),
        (
            FactResource::RetainedBytes,
            |limits, value| limits.max_retained_bytes = value,
            prospective.retained_bytes(),
        ),
        (
            FactResource::TemporaryBytes,
            |limits, value| limits.max_temporary_bytes = value,
            prospective.temporary_bytes(),
        ),
        (
            FactResource::PeakBytes,
            |limits, value| limits.max_peak_bytes = value,
            prospective.peak_bytes(),
        ),
        (
            FactResource::AllocationAttempts,
            |limits, value| limits.max_allocation_attempts = value,
            prospective.allocation_attempts(),
        ),
    ];
    for &(resource, set, exact) in cases {
        let mut limits = base_limits;
        set(&mut limits, exact);
        analyze_hir_facts(hir, operation, limits)
            .unwrap_or_else(|error| panic!("exact {resource:?} failed: {error}"));

        let below = one_below_usize(exact);
        let mut limits = base_limits;
        set(&mut limits, below);
        assert!(matches!(
            analyze_hir_facts(hir, operation, limits),
            Err(FactError::ResourceLimit {
                resource: actual,
                needed,
                limit,
            }) if actual == resource
                && needed == u64::try_from(exact).expect("small exact limit")
                && limit == u64::try_from(below).expect("small one-below limit")
        ));
    }

    let exact_work = prospective.work();
    let mut limits = base_limits;
    limits.max_work = exact_work;
    analyze_hir_facts(hir, operation, limits).expect("exact work limit passes");

    let below_work = one_below_u64(exact_work);
    let mut limits = base_limits;
    limits.max_work = below_work;
    assert!(matches!(
        analyze_hir_facts(hir, operation, limits),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit,
        }) if needed == exact_work && limit == below_work
    ));
}

fn parsed(pattern: &str, unicode: bool) -> RustParsed {
    let mut profile = RustProfile::default();
    profile.options.unicode = unicode;
    let record = parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile),
    ))
    .unwrap_or_else(|error| panic!("failed to parse {pattern:?}: {error}"));
    match record.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) | CanonicalPattern::Re2Literal(_) => {
            panic!("Rust request returned another syntax family")
        }
    }
}

fn facts(pattern: &str, unicode: bool, output: FactOutput) -> fre_lower::HirFacts {
    let parsed = parsed(pattern, unicode);
    analyze_hir_facts(
        &parsed.hir,
        FactOperation::new(output),
        FactLimits::default(),
    )
    .unwrap_or_else(|error| panic!("failed to analyze {pattern:?}: {error}"))
}

fn strings(proof: &FactProof<fre_lower::FiniteLanguage>) -> Vec<Vec<u8>> {
    proof
        .as_proven()
        .expect("finite language should be proved")
        .strings()
        .map(<[u8]>::to_vec)
        .collect()
}

#[test]
fn empty_language_nullable_and_unbounded_widths_are_distinct() {
    let empty = analyze_hir_facts(
        &Hir::fail(),
        FactOperation::new(FactOutput::Count),
        FactLimits::default(),
    )
    .expect("empty language analyzes");
    assert_eq!(empty.width(), CheckedWidth::EmptyLanguage);
    assert!(empty.width().minimum().is_none());
    assert!(!empty.width().is_nullable());

    let nullable = analyze_hir_facts(
        &Hir::empty(),
        FactOperation::new(FactOutput::Count),
        FactLimits::default(),
    )
    .expect("nullable language analyzes");
    assert_eq!(
        nullable.width(),
        CheckedWidth::NonEmpty {
            minimum: 0,
            maximum: Some(0),
        }
    );
    assert!(nullable.width().is_nullable());

    let star = facts("a*", false, FactOutput::Count);
    assert_eq!(
        star.width(),
        CheckedWidth::NonEmpty {
            minimum: 0,
            maximum: None,
        }
    );
    assert!(matches!(
        star.finite_language(),
        FactProof::Refused(FactRefusal::InfiniteLanguage)
    ));

    let fail = Hir::fail();
    assert_eq!(fail.properties().minimum_len(), None);
    assert_eq!(
        analyze_hir_facts(
            &fail,
            FactOperation::new(FactOutput::Exists),
            FactLimits::default()
        )
        .expect("unknown minimum remains analyzable")
        .width(),
        CheckedWidth::EmptyLanguage
    );
}

#[test]
fn complete_finite_language_is_separate_from_required_substrings_and_contexts() {
    let facts = facts("xx(?:foo|bar)yy", false, FactOutput::SpanSequence);
    assert_eq!(
        strings(facts.finite_language()),
        [b"xxfooyy".to_vec(), b"xxbaryy".to_vec()]
    );
    let groups = facts.required().as_proven().expect("required proof");
    let branch = groups
        .iter()
        .find(|group| {
            group.alternatives().len() == 2
                && group.alternatives().iter().all(|alternative| {
                    alternative.bytes() == b"foo" || alternative.bytes() == b"bar"
                })
        })
        .expect("finite alternation remains a required substring group");
    for alternative in branch.alternatives() {
        assert_eq!(alternative.context().before().minimum(), 2);
        assert_eq!(alternative.context().before().maximum(), Some(2));
        assert_eq!(alternative.context().after().minimum(), 2);
        assert_eq!(alternative.context().after().maximum(), Some(2));
        assert_eq!(alternative.encoding(), StringEncoding::Bytes);
    }
    assert_eq!(
        facts
            .reductions()
            .common_prefix()
            .as_proven()
            .expect("common prefix")
            .bytes(),
        b"xx"
    );
    assert_eq!(
        facts
            .reductions()
            .common_suffix()
            .as_proven()
            .expect("common suffix")
            .bytes(),
        b"yy"
    );
}

#[test]
fn assertions_publish_positions_and_only_proved_finite_delay() {
    let line = facts(r"(?m:^ab$)", false, FactOutput::Count);
    let possible = line
        .assertions()
        .possible()
        .as_proven()
        .expect("assertion positions");
    assert_eq!(possible.len(), 2);
    assert!(possible.iter().any(|assertion| {
        assertion.context().before().minimum() == 0 && assertion.context().after().minimum() == 2
    }));
    assert!(possible.iter().any(|assertion| {
        assertion.context().before().minimum() == 2 && assertion.context().after().minimum() == 0
    }));
    assert_eq!(line.finite_decision_horizon_bytes().as_proven(), Some(&3));

    let absolute_end = facts(r"ab\z", false, FactOutput::Count);
    assert!(absolute_end.assertions().requires_stream_end());
    assert!(matches!(
        absolute_end.finite_decision_horizon_bytes(),
        FactProof::Unknown
    ));
    assert!(matches!(
        absolute_end.determinism().subset(),
        FactProof::Refused(FactRefusal::AssertionContext)
    ));

    let finite_absolute_end = facts(r"a{1,3}\z", false, FactOutput::Count);
    assert_eq!(
        finite_absolute_end.width(),
        CheckedWidth::NonEmpty {
            minimum: 1,
            maximum: Some(3),
        }
    );
    assert!(finite_absolute_end.assertions().requires_stream_end());
    assert!(matches!(
        finite_absolute_end.finite_decision_horizon_bytes(),
        FactProof::Unknown
    ));
}

#[test]
fn unicode_scalar_alternatives_cover_simple_fold_edges_without_claiming_origin() {
    for (pattern, expected) in [
        (r"(?i:k)", vec!["K", "k", "\u{212A}"]),
        (r"(?i:σ)", vec!["Σ", "ς", "σ"]),
        (r"(?i:ш)", vec!["Ш", "ш"]),
    ] {
        let facts = facts(pattern, true, FactOutput::Count);
        let alternatives = facts
            .unicode()
            .scalar_alternatives()
            .as_proven()
            .unwrap_or_else(|| panic!("missing scalar alternatives for {pattern}"));
        let actual: Vec<&str> = alternatives
            .strings()
            .map(|bytes| std::str::from_utf8(bytes).expect("canonical scalar UTF-8"))
            .collect();
        for scalar in expected {
            assert!(actual.contains(&scalar), "{pattern}: missing {scalar:?}");
        }
        assert!(matches!(
            facts.unicode().simple_fold_origin(),
            FactProof::Refused(FactRefusal::OriginUnavailable)
        ));
        assert!(matches!(
            facts.unicode().full_fold_equivalence(),
            FactProof::Refused(FactRefusal::OriginUnavailable)
        ));
    }

    let kelvin = facts(r"(?i:k)", true, FactOutput::Count);
    assert!(kelvin.unicode().width_changing_alternatives());
    assert_eq!(kelvin.unicode().utf8_width_mask(), 0b0101);
}

#[test]
fn unicode_one_pass_requires_disjoint_emitted_utf8_first_edges() {
    let overlapping = Hir::class(Class::Unicode(ClassUnicode::new([
        ClassUnicodeRange::new('\u{100}', '\u{100}'),
        ClassUnicodeRange::new('\u{102}', '\u{102}'),
    ])));
    let report = analyze_hir_facts(
        &overlapping,
        FactOperation::new(FactOutput::Count),
        FactLimits::default(),
    )
    .expect("overlapping UTF-8 prefixes remain analyzable");
    assert!(matches!(
        report.determinism().one_pass(),
        FactProof::Refused(FactRefusal::OrderedAmbiguity)
    ));

    let singleton = Hir::class(Class::Unicode(ClassUnicode::new([ClassUnicodeRange::new(
        '\u{100}', '\u{100}',
    )])));
    assert!(
        analyze_hir_facts(
            &singleton,
            FactOperation::new(FactOutput::Count),
            FactLimits::default(),
        )
        .expect("single emitted UTF-8 branch")
        .determinism()
        .one_pass()
        .as_proven()
        .is_some()
    );
}

#[test]
fn broad_unicode_class_skips_surrogates_and_refuses_only_the_optional_proof() {
    let broad = facts(r"(?s:.)", true, FactOutput::Count);
    assert_eq!(broad.unicode().scalar_count(), 0x11_0000 - 0x800);
    assert_eq!(
        broad.width(),
        CheckedWidth::NonEmpty {
            minimum: 1,
            maximum: Some(4),
        }
    );
    assert!(matches!(
        broad.unicode().scalar_alternatives(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::FiniteStrings,
            ..
        })
    ));
    assert!(matches!(
        broad.finite_language(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::FiniteStrings,
            ..
        })
    ));
}

#[test]
fn capture_facts_are_operation_aware_ordered_and_participation_typed() {
    let captures = facts(r"(?P<outer>a(?P<inner>b))?", false, FactOutput::Captures);
    assert!(captures.captures().observable());
    let schema = captures.captures().captures();
    assert_eq!(
        schema
            .iter()
            .map(fre_lower::PositionedCapture::index)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(schema[0].name(), Some("outer"));
    assert_eq!(schema[1].name(), Some("inner"));
    assert!(
        schema
            .iter()
            .all(|capture| capture.participation() == CaptureParticipation::Maybe)
    );
    assert!(matches!(
        captures.reductions().common_prefix(),
        FactProof::Refused(FactRefusal::CapturesObservable)
    ));
    assert!(matches!(
        captures.captures().source_schema_complete(),
        FactProof::Refused(FactRefusal::OriginUnavailable)
    ));

    let value = facts(r"(ab)", false, FactOutput::SpanSum);
    assert!(!value.captures().observable());
    assert!(value.captures().erasure_permitted());
}

#[test]
fn value_capture_erasure_skips_priority_facts_and_closes_every_hard_limit() {
    let hir = parsed(r"(?:a|(ab))c|(?P<tail>(?:x+|xy){1,2})", false).hir;
    let operation = FactOperation::capture_erased(FactOutput::SpanSum);
    let baseline = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("capture-erased value facts");
    assert!(baseline.operation().erases_captures());
    assert!(baseline.captures().captures().is_empty());
    assert!(baseline.captures().erasure_permitted());
    assert_eq!(baseline.width().minimum(), Some(1));

    let prospective = baseline.prospective();
    let cases: &[LimitCase] = &[
        (
            FactResource::StackItems,
            |limits, value| limits.max_stack_items = value,
            prospective.peak_stack_items(),
        ),
        (
            FactResource::HirNodes,
            |limits, value| limits.max_hir_nodes = value,
            prospective.hir_nodes(),
        ),
        (
            FactResource::RetainedBytes,
            |limits, value| limits.max_retained_bytes = value,
            prospective.retained_bytes(),
        ),
        (
            FactResource::TemporaryBytes,
            |limits, value| limits.max_temporary_bytes = value,
            prospective.temporary_bytes(),
        ),
        (
            FactResource::PeakBytes,
            |limits, value| limits.max_peak_bytes = value,
            prospective.peak_bytes(),
        ),
        (
            FactResource::AllocationAttempts,
            |limits, value| limits.max_allocation_attempts = value,
            prospective.allocation_attempts(),
        ),
    ];
    for &(resource, set, exact) in cases {
        let mut exact_limits = FactLimits::default();
        set(&mut exact_limits, exact);
        analyze_hir_facts(&hir, operation, exact_limits)
            .unwrap_or_else(|error| panic!("exact erased {resource:?} failed: {error}"));

        let mut below = FactLimits::default();
        set(&mut below, one_below_usize(exact));
        assert!(
            matches!(
                analyze_hir_facts(&hir, operation, below),
                Err(FactError::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ),
            "one-below erased {resource:?}"
        );
    }

    analyze_hir_facts(
        &hir,
        operation,
        FactLimits {
            max_work: prospective.work(),
            ..FactLimits::default()
        },
    )
    .expect("exact erased work");
    assert!(matches!(
        analyze_hir_facts(
            &hir,
            operation,
            FactLimits {
                max_work: one_below_u64(prospective.work()),
                ..FactLimits::default()
            }
        ),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
    assert!(matches!(
        analyze_hir_facts(
            &hir,
            FactOperation::capture_erased(FactOutput::Captures),
            FactLimits::default()
        ),
        Err(FactError::CaptureErasureForCaptureOutput)
    ));
}

#[test]
fn ordered_shadowing_makes_capture_participation_exact_or_typed_unknown() {
    for (pattern, expected) in [
        ("a|(a)", CaptureParticipation::Never),
        ("(a)|a", CaptureParticipation::Always),
        ("a|(b)", CaptureParticipation::Maybe),
    ] {
        let report = facts(pattern, false, FactOutput::Captures);
        assert_eq!(
            report.captures().captures()[0].participation(),
            expected,
            "{pattern}"
        );
    }

    let unbounded = Hir::alternation(vec![
        Hir::repetition(Repetition {
            min: 1,
            max: None,
            greedy: true,
            sub: Box::new(Hir::literal(*b"a")),
        }),
        Hir::capture(Capture {
            index: 1,
            name: None,
            sub: Box::new(Hir::repetition(Repetition {
                min: 1,
                max: None,
                greedy: true,
                sub: Box::new(Hir::literal(*b"a")),
            })),
        }),
    ]);
    let report = analyze_hir_facts(
        &unbounded,
        FactOperation::new(FactOutput::Captures),
        FactLimits::default(),
    )
    .expect("unbounded shadow proof fails closed");
    assert_eq!(
        report.captures().captures()[0].participation(),
        CaptureParticipation::Unknown
    );
}

#[test]
fn a_rejecting_continuation_invalidates_local_prefix_shadowing() {
    let pattern = r"(?:a|(ab))c";
    let report = facts(pattern, false, FactOutput::Captures);
    assert_eq!(
        report.captures().captures()[0].participation(),
        CaptureParticipation::Maybe
    );
    assert!(report.stats().work() <= report.prospective().work());
    let hir = parsed(pattern, false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    let exact = report.prospective().work();
    analyze_hir_facts(
        &hir,
        operation,
        FactLimits {
            max_work: exact,
            ..FactLimits::default()
        },
    )
    .expect("exact continuation-aware work passes");
    let limit = one_below_u64(exact);
    assert!(matches!(
        analyze_hir_facts(
            &hir,
            operation,
            FactLimits {
                max_work: limit,
                ..FactLimits::default()
            }
        ),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit: actual_limit,
        }) if needed == exact && actual_limit == limit
    ));

    let oracle = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("directed continuation oracle compiles");
    assert!(
        oracle
            .captures(b"ac")
            .expect("first branch matches")
            .get(1)
            .is_none()
    );
    assert_eq!(
        oracle
            .captures(b"abc")
            .expect("continuation exposes the captured branch")
            .get(1)
            .map(|matched| matched.as_bytes()),
        Some(&b"ab"[..])
    );

    assert_eq!(
        facts(r"a|(ab)", false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation(),
        CaptureParticipation::Never,
        "terminal alternations retain exact prefix-shadow precision"
    );
    assert_eq!(
        facts(r"x(?:a|(ab))", false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation(),
        CaptureParticipation::Never,
        "a preceding concatenand is not a rejecting continuation"
    );
    assert_eq!(
        facts(r"(?:a|(ab)){2}", false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation(),
        CaptureParticipation::Unknown,
        "a later repetition can expose a locally shadowed branch"
    );

    let asserted_optional = r"(a)?\A";
    assert_eq!(
        facts(asserted_optional, false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation(),
        CaptureParticipation::Unknown,
        "a rejecting continuation can filter every capture-present repeat"
    );
    let optional_oracle = RegexBuilder::new(asserted_optional)
        .unicode(false)
        .build()
        .expect("asserted optional oracle compiles");
    for haystack in [b"".as_slice(), b"a".as_slice()] {
        assert!(
            optional_oracle
                .captures(haystack)
                .expect("asserted optional has an empty match")
                .get(1)
                .is_none()
        );
    }
}

fn tiny_ascii_haystacks(maximum_len: usize) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for byte in b"abc" {
                let mut value = prefix.clone();
                value.push(*byte);
                next.push(value);
            }
        }
        output.extend(next.iter().cloned());
        frontier = next;
    }
    output
}

fn oracle_participation(
    pattern: &str,
    capture: usize,
    haystacks: &[Vec<u8>],
) -> CaptureParticipation {
    let (present, absent) = oracle_capture_outcomes(pattern, capture, haystacks);
    match (present, absent) {
        (true, false) => CaptureParticipation::Always,
        (false, true) => CaptureParticipation::Never,
        (true, true) => CaptureParticipation::Maybe,
        (false, false) => panic!("oracle had no match for {pattern:?}"),
    }
}

fn oracle_capture_outcomes(pattern: &str, capture: usize, haystacks: &[Vec<u8>]) -> (bool, bool) {
    let oracle = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("oracle {pattern:?} failed: {error}"));
    let mut present = false;
    let mut absent = false;
    for haystack in haystacks {
        if let Some(captures) = oracle.captures(haystack) {
            if captures.get(capture).is_some() {
                present = true;
            } else {
                absent = true;
            }
        }
    }
    (present, absent)
}

#[test]
fn reverse_suffix_capture_participation_matches_pinned_oracle() {
    let haystacks = tiny_ascii_haystacks(7);
    for (pattern, expected) in [
        (r"(?:|(?:|(abc)))c", CaptureParticipation::Never),
        (r"(?:|(?:a|(abc)))c", CaptureParticipation::Never),
        (r"(?:a|(?:|(abc)))c", CaptureParticipation::Never),
        (r"(?:abc|())c", CaptureParticipation::Always),
    ] {
        let participation = facts(pattern, false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation();
        assert_eq!(participation, expected, "{pattern:?}");
        assert_eq!(
            oracle_participation(pattern, 1, &haystacks),
            expected,
            "pinned oracle changed for {pattern:?}",
        );
    }

    let oracle = RegexBuilder::new(r"(?:|(?:|(abc)))c")
        .unicode(false)
        .build()
        .expect("sealed regression oracle compiles");
    for haystack in [b"c".as_slice(), b"abcc".as_slice()] {
        assert!(
            oracle
                .captures(haystack)
                .expect("sealed witness matches")
                .get(1)
                .is_none(),
            "sealed witness unexpectedly entered capture: {haystack:?}",
        );
    }

    let report = facts(r"b|((?:a|(b)))", false, FactOutput::Captures);
    let captures = report.captures().captures();
    assert_eq!(captures[0].participation(), CaptureParticipation::Maybe);
    assert_eq!(captures[1].participation(), CaptureParticipation::Never);

    let hir = parsed(r"(?:|(?:|(abc)))c", false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    let report = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("sealed reverse-suffix regression analyzes");
    assert_exact_and_one_below_hard_limits(&hir, operation, FactLimits::default(), &report);
}

#[test]
fn adjacent_b_arm_reverse_suffix_preserves_full_match_source_priority() {
    let pattern = r"(?:|(?:b|(abc)))c";
    let report = facts(pattern, false, FactOutput::Captures);
    assert_eq!(
        report.captures().captures()[0].participation(),
        CaptureParticipation::Maybe,
    );

    let oracle = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("adjacent b-arm regression oracle compiles");
    let captured = oracle
        .captures(b"abcc")
        .expect("captured regression witness matches");
    assert_eq!(
        captured.get(0).map(|matched| matched.as_bytes()),
        Some(&b"abcc"[..]),
        "the captured witness must select its full match",
    );
    assert_eq!(
        captured.get(1).map(|matched| matched.as_bytes()),
        Some(&b"abc"[..]),
        "the full match must retain the captured arm",
    );
    let uncaptured = oracle
        .captures(b"c")
        .expect("uncaptured regression witness matches");
    assert_eq!(
        uncaptured.get(0).map(|matched| matched.as_bytes()),
        Some(&b"c"[..]),
        "the short witness must select its complete match",
    );
    assert!(
        uncaptured.get(1).is_none(),
        "the short witness must retain the uncaptured arm",
    );

    let hir = parsed(pattern, false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    let report = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("adjacent b-arm reverse-suffix regression analyzes");
    assert_exact_and_one_below_hard_limits(&hir, operation, FactLimits::default(), &report);
}

#[test]
fn reverse_suffix_certificate_rejects_retrying_neighbors() {
    let haystacks = tiny_ascii_haystacks(7);
    for (pattern, expected) in [
        (r"b(?:|(abc))c", CaptureParticipation::Maybe),
        (r"(?:|(ac))c", CaptureParticipation::Maybe),
        (r"(?:|(abcab))c", CaptureParticipation::Maybe),
        (r"(?:aa|(?:aa|(a)))", CaptureParticipation::Maybe),
    ] {
        let participation = facts(pattern, false, FactOutput::Captures)
            .captures()
            .captures()[0]
            .participation();
        assert_eq!(participation, expected, "{pattern:?}");
        assert_eq!(
            oracle_participation(pattern, 1, &haystacks),
            expected,
            "pinned oracle changed for {pattern:?}",
        );
    }

    let oracle = RegexBuilder::new(r"b(?:|(abc))c")
        .unicode(false)
        .build()
        .expect("retrying-neighbor oracle compiles");
    assert!(
        oracle
            .captures(b"bc")
            .expect("short neighbor witness matches")
            .get(1)
            .is_none(),
        "short witness must leave the nested capture absent",
    );
    assert_eq!(
        oracle
            .captures(b"ccbabcc")
            .expect("external-prefix neighbor witness matches")
            .get(1)
            .map(|matched| matched.as_bytes()),
        Some(&b"abc"[..]),
        "reverse-suffix fallback must be able to expose the nested capture",
    );
}

#[test]
fn nullable_nested_continuations_do_not_contradict_pinned_capture_oracle() {
    // Keep the sealed continuation reproducer's length-seven horizon. In
    // particular, it includes the external-prefix retry witness for
    // `b(?:|(abc))c` rather than treating bounded absence as a Never proof.
    let haystacks = tiny_ascii_haystacks(7);
    let operands = ["", "a", "b", "abc"];
    let contexts = [("", ""), ("b", ""), ("", "b"), ("b", "b")];
    let mut cases = 0_usize;
    for outer in operands {
        for inner in operands {
            for captured in operands {
                let capture = format!("({captured})");
                let source_orders = [
                    [outer, inner, capture.as_str()],
                    [outer, capture.as_str(), inner],
                    [capture.as_str(), outer, inner],
                ];
                for arms in source_orders {
                    let [first, second, third] = arms;
                    let bodies = [
                        format!("(?:{first}|(?:{second}|{third}))"),
                        format!("(?:(?:{first}|{second})|{third})"),
                        format!("(?:|(?:{first}|(?:{second}|{third})))"),
                        format!("(?:{first}|(?:|(?:{second}|{third})))"),
                        format!("(?:{first}|(?:{second}|{third})|)"),
                    ];
                    for (prefix, suffix) in contexts {
                        for body in &bodies {
                            let pattern = format!("{prefix}{body}c{suffix}");
                            let (present, absent) =
                                oracle_capture_outcomes(&pattern, 1, &haystacks);
                            let actual = facts(&pattern, false, FactOutput::Captures)
                                .captures()
                                .captures()[0]
                                .participation();
                            match actual {
                                CaptureParticipation::Never => assert!(
                                    !present,
                                    "{pattern:?} published Never despite a pinned captured witness"
                                ),
                                CaptureParticipation::Always => assert!(
                                    !absent,
                                    "{pattern:?} published Always despite a pinned absent witness"
                                ),
                                CaptureParticipation::Maybe | CaptureParticipation::Unknown => {}
                            }
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 3_840);
}

#[test]
fn generated_nested_alternations_are_conservative_against_a_capture_oracle() {
    let haystacks = tiny_ascii_haystacks(3);
    for left in ["a", "b", "aa", "ab", "ba"] {
        for right in ["a", "b", "aa", "ab", "ba"] {
            for suffix in ["a", "b", "c"] {
                for capture_left in [false, true] {
                    let pattern = if capture_left {
                        format!(r"\A(?:({left})|{right}){suffix}\z")
                    } else {
                        format!(r"\A(?:{left}|({right})){suffix}\z")
                    };
                    let oracle = RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap_or_else(|error| {
                            panic!("generated oracle {pattern:?} failed: {error}")
                        });
                    let mut saw_present = false;
                    let mut saw_absent = false;
                    for haystack in &haystacks {
                        if let Some(captures) = oracle.captures(haystack) {
                            if captures.get(1).is_some() {
                                saw_present = true;
                            } else {
                                saw_absent = true;
                            }
                        }
                    }
                    let participation = facts(&pattern, false, FactOutput::Captures)
                        .captures()
                        .captures()[0]
                        .participation();
                    match participation {
                        CaptureParticipation::Never => assert!(
                            !saw_present,
                            "{pattern:?} published Never despite a captured match"
                        ),
                        CaptureParticipation::Maybe => assert!(
                            saw_present && saw_absent,
                            "{pattern:?} published Maybe without both outcomes"
                        ),
                        CaptureParticipation::Always => assert!(
                            saw_present && !saw_absent,
                            "{pattern:?} published Always despite an absent capture"
                        ),
                        CaptureParticipation::Unknown => {}
                    }
                }
            }
        }
    }
}

#[test]
fn enclosing_priority_resolves_an_inherited_maybe_from_whole_match_paths() {
    let pattern = r"b|((?:a|(b)))";
    let report = facts(pattern, false, FactOutput::Captures);
    let captures = report.captures().captures();
    assert_eq!(captures.len(), 2);
    assert_eq!(
        captures[0].participation(),
        CaptureParticipation::Maybe,
        "the enclosing capture has reachable present and absent paths"
    );
    assert_eq!(
        captures[1].participation(),
        CaptureParticipation::Never,
        "whole-match priority proves every capture-present path unreachable"
    );

    let oracle = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("nested priority oracle compiles");
    for haystack in [b"a".as_slice(), b"b".as_slice()] {
        let matched = oracle
            .captures(haystack)
            .expect("each finite-language value matches");
        assert!(
            matched.get(2).is_none(),
            "outer priority must shadow every capture-present path for {haystack:?}"
        );
    }
}

#[test]
fn capture_trace_precision_cap_fails_closed_one_byte_below() {
    let hir = parsed(r"b|((?:a|(b)))", false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    let exact = analyze_hir_facts(
        &hir,
        operation,
        FactLimits {
            max_finite_string_bytes: 16,
            ..FactLimits::default()
        },
    )
    .expect("two one-word traces fit exactly");
    assert_eq!(
        exact.captures().captures()[1].participation(),
        CaptureParticipation::Never
    );

    let one_below = analyze_hir_facts(
        &hir,
        operation,
        FactLimits {
            max_finite_string_bytes: 15,
            ..FactLimits::default()
        },
    )
    .expect("optional trace precision fails closed");
    assert_eq!(
        one_below.captures().captures()[1].participation(),
        CaptureParticipation::Unknown
    );
}

#[test]
fn optional_capture_traces_are_isolated_from_count_and_span_sum() {
    let hir = parsed(r"b|((?:a|(b)))", false).hir;
    let precise_limits = FactLimits {
        max_finite_string_bytes: 16,
        ..FactLimits::default()
    };
    let refused_limits = FactLimits {
        max_finite_string_bytes: 15,
        ..FactLimits::default()
    };
    for output in [FactOutput::Count, FactOutput::SpanSum] {
        let operation = FactOperation::new(output);
        let precise = analyze_hir_facts(&hir, operation, precise_limits)
            .unwrap_or_else(|error| panic!("precise {output:?} failed: {error}"));
        let refused = analyze_hir_facts(&hir, operation, refused_limits)
            .unwrap_or_else(|error| panic!("refused {output:?} failed: {error}"));
        assert_eq!(
            precise, refused,
            "{output:?} observed private trace precision"
        );
        assert!(!precise.captures().observable(), "{output:?}");
        assert!(precise.captures().erasure_permitted(), "{output:?}");
        assert_exact_and_one_below_hard_limits(&hir, operation, precise_limits, &precise);
        assert_exact_and_one_below_hard_limits(&hir, operation, refused_limits, &refused);
    }
}

#[test]
fn capture_trace_fallback_keeps_exact_and_one_below_hard_accounting() {
    let hir = parsed(r"b|((?:a|(b)))", false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    for trace_cap in [16, 15] {
        let limits = FactLimits {
            max_finite_string_bytes: trace_cap,
            ..FactLimits::default()
        };
        let report = analyze_hir_facts(&hir, operation, limits)
            .unwrap_or_else(|error| panic!("trace cap {trace_cap} failed: {error}"));
        assert_exact_and_one_below_hard_limits(&hir, operation, limits, &report);
    }
}

fn trace_overflow_hir() -> Hir {
    let byte_class = || {
        Hir::class(Class::Bytes(ClassBytes::new([ClassBytesRange::new(
            0, 255,
        )])))
    };
    let captured = Hir::capture(Capture {
        index: 1,
        name: None,
        sub: Box::new(Hir::concat((0..5).map(|_| byte_class()).collect())),
    });
    Hir::alternation(vec![Hir::literal([b'z']), captured])
}

#[test]
fn unrepresentable_optional_capture_trace_refuses_before_hard_preflight() {
    let hir = trace_overflow_hir();
    let limits = FactLimits {
        max_finite_strings: usize::MAX,
        max_finite_string_bytes: usize::MAX,
        ..FactLimits::default()
    };
    let mut errors = Vec::new();
    for output in [FactOutput::Captures, FactOutput::Count, FactOutput::SpanSum] {
        let error = analyze_hir_facts(&hir, FactOperation::new(output), limits)
            .expect_err("ordinary hard preflight should stop the enormous finite language");
        assert!(
            matches!(error, FactError::ResourceLimit { .. }),
            "{output:?} leaked an optional trace failure: {error:?}",
        );
        errors.push(error);
    }
    assert!(
        errors.windows(2).all(|pair| pair[0] == pair[1]),
        "all routes must reach the same non-trace preflight: {errors:?}",
    );
}

#[test]
fn capture_trace_construction_and_root_resolution_are_preflighted() {
    let hir = parsed(r"b|((?:a|(b)))", false).hir;
    let operation = FactOperation::new(FactOutput::Captures);
    let baseline =
        analyze_hir_facts(&hir, operation, FactLimits::default()).expect("trace baseline");
    let prospective = baseline.prospective();
    assert!(baseline.stats().work() <= prospective.work());
    assert!(baseline.stats().temporary_bytes() <= prospective.temporary_bytes());
    assert!(baseline.stats().peak_bytes() <= prospective.peak_bytes());
    assert!(baseline.stats().allocation_attempts() <= prospective.allocation_attempts());

    let exact_work = FactLimits {
        max_work: prospective.work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact_work).expect("exact trace work passes");
    let below_work = one_below_u64(prospective.work());
    assert!(matches!(
        analyze_hir_facts(
            &hir,
            operation,
            FactLimits {
                max_work: below_work,
                ..FactLimits::default()
            }
        ),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit,
        }) if needed == prospective.work() && limit == below_work
    ));

    let cases: &[LimitCase] = &[
        (
            FactResource::TemporaryBytes,
            |limits, value| limits.max_temporary_bytes = value,
            prospective.temporary_bytes(),
        ),
        (
            FactResource::PeakBytes,
            |limits, value| limits.max_peak_bytes = value,
            prospective.peak_bytes(),
        ),
        (
            FactResource::AllocationAttempts,
            |limits, value| limits.max_allocation_attempts = value,
            prospective.allocation_attempts(),
        ),
    ];
    for &(resource, set, exact) in cases {
        let mut limits = FactLimits::default();
        set(&mut limits, exact);
        analyze_hir_facts(&hir, operation, limits)
            .unwrap_or_else(|error| panic!("exact {resource:?} failed: {error}"));
        let below = one_below_usize(exact);
        let mut limits = FactLimits::default();
        set(&mut limits, below);
        assert!(matches!(
            analyze_hir_facts(&hir, operation, limits),
            Err(FactError::ResourceLimit {
                resource: actual,
                needed,
                limit,
            }) if actual == resource
                && needed == u64::try_from(exact).expect("small exact limit")
                && limit == u64::try_from(below).expect("small one-below limit")
        ));
    }
}

#[test]
fn refused_capture_traces_do_not_consume_optional_proof_budget() {
    let mut branches = Vec::new();
    for index in 1..=8 {
        branches.push(Hir::capture(Capture {
            index,
            name: None,
            sub: Box::new(Hir::empty()),
        }));
    }
    let hir = Hir::concat(vec![
        Hir::alternation(branches),
        Hir::capture(Capture {
            index: 9,
            name: None,
            sub: Box::new(Hir::empty()),
        }),
    ]);
    let operation = FactOperation::new(FactOutput::Captures);
    let analyze = |trace_cap, max_work| {
        analyze_hir_facts(
            &hir,
            operation,
            FactLimits {
                max_finite_string_bytes: trace_cap,
                max_work,
                ..FactLimits::default()
            },
        )
    };

    let refused = analyze(0, u64::MAX).expect("zero-byte optional trace cap fails closed");
    let admitted = analyze(72, u64::MAX).expect("nine one-word trace slots are admitted");
    assert!(
        refused.prospective().work() < admitted.prospective().work(),
        "refused optional traces must not retain hypothetical construction or root work"
    );
    let refused_work = refused.prospective().work();
    analyze(0, refused_work).expect("refused optional proof passes at its exact work bound");
    assert!(matches!(
        analyze(72, refused_work),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit,
        }) if needed == admitted.prospective().work() && limit == refused_work
    ));
}

#[test]
fn capture_trace_mixed_radix_rows_follow_concat_derivation_order() {
    for pattern in [
        r"bx|by|(?:a|(b))(?:x|y)",
        r"pbx|pby|qbx|qby|(?:p|q)(?:a|(b))(?:x|y)",
        r"pb|qb|(?:p|q)(?:a|(b))",
    ] {
        assert_eq!(
            facts(pattern, false, FactOutput::Captures)
                .captures()
                .captures()[0]
                .participation(),
            CaptureParticipation::Never,
            "{pattern:?}",
        );
    }
}

#[test]
fn capture_trace_handles_duplicate_and_empty_derivations() {
    for (pattern, expected) in [
        (r"|()", CaptureParticipation::Never),
        (r"()|", CaptureParticipation::Always),
        (r"|(?:a|())", CaptureParticipation::Never),
        (r"(?:a|(a))(?:|b)", CaptureParticipation::Never),
    ] {
        assert_eq!(
            facts(pattern, false, FactOutput::Captures)
                .captures()
                .captures()[0]
                .participation(),
            expected,
            "{pattern:?}",
        );
    }
}

#[test]
fn capture_trace_does_not_refine_across_assertion_context() {
    let report = facts(r"(?:b|((?:a|(b))))\z", false, FactOutput::Captures);
    assert_eq!(
        report.captures().captures()[1].participation(),
        CaptureParticipation::Unknown,
    );
    assert!(report.stats().work() <= report.prospective().work());

    let repeated_prefix = facts(
        r"(?:x|xx){0,2}(?:b|((?:a|(b))))",
        false,
        FactOutput::Captures,
    );
    assert_eq!(
        repeated_prefix.captures().captures()[1].participation(),
        CaptureParticipation::Unknown,
        "a nontrivial adjacent repeat makes whole-root derivation order unavailable"
    );
}

#[test]
fn capture_trace_word_rounding_and_cap_fallback_are_exact() {
    fn analyze(rows: usize, trace_cap: usize) -> fre_lower::HirFacts {
        let absent_count = rows.checked_sub(2).expect("outer and present rows");
        let absent_end = 10_u8
            .checked_add(u8::try_from(absent_count - 1).expect("small class"))
            .expect("small class end");
        let absent = Hir::class(Class::Bytes(ClassBytes::new([ClassBytesRange::new(
            10, absent_end,
        )])));
        let mut present = Hir::literal([200_u8]);
        for index in (2..=9).rev() {
            present = Hir::capture(Capture {
                index,
                name: None,
                sub: Box::new(present),
            });
        }
        let second = Hir::capture(Capture {
            index: 1,
            name: None,
            sub: Box::new(Hir::alternation(vec![absent, present])),
        });
        let hir = Hir::alternation(vec![Hir::literal([200_u8]), second]);
        analyze_hir_facts(
            &hir,
            FactOperation::new(FactOutput::Captures),
            FactLimits {
                max_finite_string_bytes: trace_cap,
                ..FactLimits::default()
            },
        )
        .expect("optional trace cap fails closed")
    }

    for (rows, exact_cap) in [(64, 72), (65, 144)] {
        let exact = analyze(rows, exact_cap);
        assert_eq!(
            exact
                .finite_language()
                .as_proven()
                .expect("finite language remains available")
                .len(),
            rows
        );
        assert!(
            exact.captures().captures()[1..]
                .iter()
                .all(|capture| capture.participation() == CaptureParticipation::Never)
        );

        let below = analyze(rows, exact_cap - 1);
        assert!(
            below.captures().captures()[1..]
                .iter()
                .all(|capture| capture.participation() == CaptureParticipation::Unknown)
        );
    }
}

#[test]
fn whole_match_capture_paths_cross_a_rejecting_concatenation_continuation() {
    let report = facts(r"x(?:b|((?:a|(b))))y", false, FactOutput::Captures);
    let captures = report.captures().captures();
    assert_eq!(captures.len(), 2);
    assert_eq!(captures[0].participation(), CaptureParticipation::Maybe);
    assert_eq!(captures[1].participation(), CaptureParticipation::Never);

    let recovered = facts(r"(?:a|(ab))c", false, FactOutput::Captures);
    assert_eq!(
        recovered.captures().captures()[0].participation(),
        CaptureParticipation::Maybe,
        "whole-match rows retain the locally rejected captured path"
    );
}

#[test]
fn generated_nested_partial_shadowing_is_exact_against_a_capture_oracle() {
    let haystacks = tiny_ascii_haystacks(4);
    for (prefix, suffix) in [("", ""), ("c", ""), ("", "c"), ("c", "c")] {
        for outer in ["a", "b", "aa", "ab"] {
            for absent in ["a", "b", "aa", "ba"] {
                for present in ["a", "b", "ab", "ba"] {
                    let pattern = format!(r"{prefix}(?:{outer}|(?:{absent}|({present}))){suffix}");
                    let oracle = RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap_or_else(|error| {
                            panic!("generated nested oracle {pattern:?} failed: {error}")
                        });
                    let mut saw_present = false;
                    let mut saw_absent = false;
                    for haystack in &haystacks {
                        if let Some(captures) = oracle.captures(haystack) {
                            if captures.get(1).is_some() {
                                saw_present = true;
                            } else {
                                saw_absent = true;
                            }
                        }
                    }
                    let participation = facts(&pattern, false, FactOutput::Captures)
                        .captures()
                        .captures()[0]
                        .participation();
                    let expected = match (saw_present, saw_absent) {
                        (true, true) => CaptureParticipation::Maybe,
                        (true, false) => CaptureParticipation::Always,
                        (false, true) => CaptureParticipation::Never,
                        (false, false) => panic!("{pattern:?} had no oracle matches"),
                    };
                    assert_eq!(participation, expected, "{pattern:?}");
                }
            }
        }
    }
}

fn unavailable_predecessor_capture_facts(
    predecessors: usize,
    candidate_values: u8,
    max_work: u64,
) -> Result<fre_lower::HirFacts, FactError> {
    let mut branches = Vec::new();
    for index in 0..predecessors {
        let start = u8::try_from(index)
            .expect("small predecessor index")
            .checked_mul(10)
            .expect("small predecessor range");
        let end = start.checked_add(8).expect("nine-value predecessor range");
        branches.push(Hir::class(Class::Bytes(ClassBytes::new([
            ClassBytesRange::new(start, end),
        ]))));
    }
    let candidate_end = 200_u8
        .checked_add(candidate_values)
        .and_then(|end| end.checked_sub(1))
        .expect("nonempty small candidate range");
    branches.push(Hir::capture(Capture {
        index: 1,
        name: None,
        sub: Box::new(Hir::class(Class::Bytes(ClassBytes::new([
            ClassBytesRange::new(200, candidate_end),
        ])))),
    }));
    analyze_hir_facts(
        &Hir::alternation(branches),
        FactOperation::new(FactOutput::Captures),
        FactLimits {
            max_work,
            max_finite_strings: 8,
            ..FactLimits::default()
        },
    )
}

#[test]
fn unavailable_predecessor_capture_work_scales_by_p_times_m_and_is_preflighted() {
    let analyze = |predecessors, values| {
        unavailable_predecessor_capture_facts(predecessors, values, u64::MAX)
            .expect("capture-priority fixture analyzes")
    };
    let p0_m0 = analyze(1, 2);
    let p0_m1 = analyze(1, 6);
    let p1_m0 = analyze(4, 2);
    let p1_m1 = analyze(4, 6);

    let actual_mixed = i128::from(p1_m1.stats().work())
        - i128::from(p0_m1.stats().work())
        - i128::from(p1_m0.stats().work())
        + i128::from(p0_m0.stats().work());
    let prospective_mixed = i128::from(p1_m1.prospective().work())
        - i128::from(p0_m1.prospective().work())
        - i128::from(p1_m0.prospective().work())
        + i128::from(p0_m0.prospective().work());
    let expected_product = i128::from((4 - 1) * (6 - 2));
    assert_eq!(actual_mixed, expected_product);
    assert_eq!(prospective_mixed, expected_product);
    assert!(p1_m1.stats().work() <= p1_m1.prospective().work());

    let exact = p1_m1.prospective().work();
    unavailable_predecessor_capture_facts(4, 6, exact).expect("exact capture-priority work passes");
    let limit = one_below_u64(exact);
    assert!(matches!(
        unavailable_predecessor_capture_facts(4, 6, limit),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit: actual_limit,
        }) if needed == exact && actual_limit == limit
    ));
}

fn finite_predecessor_capture_facts(
    predecessor_values: u8,
    candidate_values: u8,
    max_work: u64,
) -> Result<fre_lower::HirFacts, FactError> {
    let predecessor_end = 10_u8
        .checked_add(predecessor_values)
        .and_then(|end| end.checked_sub(1))
        .expect("nonempty small predecessor range");
    let candidate_end = 200_u8
        .checked_add(candidate_values)
        .and_then(|end| end.checked_sub(1))
        .expect("nonempty small candidate range");
    let hir = Hir::alternation(vec![
        Hir::class(Class::Bytes(ClassBytes::new([ClassBytesRange::new(
            10,
            predecessor_end,
        )]))),
        Hir::capture(Capture {
            index: 1,
            name: None,
            sub: Box::new(Hir::class(Class::Bytes(ClassBytes::new([
                ClassBytesRange::new(200, candidate_end),
            ])))),
        }),
    ]);
    analyze_hir_facts(
        &hir,
        FactOperation::new(FactOutput::Captures),
        FactLimits {
            max_work,
            // Keep each child finite while refusing the combined root
            // language. That isolates the Q/R priority comparisons from the
            // independent root duplicate-reduction upper bound.
            max_finite_strings: usize::from(predecessor_values.max(candidate_values)),
            ..FactLimits::default()
        },
    )
}

#[test]
fn finite_predecessor_capture_q_and_r_work_is_preflighted_at_the_exact_boundary() {
    let analyze = |predecessors, values| {
        finite_predecessor_capture_facts(predecessors, values, u64::MAX)
            .expect("finite capture-priority fixture analyzes")
    };
    let q0_m0 = analyze(2, 2);
    let q0_m1 = analyze(2, 6);
    let q1_m0 = analyze(6, 2);
    let q1_m1 = analyze(6, 6);

    // Each additional one-byte predecessor contributes one Q length probe and
    // one R byte probe for each additional candidate.
    let expected_q_and_r = i128::from((6 - 2) * (6 - 2) * 2);
    let actual_mixed = i128::from(q1_m1.stats().work())
        - i128::from(q0_m1.stats().work())
        - i128::from(q1_m0.stats().work())
        + i128::from(q0_m0.stats().work());
    let prospective_mixed = i128::from(q1_m1.prospective().work())
        - i128::from(q0_m1.prospective().work())
        - i128::from(q1_m0.prospective().work())
        + i128::from(q0_m0.prospective().work());
    assert_eq!(actual_mixed, expected_q_and_r);
    assert_eq!(prospective_mixed, expected_q_and_r);
    assert!(q1_m1.stats().work() <= q1_m1.prospective().work());

    let exact = q1_m1.prospective().work();
    finite_predecessor_capture_facts(6, 6, exact).expect("exact finite-predecessor work passes");
    let limit = one_below_u64(exact);
    assert!(matches!(
        finite_predecessor_capture_facts(6, 6, limit),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            needed,
            limit: actual_limit,
        }) if needed == exact && actual_limit == limit
    ));
}

#[test]
fn tiny_ordered_capture_alternations_match_an_independent_priority_oracle() {
    for left in [b'a', b'b'] {
        for right in [b'a', b'b'] {
            for capture_left in [false, true] {
                let mut left_hir = Hir::literal([left]);
                let mut right_hir = Hir::literal([right]);
                if capture_left {
                    left_hir = Hir::capture(Capture {
                        index: 1,
                        name: None,
                        sub: Box::new(left_hir),
                    });
                } else {
                    right_hir = Hir::capture(Capture {
                        index: 1,
                        name: None,
                        sub: Box::new(right_hir),
                    });
                }
                let report = analyze_hir_facts(
                    &Hir::alternation(vec![left_hir, right_hir]),
                    FactOperation::new(FactOutput::Captures),
                    FactLimits::default(),
                )
                .expect("tiny ordered alternation");
                let expected = match (left == right, capture_left) {
                    (true, true) => CaptureParticipation::Always,
                    (true, false) => CaptureParticipation::Never,
                    (false, _) => CaptureParticipation::Maybe,
                };
                assert_eq!(
                    report.captures().captures()[0].participation(),
                    expected,
                    "left={left:?}, right={right:?}, capture_left={capture_left}"
                );
            }
        }
    }
}

#[test]
fn impossible_hir_capture_arms_remain_in_the_schema_as_never_participating() {
    let dead = Hir::capture(Capture {
        index: 1,
        name: Some("dead".into()),
        sub: Box::new(Hir::fail()),
    });
    let hir = Hir::alternation(vec![dead, Hir::literal(*b"a")]);
    let facts = analyze_hir_facts(
        &hir,
        FactOperation::new(FactOutput::Captures),
        FactLimits::default(),
    )
    .expect("mixed empty alternation analyzes");
    let captures = facts.captures().captures();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].index(), 1);
    assert_eq!(captures[0].participation(), CaptureParticipation::Never);

    // regex-syntax's canonical smart constructor erases an outer `{0}` and
    // therefore its child capture before this HIR-only analyzer can see it.
    let erased = Hir::repetition(Repetition {
        min: 0,
        max: Some(0),
        greedy: true,
        sub: Box::new(Hir::capture(Capture {
            index: 2,
            name: None,
            sub: Box::new(Hir::literal(*b"b")),
        })),
    });
    let erased = analyze_hir_facts(
        &erased,
        FactOperation::new(FactOutput::Captures),
        FactLimits::default(),
    )
    .expect("canonical zero repeat analyzes");
    assert!(erased.captures().captures().is_empty());
    assert!(matches!(
        erased.captures().source_schema_complete(),
        FactProof::Refused(FactRefusal::OriginUnavailable)
    ));
}

#[test]
fn deterministic_certificate_uses_priority_ordered_not_unordered_state_bound() {
    let report = facts(r"(?:ab|ac)d", false, FactOutput::SpanSequence);
    if let FactProof::Proven(certificate) = report.determinism().subset() {
        let states = certificate.thompson_states_upper_bound();
        if states < usize::try_from(usize::BITS).expect("usize bit width fits usize") {
            assert!(
                certificate.subset_states_upper_bound()
                    >= 1_usize
                        .checked_shl(u32::try_from(states).expect("state count fits shift"))
                        .expect("guarded shift fits usize"),
                "ordered subsets cannot use a smaller unordered 2^N bound"
            );
        }
        assert!(certificate.preconditions().preserves_priority());
        assert!(certificate.preconditions().preserves_greediness());
    }

    let ambiguous = facts(r"(?:a+b|a)", false, FactOutput::SpanSequence);
    assert!(matches!(
        ambiguous.determinism().one_pass(),
        FactProof::Refused(FactRefusal::OrderedAmbiguity)
    ));
}

#[test]
fn thompson_state_bound_includes_the_lowerers_final_accept_state() {
    for hir in [
        Hir::empty(),
        Hir::literal(*b"a"),
        parsed("[ab]", false).hir,
        parsed(r"\A", false).hir,
    ] {
        let facts = analyze_hir_facts(
            &hir,
            FactOperation::new(FactOutput::Count),
            FactLimits::default(),
        )
        .expect("leaf facts analyze");
        let lowered = lower_hir_raw(
            &hir,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("leaf lowers");
        assert_eq!(
            facts.determinism().thompson_states_upper_bound(),
            lowered.stats().states(),
            "{hir:?}"
        );
    }
}

#[test]
fn duplicate_reduction_is_typed_and_capture_assertion_barriers_are_isolated() {
    let duplicate = facts(r"(?:ab|ab|ac)", false, FactOutput::Count);
    assert_eq!(
        duplicate
            .reductions()
            .duplicate_consuming_alternatives()
            .as_proven(),
        Some(&1)
    );

    let asserted = facts(r"(?:\Aab|\Aab)", false, FactOutput::Count);
    assert!(matches!(
        asserted.reductions().duplicate_consuming_alternatives(),
        FactProof::Refused(FactRefusal::AssertionContext)
    ));
}

#[test]
fn duplicate_sort_scratch_is_live_with_byte_class_facts_and_peak_gated() {
    let hir = parsed("[a-d]", false).hir;
    let operation = FactOperation::new(FactOutput::Count);
    let baseline = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("byte-class facts analyze");
    let order_bytes = baseline
        .finite_language()
        .as_proven()
        .expect("byte class is finite")
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .expect("tiny fixture order bytes");
    assert!(
        baseline
            .stats()
            .temporary_bytes()
            .checked_add(std::mem::size_of::<fre_lower::HirFacts>())
            .expect("tiny fixture peak bytes")
            >= baseline
                .stats()
                .retained_bytes()
                .checked_add(order_bytes)
                .expect("tiny fixture retained bytes")
    );

    let prospective = baseline.prospective();
    let exact = FactLimits {
        max_temporary_bytes: prospective.temporary_bytes(),
        max_peak_bytes: prospective.peak_bytes(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact).expect("exact scratch peak passes");

    let below_temporary = FactLimits {
        max_temporary_bytes: one_below_usize(prospective.temporary_bytes()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, below_temporary),
        Err(FactError::ResourceLimit {
            resource: FactResource::TemporaryBytes,
            ..
        })
    ));

    let below_peak = FactLimits {
        max_peak_bytes: one_below_usize(prospective.peak_bytes()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, below_peak),
        Err(FactError::ResourceLimit {
            resource: FactResource::PeakBytes,
            ..
        })
    ));
}

#[test]
fn every_hard_prospective_dimension_passes_exact_and_refuses_one_below() {
    let hir = parsed(r"(?:ab|cd){2}", false).hir;
    let operation = FactOperation::new(FactOutput::SpanSequence);
    let baseline =
        analyze_hir_facts(&hir, operation, FactLimits::default()).expect("baseline facts analyze");
    let prospective = baseline.prospective();
    assert!(baseline.stats().work() <= prospective.work());
    assert!(baseline.stats().retained_bytes() <= prospective.retained_bytes());
    assert!(baseline.stats().temporary_bytes() <= prospective.temporary_bytes());
    assert!(baseline.stats().peak_bytes() <= prospective.peak_bytes());
    assert!(baseline.stats().allocation_attempts() <= prospective.allocation_attempts());

    let cases: &[LimitCase] = &[
        (
            FactResource::StackItems,
            |limits, value| limits.max_stack_items = value,
            prospective.peak_stack_items(),
        ),
        (
            FactResource::HirNodes,
            |limits, value| limits.max_hir_nodes = value,
            prospective.hir_nodes(),
        ),
        (
            FactResource::RetainedBytes,
            |limits, value| limits.max_retained_bytes = value,
            prospective.retained_bytes(),
        ),
        (
            FactResource::TemporaryBytes,
            |limits, value| limits.max_temporary_bytes = value,
            prospective.temporary_bytes(),
        ),
        (
            FactResource::PeakBytes,
            |limits, value| limits.max_peak_bytes = value,
            prospective.peak_bytes(),
        ),
        (
            FactResource::AllocationAttempts,
            |limits, value| limits.max_allocation_attempts = value,
            prospective.allocation_attempts(),
        ),
    ];
    for &(resource, set, exact) in cases {
        let mut limits = FactLimits::default();
        set(&mut limits, exact);
        analyze_hir_facts(&hir, operation, limits)
            .unwrap_or_else(|error| panic!("exact {resource:?} failed: {error}"));
        let mut one_below = FactLimits::default();
        set(&mut one_below, one_below_usize(exact));
        assert!(
            matches!(
                analyze_hir_facts(&hir, operation, one_below),
                Err(FactError::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ),
            "one-below {resource:?}"
        );
    }

    let exact_work = FactLimits {
        max_work: prospective.work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact_work).expect("exact work passes");
    let one_below_work = FactLimits {
        max_work: one_below_u64(prospective.work()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, one_below_work),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
}

#[test]
fn repaired_fact_identity_and_assertion_work_envelope_are_exact() {
    let hir = Hir::alternation(vec![
        Hir::concat(vec![
            Hir::look(Look::Start),
            Hir::literal(*b"a"),
            Hir::look(Look::End),
        ]),
        Hir::concat(vec![
            Hir::look(Look::Start),
            Hir::literal(*b"b"),
            Hir::look(Look::End),
        ]),
    ]);
    let operation = FactOperation::new(FactOutput::Count);
    let baseline =
        analyze_hir_facts(&hir, operation, FactLimits::default()).expect("assertion baseline");
    let identity = baseline.identity();
    assert!(identity.authenticates_current());
    assert_eq!(identity.algorithm_version(), HIR_FACT_ALGORITHM_VERSION);
    assert_eq!(identity.accounting_version(), HIR_FACT_ACCOUNTING_VERSION);
    assert_eq!(HIR_FACT_ALGORITHM_VERSION, 8);
    assert_eq!(HIR_FACT_ACCOUNTING_VERSION, 8);

    let exact = FactLimits {
        max_work: baseline.prospective().work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact).expect("exact assertion-work envelope");
    let one_below = FactLimits {
        max_work: one_below_u64(baseline.prospective().work()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, one_below),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
}

#[test]
fn explicit_optional_fact_envelopes_preserve_default_and_close_route_requests() {
    let hir = Hir::concat(vec![Hir::literal(*b"a"), Hir::literal(*b"b")]);
    let complete = FactOperation::capture_erased(FactOutput::Count);
    let baseline = analyze_hir_facts(&hir, complete, FactLimits::default())
        .expect("complete default analysis remains available");
    assert!(matches!(baseline.finite_language(), FactProof::Proven(_)));
    assert!(matches!(baseline.required(), FactProof::Proven(_)));
    assert!(matches!(
        baseline.assertions().possible(),
        FactProof::Proven(assertions) if assertions.is_empty()
    ));

    let core = complete.with_optional_proofs(FactOptionalProofs::CoreOnly);
    let core_facts =
        analyze_hir_facts(&hir, core, FactLimits::default()).expect("core route envelope analyzes");
    assert_eq!(core_facts.width(), baseline.width());
    assert_eq!(core_facts.operation(), core);
    assert!(matches!(
        core_facts.finite_language(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert!(matches!(
        core_facts.required(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert!(matches!(
        core_facts.assertions().possible(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert!(matches!(
        core_facts.finite_decision_horizon_bytes(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert!(matches!(
        core_facts.determinism().subset(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert!(matches!(
        core_facts.reductions().common_prefix(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert_exact_and_one_below_hard_limits(&hir, core, FactLimits::default(), &core_facts);

    let finite = complete.with_optional_proofs(FactOptionalProofs::AssertionContext);
    let finite_facts = analyze_hir_facts(&hir, finite, FactLimits::default())
        .expect("finite-horizon route envelope analyzes");
    assert!(matches!(
        finite_facts.assertions().possible(),
        FactProof::Proven(assertions) if assertions.is_empty()
    ));
    assert!(matches!(
        finite_facts.finite_decision_horizon_bytes(),
        FactProof::Proven(2)
    ));
    assert!(matches!(
        finite_facts.determinism().subset(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));

    let deterministic =
        complete.with_optional_proofs(FactOptionalProofs::AssertionContextAndDeterminism);
    let deterministic_facts = analyze_hir_facts(&hir, deterministic, FactLimits::default())
        .expect("deterministic route envelope analyzes");
    assert!(matches!(
        deterministic_facts.determinism().subset(),
        FactProof::Proven(_)
    ));
    assert!(matches!(
        deterministic_facts.finite_language(),
        FactProof::Refused(FactRefusal::NotRequested)
    ));
    assert_exact_and_one_below_hard_limits(
        &hir,
        deterministic,
        FactLimits::default(),
        &deterministic_facts,
    );
}

#[test]
fn unicode_optional_envelopes_skip_scalar_materialization_and_keep_exact_limits() {
    // A broad Unicode class has a compact width fact, but its scalar language
    // is intentionally far beyond the optional finite-language envelope.
    // Core and assertion-context routes must not construct that envelope just
    // to publish width or assertion context.
    let hir = Hir::class(Class::Unicode(ClassUnicode::new([ClassUnicodeRange::new(
        '\0',
        '\u{10_FFFF}',
    )])));
    let base = FactOperation::capture_erased(FactOutput::Count);

    for operation in [
        base.with_optional_proofs(FactOptionalProofs::CoreOnly),
        base.with_optional_proofs(FactOptionalProofs::AssertionContext),
    ] {
        let report = analyze_hir_facts(&hir, operation, FactLimits::default())
            .expect("Unicode optional envelope analyzes without scalar materialization");
        assert_eq!(
            report.width(),
            CheckedWidth::NonEmpty {
                minimum: 1,
                maximum: Some(4),
            }
        );
        assert!(matches!(
            report.finite_language(),
            FactProof::Refused(FactRefusal::NotRequested)
        ));
        assert!(matches!(
            report.unicode().scalar_alternatives(),
            FactProof::Refused(FactRefusal::NotRequested)
        ));
        match operation.optional_proofs() {
            FactOptionalProofs::CoreOnly => assert!(matches!(
                report.assertions().possible(),
                FactProof::Refused(FactRefusal::NotRequested)
            )),
            FactOptionalProofs::AssertionContext => {
                assert!(matches!(
                    report.assertions().possible(),
                    FactProof::Proven(assertions) if assertions.is_empty()
                ));
                assert!(matches!(
                    report.finite_decision_horizon_bytes(),
                    FactProof::Proven(4)
                ));
            }
            FactOptionalProofs::Complete | FactOptionalProofs::AssertionContextAndDeterminism => {
                unreachable!("test enumerates only scalar-free envelopes")
            }
            _ => unreachable!("test enumerates only the current scalar-free envelopes"),
        }
        assert_exact_and_one_below_hard_limits(&hir, operation, FactLimits::default(), &report);
    }
}

#[test]
fn unicode_composite_route_envelopes_bound_actual_fact_work() {
    for pattern in [r"\w{5}\s\w{6}\s\w{7}", r"\pL+herloc\pL+|\pL+olme\pL+"] {
        let hir = parsed(pattern, true).hir;
        for output in [FactOutput::Count, FactOutput::SpanSum] {
            let base = FactOperation::capture_erased(output);
            for optional_proofs in [
                FactOptionalProofs::CoreOnly,
                FactOptionalProofs::AssertionContext,
            ] {
                let operation = base.with_optional_proofs(optional_proofs);
                let report = analyze_hir_facts(&hir, operation, FactLimits::default())
                    .unwrap_or_else(|error| {
                        panic!(
                            "{pattern:?} {output:?}/{optional_proofs:?} fact analysis failed: {error}"
                        )
                    });
                assert_exact_and_one_below_hard_limits(
                    &hir,
                    operation,
                    FactLimits::default(),
                    &report,
                );
            }
        }
    }
}

#[test]
fn shifted_assertion_copy_work_passes_exact_and_refuses_one_below() {
    let hir = Hir::repetition(Repetition {
        min: 1,
        max: Some(2),
        greedy: true,
        sub: Box::new(Hir::concat(vec![
            Hir::look(Look::Start),
            Hir::literal(*b"a"),
            Hir::look(Look::End),
        ])),
    });
    let operation = FactOperation::new(FactOutput::Count);
    let baseline =
        analyze_hir_facts(&hir, operation, FactLimits::default()).expect("shifted assertions");
    let exact = FactLimits {
        max_work: baseline.prospective().work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact).expect("exact shifted-assertion work");
    let one_below = FactLimits {
        max_work: one_below_u64(baseline.prospective().work()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, one_below),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
}

#[test]
fn optional_proof_limits_publish_exact_refusals_and_preserve_fallback() {
    let hir = parsed("foo|bar", false).hir;
    let operation = FactOperation::new(FactOutput::Count);
    let baseline =
        analyze_hir_facts(&hir, operation, FactLimits::default()).expect("baseline facts");
    assert_eq!(baseline.stats().finite_strings(), 2);
    assert_eq!(baseline.stats().finite_string_bytes(), 6);

    let exact = FactLimits {
        max_finite_strings: 2,
        max_finite_string_bytes: 6,
        max_required_groups: 1,
        max_required_alternatives: 2,
        max_required_bytes: 6,
        ..FactLimits::default()
    };
    assert!(
        analyze_hir_facts(&hir, operation, exact)
            .expect("exact proof limits")
            .finite_language()
            .as_proven()
            .is_some()
    );

    let finite_count_below = FactLimits {
        max_finite_strings: 1,
        ..FactLimits::default()
    };
    let refused = analyze_hir_facts(&hir, operation, finite_count_below)
        .expect("optional proof refusal is not a hard failure");
    assert!(matches!(
        refused.finite_language(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::FiniteStrings,
            needed: 2,
            limit: 1,
        })
    ));

    let finite_bytes_below = FactLimits {
        max_finite_string_bytes: 5,
        ..FactLimits::default()
    };
    let refused = analyze_hir_facts(&hir, operation, finite_bytes_below)
        .expect("optional byte proof refusal");
    assert!(matches!(
        refused.finite_language(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::FiniteStringBytes,
            needed: 6,
            limit: 5,
        })
    ));

    let required_below = FactLimits {
        max_required_alternatives: 1,
        ..FactLimits::default()
    };
    let refused =
        analyze_hir_facts(&hir, operation, required_below).expect("required proof falls back");
    assert!(matches!(
        refused.required(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::RequiredAlternatives,
            needed: 2,
            limit: 1,
        })
    ));

    let required_groups_below = FactLimits {
        max_required_groups: 0,
        ..FactLimits::default()
    };
    let refused = analyze_hir_facts(&hir, operation, required_groups_below)
        .expect("required group proof falls back");
    assert!(matches!(
        refused.required(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::RequiredGroups,
            needed: 1,
            limit: 0,
        })
    ));

    let required_bytes_below = FactLimits {
        max_required_bytes: 5,
        ..FactLimits::default()
    };
    let refused = analyze_hir_facts(&hir, operation, required_bytes_below)
        .expect("required byte proof falls back");
    assert!(matches!(
        refused.required(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::RequiredBytes,
            needed: 6,
            limit: 5,
        })
    ));
}

#[test]
fn assertion_cap_refusal_preserves_structural_stream_end_provenance() {
    let operation = FactOperation::new(FactOutput::Count)
        .with_optional_proofs(FactOptionalProofs::AssertionContext);

    let non_stream_hir = parsed(r"\b(?:cat|cater)\b", false).hir;
    let non_stream_baseline = analyze_hir_facts(&non_stream_hir, operation, FactLimits::default())
        .expect("non-stream assertion baseline");
    let non_stream_assertions = non_stream_baseline.prospective().assertions();
    assert!(
        non_stream_assertions > 0,
        "fixture has positioned assertions"
    );
    let non_stream_limit = one_below_usize(non_stream_assertions);
    let non_stream = analyze_hir_facts(
        &non_stream_hir,
        operation,
        FactLimits {
            max_assertions: non_stream_limit,
            ..FactLimits::default()
        },
    )
    .expect("assertion cap is an optional-proof refusal");
    assert!(!non_stream.assertions().requires_stream_end());
    assert!(matches!(
        non_stream.assertions().possible(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::Assertions,
            needed,
            limit,
        }) if *needed == u64::try_from(non_stream_assertions).expect("small assertion count")
            && *limit == u64::try_from(non_stream_limit).expect("small assertion limit")
    ));
    assert!(matches!(
        non_stream.finite_decision_horizon_bytes(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::Assertions,
            needed,
            limit,
        }) if *needed == u64::try_from(non_stream_assertions).expect("small assertion count")
            && *limit == u64::try_from(non_stream_limit).expect("small assertion limit")
    ));

    let stream_end_hir = parsed(r"a{1,3}\z", false).hir;
    let stream_end_baseline = analyze_hir_facts(&stream_end_hir, operation, FactLimits::default())
        .expect("stream-end assertion baseline");
    let stream_end_assertions = stream_end_baseline.prospective().assertions();
    assert!(
        stream_end_assertions > 0,
        "fixture has a stream-end assertion"
    );
    let stream_end_limit = one_below_usize(stream_end_assertions);
    let stream_end = analyze_hir_facts(
        &stream_end_hir,
        operation,
        FactLimits {
            max_assertions: stream_end_limit,
            ..FactLimits::default()
        },
    )
    .expect("assertion cap is an optional-proof refusal");
    assert!(stream_end.assertions().requires_stream_end());
    assert!(matches!(
        stream_end.assertions().possible(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::Assertions,
            needed,
            limit,
        }) if *needed == u64::try_from(stream_end_assertions).expect("small assertion count")
            && *limit == u64::try_from(stream_end_limit).expect("small assertion limit")
    ));
    assert!(matches!(
        stream_end.finite_decision_horizon_bytes(),
        FactProof::Unknown
    ));
}

#[test]
fn assertion_and_ordered_state_optional_caps_are_exact_and_one_below() {
    let assertion_hir = parsed(r"\Aab\z", false).hir;
    let operation = FactOperation::new(FactOutput::Count);
    let exact_assertions = FactLimits {
        max_assertions: 2,
        ..FactLimits::default()
    };
    assert!(
        analyze_hir_facts(&assertion_hir, operation, exact_assertions)
            .expect("exact assertion limit")
            .assertions()
            .possible()
            .as_proven()
            .is_some()
    );
    let below_assertions = FactLimits {
        max_assertions: 1,
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&assertion_hir, operation, below_assertions)
            .expect("assertion proof refusal")
            .assertions()
            .possible(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::Assertions,
            needed: 2,
            limit: 1,
        })
    ));

    let literal = parsed("a", false).hir;
    let baseline =
        analyze_hir_facts(&literal, operation, FactLimits::default()).expect("literal facts");
    let bound = baseline
        .determinism()
        .subset()
        .as_proven()
        .expect("literal deterministic certificate")
        .subset_states_upper_bound();
    let exact_states = FactLimits {
        max_deterministic_states: bound,
        ..FactLimits::default()
    };
    assert!(
        analyze_hir_facts(&literal, operation, exact_states)
            .expect("exact ordered-state bound")
            .determinism()
            .subset()
            .as_proven()
            .is_some()
    );
    let below_states = FactLimits {
        max_deterministic_states: one_below_usize(bound),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&literal, operation, below_states)
            .expect("state proof refusal")
            .determinism()
            .subset(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::DeterministicStates,
            ..
        })
    ));
}

fn captured_concat(parts: usize) -> Hir {
    Hir::concat(
        (0..parts)
            .map(|index| {
                Hir::capture(Capture {
                    index: u32::try_from(index)
                        .expect("small capture index")
                        .checked_add(1)
                        .expect("positive small capture index"),
                    name: None,
                    sub: Box::new(Hir::literal(*b"a")),
                })
            })
            .collect(),
    )
}

fn oracle_concat(left: &[Vec<u8>], right: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for prefix in left {
        for suffix in right {
            let capacity = prefix
                .len()
                .checked_add(suffix.len())
                .expect("tiny oracle string length");
            let mut value = Vec::with_capacity(capacity);
            value.extend_from_slice(prefix);
            value.extend_from_slice(suffix);
            output.push(value);
        }
    }
    output
}

fn oracle_repeat(language: &[Vec<u8>], copies: u32) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new()];
    for _ in 0..copies {
        output = oracle_concat(&output, language);
    }
    output
}

fn oracle_finite(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(vec![Vec::new()]),
        HirKind::Literal(literal) => Some(vec![literal.0.to_vec()]),
        HirKind::Class(Class::Bytes(class)) => {
            let mut output = Vec::new();
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    output.push(vec![byte]);
                }
            }
            Some(output)
        }
        HirKind::Class(Class::Unicode(class)) => {
            let mut output = Vec::new();
            for range in class.ranges() {
                for scalar in u32::from(range.start())..=u32::from(range.end()) {
                    let Some(character) = char::from_u32(scalar) else {
                        continue;
                    };
                    let mut encoded = [0_u8; 4];
                    output.push(character.encode_utf8(&mut encoded).as_bytes().to_vec());
                    if output.len() > 64 {
                        return None;
                    }
                }
            }
            Some(output)
        }
        HirKind::Capture(capture) => oracle_finite(&capture.sub),
        HirKind::Concat(children) => {
            let mut output = vec![Vec::new()];
            for child in children {
                output = oracle_concat(&output, &oracle_finite(child)?);
            }
            Some(output)
        }
        HirKind::Alternation(children) => {
            let mut output = Vec::new();
            for child in children {
                output.extend(oracle_finite(child)?);
            }
            Some(output)
        }
        HirKind::Repetition(repetition) => {
            let maximum = repetition.max?;
            let language = oracle_finite(&repetition.sub)?;
            let mut output = Vec::new();
            if repetition.greedy {
                for copies in (repetition.min..=maximum).rev() {
                    output.extend(oracle_repeat(&language, copies));
                }
            } else {
                for copies in repetition.min..=maximum {
                    output.extend(oracle_repeat(&language, copies));
                }
            }
            Some(output)
        }
    }
}

#[test]
fn bounded_generated_tiny_hir_oracle_matches_complete_finite_fact() {
    let atoms = [
        Hir::empty(),
        Hir::fail(),
        Hir::literal(*b"a"),
        Hir::literal(*b"b"),
    ];
    let mut cases = atoms.to_vec();
    for left in &atoms {
        for right in &atoms {
            cases.push(Hir::concat(vec![left.clone(), right.clone()]));
            cases.push(Hir::alternation(vec![left.clone(), right.clone()]));
        }
    }
    for atom in &atoms {
        for (min, max, greedy) in [(0, 2, true), (0, 2, false), (1, 2, true)] {
            cases.push(Hir::repetition(Repetition {
                min,
                max: Some(max),
                greedy,
                sub: Box::new(atom.clone()),
            }));
        }
    }

    for hir in cases {
        let expected =
            oracle_finite(&hir).unwrap_or_else(|| panic!("generated case is finite: {hir:?}"));
        let actual = analyze_hir_facts(
            &hir,
            FactOperation::new(FactOutput::SpanSequence),
            FactLimits::default(),
        )
        .expect("generated case analyzes");
        let actual_strings = actual
            .finite_language()
            .as_proven()
            .unwrap_or_else(|| {
                panic!(
                    "generated finite case {hir:?} returned {:?}",
                    actual.finite_language()
                )
            })
            .strings()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        assert_eq!(actual_strings, expected, "{hir:?}");
    }
}

#[test]
fn fixed_shape_doubling_has_near_linear_actual_analysis_work() {
    let operation = FactOperation::new(FactOutput::Count);
    let small = analyze_hir_facts(&captured_concat(32), operation, FactLimits::default())
        .expect("small concat");
    let large = analyze_hir_facts(&captured_concat(64), operation, FactLimits::default())
        .expect("large concat");
    assert!(
        large.stats().work() <= small.stats().work() * 3,
        "small={}, large={}",
        small.stats().work(),
        large.stats().work()
    );
    assert_eq!(large.width().minimum(), Some(64));
}

#[test]
fn over_quota_finite_concat_becomes_an_optional_refusal_before_work_overflow() {
    let hir = Hir::concat(
        (0..80)
            .map(|_| Hir::alternation(vec![Hir::literal(*b"a"), Hir::literal(*b"b")]))
            .collect(),
    );
    let operation = FactOperation::new(FactOutput::Count);
    let baseline = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("over-quota finite concat remains a successful hard analysis");
    assert_eq!(
        baseline.width(),
        CheckedWidth::NonEmpty {
            minimum: 80,
            maximum: Some(80),
        }
    );
    assert!(matches!(
        baseline.finite_language(),
        FactProof::Refused(
            FactRefusal::Limit {
                resource: FactResource::FiniteStrings | FactResource::FiniteStringBytes,
                ..
            } | FactRefusal::ArithmeticOverflow { .. }
        )
    ));
    let exact = FactLimits {
        max_work: baseline.prospective().work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact).expect("exact over-quota concat work passes");
    let below = FactLimits {
        max_work: one_below_u64(baseline.prospective().work()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, below),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
}

#[test]
fn factored_alternation_census_bounds_the_strongest_nested_required_group() {
    let hir = parsed(r"(?:a(?:xx|yyy)|b(?:qq|rrrr))", false).hir;
    let report = analyze_hir_facts(
        &hir,
        FactOperation::capture_erased(FactOutput::SpanSum),
        FactLimits::default(),
    )
    .expect("factored required groups remain within their prospective envelope");
    assert_eq!(report.stats().required_groups(), 1);
    assert_eq!(report.stats().required_alternatives(), 4);
    assert_eq!(report.stats().required_bytes(), 11);
    assert!(report.stats().required_alternatives() <= report.prospective().required_alternatives());
    assert!(report.stats().required_bytes() <= report.prospective().required_bytes());
    assert!(report.stats().retained_bytes() <= report.prospective().retained_bytes());
}

#[test]
fn many_unicode_ranges_are_work_bounded_before_optional_materialization() {
    let ranges = (0_u32..5_000)
        .map(|index| {
            let scalar = index
                .checked_mul(2)
                .and_then(|offset| 0x1_0000_u32.checked_add(offset))
                .and_then(char::from_u32)
                .expect("valid scalar");
            ClassUnicodeRange::new(scalar, scalar)
        })
        .collect::<Vec<_>>();
    let hir = Hir::class(Class::Unicode(ClassUnicode::new(ranges)));
    let operation = FactOperation::new(FactOutput::Count);
    let baseline = analyze_hir_facts(&hir, operation, FactLimits::default())
        .expect("many-range class stays bounded");
    assert!(matches!(
        baseline.finite_language(),
        FactProof::Refused(FactRefusal::Limit {
            resource: FactResource::FiniteStrings,
            ..
        })
    ));
    let exact = FactLimits {
        max_work: baseline.prospective().work(),
        ..FactLimits::default()
    };
    analyze_hir_facts(&hir, operation, exact).expect("exact many-range work");
    let below = FactLimits {
        max_work: one_below_u64(baseline.prospective().work()),
        ..FactLimits::default()
    };
    assert!(matches!(
        analyze_hir_facts(&hir, operation, below),
        Err(FactError::ResourceLimit {
            resource: FactResource::Work,
            ..
        })
    ));
}

#[test]
fn reports_are_deterministic_for_identical_hir_operation_and_limits() {
    let hir = parsed(r"(?i:σ)(?:ab|ac){1,2}", true).hir;
    let operation = FactOperation::new(FactOutput::SpanSum);
    let first = analyze_hir_facts(&hir, operation, FactLimits::default()).expect("first report");
    let second = analyze_hir_facts(&hir, operation, FactLimits::default()).expect("second report");
    assert_eq!(first, second);
    assert_eq!(
        format!("{first:?}").as_bytes(),
        format!("{second:?}").as_bytes()
    );
}
