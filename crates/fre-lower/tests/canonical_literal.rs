#![forbid(unsafe_code)]

use fre_lower::{
    CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION, CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
    CANONICAL_EXACT_LITERAL_MAX_NESTING, CanonicalExactLiteralCopyError,
    CanonicalExactLiteralError, CanonicalExactLiteralIdentity, CanonicalExactLiteralLimits,
    CanonicalExactLiteralResource, analyze_canonical_exact_literal,
};
use regex_syntax::{
    ParserBuilder,
    hir::{Capture, Hir, Look, Repetition},
};

fn parse(pattern: &str, utf8: bool) -> Hir {
    let mut builder = ParserBuilder::new();
    builder.utf8(utf8);
    builder.build().parse(pattern).expect("test pattern")
}

fn materialize(hir: &Hir) -> Option<(Vec<u8>, fre_lower::CanonicalExactLiteralStats)> {
    let proof = analyze_canonical_exact_literal(hir, CanonicalExactLiteralLimits::default())
        .expect("bounded test HIR")?;
    let mut bytes = vec![0; proof.literal_len()];
    proof.copy_into(&mut bytes).expect("exact destination");
    Some((bytes, proof.stats()))
}

fn assert_resource_limit(
    hir: &Hir,
    limits: CanonicalExactLiteralLimits,
    expected_resource: CanonicalExactLiteralResource,
    expected_needed: u64,
    expected_limit: u64,
) {
    match analyze_canonical_exact_literal(hir, limits) {
        Err(CanonicalExactLiteralError::ResourceLimit {
            resource,
            needed,
            limit,
        }) => assert_eq!(
            (expected_resource, expected_needed, expected_limit),
            (resource, needed, limit)
        ),
        other => panic!("expected resource limit, got {other:?}"),
    }
}

#[test]
fn canonical_literals_ignore_source_spelling_and_capture_placement() {
    let cases = [
        ("", b"".as_slice()),
        (r"a\x62c", b"abc".as_slice()),
        (r"\.", b".".as_slice()),
        (r"(?:a(?:b)c)", b"abc".as_slice()),
        (r"(?x:a b c)", b"abc".as_slice()),
        (r"[a]", b"a".as_slice()),
        (r"(a)b", b"ab".as_slice()),
        (r"a(b)c", b"abc".as_slice()),
        (r"(?P<outer>a(?P<inner>b)c)", b"abc".as_slice()),
        (r"a{3}", b"aaa".as_slice()),
        (r"(a){2}", b"aa".as_slice()),
        (r"(()a){3}", b"aaa".as_slice()),
    ];
    for (pattern, expected) in cases {
        assert_eq!(
            Some(expected),
            materialize(&parse(pattern, false))
                .as_ref()
                .map(|(bytes, _)| bytes.as_slice()),
            "pattern {pattern:?}"
        );
    }
}

#[test]
fn unicode_and_invalid_byte_literals_remain_opaque_exact_bytes() {
    let snowman = "☃".as_bytes();
    assert_eq!(
        Some(snowman),
        materialize(&parse("☃", true))
            .as_ref()
            .map(|(bytes, _)| bytes.as_slice())
    );
    assert_eq!(
        Some(snowman),
        materialize(&parse("☃", false))
            .as_ref()
            .map(|(bytes, _)| bytes.as_slice())
    );
    assert_eq!(
        Some(&[0xFF_u8][..]),
        materialize(&parse(r"(?-u:\xFF)", false))
            .as_ref()
            .map(|(bytes, _)| bytes.as_slice())
    );
}

#[test]
fn broader_language_or_context_nodes_decline_without_source_heuristics() {
    for pattern in [
        "[ab]",
        "a|b",
        "ab?",
        "a{2,3}",
        "^abc",
        r"(?i:a)",
        r"(?i-u:a)",
        r"\bword\b",
    ] {
        assert!(
            materialize(&parse(pattern, false)).is_none(),
            "pattern {pattern:?}"
        );
    }
}

#[test]
fn canonical_zero_repetition_erases_even_an_ineligible_dead_child() {
    let hir = Hir::repetition(Repetition {
        min: 0,
        max: Some(0),
        greedy: true,
        sub: Box::new(Hir::look(Look::Start)),
    });
    assert!(matches!(hir.kind(), regex_syntax::hir::HirKind::Empty));
    let (bytes, stats) = materialize(&hir).expect("canonical dead repetition is empty");
    assert!(bytes.is_empty());
    assert_eq!(1, stats.hir_nodes());
    assert_eq!(1, stats.expanded_hir_visits());
}

fn nested_repetition_with_empty_capture() -> Hir {
    let empty_capture = Hir::capture(Capture {
        index: 1,
        name: None,
        sub: Box::new(Hir::empty()),
    });
    let body = Hir::concat(vec![empty_capture, Hir::literal([b'a'])]);
    let inner = Hir::repetition(Repetition {
        min: 3,
        max: Some(3),
        greedy: true,
        sub: Box::new(body),
    });
    Hir::repetition(Repetition {
        min: 2,
        max: Some(2),
        greedy: false,
        sub: Box::new(inner),
    })
}

#[test]
fn nested_fixed_repetition_accounts_empty_capture_visits_before_copy() {
    let hir = nested_repetition_with_empty_capture();
    let proof = analyze_canonical_exact_literal(&hir, CanonicalExactLiteralLimits::default())
        .unwrap()
        .expect("exact fixed repetition");
    let stats = proof.stats();
    assert_eq!(CanonicalExactLiteralIdentity::current(), proof.identity());
    assert_eq!(proof.identity(), stats.identity());
    assert!(stats.identity().authenticates_current());
    assert_eq!(
        CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
        stats.identity().algorithm_version()
    );
    assert_eq!(
        CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION,
        stats.identity().accounting_version()
    );
    assert_eq!(6, stats.hir_nodes());
    assert_eq!(5, stats.max_nesting());
    assert_eq!(6, stats.literal_bytes());
    assert_eq!(27, stats.expanded_hir_visits());
    assert_eq!(6, stats.analysis_work());
    assert_eq!(33, stats.materialization_work());
    assert_eq!(39, stats.total_work());

    let mut bytes = [0; 6];
    proof.copy_into(&mut bytes).unwrap();
    assert_eq!(b"aaaaaa", &bytes);

    let limits = CanonicalExactLiteralLimits {
        max_work: stats.total_work() - 1,
        ..CanonicalExactLiteralLimits::default()
    };
    assert_resource_limit(
        &hir,
        limits,
        CanonicalExactLiteralResource::Work,
        stats.total_work(),
        stats.total_work() - 1,
    );
}

#[test]
fn every_structural_and_expansion_limit_has_a_typed_one_below_boundary() {
    let hir = nested_repetition_with_empty_capture();
    let defaults = CanonicalExactLiteralLimits::default();
    for (limits, resource, needed, limit) in [
        (
            CanonicalExactLiteralLimits {
                max_hir_nodes: 5,
                ..defaults
            },
            CanonicalExactLiteralResource::HirNodes,
            6,
            5,
        ),
        (
            CanonicalExactLiteralLimits {
                max_nesting: 4,
                ..defaults
            },
            CanonicalExactLiteralResource::Nesting,
            5,
            4,
        ),
        (
            CanonicalExactLiteralLimits {
                max_literal_bytes: 5,
                ..defaults
            },
            CanonicalExactLiteralResource::LiteralBytes,
            6,
            5,
        ),
    ] {
        assert_resource_limit(&hir, limits, resource, needed, limit);
    }
}

fn nested_captures(captures: usize) -> Hir {
    let mut hir = Hir::literal([b'x']);
    for index in 1..=captures {
        hir = Hir::capture(Capture {
            index: u32::try_from(index).expect("bounded test capture index"),
            name: None,
            sub: Box::new(hir),
        });
    }
    hir
}

#[test]
fn recursion_ceiling_accepts_boundary_and_types_deeper_custom_hir() {
    let at_limit = nested_captures(CANONICAL_EXACT_LITERAL_MAX_NESTING - 1);
    let proof = analyze_canonical_exact_literal(
        &at_limit,
        CanonicalExactLiteralLimits {
            max_nesting: usize::MAX,
            ..CanonicalExactLiteralLimits::default()
        },
    )
    .unwrap()
    .expect("hard nesting boundary");
    assert_eq!(
        CANONICAL_EXACT_LITERAL_MAX_NESTING,
        proof.stats().max_nesting()
    );

    let over_limit = nested_captures(CANONICAL_EXACT_LITERAL_MAX_NESTING);
    assert_resource_limit(
        &over_limit,
        CanonicalExactLiteralLimits {
            max_nesting: usize::MAX,
            ..CanonicalExactLiteralLimits::default()
        },
        CanonicalExactLiteralResource::Nesting,
        u64::try_from(CANONICAL_EXACT_LITERAL_MAX_NESTING + 1).unwrap(),
        u64::try_from(CANONICAL_EXACT_LITERAL_MAX_NESTING).unwrap(),
    );
}

#[test]
fn copy_length_failure_is_transactional() {
    let hir = parse("a(b)c", false);
    let proof = analyze_canonical_exact_literal(&hir, CanonicalExactLiteralLimits::default())
        .unwrap()
        .expect("exact captured concat");
    let mut short = [0xA5; 2];
    assert_eq!(
        Err(CanonicalExactLiteralCopyError::DestinationLength {
            needed: 3,
            actual: 2,
        }),
        proof.copy_into(&mut short)
    );
    assert_eq!([0xA5; 2], short);

    let mut long = [0x5A; 4];
    assert_eq!(
        Err(CanonicalExactLiteralCopyError::DestinationLength {
            needed: 3,
            actual: 4,
        }),
        proof.copy_into(&mut long)
    );
    assert_eq!([0x5A; 4], long);
}
