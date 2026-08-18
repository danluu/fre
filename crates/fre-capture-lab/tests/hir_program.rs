use std::sync::Arc;

use fre_capture_lab::{
    BuildError, CaptureGroupSlot, HirBuildAccounting, HirBuildResource, HirProgramBuildError,
    HirProgramBuildLimits, HistoryRegex, OnePassCaptureBuildLimits, OnePassCapturePlan,
    ResourceKind, SearchConfig, SearchLimits, Span, Window, build_program_from_hir,
    build_program_from_hir_with_accounting,
};
use regex_automata::{Anchored, Input, meta, util::syntax};
use regex_syntax::{ParserBuilder, hir::Hir};

fn parse(pattern: &str, unicode: bool, multi_line: bool, crlf: bool, line_terminator: u8) -> Hir {
    ParserBuilder::new()
        .utf8(false)
        .unicode(unicode)
        .multi_line(multi_line)
        .crlf(crlf)
        .line_terminator(line_terminator)
        .build()
        .parse(pattern)
        .expect("test HIR")
}

#[test]
fn direct_hir_build_preserves_named_nested_repeated_and_unmatched_groups() {
    let hir = parse(
        r"^(?P<outer>(?P<item>a|[β-δ])+)(?P<optional>z)?$",
        true,
        true,
        false,
        b'\n',
    );
    let built = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("direct HIR build");
    assert_eq!(built.report().hir.capture_slots, 3);
    assert_eq!(built.report().program.captures, 3);

    let engine = HistoryRegex::from_program(Arc::new(built.into_program()));
    let haystack = "junk\naβδ\n".as_bytes();
    let outcome = engine
        .captures(haystack, Window::all(haystack), SearchLimits::default())
        .expect("capture search");
    let groups = &outcome.captures.expect("one line match").groups;
    assert_eq!(groups.len(), 4);
    assert_eq!((groups[0].index, groups[0].name.as_deref()), (0, None));
    assert_eq!(
        (groups[1].index, groups[1].name.as_deref()),
        (1, Some("outer"))
    );
    assert_eq!(
        (groups[2].index, groups[2].name.as_deref()),
        (2, Some("item"))
    );
    assert_eq!(
        (groups[3].index, groups[3].name.as_deref()),
        (3, Some("optional"))
    );
    assert_eq!(
        groups[0].span,
        Some(fre_capture_lab::Span { start: 5, end: 10 })
    );
    assert_eq!(groups[1].span, groups[0].span);
    // A repeated capture retains the final participating iteration.
    assert_eq!(
        groups[2].span,
        Some(fre_capture_lab::Span { start: 8, end: 10 })
    );
    assert_eq!(groups[3].span, None);
}

#[test]
fn hir_build_returns_an_atomic_opaque_first_byte_proof() {
    const ASCII_ALPHA_WORDS: [u64; 4] = [
        0,
        (((1_u64 << 26) - 1) << 1) | (((1_u64 << 26) - 1) << 33),
        0,
        0,
    ];

    let hir = parse(r"[A-Za-z]+", false, false, false, b'\n');
    let built = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("ASCII alphabetic HIR build");
    let report_before = built.report().clone();
    let (program, report, proof) = built.into_parts_with_first_byte_proof();
    assert_eq!(report, report_before);
    assert_eq!(program.build_report(), &report.program);
    assert!(proof.equals_nonnullable_words(ASCII_ALPHA_WORDS));

    let nullable = parse(r"[A-Za-z]*", false, false, false, b'\n');
    let nullable = build_program_from_hir(&nullable, b'\n', HirProgramBuildLimits::default())
        .expect("nullable ASCII alphabetic HIR build");
    let (_, _, proof) = nullable.into_parts_with_first_byte_proof();
    assert!(!proof.equals_nonnullable_words(ASCII_ALPHA_WORDS));
}

#[test]
fn direct_hir_build_preserves_custom_line_assertions_and_invalid_bytes() {
    let hir = parse(
        r"^(?P<raw>[\x80-\xFF]+)(?P<optional>x)?$",
        false,
        true,
        false,
        b';',
    );
    let built = build_program_from_hir(&hir, b';', HirProgramBuildLimits::default())
        .expect("direct byte HIR build");
    let engine = HistoryRegex::from_program(Arc::new(built.into_program()));
    let haystack = b"ascii;\x80\xff;tail";
    let outcome = engine
        .captures(haystack, Window::all(haystack), SearchLimits::default())
        .expect("invalid-byte capture search");
    let groups = &outcome.captures.expect("custom-line match").groups;
    assert_eq!(
        groups[0].span,
        Some(fre_capture_lab::Span { start: 6, end: 8 })
    );
    assert_eq!(groups[1].span, groups[0].span);
    assert_eq!(groups[2].span, None);
}

#[test]
fn direct_hir_build_preserves_crlf_and_word_assertions() {
    let hir = parse(r"^(?P<word>\b[a-z]+\b)$", false, true, true, b'\n');
    let built = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("direct CRLF HIR build");
    let engine = HistoryRegex::from_program(Arc::new(built.into_program()));
    let haystack = b"9\r\nabc\r\n!";
    let outcome = engine
        .captures(haystack, Window::all(haystack), SearchLimits::default())
        .expect("CRLF capture search");
    let groups = &outcome.captures.expect("CRLF line match").groups;
    assert_eq!(
        groups[0].span,
        Some(fre_capture_lab::Span { start: 3, end: 6 })
    );
    assert_eq!(groups[1].span, groups[0].span);
}

#[test]
fn direct_hir_build_is_exactly_bounded_and_continues_an_outer_ledger() {
    let hir = parse(r"(?P<name>[a-c]+)([β-δ])?", true, false, false, b'\n');
    let baseline = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("baseline HIR build");
    let exact = baseline.report().clone();

    let exact_limits = HirProgramBuildLimits {
        max_hir_work: exact.hir.work,
        max_hir_depth: exact.hir.hir_depth,
        ..HirProgramBuildLimits::default()
    };
    let rebuilt = build_program_from_hir(&hir, b'\n', exact_limits).expect("exact limits");
    assert_eq!(rebuilt.report(), baseline.report());
    assert_eq!(rebuilt.program(), baseline.program());

    let one_below_work = exact.hir.work.checked_sub(1).expect("positive HIR work");
    let work_error = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            max_hir_work: one_below_work,
            ..exact_limits
        },
    )
    .expect_err("one-below HIR work");
    assert!(matches!(
        work_error,
        HirProgramBuildError::Resource {
            resource: HirBuildResource::Work,
            required,
            limit,
        } if required > limit && limit == one_below_work
    ));

    let one_below_depth = exact
        .hir
        .hir_depth
        .checked_sub(1)
        .expect("positive HIR depth");
    let depth_error = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            max_hir_depth: one_below_depth,
            ..exact_limits
        },
    )
    .expect_err("one-below HIR depth");
    assert!(matches!(
        depth_error,
        HirProgramBuildError::Resource {
            resource: HirBuildResource::Depth,
            required,
            limit,
        } if required > limit && limit == one_below_depth
    ));

    let initial = HirBuildAccounting {
        work: 17,
        ..HirBuildAccounting::default()
    };
    let continued_work = exact
        .hir
        .work
        .checked_add(initial.work)
        .expect("continued HIR work");
    let continued = build_program_from_hir_with_accounting(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            max_hir_work: continued_work,
            ..exact_limits
        },
        initial,
    )
    .expect("continued outer ledger");
    assert_eq!(continued.report().hir.work, continued_work);
    assert_eq!(continued.report().hir.hir_nodes, exact.hir.hir_nodes);
    assert_eq!(continued.program(), baseline.program());

    let one_below_captures = exact
        .program
        .captures
        .checked_sub(1)
        .expect("positive capture count");
    let program_error = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            program: fre_capture_lab::BuildLimits {
                max_captures: one_below_captures,
                ..fre_capture_lab::BuildLimits::default()
            },
            ..HirProgramBuildLimits::default()
        },
    )
    .expect_err("capture program limit");
    assert!(matches!(
        program_error,
        HirProgramBuildError::Program(BuildError::Resource {
            kind: ResourceKind::Captures,
            required,
            limit,
        }) if required > limit && limit == one_below_captures
    ));
}

#[test]
fn direct_hir_build_rejects_hostile_initial_ledgers_before_lowering() {
    let hir = parse("", false, false, false, b'\n');
    let limits = HirProgramBuildLimits {
        max_hir_work: 8,
        max_hir_depth: 4,
        program: fre_capture_lab::BuildLimits {
            max_captures: 3,
            ..fre_capture_lab::BuildLimits::default()
        },
    };
    let cases = [
        (
            HirBuildAccounting {
                work: 9,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::Work,
            9,
            8,
        ),
        (
            HirBuildAccounting {
                hir_depth: 5,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::Depth,
            5,
            4,
        ),
        (
            HirBuildAccounting {
                hir_nodes: 9,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::Nodes,
            9,
            8,
        ),
        (
            HirBuildAccounting {
                literal_bytes: 9,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::LiteralBytes,
            9,
            8,
        ),
        (
            HirBuildAccounting {
                class_ranges: 9,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::ClassRanges,
            9,
            8,
        ),
        (
            HirBuildAccounting {
                capture_slots: 4,
                ..HirBuildAccounting::default()
            },
            HirBuildResource::CaptureSlots,
            4,
            3,
        ),
    ];

    for (accounting, resource, required, limit) in cases {
        let error = build_program_from_hir_with_accounting(&hir, b'\n', limits, accounting)
            .expect_err("hostile initial ledger");
        assert_eq!(
            error,
            HirProgramBuildError::Resource {
                resource,
                required,
                limit,
            }
        );
    }
}

#[test]
fn initial_capture_slots_are_authenticated_against_the_same_hir_schema() {
    let captured = parse("(a)", false, false, false, b'\n');
    let initial = HirBuildAccounting {
        capture_slots: 1,
        ..HirBuildAccounting::default()
    };
    let built = build_program_from_hir_with_accounting(
        &captured,
        b'\n',
        HirProgramBuildLimits::default(),
        initial,
    )
    .expect("matching initial capture schema");
    assert_eq!(built.report().hir.capture_slots, 1);
    assert_eq!(built.report().program.captures, 1);

    let empty = parse("", false, false, false, b'\n');
    let error = build_program_from_hir_with_accounting(
        &empty,
        b'\n',
        HirProgramBuildLimits::default(),
        initial,
    )
    .expect_err("mismatched initial capture schema");
    assert_eq!(
        error,
        HirProgramBuildError::InternalInvariant("capture compiler schema differs from parsed HIR")
    );
}

fn assert_unicode_onepass_matches_history_and_rust(pattern: &str, haystacks: &[&[u8]]) {
    let hir = parse(pattern, true, false, false, b'\n');
    let built = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .unwrap_or_else(|error| {
            panic!("compact Unicode HIR build failed for {pattern:?}: {error}")
        });
    let program = Arc::new(built.into_program());
    let history = HistoryRegex::from_program(Arc::clone(&program));
    let onepass =
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .unwrap_or_else(|error| panic!("one-pass build failed for {pattern:?}: {error}"));
    let reference = meta::Regex::builder()
        .configure(meta::Regex::config().utf8_empty(false))
        .syntax(syntax::Config::default().utf8(false))
        .build(pattern)
        .unwrap_or_else(|error| panic!("Rust build failed for {pattern:?}: {error}"));
    let mut workspace = onepass
        .create_search_workspace(SearchLimits::default())
        .expect("one-pass Unicode search workspace");
    let mut groups = vec![CaptureGroupSlot::UNMATCHED; history.program().group_len()];

    for &haystack in haystacks {
        let window = Window::all(haystack);
        let expected = history
            .captures_from_with_config(
                haystack,
                window,
                0,
                SearchConfig::LEFTMOST.anchored(true),
                SearchLimits::default(),
            )
            .unwrap_or_else(|error| panic!("History failed for {pattern:?}/{haystack:?}: {error}"));
        let got = onepass
            .captures_anchored_slots(
                &mut workspace,
                haystack,
                window,
                0,
                &mut groups,
                SearchLimits::default(),
            )
            .unwrap_or_else(|error| {
                panic!("one-pass failed for {pattern:?}/{haystack:?}: {error}")
            });
        let mut rust = reference.create_captures();
        reference.captures(
            Input::new(haystack)
                .span(0..haystack.len())
                .anchored(Anchored::Yes),
            &mut rust,
        );
        assert_eq!(got.matched, rust.is_match(), "{pattern:?}/{haystack:?}");
        assert_eq!(got.matched, expected.captures.is_some());
        if got.matched {
            let expected = expected.captures.expect("History matched capture record");
            assert_eq!(groups.len(), rust.group_len());
            assert_eq!(groups.len(), expected.groups.len());
            for (index, (slot, group)) in groups.iter().zip(expected.groups).enumerate() {
                let rust_span = rust.get_group(index).map(|matched| Span {
                    start: matched.start,
                    end: matched.end,
                });
                assert_eq!(slot.span(), rust_span, "{pattern:?}/{haystack:?}/g{index}");
                assert_eq!(slot.span(), group.span);
            }
        } else {
            assert!(
                groups
                    .iter()
                    .all(|slot| *slot == CaptureGroupSlot::UNMATCHED)
            );
        }
    }
}

#[test]
fn unicode_prefix_radix_reduces_exact_shared_prefix_shape() {
    let hir = parse(r"[\u{100}\u{102}]", true, false, false, b'\n');
    let first = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("compact Unicode HIR build");
    let second = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("deterministic compact Unicode HIR build");

    // U+0100 and U+0102 encode as C4 80 and C4 82. The flat product has four
    // byte states and seven AST nodes; the radix form shares C4 and has three
    // byte states and five AST nodes. Group-zero framing contributes three
    // additional states to both shapes.
    assert_eq!(first.report().hir.work, 9);
    assert_eq!(first.report().hir.class_ranges, 4);
    assert_eq!(first.report().program.ast_nodes, 5);
    assert_eq!(first.report().program.ast_depth, 3);
    assert_eq!(first.report().program.states, 7);
    assert_eq!(second.report(), first.report());
    assert_eq!(second.program(), first.program());
    OnePassCapturePlan::try_from_program(
        Arc::new(first.into_program()),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("factored Unicode class is one-pass");
}

#[test]
fn unicode_prefix_radix_preserves_flat_depth_fallback_and_exact_gates() {
    let hir = parse(r"[\u{100}\u{102}]", true, false, false, b'\n');
    let compact = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            program: fre_capture_lab::BuildLimits {
                max_ast_depth: 8,
                ..fre_capture_lab::BuildLimits::default()
            },
            ..HirProgramBuildLimits::default()
        },
    )
    .expect("exact compact-depth admission");
    let compact_report = compact.report().clone();
    assert_eq!(compact_report.program.states, 7);

    let flat = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            program: fre_capture_lab::BuildLimits {
                max_ast_depth: 7,
                ..fre_capture_lab::BuildLimits::default()
            },
            ..HirProgramBuildLimits::default()
        },
    )
    .expect("one-below compact depth retains flat lowering");
    assert_eq!(flat.report().hir, compact_report.hir);
    assert_eq!(flat.report().program.ast_nodes, 7);
    assert_eq!(flat.report().program.ast_depth, 3);
    assert_eq!(flat.report().program.states, 8);

    let exact_program = fre_capture_lab::BuildLimits {
        max_ast_nodes: compact_report.program.ast_nodes,
        max_ast_depth: 8,
        max_states: compact_report.program.states,
        max_patch_entries: compact_report.program.patch_entries,
        max_compile_work: compact_report.program.compile_work,
        max_program_bytes: compact_report.program.program_bytes,
        ..fre_capture_lab::BuildLimits::default()
    };
    let exact = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            max_hir_work: compact_report.hir.work,
            program: exact_program,
            ..HirProgramBuildLimits::default()
        },
    )
    .expect("all exact compact construction gates");
    assert_eq!(exact.report(), &compact_report);

    let cases = [
        (
            ResourceKind::AstNodes,
            fre_capture_lab::BuildLimits {
                max_ast_nodes: exact_program.max_ast_nodes - 1,
                ..exact_program
            },
        ),
        (
            ResourceKind::States,
            fre_capture_lab::BuildLimits {
                max_states: exact_program.max_states - 1,
                ..exact_program
            },
        ),
        (
            ResourceKind::PatchEntries,
            fre_capture_lab::BuildLimits {
                max_patch_entries: exact_program.max_patch_entries - 1,
                ..exact_program
            },
        ),
        (
            ResourceKind::CompileWork,
            fre_capture_lab::BuildLimits {
                max_compile_work: exact_program.max_compile_work - 1,
                ..exact_program
            },
        ),
        (
            ResourceKind::ProgramBytes,
            fre_capture_lab::BuildLimits {
                max_program_bytes: exact_program.max_program_bytes - 1,
                ..exact_program
            },
        ),
    ];
    for (kind, program) in cases {
        let error = build_program_from_hir(
            &hir,
            b'\n',
            HirProgramBuildLimits {
                max_hir_work: compact_report.hir.work,
                program,
                ..HirProgramBuildLimits::default()
            },
        )
        .expect_err("one-below compact Program gate");
        assert!(matches!(
            error,
            HirProgramBuildError::Program(BuildError::Resource {
                kind: actual,
                required,
                limit,
            }) if actual == kind && required > limit
        ));
    }

    let one_below_hir = build_program_from_hir(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            max_hir_work: compact_report.hir.work - 1,
            program: exact_program,
            ..HirProgramBuildLimits::default()
        },
    )
    .expect_err("one-below Unicode HIR work");
    assert!(matches!(
        one_below_hir,
        HirProgramBuildError::Resource {
            resource: HirBuildResource::Work,
            required,
            limit,
        } if required == limit + 1
    ));
}

#[test]
fn unicode_prefix_radix_preserves_class_range_first_crossing_from_outer_ledger() {
    let hir = parse(r"[\u{100}-\u{101}]", true, false, false, b'\n');
    let error = build_program_from_hir_with_accounting(
        &hir,
        b'\n',
        HirProgramBuildLimits {
            // The HIR work is exactly 1 node + 1 scalar range + 1 sequence +
            // 2 byte tokens. The initial class ledger leaves room for only
            // the first byte token, independently pinning the second token's
            // exact ClassRanges refusal.
            max_hir_work: 5,
            ..HirProgramBuildLimits::default()
        },
        HirBuildAccounting {
            class_ranges: 4,
            ..HirBuildAccounting::default()
        },
    )
    .expect_err("second UTF-8 token must cross the class-range ceiling");
    assert_eq!(
        error,
        HirProgramBuildError::Resource {
            resource: HirBuildResource::ClassRanges,
            required: 6,
            limit: 5,
        }
    );
}

#[test]
fn compact_unicode_onepass_matches_rust_across_boundaries_and_malformed_utf8() {
    let malformed = [
        0xFF, b'a', 0x80, 0xC0, 0x80, b' ', 0xED, 0xA0, 0x80, b'_', 0xF4, 0x90, 0x80, 0x80,
    ];
    let truncated = [0x7F, 0xC2, b' ', 0xE0, 0xA0, b' ', 0xF0, 0x90, 0x80];
    let common_negatives = [
        b"".as_slice(),
        b"ASCII words_123".as_slice(),
        "αβ ЖЮ 東京".as_bytes(),
        malformed.as_slice(),
        truncated.as_slice(),
    ];
    let exact_members = [
        "Ā".as_bytes(),
        "Ă".as_bytes(),
        "ĀĂĀ".as_bytes(),
        common_negatives[0],
        common_negatives[1],
        common_negatives[3],
        common_negatives[4],
    ];
    assert_unicode_onepass_matches_history_and_rust(r"^([\u{100}\u{102}]+)$", &exact_members);

    let mixed_scripts = [
        "αβ".as_bytes(),
        "ЖЮ".as_bytes(),
        "𐀀𐀄".as_bytes(),
        common_negatives[0],
        common_negatives[1],
        common_negatives[3],
        common_negatives[4],
    ];
    assert_unicode_onepass_matches_history_and_rust(
        r"^([\p{Greek}\p{Cyrillic}\u{10000}-\u{10004}]+)$",
        &mixed_scripts,
    );

    let non_ascii = [
        "Ā".as_bytes(),
        "😀".as_bytes(),
        "αЖ".as_bytes(),
        common_negatives[0],
        common_negatives[1],
        common_negatives[3],
        common_negatives[4],
    ];
    assert_unicode_onepass_matches_history_and_rust(r"^([^\p{ASCII}]{1,2})$", &non_ascii);

    for scalar in [
        "\u{7F}",
        "\u{80}",
        "\u{7FF}",
        "\u{800}",
        "\u{D7FF}",
        "\u{E000}",
        "\u{FFFF}",
        "\u{10000}",
        "\u{10FFFF}",
    ] {
        assert_unicode_onepass_matches_history_and_rust(
            r"^([\u{7F}-\u{80}\u{7FF}-\u{800}\u{D7FF}\u{E000}\u{FFFF}-\u{10000}\u{10FFFF}])$",
            &[
                scalar.as_bytes(),
                malformed.as_slice(),
                truncated.as_slice(),
            ],
        );
    }

    let russian = "абвгдежзи ".as_bytes();
    let target_inputs = [
        russian,
        "abcdefghi ".as_bytes(),
        "αβγδεζηθι ".as_bytes(),
        b"abcdefgh\xff ".as_slice(),
        b"abcdefgh\xe2\x82 ".as_slice(),
        b"abcdefgh_ ".as_slice(),
    ];
    assert_unicode_onepass_matches_history_and_rust(r"^(\S{8})(\S)\b", &target_inputs);
}
