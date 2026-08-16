use std::sync::Arc;

use fre_capture_lab::{
    BuildError, HirBuildAccounting, HirBuildResource, HirProgramBuildError, HirProgramBuildLimits,
    HistoryRegex, ResourceKind, SearchLimits, Window, build_program_from_hir,
    build_program_from_hir_with_accounting,
};
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
