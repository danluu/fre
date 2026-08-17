use std::sync::Arc;

use fre_capture_lab::{
    CAPTURE_PROGRAM_V1_HEADER_BYTES, CaptureProgramV1, CaptureProgramV1Census,
    CaptureProgramV1Error, CaptureProgramV1Limits, CaptureProgramV1Resource, HistoryRegex,
    OnePassCaptureBuildLimits, OnePassCapturePlan, ProgramBuildOrigin, SearchLimits, Window,
    build_program_from_hir,
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

fn program(
    pattern: &str,
    unicode: bool,
    multi_line: bool,
    crlf: bool,
    line: u8,
) -> fre_capture_lab::Program {
    let hir = parse(pattern, unicode, multi_line, crlf, line);
    build_program_from_hir(
        &hir,
        line,
        fre_capture_lab::HirProgramBuildLimits::default(),
    )
    .expect("capture HIR build")
    .into_program()
}

#[test]
fn v1_roundtrip_is_deterministic_and_preserves_capture_execution() {
    struct Case {
        pattern: &'static str,
        unicode: bool,
        multi_line: bool,
        crlf: bool,
        line: u8,
        haystack: &'static [u8],
    }
    let cases = [
        Case {
            pattern: r"^(?P<_two9>(?P<item>a|[β-δ])+)(?P<optional>z)?$",
            unicode: true,
            multi_line: true,
            crlf: false,
            line: b'\n',
            haystack: "junk\naβδ\n".as_bytes(),
        },
        Case {
            pattern: r"^(?P<word>\b[a-z]+\b)$",
            unicode: false,
            multi_line: true,
            crlf: true,
            line: b'\n',
            haystack: b"9\r\nabc\r\n!",
        },
        Case {
            pattern: r"^(?P<raw>[\x80-\xFF]+)(?P<optional>x)?$",
            unicode: false,
            multi_line: true,
            crlf: false,
            line: b';',
            haystack: b"ascii;\x80\xff;tail",
        },
    ];

    for case in cases {
        let compiled = program(
            case.pattern,
            case.unicode,
            case.multi_line,
            case.crlf,
            case.line,
        );
        assert!(compiled.build_report_closes());
        let expected = HistoryRegex::from_program(Arc::new(compiled.clone()))
            .captures(
                case.haystack,
                Window::all(case.haystack),
                SearchLimits::default(),
            )
            .expect("original capture execution");
        let first = CaptureProgramV1::from_program(compiled, CaptureProgramV1Limits::default())
            .expect("seal V1");
        let second = CaptureProgramV1::from_program(
            program(
                case.pattern,
                case.unicode,
                case.multi_line,
                case.crlf,
                case.line,
            ),
            CaptureProgramV1Limits::default(),
        )
        .expect("repeat seal V1");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.semantic_digest(), second.semantic_digest());
        assert_eq!(
            CaptureProgramV1::serialized_len_from_header(
                &first.as_bytes()[..fre_capture_lab::CAPTURE_PROGRAM_V1_HEADER_BYTES],
                CaptureProgramV1Limits::default(),
            )
            .expect("header extent"),
            first.as_bytes().len()
        );

        let restored =
            CaptureProgramV1::deserialize(first.as_bytes(), CaptureProgramV1Limits::default())
                .expect("restore V1");
        assert_eq!(restored.as_bytes(), first.as_bytes());
        assert_eq!(restored.serialize().expect("copy V1"), first.as_bytes());
        assert!(restored.program().build_report_closes());
        assert!(matches!(
            restored.program().build_report().origin,
            ProgramBuildOrigin::CaptureProgramV1Restore { validation_work }
                if validation_work == restored.usage().validation_work
        ));
        let actual = HistoryRegex::from_program(Arc::new(restored.program().clone()))
            .captures(
                case.haystack,
                Window::all(case.haystack),
                SearchLimits::default(),
            )
            .expect("restored capture execution");
        assert_eq!(actual, expected, "pattern={:?}", case.pattern);
    }
}

#[test]
fn schema_explicitly_includes_group_zero_and_both_slots_per_group() {
    for (pattern, haystack, expected_groups, expected_slots) in [
        ("", b"x".as_slice(), 1, 2),
        ("(a)", b"za".as_slice(), 2, 4),
        ("(?P<_two9>a)(b)", b"zab".as_slice(), 3, 6),
    ] {
        let compiled = program(pattern, false, false, false, b'\n');
        let expected = HistoryRegex::from_program(Arc::new(compiled.clone()))
            .captures(haystack, Window::all(haystack), SearchLimits::default())
            .expect("original boundary execution");
        let artifact = CaptureProgramV1::from_program(compiled, CaptureProgramV1Limits::default())
            .expect("seal schema fixture");
        assert_eq!(artifact.schema().group_count(), expected_groups);
        assert_eq!(artifact.schema().user_group_count(), expected_groups - 1);
        assert_eq!(artifact.schema().slot_count(), expected_slots);
        assert_eq!(artifact.schema().group(0).expect("group zero").index(), 0);
        assert_eq!(artifact.schema().group(0).expect("group zero").name(), None);
        assert_eq!(
            artifact.program().build_report().captures,
            expected_groups - 1
        );
        assert_eq!(artifact.usage().groups, expected_groups);
        assert_eq!(artifact.usage().slots, expected_slots);
        let restored =
            CaptureProgramV1::deserialize(artifact.as_bytes(), CaptureProgramV1Limits::default())
                .expect("restore boundary fixture");
        assert!(restored.program().build_report_closes());
        let actual = HistoryRegex::from_program(Arc::new(restored.into_program()))
            .captures(haystack, Window::all(haystack), SearchLimits::default())
            .expect("restored boundary execution");
        assert_eq!(actual, expected);
    }
}

#[test]
fn restored_program_is_accepted_by_history_and_one_pass_planners() {
    let sealed = CaptureProgramV1::from_program(
        program(r"^(?P<_two9>ab+)(c)?$", false, false, false, b'\n'),
        CaptureProgramV1Limits::default(),
    )
    .expect("seal one-pass fixture");
    let restored =
        CaptureProgramV1::deserialize(sealed.as_bytes(), CaptureProgramV1Limits::default())
            .expect("restore one-pass fixture");
    assert!(restored.program().build_report_closes());
    let shared = Arc::new(restored.into_program());
    let history = HistoryRegex::from_program(Arc::clone(&shared));
    let history_outcome = history
        .captures(b"abbbc", Window::all(b"abbbc"), SearchLimits::default())
        .expect("history capture");
    let expected = history_outcome.captures.expect("history match");
    let span = expected.groups[0].span.expect("overall span");
    let plan = OnePassCapturePlan::try_from_program(shared, OnePassCaptureBuildLimits::default())
        .expect("restored program remains one-pass plannable");
    let mut workspace = plan
        .create_workspace(SearchLimits::default())
        .expect("one-pass workspace");
    let replay = plan
        .captures_exact(
            &mut workspace,
            b"abbbc",
            Window::all(b"abbbc"),
            span,
            SearchLimits::default(),
        )
        .expect("one-pass replay");
    assert_eq!(replay.captures, Some(expected));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all eight independent exact/one-below census and owned resource gates stay paired"
)]
fn every_v1_resource_ceiling_is_exact_and_one_below_refuses() {
    let artifact = CaptureProgramV1::from_program(
        program(
            r"(?P<_two9>[a-cx-z]+)(?P<other>q)?",
            false,
            false,
            false,
            b'\n',
        ),
        CaptureProgramV1Limits::default(),
    )
    .expect("resource fixture");
    let usage = artifact.usage();
    let exact = CaptureProgramV1Limits {
        max_serialized_bytes: usage.serialized_bytes,
        max_states: usage.states,
        max_byte_ranges: usage.byte_ranges,
        max_groups: usage.groups,
        max_slots: usage.slots,
        max_name_bytes: usage.name_bytes,
        max_validation_work: usage.validation_work,
        max_program_bytes: usage.program_bytes,
    };
    let required_scratch = CaptureProgramV1Census::scratch_words_from_header(
        &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
        exact,
    )
    .expect("exact census scratch");
    let mut scratch = vec![0_u32; required_scratch];
    CaptureProgramV1Census::from_wire(artifact.as_bytes(), exact, &mut scratch)
        .expect("all exact census limits");
    CaptureProgramV1::deserialize(artifact.as_bytes(), exact).expect("all exact limits");

    for (resource, required, limited) in [
        (
            CaptureProgramV1Resource::SerializedBytes,
            usage.serialized_bytes,
            CaptureProgramV1Limits {
                max_serialized_bytes: usage.serialized_bytes - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::States,
            usage.states,
            CaptureProgramV1Limits {
                max_states: usage.states - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::ByteRanges,
            usage.byte_ranges,
            CaptureProgramV1Limits {
                max_byte_ranges: usage.byte_ranges - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::Groups,
            usage.groups,
            CaptureProgramV1Limits {
                max_groups: usage.groups - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::Slots,
            usage.slots,
            CaptureProgramV1Limits {
                max_slots: usage.slots - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::NameBytes,
            usage.name_bytes,
            CaptureProgramV1Limits {
                max_name_bytes: usage.name_bytes - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::ValidationWork,
            usage.validation_work,
            CaptureProgramV1Limits {
                max_validation_work: usage.validation_work - 1,
                ..exact
            },
        ),
        (
            CaptureProgramV1Resource::ProgramBytes,
            usage.program_bytes,
            CaptureProgramV1Limits {
                max_program_bytes: usage.program_bytes - 1,
                ..exact
            },
        ),
    ] {
        let census_error =
            CaptureProgramV1Census::from_wire(artifact.as_bytes(), limited, &mut scratch)
                .expect_err("one-below census resource must refuse");
        let error = CaptureProgramV1::deserialize(artifact.as_bytes(), limited)
            .expect_err("one-below resource must refuse");
        assert_eq!(census_error, error);
        assert!(matches!(
            error,
            CaptureProgramV1Error::Resource {
                resource: actual,
                required: actual_required,
                limit,
            } if actual == resource && actual_required == required && limit == required - 1
        ));
    }
}
