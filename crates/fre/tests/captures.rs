use core::mem::size_of;
use std::sync::Arc;

use fre::{
    CaptureAggregateLimits, CaptureBuildError, CaptureBuildLimits, CaptureBuilder,
    CaptureExecutionSource, CaptureRequiredLiteralBuildError, CaptureRequiredLiteralBuildLimits,
    CaptureRequiredLiteralRunLimits, CaptureResource, CaptureRunLimits, CaptureSearchError,
    CaptureSearchLimits, LineCaptureBuildError, LineCaptureBuildLimits, LineCaptureBuildResource,
    LineCaptureBuilder, LineCaptureConfiguration, LineCapturePlanKind, LineCaptureResource,
    LineCaptureRunError, LineCaptureRunLimits, PortableTextCaptureBuilder, SHEBANG_CAPTURE_PATTERN,
    SHEBANG_INSPECTION_WORK, SHEBANG_OPERATION_ID, SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
    SPACE_AROUND_OPERATOR_INSPECTION_WORK, STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
    STRING_QUOTE_PREFIX_INSPECTION_WORK, STRING_QUOTE_PREFIX_OPERATION_ID,
    WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN, WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
    WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
};
use regex::RegexBuilder as TextRegexBuilder;
use regex::bytes::RegexBuilder;

type GroupFixture = (u32, Option<String>, Option<(usize, usize)>);
type CaptureFixture = Vec<GroupFixture>;

fn reference_count(pattern: &str, haystack: &[u8]) -> usize {
    let regex = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("reference pattern");
    regex
        .captures_iter(haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum()
}

fn assert_count(pattern: &str, haystack: &[u8]) {
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("capture build");
    let result = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("capture reduction");
    assert_eq!(result.accounting.count, reference_count(pattern, haystack));
    assert_eq!(
        result.identity.plan,
        regex.cache_identity(CaptureRunLimits::default()).plan
    );
}

fn space_operator_plan() -> fre::LineCapturePlan {
    line_capture_plan(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN)
}

fn line_capture_plan(pattern: &str) -> fre::LineCapturePlan {
    LineCaptureBuilder::new(pattern)
        .profile(fre::RustProfile::rebar_1_12_4())
        .build()
        .expect("exact direct line-capture plan")
}

fn reference_grep_capture_count(pattern: &str, haystack: &[u8]) -> usize {
    let reference = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("reference grep-capture pattern");
    if haystack.is_empty() {
        return 0;
    }
    let mut count = 0_usize;
    let mut start = 0_usize;
    while start < haystack.len() {
        let terminator = haystack[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start.checked_add(offset).expect("line terminator offset"));
        let end = terminator.unwrap_or(haystack.len());
        let mut line = &haystack[start..end];
        if terminator.is_some() && line.last() == Some(&b'\r') {
            line = &line[..line.len().checked_sub(1).expect("nonempty CR line")];
        }
        for captures in reference.captures_iter(line) {
            count = count
                .checked_add(captures.iter().flatten().count())
                .expect("reference capture count");
        }
        let Some(terminator) = terminator else {
            break;
        };
        start = terminator.checked_add(1).expect("line start");
    }
    count
}

#[test]
fn space_around_operator_direct_plan_authenticates_exact_hir_and_inspection_limit() {
    let plan = space_operator_plan();
    let report = plan.build_report();
    assert_eq!(
        report.identity.plan,
        LineCapturePlanKind::SpaceAroundOperator
    );
    assert_eq!(report.hir_nodes, 12);
    assert_eq!(report.class_ranges, 40);
    assert_eq!(report.literal_bytes, 2);
    assert_eq!(
        report.inspection_work,
        SPACE_AROUND_OPERATOR_INSPECTION_WORK
    );
    assert_eq!(report.minimum_match_bytes, 2);
    assert_eq!(report.participating_groups_per_match, 3);
    assert_eq!(report.allocations, 0);
    assert_eq!(report.scratch_bytes, 0);
    assert_eq!(report.persistent_bytes, size_of::<fre::LineCapturePlan>());
    assert_eq!(report.peak_bytes, size_of::<fre::LineCapturePlan>());
    assert_eq!(
        report.identity.source,
        SPACE_AROUND_OPERATOR_CAPTURE_PATTERN
    );
    assert_eq!(report.identity.profile, fre::RustProfile::rebar_1_12_4());

    let one_below = LineCaptureBuildLimits {
        max_inspection_work: SPACE_AROUND_OPERATOR_INSPECTION_WORK - 1,
        ..LineCaptureBuildLimits::default()
    };
    assert!(matches!(
        LineCaptureBuilder::new(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN)
            .profile(fre::RustProfile::rebar_1_12_4())
            .limits(one_below)
            .build(),
        Err(LineCaptureBuildError::InspectionWork {
            required: SPACE_AROUND_OPERATOR_INSPECTION_WORK,
            limit
        }) if limit == SPACE_AROUND_OPERATOR_INSPECTION_WORK - 1
    ));
    assert!(matches!(
        LineCaptureBuilder::new(r"[^,\s](\s*)[-+](\s*)$")
            .profile(fre::RustProfile::rebar_1_12_4())
            .build(),
        Err(LineCaptureBuildError::Unsupported(_))
    ));

    let plan_bytes = size_of::<fre::LineCapturePlan>();
    for (resource, limits) in [
        (
            LineCaptureBuildResource::PersistentBytes,
            LineCaptureBuildLimits {
                max_persistent_bytes: plan_bytes.checked_sub(1).expect("nonempty plan"),
                ..LineCaptureBuildLimits::default()
            },
        ),
        (
            LineCaptureBuildResource::PeakBytes,
            LineCaptureBuildLimits {
                max_peak_bytes: plan_bytes.checked_sub(1).expect("nonempty plan"),
                ..LineCaptureBuildLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            LineCaptureBuilder::new(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN)
                .profile(fre::RustProfile::rebar_1_12_4())
                .limits(limits)
                .build(),
            Err(LineCaptureBuildError::Resource {
                resource: got,
                required,
                limit,
            }) if got == resource
                && required == plan_bytes
                && Some(limit) == required.checked_sub(1)
        ));
    }
}

#[test]
fn space_around_operator_direct_plan_matches_empty_unicode_malformed_crlf_and_overlap_oracles() {
    let plan = space_operator_plan();
    let cases: &[&[u8]] = &[
        b"",
        b"\n",
        b"\n\n",
        b"x+",
        b"x + ",
        b"++",
        b"+++",
        b"x+b+c",
        b"x:+",
        b"x:=",
        b":=",
        b"x:==",
        b"x:=++",
        b"x::=",
        b"x::+",
        b"x: =",
        b",+",
        b",++",
        b" +",
        b"x+ y+",
        b"a b+",
        "a\u{2003}b+".as_bytes(),
        b"a++b+",
        b"a:=b+",
        b"x+=",
        b"x+\r\n",
        b"x+\r",
        b"x+\r\r\n",
        b"\xFFx+",
        b"x \xFF+",
        "雪\u{2003}+\u{3000}".as_bytes(),
        "\u{2003}+".as_bytes(),
        b"x+\n\xFF++\r\n,+\nx + ",
    ];
    for haystack in cases {
        let expected =
            reference_grep_capture_count(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN, haystack);
        let actual = plan
            .grep_capture_count(haystack, LineCaptureRunLimits::default())
            .unwrap_or_else(|error| panic!("haystack={haystack:?}: {error}"));
        assert_eq!(actual.capture_count, expected, "haystack={haystack:?}");
        assert_eq!(actual.actual_input_loads, haystack.len());
        assert!(actual.capture_count <= actual.prospective_capture_count);
        assert!(actual.reducer_events <= actual.prospective_reducer_events);
        assert_eq!(actual.scratch_bytes, 0);
        assert_eq!(actual.output_bytes, 0);
    }
}

#[test]
fn space_around_operator_direct_plan_small_alphabet_is_exact() {
    let plan = space_operator_plan();
    let tokens: &[&[u8]] = &[
        b"a",
        b",",
        b" ",
        b"\t",
        b"\r",
        b"\n",
        b":",
        b"=",
        b"+",
        b"!",
        "é".as_bytes(),
        "\u{2003}".as_bytes(),
        b"\xFF",
    ];
    let mut haystacks = vec![Vec::<u8>::new()];
    for _ in 0..4 {
        let previous = haystacks.clone();
        for prefix in previous {
            for token in tokens {
                let mut value = prefix.clone();
                value.extend_from_slice(token);
                haystacks.push(value);
            }
        }
    }
    for haystack in haystacks {
        let expected =
            reference_grep_capture_count(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN, &haystack);
        let actual = plan
            .grep_capture_count(&haystack, LineCaptureRunLimits::default())
            .unwrap_or_else(|error| panic!("haystack={haystack:?}: {error}"));
        assert_eq!(actual.capture_count, expected, "haystack={haystack:?}");
        assert_eq!(actual.actual_input_loads, haystack.len());
    }
}

fn assert_space_operator_single_load_case(plan: &fre::LineCapturePlan, haystack: &[u8]) {
    let expected = reference_grep_capture_count(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN, haystack);
    let baseline = plan
        .grep_capture_count(haystack, LineCaptureRunLimits::default())
        .unwrap_or_else(|error| panic!("haystack={haystack:?}: {error}"));
    assert_eq!(baseline.capture_count, expected, "haystack={haystack:?}");
    assert_eq!(baseline.sequential_bytes, haystack.len());
    assert_eq!(baseline.actual_input_loads, haystack.len());

    let exact = LineCaptureRunLimits {
        max_work: baseline.work,
        max_sequential_bytes: baseline.sequential_bytes,
        max_capture_count: baseline.prospective_capture_count,
        max_reducer_events: baseline.prospective_reducer_events,
    };
    let report = plan
        .grep_capture_count(haystack, exact)
        .unwrap_or_else(|error| panic!("exact haystack={haystack:?}: {error}"));
    assert_eq!(report, baseline, "exact haystack={haystack:?}");

    let one_below = [
        (
            LineCaptureResource::ExecutionWork,
            LineCaptureRunLimits {
                max_work: exact.max_work.checked_sub(1).expect("positive work"),
                ..exact
            },
        ),
        (
            LineCaptureResource::SequentialBytes,
            LineCaptureRunLimits {
                max_sequential_bytes: exact
                    .max_sequential_bytes
                    .checked_sub(1)
                    .expect("nonempty input"),
                ..exact
            },
        ),
        (
            LineCaptureResource::ReducerEvents,
            LineCaptureRunLimits {
                max_reducer_events: exact
                    .max_reducer_events
                    .checked_sub(1)
                    .expect("positive reducer bound"),
                ..exact
            },
        ),
    ];
    for (resource, limits) in one_below {
        assert!(matches!(
            plan.grep_capture_count(haystack, limits),
            Err(LineCaptureRunError::Resource { resource: got, .. }) if got == resource
        ));
    }
    if exact.max_capture_count > 0 {
        let one_below_capture = LineCaptureRunLimits {
            max_capture_count: exact
                .max_capture_count
                .checked_sub(1)
                .expect("positive capture bound"),
            ..exact
        };
        assert!(matches!(
            plan.grep_capture_count(haystack, one_below_capture),
            Err(LineCaptureRunError::Resource {
                resource: LineCaptureResource::CaptureCount,
                required,
                limit,
            }) if required == exact.max_capture_count
                && Some(limit) == required.checked_sub(1)
        ));
    }
}

#[test]
fn space_around_operator_stream_loads_each_valid_malformed_and_cr_byte_once() {
    let plan = space_operator_plan();
    let cases: &[&[u8]] = &[
        b"\ra",
        b"\r\n",
        b"\r\r\n",
        b"\xC2\xA0x+",
        b"\xE2\x80\x83x+",
        b"\xF0\x9F\x92\xA9x+",
        b"\xC2+",
        b"\xE2+",
        b"\xE2\x82+",
        b"\xF0+",
        b"\xF0\x9F+",
        b"\xF0\x9F\x92+",
        b"\xC2",
        b"\xE2",
        b"\xE2\x82",
        b"\xF0",
        b"\xF0\x9F",
        b"\xF0\x9F\x92",
        b"\xC2\r\n",
        b"\xE2\r\n",
        b"\xE2\x82\r\n",
        b"\xF0\r\n",
        b"\xF0\x9F\r\n",
        b"\xF0\x9F\x92\r\n",
        b"\xE0\x80\x80x+",
        b"\xED\xA0\x80x+",
        b"\xF4\x90\x80\x80x+",
        b"\r\xE2\x82+\r\n\xF0\x9F\x92x+",
    ];
    for haystack in cases {
        assert_space_operator_single_load_case(&plan, haystack);
    }
}

#[test]
fn space_around_operator_direct_plan_has_exact_prospective_limits() {
    let plan = space_operator_plan();
    let haystack = b"x+";
    let exact = LineCaptureRunLimits {
        max_work: 25,
        max_sequential_bytes: 2,
        max_capture_count: 3,
        max_reducer_events: 5,
    };
    let report = plan
        .grep_capture_count(haystack, exact)
        .expect("exact direct limits");
    assert_eq!(report.work, 25);
    assert_eq!(report.sequential_bytes, 2);
    assert_eq!(report.actual_input_loads, 2);
    assert_eq!(report.prospective_matches, 1);
    assert_eq!(report.prospective_capture_count, 3);
    assert_eq!(report.prospective_line_events, 2);
    assert_eq!(report.prospective_reducer_events, 5);
    assert_eq!(report.matches, 1);
    assert_eq!(report.capture_count, 3);
    assert_eq!(report.reducer_events, 4);
    assert_eq!(report.scratch_bytes, 0);
    assert_eq!(report.output_bytes, 0);

    let multiple = plan
        .grep_capture_count(b"x+x+", LineCaptureRunLimits::default())
        .expect("multiple non-overlapping matches");
    assert_eq!(multiple.matches, 2);
    assert_eq!(multiple.capture_count, 6);
    assert_eq!(multiple.reducer_events, 7);
    assert_eq!(multiple.prospective_matches, 2);
    assert_eq!(multiple.prospective_capture_count, 6);
    assert_eq!(multiple.prospective_line_events, 4);
    assert_eq!(multiple.prospective_reducer_events, 10);

    let cases = [
        (
            LineCaptureResource::ExecutionWork,
            LineCaptureRunLimits {
                max_work: 24,
                ..exact
            },
        ),
        (
            LineCaptureResource::SequentialBytes,
            LineCaptureRunLimits {
                max_sequential_bytes: 1,
                ..exact
            },
        ),
        (
            LineCaptureResource::CaptureCount,
            LineCaptureRunLimits {
                max_capture_count: 2,
                ..exact
            },
        ),
        (
            LineCaptureResource::ReducerEvents,
            LineCaptureRunLimits {
                max_reducer_events: 4,
                ..exact
            },
        ),
    ];
    for (resource, limits) in cases {
        assert!(matches!(
            plan.grep_capture_count(haystack, limits),
            Err(LineCaptureRunError::Resource { resource: got, .. }) if got == resource
        ));
    }

    for bytes in [1_usize, 64, 4_096] {
        let haystack = vec![b'a'; bytes];
        let report = plan
            .grep_capture_count(&haystack, LineCaptureRunLimits::default())
            .expect("scaled direct reduction");
        assert_eq!(report.work, 12 * bytes + 1);
        assert_eq!(report.sequential_bytes, bytes);
        assert_eq!(report.actual_input_loads, bytes);
    }
}

#[test]
fn remaining_ruff_line_plans_authenticate_exact_hir_and_one_below() {
    let cases = [
        (
            SHEBANG_CAPTURE_PATTERN,
            LineCapturePlanKind::Shebang,
            LineCaptureConfiguration::AnchoredWhitespaceLiteralTail,
            SHEBANG_OPERATION_ID,
            (9, 12, 2, SHEBANG_INSPECTION_WORK, 2, 3, 12),
        ),
        (
            STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
            LineCapturePlanKind::StringQuotePrefix,
            LineCaptureConfiguration::AnchoredAsciiPrefixQuotedTail,
            STRING_QUOTE_PREFIX_OPERATION_ID,
            (10, 12, 0, STRING_QUOTE_PREFIX_INSPECTION_WORK, 1, 2, 8),
        ),
        (
            WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
            LineCapturePlanKind::WhitespaceAroundKeywords,
            LineCaptureConfiguration::UnicodeWordKeywordSet,
            WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
            (
                45,
                20,
                155,
                WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
                2,
                3,
                16,
            ),
        ),
    ];
    for (
        pattern,
        kind,
        configuration,
        operation_id,
        (nodes, ranges, literals, inspection, explicit, groups, rate),
    ) in cases
    {
        let plan = line_capture_plan(pattern);
        let report = plan.build_report();
        assert_eq!(report.identity.source, pattern);
        assert_eq!(report.identity.profile, fre::RustProfile::rebar_1_12_4());
        assert_eq!(report.identity.plan, kind);
        assert_eq!(report.identity.operation.operation_id, operation_id);
        assert_eq!(report.identity.operation.configuration, configuration);
        assert_eq!(report.identity.operation.work_per_input_byte, rate);
        assert_eq!(report.hir_nodes, nodes);
        assert_eq!(report.class_ranges, ranges);
        assert_eq!(report.literal_bytes, literals);
        assert_eq!(report.inspection_work, inspection);
        assert_eq!(report.minimum_match_bytes, 2);
        assert_eq!(report.explicit_captures, explicit);
        assert_eq!(report.participating_groups_per_match, groups);
        assert_eq!(report.allocations, 0);
        assert_eq!(report.scratch_bytes, 0);
        assert_eq!(report.persistent_bytes, size_of::<fre::LineCapturePlan>());
        assert_eq!(report.peak_bytes, size_of::<fre::LineCapturePlan>());

        assert_remaining_ruff_build_limits(pattern, inspection);
    }
}

fn assert_remaining_ruff_build_limits(pattern: &str, inspection: usize) {
    let inspection_below = inspection
        .checked_sub(1)
        .expect("registered inspection work is nonzero");
    let plan_bytes_below = size_of::<fre::LineCapturePlan>()
        .checked_sub(1)
        .expect("line-capture plan is nonempty");
    assert!(matches!(
        LineCaptureBuilder::new(pattern)
            .profile(fre::RustProfile::rebar_1_12_4())
            .limits(LineCaptureBuildLimits {
                max_inspection_work: inspection_below,
                ..LineCaptureBuildLimits::default()
            })
            .build(),
        Err(LineCaptureBuildError::InspectionWork { required, limit })
            if required == inspection && limit == inspection_below
    ));
    for (resource, limits) in [
        (
            LineCaptureBuildResource::PersistentBytes,
            LineCaptureBuildLimits {
                max_persistent_bytes: plan_bytes_below,
                ..LineCaptureBuildLimits::default()
            },
        ),
        (
            LineCaptureBuildResource::PeakBytes,
            LineCaptureBuildLimits {
                max_peak_bytes: plan_bytes_below,
                ..LineCaptureBuildLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            LineCaptureBuilder::new(pattern)
                .profile(fre::RustProfile::rebar_1_12_4())
                .limits(limits)
                .build(),
            Err(LineCaptureBuildError::Resource { resource: got, .. }) if got == resource
        ));
    }
    let mutated = format!("{pattern} ");
    assert!(matches!(
        LineCaptureBuilder::new(&mutated)
            .profile(fre::RustProfile::rebar_1_12_4())
            .build(),
        Err(LineCaptureBuildError::Unsupported("source identity"))
    ));
}

#[test]
fn remaining_ruff_line_plans_bind_exact_prospective_limits_and_single_load() {
    let cases = [
        (SHEBANG_CAPTURE_PATTERN, b"#!".as_slice(), 12, 3, 23),
        (
            STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
            b"''".as_slice(),
            8,
            2,
            15,
        ),
        (
            WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
            b"if".as_slice(),
            16,
            3,
            28,
        ),
    ];
    for (pattern, haystack, rate, count, actual_work) in cases {
        let plan = line_capture_plan(pattern);
        let prospective_work = rate * haystack.len() + 1;
        let prospective_matches = haystack.len() / 2;
        let prospective_captures = prospective_matches * count;
        let prospective_events = haystack.len() + prospective_captures;
        let exact = LineCaptureRunLimits {
            max_work: prospective_work,
            max_sequential_bytes: haystack.len(),
            max_capture_count: prospective_captures,
            max_reducer_events: prospective_events,
        };
        let report = plan
            .grep_capture_count(haystack, exact)
            .expect("exact direct execution bounds");
        assert_eq!(report.work, prospective_work);
        assert_eq!(report.actual_work, actual_work);
        assert!(report.actual_work <= report.work);
        assert_eq!(report.sequential_bytes, haystack.len());
        assert_eq!(report.actual_input_loads, haystack.len());
        assert_eq!(report.prospective_matches, prospective_matches);
        assert_eq!(report.prospective_capture_count, prospective_captures);
        assert_eq!(report.prospective_line_events, haystack.len());
        assert_eq!(report.prospective_reducer_events, prospective_events);
        assert_eq!(report.matches, 1);
        assert_eq!(report.capture_count, count);
        assert_eq!(report.lines, 1);
        assert_eq!(report.reducer_events, count + 1);
        assert_eq!(report.scratch_bytes, 0);
        assert_eq!(report.output_bytes, 0);

        for (resource, limits) in [
            (
                LineCaptureResource::ExecutionWork,
                LineCaptureRunLimits {
                    max_work: prospective_work - 1,
                    ..exact
                },
            ),
            (
                LineCaptureResource::SequentialBytes,
                LineCaptureRunLimits {
                    max_sequential_bytes: haystack.len() - 1,
                    ..exact
                },
            ),
            (
                LineCaptureResource::CaptureCount,
                LineCaptureRunLimits {
                    max_capture_count: prospective_captures - 1,
                    ..exact
                },
            ),
            (
                LineCaptureResource::ReducerEvents,
                LineCaptureRunLimits {
                    max_reducer_events: prospective_events - 1,
                    ..exact
                },
            ),
        ] {
            assert!(matches!(
                plan.grep_capture_count(haystack, limits),
                Err(LineCaptureRunError::Resource { resource: got, .. }) if got == resource
            ));
        }

        for bytes in [1_usize, 64, 4_096] {
            let input = vec![b'a'; bytes];
            let report = plan
                .grep_capture_count(&input, LineCaptureRunLimits::default())
                .expect("scaled direct reduction");
            assert_eq!(report.work, rate * bytes + 1);
            assert_eq!(report.sequential_bytes, bytes);
            assert_eq!(report.actual_input_loads, bytes);
            assert!(report.actual_work <= report.work);
        }
    }
}

fn assert_line_capture_oracle(pattern: &str, haystack: &[u8]) {
    let plan = line_capture_plan(pattern);
    let expected = reference_grep_capture_count(pattern, haystack);
    let report = plan
        .grep_capture_count(haystack, LineCaptureRunLimits::default())
        .unwrap_or_else(|error| panic!("pattern={pattern:?} haystack={haystack:?}: {error}"));
    assert_eq!(report.capture_count, expected, "haystack={haystack:?}");
    assert_eq!(report.actual_input_loads, haystack.len());
    assert!(report.actual_work <= report.work);
    assert_eq!(report.scratch_bytes, 0);
    assert_eq!(report.output_bytes, 0);
}

#[test]
fn shebang_direct_plan_matches_anchor_unicode_invalid_and_crlf_oracles() {
    let cases: &[&[u8]] = &[
        b"",
        b"#!",
        b" \t#!",
        b"#!directive",
        b"#!\xFFtail",
        b"#!a\xFFb",
        b"\xFF#!",
        b" \xFF#!",
        b"x#!",
        b" #x#!",
        b"#!\r\n",
        b"#!\r",
        b"\r#!",
        "\u{0085}\u{2003}#!\u{2028}".as_bytes(),
        b"#!\n \t#!x\r\n\xFF#!\n",
    ];
    for haystack in cases {
        assert_line_capture_oracle(SHEBANG_CAPTURE_PATTERN, haystack);
    }
}

#[test]
fn string_quote_direct_plan_matches_casefold_raw_invalid_and_crlf_oracles() {
    let cases: &[&[u8]] = &[
        b"",
        b"'",
        b"''",
        b"\"\"",
        b"'\"",
        b"\"'",
        b"r''",
        b"URB\"\"",
        b"RuB'a'",
        b"rub",
        b"rurx''",
        b"'a'b'",
        b"''x",
        b"''\xFF",
        b"'\xFF'",
        b"\xFF''",
        b"''\r\n",
        b"''\r",
        b"'\r'\r\n",
        "'\u{2028}'".as_bytes(),
        "'\u{00E9}'".as_bytes(),
        "U\"\u{03B2}\"".as_bytes(),
    ];
    for haystack in cases {
        assert_line_capture_oracle(STRING_QUOTE_PREFIX_CAPTURE_PATTERN, haystack);
    }
}

#[test]
fn keyword_direct_plan_matches_unicode_boundaries_invalid_and_multiple_oracles() {
    let all_keywords = b"False,None,True,and,as,assert,async,await,break,class,continue,def,del,elif,else,except,finally,for,from,global,if,import,in,is,lambda,nonlocal,not,or,pass,raise,return,try,while,with,yield\n";
    assert_eq!(
        reference_grep_capture_count(WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN, all_keywords),
        105
    );
    let cases: &[&[u8]] = &[
        b"",
        b"if",
        b"if else",
        b"False None True",
        b"gift",
        b"if_",
        b"_if",
        b"if-else",
        b"if\xFFelse",
        b"\xFFif\xFF",
        b"if_\xFF",
        "\u{00E9}if".as_bytes(),
        "\u{00E9} if".as_bytes(),
        "if\u{2003}else".as_bytes(),
        "if\u{2028}else".as_bytes(),
        "if\u{200C}or".as_bytes(),
        "if\u{200D}or".as_bytes(),
        b"if\r\nelse\nwhile try\r",
        b"as assert async in is import",
        b"continue nonlocal finally assert async await",
        all_keywords,
    ];
    for haystack in cases {
        assert_line_capture_oracle(WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN, haystack);
    }
}

#[test]
fn remaining_ruff_line_plans_load_every_valid_malformed_and_cr_byte_once() {
    let inputs: &[&[u8]] = &[
        b"\ra",
        b"\r\n",
        b"\xC2",
        b"\xE2",
        b"\xE2\x82",
        b"\xF0",
        b"\xF0\x9F",
        b"\xF0\x9F\x92",
        b"\xE0\x80\x80",
        b"\xED\xA0\x80",
        b"\xF4\x90\x80\x80",
        b"#!\xFF\r\n'\xFF'\n\xFFif\xFF",
    ];
    for pattern in [
        SHEBANG_CAPTURE_PATTERN,
        STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
        WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
    ] {
        for haystack in inputs {
            assert_line_capture_oracle(pattern, haystack);
        }
    }
}

fn reference_records(pattern: &str, haystack: &[u8]) -> Vec<CaptureFixture> {
    let regex = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("reference pattern");
    let names = regex
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    regex
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .enumerate()
                .map(|(index, matched)| {
                    (
                        u32::try_from(index).unwrap(),
                        names[index].clone(),
                        matched.map(|matched| (matched.start(), matched.end())),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn materialized_capture_iteration_preserves_empty_unmatched_and_named_slots() {
    let cases: &[(&str, &[u8])] = &[
        (r"(a){0}(a)", b"a"),
        (r"(?P<left>a)|(b)", b"ab"),
        (r"()|a", b"a"),
        (r"(a*)", b"ba"),
        (r"((a)?)(b)?", b"ab b"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let limits = CaptureAggregateLimits::default();
        let report = regex
            .captures_iter(haystack, limits)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, reference_records(pattern, haystack), "{pattern:?}");
        assert_eq!(report.identity, regex.iteration_identity(limits));
        assert_eq!(
            report.identity.syntax,
            regex.build_report().plan_identity.syntax
        );
    }
}

fn reference_text_records(pattern: &str, haystack: &str) -> Vec<CaptureFixture> {
    let regex = TextRegexBuilder::new(pattern)
        .build()
        .expect("reference text pattern");
    let names = regex
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    regex
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .enumerate()
                .map(|(index, matched)| {
                    (
                        u32::try_from(index).unwrap(),
                        names[index].clone(),
                        matched.map(|matched| (matched.start(), matched.end())),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn pinned_expensive_counted_text_captures_match_upstream() {
    // Pinned corpus identities:
    // - expensive/regression-many-repeat-no-stack-overflow
    // - expensive/backtrack-blow-visited-capacity
    let cases = [
        (r"^.{1,2500}", "a"),
        (
            r"\pL{50}",
            "abcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyZZ",
        ),
    ];
    for (pattern, haystack) in cases {
        let regex = PortableTextCaptureBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let report = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<CaptureFixture>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            reference_text_records(pattern, haystack),
            "{pattern:?}"
        );
    }
}

#[test]
fn exact_hir_text_captures_preserve_utf8_empty_and_group_boundaries() {
    let cases = [
        (r"(a){0}(a)", "a"),
        (r"(?P<left>a)|(b)", "éab"),
        (r"()|a", "éa"),
        (r"(a*)", "éba"),
        (r"((a)?)(b)?", "éab b"),
        (r"(é+)", "aéé東京"),
        (r"(\w+)", "éa 東京_42"),
        (r"(.)", "é東京"),
        (r"^((?:é|a)*)$", "éaé"),
        (r"([\p{Greek}]+)", "aΔδ東京"),
        (r"(\b)", "éa 東京_42"),
        (r"(\B)", "éa 東京_42"),
        (r"(\b{start})", "éa 東京_42"),
        (r"(\b{end})", "éa 東京_42"),
        (r"(\b{start-half})", "éa 東京_42"),
        (r"(\b{end-half})", "éa 東京_42"),
        (r"(?m:^([^\n]*))", "éa\n東京\n"),
        (r"(?Rm:^([^\r\n]*))", "éa\r\n東京\r末"),
    ];
    for (pattern, haystack) in cases {
        let regex = PortableTextCaptureBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let report = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<CaptureFixture>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            reference_text_records(pattern, haystack),
            "{pattern:?}"
        );
    }
}

#[test]
fn single_text_capture_view_supports_numeric_name_and_borrowed_indexing() {
    fn named_len(haystack: &str) -> usize {
        let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
            .build()
            .expect("text capture build");
        let (captures, accounting) = regex
            .captures(haystack, CaptureSearchLimits::default())
            .expect("bounded text capture search");
        assert!(accounting.state_visits > 0);
        let captures = captures.expect("capture record");
        captures["name"].len()
    }

    let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
        .build()
        .expect("text capture build");
    let (captures, _) = regex
        .captures("abc", CaptureSearchLimits::default())
        .expect("bounded text capture search");
    let captures = captures.expect("capture record");
    assert_eq!(captures.len(), 2);
    assert!(!captures.is_empty());
    assert_eq!(captures.get(0).expect("whole match").as_str(), "abc");
    assert_eq!(captures.get(1).expect("numeric group").as_str(), "abc");
    assert_eq!(captures.name("name").expect("named group").as_str(), "abc");
    assert_eq!(&captures[0], "abc");
    assert_eq!(&captures[1], "abc");
    assert_eq!(&captures["name"], "abc");
    assert_eq!(named_len("123"), 3);
}

#[test]
fn single_text_capture_indexing_panics_for_missing_slots_and_names() {
    let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
        .build()
        .expect("text capture build");
    let (captures, _) = regex
        .captures("abc", CaptureSearchLimits::default())
        .expect("bounded text capture search");
    let captures = captures.expect("capture record");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| &captures[2])).is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| &captures["missing"])).is_err()
    );
}

#[test]
fn cross_family_capture_reducers_match_pinned_rust_bytes() {
    let cases: &[(&str, &[u8])] = &[
        (r"(a)(b)?", b"a ab"),
        (r"((a)|(b))+", b"abba cab"),
        (r"(?:fn is_(\w+)|fn as_(\w+))", b"fn is_a fn as_b"),
        (
            r"^\s*fn\s+(is_([^\(]+))\(([^)]+)\) -> bool \{$",
            b"fn is_even(x: u8) -> bool {",
        ),
        (r"(()a)", b"a"),
        (r"(?:\A(a)|(a))", b"xax"),
        (r"(?:(a)\z|(a))", b"xax"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        assert_count(pattern, haystack);
    }
}

#[test]
fn uniform_participation_uses_selector_without_history() {
    let cases: &[(&str, &[u8])] = &[
        (r"fn is_(\w+)|fn as_(\w+)", b"fn is_even fn as_byte"),
        (r"(?s)^((.*)()()($))", b"abc\ndef"),
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/",
            b"cargo/registry/src/x/name-1.2.3/",
        ),
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/|cargo\\registry\\src\\[^\\]+\\([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\",
            b"cargo/registry/src/x/name-1.2.3/",
        ),
        (r"(a){0}(a)", b"a"),
    ];
    for &(pattern, haystack) in cases {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(
            regex.build_report().plan_identity.plan,
            fre::CapturePlanKind::LinearSelectorUniformParticipation,
            "pattern={pattern:?}"
        );
        let limits = CaptureRunLimits {
            aggregate: CaptureAggregateLimits {
                per_search: CaptureSearchLimits {
                    max_state_visits: 0,
                    max_history_nodes: 0,
                    max_history_walk: 0,
                    ..CaptureSearchLimits::default()
                },
                max_total_state_visits: 0,
                max_total_history_nodes: 0,
                max_total_history_walk: 0,
                ..CaptureAggregateLimits::default()
            },
            ..CaptureRunLimits::default()
        };
        let result = regex
            .count_captures(haystack, limits)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(result.accounting.count, reference_count(pattern, haystack));
        assert_eq!(result.accounting.total_state_visits, 0);
        assert_eq!(result.accounting.total_history_nodes, 0);
        assert_eq!(result.accounting.total_history_walk, 0);
    }

    for pattern in [r"(a)(b)?", r"((a)|(b))+", r"(a)|(b)(c)"] {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(
            regex.build_report().plan_identity.plan,
            fre::CapturePlanKind::LinearSelectorPersistentHistory,
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn uniform_participation_preserves_count_and_event_limits() {
    let regex = CaptureBuilder::new(r"fn is_(\w+)|fn as_(\w+)")
        .unicode(false)
        .build()
        .expect("uniform alternation build");
    let haystack = b"fn is_even fn as_byte";
    let exact = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("uniform exact limits");
    assert_eq!(exact.accounting.matches, 2);
    assert_eq!(exact.accounting.count, 4);
    let count_starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_count: exact.accounting.count - 1,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let count_error = regex
        .count_captures(haystack, count_starved)
        .expect_err("uniform count one below must refuse");
    assert!(matches!(
        count_error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::CaptureCount,
            required: 4,
            limit: 3,
        })
    ));
    let event_starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_events: 5,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let event_error = regex
        .count_captures(haystack, event_starved)
        .expect_err("uniform events one below must refuse");
    assert!(matches!(
        event_error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::CaptureEvents,
            required: 6,
            limit: 5,
        })
    ));
}

#[test]
fn sixty_five_user_captures_match_pinned_rust_and_remain_bounded() {
    // This cardinality is shared by the authenticated Veryl lexer rows:
    // curated/05-lexer-veryl/single and wild/parol-veryl/{ascii,unicode}.
    let pattern = "(a)".repeat(65);
    let haystack = vec![b'a'; 65];
    let regex = CaptureBuilder::new(&pattern)
        .unicode(false)
        .build()
        .expect("65 user captures fit the facade's bounded default");
    assert_eq!(regex.build_report().engine.captures, 65);
    let result = regex
        .count_captures(&haystack, CaptureRunLimits::default())
        .expect("65-capture reduction");
    assert_eq!(
        result.accounting.count,
        reference_count(&pattern, &haystack)
    );

    let mut limits = fre::CaptureBuildLimits::default();
    limits.engine.max_captures = 64;
    assert!(matches!(
        CaptureBuilder::new(&pattern)
            .unicode(false)
            .limits(limits)
            .build(),
        Err(fre::CaptureBuildError::Engine(
            fre::CaptureEngineBuildError::Resource {
                kind: CaptureResource::Captures,
                required: 65,
                limit: 64,
            }
        ))
    ));
}

#[test]
fn overlapping_unicode_word_captures_fit_the_bounded_selector_default() {
    // Authenticated Rebar obligations:
    // - unicode/overlapping-words/english@rust/regex
    // - unicode/overlapping-words/russian@rust/regex
    let pattern = r"(\p{L}{14})|(\p{L}{13})|(\p{L}{12})|(\p{L}{11})|(\p{L}{10})|(\p{L}{9})|(\p{L}{8})|(\p{L}{7})|(\p{L}{6})|(\p{L}{5})";
    let regex = CaptureBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("overlapping Unicode-word selector fits the bounded default");
    assert_eq!(regex.build_report().selector.program_states, 390);
    assert_eq!(regex.build_report().selector.temporary_states_peak, 390);
    assert_eq!(regex.build_report().selector.program_bytes, 549_432);
    assert!(regex.build_report().selector.work >= 126_986);

    for haystack in [
        "abcdefghijklmn абвгдежзийклмн",
        "абвгдежзийклмн abcdefghijklmn",
    ] {
        let actual = regex
            .count_captures(haystack.as_bytes(), CaptureRunLimits::default())
            .expect("bounded Unicode-word capture reduction")
            .accounting
            .count;
        let expected = RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("pinned Rust reference")
            .captures_iter(haystack.as_bytes())
            .map(|captures| captures.iter().flatten().count())
            .sum::<usize>();
        assert_eq!(actual, expected, "{haystack:?}");
    }

    let mut limits = fre::CaptureBuildLimits::default();
    limits.selector.max_program_states = 389;
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(limits)
            .build(),
        Err(fre::CaptureBuildError::Selector(
            fre::AggregateEngineError::ResourceLimit {
                resource: fre::AggregateResource::ProgramStates,
                required: 390,
                limit: 389,
            }
        ))
    ));
}

fn adversarial_operation_work(size: usize) -> (usize, usize) {
    let regex = CaptureBuilder::new(r"(?:a.*z|a)")
        .unicode(false)
        .build()
        .expect("adversarial selector build");
    let haystack = vec![b'a'; size];
    let result = regex
        .count_captures(&haystack, CaptureRunLimits::default())
        .expect("operation-wide capture reduction");
    assert_eq!(size, result.accounting.matches);
    assert_eq!(size, result.accounting.count);
    assert_eq!(size, result.selector_certificate.output_matches);
    let state_visits = result
        .selector_accounting
        .state_evaluations
        .saturating_add(result.selector_accounting.replay_steps)
        .saturating_add(result.accounting.total_state_visits);
    (state_visits, result.accounting.total_history_nodes)
}

#[test]
fn operation_wide_selector_removes_quadratic_restart_work() {
    let samples = [64_usize, 128, 256, 512].map(adversarial_operation_work);
    for pair in samples.windows(2) {
        let (smaller_visits, smaller_histories) = pair[0];
        let (larger_visits, larger_histories) = pair[1];
        assert!(
            larger_visits <= smaller_visits.saturating_mul(5).div_ceil(2),
            "doubling input grew state visits from {smaller_visits} to {larger_visits}"
        );
        assert!(
            larger_histories <= smaller_histories.saturating_mul(5).div_ceil(2),
            "doubling input grew history nodes from {smaller_histories} to {larger_histories}"
        );
    }
}

#[test]
fn persistent_history_reports_fanout_and_refuses_node_starvation() {
    let pattern = r"(?:(a+)|(b+)|(c+)|(d+)|(e+)|(f+)|(g+)|(h+)|(i+)|(j+)|(k+)|(l+)|(m+)|(n+)|(o+)|(p+)|(q+)|(r+)|(s+)|(t+)|(u+)|(v+)|(w+)|(x+)|(y+)|(z+))";
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("fanout build");
    assert_eq!(regex.build_report().engine.captures, 26);
    let result = regex
        .count_captures(b"aaabbbccc", CaptureRunLimits::default())
        .expect("fanout reduction");
    assert_eq!(
        result.identity.plan.plan,
        fre::CapturePlanKind::LinearSelectorUniformParticipation
    );
    assert_eq!(result.accounting.total_history_nodes, 0);

    let history = CaptureBuilder::new(r"(a)(b)?")
        .unicode(false)
        .build()
        .expect("variable-participation build");
    let starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            per_search: CaptureSearchLimits {
                max_history_nodes: 0,
                ..CaptureSearchLimits::default()
            },
            max_total_history_nodes: 0,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let error = history
        .count_captures(b"ab", starved)
        .expect_err("history starvation must refuse");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::HistoryNodes,
            ..
        })
    ));
}

#[test]
fn combined_peak_caps_retained_selector_output_plus_replay_scratch() {
    let regex = CaptureBuilder::new(r"(a)(b)?")
        .unicode(false)
        .build()
        .expect("combined-peak build");
    let admitted = regex
        .count_captures(b"ab", CaptureRunLimits::default())
        .expect("combined-peak baseline");
    assert!(
        admitted.combined_peak_bytes > admitted.selector_accounting.peak_bytes,
        "fixture must expose retained spans plus replay scratch"
    );
    assert!(admitted.combined_peak_bytes <= CaptureRunLimits::default().max_combined_peak_bytes);

    let constrained = CaptureRunLimits {
        max_combined_peak_bytes: admitted.selector_accounting.peak_bytes,
        ..CaptureRunLimits::default()
    };
    let error = regex
        .count_captures(b"ab", constrained)
        .expect_err("combined peak must constrain replay before allocation");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::ScratchBytes,
            ..
        })
    ));
}

#[test]
fn unicode_capture_classes_and_admitted_contextual_looks_execute() {
    let pattern = r"([\p{L}\p{N}_]+)";
    let haystack = b"abc \xCE\x94\xCE\xB4 42 \xFF";
    let reference = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("Unicode byte reference")
        .captures_iter(haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum::<usize>();
    let regex = CaptureBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("Unicode capture lowering");
    let actual = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("Unicode capture execution")
        .accounting
        .count;
    assert_eq!(actual, reference);
    let hir_starved = fre::CaptureBuildLimits {
        max_hir_work: regex.build_report().hir.work.saturating_sub(1),
        ..fre::CaptureBuildLimits::default()
    };
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(hir_starved)
            .build(),
        Err(fre::CaptureBuildError::HirResource {
            resource: "work",
            ..
        })
    ));
    let engine = fre::CaptureEngineBuildLimits {
        max_ast_nodes: regex.build_report().engine.ast_nodes.saturating_sub(1),
        ..fre::CaptureEngineBuildLimits::default()
    };
    let ast_starved = fre::CaptureBuildLimits {
        engine,
        ..fre::CaptureBuildLimits::default()
    };
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(ast_starved)
            .build(),
        Err(fre::CaptureBuildError::Engine(
            fre::CaptureEngineBuildError::Resource {
                kind: CaptureResource::AstNodes,
                ..
            }
        ))
    ));
    assert_count(r"(?m:^([^\n]+))", b"a\nb\n");
    assert_count(r"(?Rm:^([^\r\n]+))", b"a\r\nb\rc\n");
    assert_count(r"(?-u:\b)([A-Za-z_]+)(?-u:\b)", b"a-b_c 42");
    assert_count(r"(?-u:\b{start})([A-Za-z_]+)", b"a-b_c 42");
    let word_pattern = r"([\p{L}]+)\b";
    let word_haystack = "éa 東京_42".as_bytes();
    let word_reference = RegexBuilder::new(word_pattern)
        .unicode(true)
        .build()
        .expect("Unicode word reference")
        .captures_iter(word_haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum::<usize>();
    let word_actual = CaptureBuilder::new(word_pattern)
        .unicode(true)
        .build()
        .expect("Unicode word capture")
        .count_captures(word_haystack, CaptureRunLimits::default())
        .expect("Unicode word execution")
        .accounting
        .count;
    assert_eq!(word_actual, word_reference);
}

#[test]
fn custom_line_terminator_captures_match_pinned_regex() {
    let cases: &[(&str, &[u8], u8)] = &[
        (r"(?m)^([a-z]+)$", b"\0abc\0", b'\0'),
        (r"(?m)^([a-z]+)$", b"\nabc\n", b'\0'),
        (r"(?m)^([a-z]+)$", &[0xFF, b'a', b'b', b'c', 0xFF], 0xFF),
        (r"(?m)^\b([a-z]+)\b$", b"ZabcZ", b'Z'),
        (r"(?m)^\B([a-z]+)\B$", b"ZabcZ", b'Z'),
        (r"(?m)^\b([a-z]+)\b$", b"%abc%", b'%'),
    ];
    for &(pattern, haystack, line_terminator) in cases {
        let mut reference_builder = RegexBuilder::new(pattern);
        reference_builder
            .unicode(false)
            .line_terminator(line_terminator);
        let reference = reference_builder
            .build()
            .unwrap_or_else(|error| panic!("reference pattern={pattern:?}: {error}"));
        let expected = reference
            .captures_iter(haystack)
            .map(|captures| {
                captures
                    .iter()
                    .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut profile = fre::RustProfile::default();
        profile.options.unicode = false;
        profile.options.line_terminator = line_terminator;
        let regex = CaptureBuilder::new(pattern)
            .profile(profile)
            .build()
            .unwrap_or_else(|error| panic!("FRE pattern={pattern:?}: {error}"));
        let actual = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("FRE pattern={pattern:?}: {error}"))
            .captures
            .into_iter()
            .map(|captures| {
                captures
                    .groups
                    .into_iter()
                    .map(|group| group.span.map(|span| (span.start, span.end)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual, expected,
            "pattern={pattern:?}, line={line_terminator:#04X}"
        );
    }

    let pattern = r"(?m)^([\p{L}]+)$";
    let haystack = "!é東京!";
    let mut reference_builder = TextRegexBuilder::new(pattern);
    reference_builder.line_terminator(b'!');
    let expected = reference_builder
        .build()
        .expect("reference text pattern")
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut profile = fre::RustProfile::default();
    profile.options.line_terminator = b'!';
    let actual = PortableTextCaptureBuilder::new(pattern)
        .profile(profile)
        .build()
        .expect("FRE text pattern")
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .expect("FRE text captures")
        .captures
        .into_iter()
        .map(|captures| {
            captures
                .groups
                .into_iter()
                .map(|group| group.span.map(|span| (span.start, span.end)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn source_and_execution_limits_remain_in_capture_identity() {
    let python_name = CaptureBuilder::new(r"(?P<letter>a)")
        .unicode(false)
        .build()
        .expect("Python-name spelling");
    let angle_name = CaptureBuilder::new(r"(?<letter>a)")
        .unicode(false)
        .build()
        .expect("angle-name spelling");
    assert_ne!(
        python_name.build_report().plan_identity,
        angle_name.build_report().plan_identity
    );

    let default_identity = python_name.cache_identity(CaptureRunLimits::default());
    let constrained = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_events: 1,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    assert_ne!(default_identity, python_name.cache_identity(constrained));
}

#[test]
fn required_literal_proof_shares_the_single_capture_parse_and_exact_limits() {
    fn build(
        pattern: &str,
        required: CaptureRequiredLiteralBuildLimits,
        max_hir_work: usize,
    ) -> Result<fre::CaptureRegex, CaptureBuildError> {
        let mut limits = CaptureBuildLimits::default();
        limits.max_hir_work = max_hir_work;
        limits.required_literal = Some(required);
        CaptureBuilder::new(pattern)
            .profile(fre::RustProfile::rebar_1_12_4())
            .unicode(false)
            .limits(limits)
            .build()
    }

    let baseline = build(
        "(?:AB|CD)",
        CaptureRequiredLiteralBuildLimits::default(),
        usize::MAX,
    )
    .expect("central required-literal capture build");
    let plan = baseline
        .required_literal_plan()
        .expect("required-literal plan");
    let accounting = plan.build_report().accounting;
    assert!(Arc::ptr_eq(
        &plan.build_report().identity.syntax,
        &baseline.build_report().plan_identity.syntax,
    ));
    assert_eq!(accounting.needles, 2);
    assert_eq!(accounting.needle_bytes, 4);
    assert_eq!(accounting.literal_set.patterns, 2);
    assert_eq!(accounting.literal_set.pattern_bytes, 4);
    assert_eq!(accounting.literal_set.trie_states_upper_bound, 5);
    assert_eq!(accounting.literal_set.dfa_cells_upper_bound, 1_280);
    assert_eq!(accounting.literal_set.build_work_upper_bound, 1_286);
    assert_eq!(accounting.planner_work, 25);
    assert!(
        plan.is_candidate(
            b"zzAB",
            CaptureRequiredLiteralRunLimits { max_transitions: 5 },
        )
        .expect("exact transition limit")
        .candidate
    );
    assert!(
        plan.is_candidate(
            b"zzAB",
            CaptureRequiredLiteralRunLimits { max_transitions: 4 },
        )
        .is_err()
    );

    let disabled = CaptureBuilder::new("(?:AB|CD)")
        .profile(fre::RustProfile::rebar_1_12_4())
        .unicode(false)
        .build()
        .expect("capture without optional proof");
    assert!(disabled.required_literal_plan().is_none());
    assert_ne!(
        disabled.build_report().plan_identity,
        baseline.build_report().plan_identity
    );
    for nullable in ["(?:AB|)", "(?:AB)?"] {
        assert!(
            build(
                nullable,
                CaptureRequiredLiteralBuildLimits::default(),
                usize::MAX,
            )
            .expect("nullable capture remains supported")
            .required_literal_plan()
            .is_none()
        );
    }

    for (resource, one_below) in [
        ("planner work", accounting.planner_work - 1),
        ("HIR depth", accounting.hir_depth - 1),
        ("needle count", accounting.needles - 1),
        ("needle bytes", accounting.needle_bytes - 1),
        ("source bytes", accounting.source_bytes - 1),
        ("scratch bytes", accounting.scratch_bytes - 1),
        ("peak bytes", accounting.peak_bytes_upper_bound - 1),
    ] {
        let mut required = CaptureRequiredLiteralBuildLimits::default();
        match resource {
            "planner work" => required.max_planner_work = one_below,
            "HIR depth" => required.max_hir_depth = one_below,
            "needle count" => required.max_needles = one_below,
            "needle bytes" => required.max_needle_bytes = one_below,
            "source bytes" => required.max_source_bytes = one_below,
            "scratch bytes" => required.max_scratch_bytes = one_below,
            "peak bytes" => required.max_peak_bytes = one_below,
            _ => unreachable!(),
        }
        assert!(matches!(
            build("(?:AB|CD)", required, usize::MAX),
            Err(CaptureBuildError::RequiredLiteral(
                CaptureRequiredLiteralBuildError::Resource { .. }
                    | CaptureRequiredLiteralBuildError::LiteralSet(_)
            ))
        ));
    }

    build(
        "(?:AB|CD)",
        CaptureRequiredLiteralBuildLimits::default(),
        baseline.build_report().hir.work,
    )
    .expect("exact cumulative HIR-work limit");
    assert!(
        build(
            "(?:AB|CD)",
            CaptureRequiredLiteralBuildLimits::default(),
            baseline.build_report().hir.work - 1,
        )
        .is_err()
    );
}
