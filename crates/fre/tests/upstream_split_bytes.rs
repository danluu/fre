#![forbid(unsafe_code)]

use fre::{
    AggregateBuilder, AggregateEngineError, AggregateExecutionSource, AggregateOperation,
    AggregateOperationLimits, AggregateResource, AggregateRunLimits, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_SHA256: &str = "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";

const UPSTREAM_DOCTEST_IDS: &[&str] = &[
    "split_spaces_tabs",
    "split_space_basic",
    "split_no_match_empty_haystack",
    "split_adjacent_separators",
    "split_double_colon",
    "split_contiguous_x",
    "split_contiguous_slash",
    "split_separator_at_edges",
    "split_empty_regex_utf8_code_units",
    "split_contiguous_spaces",
    "split_contiguous_space_regex",
    "splitn_first_two_words",
    "splitn_space_basic",
    "splitn_no_match_empty_haystack",
    "splitn_adjacent_separators",
    "splitn_double_colon",
    "splitn_limit_one",
    "splitn_no_match",
    "splitn_limit_zero",
];

#[derive(Debug)]
struct DoctestCase {
    id: &'static str,
    pattern: &'static str,
    haystack: &'static [u8],
    limit: Option<usize>,
    expected: Vec<&'static [u8]>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete authenticated doctest table is clearer as one ordered inventory"
)]
fn doctest_cases() -> Vec<DoctestCase> {
    vec![
        DoctestCase {
            id: "split_spaces_tabs",
            pattern: r"[ \t]+",
            haystack: b"a b \t  c\td    e",
            limit: None,
            expected: vec![
                b"a".as_slice(),
                b"b".as_slice(),
                b"c".as_slice(),
                b"d".as_slice(),
                b"e".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_space_basic",
            pattern: r" ",
            haystack: b"Mary had a little lamb",
            limit: None,
            expected: vec![
                b"Mary".as_slice(),
                b"had".as_slice(),
                b"a".as_slice(),
                b"little".as_slice(),
                b"lamb".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_no_match_empty_haystack",
            pattern: r"X",
            haystack: b"",
            limit: None,
            expected: vec![b"".as_slice()],
        },
        DoctestCase {
            id: "split_adjacent_separators",
            pattern: r"X",
            haystack: b"lionXXtigerXleopard",
            limit: None,
            expected: vec![
                b"lion".as_slice(),
                b"".as_slice(),
                b"tiger".as_slice(),
                b"leopard".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_double_colon",
            pattern: r"::",
            haystack: b"lion::tiger::leopard",
            limit: None,
            expected: vec![
                b"lion".as_slice(),
                b"tiger".as_slice(),
                b"leopard".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_contiguous_x",
            pattern: r"X",
            haystack: b"XXXXaXXbXc",
            limit: None,
            expected: vec![
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b"a".as_slice(),
                b"".as_slice(),
                b"b".as_slice(),
                b"c".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_contiguous_slash",
            pattern: r"/",
            haystack: b"(///)",
            limit: None,
            expected: vec![
                b"(".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b")".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_separator_at_edges",
            pattern: r"0",
            haystack: b"010",
            limit: None,
            expected: vec![b"".as_slice(), b"1".as_slice(), b"".as_slice()],
        },
        DoctestCase {
            id: "split_empty_regex_utf8_code_units",
            pattern: r"",
            haystack: "☃".as_bytes(),
            limit: None,
            expected: vec![b"".as_slice(), &[0xE2], &[0x98], &[0x83], b"".as_slice()],
        },
        DoctestCase {
            id: "split_contiguous_spaces",
            pattern: r" ",
            haystack: b"    a  b c",
            limit: None,
            expected: vec![
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b"a".as_slice(),
                b"".as_slice(),
                b"b".as_slice(),
                b"c".as_slice(),
            ],
        },
        DoctestCase {
            id: "split_contiguous_space_regex",
            pattern: r" +",
            haystack: b"    a  b c",
            limit: None,
            expected: vec![
                b"".as_slice(),
                b"a".as_slice(),
                b"b".as_slice(),
                b"c".as_slice(),
            ],
        },
        DoctestCase {
            id: "splitn_first_two_words",
            pattern: r"\W+",
            haystack: b"Hey! How are you?",
            limit: Some(3),
            expected: vec![b"Hey".as_slice(), b"How".as_slice(), b"are you?".as_slice()],
        },
        DoctestCase {
            id: "splitn_space_basic",
            pattern: r" ",
            haystack: b"Mary had a little lamb",
            limit: Some(3),
            expected: vec![
                b"Mary".as_slice(),
                b"had".as_slice(),
                b"a little lamb".as_slice(),
            ],
        },
        DoctestCase {
            id: "splitn_no_match_empty_haystack",
            pattern: r"X",
            haystack: b"",
            limit: Some(3),
            expected: vec![b"".as_slice()],
        },
        DoctestCase {
            id: "splitn_adjacent_separators",
            pattern: r"X",
            haystack: b"lionXXtigerXleopard",
            limit: Some(3),
            expected: vec![
                b"lion".as_slice(),
                b"".as_slice(),
                b"tigerXleopard".as_slice(),
            ],
        },
        DoctestCase {
            id: "splitn_double_colon",
            pattern: r"::",
            haystack: b"lion::tiger::leopard",
            limit: Some(2),
            expected: vec![b"lion".as_slice(), b"tiger::leopard".as_slice()],
        },
        DoctestCase {
            id: "splitn_limit_one",
            pattern: r"X",
            haystack: b"abcXdef",
            limit: Some(1),
            expected: vec![b"abcXdef".as_slice()],
        },
        DoctestCase {
            id: "splitn_no_match",
            pattern: r"X",
            haystack: b"abcdef",
            limit: Some(2),
            expected: vec![b"abcdef".as_slice()],
        },
        DoctestCase {
            id: "splitn_limit_zero",
            pattern: r"X",
            haystack: b"abcXdef",
            limit: Some(0),
            expected: vec![],
        },
    ]
}

#[test]
fn authenticated_bytes_split_doctest_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);

    let ported: Vec<_> = doctest_cases().iter().map(|case| case.id).collect();
    assert_eq!(ported, UPSTREAM_DOCTEST_IDS);
    assert_eq!(ported.len(), 19);
}

#[test]
fn every_pinned_bytes_split_and_splitn_doctest_passes() {
    for case in doctest_cases() {
        let regex = AggregateBuilder::new(case.pattern)
            .profile(RustProfile::regex_1_12_4())
            .build_spans()
            .unwrap_or_else(|error| {
                panic!(
                    "upstream split case {} failed to build from {UPSTREAM_PATH} at \
                     {UPSTREAM_REVISION} ({UPSTREAM_SHA256}): {error}",
                    case.id
                )
            });
        let mut actual = match case.limit {
            None => regex.split(case.haystack, AggregateRunLimits::default()),
            Some(limit) => regex.splitn(case.haystack, limit, AggregateRunLimits::default()),
        }
        .unwrap_or_else(|error| panic!("upstream split case {} failed: {error}", case.id));
        assert_eq!(
            actual.selector_report().identity.operation,
            AggregateOperation::Spans
        );
        assert_eq!(actual.len(), case.expected.len(), "case {}", case.id);
        let fields: Vec<_> = actual.by_ref().collect();
        assert_eq!(fields, case.expected, "case {}", case.id);
        assert_eq!(actual.len(), 0, "case {}", case.id);
        assert_eq!(actual.next(), None, "case {}", case.id);
        assert_eq!(actual.next(), None, "case {}", case.id);
    }
}

#[test]
fn split_and_splitn_match_pinned_bytes_on_empty_progress_and_invalid_bytes() {
    const PATTERNS: &[&str] = &["", "a", "a*?", r"(?:ab|a)", r"[a-c\xFF]+", r"(?m:^a+$)"];
    const HAYSTACKS: &[&[u8]] = &[
        b"",
        b"ab",
        b"aaaa",
        b"aaaab",
        &[b'a', 0xFF, b'b', b'c'],
        b"a\naa\nb",
    ];
    const LIMITS: &[usize] = &[0, 1, 2, 3, usize::MAX];

    for pattern in PATTERNS {
        let fre = AggregateBuilder::new(*pattern)
            .profile(RustProfile::regex_1_12_4())
            .unicode(false)
            .build_spans()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        for haystack in HAYSTACKS {
            let expected: Vec<_> = upstream.split(haystack).collect();
            let actual: Vec<_> = fre
                .split(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("FRE split failed for {pattern:?}: {error}"))
                .collect();
            assert_eq!(actual, expected, "split {pattern:?}/{haystack:?}");

            for limit in LIMITS {
                let expected: Vec<_> = upstream.splitn(haystack, *limit).collect();
                let actual: Vec<_> = fre
                    .splitn(haystack, *limit, AggregateRunLimits::default())
                    .unwrap_or_else(|error| {
                        panic!("FRE splitn failed for {pattern:?}/{haystack:?}/{limit}: {error}")
                    })
                    .collect();
                assert_eq!(actual, expected, "splitn {pattern:?}/{haystack:?}/{limit}");
            }
        }
    }
}

#[test]
fn split_propagates_the_complete_selector_output_limit_exactly() {
    let regex = AggregateBuilder::new("X")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("split selector");
    let exact = AggregateRunLimits {
        continuation: AggregateOperationLimits {
            max_output_matches: 3,
            ..AggregateOperationLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let fields = regex.split(b"XXX", exact).expect("exact selector limit");
    assert_eq!(fields.selected_matches(), 3);
    assert_eq!(fields.len(), 4);

    let below = AggregateRunLimits {
        continuation: AggregateOperationLimits {
            max_output_matches: 2,
            ..AggregateOperationLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex
        .split(b"XXX", below)
        .expect_err("one below selected match count must fail");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputMatches,
            required: 3,
            limit: 2,
        })
    ));
}
