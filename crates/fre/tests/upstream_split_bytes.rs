#![forbid(unsafe_code)]

use fre::{
    AggregateBuilder, AggregateEngineError, AggregateExecutionSource, AggregateOperation,
    AggregateOperationLimits, AggregateResource, AggregateRunLimits, BuildLimits, PlanKind,
    PlanSelection, PortableBuilder, PortableFindIterError, PortableFindIterLimits, PortableRegex,
    RustProfile, SearchLimits, SearchSessionLimits,
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
            actual.selector_report().cache_identity().operation,
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
fn every_pinned_bytes_split_doctest_passes_through_portable_regex() {
    for case in doctest_cases() {
        let regex = PortableRegex::new(case.pattern).unwrap_or_else(|error| {
            panic!(
                "portable upstream split case {} failed to build from {UPSTREAM_PATH} at \
                 {UPSTREAM_REVISION} ({UPSTREAM_SHA256}): {error}",
                case.id
            )
        });
        let mut actual = match case.limit {
            None => regex.split(case.haystack, PortableFindIterLimits::unlimited()),
            Some(limit) => regex.splitn(case.haystack, limit, PortableFindIterLimits::unlimited()),
        }
        .unwrap_or_else(|error| {
            panic!(
                "portable upstream split case {} failed to prepare: {error}",
                case.id
            )
        });
        let fields: Vec<_> = actual
            .by_ref()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| {
                panic!(
                    "portable upstream split case {} failed to execute: {error}",
                    case.id
                )
            });
        assert_eq!(fields, case.expected, "case {}", case.id);
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
            max_output_matches: 4,
            ..AggregateOperationLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let fields = regex.split(b"XXX", exact).expect("exact selector limit");
    assert_eq!(fields.selected_matches(), 3);
    assert_eq!(fields.len(), 4);

    let below = AggregateRunLimits {
        continuation: AggregateOperationLimits {
            max_output_matches: 3,
            ..AggregateOperationLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex
        .split(b"XXX", below)
        .expect_err("one below the published selector bound must fail");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputMatches,
            required: 4,
            limit: 3,
        })
    ));
}

#[derive(Clone, Copy, Debug)]
struct PortableSplitCase {
    pattern: &'static str,
    unicode: bool,
    selection: PlanSelection,
    force_literal_set_dfa: bool,
    expected_plan: PlanKind,
}

#[test]
fn portable_split_and_splitn_match_pinned_bytes_across_every_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"abab",
        b"xxfoobaz-alphaZ-Sherlock",
        " αβ ab 雪_42 ".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0x80],
    ];
    let limits = [0, 1, 2, 3, usize::MAX];

    for case in portable_split_cases() {
        let fre = build_portable_split_case(case);
        assert_eq!(fre.build_report().plan, case.expected_plan, "{case:?}");
        let mut upstream = regex::bytes::RegexBuilder::new(case.pattern);
        upstream.unicode(case.unicode);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {case:?}: {error}"));

        for &haystack in haystacks {
            let expected: Vec<_> = upstream.split(haystack).collect();
            let mut actual = fre
                .split(haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("portable split setup failed for {case:?}: {error}")
                });
            let fields: Vec<_> = actual
                .by_ref()
                .collect::<Result<_, _>>()
                .unwrap_or_else(|error| panic!("portable split failed for {case:?}: {error}"));
            assert_eq!(
                fields, expected,
                "split case={case:?}, haystack={haystack:?}"
            );
            assert!(actual.accounting().matches <= fields.len());
            assert!(actual.next().is_none(), "completed split must fuse");

            for limit in limits {
                let expected: Vec<_> = upstream.splitn(haystack, limit).collect();
                let mut actual = fre
                    .splitn(haystack, limit, PortableFindIterLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("portable splitn setup failed for {case:?}/{limit}: {error}")
                    });
                assert_eq!(actual.size_hint().1, Some(limit));
                let fields: Vec<_> =
                    actual
                        .by_ref()
                        .collect::<Result<_, _>>()
                        .unwrap_or_else(|error| {
                            panic!("portable splitn failed for {case:?}/{limit}: {error}")
                        });
                assert_eq!(
                    fields, expected,
                    "splitn case={case:?}, haystack={haystack:?}, limit={limit}"
                );
                assert!(actual.next().is_none(), "completed splitn must fuse");
            }
        }
    }
}

#[test]
fn portable_split_limits_fail_visibly_and_trivial_splitn_does_no_search() {
    let regex = PortableBuilder::new("(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable K0 split regex");
    let mut probe = regex
        .split(b"abab", PortableFindIterLimits::unlimited())
        .expect("unlimited split setup");
    let probe_fields: Vec<_> = probe
        .by_ref()
        .collect::<Result<_, _>>()
        .expect("unlimited split execution");
    assert_eq!(probe_fields, vec![b"".as_slice(), b"".as_slice()]);
    let probe_accounting = probe.accounting();
    assert!(probe_accounting.search_calls > probe_accounting.matches);
    assert!(probe.workspace_setup_accounting().is_some());

    let below_limits = PortableFindIterLimits {
        max_search_calls: probe_accounting.search_calls - 1,
        ..PortableFindIterLimits::unlimited()
    };
    let mut below = regex
        .split(b"abab", below_limits)
        .expect("below-limit split setup");
    assert_eq!(below.next(), Some(Ok(b"".as_slice())));
    assert_eq!(
        below.next(),
        Some(Err(PortableFindIterError::SearchCallLimit {
            needed: probe_accounting.search_calls,
            limit: probe_accounting.search_calls - 1,
        }))
    );
    assert!(below.next().is_none(), "resource refusal must fuse split");

    let no_search = PortableFindIterLimits {
        session: SearchSessionLimits {
            max_setup_work: 0,
            max_scratch_bytes: 0,
        },
        search: SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        },
        max_search_calls: 0,
    };
    let zero: Vec<_> = regex
        .splitn(b"abab", 0, no_search)
        .expect("zero fields require no search setup")
        .collect::<Result<_, _>>()
        .expect("zero fields require no search execution");
    assert!(zero.is_empty());

    let mut one = regex
        .splitn(b"abab", 1, no_search)
        .expect("one field requires no search setup");
    assert!(one.workspace_setup_accounting().is_none());
    assert_eq!(one.accounting().search_calls, 0);
    assert_eq!(one.next(), Some(Ok(b"abab".as_slice())));
    assert!(one.next().is_none());
    assert!(regex.split(b"abab", no_search).is_err());
}

fn portable_split_cases() -> [PortableSplitCase; 8] {
    [
        PortableSplitCase {
            pattern: "ab",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::ExactLiteral,
        },
        PortableSplitCase {
            pattern: "a|ab",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::PackedLiteralSet,
        },
        PortableSplitCase {
            pattern: "foobar|foobaz|fooquux",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: true,
            expected_plan: PlanKind::LiteralSetDfa,
        },
        PortableSplitCase {
            pattern: "[a-z]+Z",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::RequiredLiteral,
        },
        PortableSplitCase {
            pattern: r"\A[a-z]+Z",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::ForwardAnchored,
        },
        PortableSplitCase {
            pattern: r"\b\w{2,}\b",
            unicode: true,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::UnicodeWordRun,
        },
        PortableSplitCase {
            pattern: "(?:ab)+",
            unicode: false,
            selection: PlanSelection::ForceK0,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::K0,
        },
        PortableSplitCase {
            pattern: "",
            unicode: false,
            selection: PlanSelection::ForceK0,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::K0,
        },
    ]
}

fn build_portable_split_case(case: PortableSplitCase) -> PortableRegex {
    let limits = if case.force_literal_set_dfa {
        BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        }
    } else {
        BuildLimits::default()
    };
    PortableBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .unicode(case.unicode)
        .limits(limits)
        .plan_selection(case.selection)
        .build()
        .unwrap_or_else(|error| panic!("portable regex rejected {case:?}: {error}"))
}
