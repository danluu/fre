use fre::{AggregateBuilder, AggregateRunLimits, AggregateSearchStep, RustProfile};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "tests/searcher.rs";
const UPSTREAM_SHA256: &str = "04152e5c86431deec0c196d2564a11bc4ec36f14c77e8c16a2f9d1cbc9fc574e";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedStep {
    Match(usize, usize),
    Reject(usize, usize),
}

#[derive(Clone, Copy, Debug)]
struct UpstreamCase {
    id: &'static str,
    pattern: &'static str,
    haystack: &'static str,
    expected: &'static [ExpectedStep],
}

const CASES: &[UpstreamCase] = &[
    UpstreamCase {
        id: "searcher_empty_regex_empty_haystack",
        pattern: r"",
        haystack: "",
        expected: &[ExpectedStep::Match(0, 0)],
    },
    UpstreamCase {
        id: "searcher_empty_regex",
        pattern: r"",
        haystack: "ab",
        expected: &[
            ExpectedStep::Match(0, 0),
            ExpectedStep::Reject(0, 1),
            ExpectedStep::Match(1, 1),
            ExpectedStep::Reject(1, 2),
            ExpectedStep::Match(2, 2),
        ],
    },
    UpstreamCase {
        id: "searcher_empty_haystack",
        pattern: r"\d",
        haystack: "",
        expected: &[],
    },
    UpstreamCase {
        id: "searcher_one_match",
        pattern: r"\d",
        haystack: "5",
        expected: &[ExpectedStep::Match(0, 1)],
    },
    UpstreamCase {
        id: "searcher_no_match",
        pattern: r"\d",
        haystack: "a",
        expected: &[ExpectedStep::Reject(0, 1)],
    },
    UpstreamCase {
        id: "searcher_two_adjacent_matches",
        pattern: r"\d",
        haystack: "56",
        expected: &[ExpectedStep::Match(0, 1), ExpectedStep::Match(1, 2)],
    },
    UpstreamCase {
        id: "searcher_two_non_adjacent_matches",
        pattern: r"\d",
        haystack: "5a6",
        expected: &[
            ExpectedStep::Match(0, 1),
            ExpectedStep::Reject(1, 2),
            ExpectedStep::Match(2, 3),
        ],
    },
    UpstreamCase {
        id: "searcher_reject_first",
        pattern: r"\d",
        haystack: "a6",
        expected: &[ExpectedStep::Reject(0, 1), ExpectedStep::Match(1, 2)],
    },
    UpstreamCase {
        id: "searcher_one_zero_length_matches",
        pattern: r"\d*",
        haystack: "a1b2",
        expected: &[
            ExpectedStep::Match(0, 0),
            ExpectedStep::Reject(0, 1),
            ExpectedStep::Match(1, 2),
            ExpectedStep::Reject(2, 3),
            ExpectedStep::Match(3, 4),
        ],
    },
    UpstreamCase {
        id: "searcher_many_zero_length_matches",
        pattern: r"\d*",
        haystack: "a1bbb2",
        expected: &[
            ExpectedStep::Match(0, 0),
            ExpectedStep::Reject(0, 1),
            ExpectedStep::Match(1, 2),
            ExpectedStep::Reject(2, 3),
            ExpectedStep::Match(3, 3),
            ExpectedStep::Reject(3, 4),
            ExpectedStep::Match(4, 4),
            ExpectedStep::Reject(4, 5),
            ExpectedStep::Match(5, 6),
        ],
    },
    UpstreamCase {
        id: "searcher_unicode",
        pattern: r".+?",
        haystack: "Ⅰ1Ⅱ2",
        expected: &[
            ExpectedStep::Match(0, 3),
            ExpectedStep::Match(3, 4),
            ExpectedStep::Match(4, 7),
            ExpectedStep::Match(7, 8),
        ],
    },
];

const UPSTREAM_CASE_IDS: &[&str] = &[
    "searcher_empty_regex_empty_haystack",
    "searcher_empty_regex",
    "searcher_empty_haystack",
    "searcher_one_match",
    "searcher_no_match",
    "searcher_two_adjacent_matches",
    "searcher_two_non_adjacent_matches",
    "searcher_reject_first",
    "searcher_one_zero_length_matches",
    "searcher_many_zero_length_matches",
    "searcher_unicode",
];

fn canonical_step(step: AggregateSearchStep) -> ExpectedStep {
    let span = step.span();
    if step.is_match() {
        ExpectedStep::Match(span.start(), span.end())
    } else {
        ExpectedStep::Reject(span.start(), span.end())
    }
}

#[test]
fn authenticated_upstream_searcher_inventory_has_no_silent_omissions() {
    let ids: Vec<_> = CASES.iter().map(|case| case.id).collect();
    assert_eq!(ids, UPSTREAM_CASE_IDS);

    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "tests/searcher.rs");
    assert_eq!(CASES.len(), 11);
}

#[test]
fn complete_upstream_searcher_behavior_port_passes() {
    for case in CASES {
        let regex = AggregateBuilder::new(case.pattern)
            .profile(RustProfile::regex_1_12_4())
            .build_spans()
            .unwrap_or_else(|error| {
                panic!(
                    "upstream searcher case {} failed to build from {UPSTREAM_PATH} at \
                     {UPSTREAM_REVISION} ({UPSTREAM_SHA256}): {error}",
                    case.id
                )
            });
        let spans = regex
            .spans(case.haystack.as_bytes(), AggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("upstream searcher case {} failed: {error}", case.id));
        let actual: Vec<_> = spans.search_steps().map(canonical_step).collect();
        assert_eq!(actual, case.expected, "upstream searcher case {}", case.id);
    }
}
