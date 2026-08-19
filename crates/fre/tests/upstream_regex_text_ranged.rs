#![forbid(unsafe_code)]

use fre::{
    BuildLimits, PlanKind, PlanSelection, PortableTextBuilder, PortableTextRegex,
    PortableTextSearchError, RustProfile, SearchLimits, SearchSessionLimits, SearchWindow,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/string.rs";
const UPSTREAM_SHA256: &str = "9f7686e10535fe385a767063132d39ee1a1af1a20a119d78df479f110822e274";
const UPSTREAM_API_IDS: &[&str] = &["string_regex_is_match_at", "string_regex_find_at"];

#[test]
fn authenticated_text_ranged_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/string.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(
        UPSTREAM_API_IDS,
        ["string_regex_is_match_at", "string_regex_find_at"]
    );
}

#[test]
fn text_ranged_search_preserves_original_assertion_context() {
    let pattern = r"\bchew\b";
    let haystack = "eschew";
    let fre = PortableTextBuilder::new(pattern)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable contextual text regex");
    let upstream = regex::Regex::new(pattern).expect("pinned contextual text regex");

    assert_eq!(
        upstream.find(&haystack[2..]).map(|matched| matched.range()),
        Some(0..4)
    );
    assert_eq!(upstream.find_at(haystack, 2), None);
    assert!(!upstream.is_match_at(haystack, 2));
    assert_eq!(
        fre.find_at(haystack, 2, SearchLimits::unlimited())
            .expect("contextual text span search")
            .0,
        None
    );
    assert!(
        !fre.is_match_at(haystack, 2, SearchLimits::unlimited())
            .expect("contextual text existence search")
            .0
    );
}

#[test]
fn text_value_singletons_and_sessions_match_accounted_and_pinned_searches() {
    let cases = [
        (
            PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .expect("forced K0 text regex"),
            regex::Regex::new(r"(?:αβ|γδ)+Z").expect("pinned K0 oracle"),
            PlanKind::K0,
        ),
        (
            PortableTextRegex::new("東京").expect("native text regex"),
            regex::Regex::new("東京").expect("pinned native oracle"),
            PlanKind::ExactLiteral,
        ),
    ];
    let haystacks = ["", "xαβγδZy", "☃γδZ 東京", "none"];

    for (fre, upstream, expected_plan) in cases {
        assert_eq!(fre.build_report().portable.plan, expected_plan);
        let mut full = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("full text value session");

        for haystack in haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let accounted = fre
                .find(haystack, SearchLimits::unlimited())
                .expect("accounted text find")
                .0
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(accounted, expected);
            assert_eq!(
                fre.find_value(haystack, SearchLimits::unlimited())
                    .expect("singleton text value find")
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );
            assert_eq!(
                full.find_value(haystack, SearchLimits::unlimited())
                    .expect("session text value find")
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );

            let expected_exists = expected.is_some();
            assert_eq!(
                fre.is_match_value(haystack, SearchLimits::unlimited())
                    .expect("singleton text value existence"),
                expected_exists,
            );
            assert_eq!(
                fre.is_match(haystack, SearchLimits::unlimited())
                    .expect("accounted text existence")
                    .0,
                expected_exists,
            );
            assert_eq!(
                full.is_match_value(haystack, SearchLimits::unlimited())
                    .expect("session text value existence"),
                expected_exists,
            );
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    fre.find_at_value(haystack, start, SearchLimits::unlimited())
                        .expect("singleton ranged text value find")
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={:?}, haystack={haystack:?}, start={start}",
                    upstream.as_str(),
                );
                assert_eq!(
                    full.find_at_value(haystack, start, SearchLimits::unlimited())
                        .expect("session ranged text value find")
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={:?}, haystack={haystack:?}, start={start}",
                    upstream.as_str(),
                );
                assert_eq!(
                    fre.is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .expect("singleton ranged text value existence"),
                    upstream.is_match_at(haystack, start),
                );
                assert_eq!(
                    full.is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .expect("session ranged text value existence"),
                    upstream.is_match_at(haystack, start),
                );
            }

            let boundaries = (0..=haystack.len())
                .filter(|&offset| haystack.is_char_boundary(offset))
                .collect::<Vec<_>>();
            for &start in &boundaries {
                for &end in boundaries.iter().filter(|&&end| end >= start) {
                    let window = SearchWindow::new(start, end);
                    let expected = fre
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .expect("accounted text window")
                        .0;
                    assert_eq!(
                        fre.find_window_value(haystack, window, SearchLimits::unlimited())
                            .expect("singleton text value window"),
                        expected,
                    );
                    assert_eq!(
                        full.find_window_value(haystack, window, SearchLimits::unlimited())
                            .expect("session text value window"),
                        expected,
                    );
                }
            }
        }
    }
}

#[test]
fn text_value_searches_preserve_utf8_validation_context_and_finite_refusal() {
    let regex = PortableTextBuilder::new(r"\b(?:αβ)+Z\b")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("contextual K0 text regex");
    let haystack = "☃ αβZ αβZ";
    let expected = regex::Regex::new(r"\b(?:αβ)+Z\b")
        .expect("pinned contextual oracle")
        .find_at(haystack, 1)
        .map(|matched| matched.range());
    assert_eq!(
        regex
            .find_at_value(haystack, 1, SearchLimits::unlimited())
            .expect("interior-offset value search")
            .map(fre::Match::range),
        expected,
    );

    let invalid = SearchWindow::new(1, haystack.len());
    let expected_error = regex
        .find_window(haystack, invalid, SearchLimits::unlimited())
        .expect_err("accounted API rejects an interior UTF-8 window");
    assert_eq!(
        regex
            .find_window_value(haystack, invalid, SearchLimits::unlimited())
            .expect_err("value API rejects an interior UTF-8 window"),
        expected_error,
    );
    assert!(matches!(
        &expected_error,
        PortableTextSearchError::InvalidUtf8Window {
            start: 1,
            haystack_len,
            ..
        } if *haystack_len == haystack.len()
    ));

    let zero = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(regex.find_value(haystack, zero).is_err());
    assert!(regex.is_match_value(haystack, zero).is_err());
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("text refusal session");
    assert_eq!(
        session
            .find_window_value(haystack, invalid, SearchLimits::unlimited())
            .expect_err("session rejects an interior UTF-8 window"),
        expected_error,
    );
    assert!(session.find_value(haystack, zero).is_err());
    assert!(session.is_match_value(haystack, zero).is_err());
}

#[test]
fn text_ranged_search_matches_pinned_upstream_across_every_portable_plan() {
    let haystacks = [
        "",
        "ab",
        "zababx",
        "xxfoobaz-alphaZ-Sherlock",
        "--αβγ--",
        "雪 ab 東京Z Sherlock",
    ];

    for (fre, upstream, expected_plan) in ranged_cases() {
        assert_eq!(fre.build_report().portable.plan, expected_plan);
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream.find_at(haystack, start);
                let expected_span = expected.map(|matched| (matched.start(), matched.end()));
                let (actual, find_accounting) = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "find_at failed for {:?}/{haystack:?}/{start}: {error}",
                            upstream.as_str()
                        )
                    });
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected_span,
                    "pattern={:?}, haystack={haystack:?}, start={start}",
                    upstream.as_str()
                );
                assert_eq!(find_accounting.plan(), expected_plan);

                let (exists, exists_accounting) = fre
                    .is_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "is_match_at failed for {:?}/{haystack:?}/{start}: {error}",
                            upstream.as_str()
                        )
                    });
                assert_eq!(exists, upstream.is_match_at(haystack, start));
                assert_eq!(exists, expected_span.is_some());
                assert_eq!(exists_accounting.plan(), expected_plan);
            }
        }
    }
}

fn ranged_cases() -> Vec<(PortableTextRegex, regex::Regex, PlanKind)> {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    vec![
        case("", PlanKind::ExactLiteral, PlanSelection::Auto),
        case("Sherlock", PlanKind::ExactLiteral, PlanSelection::Auto),
        case("a|ab", PlanKind::PackedLiteralSet, PlanSelection::Auto),
        (
            PortableTextBuilder::new("foobar|foobaz|fooquux")
                .limits(dfa_limits)
                .build()
                .expect("text literal-set DFA"),
            regex::Regex::new("foobar|foobaz|fooquux").expect("pinned literal-set DFA"),
            PlanKind::LiteralSetDfa,
        ),
        ascii_case(
            "[a-z]+Z",
            PlanKind::RequiredLiteral,
            PlanSelection::ForceRequiredLiteral,
        ),
        ascii_case(
            r"\A[a-z]+Z",
            PlanKind::ForwardAnchored,
            PlanSelection::ForceForwardAnchored,
        ),
        case("(?:ab)+", PlanKind::K0, PlanSelection::ForceK0),
        case(r"\b\w{2,}\b", PlanKind::UnicodeWordRun, PlanSelection::Auto),
    ]
}

fn case(
    pattern: &str,
    expected_plan: PlanKind,
    selection: PlanSelection,
) -> (PortableTextRegex, regex::Regex, PlanKind) {
    (
        PortableTextBuilder::new(pattern)
            .plan_selection(selection)
            .build()
            .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}")),
        regex::Regex::new(pattern)
            .unwrap_or_else(|error| panic!("pinned build failed for {pattern:?}: {error}")),
        expected_plan,
    )
}

fn ascii_case(
    pattern: &str,
    expected_plan: PlanKind,
    selection: PlanSelection,
) -> (PortableTextRegex, regex::Regex, PlanKind) {
    (
        PortableTextBuilder::new(pattern)
            .unicode(false)
            .plan_selection(selection)
            .build()
            .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}")),
        regex::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned build failed for {pattern:?}: {error}")),
        expected_plan,
    )
}
