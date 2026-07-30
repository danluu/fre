#![forbid(unsafe_code)]

use fre::{
    BuildLimits, PlanKind, PlanSelection, PortableFindIterError, PortableFindIterLimits,
    PortableTextBuilder, PortableTextRegex, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/string.rs";
const UPSTREAM_SHA256: &str = "9f7686e10535fe385a767063132d39ee1a1af1a20a119d78df479f110822e274";
const UPSTREAM_API_IDS: &[&str] = &["string_regex_find_iter"];
const UPSTREAM_DOCTEST_LINES: &[usize] = &[250];

#[test]
fn authenticated_text_find_iter_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/string.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS, ["string_regex_find_iter"]);
    assert_eq!(UPSTREAM_DOCTEST_LINES, [250]);
}

#[test]
fn text_find_iter_matches_pinned_upstream_across_portable_plans() {
    let haystacks = [
        "",
        "ab",
        "zababx",
        "xxfoobaz-alphaZ-Sherlock",
        " αβ ab 雪_42 ",
        "é\n€\n",
    ];

    for (fre, upstream, expected_plan) in differential_cases() {
        assert_eq!(fre.build_report().portable.plan, expected_plan);
        for haystack in haystacks {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let mut iterator = fre
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!(
                        "text iterator construction failed for {:?}/{haystack:?}: {error}",
                        upstream.as_str()
                    )
                });
            let actual = iterator
                .by_ref()
                .map(|matched| {
                    let matched = matched.unwrap_or_else(|error| {
                        panic!(
                            "text iteration failed for {:?}/{haystack:?}: {error}",
                            upstream.as_str()
                        )
                    });
                    (matched.start(), matched.end())
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "pattern={:?}", upstream.as_str());
            assert_eq!(iterator.accounting().matches, expected.len());
            assert!(iterator.next().is_none(), "text iterator must fuse");
        }
    }
}

#[test]
fn empty_text_iteration_uses_scalar_progress_and_exact_terminal_limits() {
    let haystack = "💩a";
    let fre = PortableTextBuilder::new("")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty text regex");
    let upstream = regex::Regex::new("").expect("pinned empty text regex");
    let expected = upstream
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    assert_eq!(expected, vec![(0, 0), (4, 4), (5, 5)]);

    let mut unlimited = fre
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .expect("unlimited text iterator construction");
    let actual = unlimited
        .by_ref()
        .map(|matched| {
            let matched = matched.expect("unlimited text iteration");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(unlimited.accounting().matches, 3);
    assert_eq!(unlimited.accounting().suppressed_empty, 3);
    assert_eq!(unlimited.accounting().search_calls, 3);
    assert_eq!(unlimited.accounting().utf8_progress_byte_probes, 4);
    assert_eq!(unlimited.accounting().utf8_progress_work, 9);
    assert!(unlimited.accounting().work_or_linear_terms >= 9);

    let exact_limits = PortableFindIterLimits {
        max_search_calls: unlimited.accounting().search_calls,
        ..PortableFindIterLimits::unlimited()
    };
    let exact = fre
        .find_iter(haystack, exact_limits)
        .expect("exact-limit text iterator")
        .map(|matched| {
            let matched = matched.expect("exact-limit text match");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(exact, expected);

    let limits = PortableFindIterLimits {
        max_search_calls: unlimited.accounting().search_calls - 1,
        ..PortableFindIterLimits::unlimited()
    };
    let mut limited = fre
        .find_iter(haystack, limits)
        .expect("limited text iterator construction");
    let emitted = limited
        .by_ref()
        .take(expected.len() - 1)
        .map(|matched| {
            let matched = matched.expect("limited text match before terminal refusal");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(emitted, expected[..expected.len() - 1]);
    assert_eq!(
        limited.next(),
        Some(Err(PortableFindIterError::SearchCallLimit {
            needed: unlimited.accounting().search_calls,
            limit: unlimited.accounting().search_calls - 1,
        }))
    );
    assert!(limited.next().is_none(), "terminal refusal must fuse");
}

#[test]
fn empty_text_iteration_charges_two_and_three_byte_scalar_progress() {
    let haystack = "é€a";
    let fre = PortableTextBuilder::new("")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty text regex");
    let mut iterator = fre
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .expect("text iterator");
    let actual = iterator
        .by_ref()
        .map(|found| {
            let found = found.expect("text match");
            (found.start(), found.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, vec![(0, 0), (2, 2), (5, 5), (6, 6)]);
    assert_eq!(iterator.accounting().suppressed_empty, 4);
    assert_eq!(iterator.accounting().utf8_progress_byte_probes, 5);
    assert_eq!(iterator.accounting().utf8_progress_work, 11);
    assert!(iterator.accounting().work_or_linear_terms >= 11);
}

fn differential_cases() -> Vec<(PortableTextRegex, regex::Regex, PlanKind)> {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    vec![
        case("Sherlock", PlanKind::ExactLiteral, PlanSelection::Auto),
        case("a|ab", PlanKind::PackedLiteralSet, PlanSelection::Auto),
        (
            PortableTextBuilder::new("foobar|foobaz|fooquux")
                .limits(dfa_limits)
                .build()
                .expect("portable text literal-set DFA"),
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
        case("(?m)^", PlanKind::K0, PlanSelection::ForceK0),
        case(r"\b\w{2,}\b", PlanKind::UnicodeWordRun, PlanSelection::Auto),
    ]
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
