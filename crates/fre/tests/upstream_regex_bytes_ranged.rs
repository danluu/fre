#![forbid(unsafe_code)]

use fre::{
    BuildLimits, K0SearchError, Match, PlanKind, PlanSelection, PortableBuilder, PortableRegex,
    RustProfile, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
};
use regex::bytes::{Regex, RegexBuilder};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_SHA256: &str = "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_API_IDS: &[&str] = &["bytes_regex_is_match_at", "bytes_regex_find_at"];

#[test]
fn authenticated_bytes_ranged_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 2);
}

#[test]
fn pinned_ranged_search_examples_preserve_original_haystack_context() {
    let pattern = r"\bchew\b";
    let haystack = b"eschew";
    let fre = portable(pattern, false, PlanSelection::ForceK0);
    let upstream = pinned(pattern, false);

    let sliced = &haystack[2..];
    assert!(upstream.is_match(sliced));
    assert_eq!(
        upstream.find(sliced).map(|matched| matched.range()),
        Some(0..4)
    );
    assert!(
        fre.is_match(sliced, SearchLimits::unlimited())
            .expect("sliced existence search")
            .0
    );
    assert_eq!(
        span(
            fre.find(sliced, SearchLimits::unlimited())
                .expect("sliced span search")
                .0
        ),
        Some((0, 4))
    );

    assert!(!upstream.is_match_at(haystack, 2));
    assert_eq!(upstream.find_at(haystack, 2), None);
    assert!(
        !fre.is_match_at(haystack, 2, SearchLimits::unlimited())
            .expect("contextual existence search")
            .0
    );
    assert_eq!(
        fre.find_at(haystack, 2, SearchLimits::unlimited())
            .expect("contextual span search")
            .0,
        None
    );

    let mut session = fre
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable K0 session");
    assert!(
        !session
            .is_match_at(haystack, 2, SearchLimits::unlimited())
            .expect("reused contextual existence search")
            .0
    );
    assert_eq!(
        session
            .find_at(haystack, 2, SearchLimits::unlimited())
            .expect("reused contextual span search")
            .0,
        None
    );
}

#[test]
fn ranged_search_matches_pinned_bytes_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"xxfoobaz-alphaZ-Sherlock",
        b"zababx",
        "--αβγ--".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0xFF],
    ];

    for (fre, upstream, expected_plan) in ranged_cases() {
        assert_eq!(fre.build_report().plan, expected_plan);
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("portable ranged-search session");
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, find_accounting) = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "find_at failed for {:?}/{haystack:?}/{start}: {error}",
                            fre.as_str()
                        )
                    });
                let (exists, exists_accounting) = fre
                    .is_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "is_match_at failed for {:?}/{haystack:?}/{start}: {error}",
                            fre.as_str()
                        )
                    });
                assert_eq!(
                    span(actual),
                    expected,
                    "{:?}/{haystack:?}/{start}",
                    fre.as_str()
                );
                assert_eq!(exists, upstream.is_match_at(haystack, start));
                assert_eq!(exists, expected.is_some());
                assert_accounting_plan(&find_accounting, expected_plan);
                assert_accounting_plan(&exists_accounting, expected_plan);

                let reused_find = session
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged span search");
                let reused_exists = session
                    .is_match_at(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged existence search");
                assert_eq!(span(reused_find.0), expected);
                assert_eq!(reused_exists.0, exists);
                assert_accounting_plan(&reused_find.1, expected_plan);
                assert_accounting_plan(&reused_exists.1, expected_plan);
            }
        }
    }
}

#[test]
fn out_of_bounds_start_is_a_typed_cold_and_reused_error() {
    let fre = portable("(?:ab)+", false, PlanSelection::ForceK0);
    let haystack = b"ab";
    let start = haystack.len() + 1;

    for error in [
        fre.find_at(haystack, start, SearchLimits::unlimited())
            .expect_err("cold find_at must reject an out-of-bounds start"),
        fre.is_match_at(haystack, start, SearchLimits::unlimited())
            .expect_err("cold is_match_at must reject an out-of-bounds start"),
    ] {
        assert!(matches!(
            error,
            SearchError::K0(K0SearchError::InvalidWindow {
                start: 3,
                end: 2,
                haystack_len: 2,
            })
        ));
    }

    let mut session = fre
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable K0 session");
    assert!(matches!(
        session.find_at(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
    assert!(matches!(
        session.is_match_at(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
}

fn portable(pattern: &str, unicode: bool, selection: PlanSelection) -> PortableRegex {
    PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(unicode)
        .plan_selection(selection)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn pinned(pattern: &str, unicode: bool) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(unicode)
        .build()
        .unwrap_or_else(|error| panic!("pinned build failed for {pattern:?}: {error}"))
}

fn case(
    pattern: &str,
    unicode: bool,
    expected_plan: PlanKind,
    selection: PlanSelection,
) -> (PortableRegex, Regex, PlanKind) {
    (
        portable(pattern, unicode, selection),
        pinned(pattern, unicode),
        expected_plan,
    )
}

fn ranged_cases() -> Vec<(PortableRegex, Regex, PlanKind)> {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    vec![
        case("", false, PlanKind::ExactLiteral, PlanSelection::Auto),
        case(
            "Sherlock",
            false,
            PlanKind::ExactLiteral,
            PlanSelection::Auto,
        ),
        case(
            "a|ab",
            false,
            PlanKind::PackedLiteralSet,
            PlanSelection::Auto,
        ),
        (
            PortableBuilder::new("foobar|foobaz|fooquux")
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
                .limits(dfa_limits)
                .build()
                .expect("literal-set DFA"),
            pinned("foobar|foobaz|fooquux", false),
            PlanKind::LiteralSetDfa,
        ),
        case(
            "[a-z]+Z",
            false,
            PlanKind::RequiredLiteral,
            PlanSelection::Auto,
        ),
        case(
            r"\A[a-z]+Z",
            false,
            PlanKind::ForwardAnchored,
            PlanSelection::Auto,
        ),
        case("(?:ab)+", false, PlanKind::K0, PlanSelection::ForceK0),
        case(
            r"\b\w{2,}\b",
            true,
            PlanKind::UnicodeWordRun,
            PlanSelection::Auto,
        ),
    ]
}

fn span(matched: Option<Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

fn assert_accounting_plan(accounting: &SearchAccounting, expected: PlanKind) {
    assert_eq!(accounting.plan(), expected);
}
