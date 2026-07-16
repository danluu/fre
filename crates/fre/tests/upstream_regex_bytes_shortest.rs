#![forbid(unsafe_code)]

use fre::{
    BuildLimits, K0SearchError, PlanKind, PlanSelection, PortableBuilder, PortableRegex,
    RustProfile, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
};
use regex::bytes::{Regex, RegexBuilder};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_SHA256: &str = "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_API_IDS: &[&str] = &[
    "bytes_regex_shortest_match",
    "bytes_regex_shortest_match_at",
];

#[test]
fn authenticated_bytes_shortest_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 2);
}

#[test]
fn pinned_shortest_examples_distinguish_earliest_accept_and_context() {
    let greedy = portable("a+", false, PlanSelection::ForceK0);
    assert_eq!(
        greedy
            .shortest_match(b"aaaaa", SearchLimits::unlimited())
            .expect("earliest greedy end")
            .0,
        Some(1)
    );
    assert_eq!(
        greedy
            .find(b"aaaaa", SearchLimits::unlimited())
            .expect("selected greedy span")
            .0
            .map(fre::Match::end),
        Some(5)
    );

    let contextual = portable(r"\bchew\b", false, PlanSelection::ForceK0);
    let haystack = b"eschew";
    assert_eq!(
        contextual
            .shortest_match(&haystack[2..], SearchLimits::unlimited())
            .expect("sliced shortest search")
            .0,
        Some(4)
    );
    assert_eq!(
        contextual
            .shortest_match_at(haystack, 2, SearchLimits::unlimited())
            .expect("contextual shortest search")
            .0,
        None
    );
}

#[test]
fn shortest_match_matches_pinned_bytes_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"abcd",
        b"ababx",
        b"zzab",
        b"xxfoobaz-alphaZ-Sherlock",
        "--αβγ--".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0xFF],
    ];
    let mut saw_earliest_selected_difference = false;

    for (fre, upstream, expected_plan) in shortest_cases() {
        assert_eq!(fre.build_report().plan, expected_plan, "{:?}", fre.as_str());
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("portable shortest-search session");
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream.shortest_match_at(haystack, start);
                let selected_end = upstream
                    .find_at(haystack, start)
                    .map(|matched| matched.end());
                saw_earliest_selected_difference |= expected != selected_end;

                let (actual, accounting) = fre
                    .shortest_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "shortest_match_at failed for {:?}/{haystack:?}/{start}: {error}",
                            fre.as_str()
                        )
                    });
                assert_eq!(
                    actual,
                    expected,
                    "pattern={:?}, haystack={haystack:?}, start={start}",
                    fre.as_str()
                );
                assert_accounting_plan(&accounting, expected_plan);

                let (reused, reused_accounting) = session
                    .shortest_match_at(haystack, start, SearchLimits::unlimited())
                    .expect("reused shortest search");
                assert_eq!(reused, expected);
                assert_accounting_plan(&reused_accounting, expected_plan);
            }

            let expected = upstream.shortest_match(haystack);
            assert_eq!(
                fre.shortest_match(haystack, SearchLimits::unlimited())
                    .expect("full shortest search")
                    .0,
                expected
            );
            assert_eq!(
                session
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .expect("reused full shortest search")
                    .0,
                expected
            );
        }
    }
    assert!(saw_earliest_selected_difference);
}

#[test]
fn earliest_k0_matches_pinned_bytes_exhaustively_on_small_greedy_languages() {
    let patterns = [
        "a+",
        "(?:ab)+",
        "a+b",
        "(?:ab|a)+",
        "[ab]+c",
        "(?:a|bc)*d",
        r"\Aa+",
        r"a+\z",
        r"\ba+\b",
    ];
    let haystacks = byte_words(b"abc", 4);
    for pattern in patterns {
        let fre = portable(pattern, false, PlanSelection::ForceK0);
        let upstream = pinned(pattern, false);
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                assert_eq!(
                    fre.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap_or_else(|error| {
                            panic!("pattern={pattern:?}, haystack={haystack:?}: {error}")
                        })
                        .0,
                    upstream.shortest_match_at(haystack, start),
                    "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                );
            }
        }
    }
}

#[test]
fn out_of_bounds_shortest_start_is_a_typed_cold_and_reused_error() {
    let fre = portable("(?:ab)+", false, PlanSelection::ForceK0);
    let haystack = b"ab";
    let start = haystack.len().checked_add(1).expect("small haystack");
    assert!(matches!(
        fre.shortest_match_at(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));

    let mut session = fre
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable K0 session");
    assert!(matches!(
        session.shortest_match_at(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
}

#[test]
fn earliest_k0_work_limit_is_exact_and_never_returns_a_partial_offset() {
    let fre = portable("(?:ab)+", false, PlanSelection::ForceK0);
    let haystack = b"zzababab";
    let (expected, accounting) = fre
        .shortest_match(haystack, SearchLimits::unlimited())
        .expect("unlimited shortest search");
    let SearchAccounting::K0(accounting) = accounting else {
        panic!("forced K0 returned native accounting");
    };
    let exact = SearchLimits {
        max_work: accounting.work(),
        max_scratch_bytes: accounting.scratch_bytes(),
    };
    assert_eq!(
        fre.shortest_match(haystack, exact)
            .expect("exact K0 shortest limits")
            .0,
        expected
    );
    let one_below = SearchLimits {
        max_work: accounting.work().checked_sub(1).expect("positive K0 work"),
        max_scratch_bytes: accounting.scratch_bytes(),
    };
    assert!(matches!(
        fre.shortest_match(haystack, one_below),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
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

fn shortest_cases() -> Vec<(PortableRegex, Regex, PlanKind)> {
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
            "ab|a",
            false,
            PlanKind::PackedLiteralSet,
            PlanSelection::Auto,
        ),
        case(
            "abcd|b",
            false,
            PlanKind::PackedLiteralSet,
            PlanSelection::Auto,
        ),
        case("a|", false, PlanKind::LiteralSetDfa, PlanSelection::Auto),
        case("|a", false, PlanKind::LiteralSetDfa, PlanSelection::Auto),
        (
            PortableBuilder::new("ab|a")
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
                .limits(dfa_limits)
                .build()
                .expect("literal-set DFA"),
            pinned("ab|a", false),
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
        case(
            r"\A[a-z]+Z\z",
            false,
            PlanKind::ForwardAnchored,
            PlanSelection::ForceForwardAnchored,
        ),
        case("(?:ab)+", false, PlanKind::K0, PlanSelection::ForceK0),
        case("a+", false, PlanKind::K0, PlanSelection::ForceK0),
        case(
            r"\b\w{2,}\b",
            true,
            PlanKind::UnicodeWordRun,
            PlanSelection::Auto,
        ),
    ]
}

fn assert_accounting_plan(accounting: &SearchAccounting, expected: PlanKind) {
    assert_eq!(accounting.plan(), expected);
}

fn byte_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut word = prefix.clone();
                word.push(byte);
                next.push(word);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}
