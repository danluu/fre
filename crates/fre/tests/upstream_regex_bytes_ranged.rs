#![forbid(unsafe_code)]

use fre::{
    BuildLimits, ByteMatch, K0SearchError, Match, PlanKind, PlanSelection, PortableBuilder,
    PortableRegex, RustProfile, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
    SearchWindow,
};
use regex::bytes::{Regex, RegexBuilder};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_SHA256: &str = "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_API_IDS: &[&str] = &[
    "bytes_regex_is_match_at",
    "bytes_regex_find_at",
    "bytes_regex_find_at_borrowed_match",
];

#[test]
fn authenticated_bytes_ranged_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 3);
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
        fre.is_match_accounted(sliced, SearchLimits::unlimited())
            .expect("sliced existence search")
            .0
    );
    assert_eq!(
        span(
            fre.find_accounted(sliced, SearchLimits::unlimited())
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
    assert_eq!(
        fre.find_at_value(haystack, 2, SearchLimits::unlimited())
            .expect("contextual value-only span search"),
        None
    );
    assert_eq!(
        fre.find_window_value(
            haystack,
            SearchWindow::new(2, haystack.len()),
            SearchLimits::unlimited(),
        )
        .expect("contextual value-only windowed span search"),
        None
    );
    assert_eq!(
        fre.find_at_borrowed(haystack, 2, SearchLimits::unlimited())
            .expect("contextual borrowed search")
            .0,
        None
    );
    assert_eq!(
        fre.find_at_borrowed_value(haystack, 2, SearchLimits::unlimited())
            .expect("contextual borrowed value search"),
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
    assert_eq!(
        session
            .find_at_value(haystack, 2, SearchLimits::unlimited())
            .expect("reused contextual value-only span search"),
        None
    );
    assert_eq!(
        session
            .find_window_value(
                haystack,
                SearchWindow::new(2, haystack.len()),
                SearchLimits::unlimited(),
            )
            .expect("reused contextual value-only windowed span search"),
        None
    );
    assert_eq!(
        session
            .find_at_borrowed(haystack, 2, SearchLimits::unlimited())
            .expect("reused contextual borrowed search")
            .0,
        None
    );
    assert_eq!(
        session
            .find_at_borrowed_value(haystack, 2, SearchLimits::unlimited())
            .expect("reused contextual borrowed value search"),
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
            let expected_full = upstream
                .find(haystack)
                .map(|matched| (matched.range(), matched.as_bytes()));
            let immutable_full_value = fre
                .find_borrowed_value(haystack, SearchLimits::unlimited())
                .expect("immutable full borrowed value search");
            assert_eq!(borrowed(immutable_full_value), expected_full);
            let (reused_full, reused_full_accounting) = session
                .find_borrowed(haystack, SearchLimits::unlimited())
                .expect("reused full borrowed search");
            assert_eq!(borrowed(reused_full), expected_full);
            assert_accounting_plan(&reused_full_accounting, expected_plan);
            let reused_full_value = session
                .find_borrowed_value(haystack, SearchLimits::unlimited())
                .expect("reused full borrowed value search");
            assert_eq!(borrowed(reused_full_value), expected_full);

            for start in 0..=haystack.len() {
                let expected_match = upstream.find_at(haystack, start);
                let expected = expected_match.map(|matched| (matched.start(), matched.end()));
                let expected_borrowed =
                    expected_match.map(|matched| (matched.range(), matched.as_bytes()));
                let (actual, find_accounting) = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "find_at failed for {:?}/{haystack:?}/{start}: {error}",
                            fre.as_str()
                        )
                    });
                let (actual_borrowed, borrowed_accounting) = fre
                    .find_at_borrowed(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "find_at_borrowed failed for {:?}/{haystack:?}/{start}: {error}",
                            fre.as_str()
                        )
                    });
                let actual_borrowed_value = fre
                    .find_at_borrowed_value(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "find_at_borrowed_value failed for {:?}/{haystack:?}/{start}: {error}",
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
                assert_eq!(borrowed(actual_borrowed), expected_borrowed);
                assert_eq!(borrowed(actual_borrowed_value), expected_borrowed);
                assert_eq!(borrowed_accounting, find_accounting);
                assert_accounting_plan(&find_accounting, expected_plan);
                assert_accounting_plan(&exists_accounting, expected_plan);

                let reused_find = session
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged span search");
                let reused_exists = session
                    .is_match_at(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged existence search");
                let reused_borrowed = session
                    .find_at_borrowed(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged borrowed search");
                let reused_borrowed_value = session
                    .find_at_borrowed_value(haystack, start, SearchLimits::unlimited())
                    .expect("reused ranged borrowed value search");
                assert_eq!(span(reused_find.0), expected);
                assert_eq!(reused_exists.0, exists);
                assert_eq!(borrowed(reused_borrowed.0), expected_borrowed);
                assert_eq!(borrowed(reused_borrowed_value), expected_borrowed);
                assert_eq!(reused_borrowed.1, reused_find.1);
                assert_accounting_plan(&reused_find.1, expected_plan);
                assert_accounting_plan(&reused_exists.1, expected_plan);
            }
        }
    }
}

#[test]
fn value_only_existence_matches_pinned_bytes_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"xxfoobaz-alphaZ-Sherlock",
        "--αβγ--".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0xFF],
    ];

    for (fre, upstream, expected_plan) in ranged_cases() {
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("portable value-only existence session");
        for &haystack in haystacks {
            let expected = upstream.is_match(haystack);
            assert_eq!(
                fre.is_match_value(haystack, SearchLimits::unlimited()),
                Ok(expected),
                "cold full {expected_plan:?}/{haystack:?}"
            );
            assert_eq!(
                session.is_match_value(haystack, SearchLimits::unlimited()),
                Ok(expected),
                "reused full {expected_plan:?}/{haystack:?}"
            );

            for start in 0..=haystack.len() {
                let expected = upstream.is_match_at(haystack, start);
                let window = SearchWindow::new(start, haystack.len());
                assert_eq!(
                    fre.is_match_value_at(haystack, start, SearchLimits::unlimited()),
                    Ok(expected),
                    "cold ranged {expected_plan:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    fre.is_match_window_value(haystack, window, SearchLimits::unlimited()),
                    Ok(expected),
                    "cold windowed {expected_plan:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    session.is_match_value_at(haystack, start, SearchLimits::unlimited()),
                    Ok(expected),
                    "reused ranged {expected_plan:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    session.is_match_window_value(haystack, window, SearchLimits::unlimited()),
                    Ok(expected),
                    "reused windowed {expected_plan:?}/{haystack:?}/{start}"
                );
            }
        }
    }
}

#[test]
fn value_only_existence_preserves_plan_resource_refusals() {
    let haystack = b"xxfoobaz-alphaZ-Sherlock";
    let limits = SearchLimits {
        max_work: 0,
        max_scratch_bytes: 0,
    };

    for (fre, _, expected_plan) in ranged_cases() {
        let reporting = fre
            .is_match_accounted(haystack, limits)
            .map(|(matched, _)| matched);
        let value_only = fre.is_match_value(haystack, limits);
        assert_eq!(value_only, reporting, "cold {expected_plan:?}");

        let mut reporting_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("reporting resource-parity session");
        let mut value_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("value-only resource-parity session");
        let reporting = reporting_session
            .is_match(haystack, limits)
            .map(|(matched, _)| matched);
        let value_only = value_session.is_match_value(haystack, limits);
        assert_eq!(value_only, reporting, "reused {expected_plan:?}");
    }
}

#[test]
fn value_only_find_matches_reporting_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"xxfoobaz-alphaZ-Sherlock",
        "--αβγ--".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0xFF],
    ];

    for (fre, upstream, expected_plan) in ranged_cases() {
        for &haystack in haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                fre.find_value(haystack, SearchLimits::unlimited())
                    .map(span),
                Ok(expected),
                "cold full {expected_plan:?}/{haystack:?}"
            );

            let mut reporting_session = fre
                .search_session(SearchSessionLimits::unlimited())
                .expect("fresh reporting full-span session");
            let mut value_session = fre
                .search_session(SearchSessionLimits::unlimited())
                .expect("fresh value-only full-span session");
            let reporting = reporting_session
                .find(haystack, SearchLimits::unlimited())
                .map(|(matched, _)| matched);
            let value_only = value_session.find_value(haystack, SearchLimits::unlimited());
            assert_eq!(value_only, reporting, "reused full {expected_plan:?}");
            assert_eq!(value_only.map(span), Ok(expected));

            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let window = SearchWindow::new(start, haystack.len());
                assert_eq!(
                    fre.find_at_value(haystack, start, SearchLimits::unlimited())
                        .map(span),
                    Ok(expected),
                    "cold ranged {expected_plan:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    fre.find_window_value(haystack, window, SearchLimits::unlimited())
                        .map(span),
                    Ok(expected),
                    "cold windowed {expected_plan:?}/{haystack:?}/{start}"
                );

                let mut reporting_session = fre
                    .search_session(SearchSessionLimits::unlimited())
                    .expect("fresh reporting ranged session");
                let mut value_session = fre
                    .search_session(SearchSessionLimits::unlimited())
                    .expect("fresh value-only ranged session");
                let reporting = reporting_session
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .map(|(matched, _)| matched);
                let value_only =
                    value_session.find_at_value(haystack, start, SearchLimits::unlimited());
                assert_eq!(
                    value_only, reporting,
                    "reused ranged {expected_plan:?}/{haystack:?}/{start}"
                );
                assert_eq!(value_only.map(span), Ok(expected));

                let mut reporting_session = fre
                    .search_session(SearchSessionLimits::unlimited())
                    .expect("fresh reporting windowed session");
                let mut value_session = fre
                    .search_session(SearchSessionLimits::unlimited())
                    .expect("fresh value-only windowed session");
                let reporting = reporting_session
                    .find_window(haystack, window, SearchLimits::unlimited())
                    .map(|(matched, _)| matched);
                let value_only =
                    value_session.find_window_value(haystack, window, SearchLimits::unlimited());
                assert_eq!(
                    value_only, reporting,
                    "reused windowed {expected_plan:?}/{haystack:?}/{start}"
                );
            }
        }
    }
}

#[test]
fn value_only_find_preserves_plan_resource_refusals_from_fresh_state() {
    let haystack = b"xxfoobaz-alphaZ-Sherlock";
    let window = SearchWindow::new(2, haystack.len());
    let limits = SearchLimits {
        max_work: 0,
        max_scratch_bytes: 0,
    };

    for (fre, _, expected_plan) in ranged_cases() {
        let reporting = fre
            .find_window(haystack, window, limits)
            .map(|(matched, _)| matched);
        let value_only = fre.find_window_value(haystack, window, limits);
        assert_eq!(value_only, reporting, "cold {expected_plan:?}");

        let mut reporting_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("fresh reporting resource-parity session");
        let mut value_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("fresh value-only resource-parity session");
        let reporting = reporting_session
            .find_window(haystack, window, limits)
            .map(|(matched, _)| matched);
        let value_only = value_session.find_window_value(haystack, window, limits);
        assert_eq!(value_only, reporting, "reused {expected_plan:?}");
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
        fre.find_at_borrowed(haystack, start, SearchLimits::unlimited())
            .expect_err("cold find_at_borrowed must reject an out-of-bounds start"),
        fre.find_at_borrowed_value(haystack, start, SearchLimits::unlimited())
            .expect_err("cold borrowed-value find_at must reject an out-of-bounds start"),
        fre.find_at_value(haystack, start, SearchLimits::unlimited())
            .expect_err("cold value-only find_at must reject an out-of-bounds start"),
        fre.find_window_value(
            haystack,
            SearchWindow::new(start, haystack.len()),
            SearchLimits::unlimited(),
        )
        .expect_err("cold value-only find window must reject an out-of-bounds start"),
        fre.is_match_at(haystack, start, SearchLimits::unlimited())
            .expect_err("cold is_match_at must reject an out-of-bounds start"),
        fre.is_match_value_at(haystack, start, SearchLimits::unlimited())
            .expect_err("cold value-only is_match_at must reject an out-of-bounds start"),
        fre.is_match_window_value(
            haystack,
            SearchWindow::new(start, haystack.len()),
            SearchLimits::unlimited(),
        )
        .expect_err("cold value-only window must reject an out-of-bounds start"),
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
        session.find_at_borrowed(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
    assert!(matches!(
        session.find_at_borrowed_value(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
    assert!(matches!(
        session.find_at_value(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
    assert!(matches!(
        session.find_window_value(
            haystack,
            SearchWindow::new(start, haystack.len()),
            SearchLimits::unlimited(),
        ),
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
    assert!(matches!(
        session.is_match_value_at(haystack, start, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 3,
            end: 2,
            haystack_len: 2,
        }))
    ));
    assert!(matches!(
        session.is_match_window_value(
            haystack,
            SearchWindow::new(start, haystack.len()),
            SearchLimits::unlimited(),
        ),
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

fn borrowed(matched: Option<ByteMatch<'_>>) -> Option<(core::ops::Range<usize>, &[u8])> {
    matched.map(|matched| (matched.range(), matched.as_bytes()))
}

fn assert_accounting_plan(accounting: &SearchAccounting, expected: PlanKind) {
    assert_eq!(accounting.plan(), expected);
}
