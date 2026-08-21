#![forbid(unsafe_code)]

use fre::{
    Match, PlanKind, PlanSelection, PortableBuilder, PortableFindIterError, PortableFindIterLimits,
    PortableFindIterRunLimits, SearchError, SearchLimits, SearchSessionLimits,
};

fn spans(
    matches: impl Iterator<Item = Result<Match, PortableFindIterError>>,
) -> Vec<(usize, usize)> {
    matches
        .map(|matched| {
            let matched = matched.expect("value iterator match");
            (matched.start(), matched.end())
        })
        .collect()
}

fn upstream_spans_at(
    regex: &regex::bytes::Regex,
    haystack: &[u8],
    start: usize,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut next_start = start;
    let mut last_match_end = None;
    while next_start <= haystack.len() {
        let Some(matched) = regex.find_at(haystack, next_start) else {
            break;
        };
        if matched.is_empty() && last_match_end == Some(matched.end()) {
            if matched.end() == haystack.len() {
                break;
            }
            next_start = matched.end().saturating_add(1);
            continue;
        }
        spans.push((matched.start(), matched.end()));
        next_start = matched.end();
        last_match_end = Some(matched.end());
        if matched.is_empty() {
            if matched.end() == haystack.len() {
                break;
            }
            next_start = matched.end().saturating_add(1);
        }
    }
    spans
}

#[test]
fn value_iterators_start_at_every_byte_and_preserve_original_context() {
    let cases: &[(&str, bool, PlanSelection, PlanKind, &[u8])] = &[
        (
            "ab",
            false,
            PlanSelection::Auto,
            PlanKind::ExactLiteral,
            b"zzab ab",
        ),
        (
            "a|ab",
            false,
            PlanSelection::Auto,
            PlanKind::PackedLiteralSet,
            b"zzaab",
        ),
        (
            r"(?:ab[0-9]+|cd[A-Z]+)",
            false,
            PlanSelection::Auto,
            PlanKind::PrefixClassAlternation,
            b"xxab42--cdQ",
        ),
        (
            r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]",
            false,
            PlanSelection::Auto,
            PlanKind::FixedPredicateWord64,
            b"--Qacegikmortvx0--",
        ),
        (
            r"\p{Greek}{2,6}",
            true,
            PlanSelection::Auto,
            PlanKind::UnicodeScalarRun,
            "xΑΒΓyΔΕ".as_bytes(),
        ),
        (
            r"(?m)^Sherlock Holmes$",
            true,
            PlanSelection::Auto,
            PlanKind::LineDomainByteAtoms,
            b"prefix\nSherlock Holmes\nsuffix",
        ),
        (
            r"\bab",
            false,
            PlanSelection::ForceK0,
            PlanKind::K0,
            b"zab ab",
        ),
        (
            r"(?m:^ab)",
            false,
            PlanSelection::ForceK0,
            PlanKind::K0,
            b"x\nab\nab",
        ),
        ("", false, PlanSelection::ForceK0, PlanKind::K0, b"abc"),
        (
            r"[aceg][\x00-\x40]",
            false,
            PlanSelection::ForceK0,
            PlanKind::K0,
            b"pppppa\x20ppg\x30pp",
        ),
    ];

    for &(pattern, unicode, selection, expected_plan, haystack) in cases {
        let portable = PortableBuilder::new(pattern)
            .unicode(unicode)
            .plan_selection(selection)
            .retained_find_iter(true)
            .build()
            .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
        assert_eq!(
            portable.build_report().plan,
            expected_plan,
            "pattern={pattern:?}"
        );
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .unwrap_or_else(|error| panic!("upstream build failed for {pattern:?}: {error}"));
        let mut session = portable
            .search_session(SearchSessionLimits::unlimited())
            .expect("reusable session");

        for start in 0..=haystack.len() {
            let expected = upstream_spans_at(&upstream, haystack, start);
            let immutable = spans(
                portable
                    .find_iter_value_at(haystack, start, PortableFindIterLimits::unlimited())
                    .expect("immutable iterator construction"),
            );
            assert_eq!(
                immutable, expected,
                "immutable pattern={pattern:?}, start={start}"
            );

            let retained = spans(session.find_iter_value_at(
                haystack,
                start,
                PortableFindIterRunLimits::unlimited(),
            ));
            assert_eq!(
                retained, expected,
                "retained pattern={pattern:?}, start={start}"
            );
        }
    }
}

#[test]
fn invalid_start_and_resource_refusals_fuse_and_leave_retained_session_reusable() {
    let portable = PortableBuilder::new("ab")
        .unicode(false)
        .build()
        .expect("portable exact literal");
    let mut iterator = portable
        .find_iter_value_at(b"ab", 3, PortableFindIterLimits::unlimited())
        .expect("session construction precedes per-search validation");
    let error = iterator
        .next()
        .expect("invalid-start item")
        .expect_err("start past the haystack must fail");
    assert!(matches!(
        &error,
        PortableFindIterError::Search(SearchError::ExactLiteral(_))
    ));
    assert_eq!(
        error.to_string(),
        "portable iteration search failed: literal search failed: literal window 3..2 is invalid for 2 bytes"
    );
    assert!(iterator.next().is_none(), "terminal error must fuse");

    let zero_calls = PortableFindIterLimits {
        max_search_calls: 0,
        ..PortableFindIterLimits::unlimited()
    };
    let mut capped = portable
        .find_iter_value_at(b"ab", 3, zero_calls)
        .expect("session construction");
    assert_eq!(
        capped.next(),
        Some(Err(PortableFindIterError::SearchCallLimit {
            needed: 1,
            limit: 0
        }))
    );
    assert!(capped.next().is_none());

    let mut session = portable
        .search_session(SearchSessionLimits::unlimited())
        .expect("retained exact session");
    {
        let mut invalid =
            session.find_iter_value_at(b"ab", 3, PortableFindIterRunLimits::unlimited());
        let error = invalid
            .next()
            .expect("invalid-start item")
            .expect_err("start past the haystack must fail");
        assert!(matches!(
            &error,
            PortableFindIterError::Search(SearchError::ExactLiteral(_))
        ));
        assert_eq!(
            error.to_string(),
            "portable iteration search failed: literal search failed: literal window 3..2 is invalid for 2 bytes"
        );
        assert!(invalid.next().is_none());
    }
    assert_eq!(
        session
            .find_value(b"zab", SearchLimits::unlimited())
            .expect("session after terminal iterator error")
            .map(|matched| (matched.start(), matched.end())),
        Some((1, 3))
    );

    let k0 = PortableBuilder::new(r"(?:ab|ac)+z")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0");
    let refused_limits = PortableFindIterLimits {
        search: SearchLimits {
            max_work: 0,
            max_scratch_bytes: usize::MAX,
        },
        ..PortableFindIterLimits::unlimited()
    };
    let mut refused = k0
        .find_iter_value_at(b"xxabacz", 2, refused_limits)
        .expect("K0 iterator session construction");
    assert!(matches!(
        refused.next(),
        Some(Err(PortableFindIterError::Search(SearchError::K0(
            fre::K0SearchError::WorkLimitExceeded { limit: 0, .. }
        ))))
    ));
    assert!(refused.next().is_none());
}
