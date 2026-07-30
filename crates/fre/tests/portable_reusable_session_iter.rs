#![forbid(unsafe_code)]

use fre::{
    Match, PlanSelection, PortableBuilder, PortableFindIterAccounting, PortableFindIterError,
    PortableFindIterRunLimits, PortableSearchSession, PortableTextBuilder, SearchLimits,
    SearchSessionLimits,
};

fn collect_bytes(
    session: &mut PortableSearchSession<'_>,
    haystack: &[u8],
    limits: PortableFindIterRunLimits,
) -> Result<(Vec<Match>, PortableFindIterAccounting), PortableFindIterError> {
    let mut iterator = session.find_iter(haystack, limits);
    let mut matches = Vec::new();
    for matched in iterator.by_ref() {
        matches.push(matched?);
    }
    Ok((matches, iterator.accounting()))
}

fn spans(matches: &[Match]) -> Vec<(usize, usize)> {
    matches
        .iter()
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

#[test]
fn byte_session_iterator_reuses_one_workspace_across_haystacks_and_early_drop() {
    let regex = PortableBuilder::new(r"(?m:^a$)|(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable contextual K0");
    let upstream = regex::bytes::RegexBuilder::new(r"(?m:^a$)|(?:ab)+")
        .unicode(false)
        .build()
        .expect("upstream bytes regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable K0 session");
    let setup = session
        .workspace_setup_accounting()
        .expect("K0 setup accounting");

    for haystack in [
        b"xxababyyab".as_slice(),
        b"a\nb\na\n".as_slice(),
        b"no match".as_slice(),
    ] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let mut iterator = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
        assert_eq!(iterator.workspace_setup_accounting(), Some(setup));
        assert_eq!(
            iterator
                .by_ref()
                .map(|matched| {
                    let matched = matched.expect("reused byte iteration");
                    (matched.start(), matched.end())
                })
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(iterator.accounting().matches, expected.len());
        assert!(iterator.next().is_none(), "completed iterator must fuse");
    }

    {
        let mut partial = session.find_iter(b"ababxxab", PortableFindIterRunLimits::unlimited());
        let first = partial
            .next()
            .expect("first partial item")
            .expect("first partial match");
        assert_eq!((first.start(), first.end()), (0, 4));
    }

    let (after_drop, accounting) = collect_bytes(
        &mut session,
        b"zzab",
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("session after early iterator drop");
    assert_eq!(spans(&after_drop), vec![(2, 4)]);
    assert_eq!(accounting.matches, 1);
    assert_eq!(session.workspace_setup_accounting(), Some(setup));
}

#[test]
fn reusable_byte_and_text_empty_iteration_preserve_distinct_progress_rules() {
    let haystack = "é";
    let byte_regex = PortableBuilder::new("")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty byte regex");
    let mut byte_session = byte_regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("empty byte session");
    let (byte_matches, byte_accounting) = collect_bytes(
        &mut byte_session,
        haystack.as_bytes(),
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("empty byte iteration");
    assert_eq!(spans(&byte_matches), vec![(0, 0), (1, 1), (2, 2)]);
    assert_eq!(byte_accounting.search_calls, 3);
    assert_eq!(byte_accounting.matches, 3);
    assert_eq!(byte_accounting.suppressed_empty, 3);
    assert_eq!(byte_accounting.utf8_progress_byte_probes, 0);
    assert_eq!(byte_accounting.utf8_progress_work, 0);

    let text_regex = PortableTextBuilder::new("")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty text regex");
    let mut text_session = text_regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("empty text session");
    let text_setup = text_session
        .workspace_setup_accounting()
        .expect("text K0 setup accounting");
    let mut text_iterator =
        text_session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
    assert_eq!(text_iterator.workspace_setup_accounting(), Some(text_setup));
    let text_matches = text_iterator
        .by_ref()
        .map(|matched| matched.expect("empty text match"))
        .collect::<Vec<_>>();
    assert_eq!(spans(&text_matches), vec![(0, 0), (2, 2)]);
    assert_eq!(text_iterator.accounting().search_calls, 2);
    assert_eq!(text_iterator.accounting().matches, 2);
    assert_eq!(text_iterator.accounting().suppressed_empty, 2);
    assert_eq!(text_iterator.accounting().utf8_progress_byte_probes, 1);
    assert_eq!(text_iterator.accounting().utf8_progress_work, 3);
}

#[test]
fn empty_replay_elision_is_linear_and_preserves_context_limits_and_reuse() {
    let empty = PortableBuilder::new("")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty K0");
    let upstream_empty = regex::bytes::RegexBuilder::new("")
        .unicode(false)
        .build()
        .expect("upstream empty bytes regex");
    let mut empty_session = empty
        .search_session(SearchSessionLimits::unlimited())
        .expect("empty K0 session");
    collect_bytes(
        &mut empty_session,
        b"warm",
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("warm empty session");

    let mut measured_work = Vec::new();
    for length in [64_usize, 128] {
        let haystack = vec![b'x'; length];
        let expected = upstream_empty
            .find_iter(&haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let (actual, accounting) = collect_bytes(
            &mut empty_session,
            &haystack,
            PortableFindIterRunLimits::unlimited(),
        )
        .expect("empty iteration");
        assert_eq!(spans(&actual), expected);
        assert_eq!(accounting.matches, length + 1);
        assert_eq!(accounting.search_calls, length + 1);
        assert_eq!(accounting.suppressed_empty, length + 1);
        measured_work.push(accounting.work_or_linear_terms);
    }
    assert!(measured_work[0] > 0);
    assert!(
        measured_work[1] <= measured_work[0].saturating_mul(3),
        "doubling the empty-match haystack must retain linear charged work"
    );

    let contextual = PortableBuilder::new(r"\A|a$")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable contextual nullable K0");
    let upstream_contextual = regex::bytes::RegexBuilder::new(r"\A|a$")
        .unicode(false)
        .build()
        .expect("upstream contextual bytes regex");
    let haystack = b"ba";
    let expected_spans = upstream_contextual
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    assert_eq!(expected_spans, vec![(0, 0), (1, 2)]);
    let mut contextual_session = contextual
        .search_session(SearchSessionLimits::unlimited())
        .expect("contextual K0 session");

    let (actual, full) = collect_bytes(
        &mut contextual_session,
        haystack,
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("contextual iteration");
    assert_eq!(spans(&actual), expected_spans);
    assert_eq!(full.search_calls, 3);
    assert_eq!(full.matches, 2);
    assert_eq!(full.suppressed_empty, 1);

    let (exact, exact_accounting) = collect_bytes(
        &mut contextual_session,
        haystack,
        PortableFindIterRunLimits {
            max_search_calls: full.search_calls,
            ..PortableFindIterRunLimits::unlimited()
        },
    )
    .expect("exact contextual search-call limit");
    assert_eq!(exact, actual);
    assert_eq!(exact_accounting.search_calls, full.search_calls);

    {
        let mut below = contextual_session.find_iter(
            haystack,
            PortableFindIterRunLimits {
                max_search_calls: full.search_calls - 1,
                ..PortableFindIterRunLimits::unlimited()
            },
        );
        assert_eq!(below.next(), Some(Ok(actual[0])));
        assert_eq!(below.next(), Some(Ok(actual[1])));
        assert_eq!(
            below.next(),
            Some(Err(PortableFindIterError::SearchCallLimit {
                needed: full.search_calls,
                limit: full.search_calls - 1,
            }))
        );
        assert!(below.next().is_none(), "terminal refusal must fuse");
    }

    let (recovered, _) = collect_bytes(
        &mut contextual_session,
        haystack,
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("session recovery after contextual refusal");
    assert_eq!(recovered, actual);
}

#[test]
fn text_session_iterator_preserves_context_and_resets_accounting_per_haystack() {
    let regex = PortableTextBuilder::new(r"(?m)^")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable contextual text regex");
    let upstream = regex::Regex::new(r"(?m)^").expect("upstream text regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable contextual text session");

    for haystack in ["a\né\n", "x", "\n\n"] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let mut iterator = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
        assert_eq!(
            iterator
                .by_ref()
                .map(|matched| {
                    let matched = matched.expect("contextual text match");
                    (matched.start(), matched.end())
                })
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(iterator.accounting().matches, expected.len());
        assert!(
            iterator.accounting().search_calls >= expected.len(),
            "each iterator must own an independent complete-search ledger"
        );
    }
}

#[test]
fn session_recovers_after_whole_iterator_and_per_search_refusals() {
    let regex = PortableBuilder::new("(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable K0");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable K0 session");

    let (expected, full_accounting) = collect_bytes(
        &mut session,
        b"abxxabab",
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("unlimited reference iteration");
    assert_eq!(spans(&expected), vec![(0, 2), (4, 8)]);
    assert!(full_accounting.search_calls > full_accounting.matches);

    let exact_limits = PortableFindIterRunLimits {
        max_search_calls: full_accounting.search_calls,
        ..PortableFindIterRunLimits::unlimited()
    };
    let (exact, exact_accounting) =
        collect_bytes(&mut session, b"abxxabab", exact_limits).expect("exact call boundary");
    assert_eq!(exact, expected);
    assert_eq!(exact_accounting.search_calls, full_accounting.search_calls);

    let call_limit = full_accounting.search_calls - 1;
    {
        let mut limited = session.find_iter(
            b"abxxabab",
            PortableFindIterRunLimits {
                max_search_calls: call_limit,
                ..PortableFindIterRunLimits::unlimited()
            },
        );
        assert_eq!(limited.next(), Some(Ok(expected[0])));
        assert_eq!(limited.next(), Some(Ok(expected[1])));
        assert_eq!(
            limited.next(),
            Some(Err(PortableFindIterError::SearchCallLimit {
                needed: full_accounting.search_calls,
                limit: call_limit,
            }))
        );
        assert_eq!(limited.accounting().search_calls, call_limit);
        assert!(limited.next().is_none(), "whole-iterator refusal must fuse");
    }

    let (after_call_limit, _) = collect_bytes(
        &mut session,
        b"zzab",
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("session after whole-iterator refusal");
    assert_eq!(spans(&after_call_limit), vec![(2, 4)]);

    {
        let mut refused = session.find_iter(
            b"ab",
            PortableFindIterRunLimits {
                search: SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: 0,
                },
                ..PortableFindIterRunLimits::unlimited()
            },
        );
        assert!(matches!(
            refused.next(),
            Some(Err(PortableFindIterError::Search(_)))
        ));
        assert_eq!(refused.accounting().search_calls, 1);
        assert!(refused.next().is_none(), "per-search refusal must fuse");
    }

    let (after_search_error, _) = collect_bytes(
        &mut session,
        b"abab",
        PortableFindIterRunLimits::unlimited(),
    )
    .expect("session after per-search refusal");
    assert_eq!(spans(&after_search_error), vec![(0, 4)]);
}

#[test]
fn text_session_recovers_after_terminal_error() {
    let regex = PortableTextBuilder::new("")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable empty text regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("reusable empty text session");

    {
        let mut refused = session.find_iter(
            "é",
            PortableFindIterRunLimits {
                max_search_calls: 0,
                ..PortableFindIterRunLimits::unlimited()
            },
        );
        assert_eq!(
            refused.next(),
            Some(Err(PortableFindIterError::SearchCallLimit {
                needed: 1,
                limit: 0,
            }))
        );
        assert!(refused.next().is_none(), "text refusal must fuse");
    }

    let mut recovered = session.find_iter("a", PortableFindIterRunLimits::unlimited());
    let actual = recovered
        .by_ref()
        .map(|matched| {
            let matched = matched.expect("recovered text match");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, vec![(0, 0), (1, 1)]);
}
