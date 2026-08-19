#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "small exact-limit and public-fixture counters are independently bounded"
)]

use std::{mem::size_of, sync::Arc};

use fre_capture_lab::{
    AggregateLimits, Ast, BOUNDED_BACKTRACK_WORKSPACE_ACCOUNTING_VERSION,
    BOUNDED_BACKTRACK_WORKSPACE_ALGORITHM_VERSION, BoundedBacktrackWorkspace, BuildLimits,
    CandidateKind, Greed, HirProgramBuildLimits, HistoryRegex, ResourceKind, SearchConfig,
    SearchError, SearchLimits, Window, build_program_from_hir,
};
use sha2::{Digest, Sha256};

fn capture_program() -> Ast {
    Ast::alt([
        Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'!')]),
        Ast::Byte(b'a').capture(2),
    ])
}

fn assert_replay(
    regex: &HistoryRegex,
    workspace: &mut BoundedBacktrackWorkspace,
    haystack: &[u8],
    window: Window,
    from: usize,
    config: SearchConfig,
) {
    let limits = SearchLimits::default();
    let expected = regex
        .captures_from_with_config(haystack, window, from, config, limits)
        .expect("persistent-history authority");
    let actual = regex
        .captures_from_with_bounded_backtrack_workspace(
            workspace, haystack, window, from, config, limits,
        )
        .expect("reusable bounded replay");
    let prospective = regex
        .bounded_backtrack_prospective(window, from, config)
        .expect("valid prospective")
        .expect("leftmost-first bounded route");
    assert_eq!(actual.captures, expected.captures);
    assert_eq!(actual.report.candidate, CandidateKind::BoundedBacktracker);
    assert!(prospective.closes_report(&actual.report));
}

#[test]
fn reusable_bounded_workspace_restores_captures_across_distinct_searches() {
    let regex =
        HistoryRegex::compile(&capture_program(), BuildLimits::default()).expect("capture program");
    let max_search_bytes = 96;
    let usage = regex
        .bounded_backtrack_workspace_usage(max_search_bytes, SearchLimits::default())
        .expect("workspace usage")
        .expect("compact bounded program");
    assert_eq!(
        usage.algorithm_version,
        BOUNDED_BACKTRACK_WORKSPACE_ALGORITHM_VERSION
    );
    assert_eq!(
        usage.accounting_version,
        BOUNDED_BACKTRACK_WORKSPACE_ACCOUNTING_VERSION
    );
    assert_eq!(usage.max_search_bytes, max_search_bytes);
    assert_eq!(usage.state_count, regex.program().state_len());
    assert_eq!(usage.slot_capacity, regex.program_shape().slots);
    assert!(usage.frame_state_count <= usage.state_count);
    assert!(usage.frame_capacity > 0);
    assert!(usage.visited_word_capacity > 0);
    assert!(usage.persistent_bytes > usage.admitted_scratch_bytes);

    let mut workspace = regex
        .prepare_bounded_backtrack_workspace(max_search_bytes, SearchLimits::default())
        .expect("workspace preparation")
        .expect("compact bounded program");
    assert_eq!(workspace.usage(), usage);

    let mut haystack = vec![b'x'; max_search_bytes];
    haystack[70] = b'a';
    haystack[71] = b'!';
    assert_replay(
        &regex,
        &mut workspace,
        &haystack,
        Window::all(&haystack),
        0,
        SearchConfig::LEFTMOST,
    );

    // Reusing the same slots must not retain group 1 after priority falls
    // through to the second alternative.
    haystack[71] = b'x';
    assert_replay(
        &regex,
        &mut workspace,
        &haystack,
        Window::all(&haystack),
        0,
        SearchConfig::LEFTMOST,
    );
    assert_replay(
        &regex,
        &mut workspace,
        &haystack,
        Window::all(&haystack),
        70,
        SearchConfig::LEFTMOST.anchored(true),
    );
    assert_replay(
        &regex,
        &mut workspace,
        &haystack,
        Window::all(&haystack),
        69,
        SearchConfig::LEFTMOST.anchored(true),
    );

    let malformed = b"\xFFza";
    assert_replay(
        &regex,
        &mut workspace,
        malformed,
        Window::all(malformed),
        0,
        SearchConfig::LEFTMOST,
    );
    let absent = vec![b'x'; max_search_bytes];
    assert_replay(
        &regex,
        &mut workspace,
        &absent,
        Window::all(&absent),
        0,
        SearchConfig::LEFTMOST,
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one transactional workspace fixture exercises every public refusal boundary"
)]
fn reusable_bounded_workspace_authenticates_owner_width_policy_and_limits() {
    let regex =
        HistoryRegex::compile(&capture_program(), BuildLimits::default()).expect("capture program");
    let clone = regex.clone();
    let unrelated = HistoryRegex::from_program(Arc::clone(regex.program()));
    let limits = SearchLimits::default();
    let mut workspace = regex
        .prepare_bounded_backtrack_workspace(2, limits)
        .expect("workspace preparation")
        .expect("compact bounded program");
    let haystack = b"za";
    let window = Window::all(haystack);

    clone
        .captures_from_with_bounded_backtrack_workspace(
            &mut workspace,
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            limits,
        )
        .expect("a clone retains workspace lineage");
    assert_eq!(
        unrelated.captures_from_with_bounded_backtrack_workspace(
            &mut workspace,
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            limits,
        ),
        Err(SearchError::InvalidProgram)
    );
    assert_eq!(
        regex.captures_from_with_bounded_backtrack_workspace(
            &mut workspace,
            b"xxx",
            Window::all(b"xxx"),
            0,
            SearchConfig::LEFTMOST,
            limits,
        ),
        Err(SearchError::InvalidWindow)
    );
    assert_eq!(
        regex.captures_from_with_bounded_backtrack_workspace(
            &mut workspace,
            haystack,
            window,
            0,
            SearchConfig::EARLIEST,
            limits,
        ),
        Err(SearchError::InvalidProgram)
    );

    let prospective = regex
        .bounded_backtrack_prospective(window, 0, SearchConfig::LEFTMOST)
        .expect("valid prospective")
        .expect("bounded route");
    let exact = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_slot_copies: prospective.slot_copies,
        max_scratch_bytes: prospective.scratch_bytes,
        ..limits
    };
    for (kind, one_below) in [
        (
            ResourceKind::StateVisits,
            SearchLimits {
                max_state_visits: prospective.state_visits - 1,
                ..exact
            },
        ),
        (
            ResourceKind::SlotCopies,
            SearchLimits {
                max_slot_copies: prospective.slot_copies - 1,
                ..exact
            },
        ),
        (
            ResourceKind::ScratchBytes,
            SearchLimits {
                max_scratch_bytes: prospective.scratch_bytes - 1,
                ..exact
            },
        ),
    ] {
        assert!(matches!(
            regex.captures_from_with_bounded_backtrack_workspace(
                &mut workspace,
                haystack,
                window,
                0,
                SearchConfig::LEFTMOST,
                one_below,
            ),
            Err(SearchError::Resource { kind: actual, .. }) if actual == kind
        ));
    }

    let accepted = regex
        .captures_from_with_bounded_backtrack_workspace(
            &mut workspace,
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            exact,
        )
        .expect("exact limits");
    assert_eq!(accepted.report.candidate, CandidateKind::BoundedBacktracker);
    assert!(accepted.captures.is_some());
}

#[test]
fn workspace_preparation_refuses_one_below_before_construction() {
    let regex = HistoryRegex::compile(
        &Ast::Byte(b'a').repeat(0, Some(2), Greed::Greedy),
        BuildLimits::default(),
    )
    .expect("capture program");
    let max_search_bytes = 8;
    let prospective = regex
        .bounded_backtrack_prospective(
            Window {
                start: 0,
                end: max_search_bytes,
            },
            0,
            SearchConfig::LEFTMOST,
        )
        .expect("valid prospective")
        .expect("bounded route");
    let exact = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_slot_copies: prospective.slot_copies,
        max_scratch_bytes: prospective.scratch_bytes,
        ..SearchLimits::default()
    };
    regex
        .prepare_bounded_backtrack_workspace(max_search_bytes, exact)
        .expect("exact preparation")
        .expect("compact bounded program");

    for (kind, one_below) in [
        (
            ResourceKind::StateVisits,
            SearchLimits {
                max_state_visits: prospective.state_visits - 1,
                ..exact
            },
        ),
        (
            ResourceKind::SlotCopies,
            SearchLimits {
                max_slot_copies: prospective.slot_copies - 1,
                ..exact
            },
        ),
        (
            ResourceKind::ScratchBytes,
            SearchLimits {
                max_scratch_bytes: prospective.scratch_bytes - 1,
                ..exact
            },
        ),
    ] {
        assert!(matches!(
            regex.prepare_bounded_backtrack_workspace(max_search_bytes, one_below),
            Err(SearchError::Resource { kind: actual, .. }) if actual == kind
        ));
    }
}

#[test]
fn public_bibleref_short_replay_matches_capture_count_authority() {
    const PATTERN: &str = r"(?P<Book>(([1234]|I{1,4})[\t\f\pZ]*)?\pL+\.?)[\t\f\pZ]+(?P<Locations>((?P<Chapter>1?[0-9]?[0-9])(-(?P<ChapterEnd>\d+)|,\s*(?P<ChapterNext>\\d+))*(:\s*(?P<Verse>\d+))?(-(?P<VerseEnd>\d+)|,\s*(?P<VerseNext>\d+))*\s?)+)";
    const HAYSTACK: &[u8] = b"Gen 1:1, 2\n3 King 1:3-4\nII Ki. 3:12-14, 25\n";
    assert_eq!(PATTERN.len(), 216);
    assert_eq!(HAYSTACK.len(), 43);
    assert_eq!(
        format!("{:x}", Sha256::digest(PATTERN.as_bytes())),
        "4c8cb903c4f34954bc810f88cbe73ab2da5cbefacb9db929632e3b0b576877b2"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(HAYSTACK)),
        "2b597ad9c5778f281dd26b4e301b6a7c7471b5a7486ff13657ce7724c9d62da0"
    );

    let mut parser = regex_syntax::ParserBuilder::new();
    parser.utf8(false).unicode(true);
    let hir = parser.build().parse(PATTERN).expect("public pattern HIR");
    let program = build_program_from_hir(&hir, b'\n', HirProgramBuildLimits::default())
        .expect("public capture program")
        .into_program();
    let regex = HistoryRegex::from_program(Arc::new(program));
    let authority = regex
        .count_captures_nonempty(HAYSTACK, Window::all(HAYSTACK), AggregateLimits::default())
        .expect("persistent-history capture count");
    assert_eq!(authority.count, 30);
    assert_eq!(authority.matches, 3);
    assert_eq!(authority.searches, 4);

    let mut workspace = regex
        .prepare_bounded_backtrack_workspace(HAYSTACK.len(), SearchLimits::default())
        .expect("bounded workspace")
        .expect("compact public program");
    let mut cursor = 0;
    let mut count = 0;
    let mut matches = 0;
    let mut searches = 0;
    let mut state_visits = 0;
    let mut slot_copies = 0;
    let mut starts_injected = 0;
    let mut bytes_examined = 0;
    let mut peak_frames = 0;
    loop {
        searches += 1;
        let outcome = regex
            .captures_from_with_bounded_backtrack_workspace(
                &mut workspace,
                HAYSTACK,
                Window::all(HAYSTACK),
                cursor,
                SearchConfig::LEFTMOST,
                SearchLimits::default(),
            )
            .expect("bounded public replay");
        state_visits += outcome.report.state_visits;
        slot_copies += outcome.report.slot_copies;
        starts_injected += outcome.report.starts_injected;
        bytes_examined += outcome.report.bytes_examined;
        peak_frames = peak_frames.max(outcome.report.peak_threads);
        let Some(captures) = outcome.captures else {
            break;
        };
        let overall = captures.overall().expect("whole match");
        assert!(overall.start < overall.end);
        count += captures
            .groups
            .iter()
            .filter(|group| group.span.is_some())
            .count();
        matches += 1;
        cursor = overall.end;
    }
    assert_eq!((count, matches, searches), (30, 3, 4));
    assert_eq!(
        (
            state_visits,
            slot_copies,
            starts_injected,
            bytes_examined,
            peak_frames,
        ),
        (881, 112, 4, 333, 54)
    );
    assert_eq!(
        workspace.usage().persistent_bytes - workspace.usage().admitted_scratch_bytes,
        size_of::<BoundedBacktrackWorkspace>() - 3 * size_of::<Vec<usize>>()
    );
    assert_eq!(
        (
            authority.total_state_visits,
            authority.total_history_nodes,
            authority.total_history_walk,
            authority.peak_threads,
        ),
        (3_253, 281, 66, 59)
    );
}
