#![forbid(unsafe_code)]

use fre::{
    K0SearchError, Match, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
    PortableFindIterRunLimits, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
};

const ROOT_START: u8 = 0x20;
const ROOT_END: u8 = 0x60;
const SUFFIX_START: u8 = 0x80;
const SUFFIX_END: u8 = 0xff;

fn portable() -> fre::PortableRegex {
    let regex = PortableBuilder::new(r"[\x20-\x60][\x80-\xFF]")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("portable range-pair K0");
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    regex
}

fn dense_source() -> Vec<u8> {
    let mut source = vec![0_u8; 72];
    for candidate in [16_usize, 20, 24, 28, 36, 40, 58, 62] {
        source[candidate] = 0x40;
    }
    for suffix in [29_usize, 41, 63] {
        source[suffix] = 0x80;
    }
    source
}

fn oracle_first(source: &[u8], window: SearchWindow) -> Option<(usize, usize)> {
    if window.start() > window.end() || window.end() > source.len() {
        return None;
    }
    (window.start()..window.end()).find_map(|at| {
        let next = at.checked_add(1)?;
        if next < window.end()
            && (ROOT_START..=ROOT_END).contains(&source[at])
            && (SUFFIX_START..=SUFFIX_END).contains(&source[next])
        {
            Some((at, next + 1))
        } else {
            None
        }
    })
}

fn oracle_iter(source: &[u8]) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    let mut start = 0;
    while let Some((matched_start, matched_end)) =
        oracle_first(source, SearchWindow::new(start, source.len()))
    {
        matches.push((matched_start, matched_end));
        start = matched_end;
    }
    matches
}

fn span(matched: Option<Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn scalar_oracle_covers_reporting_value_windows_fallback_and_session_isolation() {
    let regex = portable();
    let dense = dense_source();
    let mut changed = dense.clone();
    changed[29] = 0;
    changed[37] = 0x80;
    let absent = vec![0_u8; dense.len()];
    let immediate = vec![0x40, 0x80];
    let short = vec![0x40];
    let sources = [&dense[..], &changed, &absent, &immediate, &short, &[]];

    for source in sources {
        let len = source.len();
        let mut windows = vec![
            SearchWindow::full(source),
            SearchWindow::new(0, len.min(16)),
            SearchWindow::new(0, len.min(17)),
            SearchWindow::new(0, len.min(31)),
            SearchWindow::new(0, len.min(32)),
            SearchWindow::new(0, len.min(33)),
        ];
        if len >= 33 {
            windows.extend([
                SearchWindow::new(15, 29),
                SearchWindow::new(15, 30),
                SearchWindow::new(16, 29),
                SearchWindow::new(16, 30),
                SearchWindow::new(17, 30),
                SearchWindow::new(29, 32),
                SearchWindow::new(31, 32),
                SearchWindow::new(32, 33),
            ]);
        }

        let mut reporting_session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("reporting session");
        let mut value_session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("value session");
        for window in windows {
            let expected = oracle_first(source, window);

            let cold_reporting = regex
                .find_window(source, window, SearchLimits::unlimited())
                .expect("cold reporting search");
            let cold_value = regex
                .find_window_value(source, window, SearchLimits::unlimited())
                .expect("cold value search");
            let cold_exists = regex
                .is_match_window(source, window, SearchLimits::unlimited())
                .expect("cold reporting existence");
            let cold_exists_value = regex
                .is_match_window_value(source, window, SearchLimits::unlimited())
                .expect("cold value existence");
            assert_eq!(span(cold_reporting.0), expected);
            assert_eq!(span(cold_value), expected);
            assert_eq!(cold_exists.0, expected.is_some());
            assert_eq!(cold_exists_value, expected.is_some());

            let reused_reporting = reporting_session
                .find_window(source, window, SearchLimits::unlimited())
                .expect("reused reporting search");
            let reused_exists = reporting_session
                .is_match_window(source, window, SearchLimits::unlimited())
                .expect("reused reporting existence");
            let reused_value = value_session
                .find_window_value(source, window, SearchLimits::unlimited())
                .expect("reused value search");
            let reused_exists_value = value_session
                .is_match_window_value(source, window, SearchLimits::unlimited())
                .expect("reused value existence");
            assert_eq!(span(reused_reporting.0), expected);
            assert_eq!(span(reused_value), expected);
            assert_eq!(reused_exists.0, expected.is_some());
            assert_eq!(reused_exists_value, expected.is_some());
        }
    }

    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("source-isolation session");
    let setup = session
        .workspace_setup_accounting()
        .expect("K0 workspace setup");
    for source in [&dense[..], &changed, &absent, &immediate, &dense] {
        let expected = oracle_first(source, SearchWindow::full(source));
        assert_eq!(
            span(
                session
                    .find_value(source, SearchLimits::unlimited())
                    .expect("source-isolated call")
            ),
            expected
        );
        assert_eq!(session.workspace_setup_accounting(), Some(setup));
    }

    let invalid = SearchWindow::new(4, 3);
    assert!(matches!(
        regex.find_window(&dense, invalid, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 4,
            end: 3,
            haystack_len: 72,
        }))
    ));
    assert!(matches!(
        regex.find_window_value(&dense, invalid, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 4,
            end: 3,
            haystack_len: 72,
        }))
    ));
    assert!(matches!(
        session.find_window(&dense, invalid, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 4,
            end: 3,
            haystack_len: 72,
        }))
    ));
    assert!(matches!(
        session.find_window_value(&dense, invalid, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 4,
            end: 3,
            haystack_len: 72,
        }))
    ));
}

#[test]
fn scalar_oracle_covers_iteration_early_drop_absence_and_refusal_recovery() {
    let regex = portable();
    let dense = dense_source();
    let absent = vec![0_u8; dense.len()];
    let expected = oracle_iter(&dense);
    assert_eq!(expected, vec![(28, 30), (40, 42), (62, 64)]);

    let cold = regex
        .find_iter(&dense, PortableFindIterLimits::unlimited())
        .expect("cold iterator")
        .map(|matched| {
            let matched = matched.expect("cold match");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(cold, expected);

    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("iteration session");
    let reused = session
        .find_iter(&dense, PortableFindIterRunLimits::unlimited())
        .map(|matched| {
            let matched = matched.expect("reused match");
            (matched.start(), matched.end())
        })
        .collect::<Vec<_>>();
    assert_eq!(reused, expected);
    assert!(
        session
            .find_iter(&absent, PortableFindIterRunLimits::unlimited())
            .next()
            .is_none()
    );

    {
        let mut partial = session.find_iter(&dense, PortableFindIterRunLimits::unlimited());
        let first = partial
            .next()
            .expect("first partial item")
            .expect("first partial match");
        assert_eq!((first.start(), first.end()), expected[0]);
    }
    assert_eq!(
        session
            .find_iter(&dense, PortableFindIterRunLimits::unlimited())
            .map(|matched| {
                let matched = matched.expect("post-drop match");
                (matched.start(), matched.end())
            })
            .collect::<Vec<_>>(),
        expected
    );

    let refused = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    assert!(session.find(&dense, refused).is_err());
    assert!(session.find_value(&dense, refused).is_err());
    assert_eq!(
        span(
            session
                .find_value(&dense, SearchLimits::unlimited())
                .expect("session recovery after scratch refusal")
        ),
        oracle_first(&dense, SearchWindow::full(&dense))
    );

    let no_work = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(session.find(&dense, no_work).is_err());
    assert_eq!(
        span(
            session
                .find_value(&dense, SearchLimits::unlimited())
                .expect("session recovery after work refusal")
        ),
        oracle_first(&dense, SearchWindow::full(&dense))
    );
}
