#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableBuilder, PortableRegex, PortableSearchSession, SearchAccounting, SearchError,
    SearchLimits, SearchSessionLimits, SearchWindow,
};

const CASES: [(&str, &str); 6] = [
    ("constant-256", "(?s-u:.)+"),
    ("small-1", "a+"),
    ("small-2", "(?-u:[ab])+"),
    ("small-3", "(?-u:[abc])+"),
    ("classified-4", "(?-u:[abcd])+"),
    ("classified-255", "(?-u:[^\\x00])+"),
];

fn build(pattern: &str) -> PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
    assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
    assert_eq!(
        regex.runtime_implementation_id(),
        fre::PURE_BYTE_CLASS_REPEAT_PLAN_ID
    );
    regex
}

fn reporting(
    regex: &PortableRegex,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> Result<bool, SearchError> {
    regex
        .is_match_window(haystack, window, limits)
        .map(|(matched, _)| matched)
}

fn measured_work(regex: &PortableRegex, haystack: &[u8], window: SearchWindow) -> u64 {
    let (_, accounting) = regex
        .is_match_window(haystack, window, SearchLimits::unlimited())
        .unwrap();
    match accounting {
        SearchAccounting::PureByteClassRepeat(accounting) => accounting.actual_work,
        other => panic!("expected pure-byte-class accounting, got {other:?}"),
    }
}

fn assert_direct_parity(
    regex: &PortableRegex,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    context: &str,
) {
    let expected = reporting(regex, haystack, window, limits);
    let actual = regex.is_match_window_value(haystack, window, limits);
    assert_eq!(actual, expected, "{context}; limits={limits:?}");
}

fn assert_direct_and_session_parity(
    regex: &PortableRegex,
    session: &mut PortableSearchSession<'_>,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    context: &str,
) {
    let expected = reporting(regex, haystack, window, limits);
    assert_eq!(
        regex.is_match_window_value(haystack, window, limits),
        expected,
        "direct: {context}; limits={limits:?}"
    );
    assert_eq!(
        session
            .is_match_window(haystack, window, limits)
            .map(|(matched, _)| matched),
        expected,
        "session reporting: {context}; limits={limits:?}"
    );
    assert_eq!(
        session.is_match_window_value(haystack, window, limits),
        expected,
        "session value: {context}; limits={limits:?}"
    );
}

#[test]
fn value_exists_is_exhaustive_across_leaf_cardinality_boundaries() {
    let haystacks = words(&[0x00, b'a', b'b', b'd', 0xFF], 4);

    for (case, pattern) in CASES {
        let regex = build(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();

        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected_semantics = oracle.is_match(&haystack[start..end]);
                    assert_eq!(
                        reporting(&regex, haystack, window, SearchLimits::unlimited()),
                        Ok(expected_semantics),
                        "oracle: case={case}, haystack={haystack:?}, window={start}..{end}"
                    );

                    let work = measured_work(&regex, haystack, window);
                    for max_work in 0..=work.saturating_add(1) {
                        let limits = SearchLimits {
                            max_work,
                            max_scratch_bytes: if max_work & 1 == 0 { 0 } else { 1 },
                        };
                        assert_direct_parity(
                            &regex,
                            haystack,
                            window,
                            limits,
                            &format!("case={case}, haystack={haystack:?}, window={start}..{end}"),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn classified_scanner_block_edges_preserve_results_and_refusal_payloads() {
    let regex = build("(?-u:[abcd])+");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    assert_eq!(
        session.runtime_implementation_id(),
        fre::PURE_BYTE_CLASS_REPEAT_PLAN_ID
    );
    assert!(session.workspace_setup_accounting().is_none());

    for length in [0_usize, 1, 15, 16, 17, 18, 31, 32, 33, 34, 47, 48, 49] {
        let mut hit_positions = vec![None];
        for position in [0_usize, 1, 15, 16, 17, 31, 32, length.saturating_sub(1)] {
            if position < length {
                hit_positions.push(Some(position));
            }
        }
        hit_positions.sort_unstable();
        hit_positions.dedup();

        for hit in hit_positions {
            let mut haystack = vec![b'!'; length.saturating_add(2)];
            haystack[1..length + 1].fill(b'z');
            if let Some(position) = hit {
                haystack[position + 1] = b'a';
            }
            let window = SearchWindow::new(1, length + 1);
            assert_eq!(
                reporting(&regex, &haystack, window, SearchLimits::unlimited()),
                Ok(hit.is_some()),
                "length={length}, hit={hit:?}"
            );

            let work = measured_work(&regex, &haystack, window);
            for max_work in 0..=work.saturating_add(1) {
                assert_direct_and_session_parity(
                    &regex,
                    &mut session,
                    &haystack,
                    window,
                    SearchLimits {
                        max_work,
                        max_scratch_bytes: usize::MAX,
                    },
                    &format!("length={length}, hit={hit:?}"),
                );
            }
        }
    }
}

#[test]
fn invalid_windows_win_before_zero_work_for_direct_and_native_session_paths() {
    let zero_work = SearchLimits {
        max_work: 0,
        max_scratch_bytes: 0,
    };

    for (case, pattern) in CASES {
        let regex = build(pattern);
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let haystack = b"abc";
        for window in [
            SearchWindow::new(2, 1),
            SearchWindow::new(0, haystack.len() + 1),
            SearchWindow::new(haystack.len() + 1, haystack.len() + 1),
            SearchWindow::new(usize::MAX, 0),
            SearchWindow::new(usize::MAX, usize::MAX),
        ] {
            assert_direct_and_session_parity(
                &regex,
                &mut session,
                haystack,
                window,
                zero_work,
                &format!("case={case}, invalid={window:?}"),
            );
        }
    }
}

fn words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
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
        words.extend(next.iter().cloned());
        frontier = next;
    }
    words
}
