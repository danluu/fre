#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableBuilder, PortableRegex, SearchAccounting, SearchLimits, SearchSessionLimits,
    SearchWindow, UnicodeWordRunError,
};
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};

const PLAN_ID: &str = "bounded-word-class-linear-full-byte-v4";

fn portable(pattern: &str, unicode: bool) -> PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(unicode)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
    assert_eq!(regex.build_report().plan, PlanKind::UnicodeWordRun);
    assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
    regex
}

fn oracle(pattern: &str, unicode: bool) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(unicode))
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned oracle rejected {pattern:?}: {error}"))
}

#[test]
fn bounded_word_class_existence_values_match_every_window_and_session() {
    let ascii_haystacks = [
        b"".as_slice(),
        b"a",
        b"a!",
        b"--a!a-",
        b"xaa!a-y",
        &[0xff, b'a', b'!', 0x80, b'-'],
    ];
    let exact_byte_haystacks = [
        b"".as_slice(),
        &[b'a', 0x80, b'a'],
        &[b'a', 0x80, 0x81, b'a'],
        &[b'-', 0xff, b'a', 0x81, b'-'],
    ];
    let unicode_haystacks = [
        b"".as_slice(),
        "α!".as_bytes(),
        "--α!α-".as_bytes(),
        "xα!β-y".as_bytes(),
        &[0xff, 0xce, 0xb1, b'!', 0xce],
        &[0xed, 0xa0, 0x80, 0xce, 0xb1, b'-'],
    ];

    for (pattern, unicode, haystacks) in [
        (r"(?-u:\b[a!]{1,4}\b)", false, ascii_haystacks.as_slice()),
        (
            r"(?-u:\b[\x80-\x81!]{1,3}\b)",
            false,
            exact_byte_haystacks.as_slice(),
        ),
        (r"\b[α!]{1,4}\b", true, unicode_haystacks.as_slice()),
    ] {
        let regex = portable(pattern, unicode);
        let oracle = oracle(pattern, unicode);
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert_eq!(session.runtime_implementation_id(), PLAN_ID);
        assert_eq!(session.workspace_setup_accounting(), None);

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = oracle.find(Input::new(haystack).span(start..end)).is_some();
                    assert_eq!(
                        regex
                            .is_match_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        expected,
                        "accounted pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                    );
                    assert_eq!(
                        regex
                            .is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected,
                        "immutable value pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                    );
                    assert_eq!(
                        session
                            .is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected,
                        "session value pattern={pattern:?} haystack={haystack:?} window={start}..{end}",
                    );
                }
                assert_eq!(
                    regex
                        .is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .unwrap(),
                    oracle
                        .find(Input::new(haystack).span(start..haystack.len()))
                        .is_some(),
                    "immutable at pattern={pattern:?} haystack={haystack:?} start={start}",
                );
                assert_eq!(
                    session
                        .is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .unwrap(),
                    regex
                        .is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .unwrap(),
                    "session at pattern={pattern:?} haystack={haystack:?} start={start}",
                );
            }
            assert_eq!(
                regex
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                oracle.is_match(haystack),
                "full pattern={pattern:?} haystack={haystack:?}",
            );
        }
    }
}

#[test]
fn bounded_word_class_existence_values_preserve_finite_and_error_contracts() {
    let regex = portable(r"(?-u:\b[a!]{1,64}\b)", false);
    let mut haystack = b"a!".repeat(31);
    haystack.extend_from_slice(b"a-");
    let window = SearchWindow::full(&haystack);
    let (expected, accounting) = regex
        .is_match_window(&haystack, window, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::UnicodeWordRun(accounting) = accounting else {
        panic!("bounded-word fixture published another accounting family");
    };
    assert!(expected);
    assert!(accounting.work() > 0);
    let exact = SearchLimits {
        max_work: accounting.work(),
        max_scratch_bytes: 0,
    };
    let one_below = SearchLimits {
        max_work: accounting.work() - 1,
        max_scratch_bytes: 0,
    };
    let zero_scratch_unmetered = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    for limits in [exact, zero_scratch_unmetered] {
        assert_eq!(
            regex.is_match_window_value(&haystack, window, limits),
            regex
                .is_match_window(&haystack, window, limits)
                .map(|(matched, _)| matched),
        );
        assert_eq!(
            session.is_match_window_value(&haystack, window, limits),
            regex
                .is_match_window(&haystack, window, limits)
                .map(|(matched, _)| matched),
        );
    }
    assert_eq!(
        regex
            .is_match_window_value(&haystack, window, one_below)
            .unwrap_err(),
        regex
            .is_match_window(&haystack, window, one_below)
            .unwrap_err(),
    );
    assert_eq!(
        session
            .is_match_window_value(&haystack, window, one_below)
            .unwrap_err(),
        regex
            .is_match_window(&haystack, window, one_below)
            .unwrap_err(),
    );

    for (invalid, limits) in [
        (
            SearchWindow::new(haystack.len(), haystack.len() - 1),
            zero_scratch_unmetered,
        ),
        (
            SearchWindow::new(0, haystack.len() + 1),
            SearchLimits {
                max_work: 0,
                max_scratch_bytes: 0,
            },
        ),
    ] {
        let expected_error = regex
            .is_match_window(&haystack, invalid, limits)
            .unwrap_err();
        assert!(matches!(
            expected_error,
            fre::SearchError::UnicodeWordRun(UnicodeWordRunError::InvalidWindow { .. })
        ));
        assert_eq!(
            regex
                .is_match_window_value(&haystack, invalid, limits)
                .unwrap_err(),
            expected_error,
        );
        assert_eq!(
            session
                .is_match_window_value(&haystack, invalid, limits)
                .unwrap_err(),
            expected_error,
        );
    }
}

#[test]
fn existence_values_may_stop_before_the_selected_greedy_end() {
    let ascii = portable(r"(?-u:\b[a!]{1,64}\b)", false);
    let mut ascii_haystack = b"a!".repeat(31);
    ascii_haystack.extend_from_slice(b"a-");
    let selected_end = ascii
        .find_accounted(&ascii_haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap()
        .end();
    let shortest_end = ascii
        .shortest_match(&ascii_haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap();
    assert!(shortest_end < selected_end);
    assert!(
        ascii
            .is_match_value(&ascii_haystack, SearchLimits::unlimited())
            .unwrap()
    );

    let unicode = portable(r"\b[α!]{1,64}\b", true);
    let unicode_haystack = format!("xx-{}α-", "α!".repeat(31)).into_bytes();
    let selected_end = unicode
        .find_at(&unicode_haystack, 3, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap()
        .end();
    let shortest_end = unicode
        .shortest_match_at(&unicode_haystack, 3, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap();
    assert!(shortest_end < selected_end);
    let mut session = unicode
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    assert!(
        session
            .is_match_value_at(&unicode_haystack, 3, SearchLimits::unlimited())
            .unwrap()
    );
}
