use fre::{
    PortableBuilder, PortableFindIterError, PortableFindIterRunLimits, RustProfile, SearchError,
    SearchLimits, SearchSessionLimits,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = ".*.*=.*";

fn builder() -> PortableBuilder {
    PortableBuilder::new(PATTERN).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn retained_value_iteration_matches_pinned_regex_exhaustively() {
    let regex = builder().unicode(false).build().unwrap();
    let oracle = RegexBuilder::new(PATTERN).unicode(false).build().unwrap();
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let alphabet = [b'x', b'=', b'\n', b'\r', 0, 0xFF];
    let mut haystack = Vec::new();
    for len in 0..=5 {
        let cases = alphabet.len().pow(u32::try_from(len).unwrap());
        for mut encoded in 0..cases {
            haystack.clear();
            for _ in 0..len {
                haystack.push(alphabet[encoded % alphabet.len()]);
                encoded /= alphabet.len();
            }
            let expected: Vec<_> = oracle
                .find_iter(&haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let actual: Vec<_> = session
                .find_iter_value(&haystack, PortableFindIterRunLimits::unlimited())
                .map(|result| {
                    let matched = result.unwrap();
                    (matched.start(), matched.end())
                })
                .collect();
            assert_eq!(expected, actual, "haystack={haystack:?}");
        }
    }
}

#[test]
fn retained_value_iteration_handles_large_hostile_corridors() {
    let regex = builder().unicode(false).build().unwrap();
    let oracle = RegexBuilder::new(PATTERN).unicode(false).build().unwrap();
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let mut haystack = Vec::new();
    for line in 0..512 {
        haystack.extend(core::iter::repeat_n(0xFF, line % 31));
        if line % 7 == 0 {
            haystack.push(b'=');
        }
        haystack.extend(core::iter::repeat_n(b'x', line % 47));
        haystack.push(b'\n');
    }
    let expected: Vec<_> = oracle
        .find_iter(&haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    let actual: Vec<_> = session
        .find_iter_value(&haystack, PortableFindIterRunLimits::unlimited())
        .map(|result| {
            let matched = result.unwrap();
            (matched.start(), matched.end())
        })
        .collect();
    assert_eq!(expected, actual);
}

#[test]
fn retained_value_iteration_enforces_terminal_work_limit() {
    let haystack = b"x=xxxxxxxx";
    let regex = builder().unicode(false).build().unwrap();
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let mut refused = session.find_iter_value(
        haystack,
        PortableFindIterRunLimits {
            search: SearchLimits {
                max_work: u64::try_from(haystack.len() - 1).unwrap(),
                max_scratch_bytes: 0,
            },
            max_search_calls: usize::MAX,
        },
    );
    assert!(matches!(
        refused.next(),
        Some(Err(PortableFindIterError::Search(SearchError::K0(
            fre::K0SearchError::WorkLimitExceeded {
                consumed: 0,
                requested,
                position: 0,
                ..
            }
        )))) if requested == u64::try_from(haystack.len()).unwrap()
    ));
    assert!(refused.next().is_none());

    let actual: Vec<_> = session
        .find_iter_value(
            haystack,
            PortableFindIterRunLimits {
                search: SearchLimits {
                    max_work: u64::try_from(haystack.len()).unwrap(),
                    max_scratch_bytes: 0,
                },
                max_search_calls: usize::MAX,
            },
        )
        .map(Result::unwrap)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    assert_eq!(vec![(0, haystack.len())], actual);
}
