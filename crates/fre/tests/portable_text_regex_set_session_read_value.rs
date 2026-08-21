#![forbid(unsafe_code)]

use fre::{
    PortableRegexSetExecutionError, PortableRegexSetSessionLimits, PortableTextRegexSet,
    PortableTextRegexSetSearchSession,
};

fn session(set: &PortableTextRegexSet) -> PortableTextRegexSetSearchSession<'_> {
    set.search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed text-set session")
}

fn expected_flags(
    upstream: &regex::RegexSet,
    haystack: &str,
    start: usize,
    initial: &[bool],
) -> (bool, Vec<bool>) {
    let matches = upstream.matches_at(haystack, start);
    let mut expected = initial.to_vec();
    for index in matches.iter() {
        expected[index] = true;
    }
    (matches.iter().next().is_some(), expected)
}

#[test]
fn session_caller_buffer_values_match_upstream_at_every_utf8_offset() {
    let patterns = [
        "(?:ab|cd|ef)+X",
        "a",
        "a*",
        "é",
        r"\bbar\b",
        r"(?m)^bar$",
        "東京",
    ];
    let set = PortableTextRegexSet::new(patterns).expect("mixed text set");
    let upstream = regex::RegexSet::new(patterns).expect("upstream mixed text set");
    let mut value = session(&set);

    for haystack in ["", "ababX", "a7", "é\nbar\n東京", "🦀 none"] {
        for start in 0..=haystack.len() {
            let mut initial = vec![false; patterns.len() + 2];
            initial[1] = true;
            initial[patterns.len()] = true;
            let (expected_any, expected) = expected_flags(&upstream, haystack, start, &initial);
            let mut flags = initial;
            assert_eq!(
                value
                    .matches_read_at_value_unlimited(&mut flags, haystack, start)
                    .unwrap_or_else(|error| panic!("value {haystack:?}/{start}: {error}")),
                expected_any,
                "returned membership {haystack:?}/{start}",
            );
            assert_eq!(flags, expected, "flags {haystack:?}/{start}");
        }

        let initial = vec![false; patterns.len() + 2];
        let (expected_any, expected) = expected_flags(&upstream, haystack, 0, &initial);
        let mut flags = initial;
        assert_eq!(
            value
                .matches_read_value_unlimited(&mut flags, haystack)
                .expect("whole-haystack session caller-buffer value search"),
            expected_any,
        );
        assert_eq!(flags, expected);
    }
}

#[test]
fn session_caller_buffer_validation_precedes_mutation_and_empty_is_exact() {
    let set = PortableTextRegexSet::new(["a", "é", "(?:ab|cd)+X"]).expect("validation text set");
    let mut value = session(&set);
    let mut flags = [true, false, true, false];
    let original = flags;
    let invalid = "é".len() + 1;
    assert_eq!(
        value
            .matches_read_at_value_unlimited(&mut flags[..1], "é", invalid)
            .expect_err("invalid start precedes short buffer"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: "é".len(),
        },
    );
    assert_eq!(flags, original);

    assert_eq!(
        value
            .matches_read_at_value_unlimited(&mut flags[..1], "é", 0)
            .expect_err("short caller buffer"),
        PortableRegexSetExecutionError::MatchBufferTooSmall {
            needed: value.len(),
            available: 1,
        },
    );
    assert_eq!(flags, original);

    let empty = PortableTextRegexSet::empty();
    let mut empty_value = session(&empty);
    let mut tail = [true, false];
    assert!(
        !empty_value
            .matches_read_at_value_unlimited(&mut tail, "é", 1)
            .expect("interior start on empty set")
    );
    assert_eq!(tail, [true, false]);
    assert_eq!(
        empty_value
            .matches_read_at_value_unlimited(&mut tail[..0], "é", invalid)
            .expect_err("empty set still validates range"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: "é".len(),
        },
    );
}
