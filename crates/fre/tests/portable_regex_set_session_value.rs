#![forbid(unsafe_code)]

use fre::{
    PortableRegexSet, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    PortableRegexSetSearchSession, PortableRegexSetSessionLimits, SearchLimits,
};

const PATTERNS: [&str; 3] = ["!", "[a-z]+", r"(?-u:[0-9]+)"];

fn session(set: &PortableRegexSet) -> PortableRegexSetSearchSession<'_> {
    set.search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed set session")
}

#[test]
fn value_existence_matches_accounted_source_order_and_ranges() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan set");
    let mut accounted = session(&set);
    let mut value = session(&set);
    let limits = PortableRegexSetRunLimits {
        max_output_matches: 0,
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let cases: &[(&[u8], usize, bool)] = &[
        (b"!", 0, true),
        (b"abc", 0, true),
        (b"123", 0, true),
        (b"\xFF", 0, false),
        (b"!abc123", 1, true),
        (b"!abc123", 4, true),
        (b"!abc123", 7, false),
    ];
    for &(haystack, start, expected) in cases {
        let incumbent = accounted
            .is_match_at(haystack, start, limits)
            .expect("accounted set search")
            .0;
        assert_eq!(incumbent, expected);
        assert_eq!(
            value
                .is_match_value_at(haystack, start, limits)
                .expect("value set search"),
            incumbent,
        );
        if start == 0 {
            assert_eq!(
                value
                    .is_match_value(haystack, limits)
                    .expect("full value set search"),
                incumbent,
            );
        }
    }

    let invalid = PATTERNS.len() + b"short".len();
    assert_eq!(
        value
            .is_match_value_at(b"short", invalid, limits)
            .expect_err("invalid value start"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: b"short".len(),
        },
    );
}

#[test]
fn value_existence_preserves_finite_refusals_and_pattern_search_limits() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan set");
    let haystack = b"\xFF";
    let unlimited = PortableRegexSetRunLimits::unlimited();
    let finite_success = PortableRegexSetRunLimits {
        max_total_work: u64::MAX - 1,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, finite_success)
            .expect("finite aggregate work"),
        session(&set)
            .is_match(haystack, finite_success)
            .expect("accounted finite aggregate work")
            .0,
    );

    let zero_total = PortableRegexSetRunLimits {
        max_total_work: 0,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, zero_total)
            .expect_err("value aggregate work refusal"),
        session(&set)
            .is_match(haystack, zero_total)
            .expect_err("accounted aggregate work refusal"),
    );

    for pattern in [
        SearchLimits {
            max_work: 0,
            ..SearchLimits::unlimited()
        },
        SearchLimits {
            max_scratch_bytes: 0,
            ..SearchLimits::unlimited()
        },
    ] {
        let finite = PortableRegexSetRunLimits {
            pattern,
            ..unlimited
        };
        assert_eq!(
            session(&set)
                .is_match_value(haystack, finite)
                .expect_err("value constituent refusal"),
            session(&set)
                .is_match(haystack, finite)
                .expect_err("accounted constituent refusal"),
        );
    }

    let ordered = PortableRegexSet::new(["z", "[a-z][0-9]", "q"]).expect("ordered mixed-plan set");
    let one_search = PortableRegexSetRunLimits {
        max_pattern_searches: 1,
        ..unlimited
    };
    assert_eq!(
        session(&ordered)
            .is_match_value(b"a7", one_search)
            .expect_err("value pattern-search refusal"),
        session(&ordered)
            .is_match(b"a7", one_search)
            .expect_err("accounted pattern-search refusal"),
    );
}
