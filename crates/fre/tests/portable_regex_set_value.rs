#![forbid(unsafe_code)]

use fre::{PortableRegexSet, PortableRegexSetExecutionError, PortableRegexSetRunLimits};

const PATTERNS: [&str; 4] = ["!", "[a-z]+", r"(?-u:[0-9]+)", r"(?m:^anchor)"];

#[test]
fn immutable_value_existence_matches_accounted_source_order_assertions_and_ranges() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan set");
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
        (b"x\nanchor", 1, true),
        (b"x\nanchor", 3, true),
    ];
    for &(haystack, start, expected) in cases {
        let incumbent = set
            .is_match_at(haystack, start, limits)
            .expect("accounted set search")
            .0;
        assert_eq!(incumbent, expected);
        assert_eq!(
            set.is_match_value_at_unlimited(haystack, start)
                .expect("value set search"),
            incumbent,
        );
        if start == 0 {
            assert_eq!(
                set.is_match_value_unlimited(haystack)
                    .expect("full value set search"),
                incumbent,
            );
        }
    }

    let asserted = PortableRegexSet::new([r"(?m:^anchor)"]).expect("asserted set");
    for (start, expected) in [(1, true), (3, false)] {
        assert_eq!(
            asserted
                .is_match_value_at_unlimited(b"x\nanchor", start)
                .expect("asserted ranged value search"),
            expected,
        );
        assert_eq!(
            asserted
                .is_match_at(b"x\nanchor", start, limits)
                .expect("asserted ranged accounted search")
                .0,
            expected,
        );
    }

    let invalid = b"short".len() + 1;
    assert_eq!(
        set.is_match_value_at_unlimited(b"short", invalid)
            .expect_err("invalid value start"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: b"short".len(),
        },
    );
}
