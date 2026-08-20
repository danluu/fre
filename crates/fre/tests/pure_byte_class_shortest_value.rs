#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, PortableRegex, SearchAccounting, SearchError, SearchLimits};

const CASES: [(&str, &[u8]); 8] = [
    ("(?s-u:.)+", b"\0\n\x80\xff"),
    ("a+", b"zzzaaa!"),
    ("(?-u:[ab])+", b"zzzbba!"),
    ("(?-u:[abc])+", b"zzzcba!"),
    ("(?-u:[a-d])+", b"zzzdcb!"),
    ("(?-u:[^\\x00])+", b"\0\0z!"),
    ("(?-u:[ac])+", b"zzzca!"),
    ("(?-u:[aceg])+", b"zzzgca!"),
];

fn build(pattern: &str) -> PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
    assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
    regex
}

#[test]
fn pure_byte_class_shortest_values_match_accounted_results_and_oracle() {
    for (pattern, haystack) in CASES {
        let regex = build(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let limits = SearchLimits::unlimited();
        let expected_full = oracle.shortest_match(haystack);
        assert_eq!(
            regex.shortest_match_value(haystack, limits).unwrap(),
            expected_full
        );
        assert_eq!(
            regex.shortest_match(haystack, limits).unwrap().0,
            expected_full
        );

        for start in 0..=haystack.len() {
            let expected = oracle
                .shortest_match(&haystack[start..])
                .map(|end| start + end);
            assert_eq!(
                regex
                    .shortest_match_at_value(haystack, start, limits)
                    .unwrap(),
                expected,
                "value pattern={pattern:?}, start={start}",
            );
            assert_eq!(
                regex.shortest_match_at(haystack, start, limits).unwrap().0,
                expected,
                "accounted pattern={pattern:?}, start={start}",
            );
        }
    }
}

#[test]
fn pure_byte_class_shortest_value_preserves_finite_limits_and_invalid_precedence() {
    for (pattern, haystack) in [
        ("a+", b"zzza".as_slice()),
        ("(?-u:[a-d])+", b"zzzc".as_slice()),
        ("(?-u:[aceg])+", b"zzzg".as_slice()),
        ("(?-u:[^a-d])+", b"aaaz".as_slice()),
    ] {
        let regex = build(pattern);
        let (expected, accounting) = regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::PureByteClassRepeat(accounting) = accounting else {
            panic!("pure-byte shortest search published another accounting family");
        };
        assert!(accounting.actual_work > 0);

        let exact = SearchLimits {
            max_work: accounting.actual_work,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            regex.shortest_match_value(haystack, exact).unwrap(),
            expected
        );
        assert_eq!(regex.shortest_match(haystack, exact).unwrap().0, expected);

        let one_below = SearchLimits {
            max_work: accounting.actual_work - 1,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            regex.shortest_match_value(haystack, one_below).unwrap_err(),
            regex.shortest_match(haystack, one_below).unwrap_err(),
            "one-below pattern={pattern:?}",
        );

        let invalid_start = haystack.len() + 1;
        let zero = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        let value_error = regex
            .shortest_match_at_value(haystack, invalid_start, zero)
            .unwrap_err();
        assert_eq!(
            value_error,
            regex
                .shortest_match_at(haystack, invalid_start, zero)
                .unwrap_err(),
        );
        assert!(matches!(
            value_error,
            SearchError::PureByteClassRepeat(fre::PureByteClassRepeatSearchError::InvalidWindow)
        ));
    }
}

#[test]
fn pure_byte_class_shortest_value_preserves_earliest_end_and_start_order() {
    for pattern in ["a+", "a+?"] {
        let regex = build(pattern);
        let haystack = b"aaa---a";
        let limits = SearchLimits::unlimited();
        assert_eq!(
            regex.shortest_match_value(haystack, limits).unwrap(),
            Some(1)
        );
        assert_eq!(
            regex.shortest_match_at_value(haystack, 1, limits).unwrap(),
            Some(2),
        );
        assert_eq!(
            regex.shortest_match_at_value(haystack, 3, limits).unwrap(),
            Some(7),
        );
        assert_eq!(
            regex.shortest_match_at_value(haystack, 7, limits).unwrap(),
            None,
        );
    }
}
