#![forbid(unsafe_code)]

use fre::{
    BOUNDED_BYTE_CLASS_SEQUENCE_PLAN_ID, BoundedByteClassSequenceSearchError, PortableBuilder,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
};

const CASES: [(&str, &[u8]); 4] = [
    (r"(?-u:[ab]){1,3}(?-u:[CD]){1,3}(?-u:[xy])?", b"xxaCDx--bD"),
    (
        r"(?-u:[QX])(?-u:[0-2]){1,3}(?-u:[a-c]){0,4}(?-u:[b-d])",
        b"--Q01abbd--X2c",
    ),
    (
        r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,11}(?-u:\x7a)",
        b"\xff\x12\x16EEz\x10z",
    ),
    (
        r"\A(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,11}(?-u:\x7a)",
        b"\x12\x16EEz--\x10z",
    ),
];

#[test]
fn bounded_sequence_shortest_values_match_accounted_oracle_and_session() {
    for (pattern, haystack) in CASES {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            regex.runtime_implementation_id(),
            BOUNDED_BYTE_CLASS_SEQUENCE_PLAN_ID,
        );
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        for start in 0..=haystack.len() {
            let expected = oracle.shortest_match_at(haystack, start);
            assert_eq!(
                regex
                    .shortest_match_at_value(haystack, start, SearchLimits::unlimited())
                    .unwrap(),
                expected,
                "immutable value pattern={pattern:?} start={start}",
            );
            assert_eq!(
                session
                    .shortest_match_at_value(haystack, start, SearchLimits::unlimited())
                    .unwrap(),
                expected,
                "session value pattern={pattern:?} start={start}",
            );
            assert_eq!(
                regex
                    .shortest_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected,
                "accounted pattern={pattern:?} start={start}",
            );
        }
    }
}

#[test]
fn bounded_sequence_shortest_values_preserve_limits_and_invalid_precedence() {
    for (pattern, haystack) in CASES {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            regex.runtime_implementation_id(),
            BOUNDED_BYTE_CLASS_SEQUENCE_PLAN_ID,
        );
        let (expected, accounting) = regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::BoundedByteClassSequence(accounting) = accounting else {
            panic!("bounded-sequence shortest fixture published another accounting family");
        };
        assert!(accounting.actual_work > 0);
        let exact = SearchLimits {
            max_work: accounting.actual_work,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            regex.shortest_match_value(haystack, exact).unwrap(),
            expected,
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

        let invalid = haystack.len() + 1;
        let zero = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        let value_error = regex
            .shortest_match_at_value(haystack, invalid, zero)
            .unwrap_err();
        assert_eq!(
            value_error,
            regex
                .shortest_match_at(haystack, invalid, zero)
                .unwrap_err(),
        );
        assert!(matches!(
            value_error,
            SearchError::BoundedByteClassSequence(
                BoundedByteClassSequenceSearchError::InvalidWindow
            )
        ));
    }
}
