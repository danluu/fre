#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableBuilder, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
    SearchWindow,
};

const CASES: [(&str, &[u8]); 4] = [
    (r"(?-u:[a-z]+?)", b"--hello--"),
    (r"(?-u:[0-9]+?)", b"xxxx12345"),
    (r"(?-u:[aceg]+)", b"xxacegg--"),
    (r"(?s-u:.)+", b"\x00ab\xff"),
];

#[test]
fn pure_byte_find_values_match_accounted_results_and_pinned_regex() {
    for (pattern, haystack) in CASES {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
        assert_eq!(
            regex.runtime_implementation_id(),
            fre::PURE_BYTE_CLASS_REPEAT_PLAN_ID
        );
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = SearchWindow::new(start, end);
                let expected = oracle
                    .find(&haystack[start..end])
                    .map(|matched| (start + matched.start(), start + matched.end()));
                let value = regex
                    .find_window_value(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end()));
                let accounted = regex
                    .find_window(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                let session_value = session
                    .find_window_value(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    value, expected,
                    "value pattern={pattern:?} window={start}..{end}"
                );
                assert_eq!(
                    accounted, expected,
                    "accounted pattern={pattern:?} window={start}..{end}"
                );
                assert_eq!(
                    session_value, expected,
                    "session pattern={pattern:?} window={start}..{end}"
                );
            }
        }
    }
}

#[test]
fn pure_byte_find_values_preserve_limits_and_invalid_precedence() {
    let mut tested_refusal = false;
    for (pattern, haystack) in CASES {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let (expected, accounting) = regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::PureByteClassRepeat(accounting) = accounting else {
            panic!("pure-byte fixture published another accounting family");
        };
        assert!(accounting.work_upper_bound > 0);
        let exact = SearchLimits {
            max_work: accounting.work_upper_bound,
            max_scratch_bytes: 0,
        };
        assert_eq!(regex.find_value(haystack, exact).unwrap(), expected);
        assert_eq!(regex.find_accounted(haystack, exact).unwrap().0, expected);

        if accounting.actual_work == 0 {
            let zero = SearchLimits {
                max_work: 0,
                max_scratch_bytes: 0,
            };
            assert_eq!(
                regex.find_value(haystack, zero).unwrap(),
                regex.find_accounted(haystack, zero).unwrap().0,
                "zero-work pattern={pattern:?}",
            );
        } else {
            tested_refusal = true;
            let one_below = SearchLimits {
                max_work: accounting.actual_work - 1,
                max_scratch_bytes: 0,
            };
            assert_eq!(
                regex.find_value(haystack, one_below).unwrap_err(),
                regex.find_accounted(haystack, one_below).unwrap_err(),
                "one-below pattern={pattern:?}",
            );
        }

        let invalid = haystack.len() + 1;
        let zero = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        let value_error = regex.find_at_value(haystack, invalid, zero).unwrap_err();
        assert_eq!(
            value_error,
            regex.find_at(haystack, invalid, zero).unwrap_err()
        );
        assert!(matches!(value_error, SearchError::PureByteClassRepeat(_)));
    }
    assert!(tested_refusal);
}
