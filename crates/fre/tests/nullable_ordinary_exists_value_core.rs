#![forbid(unsafe_code)]

use fre::{
    NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID, NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
    NullableOptionalChainSearchError, PortableBuilder, SearchAccounting, SearchError, SearchLimits,
    SearchWindow,
};

const CASES: [(&str, &[u8], usize, &str); 4] = [
    (
        r"(?-u:[ab]{0,3}[cd]{0,2}z)",
        b"abcz",
        6,
        NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
    ),
    (
        r"(?-u:[ab]{0,3}?[cd]{0,2}?zz)",
        b"abcz",
        6,
        NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
    ),
    (
        r"(?-u:(?:a|aa|ba){0,3}z)",
        b"abz",
        7,
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    ),
    (
        r"(?-u:(?:ab|b|baa){0,3}?z)",
        b"abz",
        7,
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    ),
];

fn enumerate_haystacks(alphabet: &[u8], maximum: usize, mut visit: impl FnMut(&[u8])) {
    fn recurse(
        alphabet: &[u8],
        remaining: usize,
        haystack: &mut Vec<u8>,
        visit: &mut impl FnMut(&[u8]),
    ) {
        visit(haystack);
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            haystack.push(byte);
            recurse(alphabet, remaining - 1, haystack, visit);
            haystack.pop();
        }
    }

    recurse(alphabet, maximum, &mut Vec::new(), &mut visit);
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn ordinary_nullable_exists_matches_canonical_accounting_and_upstream_exhaustively() {
    for (pattern, alphabet, maximum, plan_id) in CASES {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(regex.runtime_implementation_id(), plan_id);

        enumerate_haystacks(alphabet, maximum, |haystack| {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let expected_exists = expected.is_some();
            assert_eq!(
                regex.is_match(haystack),
                expected_exists,
                "ordinary exists {pattern:?}/{haystack:?}",
            );
            assert_eq!(
                regex
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                expected_exists,
                "canonical exists {pattern:?}/{haystack:?}",
            );
            assert_eq!(
                regex
                    .is_match_accounted(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected_exists,
                "accounted exists {pattern:?}/{haystack:?}",
            );

            assert_eq!(span(regex.find(haystack)), expected);
            assert_eq!(
                span(
                    regex
                        .find_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                ),
                expected,
            );
            assert_eq!(
                span(
                    regex
                        .find_accounted(haystack, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                ),
                expected,
            );
        });
    }
}

#[test]
fn ordinary_nullable_exists_covers_long_prefixes_tail_only_and_misses() {
    let optional_pattern = r"(?-u:[ab]{0,64}z)";
    let optional = PortableBuilder::new(optional_pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(
        optional.runtime_implementation_id(),
        NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
    );
    let mut optional_haystack = vec![b'x'; 3];
    optional_haystack.extend(core::iter::repeat_n(b'a', 80));
    optional_haystack.push(b'z');
    optional_haystack.extend_from_slice(b"--z");

    let token = "a".repeat(64);
    let finite_pattern = format!(r"(?-u:(?:{token}|b){{0,8}}z)");
    let finite = PortableBuilder::new(&finite_pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(
        finite.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let mut finite_haystack = b"xxx".to_vec();
    finite_haystack.extend(core::iter::repeat_n(b'a', 8 * 64));
    finite_haystack.push(b'z');
    finite_haystack.extend_from_slice(b"--z");

    for (pattern, regex, haystack) in [
        (optional_pattern, &optional, optional_haystack.as_slice()),
        (&finite_pattern, &finite, finite_haystack.as_slice()),
    ] {
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(regex.is_match(haystack), upstream.is_match(haystack));
        assert_eq!(regex.is_match(b"z"), upstream.is_match(b"z"));
        assert!(!regex.is_match(b"xxxxxxxx"));
    }
}

#[test]
fn finite_exists_apis_retain_canonical_failure_precedence() {
    for (pattern, haystack, plan_id) in [
        (
            r"(?-u:[ab]{0,3}[cd]{0,2}z)",
            b"xxaacz--z".as_slice(),
            NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
        ),
        (
            r"(?-u:(?:a|aa|ba){0,5}z)",
            b"xxaabaabazyy".as_slice(),
            NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
        ),
    ] {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(regex.runtime_implementation_id(), plan_id);
        let (expected, accounting) = regex
            .is_match_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::NullableOptionalChain(accounting) = accounting else {
            panic!("nullable fixture published another accounting family");
        };
        let exact = SearchLimits {
            max_work: accounting.work_upper_bound,
            max_scratch_bytes: usize::from(accounting.scratch_bytes),
        };
        assert_eq!(regex.is_match_value(haystack, exact).unwrap(), expected);

        let one_below = SearchLimits {
            max_work: accounting.work_upper_bound - 1,
            max_scratch_bytes: usize::MAX,
        };
        assert_eq!(
            regex.is_match_value(haystack, one_below).unwrap_err(),
            regex.is_match_accounted(haystack, one_below).unwrap_err(),
        );

        let invalid = SearchWindow::new(haystack.len() + 1, haystack.len() + 1);
        let zero = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            regex
                .is_match_window_value(haystack, invalid, zero)
                .unwrap_err(),
            regex.is_match_window(haystack, invalid, zero).unwrap_err(),
        );
        assert!(matches!(
            regex.is_match_window_value(haystack, invalid, zero),
            Err(SearchError::NullableOptionalChain(
                NullableOptionalChainSearchError::InvalidWindow
            ))
        ));
    }
}
