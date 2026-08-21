#![forbid(unsafe_code)]

use std::borrow::Cow;

use fre::{
    NoExpand, PlanKind, PlanSelection, PortableBuilder, PortableFindIterError,
    PortableFindIterLimits, PortableFindIterRunLimits, PortableValueReplacementError, RustProfile,
    SearchLimits, SearchSessionLimits, ValueReplacementOutputLimits,
};

#[derive(Clone, Copy)]
struct Case {
    pattern: &'static str,
    haystack: &'static [u8],
    replacement: &'static [u8],
    unicode: bool,
}

const CASES: &[Case] = &[
    Case {
        pattern: r"[0-9]",
        haystack: b"age: 26",
        replacement: b"Z",
        unicode: false,
    },
    Case {
        pattern: r"([^ ]+)[ ]+([^ ]+)",
        haystack: b"w1 w2",
        replacement: b"$2 $1",
        unicode: false,
    },
    Case {
        pattern: r"^",
        haystack: b"bar",
        replacement: b"foo",
        unicode: false,
    },
    Case {
        pattern: r"^$",
        haystack: b"",
        replacement: b"",
        unicode: false,
    },
    Case {
        pattern: r"a",
        haystack: b"a",
        replacement: b"a",
        unicode: false,
    },
    Case {
        pattern: r"a*?",
        haystack: b"ab",
        replacement: b"_",
        unicode: false,
    },
    Case {
        pattern: r"(?m:^a+$)",
        haystack: b"x\naa\nz",
        replacement: b"$$",
        unicode: false,
    },
    Case {
        pattern: r"[a-c\xFF]+",
        haystack: &[b'x', 0xFF, b'a', b'b', b'!'],
        replacement: &[0xFF, b'Z'],
        unicode: false,
    },
    Case {
        pattern: r"Z",
        haystack: &[b'a', 0xFF, b'b'],
        replacement: b"unused",
        unicode: false,
    },
    Case {
        pattern: r"",
        haystack: "Ⅰ1".as_bytes(),
        replacement: b"_",
        unicode: true,
    },
];

#[test]
fn first_literal_value_matches_pinned_no_expand_and_ownership() {
    for case in CASES {
        let regex = PortableBuilder::new(case.pattern)
            .profile(RustProfile::regex_1_12_4())
            .unicode(case.unicode)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {:?}: {error}", case.pattern));
        let upstream = regex::bytes::RegexBuilder::new(case.pattern)
            .unicode(case.unicode)
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {:?}: {error}", case.pattern));
        let expected = upstream.replace(case.haystack, regex::bytes::NoExpand(case.replacement));
        let matched = upstream.find(case.haystack).is_some();

        let fresh = regex
            .replace_literal_value(
                case.haystack,
                NoExpand(case.replacement),
                PortableFindIterLimits::unlimited(),
                ValueReplacementOutputLimits::default(),
            )
            .unwrap_or_else(|error| {
                panic!("fresh replacement failed for {:?}: {error}", case.pattern)
            });
        assert_eq!(
            fresh.as_ref(),
            expected.as_ref(),
            "fresh {:?}",
            case.pattern
        );
        assert_eq!(
            matches!(fresh, Cow::Owned(_)),
            matched,
            "fresh {:?}",
            case.pattern
        );

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap_or_else(|error| panic!("session setup failed for {:?}: {error}", case.pattern));
        let reused = session
            .replace_literal_value(
                case.haystack,
                case.replacement,
                PortableFindIterRunLimits::unlimited(),
                ValueReplacementOutputLimits::default(),
            )
            .unwrap_or_else(|error| {
                panic!("session replacement failed for {:?}: {error}", case.pattern)
            });
        assert_eq!(
            reused.as_ref(),
            expected.as_ref(),
            "session {:?}",
            case.pattern
        );
        assert_eq!(
            matches!(reused, Cow::Owned(_)),
            matched,
            "session {:?}",
            case.pattern
        );
    }
}

#[test]
fn value_replacement_preserves_setup_search_and_call_cap_refusals() {
    let regex = PortableBuilder::new(r"(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 value replacement regex");
    let zero_calls = PortableFindIterLimits {
        max_search_calls: 0,
        ..PortableFindIterLimits::unlimited()
    };
    assert_eq!(
        regex
            .replace_literal_value(
                b"ababx",
                b"_",
                zero_calls,
                ValueReplacementOutputLimits::default(),
            )
            .expect_err("zero call cap must refuse"),
        PortableValueReplacementError::Iteration(PortableFindIterError::SearchCallLimit {
            needed: 1,
            limit: 0,
        })
    );

    let setup_refusal = PortableFindIterLimits {
        session: SearchSessionLimits {
            max_setup_work: 0,
            max_scratch_bytes: 0,
        },
        ..PortableFindIterLimits::unlimited()
    };
    assert!(matches!(
        regex
            .replace_literal_value(
                b"ababx",
                b"_",
                setup_refusal,
                ValueReplacementOutputLimits::default(),
            )
            .expect_err("zero setup allowance must refuse K0"),
        PortableValueReplacementError::Setup(_)
    ));

    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("unlimited K0 session");
    let run_zero_calls = PortableFindIterRunLimits {
        max_search_calls: 0,
        ..PortableFindIterRunLimits::unlimited()
    };
    assert_eq!(
        session
            .replace_literal_value(
                b"ababx",
                b"_",
                run_zero_calls,
                ValueReplacementOutputLimits::default(),
            )
            .expect_err("session zero call cap must refuse"),
        PortableValueReplacementError::Iteration(PortableFindIterError::SearchCallLimit {
            needed: 1,
            limit: 0,
        })
    );

    let no_work = PortableFindIterRunLimits {
        search: SearchLimits {
            max_work: 0,
            max_scratch_bytes: usize::MAX,
        },
        max_search_calls: 1,
    };
    assert!(matches!(
        session
            .replace_literal_value(
                b"ababx",
                b"_",
                no_work,
                ValueReplacementOutputLimits::default(),
            )
            .expect_err("zero search work must refuse"),
        PortableValueReplacementError::Iteration(PortableFindIterError::Search(_))
    ));

    let recovered = session
        .replace_literal_value(
            b"ababx",
            b"_",
            PortableFindIterRunLimits {
                max_search_calls: 1,
                ..PortableFindIterRunLimits::unlimited()
            },
            ValueReplacementOutputLimits::default(),
        )
        .expect("session must remain reusable after refusal");
    assert_eq!(recovered.as_ref(), b"_x");
}

#[test]
fn exact_literal_value_replacement_matches_the_first_value_iterator_item() {
    let regex = PortableBuilder::new("needle")
        .unicode(false)
        .build()
        .expect("exact literal value replacement regex");
    assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);

    let limits = [
        PortableFindIterLimits::unlimited(),
        PortableFindIterLimits {
            session: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            },
            ..PortableFindIterLimits::unlimited()
        },
        PortableFindIterLimits {
            search: SearchLimits {
                max_work: 0,
                max_scratch_bytes: 0,
            },
            ..PortableFindIterLimits::unlimited()
        },
        PortableFindIterLimits {
            max_search_calls: 0,
            ..PortableFindIterLimits::unlimited()
        },
    ];
    let output_limits = ValueReplacementOutputLimits {
        max_output_bytes: usize::MAX,
        max_output_capacity_bytes: usize::MAX,
    };

    for haystack in [
        b"needle first".as_slice(),
        b"prefix needle suffix".as_slice(),
        b"absent".as_slice(),
        b"".as_slice(),
    ] {
        for iterator_limits in limits {
            let first = regex
                .find_iter_value(haystack, iterator_limits)
                .expect("an exact literal needs no session resources")
                .next();
            let actual =
                regex.replace_literal_value(haystack, b"X", iterator_limits, output_limits);

            match first {
                Some(Ok(matched)) => {
                    let mut expected = Vec::new();
                    expected.extend_from_slice(&haystack[..matched.start()]);
                    expected.extend_from_slice(b"X");
                    expected.extend_from_slice(&haystack[matched.end()..]);
                    assert_eq!(actual.expect("matching replacement").as_ref(), expected);
                }
                Some(Err(error)) => assert_eq!(
                    actual.expect_err("the direct search must preserve iterator refusal"),
                    PortableValueReplacementError::Iteration(error),
                ),
                None => {
                    let actual = actual.expect("absent replacement");
                    assert!(matches!(actual, Cow::Borrowed(_)));
                    assert_eq!(actual.as_ref(), haystack);
                }
            }
        }
    }
}

#[test]
fn fixed_predicate_value_replacement_matches_the_first_value_iterator_item() {
    let regex = PortableBuilder::new(r"[A-D][\x00-\x7F]Q")
        .unicode(false)
        .build()
        .expect("fixed-predicate value replacement regex");
    assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);

    let limits = [
        PortableFindIterLimits::unlimited(),
        PortableFindIterLimits {
            session: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            },
            ..PortableFindIterLimits::unlimited()
        },
        PortableFindIterLimits {
            search: SearchLimits {
                max_work: 0,
                max_scratch_bytes: 0,
            },
            ..PortableFindIterLimits::unlimited()
        },
        PortableFindIterLimits {
            max_search_calls: 0,
            ..PortableFindIterLimits::unlimited()
        },
    ];
    let output_limits = ValueReplacementOutputLimits {
        max_output_bytes: usize::MAX,
        max_output_capacity_bytes: usize::MAX,
    };

    for haystack in [
        b"A!Q first".as_slice(),
        b"prefix D0Q suffix".as_slice(),
        b"absent".as_slice(),
        b"".as_slice(),
    ] {
        for iterator_limits in limits {
            let first = regex
                .find_iter_value(haystack, iterator_limits)
                .expect("a fixed predicate needs no session resources")
                .next();
            let actual =
                regex.replace_literal_value(haystack, b"X", iterator_limits, output_limits);

            match first {
                Some(Ok(matched)) => {
                    let mut expected = Vec::new();
                    expected.extend_from_slice(&haystack[..matched.start()]);
                    expected.extend_from_slice(b"X");
                    expected.extend_from_slice(&haystack[matched.end()..]);
                    assert_eq!(actual.expect("matching replacement").as_ref(), expected);
                }
                Some(Err(error)) => assert_eq!(
                    actual.expect_err("the direct search must preserve iterator refusal"),
                    PortableValueReplacementError::Iteration(error),
                ),
                None => {
                    let actual = actual.expect("absent replacement");
                    assert!(matches!(actual, Cow::Borrowed(_)));
                    assert_eq!(actual.as_ref(), haystack);
                }
            }
        }
    }
}

#[test]
fn value_replacement_enforces_exact_output_and_observed_capacity_limits() {
    let regex = PortableBuilder::new(r"[0-9]")
        .unicode(false)
        .build()
        .expect("value replacement limit regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("value replacement limit session");
    let exact_output = ValueReplacementOutputLimits {
        max_output_bytes: 9,
        max_output_capacity_bytes: usize::MAX,
    };
    let exact = session
        .replace_literal_value(
            b"age: 26",
            b"XYZ",
            PortableFindIterRunLimits::unlimited(),
            exact_output,
        )
        .expect("exact output limit");
    let observed_capacity = match exact {
        Cow::Owned(bytes) => {
            assert_eq!(bytes, b"age: XYZ6");
            bytes.capacity()
        }
        Cow::Borrowed(_) => panic!("a matched replacement must be owned"),
    };

    assert_eq!(
        session
            .replace_literal_value(
                b"age: 26",
                b"XYZ",
                PortableFindIterRunLimits::unlimited(),
                ValueReplacementOutputLimits {
                    max_output_bytes: 8,
                    max_output_capacity_bytes: usize::MAX,
                },
            )
            .expect_err("one below exact output must refuse"),
        PortableValueReplacementError::OutputBytesLimit {
            needed: 9,
            limit: 8,
        }
    );

    let below_capacity = observed_capacity
        .checked_sub(1)
        .expect("nonempty output must retain capacity");
    assert_eq!(
        session
            .replace_literal_value(
                b"age: 26",
                b"XYZ",
                PortableFindIterRunLimits::unlimited(),
                ValueReplacementOutputLimits {
                    max_output_bytes: 9,
                    max_output_capacity_bytes: below_capacity,
                },
            )
            .expect_err("one below observed capacity must refuse"),
        PortableValueReplacementError::OutputCapacityBytesLimit {
            needed: observed_capacity,
            limit: below_capacity,
        }
    );

    let borrowed = session
        .replace_literal_value(
            b"no digits",
            b"XYZ",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits {
                max_output_bytes: 9,
                max_output_capacity_bytes: 0,
            },
        )
        .expect("borrowed no-match at exact logical output limit");
    assert!(matches!(borrowed, Cow::Borrowed(b"no digits")));
    assert_eq!(
        session
            .replace_literal_value(
                b"no digits",
                b"XYZ",
                PortableFindIterRunLimits::unlimited(),
                ValueReplacementOutputLimits {
                    max_output_bytes: 8,
                    max_output_capacity_bytes: usize::MAX,
                },
            )
            .expect_err("borrowed output still obeys its logical byte cap"),
        PortableValueReplacementError::OutputBytesLimit {
            needed: 9,
            limit: 8,
        }
    );

    let recovered = session
        .replace_literal_value(
            b"age: 26",
            b"Z",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("session must remain reusable after output refusals");
    assert_eq!(recovered.as_ref(), b"age: Z6");
}
