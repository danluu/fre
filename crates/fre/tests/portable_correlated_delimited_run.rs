#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterRunLimits, SearchLimits, SearchSessionLimits, SearchWindow,
};

const PATTERN: &str = r"(?-u:(?:ab[bc]*Z|q[de]*Y))";
const FOUR_TERMINALS: &str =
    r"(?-u:(?:a[bc]*Q|d[ef]*T|g[hi]*X|j[kl]*Z))";
const FIVE_TERMINALS: &str =
    r"(?-u:(?:m[no]*V|p[rs]*U|s[uv]+R|w[xy]*P|h[ij]*N))";
const SIX_TERMINALS: &str =
    r"(?-u:(?:c[ab]*O|f[de]*M|i[gh]*L|l[jk]*K|o[mn]*J|r[pq]*I))";
const SEVEN_TERMINALS: &str =
    r"(?-u:(?:c[ab]*O|f[de]*M|i[gh]*L|l[jk]*K|o[mn]*J|r[pq]*I|u[st]*H))";
const EIGHT_TERMINALS: &str =
    r"(?-u:(?:c[ab]*O|f[de]*M|i[gh]*L|l[jk]*K|o[mn]*J|r[pq]*I|u[st]*H|x[vw]*G))";
const WIDE_TERMINAL_PATTERNS: [&str; 5] = [
    FOUR_TERMINALS,
    FIVE_TERMINALS,
    SIX_TERMINALS,
    SEVEN_TERMINALS,
    EIGHT_TERMINALS,
];
const CLASSIFIER_BLOCK_BYTES: usize = 16;

fn bytes_regex(pattern: &str) -> regex::bytes::Regex {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("failed to build Rust oracle {pattern:?}: {error}"))
}

fn spans(
    matches: impl Iterator<Item = Result<fre::Match, fre::PortableFindIterError>>,
) -> Vec<(usize, usize)> {
    matches
        .map(|matched| {
            let matched = matched.expect("portable value iteration");
            (matched.start(), matched.end())
        })
        .collect()
}

fn assert_window_values_match_rust(
    session: &mut fre::PortableSearchSession<'_>,
    oracle: &regex::bytes::Regex,
    haystack: &[u8],
    window: SearchWindow,
) {
    let slice = &haystack[window.start()..window.end()];
    let expected = oracle.find(slice).map(|matched| {
        (
            window.start() + matched.start(),
            window.start() + matched.end(),
        )
    });
    let expected_shortest = oracle
        .shortest_match(slice)
        .map(|end| window.start() + end);
    assert_eq!(
        session
            .find_window_value(haystack, window, SearchLimits::unlimited())
            .expect("windowed terminal-delimited find")
            .map(|matched| (matched.start(), matched.end())),
        expected,
    );
    assert_eq!(
        session
            .is_match_window_value(haystack, window, SearchLimits::unlimited())
            .expect("windowed terminal-delimited existence"),
        expected.is_some(),
    );
    assert_eq!(
        session
            .shortest_match_window_value(
                haystack,
                window,
                SearchLimits::unlimited(),
            )
            .expect("windowed terminal-delimited shortest match"),
        expected_shortest,
    );
}

fn assert_full_values_match_rust(
    session: &mut fre::PortableSearchSession<'_>,
    oracle: &regex::bytes::Regex,
    haystack: &[u8],
) {
    assert_window_values_match_rust(
        session,
        oracle,
        haystack,
        SearchWindow::full(haystack),
    );
    let expected = oracle
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(
        session
            .selected_end_value(haystack, SearchLimits::unlimited())
            .expect("terminal-delimited selected end"),
        expected.map(|(_, end)| end),
    );
    let expected_iter = oracle
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    assert_eq!(
        spans(session.find_iter_value(
            haystack,
            PortableFindIterRunLimits::unlimited(),
        )),
        expected_iter,
    );
}

#[test]
fn automatic_delimited_values_match_rust_in_every_small_window() {
    let portable = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("automatic terminal-delimited K0");
    assert_eq!(portable.build_report().plan, PlanKind::K0);
    let oracle = bytes_regex(PATTERN);
    let mut session = portable
        .search_session(SearchSessionLimits::unlimited())
        .expect("terminal-delimited session");

    fn enumerate(
        alphabet: &[u8],
        remaining: usize,
        source: &mut Vec<u8>,
        visit: &mut impl FnMut(&[u8]),
    ) {
        visit(source);
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            source.push(byte);
            enumerate(alphabet, remaining - 1, source, visit);
            source.pop();
        }
    }

    enumerate(
        b"abcZqdeYx",
        4,
        &mut Vec::new(),
        &mut |haystack| {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let slice = &haystack[start..end];
                    let expected = oracle
                        .find(slice)
                        .map(|matched| (start + matched.start(), start + matched.end()));
                    let expected_shortest = oracle
                        .shortest_match(slice)
                        .map(|matched_end| start + matched_end);
                    assert_eq!(
                        session
                            .find_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .expect("windowed terminal-delimited find")
                            .map(|matched| (matched.start(), matched.end())),
                        expected,
                        "find haystack={haystack:?} window={start}..{end}",
                    );
                    assert_eq!(
                        session
                            .is_match_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .expect("windowed terminal-delimited existence"),
                        expected.is_some(),
                        "is_match haystack={haystack:?} window={start}..{end}",
                    );
                    assert_eq!(
                        session
                            .shortest_match_window_value(
                                haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .expect("windowed terminal-delimited shortest match"),
                        expected_shortest,
                        "shortest haystack={haystack:?} window={start}..{end}",
                    );
                }
            }
        },
    );
}

#[test]
fn wide_delimited_values_match_rust_for_absent_late_windows_and_rejections() {
    for pattern in WIDE_TERMINAL_PATTERNS {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("automatic wide terminal-delimited K0");
        assert_eq!(portable.build_report().plan, PlanKind::K0);
        let oracle = bytes_regex(pattern);
        let mut session = portable
            .search_session(SearchSessionLimits::unlimited())
            .expect("wide terminal-delimited session");

        let absent = vec![b'~'; CLASSIFIER_BLOCK_BYTES * 9];
        assert_full_values_match_rust(&mut session, &oracle, &absent);

        let late_start = CLASSIFIER_BLOCK_BYTES * 5 + 3;
        let mut late = vec![b'~'; CLASSIFIER_BLOCK_BYTES * 9];
        let late_match = if pattern == FOUR_TERMINALS {
            b"abbbbQ".as_slice()
        } else if pattern == FIVE_TERMINALS {
            b"suvvR".as_slice()
        } else if pattern == SIX_TERMINALS {
            b"rpqqI".as_slice()
        } else if pattern == SEVEN_TERMINALS {
            b"usttH".as_slice()
        } else {
            b"xvwwG".as_slice()
        };
        late[late_start..late_start + late_match.len()]
            .copy_from_slice(late_match);
        assert_full_values_match_rust(&mut session, &oracle, &late);

        let mut windowed = late.clone();
        let early_match = if pattern == FOUR_TERMINALS {
            b"aQ".as_slice()
        } else if pattern == FIVE_TERMINALS {
            b"mV".as_slice()
        } else {
            b"cO".as_slice()
        };
        windowed[..early_match.len()].copy_from_slice(early_match);
        assert_window_values_match_rust(
            &mut session,
            &oracle,
            &windowed,
            SearchWindow::new(7, windowed.len() - 5),
        );

        let mut end_bounded = absent.clone();
        let after_end_start = end_bounded.len() - late_match.len();
        end_bounded[after_end_start..].copy_from_slice(late_match);
        assert_window_values_match_rust(
            &mut session,
            &oracle,
            &end_bounded,
            SearchWindow::new(7, end_bounded.len() - 1),
        );

        let rejection = CLASSIFIER_BLOCK_BYTES * 4 + 3;
        let rejected_terminal = if pattern == FOUR_TERMINALS {
            b'Q'
        } else if pattern == FIVE_TERMINALS {
            b'R'
        } else if pattern == SIX_TERMINALS {
            b'I'
        } else if pattern == SEVEN_TERMINALS {
            b'H'
        } else {
            b'G'
        };
        let mut rejected_then_near = vec![b'~'; CLASSIFIER_BLOCK_BYTES * 10];
        rejected_then_near[rejection] = rejected_terminal;
        let near_start = rejection + 7;
        rejected_then_near[near_start..near_start + late_match.len()]
            .copy_from_slice(late_match);
        assert_full_values_match_rust(
            &mut session,
            &oracle,
            &rejected_then_near,
        );

        let mut rejected_then_far = vec![b'~'; CLASSIFIER_BLOCK_BYTES * 10];
        rejected_then_far[rejection] = rejected_terminal;
        let far_start = rejection + CLASSIFIER_BLOCK_BYTES * 2;
        rejected_then_far[far_start..far_start + late_match.len()]
            .copy_from_slice(late_match);
        assert_full_values_match_rust(
            &mut session,
            &oracle,
            &rejected_then_far,
        );
    }
}

#[test]
fn wide_delimited_sessions_are_plan_local_across_same_address_mutations() {
    let four = PortableBuilder::new(FOUR_TERMINALS)
        .unicode(false)
        .build()
        .expect("four-terminal K0");
    let five = PortableBuilder::new(FIVE_TERMINALS)
        .unicode(false)
        .build()
        .expect("five-terminal K0");
    let eight = PortableBuilder::new(EIGHT_TERMINALS)
        .unicode(false)
        .build()
        .expect("eight-terminal K0");
    for portable in [&four, &five, &eight] {
        assert_eq!(portable.build_report().plan, PlanKind::K0);
    }
    let four_oracle = bytes_regex(FOUR_TERMINALS);
    let five_oracle = bytes_regex(FIVE_TERMINALS);
    let eight_oracle = bytes_regex(EIGHT_TERMINALS);
    let mut four_session = four
        .search_session(SearchSessionLimits::unlimited())
        .expect("four-terminal session");
    let mut five_session = five
        .search_session(SearchSessionLimits::unlimited())
        .expect("five-terminal session");
    let mut eight_session = eight
        .search_session(SearchSessionLimits::unlimited())
        .expect("eight-terminal session");

    const SOURCE_BYTES: usize = CLASSIFIER_BLOCK_BYTES * 8;
    let mut variants = Vec::new();
    for placements in [
        &[][..],
        &[(7_usize, b"abbbbQ".as_slice())][..],
        &[(CLASSIFIER_BLOCK_BYTES * 5 + 3, b"suvvR".as_slice())][..],
        &[(CLASSIFIER_BLOCK_BYTES * 5 + 3, b"xvwwG".as_slice())][..],
        &[
            (3_usize, b"deeeT".as_slice()),
            (CLASSIFIER_BLOCK_BYTES * 4 + 1, b"mnnnV".as_slice()),
            (CLASSIFIER_BLOCK_BYTES * 6 + 2, b"cabbO".as_slice()),
        ][..],
    ] {
        let mut source = vec![b'~'; SOURCE_BYTES];
        for &(start, bytes) in placements {
            source[start..start + bytes.len()].copy_from_slice(bytes);
        }
        variants.push(source);
    }
    variants.push(b"QTXZVURPNOMLKJIH".repeat(SOURCE_BYTES / 16));
    assert!(
        variants
            .iter()
            .all(|variant| variant.len() == SOURCE_BYTES)
    );

    let mut source = vec![0_u8; SOURCE_BYTES];
    let address = source.as_ptr();
    let capacity = source.capacity();
    for variant in variants.iter().cycle().take(12) {
        source.copy_from_slice(variant);
        assert_eq!(source.as_ptr(), address);
        assert_eq!(source.capacity(), capacity);
        for (session, oracle) in [
            (&mut four_session, &four_oracle),
            (&mut five_session, &five_oracle),
            (&mut eight_session, &eight_oracle),
        ] {
            assert_full_values_match_rust(session, oracle, &source);
        }
    }
}

#[test]
fn delimited_iterations_and_sessions_are_source_and_plan_local() {
    const OTHER: &str = r"(?-u:(?:mn[no]*X|r[st]+W))";
    let left = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("left terminal-delimited K0");
    let right = PortableBuilder::new(OTHER)
        .unicode(false)
        .build()
        .expect("right terminal-delimited K0");
    let left_oracle = bytes_regex(PATTERN);
    let right_oracle = bytes_regex(OTHER);
    let mut left_session = left
        .search_session(SearchSessionLimits::unlimited())
        .expect("left session");
    let mut right_session = right
        .search_session(SearchSessionLimits::unlimited())
        .expect("right session");
    let mut source = vec![b'~'; 64];
    let address = source.as_ptr();

    for placements in [
        &[][..],
        &[(7_usize, b"abbbbZ".as_slice())][..],
        &[(19_usize, b"rsttW".as_slice())][..],
        &[
            (3_usize, b"qdddY".as_slice()),
            (31_usize, b"mnnnX".as_slice()),
            (48_usize, b"abZ".as_slice()),
        ][..],
    ] {
        source.fill(b'~');
        for &(start, bytes) in placements {
            source[start..start + bytes.len()].copy_from_slice(bytes);
        }
        assert_eq!(source.as_ptr(), address);

        for (session, oracle) in [
            (&mut left_session, &left_oracle),
            (&mut right_session, &right_oracle),
        ] {
            let expected = oracle
                .find(&source)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                session
                    .find_value(&source, SearchLimits::unlimited())
                    .expect("terminal-delimited find")
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );
            assert_eq!(
                session
                    .selected_end_value(&source, SearchLimits::unlimited())
                    .expect("terminal-delimited selected end"),
                expected.map(|(_, end)| end),
            );
            let expected_iter = oracle
                .find_iter(&source)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            assert_eq!(
                spans(session.find_iter_value(
                    &source,
                    PortableFindIterRunLimits::unlimited(),
                )),
                expected_iter,
            );
        }
    }

    let limited = SearchLimits {
        max_work: 0,
        max_scratch_bytes: 0,
    };
    assert!(left_session.find_value(&source, limited).is_err());
    assert!(
        left_session
            .find_window_value(
                &source,
                SearchWindow::new(1, source.len() + 1),
                SearchLimits::unlimited(),
            )
            .is_err(),
    );
}

#[test]
fn optional_delimited_plan_closes_planner_and_persistent_boundaries() {
    let builder = PortableBuilder::new(PATTERN).unicode(false);
    let automatic = builder.clone().build().expect("automatic K0 probe");
    let forced = builder
        .clone()
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("mandatory K0 probe");
    assert_eq!(automatic.build_report().plan, PlanKind::K0);
    assert_eq!(forced.build_report().plan, PlanKind::K0);
    assert!(
        automatic.build_report().plan_storage_bytes
            > forced.build_report().plan_storage_bytes,
    );

    let exact_planner = automatic.build_report().planner_work;
    let mut limits = BuildLimits {
        max_planner_work: exact_planner,
        ..BuildLimits::default()
    };
    let exact = builder
        .clone()
        .limits(limits)
        .build()
        .expect("exact optional planner boundary");
    assert_eq!(
        exact.build_report().plan_storage_bytes,
        automatic.build_report().plan_storage_bytes,
    );
    limits.max_planner_work = exact_planner.checked_sub(1).unwrap();
    let declined = builder
        .clone()
        .limits(limits)
        .build()
        .expect("one-below optional planner boundary preserves K0");
    assert_eq!(declined.build_report().plan, PlanKind::K0);
    assert!(declined.build_report().planner_work <= limits.max_planner_work);
    assert!(
        declined.build_report().plan_storage_bytes
            < automatic.build_report().plan_storage_bytes,
    );

    let admitted_bytes = automatic.build_report().charged_persistent_bytes;
    let exact = builder
        .clone()
        .max_persistent_bytes(admitted_bytes)
        .build()
        .expect("exact optional persistent boundary");
    assert_eq!(exact.build_report().charged_persistent_bytes, admitted_bytes);
    let declined = builder
        .clone()
        .max_persistent_bytes(admitted_bytes.checked_sub(1).unwrap())
        .build()
        .expect("one-below optional persistent boundary preserves K0");
    assert_eq!(declined.build_report().plan, PlanKind::K0);
    assert!(
        declined.build_report().charged_persistent_bytes
            <= declined.build_report().persistent_byte_limit,
    );
    assert!(
        declined.build_report().plan_storage_bytes
            < automatic.build_report().plan_storage_bytes,
    );

    let mandatory_bytes = forced.build_report().charged_persistent_bytes;
    let mandatory = builder
        .clone()
        .max_persistent_bytes(mandatory_bytes)
        .build()
        .expect("mandatory automatic K0 boundary");
    assert_eq!(mandatory.build_report().charged_persistent_bytes, mandatory_bytes);
    let error = builder
        .max_persistent_bytes(mandatory_bytes.checked_sub(1).unwrap())
        .build()
        .expect_err("one-below mandatory K0 must fail");
    assert!(matches!(
        error,
        BuildError::PersistentBytesLimit { needed, limit }
            if needed == mandatory_bytes && limit == mandatory_bytes - 1
    ));
}

#[test]
fn wide_delimited_planner_and_storage_boundaries_are_exact() {
    for pattern in WIDE_TERMINAL_PATTERNS {
        let builder = PortableBuilder::new(pattern).unicode(false);
        let automatic = builder
            .clone()
            .build()
            .expect("automatic wide terminal plan");
        let forced = builder
            .clone()
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("wide fixture mandatory K0");
        assert_eq!(automatic.build_report().plan, PlanKind::K0);
        assert_eq!(forced.build_report().plan, PlanKind::K0);
        assert!(
            automatic.build_report().plan_storage_bytes
                > forced.build_report().plan_storage_bytes,
            "pattern={pattern:?}",
        );

        let exact_planner = automatic.build_report().planner_work;
        let mut limits = BuildLimits {
            max_planner_work: exact_planner,
            ..BuildLimits::default()
        };
        let exact = builder
            .clone()
            .limits(limits)
            .build()
            .expect("exact wide planner boundary");
        assert_eq!(
            exact.build_report().plan_storage_bytes,
            automatic.build_report().plan_storage_bytes,
            "pattern={pattern:?}",
        );
        limits.max_planner_work = exact_planner
            .checked_sub(1)
            .expect("wide planner work is nonzero");
        let declined = builder
            .clone()
            .limits(limits)
            .build()
            .expect("one-below wide optional planner boundary preserves K0");
        assert_eq!(declined.build_report().plan, PlanKind::K0);
        assert!(declined.build_report().planner_work <= limits.max_planner_work);
        assert!(
            declined.build_report().plan_storage_bytes
                < automatic.build_report().plan_storage_bytes,
            "pattern={pattern:?}",
        );

        let exact_bytes = automatic.build_report().charged_persistent_bytes;
        let exact = builder
            .clone()
            .max_persistent_bytes(exact_bytes)
            .build()
            .expect("exact wide persistent boundary");
        assert_eq!(
            exact.build_report().charged_persistent_bytes,
            exact_bytes,
            "pattern={pattern:?}",
        );
        let declined = builder
            .max_persistent_bytes(
                exact_bytes
                    .checked_sub(1)
                    .expect("wide persistent bytes are nonzero"),
            )
            .build()
            .expect("one-below wide optional persistent boundary preserves K0");
        assert_eq!(declined.build_report().plan, PlanKind::K0);
        assert!(declined.build_report().charged_persistent_bytes < exact_bytes);
        assert!(
            declined.build_report().plan_storage_bytes
                < automatic.build_report().plan_storage_bytes,
            "pattern={pattern:?}",
        );
    }
}
