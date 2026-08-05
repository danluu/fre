#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterRunLimits, SearchLimits, SearchSessionLimits, SearchWindow,
};

const PATTERN: &str = r"(?-u:(?:ab[bc]*Z|q[de]*Y))";

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
