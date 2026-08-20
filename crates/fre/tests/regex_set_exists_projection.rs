#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegex, PortableRegexSet, PortableRegexSetExecutionError,
    PortableRegexSetRunLimits, SearchLimits, SearchWindow,
};

const PATTERNS: [&str; 3] = ["!", "[a-z]+", r"(?-u:[0-9]+)"];

fn warm(regexes: &[PortableRegex], set: &PortableRegexSet) {
    for regex in regexes {
        let _ = regex
            .is_match_accounted(b"", SearchLimits::unlimited())
            .expect("direct warm-up search");
    }
    let _ = set
        .matches(b"", PortableRegexSetRunLimits::unlimited())
        .expect("set warm-up search");
}

fn direct_exists(regexes: &[PortableRegex], haystack: &[u8], start: usize) -> Vec<(bool, u64)> {
    regexes
        .iter()
        .map(|regex| {
            let (matched, accounting) = regex
                .is_match_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .expect("direct existence search");
            (matched, accounting.work_or_linear_terms())
        })
        .collect()
}

fn total_work(results: &[(bool, u64)]) -> u64 {
    results
        .iter()
        .map(|(_, work)| *work)
        .try_fold(0_u64, u64::checked_add)
        .expect("small fixture work sum")
}

fn matching_ids(results: &[(bool, u64)]) -> Vec<usize> {
    results
        .iter()
        .enumerate()
        .filter_map(|(index, (matched, _))| matched.then_some(index))
        .collect()
}

#[test]
fn every_set_membership_path_projects_exists_across_native_and_k0_plans() {
    let regexes = PATTERNS
        .iter()
        .map(|pattern| PortableRegex::new(*pattern).expect("constituent regex"))
        .collect::<Vec<_>>();
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan regex set");
    assert_eq!(
        (0..set.len())
            .map(|index| set.pattern_build_report(index).unwrap().plan)
            .collect::<Vec<_>>(),
        vec![
            PlanKind::ExactLiteral,
            PlanKind::K0,
            PlanKind::PureByteClassRepeat,
        ]
    );
    warm(&regexes, &set);

    let cases: &[(&[u8], usize, &[usize])] = &[
        (b"!", 0, &[0]),
        (b"abc", 0, &[1]),
        (b"123", 0, &[2]),
        (b"\xFF", 0, &[]),
        (b"!abc123", 0, &[0, 1, 2]),
        (b"!abc123", 1, &[1, 2]),
        (b"!abc123", 4, &[2]),
        (b"!abc123", 7, &[]),
    ];
    for &(haystack, start, expected_ids) in cases {
        let direct = direct_exists(&regexes, haystack, start);
        assert_eq!(matching_ids(&direct), expected_ids);
        let expected_total = total_work(&direct);

        let (any, any_report) = set
            .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .expect("set existence search");
        assert_eq!(any, !expected_ids.is_empty());
        let searched = expected_ids
            .first()
            .map_or(PATTERNS.len(), |index| index + 1);
        assert_eq!(any_report.patterns_searched, searched);
        assert_eq!(any_report.work, total_work(&direct[..searched]));

        let matches = set
            .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .expect("set ID search");
        assert_eq!(matches.iter().collect::<Vec<_>>(), expected_ids);
        assert_eq!(matches.report().work, expected_total);

        let mut read = [false; PATTERNS.len()];
        let (read_any, read_report) = set
            .matches_read_at(
                &mut read,
                haystack,
                start,
                PortableRegexSetRunLimits {
                    max_output_bytes: 0,
                    ..PortableRegexSetRunLimits::unlimited()
                },
            )
            .expect("caller-owned ID search");
        assert_eq!(read_any, any);
        assert_eq!(
            read,
            core::array::from_fn(|index| expected_ids.contains(&index))
        );
        assert_eq!(read_report.work, expected_total);
        assert_eq!(read_report.output_capacity_bytes, 0);

        let mut alias = [false; PATTERNS.len()];
        let (alias_any, alias_report) = set
            .read_matches_at(
                &mut alias,
                haystack,
                start,
                PortableRegexSetRunLimits {
                    max_output_bytes: 0,
                    ..PortableRegexSetRunLimits::unlimited()
                },
            )
            .expect("caller-buffer alias search");
        assert_eq!((alias_any, alias), (read_any, read));
        assert_eq!(alias_report.work, expected_total);
    }
}

#[test]
fn cumulative_exists_work_limits_are_exact_and_one_below_for_every_set_path() {
    let regexes = PATTERNS
        .iter()
        .map(|pattern| PortableRegex::new(*pattern).expect("constituent regex"))
        .collect::<Vec<_>>();
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan regex set");
    warm(&regexes, &set);

    let haystack = b"\xFF";
    let direct = direct_exists(&regexes, haystack, 0);
    assert!(direct.iter().all(|(matched, work)| !matched && *work > 0));
    let exact_work = total_work(&direct);
    let exact = PortableRegexSetRunLimits {
        max_total_work: exact_work,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let below = PortableRegexSetRunLimits {
        max_total_work: exact_work - 1,
        ..PortableRegexSetRunLimits::unlimited()
    };

    let (any, any_report) = set
        .is_match(haystack, exact)
        .expect("exact cumulative is_match work");
    assert!(!any);
    assert_eq!(any_report.work, exact_work);
    let error = set
        .is_match(haystack, below)
        .expect_err("one-below cumulative is_match work");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::Pattern {
            total_work_before,
            remaining_total_work,
            ..
        } if total_work_before + remaining_total_work == exact_work - 1
    ));

    let matches = set
        .matches(haystack, exact)
        .expect("exact cumulative matches work");
    assert!(matches.iter().next().is_none());
    assert_eq!(matches.report().work, exact_work);
    assert!(matches!(
        set.matches(haystack, below),
        Err(PortableRegexSetExecutionError::Pattern { .. })
    ));

    let mut read = [false; PATTERNS.len()];
    let (read_any, read_report) = set
        .matches_read_at(&mut read, haystack, 0, exact)
        .expect("exact cumulative caller-buffer work");
    assert!(!read_any);
    assert_eq!(read, [false; PATTERNS.len()]);
    assert_eq!(read_report.work, exact_work);
    let (alias_any, alias_report) = set
        .read_matches_at(&mut read, haystack, 0, exact)
        .expect("exact cumulative caller-buffer alias work");
    assert!(!alias_any);
    assert_eq!(alias_report.work, exact_work);
    assert!(matches!(
        set.matches_read_at(&mut read, haystack, 0, below),
        Err(PortableRegexSetExecutionError::Pattern { .. })
    ));
    assert!(matches!(
        set.read_matches_at(&mut read, haystack, 0, below),
        Err(PortableRegexSetExecutionError::Pattern { .. })
    ));
}

#[test]
fn per_pattern_exists_work_limits_are_exact_with_the_total_budget_unlimited() {
    let cases: &[(&str, &[u8], PlanKind)] = &[
        ("!", b"prefix!suffix", PlanKind::ExactLiteral),
        ("[a-z]+", b"\xFFabc", PlanKind::K0),
        (
            r"(?-u:[0-9]+)",
            b"prefix123suffix",
            PlanKind::PureByteClassRepeat,
        ),
    ];

    for &(pattern, haystack, expected_plan) in cases {
        let regex = PortableRegex::new(pattern).expect("constituent regex");
        let set = PortableRegexSet::new([pattern]).expect("single-pattern regex set");
        assert_eq!(regex.build_report().plan, expected_plan, "{pattern:?}");
        assert_eq!(
            set.pattern_build_report(0)
                .expect("set pattern report")
                .plan,
            expected_plan,
            "{pattern:?}",
        );

        let _ = regex
            .is_match_accounted(b"", SearchLimits::unlimited())
            .expect("direct warm-up search");
        let _ = set
            .matches(b"", PortableRegexSetRunLimits::unlimited())
            .expect("set warm-up search");
        let (matched, accounting) = regex
            .is_match_accounted(haystack, SearchLimits::unlimited())
            .expect("direct existence work probe");
        assert!(matched, "{pattern:?}");
        let exact_work = accounting.work_or_linear_terms();
        assert!(exact_work > 0, "{pattern:?}");

        let exact = PortableRegexSetRunLimits {
            pattern: SearchLimits {
                max_work: exact_work,
                ..SearchLimits::unlimited()
            },
            max_total_work: u64::MAX,
            ..PortableRegexSetRunLimits::unlimited()
        };
        let below = PortableRegexSetRunLimits {
            pattern: SearchLimits {
                max_work: exact_work - 1,
                ..SearchLimits::unlimited()
            },
            max_total_work: u64::MAX,
            ..PortableRegexSetRunLimits::unlimited()
        };

        let (any, any_report) = set
            .is_match(haystack, exact)
            .expect("exact per-pattern is_match work");
        assert!(any, "{pattern:?}");
        assert_eq!(any_report.work, exact_work, "{pattern:?}");

        let matches = set
            .matches(haystack, exact)
            .expect("exact per-pattern matches work");
        assert_eq!(matches.iter().collect::<Vec<_>>(), vec![0], "{pattern:?}");
        assert_eq!(matches.report().work, exact_work, "{pattern:?}");

        let mut read = [false];
        let (read_any, read_report) = set
            .matches_read_at(&mut read, haystack, 0, exact)
            .expect("exact per-pattern caller-buffer work");
        assert!(read_any, "{pattern:?}");
        assert_eq!(read, [true], "{pattern:?}");
        assert_eq!(read_report.work, exact_work, "{pattern:?}");

        let mut alias = [false];
        let (alias_any, alias_report) = set
            .read_matches_at(&mut alias, haystack, 0, exact)
            .expect("exact per-pattern caller-buffer alias work");
        assert!(alias_any, "{pattern:?}");
        assert_eq!(alias, [true], "{pattern:?}");
        assert_eq!(alias_report.work, exact_work, "{pattern:?}");

        for error in [
            set.is_match(haystack, below)
                .expect_err("one-below per-pattern is_match work"),
            set.matches(haystack, below)
                .expect_err("one-below per-pattern matches work"),
            set.matches_read_at(&mut [false], haystack, 0, below)
                .expect_err("one-below per-pattern caller-buffer work"),
            set.read_matches_at(&mut [false], haystack, 0, below)
                .expect_err("one-below per-pattern caller-buffer alias work"),
        ] {
            assert!(
                matches!(
                    error,
                    PortableRegexSetExecutionError::Pattern {
                        index: 0,
                        total_work_before: 0,
                        remaining_total_work: u64::MAX,
                        ..
                    }
                ),
                "{pattern:?}: {error:?}",
            );
        }
    }
}

#[test]
fn range_and_output_preflight_contracts_are_unchanged() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan regex set");
    let haystack = b"!abc123";
    let invalid_start = haystack.len() + 1;
    let hostile_limits = PortableRegexSetRunLimits {
        max_pattern_searches: 0,
        max_total_work: 0,
        max_output_matches: 0,
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };
    assert!(matches!(
        set.is_match_at(haystack, invalid_start, hostile_limits),
        Err(PortableRegexSetExecutionError::InvalidStart { .. })
    ));
    assert!(matches!(
        set.matches_at(haystack, invalid_start, hostile_limits),
        Err(PortableRegexSetExecutionError::InvalidStart { .. })
    ));
    let mut untouched = [true, false, true];
    assert!(matches!(
        set.matches_read_at(&mut untouched, haystack, invalid_start, hostile_limits),
        Err(PortableRegexSetExecutionError::InvalidStart { .. })
    ));
    assert!(matches!(
        set.read_matches_at(&mut untouched, haystack, invalid_start, hostile_limits),
        Err(PortableRegexSetExecutionError::InvalidStart { .. })
    ));
    assert_eq!(untouched, [true, false, true]);

    assert!(matches!(
        set.matches(
            haystack,
            PortableRegexSetRunLimits {
                max_output_bytes: PATTERNS.len() - 1,
                ..PortableRegexSetRunLimits::unlimited()
            },
        ),
        Err(PortableRegexSetExecutionError::OutputBytesLimit { .. })
    ));
    assert!(matches!(
        set.matches(
            haystack,
            PortableRegexSetRunLimits {
                max_output_matches: 2,
                ..PortableRegexSetRunLimits::unlimited()
            },
        ),
        Err(PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 3,
            limit: 2
        })
    ));

    let mut partial = [false; PATTERNS.len()];
    assert!(matches!(
        set.matches_read_at(
            &mut partial,
            haystack,
            0,
            PortableRegexSetRunLimits {
                max_output_matches: 2,
                max_output_bytes: 0,
                ..PortableRegexSetRunLimits::unlimited()
            },
        ),
        Err(PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 3,
            limit: 2
        })
    ));
    assert_eq!(partial, [true, true, false]);
}
