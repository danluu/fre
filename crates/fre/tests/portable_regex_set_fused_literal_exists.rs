#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegex, PortableRegexSet, PortableRegexSetBuildError,
    PortableRegexSetBuildLimits, PortableRegexSetBuilder, PortableRegexSetExecutionError,
    PortableRegexSetRunLimits, PortableRegexSetSessionLimits, SearchLimits, SearchWindow,
};
use fre_kernels::{LiteralSetBuildLimits, LiteralSetMatchSemantics};

const PATTERNS: [&str; 8] = [
    "ab",
    "abc",
    "ab",
    r"(?-u:\xFF\x00)",
    "tail",
    "six",
    "seven",
    "eight",
];

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
                .expect("direct exact-literal search");
            (matched, accounting.work_or_linear_terms())
        })
        .collect()
}

fn matching_ids(results: &[(bool, u64)]) -> Vec<usize> {
    results
        .iter()
        .enumerate()
        .filter_map(|(index, &(matched, _))| matched.then_some(index))
        .collect()
}

#[test]
fn fused_full_existence_preserves_prefix_duplicate_raw_byte_and_incumbent_routes() {
    let regexes = PATTERNS
        .iter()
        .map(|pattern| PortableRegex::new(*pattern).expect("exact-literal constituent"))
        .collect::<Vec<_>>();
    assert!(
        regexes
            .iter()
            .all(|regex| regex.build_report().plan == PlanKind::ExactLiteral)
    );
    let set = PortableRegexSet::new(PATTERNS).expect("fused exact-literal set");
    let fused = set
        .build_report()
        .fused_literal_set_build
        .expect("eligible set retains a fused construction receipt");
    assert_eq!(
        fused.match_semantics,
        LiteralSetMatchSemantics::LeftmostFirst
    );
    assert_eq!(fused.patterns, PATTERNS.len() - 1);
    assert_eq!(fused.pattern_bytes, 24);
    assert_eq!(fused.minimum_pattern_bytes, 2);
    assert!(fused.build_work_upper_bound > 0);
    assert!(fused.build_bytes_upper_bound > 0);
    assert_eq!(
        fused.persistent_bytes,
        set.build_report().fused_literal_set_storage_bytes
    );

    let cases: &[(&[u8], usize)] = &[
        (b"", 0),
        (b"abc__", 0),
        (b"\xFF\x00__", 0),
        (b"tail__", 0),
        (b"__abc__", 0),
        (b"__abc__", 3),
        (b"__\xFF\x00__", 0),
        (b"prefix-tail", 0),
        (b"none", 0),
    ];
    for &(haystack, start) in cases {
        let direct = direct_exists(&regexes, haystack, start);
        let expected_ids = matching_ids(&direct);
        if start == 0 {
            assert_eq!(
                set.is_match_value_unlimited(haystack)
                    .expect("fused full existence"),
                !expected_ids.is_empty(),
            );
        }

        assert_eq!(
            set.is_match_value_at_unlimited(haystack, start)
                .expect("incumbent ranged value existence"),
            !expected_ids.is_empty(),
        );
        let (matched, report) = set
            .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .expect("accounted incumbent existence");
        let searched = expected_ids
            .first()
            .map_or(PATTERNS.len(), |index| index + 1);
        assert_eq!(matched, !expected_ids.is_empty());
        assert_eq!(report.patterns_searched, searched);
        assert_eq!(
            report.work,
            direct[..searched].iter().map(|&(_, work)| work).sum()
        );

        let matches = set
            .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .expect("all-ID incumbent search");
        assert_eq!(matches.iter().collect::<Vec<_>>(), expected_ids);
        let expected_flags = (0..PATTERNS.len())
            .map(|index| expected_ids.contains(&index))
            .collect::<Vec<_>>();
        let mut read_flags = vec![false; PATTERNS.len()];
        let (read_matched, read_report) = set
            .matches_read_at(
                &mut read_flags,
                haystack,
                start,
                PortableRegexSetRunLimits::unlimited(),
            )
            .expect("caller-buffer all-ID incumbent search");
        assert_eq!(read_matched, matched);
        assert_eq!(read_flags, expected_flags);
        assert_eq!(read_report.work, direct.iter().map(|&(_, work)| work).sum());
        let mut value_flags = vec![false; PATTERNS.len()];
        assert_eq!(
            set.matches_read_at_value(
                &mut value_flags,
                haystack,
                start,
                PortableRegexSetRunLimits::unlimited(),
            )
            .expect("caller-buffer all-ID value search"),
            matched,
        );
        assert_eq!(value_flags, expected_flags);

        let mut session = set
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("incumbent constituent sessions");
        let (session_matched, session_report) = session
            .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .expect("session incumbent existence");
        assert_eq!(session_matched, matched);
        assert_eq!(session_report.patterns_searched, report.patterns_searched);
        assert_eq!(session_report.work, report.work);
        assert_eq!(
            session
                .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited(),)
                .expect("session all-ID incumbent search")
                .iter()
                .collect::<Vec<_>>(),
            expected_ids,
        );
    }

    let zero_searches = PortableRegexSetRunLimits {
        max_pattern_searches: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };
    assert!(matches!(
        set.is_match(b"abc", zero_searches),
        Err(PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 1,
            limit: 0,
        })
    ));
    let mut session = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("incumbent constituent sessions");
    assert!(matches!(
        session.is_match(b"abc", zero_searches),
        Err(PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 1,
            limit: 0,
        })
    ));

    let cloned = set.clone();
    assert_eq!(cloned.patterns(), set.patterns());
    assert_eq!(cloned.build_report(), set.build_report());
    assert!(
        cloned
            .is_match_value_unlimited(b"__\xFF\x00__")
            .expect("cloned fused full existence")
    );
}

#[test]
fn ineligible_two_literal_value_routes_preserve_offsets_ids_and_empty_fallback() {
    for patterns in [["ab", "bc"], ["", "bc"]] {
        let regexes = patterns
            .iter()
            .map(|pattern| PortableRegex::new(*pattern).expect("exact-literal constituent"))
            .collect::<Vec<_>>();
        assert!(
            regexes
                .iter()
                .all(|regex| regex.build_report().plan == PlanKind::ExactLiteral)
        );
        let set = PortableRegexSet::new(patterns).expect("ineligible two-literal set");
        assert_eq!(set.build_report().fused_literal_set_build, None);
        assert_eq!(set.build_report().fused_literal_set_storage_bytes, 0);

        let haystack = b"__ab__bc";
        for start in [0, 3, haystack.len()] {
            let direct = direct_exists(&regexes, haystack, start);
            let expected_ids = matching_ids(&direct);
            assert_eq!(
                set.is_match_value_at_unlimited(haystack, start)
                    .expect("ineligible ranged value existence"),
                !expected_ids.is_empty(),
            );
            if start == 0 {
                assert_eq!(
                    set.is_match_value_unlimited(haystack)
                        .expect("ineligible full value existence"),
                    !expected_ids.is_empty(),
                );
            }

            let mut flags = [false; 2];
            assert_eq!(
                set.matches_read_at_value(
                    &mut flags,
                    haystack,
                    start,
                    PortableRegexSetRunLimits::unlimited(),
                )
                .expect("ineligible caller-buffer value search"),
                !expected_ids.is_empty(),
            );
            assert_eq!(
                flags,
                core::array::from_fn(|index| expected_ids.contains(&index))
            );
        }
    }
}

#[test]
fn fused_storage_is_separate_fallible_and_charged_only_when_retained() {
    let measured = PortableRegexSet::new(PATTERNS).expect("fused measurement");
    let report = measured.build_report();
    let fused = report.fused_literal_set_storage_bytes;
    assert!(fused > 0);
    let fused_build = report
        .fused_literal_set_build
        .expect("retained fused build receipt");
    assert_eq!(fused_build.persistent_bytes, fused);
    let incumbent = report
        .charged_persistent_bytes
        .checked_sub(fused)
        .expect("fused storage is part of the complete charge");
    assert_eq!(
        incumbent,
        report.source_capacity_bytes
            + report.regex_capacity_bytes
            + report.matcher_source_bytes
            + report.capture_name_storage_bytes
            + report.plan_storage_bytes,
    );

    let sources = PATTERNS.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut exact_limits = PortableRegexSetBuildLimits::default();
    exact_limits.max_persistent_bytes = report.charged_persistent_bytes;
    let exact = PortableRegexSetBuilder::new(&sources)
        .limits(exact_limits)
        .build()
        .expect("exact optional-attachment boundary");
    assert_eq!(exact.build_report().fused_literal_set_storage_bytes, fused);
    assert_eq!(
        exact
            .build_report()
            .fused_literal_set_build
            .expect("exact-boundary fused build receipt")
            .persistent_bytes,
        fused
    );
    assert_eq!(
        exact.build_report().charged_persistent_bytes,
        report.charged_persistent_bytes
    );

    let mut attachment_below = exact_limits;
    attachment_below.max_persistent_bytes = report.charged_persistent_bytes - 1;
    let declined = PortableRegexSetBuilder::new(&sources)
        .limits(attachment_below)
        .build()
        .expect("optional attachment declines below its exact boundary");
    assert_eq!(declined.build_report().fused_literal_set_storage_bytes, 0);
    assert_eq!(declined.build_report().fused_literal_set_build, None);
    assert_eq!(declined.build_report().charged_persistent_bytes, incumbent);

    let mut incumbent_exact = exact_limits;
    incumbent_exact.max_persistent_bytes = incumbent;
    let mandatory = PortableRegexSetBuilder::new(&sources)
        .limits(incumbent_exact)
        .build()
        .expect("exact mandatory incumbent boundary");
    assert_eq!(mandatory.build_report().fused_literal_set_storage_bytes, 0);
    assert_eq!(mandatory.build_report().fused_literal_set_build, None);
    assert_eq!(mandatory.build_report().charged_persistent_bytes, incumbent);
    let error = PortableRegexSetBuilder::new(&sources)
        .limits(PortableRegexSetBuildLimits {
            max_persistent_bytes: incumbent - 1,
            ..incumbent_exact
        })
        .build()
        .expect_err("one below mandatory incumbent boundary");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::PersistentLimit { needed, limit }
            if needed == incumbent && limit == incumbent - 1
    ));

    let mut construction_limited = PortableRegexSetBuildLimits::default();
    construction_limited.pattern.literal_set.max_build_work = 0;
    let work_declined = PortableRegexSetBuilder::new(&sources)
        .limits(construction_limited)
        .build()
        .expect("fused construction work refusal is fail-open");
    assert_eq!(
        work_declined.build_report().fused_literal_set_storage_bytes,
        0
    );
    assert_eq!(work_declined.build_report().fused_literal_set_build, None);

    for literal_set in [
        LiteralSetBuildLimits {
            max_patterns: fused_build.patterns - 1,
            ..LiteralSetBuildLimits::default()
        },
        LiteralSetBuildLimits {
            max_pattern_bytes: fused_build.pattern_bytes - 1,
            ..LiteralSetBuildLimits::default()
        },
        LiteralSetBuildLimits {
            max_build_work: fused_build.build_work_upper_bound - 1,
            ..LiteralSetBuildLimits::default()
        },
        LiteralSetBuildLimits {
            max_build_bytes: fused_build.build_bytes_upper_bound - 1,
            ..LiteralSetBuildLimits::default()
        },
        LiteralSetBuildLimits {
            max_persistent_bytes: fused - 1,
            ..LiteralSetBuildLimits::default()
        },
    ] {
        let mut limits = PortableRegexSetBuildLimits::default();
        limits.pattern.literal_set = literal_set;
        let declined = PortableRegexSetBuilder::new(&sources)
            .limits(limits)
            .build()
            .expect("every nested sidecar resource refusal is fail-open");
        assert_eq!(declined.build_report().fused_literal_set_storage_bytes, 0);
        assert_eq!(declined.build_report().fused_literal_set_build, None);
        assert_eq!(declined.build_report().charged_persistent_bytes, incumbent);
    }

    for ineligible in [
        vec!["only".to_owned()],
        vec!["one".to_owned(), "two".to_owned()],
        vec![
            "one".to_owned(),
            "two".to_owned(),
            "three".to_owned(),
            "four".to_owned(),
            "five".to_owned(),
            "six".to_owned(),
            "seven".to_owned(),
        ],
        vec![
            String::new(),
            "nonempty".to_owned(),
            "third".to_owned(),
            "fourth".to_owned(),
            "fifth".to_owned(),
            "sixth".to_owned(),
            "seventh".to_owned(),
            "eighth".to_owned(),
        ],
        vec![
            "first".to_owned(),
            String::new(),
            "third".to_owned(),
            "fourth".to_owned(),
            "fifth".to_owned(),
            "sixth".to_owned(),
            "seventh".to_owned(),
            "eighth".to_owned(),
        ],
        vec![
            "literal".to_owned(),
            "[a-z]+".to_owned(),
            "third".to_owned(),
            "fourth".to_owned(),
            "fifth".to_owned(),
            "sixth".to_owned(),
            "seventh".to_owned(),
            "eighth".to_owned(),
        ],
        vec![
            "[a-z]+".to_owned(),
            "second".to_owned(),
            "third".to_owned(),
            "fourth".to_owned(),
            "fifth".to_owned(),
            "sixth".to_owned(),
            "seventh".to_owned(),
            "eighth".to_owned(),
        ],
    ] {
        let set = PortableRegexSetBuilder::new(&ineligible)
            .build()
            .expect("ineligible set retains incumbent");
        assert_eq!(set.build_report().fused_literal_set_storage_bytes, 0);
        assert_eq!(set.build_report().fused_literal_set_build, None);
    }

    let invalid = [
        "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "(",
    ]
    .map(ToString::to_string);
    assert!(matches!(
        PortableRegexSetBuilder::new(&invalid).build(),
        Err(PortableRegexSetBuildError::Pattern { index: 7, .. })
    ));
}
