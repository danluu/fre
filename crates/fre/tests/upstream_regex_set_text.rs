use fre::{
    PortableRegexSetBuildLimits, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    PortableTextBuildError, PortableTextProof, PortableTextRegexSet,
    PortableTextRegexSetBuildError, PortableTextRegexSetBuilder, RustProfile,
};

fn sources(patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

fn ids(set: &PortableTextRegexSet, haystack: &str) -> Vec<usize> {
    set.matches(haystack, PortableRegexSetRunLimits::unlimited())
        .unwrap_or_else(|error| panic!("FRE text set search failed: {error}"))
        .into_iter()
        .collect()
}

#[test]
fn text_set_matches_pinned_rust_across_unicode_nullable_and_duplicate_patterns() {
    let suites: &[(&[&str], &[&str])] = &[
        (&["foo", "bar"], &["", "foo", "bar foo", "東京"]),
        (&["", "é", "東京"], &["", "é", "x東京y", "🦀"]),
        (
            &[r"\b\w+\b", "(?:é|東京)+", "a+"],
            &["", "é東京", "🦀 rust 東京", "zaa"],
        ),
        (&["a", "a", "z"], &["a", "z", "none"]),
        (&["^rooted$", r"\.log$"], &["rooted", "x.log", "notrooted"]),
    ];

    for (patterns, haystacks) in suites {
        let fre = PortableTextRegexSet::new(patterns.iter().copied())
            .unwrap_or_else(|error| panic!("FRE rejected {patterns:?}: {error}"));
        let upstream = regex::RegexSet::new(*patterns)
            .unwrap_or_else(|error| panic!("upstream rejected {patterns:?}: {error}"));
        for haystack in *haystacks {
            let expected = upstream.matches(haystack).into_iter().collect::<Vec<_>>();
            assert_eq!(ids(&fre, haystack), expected, "{patterns:?} {haystack:?}");
            let (matched, report) = fre
                .is_match(haystack, PortableRegexSetRunLimits::unlimited())
                .expect("text set existence search");
            assert_eq!(matched, upstream.is_match(haystack));
            assert!(report.patterns_searched <= patterns.len());
        }
    }
}

#[test]
fn text_set_preserves_proofs_profile_identity_and_traits() {
    let patterns = sources(&["雪", "a+"]);
    let set = PortableTextRegexSetBuilder::new(&patterns)
        .case_insensitive(true)
        .multi_line(true)
        .build()
        .expect("proved text set");
    assert_eq!(set.patterns(), patterns);
    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert!(set.build_report().profile.options.case_insensitive);
    assert!(set.build_report().profile.options.multi_line);
    assert!(matches!(
        set.pattern_build_report(0).unwrap().proof,
        PortableTextProof::FiniteLanguage { .. }
    ));
    assert!(matches!(
        set.pattern_build_report(1).unwrap().proof,
        PortableTextProof::IdenticalUtf8Hir { .. }
    ));
    assert_eq!(format!("{set:?}"), "PortableTextRegexSet([\"雪\", \"a+\"])");

    let cloned = set.clone();
    assert_eq!(ids(&cloned, "A雪"), ids(&set, "A雪"));
    let empty = PortableTextRegexSet::default();
    assert!(empty.is_empty());
    assert_eq!(ids(&empty, "anything"), Vec::<usize>::new());
    assert_eq!(RustProfile::default(), empty.build_report().profile);
}

#[test]
fn construction_is_bounded_and_reports_the_exact_pattern_failure() {
    let patterns = sources(&["a", "b"]);
    let defaults = PortableRegexSetBuildLimits::default();
    let error = PortableTextRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_patterns: 1,
            ..defaults
        })
        .build()
        .expect_err("pattern bound");
    assert!(matches!(
        error,
        PortableTextRegexSetBuildError::PatternLimit {
            needed: 2,
            limit: 1
        }
    ));

    let invalid = sources(&["a", "(", "b"]);
    let error = PortableTextRegexSetBuilder::new(&invalid)
        .build()
        .expect_err("invalid middle pattern");
    assert!(matches!(
        error,
        PortableTextRegexSetBuildError::Pattern {
            index: 1,
            source: PortableTextBuildError::TextSyntax(_),
        }
    ));

    let unproved = sources(&["a", r"(?-u:\B)"]);
    let error = PortableTextRegexSetBuilder::new(&unproved)
        .build()
        .expect_err("UTF-8-unsafe assertion");
    assert!(matches!(
        error,
        PortableTextRegexSetBuildError::Pattern {
            index: 1,
            source: PortableTextBuildError::NonFiniteLanguage,
        }
    ));
}

#[test]
fn execution_limits_fail_closed_without_publishing_partial_matches() {
    let set = PortableTextRegexSet::new(["a", "b"]).expect("text set");
    let defaults = PortableRegexSetRunLimits::unlimited();

    let error = set
        .matches(
            "ab",
            PortableRegexSetRunLimits {
                max_pattern_searches: 1,
                ..defaults
            },
        )
        .expect_err("second search is refused");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 2,
            limit: 1
        }
    ));

    let error = set
        .matches(
            "ab",
            PortableRegexSetRunLimits {
                max_output_matches: 1,
                ..defaults
            },
        )
        .expect_err("second matching ID is refused");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 2,
            limit: 1
        }
    ));

    let error = set
        .matches(
            "ab",
            PortableRegexSetRunLimits {
                max_output_bytes: 1,
                ..defaults
            },
        )
        .expect_err("flag storage is refused before search");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::OutputBytesLimit {
            needed: 2,
            limit: 1
        }
    ));
}
