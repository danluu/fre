use fre::{
    PlanKind, PortableRegexSetBuildLimits, PortableRegexSetExecutionError,
    PortableRegexSetRunLimits, PortableTextBuildError, PortableTextProof, PortableTextRegexSet,
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
fn text_set_offset_search_matches_pinned_rust_at_every_byte() {
    let patterns = ["", r"\bbar\b", r"(?m)^bar$", "é", "東京"];
    let fre = PortableTextRegexSet::new(patterns).expect("FRE text offset set");
    let upstream = regex::RegexSet::new(patterns).expect("pinned text offset set");
    assert_eq!(
        fre.pattern_build_report(2)
            .expect("multiline constituent report")
            .portable
            .plan,
        PlanKind::K0,
        "text-set constituents must not enter byte-only line-domain routing",
    );
    let cloned = fre.clone();
    assert_eq!(
        cloned
            .pattern_build_report(2)
            .expect("cloned multiline constituent report")
            .portable
            .plan,
        PlanKind::K0,
        "text-set cloning must replay text-facade routing provenance",
    );

    for haystack in ["", "é", "foobar", "foo\nbar\n東京"] {
        for start in 0..=haystack.len() {
            let expected = upstream
                .matches_at(haystack, start)
                .into_iter()
                .collect::<Vec<_>>();
            let actual = fre
                .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("FRE text set failed for {haystack:?}/{start}: {error}")
                });
            assert_eq!(actual.iter().collect::<Vec<_>>(), expected);
            assert_eq!(actual.report().start, start);

            let (matched, report) = fre
                .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("FRE text set existence failed for {haystack:?}/{start}: {error}")
                });
            assert_eq!(matched, upstream.is_match_at(haystack, start));
            assert_eq!(report.start, start);
        }
    }
}

#[test]
fn text_set_offset_validation_precedes_output_allocation() {
    let set = PortableTextRegexSet::new(["a", "b"]).expect("text set");
    let limits = PortableRegexSetRunLimits {
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let error = set
        .matches_at("é", 3, limits)
        .expect_err("out-of-bounds start must be reported first");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::InvalidStart {
            start: 3,
            haystack_len: 2
        }
    ));
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
fn aggregate_size_limit_matches_pinned_text_set_boundary_and_order() {
    let patterns = sources(&["a", "b"]);
    let mut upstream_below = regex::RegexSetBuilder::new(&patterns);
    upstream_below.size_limit(311);
    assert!(matches!(
        upstream_below.build(),
        Err(regex::Error::CompiledTooBig(311))
    ));
    let fre_below = PortableTextRegexSetBuilder::new(&patterns)
        .size_limit(311)
        .build()
        .expect_err("aggregate text NFA one byte below its boundary");
    assert!(matches!(
        fre_below,
        PortableTextRegexSetBuildError::UpstreamAdmission { source }
            if source.category
                == fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { limit: 311 }
    ));

    let mut upstream_exact = regex::RegexSetBuilder::new(&patterns);
    upstream_exact.size_limit(312);
    let upstream_exact = upstream_exact.build().expect("exact upstream text limit");
    let fre_exact = PortableTextRegexSetBuilder::new(&patterns)
        .size_limit(312)
        .build()
        .expect("exact FRE text limit");
    for haystack in ["", "a", "b", "ab", "é"] {
        assert_eq!(
            ids(&fre_exact, haystack),
            upstream_exact
                .matches(haystack)
                .into_iter()
                .collect::<Vec<_>>()
        );
    }
    let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
        &fre_exact.build_report().profile.constructor
    else {
        panic!("text set lost high-level constructor identity");
    };
    assert_eq!(*size_limit, 312);

    let invalid = sources(&["a", "("]);
    let error = PortableTextRegexSetBuilder::new(&invalid)
        .size_limit(0)
        .build()
        .expect_err("text syntax must precede aggregate NFA admission");
    assert!(matches!(
        error,
        PortableTextRegexSetBuildError::Pattern {
            index: 1,
            source: PortableTextBuildError::TextSyntax(ref source),
        } if source.category == fre_syntax::ErrorCategory::UpstreamRustSyntax
    ));
}

#[test]
fn text_set_uses_capture_free_aggregate_instead_of_single_regex_admission() {
    let patterns = sources(&["(a)"]);
    let mut upstream_single = regex::RegexBuilder::new(&patterns[0]);
    upstream_single.size_limit(200);
    assert!(matches!(
        upstream_single.build(),
        Err(regex::Error::CompiledTooBig(200))
    ));

    let mut upstream_set = regex::RegexSetBuilder::new(&patterns);
    upstream_set.size_limit(200);
    let upstream_set = upstream_set
        .build()
        .expect("capture-free upstream text set fits 200 bytes");
    let fre_set = PortableTextRegexSetBuilder::new(&patterns)
        .size_limit(200)
        .build()
        .expect("text set must not substitute single-regex admission");
    for haystack in ["", "a", "ba"] {
        assert_eq!(
            ids(&fre_set, haystack),
            upstream_set
                .matches(haystack)
                .into_iter()
                .collect::<Vec<_>>()
        );
    }
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
}

#[test]
fn scalar_guarded_ascii_assertions_match_pinned_text_sets() {
    let patterns = sources(&[
        "a",
        r"(?-u:\B)",
        r"(?-u:\b{start-half})",
        r"(?-u:\b{end-half})",
    ]);
    let fre = PortableTextRegexSetBuilder::new(&patterns)
        .build()
        .expect("scalar-guarded text set");
    let upstream = regex::RegexSet::new(&patterns).expect("pinned scalar-guarded text set");

    for index in 1..patterns.len() {
        assert!(matches!(
            fre.pattern_build_report(index).unwrap().proof,
            PortableTextProof::Utf8StartBoundaryGuardedHir { .. }
        ));
    }
    for haystack in ["", "a", " ", " a", "𝛃", "a𝛃", " 𝛃 ", "𝛃b", "b𝛃", "𝛃𐆀"] {
        assert_eq!(
            ids(&fre, haystack),
            upstream.matches(haystack).into_iter().collect::<Vec<_>>(),
            "haystack={haystack:?}"
        );
    }
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
