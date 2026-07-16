#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, PlanKind, PortableRegexSet, PortableRegexSetBuildError,
    PortableRegexSetBuildLimits, PortableRegexSetBuilder, PortableRegexSetExecutionError,
    PortableRegexSetRunLimits, RustProfile, SearchLimits,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_SET_PATH: &str = "src/regexset/bytes.rs";
const UPSTREAM_SET_SHA256: &str =
    "25c8d896e4b9caf627cce46e3c305d2e640aeeacea96c40526699f86960d1868";
const UPSTREAM_BUILDERS_PATH: &str = "src/builders.rs";
const UPSTREAM_BUILDERS_SHA256: &str =
    "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f";
const UPSTREAM_SUITE_PATH: &str = "tests/suite_bytes_set.rs";
const UPSTREAM_SUITE_SHA256: &str =
    "db85513e87429fc68904270a0f414e75ae0b7c6b7deb1c66f05eb4f98b09c67a";

const UPSTREAM_DOCTEST_IDS: &[&str] = &[
    "limitations_two_pass",
    "email_and_domain_example",
    "new",
    "empty",
    "is_match",
    "is_match_at",
    "matches",
    "matches_at",
    "len",
    "is_empty",
    "patterns",
    "matched_any",
    "matched_all",
    "matched",
    "set_matches_len",
    "iter",
    "borrowed_into_iter",
    "owned_into_iter",
];
const UPSTREAM_CALLER_BUFFER_IDS: &[&str] = &["matches_read_at", "read_matches_at"];
const UPSTREAM_BUILDER_API_IDS: &[&str] = &["bytes_regex_set_builder_reusable_build"];
const UPSTREAM_TRAIT_IDS: &[&str] = &[
    "bytes_regex_set_clone",
    "bytes_regex_set_default",
    "bytes_regex_set_debug",
];

fn sources(patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

fn set(patterns: &[&str]) -> PortableRegexSet {
    PortableRegexSet::new(patterns.iter().copied())
        .unwrap_or_else(|error| panic!("FRE rejected set {patterns:?}: {error}"))
}

fn ids(set: &PortableRegexSet, haystack: &[u8]) -> Vec<usize> {
    set.matches(haystack, PortableRegexSetRunLimits::unlimited())
        .unwrap_or_else(|error| panic!("FRE set search failed: {error}"))
        .into_iter()
        .collect()
}

#[test]
fn authenticated_bytes_regex_set_doctest_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_SET_PATH, "src/regexset/bytes.rs");
    assert_eq!(UPSTREAM_SET_SHA256.len(), 64);
    assert_eq!(UPSTREAM_BUILDERS_PATH, "src/builders.rs");
    assert_eq!(UPSTREAM_BUILDERS_SHA256.len(), 64);
    assert_eq!(UPSTREAM_SUITE_PATH, "tests/suite_bytes_set.rs");
    assert_eq!(UPSTREAM_SUITE_SHA256.len(), 64);
    assert_eq!(
        UPSTREAM_CALLER_BUFFER_IDS,
        ["matches_read_at", "read_matches_at"]
    );
    assert_eq!(
        UPSTREAM_BUILDER_API_IDS,
        ["bytes_regex_set_builder_reusable_build"]
    );
    assert_eq!(
        UPSTREAM_TRAIT_IDS,
        [
            "bytes_regex_set_clone",
            "bytes_regex_set_default",
            "bytes_regex_set_debug"
        ]
    );
    assert_eq!(UPSTREAM_DOCTEST_IDS.len(), 18);
    assert_eq!(UPSTREAM_DOCTEST_IDS[0], "limitations_two_pass");
    assert_eq!(UPSTREAM_DOCTEST_IDS[17], "owned_into_iter");
}

#[test]
fn configured_builder_repeats_success_and_typed_failure_like_pinned_bytes() {
    let patterns = sources(&[r"^a+$", r"x.y", r"[0-9]+"]).into_boxed_slice();
    let fre_builder = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .multi_line(true)
        .dot_matches_new_line(true);
    let mut upstream_builder = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream_builder
        .unicode(false)
        .multi_line(true)
        .dot_matches_new_line(true);

    let first = fre_builder.build().expect("first reusable FRE build");
    let second = fre_builder.build().expect("second reusable FRE build");
    let upstream_first = upstream_builder
        .build()
        .expect("first reusable upstream build");
    let upstream_second = upstream_builder
        .build()
        .expect("second reusable upstream build");

    assert_eq!(first.build_report(), second.build_report());
    assert_eq!(first.patterns(), second.patterns());
    for haystack in [b"aaa\nx\ny 123".as_slice(), b"bbb", &[b'x', 0xFF, b'y']] {
        let expected_first: Vec<_> = upstream_first.matches(haystack).into_iter().collect();
        let expected_second: Vec<_> = upstream_second.matches(haystack).into_iter().collect();
        assert_eq!(ids(&first, haystack), expected_first, "{haystack:?}");
        assert_eq!(ids(&second, haystack), expected_second, "{haystack:?}");
    }

    let invalid = sources(&["valid", "("]);
    let failing = PortableRegexSetBuilder::new(&invalid).unicode(false);
    for attempt in 0..2 {
        let error = failing.build().expect_err("repeated invalid build");
        assert!(
            matches!(error, PortableRegexSetBuildError::Pattern { index: 1, .. }),
            "attempt {attempt}: {error:?}"
        );
    }
}

#[test]
fn clone_and_default_match_pinned_traits_and_preserve_plan_identity() {
    let fre_default = PortableRegexSet::default();
    let upstream_default = regex::bytes::RegexSet::default();
    assert!(fre_default.is_empty());
    assert_eq!(fre_default.len(), upstream_default.len());
    for haystack in [b"".as_slice(), b"anything", &[0xFF]] {
        assert_eq!(
            ids(&fre_default, haystack),
            upstream_default
                .matches(haystack)
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    let patterns = sources(&[
        "Sherlock",
        "a|ab",
        "[a-z]+Z",
        r"\A[a-z]+Z",
        r"\b\w{2,}\b",
        "(?:ab)+",
    ]);
    let original = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("mixed-plan set");
    let cloned = original.clone();
    assert_eq!(cloned.patterns(), original.patterns());
    assert_eq!(cloned.build_report(), original.build_report());
    let plans = (0..original.len())
        .map(|index| {
            let original_report = original
                .pattern_build_report(index)
                .expect("original pattern report");
            let cloned_report = cloned
                .pattern_build_report(index)
                .expect("cloned pattern report");
            assert_eq!(cloned_report, original_report);
            original_report.plan
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plans,
        [
            PlanKind::ExactLiteral,
            PlanKind::PackedLiteralSet,
            PlanKind::RequiredLiteral,
            PlanKind::ForwardAnchored,
            PlanKind::UnicodeWordRun,
            PlanKind::K0,
        ]
    );

    let upstream = regex::bytes::RegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("pinned mixed-plan set");
    let upstream_clone = upstream.clone();
    for haystack in [
        b"Sherlock ab abcZ".as_slice(),
        b"word abab",
        b"---",
        &[b'a', 0xFF, b'Z'],
    ] {
        let expected = upstream_clone
            .matches(haystack)
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(ids(&original, haystack), expected);
        assert_eq!(ids(&cloned, haystack), expected);
    }

    let dfa_patterns = sources(&["foobar|foobaz|fooquux"]);
    let dfa_limits = PortableRegexSetBuildLimits {
        pattern: BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        },
        ..PortableRegexSetBuildLimits::default()
    };
    let dfa = PortableRegexSetBuilder::new(&dfa_patterns)
        .unicode(false)
        .limits(dfa_limits)
        .build()
        .expect("DFA set");
    assert_eq!(
        dfa.pattern_build_report(0).expect("DFA report").plan,
        PlanKind::LiteralSetDfa
    );
    let dfa_clone = dfa.clone();
    assert_eq!(dfa_clone.build_report(), dfa.build_report());
    assert_eq!(
        dfa_clone.pattern_build_report(0),
        dfa.pattern_build_report(0)
    );
    for haystack in [b"fooquux".as_slice(), b"none", &[0xFF]] {
        assert_eq!(ids(&dfa_clone, haystack), ids(&dfa, haystack));
    }
}

#[test]
fn debug_shows_only_original_patterns_like_the_pinned_bytes_set() {
    let patterns = [r#"a"b"#, r"\n", "α", "duplicate", "duplicate"];
    let fre = PortableRegexSet::new(patterns).expect("FRE debug pattern set");
    let upstream = regex::bytes::RegexSet::new(patterns).expect("pinned debug pattern set");
    let pinned = format!("{upstream:?}");
    let pinned_pretty = format!("{upstream:#?}");
    let expected = pinned.replacen("RegexSet", "PortableRegexSet", 1);
    let expected_pretty = pinned_pretty.replacen("RegexSet", "PortableRegexSet", 1);

    assert_eq!(format!("{fre:?}"), expected);
    assert_eq!(format!("{fre:#?}"), expected_pretty);

    let empty = PortableRegexSet::empty();
    assert_eq!(format!("{empty:?}"), "PortableRegexSet([])");
}

#[test]
fn generic_constructor_preserves_upstream_sources_ids_and_bounded_ingestion() {
    let patterns = [r"[0-9]", "duplicate", "duplicate", r"[a-z]"];
    let fre = PortableRegexSet::new(patterns)
        .unwrap_or_else(|error| panic!("FRE rejected generic array: {error}"));
    let upstream = regex::bytes::RegexSet::new(patterns)
        .unwrap_or_else(|error| panic!("upstream rejected generic array: {error}"));
    assert_eq!(
        fre.patterns(),
        patterns
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect::<Vec<_>>()
    );
    for haystack in [b"duplicate1".as_slice(), b"abc", b"---"] {
        assert_eq!(
            ids(&fre, haystack),
            upstream.matches(haystack).into_iter().collect::<Vec<_>>()
        );
    }

    let owned = sources(&["alpha", "beta"]);
    let from_borrowed_strings = PortableRegexSet::new(&owned)
        .unwrap_or_else(|error| panic!("FRE rejected borrowed Strings: {error}"));
    assert_eq!(from_borrowed_strings.patterns(), owned);

    let Err(invalid) = PortableRegexSet::new(["valid", "("]) else {
        panic!("the second generic pattern must be invalid");
    };
    assert!(matches!(
        invalid,
        PortableRegexSetBuildError::Pattern { index: 1, .. }
    ));

    let yielded = core::cell::Cell::new(0_usize);
    let endless = core::iter::from_fn(|| {
        yielded.set(yielded.get().saturating_add(1));
        Some("")
    });
    let Err(refused) = PortableRegexSet::new(endless) else {
        panic!("an endless source must stop at the default pattern limit");
    };
    let limit = PortableRegexSetBuildLimits::default().max_patterns;
    assert!(matches!(
        refused,
        PortableRegexSetBuildError::PatternLimit {
            needed,
            limit: actual_limit,
        } if needed == limit + 1 && actual_limit == limit
    ));
    assert_eq!(yielded.get(), limit + 1);
}

#[test]
fn caller_match_buffer_matches_pinned_bytes_additive_and_ranged_semantics() {
    let pattern_sets: &[&[&str]] = &[
        &[],
        &["", "a", "a"],
        &[r"\Aab", r"ab\z", r"(?m:^a+$)", r"[a-c\xFF]+"],
        &[r"\bbar\b", r"(?m)^bar$", r"bar"],
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"foobar",
        b"a\naa\nb",
        &[b'a', 0xFF, b'b', b'c'],
    ];

    for patterns in pattern_sets {
        let owned = sources(patterns);
        let fre = PortableRegexSetBuilder::new(&owned)
            .profile(RustProfile::regex_1_12_4())
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {patterns:?}: {error}"));
        let mut upstream = regex::bytes::RegexSetBuilder::new(patterns.iter().copied());
        upstream.unicode(false);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {patterns:?}: {error}"));

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for seeded in [false, true] {
                    let seed = (0..patterns.len().saturating_add(2))
                        .map(|index| seeded && index % 2 == 1)
                        .collect::<Vec<_>>();
                    let mut expected = seed.clone();
                    let mut actual = seed.clone();
                    let expected_any = upstream.matches_read_at(&mut expected, haystack, start);
                    let (actual_any, report) = fre
                        .matches_read_at(
                            &mut actual,
                            haystack,
                            start,
                            PortableRegexSetRunLimits {
                                max_output_bytes: 0,
                                ..PortableRegexSetRunLimits::unlimited()
                            },
                        )
                        .unwrap_or_else(|error| {
                            panic!("FRE failed {patterns:?}/{haystack:?}/{start}: {error}")
                        });
                    assert_eq!(actual, expected, "{patterns:?}/{haystack:?}/{start}");
                    assert_eq!(
                        actual_any, expected_any,
                        "{patterns:?}/{haystack:?}/{start}"
                    );
                    assert_eq!(report.start, start);
                    assert_eq!(report.patterns_searched, patterns.len());
                    assert_eq!(report.output_capacity_bytes, 0);
                    assert_eq!(
                        report.matched_patterns,
                        upstream.matches_at(haystack, start).iter().count()
                    );

                    let mut alias = seed;
                    let alias_result = fre
                        .read_matches_at(
                            &mut alias,
                            haystack,
                            start,
                            PortableRegexSetRunLimits {
                                max_output_bytes: 0,
                                ..PortableRegexSetRunLimits::unlimited()
                            },
                        )
                        .expect("caller-buffer compatibility alias");
                    assert_eq!(alias, expected);
                    assert_eq!(alias_result, (actual_any, report));
                }
            }
        }
    }
}

#[test]
fn caller_match_buffer_preflights_capacity_and_preserves_exact_limits() {
    let set = set(&["a", "b"]);
    let unlimited = PortableRegexSetRunLimits::unlimited();

    let mut short = [false];
    let error = set
        .matches_read_at(&mut short, b"ab", 0, unlimited)
        .expect_err("undersized caller buffer must fail before search");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::MatchBufferTooSmall {
            needed: 2,
            available: 1
        }
    ));
    assert_eq!(short, [false]);

    let mut invalid_range = [false, false];
    let error = set
        .matches_read_at(&mut invalid_range, b"ab", 3, unlimited)
        .expect_err("invalid range must fail before search");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::InvalidStart {
            start: 3,
            haystack_len: 2
        }
    ));
    assert_eq!(invalid_range, [false, false]);

    let mut no_searches = [false, false];
    let error = set
        .matches_read_at(
            &mut no_searches,
            b"ab",
            0,
            PortableRegexSetRunLimits {
                max_pattern_searches: 0,
                ..unlimited
            },
        )
        .expect_err("zero pattern searches must refuse before mutation");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 1,
            limit: 0
        }
    ));
    assert_eq!(no_searches, [false, false]);

    let mut one_match = [false, false];
    let error = set
        .matches_read_at(
            &mut one_match,
            b"ab",
            0,
            PortableRegexSetRunLimits {
                max_output_matches: 1,
                max_output_bytes: 0,
                ..unlimited
            },
        )
        .expect_err("second match must exceed the exact output limit");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 2,
            limit: 1
        }
    ));
    assert_eq!(one_match, [true, false]);

    let mut exact = [false, false];
    let (matched, report) = set
        .matches_read_at(
            &mut exact,
            b"ab",
            0,
            PortableRegexSetRunLimits {
                max_output_matches: 2,
                max_output_bytes: 0,
                ..unlimited
            },
        )
        .expect("exact caller-buffer match limit");
    assert!(matched);
    assert_eq!(exact, [true, true]);
    assert_eq!(report.matched_patterns, 2);
    assert_eq!(report.output_capacity_bytes, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated upstream doctest order is clearer as one complete executable port"
)]
fn every_pinned_bytes_regex_set_doctest_passes() {
    let mut executed = Vec::new();

    let patterns = ["foo", "bar"];
    let regexes: Vec<_> = patterns
        .iter()
        .map(|pattern| regex::bytes::Regex::new(pattern).unwrap())
        .collect();
    let found_bytes: Vec<_> = ids(&set(&patterns), b"barfoo")
        .into_iter()
        .map(|index| regexes[index].find(b"barfoo").unwrap().as_bytes())
        .collect();
    assert_eq!(found_bytes, vec![b"foo".as_slice(), b"bar".as_slice()]);
    executed.push("limitations_two_pass");

    let email = set(&[r"[a-z]+@[a-z]+\.(com|org|net)", r"[a-z]+\.(com|org|net)"]);
    let (any_email, _) = email
        .is_match(b"foo@example.com", PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert!(any_email);
    assert_eq!(ids(&email, b"foo@example.com"), vec![0, 1]);
    assert_eq!(ids(&email, b"example.com"), vec![1]);
    assert!(ids(&email, b"example").is_empty());
    executed.push("email_and_domain_example");

    let word_digit = set(&[r"\w+", r"\d+"]);
    assert!(
        word_digit
            .is_match(b"foo", PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    executed.push("new");

    let empty = PortableRegexSet::empty();
    assert!(empty.is_empty());
    assert!(
        !empty
            .is_match(b"", PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    executed.push("empty");

    assert!(
        word_digit
            .is_match(b"foo", PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    assert!(
        !word_digit
            .is_match("☃".as_bytes(), PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    executed.push("is_match");

    let contextual = set(&[r"\bbar\b", r"(?m)^bar$"]);
    assert!(
        contextual
            .is_match(b"bar", PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    assert!(
        !contextual
            .is_match_at(b"foobar", 3, PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .0
    );
    executed.push("is_match_at");

    let mixed = set(&[
        r"\w+", r"\d+", r"\pL+", r"foo", r"bar", r"barfoo", r"foobar",
    ]);
    let matches = mixed
        .matches(b"foobar", PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert_eq!(matches.iter().collect::<Vec<_>>(), vec![0, 2, 3, 4, 6]);
    assert!(!matches.matched(5));
    assert!(matches.matched(6));
    executed.push("matches");

    assert_eq!(ids(&contextual, b"bar"), vec![0, 1]);
    assert!(
        contextual
            .matches_at(b"foobar", 3, PortableRegexSetRunLimits::unlimited())
            .unwrap()
            .iter()
            .next()
            .is_none()
    );
    executed.push("matches_at");

    assert_eq!(PortableRegexSet::empty().len(), 0);
    assert_eq!(set(&[r"[0-9]"]).len(), 1);
    assert_eq!(set(&[r"[0-9]", r"[a-z]"]).len(), 2);
    executed.push("len");

    assert!(PortableRegexSet::empty().is_empty());
    assert!(!set(&[r"[0-9]"]).is_empty());
    executed.push("is_empty");

    let expected_patterns = sources(&[
        r"\w+", r"\d+", r"\pL+", r"foo", r"bar", r"barfoo", r"foobar",
    ]);
    assert_eq!(mixed.patterns(), expected_patterns);
    let matched_patterns: Vec<_> = mixed
        .matches(b"foobar", PortableRegexSetRunLimits::unlimited())
        .unwrap()
        .into_iter()
        .map(|index| &mixed.patterns()[index])
        .collect();
    assert_eq!(
        matched_patterns,
        vec![r"\w+", r"\pL+", r"foo", r"bar", r"foobar"]
    );
    executed.push("patterns");

    let email_matches = email
        .matches(b"foo@example.com", PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert!(email_matches.matched_any());
    executed.push("matched_any");

    let all = set(&[r"^foo", r"[a-z]+\.com"])
        .matches(b"foo.example.com", PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert!(all.matched_all());
    executed.push("matched_all");

    let domain = email
        .matches(b"example.com", PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert!(!domain.matched(0));
    assert!(domain.matched(1));
    executed.push("matched");

    assert_eq!(domain.iter().count(), 1);
    assert_eq!(domain.len(), 2);
    executed.push("set_matches_len");

    let classes = set(&[r"[0-9]", r"[a-z]", r"[A-Z]", r"\p{Greek}"]);
    let class_matches = classes
        .matches("βa1".as_bytes(), PortableRegexSetRunLimits::unlimited())
        .unwrap();
    assert_eq!(class_matches.iter().collect::<Vec<_>>(), vec![0, 1, 3]);
    executed.push("iter");

    let mut borrowed = Vec::new();
    for index in &class_matches {
        borrowed.push(index);
    }
    assert_eq!(borrowed, vec![0, 1, 3]);
    executed.push("borrowed_into_iter");

    let mut owned = Vec::new();
    for index in class_matches {
        owned.push(index);
    }
    assert_eq!(owned, vec![0, 1, 3]);
    executed.push("owned_into_iter");

    assert_eq!(executed, UPSTREAM_DOCTEST_IDS);
}

#[test]
fn byte_set_matches_pinned_regex_on_ranges_duplicates_and_invalid_utf8() {
    let pattern_sets: &[&[&str]] = &[
        &[],
        &["", "a", "a"],
        &[r"\Aab", r"ab\z", r"(?m:^a+$)", r"[a-c\xFF]+"],
        &[r"\bbar\b", r"(?m)^bar$", r"bar"],
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"foobar",
        b"a\naa\nb",
        &[b'a', 0xFF, b'b', b'c'],
    ];

    for patterns in pattern_sets {
        let owned = sources(patterns);
        let fre = PortableRegexSetBuilder::new(&owned)
            .profile(RustProfile::regex_1_12_4())
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {patterns:?}: {error}"));
        let mut upstream = regex::bytes::RegexSetBuilder::new(patterns.iter().copied());
        upstream.unicode(false);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {patterns:?}: {error}"));
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected: Vec<_> = upstream.matches_at(haystack, start).into_iter().collect();
                let actual = fre
                    .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("FRE failed {patterns:?}/{haystack:?}/{start}: {error}")
                    });
                assert_eq!(
                    actual.iter().collect::<Vec<_>>(),
                    expected,
                    "{patterns:?}/{haystack:?}/{start}"
                );
                assert_eq!(actual.matched_count(), expected.len());
                assert_eq!(actual.matched_any(), !expected.is_empty());
                assert_eq!(actual.matched_all(), expected.len() == patterns.len());
                let (any, report) = fre
                    .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                    .unwrap();
                assert_eq!(any, !expected.is_empty());
                assert!(report.patterns_searched <= patterns.len());
            }
        }
    }
}

#[test]
fn set_profile_options_apply_identically_to_every_pattern() {
    let patterns = sources(&[r"^abc$", r"x.y"]);
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.case_insensitive = true;
    profile.options.multi_line = true;
    profile.options.dot_matches_new_line = true;
    let fre = PortableRegexSetBuilder::new(&patterns)
        .profile(profile)
        .build()
        .expect("profiled FRE set");

    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true);
    let upstream = upstream.build().expect("profiled upstream set");
    let haystack = b"ABC\nx\ny";
    let expected: Vec<_> = upstream.matches(haystack).into_iter().collect();
    let actual = ids(&fre, haystack);
    assert_eq!(actual, expected);
    assert_eq!(actual, vec![0, 1]);
    assert_eq!(
        &fre.pattern_build_report(0)
            .expect("first pattern report")
            .profile,
        &fre.pattern_build_report(1)
            .expect("second pattern report")
            .profile
    );
}

#[test]
fn upstream_bytes_set_builder_line_terminator_applies_to_every_pattern_and_range() {
    let patterns = sources(&[r"(?m:^a)", r"(?m:a$)", r"(?m:^$)"]);
    let line_terminator = 0x00;
    let fre = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .line_terminator(line_terminator)
        .build()
        .expect("configured FRE set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream.unicode(false).line_terminator(line_terminator);
    let upstream = upstream.build().expect("configured upstream set");
    let haystacks: &[&[u8]] = &[b"", b"a", b"x\0a\0", b"\n\0\0a", &[0xFF, 0x00, b'a']];

    for haystack in haystacks {
        for start in 0..=haystack.len() {
            let expected: Vec<_> = upstream.matches_at(haystack, start).into_iter().collect();
            let actual: Vec<_> = fre
                .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                .expect("configured FRE set search")
                .into_iter()
                .collect();
            assert_eq!(actual, expected, "{haystack:?}/{start}");
        }
    }
    assert_eq!(
        fre.pattern_build_report(0)
            .expect("first configured pattern report")
            .profile,
        fre::CompatibilityProfile::RustBytes(fre.build_report().profile.clone())
    );
}

#[test]
fn construction_limits_are_preflighted_and_pattern_failures_keep_their_id() {
    let patterns = sources(&["a", "b"]);
    let defaults = PortableRegexSetBuildLimits::default();

    let error = PortableRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_patterns: 1,
            ..defaults
        })
        .build()
        .expect_err("cardinality limit");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::PatternLimit {
            needed: 2,
            limit: 1
        }
    ));

    let error = PortableRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_pattern_bytes: 1,
            ..defaults
        })
        .build()
        .expect_err("source byte limit");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::PatternBytesLimit {
            needed: 2,
            limit: 1
        }
    ));

    let probe = PortableRegexSetBuilder::new(&patterns).build().unwrap();
    let exact = probe.build_report().charged_persistent_bytes;
    let rebuilt = PortableRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_persistent_bytes: exact,
            ..defaults
        })
        .build()
        .expect("exact persistent limit");
    assert_eq!(rebuilt.build_report().charged_persistent_bytes, exact);
    let error = PortableRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_persistent_bytes: exact - 1,
            ..defaults
        })
        .build()
        .expect_err("one below persistent limit");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::PersistentLimit { needed, limit }
            if needed == exact && limit == exact - 1
    ));

    let invalid = sources(&["a", "(", "b"]);
    let error = PortableRegexSetBuilder::new(&invalid)
        .build()
        .expect_err("invalid middle pattern");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::Pattern {
            index: 1,
            source: BuildError::Syntax(_),
        }
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one exact-boundary test keeps the probe and every one-below refusal adjacent"
)]
fn execution_limits_are_exact_and_is_match_stops_after_the_first_id() {
    let patterns = sources(&["a", "b"]);
    let set = PortableRegexSet::new(&patterns).unwrap();
    let unlimited = PortableRegexSetRunLimits::unlimited();
    let probe = set.matches(b"ab", unlimited).unwrap();
    let report = probe.report();
    assert_eq!(probe.iter().collect::<Vec<_>>(), vec![0, 1]);

    let exact = PortableRegexSetRunLimits {
        max_pattern_searches: 2,
        max_total_work: report.work,
        max_output_matches: 2,
        max_output_bytes: report.output_capacity_bytes,
        ..unlimited
    };
    assert_eq!(
        set.matches(b"ab", exact)
            .expect("exact execution limits")
            .report(),
        report
    );

    let error = set
        .matches(
            b"ab",
            PortableRegexSetRunLimits {
                max_pattern_searches: 1,
                ..unlimited
            },
        )
        .expect_err("second pattern search must refuse");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 2,
            limit: 1
        }
    ));

    let error = set
        .matches(
            b"ab",
            PortableRegexSetRunLimits {
                max_output_matches: 1,
                ..unlimited
            },
        )
        .expect_err("second match must refuse");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 2,
            limit: 1
        }
    ));

    let error = set
        .matches(
            b"ab",
            PortableRegexSetRunLimits {
                max_output_bytes: report.output_capacity_bytes - 1,
                ..unlimited
            },
        )
        .expect_err("one below output capacity must refuse");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::OutputBytesLimit { needed, limit }
            if needed == report.output_capacity_bytes && limit == needed - 1
    ));

    let error = set
        .matches(
            b"ab",
            PortableRegexSetRunLimits {
                max_total_work: report.work - 1,
                ..unlimited
            },
        )
        .expect_err("one below total work must refuse");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::Pattern { index: 1, .. }
    ));

    let (matched, report) = set
        .is_match(
            b"ab",
            PortableRegexSetRunLimits {
                max_pattern_searches: 1,
                ..unlimited
            },
        )
        .expect("first pattern matches within one visit");
    assert!(matched);
    assert_eq!(report.patterns_searched, 1);
    assert_eq!(report.matched_patterns, 1);
    assert_eq!(report.output_capacity_bytes, 0);

    let error = PortableRegexSet::empty()
        .matches_at(b"a", 2, unlimited)
        .expect_err("invalid start is checked even for an empty set");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::InvalidStart {
            start: 2,
            haystack_len: 1
        }
    ));
}

#[test]
fn small_set_membership_is_exhaustive_over_binary_haystacks_and_ranges() {
    let patterns = sources(&["", "a", "ab", "a|b", "^a", "b$", "[ab]+", "a*?"]);
    let fre = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("portable exhaustive set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream.unicode(false);
    let upstream = upstream.build().expect("upstream exhaustive set");

    for haystack in binary_words(5) {
        for start in 0..=haystack.len() {
            let expected: Vec<_> = upstream.matches_at(&haystack, start).into_iter().collect();
            let actual: Vec<_> = fre
                .matches_at(
                    &haystack,
                    start,
                    PortableRegexSetRunLimits {
                        pattern: SearchLimits::unlimited(),
                        ..PortableRegexSetRunLimits::unlimited()
                    },
                )
                .unwrap_or_else(|error| panic!("{haystack:?}/{start}: {error}"))
                .into_iter()
                .collect();
            assert_eq!(actual, expected, "{haystack:?}/{start}");
        }
    }
}

fn binary_words(max_len: usize) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
    for len in 1..=max_len {
        for bits in 0..(1_usize << len) {
            let word = (0..len)
                .map(|index| if bits & (1 << index) == 0 { b'a' } else { b'b' })
                .collect();
            words.push(word);
        }
    }
    words
}
