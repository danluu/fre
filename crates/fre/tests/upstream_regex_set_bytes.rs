#![forbid(unsafe_code)]

use fre::{
    BuildError, PortableRegexSet, PortableRegexSetBuildError, PortableRegexSetBuildLimits,
    PortableRegexSetBuilder, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    RustProfile, SearchLimits,
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

fn sources(patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

fn set(patterns: &[&str]) -> PortableRegexSet {
    PortableRegexSet::new(&sources(patterns))
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
    assert_eq!(UPSTREAM_DOCTEST_IDS.len(), 18);
    assert_eq!(UPSTREAM_DOCTEST_IDS[0], "limitations_two_pass");
    assert_eq!(UPSTREAM_DOCTEST_IDS[17], "owned_into_iter");
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
