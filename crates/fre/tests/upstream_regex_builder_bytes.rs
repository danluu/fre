#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildFailureClass, CompatibilityProfile, PlanSelection, PortableBuilder,
    PortableRegexSetBuildError, PortableRegexSetBuilder, PortableRegexSetRunLimits, RustProfile,
    SearchLimits,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/builders.rs";
const UPSTREAM_SHA256: &str = "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f";
const UPSTREAM_API_IDS: &[&str] = &[
    "bytes_regex_builder_case_insensitive",
    "bytes_regex_builder_multi_line",
    "bytes_regex_builder_dot_matches_new_line",
    "bytes_regex_builder_crlf",
    "bytes_regex_builder_swap_greed",
    "bytes_regex_builder_ignore_whitespace",
    "bytes_regex_builder_octal",
    "bytes_regex_builder_size_limit",
    "bytes_regex_set_builder_size_limit",
    "bytes_regex_builder_dfa_size_limit",
    "bytes_regex_builder_nest_limit",
];

#[test]
fn authenticated_bytes_builder_flag_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/builders.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 11);
}

#[test]
fn size_limit_matches_pinned_compiled_nfa_admission_and_error_class() {
    let mut upstream_example = regex::bytes::RegexBuilder::new(r"\w");
    upstream_example.size_limit(45_000);
    assert!(matches!(
        upstream_example.build(),
        Err(regex::Error::CompiledTooBig(45_000))
    ));
    let fre_example = PortableBuilder::new(r"\w")
        .size_limit(45_000)
        .build()
        .expect_err("the pinned size-limit doctest pattern must be rejected before planning");
    assert_eq!(
        fre_example.failure_class(),
        BuildFailureClass::ExpectedInvalid
    );

    let patterns = ["Sherlock", "a|ab", "(?:ab)+", "(?P<word>ab)"];
    let limits = [0, 1, 64, 128, 256, 512, 1_024, 2_048, 8_192, 45_000];

    for pattern in patterns {
        for size_limit in limits {
            let mut upstream = regex::bytes::RegexBuilder::new(pattern);
            upstream.unicode(false).size_limit(size_limit);
            let expected = upstream.build();
            let actual = PortableBuilder::new(pattern)
                .unicode(false)
                .size_limit(size_limit)
                .build();

            assert_eq!(
                actual.is_ok(),
                expected.is_ok(),
                "pattern={pattern:?}, size_limit={size_limit}, FRE={actual:?}, upstream={expected:?}"
            );
            match (actual, expected) {
                (Ok(fre), Ok(_)) => {
                    let CompatibilityProfile::RustBytes(profile) = fre.profile() else {
                        panic!("portable bytes builder published a non-bytes profile");
                    };
                    let fre_syntax::RustConstructor::RegexBuilder {
                        size_limit: retained,
                        ..
                    } = &profile.constructor
                    else {
                        panic!("configured builder lost its high-level constructor identity");
                    };
                    assert_eq!(*retained, u64::try_from(size_limit).unwrap_or(u64::MAX));
                }
                (Err(error), Err(regex::Error::CompiledTooBig(limit))) => {
                    assert_eq!(limit, size_limit);
                    assert_eq!(error.failure_class(), BuildFailureClass::ExpectedInvalid);
                    let BuildError::Syntax(error) = error else {
                        panic!(
                            "compiled-too-big refusal did not originate in constructor admission"
                        );
                    };
                    assert_eq!(
                        error.category,
                        fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig {
                            limit: u64::try_from(size_limit).unwrap_or(u64::MAX),
                        }
                    );
                }
                (actual, expected) => panic!(
                    "unexpected size-limit result for {pattern:?}/{size_limit}: FRE={actual:?}, upstream={expected:?}"
                ),
            }
        }
    }
}

#[test]
fn set_size_limit_matches_the_pinned_combined_capture_free_program() {
    let patterns = vec!["(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)(m)(n)(o)(p)".to_owned()];
    let capture_erasure_limit = (0..=16_384)
        .step_by(8)
        .find(|&limit| {
            let mut upstream_set = regex::bytes::RegexSetBuilder::new(&patterns);
            upstream_set.unicode(false).size_limit(limit);
            let mut upstream_single = regex::bytes::RegexBuilder::new(&patterns[0]);
            upstream_single.unicode(false).size_limit(limit);
            upstream_set.build().is_ok() && upstream_single.build().is_err()
        })
        .expect("pinned set capture erasure must have a smaller admission threshold");

    let fre = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .size_limit(capture_erasure_limit)
        .build()
        .expect("FRE must apply the set limit after capture erasure, not per pattern");
    assert_eq!(fre.len(), 1);
    let single_error = PortableBuilder::new(&patterns[0])
        .profile(fre.build_report().profile.clone())
        .unicode(false)
        .build()
        .expect_err("a set-constructor profile must not bypass single-regex admission");
    assert_eq!(
        single_error.failure_class(),
        BuildFailureClass::ExpectedInvalid
    );
    for profile in
        core::iter::once(&fre.build_report().profile).chain((0..fre.len()).map(|index| {
            let CompatibilityProfile::RustBytes(profile) = &fre
                .pattern_build_report(index)
                .expect("constituent build report")
                .profile
            else {
                panic!("set constituent published a non-bytes profile");
            };
            profile
        }))
    {
        let fre_syntax::RustConstructor::RegexSetBuilder { size_limit, .. } = &profile.constructor
        else {
            panic!("configured set lost its set-constructor identity");
        };
        assert_eq!(
            *size_limit,
            u64::try_from(capture_erasure_limit).unwrap_or(u64::MAX)
        );
    }

    let combined_patterns: Vec<String> = ["alpha", "bravo", "charlie", "delta", "echo"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let combined_limit = (0..=16_384)
        .step_by(8)
        .find(|&limit| {
            let mut upstream_set = regex::bytes::RegexSetBuilder::new(&combined_patterns);
            upstream_set.unicode(false).size_limit(limit);
            let every_single_passes = combined_patterns.iter().all(|pattern| {
                let mut single = regex::bytes::RegexBuilder::new(pattern);
                single.unicode(false).size_limit(limit);
                single.build().is_ok()
            });
            every_single_passes && upstream_set.build().is_err()
        })
        .expect("pinned combined set must exceed its constituents at one exact limit");
    let error = PortableRegexSetBuilder::new(&combined_patterns)
        .unicode(false)
        .size_limit(combined_limit)
        .build()
        .expect_err("FRE must reject the same combined-program size boundary");
    let PortableRegexSetBuildError::UpstreamAdmission { source } = error else {
        panic!("combined size refusal lost its constructor source: {error}");
    };
    assert_eq!(
        source.category,
        fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig {
            limit: u64::try_from(combined_limit).unwrap_or(u64::MAX),
        }
    );
}

#[test]
fn dfa_size_limit_is_semantic_neutral_and_retained_in_profile_identity() {
    let cases: &[(&str, bool)] = &[("Sherlock", true), ("a|ab", false), ("(?:ab)+", false)];
    let haystacks: &[&[u8]] = &[
        b"",
        b"Sherlock",
        b"xxSherlockyy",
        b"a",
        b"ab",
        b"ababx",
        &[0xFF, b'a', b'b'],
    ];

    for dfa_size_limit in [0, 1, 2 * (1 << 20), usize::MAX] {
        for &(pattern, unicode) in cases {
            let fre = PortableBuilder::new(pattern)
                .unicode(unicode)
                .dfa_size_limit(dfa_size_limit)
                .build()
                .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
            let mut upstream = regex::bytes::RegexBuilder::new(pattern);
            upstream.unicode(unicode).dfa_size_limit(dfa_size_limit);
            let upstream = upstream
                .build()
                .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));

            for haystack in haystacks {
                for start in 0..=haystack.len() {
                    let expected = upstream
                        .find_at(haystack, start)
                        .map(|matched| matched.range());
                    let actual = fre
                        .find_at(haystack, start, SearchLimits::unlimited())
                        .unwrap_or_else(|error| {
                            panic!(
                                "FRE search failed for {pattern:?}/{haystack:?}/{start}: {error}"
                            )
                        })
                        .0
                        .map(fre::Match::range);
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}");
                }
            }

            let CompatibilityProfile::RustBytes(profile) = fre.profile() else {
                panic!("portable bytes builder published a non-bytes profile");
            };
            let fre_syntax::RustConstructor::RegexBuilder {
                dfa_size_limit: retained,
                ..
            } = &profile.constructor
            else {
                panic!("portable bytes builder lost its high-level constructor identity");
            };
            assert_eq!(*retained, u64::try_from(dfa_size_limit).unwrap_or(u64::MAX));
        }
    }
}

#[test]
fn dfa_size_limit_set_builder_applies_to_every_pattern_identity() {
    let patterns = vec!["a".to_owned(), "ab".to_owned(), "(?:ab)+".to_owned()];
    let fre = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .dfa_size_limit(0)
        .build()
        .expect("zero-cache FRE set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream.unicode(false).dfa_size_limit(0);
    let upstream = upstream.build().expect("zero-cache upstream set");

    for haystack in [b"".as_slice(), b"a", b"ab", b"ababx", &[0xFF, b'a']] {
        for start in 0..=haystack.len() {
            let expected: Vec<_> = upstream.matches_at(haystack, start).into_iter().collect();
            let actual: Vec<_> = fre
                .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                .expect("zero-cache FRE set search")
                .into_iter()
                .collect();
            assert_eq!(actual, expected, "{haystack:?}/{start}");
        }
    }

    for profile in
        core::iter::once(&fre.build_report().profile).chain((0..patterns.len()).map(|index| {
            let CompatibilityProfile::RustBytes(profile) = &fre
                .pattern_build_report(index)
                .expect("constituent build report")
                .profile
            else {
                panic!("set constituent published a non-bytes profile");
            };
            profile
        }))
    {
        let fre_syntax::RustConstructor::RegexSetBuilder { dfa_size_limit, .. } =
            &profile.constructor
        else {
            panic!("configured set lost its high-level constructor identity");
        };
        assert_eq!(*dfa_size_limit, 0);
    }
}

#[test]
fn crlf_dot_semantics_and_inline_overrides_match_pinned_bytes_builder() {
    let cases = [
        (".", false, b'\n'),
        (".", true, b'\n'),
        (".", true, b'\0'),
        ("(?-R:.)", true, b'\n'),
        ("(?R:.)", false, b'\n'),
    ];
    let haystacks: &[&[u8]] = &[b"", b"\r", b"\n", b"\r\n", b"\0", b"x", b"\r\n\0x"];

    for (pattern, crlf, line_terminator) in cases {
        let fre = PortableBuilder::new(pattern)
            .unicode(false)
            .crlf(crlf)
            .line_terminator(line_terminator)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::bytes::RegexBuilder::new(pattern);
        upstream
            .unicode(false)
            .crlf(crlf)
            .line_terminator(line_terminator);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| matched.range());
                let actual = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("FRE search failed for {pattern:?}/{haystack:?}/{start}: {error}")
                    })
                    .0
                    .map(fre::Match::range);
                assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}");
            }
        }

        let CompatibilityProfile::RustBytes(profile) = fre.profile() else {
            panic!("portable bytes builder published a non-bytes profile");
        };
        assert_eq!(profile.options.crlf, crlf);
        assert_eq!(profile.options.line_terminator, line_terminator);
    }

    let fre_assertions = PortableBuilder::new(r"^foo$")
        .unicode(false)
        .multi_line(true)
        .crlf(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("the K0 executor supports CRLF assertions");
    let mut upstream_assertions = regex::bytes::RegexBuilder::new(r"^foo$");
    upstream_assertions
        .unicode(false)
        .multi_line(true)
        .crlf(true);
    let upstream_assertions = upstream_assertions
        .build()
        .expect("pinned Rust bytes builder supports CRLF assertions");
    for haystack in [
        b"".as_slice(),
        b"foo",
        b"foo\r\n",
        b"\r\nfoo",
        b"\r\nfoo\r\nbar",
        b"xfoo\r\n",
        &[0xFF, b'\r', b'\n', b'f', b'o', b'o', b'\r'],
    ] {
        for start in 0..=haystack.len() {
            let expected = upstream_assertions
                .find_at(haystack, start)
                .map(|matched| matched.range());
            let actual = fre_assertions
                .find_at(haystack, start, SearchLimits::unlimited())
                .expect("FRE CRLF assertion search")
                .0
                .map(fre::Match::range);
            assert_eq!(actual, expected, "{haystack:?}/{start}");
        }
    }
}

#[test]
fn crlf_set_builder_applies_to_every_pattern_and_profile_identity() {
    let patterns = vec![".".to_owned(), "(?-R:.)".to_owned()];
    let fre = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .crlf(true)
        .build()
        .expect("CRLF-configured FRE set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream.unicode(false).crlf(true);
    let upstream = upstream.build().expect("CRLF-configured upstream set");

    for haystack in [b"".as_slice(), b"\r", b"\n", b"\r\n", b"x", &[0xFF]] {
        for start in 0..=haystack.len() {
            let expected: Vec<_> = upstream.matches_at(haystack, start).into_iter().collect();
            let actual: Vec<_> = fre
                .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
                .expect("CRLF-configured FRE set search")
                .into_iter()
                .collect();
            assert_eq!(actual, expected, "{haystack:?}/{start}");
        }
    }

    assert!(fre.build_report().profile.options.crlf);
    for index in 0..patterns.len() {
        let CompatibilityProfile::RustBytes(profile) = &fre
            .pattern_build_report(index)
            .expect("constituent build report")
            .profile
        else {
            panic!("set constituent published a non-bytes profile");
        };
        assert!(profile.options.crlf);
        assert_eq!(profile, &fre.build_report().profile);
    }
}

#[test]
fn every_ported_pinned_bytes_builder_example_passes() {
    let case_insensitive = PortableBuilder::new(r"foo(?-i:bar)quux")
        .case_insensitive(true)
        .build()
        .expect("case-insensitive builder example");
    assert!(
        case_insensitive
            .is_match_accounted(b"FoObarQuUx", SearchLimits::unlimited())
            .expect("case-insensitive positive search")
            .0
    );
    assert!(
        !case_insensitive
            .is_match_accounted(b"fooBARquux", SearchLimits::unlimited())
            .expect("local case-sensitive negative search")
            .0
    );

    let multi_line = PortableBuilder::new(r"^foo$")
        .multi_line(true)
        .build()
        .expect("multiline builder example");
    let matched = multi_line
        .find_accounted(b"\nfoo\n", SearchLimits::unlimited())
        .expect("multiline search")
        .0
        .expect("multiline match");
    assert_eq!((matched.start(), matched.end()), (1, 4));

    let dot_matches_new_line = PortableBuilder::new(r"foo.bar")
        .dot_matches_new_line(true)
        .build()
        .expect("dot-matches-new-line builder example");
    let haystack = b"foo\nbar";
    let matched = dot_matches_new_line
        .find_accounted(haystack, SearchLimits::unlimited())
        .expect("dot-matches-new-line search")
        .0
        .expect("dot-matches-new-line match");
    assert_eq!(&haystack[matched.start()..matched.end()], haystack);

    let swap_greed = PortableBuilder::new(r"a+")
        .swap_greed(true)
        .build()
        .expect("swap-greed builder example");
    let matched = swap_greed
        .find_accounted(b"aaa", SearchLimits::unlimited())
        .expect("swap-greed search")
        .0
        .expect("swap-greed match");
    assert_eq!((matched.start(), matched.end()), (0, 1));

    let ignore_whitespace = PortableBuilder::new(
        r"
            a+       # first run
            \x20     # literal space
            b+       # second run
        ",
    )
    .ignore_whitespace(true)
    .build()
    .expect("ignore-whitespace builder example");
    assert!(
        ignore_whitespace
            .is_match_accounted(b"aaa bbb", SearchLimits::unlimited())
            .expect("ignore-whitespace search")
            .0
    );

    let octal = PortableBuilder::new(r"\141")
        .octal(true)
        .build()
        .expect("octal builder example");
    assert!(
        octal
            .is_match_accounted(b"a", SearchLimits::unlimited())
            .expect("octal search")
            .0
    );

    assert!(PortableBuilder::new("a").nest_limit(0).build().is_ok());
    assert!(PortableBuilder::new("ab").nest_limit(0).build().is_err());

    let CompatibilityProfile::RustBytes(profile) = case_insensitive.profile() else {
        panic!("portable bytes builder published a non-bytes profile");
    };
    assert!(profile.options.case_insensitive);
    assert!(!profile.options.multi_line);
    assert!(!profile.options.dot_matches_new_line);
}

#[test]
fn syntax_affecting_flags_match_pinned_bytes_builder_differentially() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"aaa",
        b"aaa bbb",
        b"ab",
        b"aaab",
        b" a#",
        &[b'a', 0xFF, b'b'],
    ];
    let cases = [
        (r"a+", true, false, false),
        (r"a+?", true, false, false),
        ("a # comment\n b", false, true, false),
        (r"\ \#", false, true, false),
        (r"\141+", false, false, true),
    ];

    for (pattern, swap_greed, ignore_whitespace, octal) in cases {
        let fre = PortableBuilder::new(pattern)
            .swap_greed(swap_greed)
            .ignore_whitespace(ignore_whitespace)
            .octal(octal)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::bytes::RegexBuilder::new(pattern);
        upstream
            .swap_greed(swap_greed)
            .ignore_whitespace(ignore_whitespace)
            .octal(octal);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("FRE search failed for {pattern:?}/{haystack:?}/{start}: {error}")
                    })
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}");
            }
        }
    }

    let configured = PortableBuilder::new(r"a+\141 # comment")
        .swap_greed(true)
        .ignore_whitespace(true)
        .octal(true)
        .nest_limit(8)
        .build()
        .expect("combined syntax-affecting options");
    let CompatibilityProfile::RustBytes(profile) = configured.profile() else {
        panic!("portable bytes builder published a non-bytes profile");
    };
    assert!(profile.options.swap_greed);
    assert!(profile.options.ignore_whitespace);
    assert!(profile.options.octal);
    assert_eq!(profile.options.nest_limit, 8);
}

#[test]
fn programmatic_flags_match_pinned_bytes_builder_differentially() {
    let cases = [
        (r"foo(?-i:bar)quux", true, false, false),
        (r"^foo$", false, true, false),
        (r"foo.bar", false, false, true),
        (r"^(?i:foo).bar$", true, true, true),
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"FoObarQuUx",
        b"fooBARquux",
        b"foo\nbar",
        b"\nFOO\nBAR\n",
        &[b'f', b'o', b'o', 0xFF, b'b', b'a', b'r'],
    ];

    for (pattern, case_insensitive, multi_line, dot_matches_new_line) in cases {
        let fre = PortableBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .multi_line(multi_line)
            .dot_matches_new_line(dot_matches_new_line)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::bytes::RegexBuilder::new(pattern);
        upstream
            .case_insensitive(case_insensitive)
            .multi_line(multi_line)
            .dot_matches_new_line(dot_matches_new_line);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("FRE search failed for {pattern:?}/{haystack:?}/{start}: {error}")
                    })
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}");
            }
        }
    }
}

#[test]
fn set_builder_flags_apply_to_every_pattern_and_profile_identity() {
    let patterns = vec![r"^abc$".to_owned(), r"x.y".to_owned()];
    let fre = PortableRegexSetBuilder::new(&patterns)
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true)
        .build()
        .expect("configured FRE set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true);
    let upstream = upstream.build().expect("configured upstream set");
    let haystacks: &[&[u8]] = &[b"", b"ABC\nx\ny", b"zzz\nAbC\n", b"x\ny"];

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

    let report = fre.build_report();
    assert!(report.profile.options.case_insensitive);
    assert!(report.profile.options.multi_line);
    assert!(report.profile.options.dot_matches_new_line);
    for index in 0..patterns.len() {
        let CompatibilityProfile::RustBytes(profile) = &fre
            .pattern_build_report(index)
            .expect("constituent build report")
            .profile
        else {
            panic!("set constituent published a non-bytes profile");
        };
        assert_eq!(profile, &report.profile);
    }
}

#[test]
fn syntax_affecting_set_flags_apply_to_every_pattern_and_failure_index() {
    let patterns = vec![
        r"a+".to_owned(),
        "a # comment\n b".to_owned(),
        r"\141".to_owned(),
    ];
    let fre = PortableRegexSetBuilder::new(&patterns)
        .swap_greed(true)
        .ignore_whitespace(true)
        .octal(true)
        .nest_limit(8)
        .build()
        .expect("configured FRE set");
    let mut upstream = regex::bytes::RegexSetBuilder::new(&patterns);
    upstream
        .swap_greed(true)
        .ignore_whitespace(true)
        .octal(true)
        .nest_limit(8);
    let upstream = upstream.build().expect("configured upstream set");
    let haystacks: &[&[u8]] = &[b"", b"a", b"aaa", b"ab", b"zzz"];

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

    assert!(fre.build_report().profile.options.swap_greed);
    assert!(fre.build_report().profile.options.ignore_whitespace);
    assert!(fre.build_report().profile.options.octal);
    assert_eq!(fre.build_report().profile.options.nest_limit, 8);
    for index in 0..patterns.len() {
        let CompatibilityProfile::RustBytes(profile) = &fre
            .pattern_build_report(index)
            .expect("constituent build report")
            .profile
        else {
            panic!("set constituent published a non-bytes profile");
        };
        assert_eq!(profile, &fre.build_report().profile);
    }

    let nested = vec!["a".to_owned(), "ab".to_owned()];
    let error = PortableRegexSetBuilder::new(&nested)
        .nest_limit(0)
        .build()
        .expect_err("second pattern exceeds the configured nesting limit");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::Pattern {
            index: 1,
            source: BuildError::Syntax(_),
        }
    ));

    let mut upstream = regex::bytes::RegexSetBuilder::new(&nested);
    assert!(upstream.nest_limit(0).build().is_err());
}
