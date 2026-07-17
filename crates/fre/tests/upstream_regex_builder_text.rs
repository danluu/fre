#![forbid(unsafe_code)]

use fre::{
    CompatibilityProfile, PortableTextBuildError, PortableTextBuilder, PortableTextRegex,
    RustProfile, SearchLimits, SearchWindow,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/builders.rs";
const UPSTREAM_SHA256: &str = "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f";

// The complete public option surface on regex 1.12.4's string::RegexBuilder.
// Keep this ordered exactly as the authenticated upstream implementation.
const UPSTREAM_OPTION_IDS: &[&str] = &[
    "unicode",
    "case_insensitive",
    "multi_line",
    "dot_matches_new_line",
    "crlf",
    "line_terminator",
    "swap_greed",
    "ignore_whitespace",
    "octal",
    "size_limit",
    "dfa_size_limit",
    "nest_limit",
];

// Each upstream doctest topic is either executed directly below or covered by
// the indicated differential/error case. Keeping this separate from the
// method inventory makes a newly added example an explicit review event.
const UPSTREAM_EXAMPLE_IDS: &[&str] = &[
    "unicode_ascii_word",
    "unicode_ascii_case_fold",
    "case_insensitive_local_override",
    "multi_line",
    "dot_matches_new_line",
    "crlf_match",
    "crlf_no_between_match",
    "line_terminator_anchor",
    "line_terminator_dot",
    "line_terminator_non_ascii_rejection",
    "swap_greed",
    "ignore_whitespace",
    "octal",
    "size_limit",
    "nest_limit",
];

type ProgrammaticFlagCase<'a> = (&'a str, bool, bool, bool, bool, &'a [&'a str]);

fn assert_searches_equal(
    pattern: &str,
    fre: &PortableTextRegex,
    upstream: &regex::Regex,
    haystacks: &[&str],
) {
    for haystack in haystacks {
        for start in 0..=haystack.len() {
            let expected = upstream
                .find_at(haystack, start)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, find_at_accounting) = fre
                .find_at(haystack, start, SearchLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("FRE search failed for {pattern:?}/{haystack:?}/{start}: {error}")
                });
            let actual = actual.map(|matched| (matched.start(), matched.end()));
            assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}");

            if haystack.is_char_boundary(start) {
                let (windowed, windowed_accounting) = fre
                    .find_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "FRE window search failed for {pattern:?}/{haystack:?}/{start}: \
                             {error}"
                        )
                    });
                assert_eq!(
                    windowed.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "window/{pattern:?}/{haystack:?}/{start}"
                );
                assert_eq!(find_at_accounting, windowed_accounting);
            }

            assert_eq!(
                fre.is_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "FRE existence search failed for {pattern:?}/{haystack:?}/{start}: \
                             {error}"
                        )
                    })
                    .0,
                upstream.is_match_at(haystack, start),
                "existence {pattern:?}/{haystack:?}/{start}"
            );
        }
    }
}

#[test]
fn text_offset_search_refuses_only_out_of_bounds_starts() {
    let regex = PortableTextRegex::new("").expect("nullable text regex");
    let haystack = "é";
    let matched = regex
        .find_at(haystack, 1, SearchLimits::unlimited())
        .expect("interior UTF-8 start is valid")
        .0
        .expect("empty match at the next scalar boundary");
    assert_eq!((matched.start(), matched.end()), (2, 2));
    assert!(
        regex
            .find_at(haystack, haystack.len() + 1, SearchLimits::unlimited())
            .is_err()
    );
}

#[test]
fn authenticated_text_builder_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/builders.rs");
    assert_eq!(
        UPSTREAM_SHA256,
        "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f"
    );
    assert_eq!(
        UPSTREAM_OPTION_IDS,
        [
            "unicode",
            "case_insensitive",
            "multi_line",
            "dot_matches_new_line",
            "crlf",
            "line_terminator",
            "swap_greed",
            "ignore_whitespace",
            "octal",
            "size_limit",
            "dfa_size_limit",
            "nest_limit",
        ]
    );
    assert_eq!(UPSTREAM_EXAMPLE_IDS.len(), 15);
}

#[test]
fn every_public_option_is_retained_in_text_profile_identity() {
    let fre = PortableTextBuilder::new("a")
        .unicode(false)
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true)
        .crlf(true)
        .line_terminator(0)
        .swap_greed(true)
        .ignore_whitespace(true)
        .octal(true)
        .size_limit(4_096)
        .dfa_size_limit(17)
        .nest_limit(9)
        .build()
        .expect("fully configured text builder");
    let CompatibilityProfile::RustText(profile) = fre.profile() else {
        panic!("text builder published a non-text profile");
    };
    assert!(!profile.options.unicode);
    assert!(profile.options.case_insensitive);
    assert!(profile.options.multi_line);
    assert!(profile.options.dot_matches_new_line);
    assert!(profile.options.crlf);
    assert_eq!(profile.options.line_terminator, 0);
    assert!(profile.options.swap_greed);
    assert!(profile.options.ignore_whitespace);
    assert!(profile.options.octal);
    assert_eq!(profile.options.nest_limit, 9);
    let fre_syntax::RustConstructor::RegexBuilder {
        size_limit,
        dfa_size_limit,
        ..
    } = &profile.constructor
    else {
        panic!("text builder lost its high-level constructor identity");
    };
    assert_eq!(*size_limit, 4_096);
    assert_eq!(*dfa_size_limit, 17);
}

#[test]
fn unicode_and_programmatic_flag_examples_match_pinned_text_builder() {
    let cases: &[ProgrammaticFlagCase<'_>] = &[
        (r"\w", false, false, false, false, &["", "δ", "δa", "東京Z"]),
        ("s", true, true, false, false, &["", "s", "S", "ſ", "xſ"]),
        (
            r"foo(?-i:bar)quux",
            true,
            true,
            false,
            false,
            &["FoObarQuUx", "fooBARquux", "xFoObarQuUxy"],
        ),
        (
            r"^foo$",
            true,
            false,
            true,
            false,
            &["", "foo", "\nfoo\n", "x\nfoo\ny"],
        ),
        (
            r"foo.bar",
            true,
            false,
            false,
            true,
            &["foo\nbar", "foo🦀bar", "foo.bar"],
        ),
    ];

    for &(pattern, unicode, case_insensitive, multi_line, dot_matches_new_line, haystacks) in cases
    {
        let fre = PortableTextBuilder::new(pattern)
            .unicode(unicode)
            .case_insensitive(case_insensitive)
            .multi_line(multi_line)
            .dot_matches_new_line(dot_matches_new_line)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::RegexBuilder::new(pattern);
        upstream
            .unicode(unicode)
            .case_insensitive(case_insensitive)
            .multi_line(multi_line)
            .dot_matches_new_line(dot_matches_new_line);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        assert_searches_equal(pattern, &fre, &upstream, haystacks);
    }
}

#[test]
fn crlf_and_line_terminator_examples_match_pinned_text_builder() {
    let cases: &[(&str, bool, bool, u8, &[&str])] = &[
        (
            r"^foo$",
            true,
            true,
            b'\n',
            &["", "foo", "\r\nfoo\r\n", "\rfoo\n", "xfoo"],
        ),
        (r"^", true, true, b'\n', &["", "\r\n\r\n", "\r", "\n"]),
        (r"^foo$", true, false, 0, &["", "foo", "\0foo\0", "\nfoo\n"]),
        (r".", false, false, 0, &["", "\0", "\n", "é", "東京"]),
    ];

    for &(pattern, multi_line, crlf, line_terminator, haystacks) in cases {
        let fre = PortableTextBuilder::new(pattern)
            .multi_line(multi_line)
            .crlf(crlf)
            .line_terminator(line_terminator)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::RegexBuilder::new(pattern);
        upstream
            .multi_line(multi_line)
            .crlf(crlf)
            .line_terminator(line_terminator);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        assert_searches_equal(pattern, &fre, &upstream, haystacks);
    }
}

#[test]
fn syntax_affecting_examples_match_pinned_text_builder() {
    let cases: &[(&str, bool, bool, bool, &[&str])] = &[
        (r"a+", true, false, false, &["", "a", "aaa", "baaa"]),
        (
            "a # first literal\n \\x20 b",
            false,
            true,
            false,
            &["", "a b", "ab", "xa by"],
        ),
        (r"\141+", false, false, true, &["", "a", "aaa", "141"]),
    ];

    for &(pattern, swap_greed, ignore_whitespace, octal, haystacks) in cases {
        let fre = PortableTextBuilder::new(pattern)
            .swap_greed(swap_greed)
            .ignore_whitespace(ignore_whitespace)
            .octal(octal)
            .build()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let mut upstream = regex::RegexBuilder::new(pattern);
        upstream
            .swap_greed(swap_greed)
            .ignore_whitespace(ignore_whitespace)
            .octal(octal);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        assert_searches_equal(pattern, &fre, &upstream, haystacks);
    }

    assert!(PortableTextBuilder::new("a").nest_limit(0).build().is_ok());
    assert!(
        PortableTextBuilder::new("ab")
            .nest_limit(0)
            .build()
            .is_err()
    );
    let mut upstream_ok = regex::RegexBuilder::new("a");
    assert!(upstream_ok.nest_limit(0).build().is_ok());
    let mut upstream_error = regex::RegexBuilder::new("ab");
    assert!(upstream_error.nest_limit(0).build().is_err());
}

#[test]
fn size_limit_matches_pinned_text_constructor_boundaries_and_error_class() {
    for pattern in ["a", "é", "a|ab", "(?:é|東京)+"] {
        for size_limit in [0, 1, 64, 128, 256, 512, 1_024, 4_096] {
            let mut upstream = regex::RegexBuilder::new(pattern);
            upstream.size_limit(size_limit);
            let expected = upstream.build();
            let actual = PortableTextBuilder::new(pattern)
                .size_limit(size_limit)
                .build();
            assert_eq!(
                actual.is_ok(),
                expected.is_ok(),
                "pattern={pattern:?}, size_limit={size_limit}, FRE={actual:?}, upstream={expected:?}"
            );
            match (actual, expected) {
                (Ok(fre), Ok(upstream)) => {
                    assert_searches_equal(pattern, &fre, &upstream, &["", "a", "ab", "é", "東京é"]);
                    let CompatibilityProfile::RustText(profile) = fre.profile() else {
                        panic!("text builder published a non-text profile");
                    };
                    let fre_syntax::RustConstructor::RegexBuilder {
                        size_limit: retained,
                        ..
                    } = &profile.constructor
                    else {
                        panic!("text builder lost constructor identity");
                    };
                    assert_eq!(*retained, u64::try_from(size_limit).unwrap_or(u64::MAX));
                }
                (
                    Err(PortableTextBuildError::TextSyntax(error)),
                    Err(regex::Error::CompiledTooBig(limit)),
                ) => {
                    assert_eq!(limit, size_limit);
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

    let mut upstream = regex::RegexBuilder::new(r"\w");
    assert!(matches!(
        upstream.size_limit(45_000).build(),
        Err(regex::Error::CompiledTooBig(45_000))
    ));
    assert!(matches!(
        PortableTextBuilder::new(r"\w").size_limit(45_000).build(),
        Err(PortableTextBuildError::TextSyntax(ref error))
            if error.category
                == fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { limit: 45_000 }
    ));
}

#[test]
fn dfa_size_limit_is_semantic_neutral_and_retained() {
    for dfa_size_limit in [0, 1, 2 * (1 << 20), usize::MAX] {
        let pattern = "(?:é|東京)+";
        let fre = PortableTextBuilder::new(pattern)
            .dfa_size_limit(dfa_size_limit)
            .build()
            .expect("FRE text builder accepts DFA cache identity");
        let mut upstream = regex::RegexBuilder::new(pattern);
        upstream.dfa_size_limit(dfa_size_limit);
        let upstream = upstream
            .build()
            .expect("upstream text builder accepts DFA cache identity");
        assert_searches_equal(
            pattern,
            &fre,
            &upstream,
            &["", "é", "東京", "x東京ééy", "🦀"],
        );
        let CompatibilityProfile::RustText(profile) = fre.profile() else {
            panic!("text builder published a non-text profile");
        };
        let fre_syntax::RustConstructor::RegexBuilder {
            dfa_size_limit: retained,
            ..
        } = &profile.constructor
        else {
            panic!("text builder lost constructor identity");
        };
        assert_eq!(*retained, u64::try_from(dfa_size_limit).unwrap_or(u64::MAX));
    }
}

#[test]
fn invalid_configuration_precedence_and_option_order_match_upstream() {
    let bad_syntax = String::from("(");
    let mut upstream_bad_syntax = regex::RegexBuilder::new(&bad_syntax);
    let upstream_bad_syntax = upstream_bad_syntax.size_limit(0).build();
    assert!(matches!(upstream_bad_syntax, Err(regex::Error::Syntax(_))));
    assert!(matches!(
        PortableTextBuilder::new(bad_syntax).size_limit(0).build(),
        Err(PortableTextBuildError::TextSyntax(ref error))
            if error.category == fre_syntax::ErrorCategory::UpstreamRustSyntax
    ));

    let mut upstream_invalid_line = regex::RegexBuilder::new(".");
    assert!(upstream_invalid_line.line_terminator(0x80).build().is_err());
    assert!(matches!(
        PortableTextBuilder::new(".").line_terminator(0x80).build(),
        Err(PortableTextBuildError::TextSyntax(_))
    ));
    let mut upstream_unused_line = regex::RegexBuilder::new("a");
    let upstream_unused_line = upstream_unused_line
        .line_terminator(0x80)
        .build()
        .expect("unused non-ASCII terminator is valid upstream");
    let fre_unused_line = PortableTextBuilder::new("a")
        .line_terminator(0x80)
        .build()
        .expect("unused non-ASCII terminator is valid in FRE");
    assert_searches_equal(
        "a",
        &fre_unused_line,
        &upstream_unused_line,
        &["", "a", "éa"],
    );

    let fre_first = PortableTextBuilder::new("s")
        .unicode(false)
        .case_insensitive(true)
        .build()
        .expect("first FRE option order");
    let fre_second = PortableTextBuilder::new("s")
        .case_insensitive(true)
        .unicode(false)
        .build()
        .expect("second FRE option order");
    let mut upstream_first = regex::RegexBuilder::new("s");
    upstream_first.unicode(false).case_insensitive(true);
    let upstream_first = upstream_first.build().expect("first upstream option order");
    let mut upstream_second = regex::RegexBuilder::new("s");
    upstream_second.case_insensitive(true).unicode(false);
    let upstream_second = upstream_second
        .build()
        .expect("second upstream option order");
    for haystack in ["", "s", "S", "ſ", "xS"] {
        let expected_first = upstream_first.find(haystack).map(|m| m.range());
        let expected_second = upstream_second.find(haystack).map(|m| m.range());
        assert_eq!(
            expected_first, expected_second,
            "upstream order/{haystack:?}"
        );
        let actual_first = fre_first
            .find(haystack, SearchLimits::unlimited())
            .expect("first FRE search")
            .0
            .map(fre::Match::range);
        let actual_second = fre_second
            .find(haystack, SearchLimits::unlimited())
            .expect("second FRE search")
            .0
            .map(fre::Match::range);
        assert_eq!(actual_first, expected_first, "first order/{haystack:?}");
        assert_eq!(actual_second, expected_second, "second order/{haystack:?}");
    }
}
