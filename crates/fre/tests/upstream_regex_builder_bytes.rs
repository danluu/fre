#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildFailureClass, BuildLimits, CompatibilityProfile, PlanSelection,
    PortableBuilder, PortableRegexSetBuildError, PortableRegexSetBuildLimits,
    PortableRegexSetBuilder, PortableRegexSetRunLimits, RustProfile, SearchLimits,
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
fn size_limit_caps_the_fre_persistent_representation_at_its_exact_boundary() {
    let pattern = r"(?P<word>ab)+(?:c|d)";
    let measured = PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .size_limit(usize::MAX)
        .build()
        .expect("unbounded FRE measurement build");
    let needed = measured.build_report().charged_persistent_bytes;
    assert!(needed > 0);
    assert_eq!(
        needed,
        measured.build_report().source_storage_bytes
            + measured.build_report().capture_name_storage_bytes
            + measured.build_report().plan_storage_bytes
    );

    let exact = PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .size_limit(needed)
        .build()
        .expect("the exact FRE persistent-byte boundary is inclusive");
    assert_eq!(exact.build_report().charged_persistent_bytes, needed);
    assert_eq!(exact.build_report().persistent_byte_limit, needed);
    let CompatibilityProfile::RustBytes(profile) = exact.profile() else {
        panic!("portable bytes builder published a non-bytes profile");
    };
    let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } = &profile.constructor
    else {
        panic!("configured builder lost its high-level constructor identity");
    };
    assert_eq!(*size_limit, u64::try_from(needed).unwrap_or(u64::MAX));

    let one_below = needed.checked_sub(1).expect("nonzero charged size");
    let error = PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .size_limit(one_below)
        .build()
        .expect_err("one byte below the FRE representation must fail");
    assert_eq!(error.failure_class(), BuildFailureClass::ResourceLimit);
    assert!(matches!(
        error,
        BuildError::PersistentBytesLimit {
            needed: rejected,
            limit,
        } if rejected == needed && limit == one_below
    ));

    let default = PortableBuilder::new("a")
        .unicode(false)
        .build()
        .expect("default FRE limit");
    assert_eq!(default.build_report().persistent_byte_limit, 10 * (1 << 20));

    let mut lower_limits = BuildLimits::default();
    lower_limits.max_persistent_bytes = one_below;
    assert!(matches!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .size_limit(needed)
            .limits(lower_limits)
            .build(),
        Err(BuildError::PersistentBytesLimit { limit, .. }) if limit == one_below
    ));
    PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .limits(lower_limits)
        .size_limit(needed)
        .build()
        .expect("the last size-limit setter owns the native ceiling");
}

#[test]
fn set_size_limit_is_one_aggregate_fre_persistent_cap() {
    let patterns = vec!["(a)".to_owned(), "bravo".to_owned(), "charlie|delta".to_owned()];
    let mut unbounded_limits = PortableRegexSetBuildLimits::default();
    unbounded_limits.max_persistent_bytes = usize::MAX;
    unbounded_limits.pattern.max_persistent_bytes = usize::MAX;
    let measured = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .limits(unbounded_limits)
        .size_limit(usize::MAX)
        .build()
        .expect("unbounded FRE set measurement build");
    let needed = measured.build_report().charged_persistent_bytes;
    assert!(needed > 0);

    let exact = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .limits(unbounded_limits)
        .size_limit(needed)
        .build()
        .expect("the exact aggregate FRE boundary is inclusive");
    assert_eq!(exact.build_report().charged_persistent_bytes, needed);
    assert_eq!(exact.build_report().limits.max_persistent_bytes, needed);
    for index in 0..exact.len() {
        let report = exact.pattern_build_report(index).expect("constituent report");
        assert_eq!(report.persistent_byte_limit, usize::MAX);
        let CompatibilityProfile::RustBytes(profile) = &report.profile else {
            panic!("set constituent published a non-bytes profile");
        };
        let fre_syntax::RustConstructor::RegexSetBuilder { size_limit, .. } = &profile.constructor
        else {
            panic!("configured set lost its set-constructor identity");
        };
        assert_eq!(*size_limit, u64::try_from(needed).unwrap_or(u64::MAX));
    }

    let one_below = needed.checked_sub(1).expect("nonzero aggregate charge");
    let error = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .limits(unbounded_limits)
        .size_limit(one_below)
        .build()
        .expect_err("one byte below the aggregate FRE representation must fail");
    assert!(matches!(
        error,
        PortableRegexSetBuildError::PersistentLimit {
            needed: rejected,
            limit,
        } if rejected == needed && limit == one_below
    ));

    let default = PortableRegexSetBuilder::new(&["a".to_owned(), "b".to_owned()])
        .unicode(false)
        .build()
        .expect("default set limit");
    assert_eq!(
        default.build_report().limits.max_persistent_bytes,
        10 * (1 << 20)
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
