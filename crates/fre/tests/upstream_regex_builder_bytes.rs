#![forbid(unsafe_code)]

use fre::{
    BuildError, CompatibilityProfile, PortableBuilder, PortableRegexSetBuildError,
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
    "bytes_regex_builder_swap_greed",
    "bytes_regex_builder_ignore_whitespace",
    "bytes_regex_builder_octal",
    "bytes_regex_builder_nest_limit",
];

#[test]
fn authenticated_bytes_builder_flag_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/builders.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 7);
}

#[test]
fn every_ported_pinned_bytes_builder_example_passes() {
    let case_insensitive = PortableBuilder::new(r"foo(?-i:bar)quux")
        .case_insensitive(true)
        .build()
        .expect("case-insensitive builder example");
    assert!(
        case_insensitive
            .is_match(b"FoObarQuUx", SearchLimits::unlimited())
            .expect("case-insensitive positive search")
            .0
    );
    assert!(
        !case_insensitive
            .is_match(b"fooBARquux", SearchLimits::unlimited())
            .expect("local case-sensitive negative search")
            .0
    );

    let multi_line = PortableBuilder::new(r"^foo$")
        .multi_line(true)
        .build()
        .expect("multiline builder example");
    let matched = multi_line
        .find(b"\nfoo\n", SearchLimits::unlimited())
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
        .find(haystack, SearchLimits::unlimited())
        .expect("dot-matches-new-line search")
        .0
        .expect("dot-matches-new-line match");
    assert_eq!(&haystack[matched.start()..matched.end()], haystack);

    let swap_greed = PortableBuilder::new(r"a+")
        .swap_greed(true)
        .build()
        .expect("swap-greed builder example");
    let matched = swap_greed
        .find(b"aaa", SearchLimits::unlimited())
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
            .is_match(b"aaa bbb", SearchLimits::unlimited())
            .expect("ignore-whitespace search")
            .0
    );

    let octal = PortableBuilder::new(r"\141")
        .octal(true)
        .build()
        .expect("octal builder example");
    assert!(
        octal
            .is_match(b"a", SearchLimits::unlimited())
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
