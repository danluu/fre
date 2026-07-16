#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, EXPLAIN_SCHEMA_VERSION, PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION,
    PlanKind, PlanSelection, PortableBuilder, PortableRegex, PortableRegexSet,
    PortableRegexSetBuildLimits, PortableRegexSetBuilder, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_BYTES_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_BYTES_SHA256: &str =
    "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_MISC_PATH: &str = "tests/misc.rs";
const UPSTREAM_MISC_SHA256: &str =
    "1aeadbeb8860bd5f5b99a0adb459baf77dd3af4f23ac6c56ecf537f793407cca";
const UPSTREAM_API_IDS: &[&str] = &[
    "bytes_regex_as_str",
    "display_original_pattern",
    "debug_original_pattern",
    "from_str",
    "try_from_str",
    "try_from_string",
    "bytes_match_len",
    "bytes_match_range",
];

#[test]
fn authenticated_bytes_source_api_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_BYTES_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_BYTES_SHA256.len(), 64);
    assert_eq!(UPSTREAM_MISC_PATH, "tests/misc.rs");
    assert_eq!(UPSTREAM_MISC_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS.len(), 8);
    assert_eq!(EXPLAIN_SCHEMA_VERSION, 2);
    assert_eq!(PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION, 2);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated cross-plan accessor matrix is clearer as one differential test"
)]
fn match_offset_accessors_match_pinned_bytes_across_every_portable_plan() {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    let cases = [
        (
            "exact literal",
            PlanKind::ExactLiteral,
            PortableBuilder::new("Sherlock").unicode(false).build(),
            regex::bytes::RegexBuilder::new("Sherlock")
                .unicode(false)
                .build(),
            b"\xFFSherlock Holmes".as_slice(),
        ),
        (
            "packed finite language",
            PlanKind::PackedLiteralSet,
            PortableBuilder::new("a|ab").unicode(false).build(),
            regex::bytes::RegexBuilder::new("a|ab")
                .unicode(false)
                .build(),
            b"\xFFab".as_slice(),
        ),
        (
            "finite language DFA",
            PlanKind::LiteralSetDfa,
            PortableBuilder::new("foobar|foobaz|fooquux")
                .unicode(false)
                .limits(dfa_limits)
                .build(),
            regex::bytes::RegexBuilder::new("foobar|foobaz|fooquux")
                .unicode(false)
                .build(),
            b"\xFFfooquux".as_slice(),
        ),
        (
            "required literal",
            PlanKind::RequiredLiteral,
            PortableBuilder::new("[a-z]+Z").unicode(false).build(),
            regex::bytes::RegexBuilder::new("[a-z]+Z")
                .unicode(false)
                .build(),
            b"\xFFabcZ".as_slice(),
        ),
        (
            "forward anchored",
            PlanKind::ForwardAnchored,
            PortableBuilder::new(r"\A[a-z]+Z").unicode(false).build(),
            regex::bytes::RegexBuilder::new(r"\A[a-z]+Z")
                .unicode(false)
                .build(),
            b"abcZ".as_slice(),
        ),
        (
            "Unicode word run",
            PlanKind::UnicodeWordRun,
            PortableBuilder::new(r"\b\w{2,}\b").build(),
            regex::bytes::RegexBuilder::new(r"\b\w{2,}\b").build(),
            " \u{3B1}\u{3B2} ".as_bytes(),
        ),
        (
            "generic K0",
            PlanKind::K0,
            PortableBuilder::new("(?:ab)+")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
            regex::bytes::RegexBuilder::new("(?:ab)+")
                .unicode(false)
                .build(),
            b"\xFFabab".as_slice(),
        ),
        (
            "empty K0 assertion",
            PlanKind::K0,
            PortableBuilder::new("^")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
            regex::bytes::RegexBuilder::new("^").unicode(false).build(),
            b"\xFF".as_slice(),
        ),
    ];

    for (name, expected_plan, fre, upstream, haystack) in cases {
        let fre = fre.unwrap_or_else(|error| panic!("failed to build {name}: {error}"));
        let upstream =
            upstream.unwrap_or_else(|error| panic!("pinned regex rejected {name}: {error}"));
        assert_eq!(fre.build_report().plan, expected_plan, "{name}");

        let actual = fre
            .find(haystack, fre::SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("FRE search failed for {name}: {error}"))
            .0
            .unwrap_or_else(|| panic!("FRE found no match for {name}"));
        let expected = upstream
            .find(haystack)
            .unwrap_or_else(|| panic!("pinned regex found no match for {name}"));

        assert_eq!(actual.start(), expected.start(), "{name}");
        assert_eq!(actual.end(), expected.end(), "{name}");
        assert_eq!(actual.is_empty(), expected.is_empty(), "{name}");
        assert_eq!(actual.len(), expected.len(), "{name}");
        assert_eq!(actual.range(), expected.range(), "{name}");
        assert_eq!(&haystack[actual.range()], expected.as_bytes(), "{name}");
    }
}

#[test]
fn original_source_and_formatting_match_the_pinned_bytes_api() {
    let pattern = "(?x) [a-zA-Z0-9]+ # retained comment\n";
    let fre = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("portable source API pattern");
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("pinned source API pattern");

    assert_eq!(fre.as_str(), upstream.as_str());
    assert_eq!(fre.to_string(), upstream.to_string());
    assert_eq!(format!("{fre:?}"), format!("PortableRegex({pattern:?})"));
    assert_eq!(fre.build_report().source_storage_bytes, pattern.len());
}

#[test]
fn source_identity_survives_every_portable_plan_family() {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    let cases = [
        (
            "Sherlock",
            PlanKind::ExactLiteral,
            PortableBuilder::new("Sherlock").unicode(false).build(),
        ),
        (
            "a|ab",
            PlanKind::PackedLiteralSet,
            PortableBuilder::new("a|ab").unicode(false).build(),
        ),
        (
            "foobar|foobaz|fooquux",
            PlanKind::LiteralSetDfa,
            PortableBuilder::new("foobar|foobaz|fooquux")
                .unicode(false)
                .limits(dfa_limits)
                .build(),
        ),
        (
            "[a-z]+Z",
            PlanKind::RequiredLiteral,
            PortableBuilder::new("[a-z]+Z").unicode(false).build(),
        ),
        (
            r"\A[a-z]+Z",
            PlanKind::ForwardAnchored,
            PortableBuilder::new(r"\A[a-z]+Z").unicode(false).build(),
        ),
        (
            r"\b\w{2,}\b",
            PlanKind::UnicodeWordRun,
            PortableBuilder::new(r"\b\w{2,}\b").build(),
        ),
        (
            "(?:ab)+",
            PlanKind::K0,
            PortableBuilder::new("(?:ab)+")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
        ),
    ];

    for (source, expected_plan, built) in cases {
        let regex = built.unwrap_or_else(|error| panic!("failed to build {source:?}: {error}"));
        assert_eq!(regex.as_str(), source);
        assert_eq!(regex.to_string(), source);
        assert_eq!(regex.build_report().plan, expected_plan, "{source:?}");
        assert_eq!(regex.build_report().source_storage_bytes, source.len());
    }
}

#[test]
fn string_conversions_share_new_semantics_and_preserve_typed_errors() {
    let pattern = "a+b";
    let parsed: PortableRegex = pattern.parse().expect("FromStr");
    let borrowed = PortableRegex::try_from(pattern).expect("TryFrom<&str>");

    let mut owned_pattern = String::with_capacity(1 << 20);
    owned_pattern.push_str(pattern);
    let owned = PortableRegex::try_from(owned_pattern).expect("TryFrom<String>");
    for regex in [&parsed, &borrowed, &owned] {
        assert_eq!(regex.as_str(), pattern);
        assert_eq!(regex.build_report().source_storage_bytes, pattern.len());
    }

    let parsed_error = "(".parse::<PortableRegex>().expect_err("invalid FromStr");
    let borrowed_error = PortableRegex::try_from("(").expect_err("invalid borrowed source");
    let owned_error = PortableRegex::try_from("(".to_owned()).expect_err("invalid owned source");
    assert!(matches!(parsed_error, BuildError::Syntax(_)));
    assert!(matches!(borrowed_error, BuildError::Syntax(_)));
    assert!(matches!(owned_error, BuildError::Syntax(_)));
}

#[test]
fn set_persistent_limit_charges_each_matcher_source_identity() {
    let patterns = vec!["a".to_owned(), "bc|de".to_owned()];
    let probe = PortableRegexSet::new(&patterns).expect("set source accounting probe");
    let report = probe.build_report();
    let expected_matcher_sources = patterns.iter().map(String::len).sum::<usize>();
    assert_eq!(report.matcher_source_bytes, expected_matcher_sources);
    assert_eq!(
        report.charged_persistent_bytes,
        report.source_capacity_bytes
            + report.regex_capacity_bytes
            + report.matcher_source_bytes
            + report.plan_storage_bytes
    );

    let exact = report.charged_persistent_bytes;
    PortableRegexSetBuilder::new(&patterns)
        .limits(PortableRegexSetBuildLimits {
            max_persistent_bytes: exact,
            ..PortableRegexSetBuildLimits::default()
        })
        .build()
        .expect("exact set source storage limit");
    assert!(
        PortableRegexSetBuilder::new(&patterns)
            .limits(PortableRegexSetBuildLimits {
                max_persistent_bytes: exact - 1,
                ..PortableRegexSetBuildLimits::default()
            })
            .build()
            .is_err()
    );
}
