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
    "bytes_regex_clone",
    "display_original_pattern",
    "debug_original_pattern",
    "from_str",
    "try_from_str",
    "try_from_string",
    "bytes_match_len",
    "bytes_match_range",
    "bytes_match_as_bytes",
    "bytes_match_into_bytes",
    "bytes_match_into_range",
    "bytes_match_debug",
    "bytes_regex_capture_names",
    "bytes_regex_captures_len",
    "bytes_regex_static_captures_len",
    "misc_capture_names",
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
    assert_eq!(UPSTREAM_API_IDS.len(), 17);
    assert_eq!(EXPLAIN_SCHEMA_VERSION, 5);
    assert_eq!(PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION, 4);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated cross-plan capture-name matrix is clearer as one differential test"
)]
fn capture_name_metadata_matches_pinned_bytes_across_every_portable_plan() {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    let cases = [
        (
            "(?P<literal>(Sherlock))",
            PlanKind::ExactLiteral,
            PortableBuilder::new("(?P<literal>(Sherlock))")
                .unicode(false)
                .build(),
        ),
        (
            "a|(?P<suffix>(ab))",
            PlanKind::PackedLiteralSet,
            PortableBuilder::new("a|(?P<suffix>(ab))")
                .unicode(false)
                .build(),
        ),
        (
            "(?P<first>foobar)|foobaz|(?P<third>fooquux)",
            PlanKind::LiteralSetDfa,
            PortableBuilder::new("(?P<first>foobar)|foobaz|(?P<third>fooquux)")
                .unicode(false)
                .limits(dfa_limits)
                .build(),
        ),
        (
            "(?P<run>([a-z]+)Z)",
            PlanKind::RequiredLiteral,
            PortableBuilder::new("(?P<run>([a-z]+)Z)")
                .unicode(false)
                .build(),
        ),
        (
            r"(?P<run>\A([a-z]+)Z)",
            PlanKind::ForwardAnchored,
            PortableBuilder::new(r"(?P<run>\A([a-z]+)Z)")
                .unicode(false)
                .build(),
        ),
        (
            r"(?P<word>\b(\w{2,})\b)",
            PlanKind::UnicodeWordRun,
            PortableBuilder::new(r"(?P<word>\b(\w{2,})\b)").build(),
        ),
        (
            "(?P<outer>(?P<inner>ab)+)",
            PlanKind::K0,
            PortableBuilder::new("(?P<outer>(?P<inner>ab)+)")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
        ),
    ];

    for (pattern, expected_plan, built) in cases {
        let fre = built.unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(pattern.contains(r"\w"))
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
        assert_eq!(fre.build_report().plan, expected_plan, "{pattern:?}");

        let mut actual_names = fre.capture_names();
        assert_eq!(
            actual_names.size_hint(),
            (fre.captures_len(), Some(fre.captures_len())),
            "{pattern:?}"
        );
        assert_eq!(actual_names.clone().count(), fre.captures_len());
        let actual: Vec<_> = actual_names.by_ref().collect();
        let expected: Vec<_> = upstream.capture_names().collect();
        assert_eq!(actual, expected, "{pattern:?}");
        assert_eq!(actual_names.next(), None);
        assert_eq!(actual_names.next(), None);

        let expected_storage = core::mem::size_of::<Option<Box<str>>>()
            .checked_mul(expected.len())
            .and_then(|slots| {
                expected
                    .iter()
                    .flatten()
                    .try_fold(slots, |total, name| total.checked_add(name.len()))
            })
            .expect("capture-name storage fixture fits usize");
        assert_eq!(
            fre.build_report().capture_name_storage_bytes,
            expected_storage,
            "{pattern:?}"
        );
    }
}

#[test]
fn capture_names_match_every_pinned_doctest_and_misc_shape() {
    for pattern in [
        "",
        r"[a&&b]",
        r"(.)(?P<a>.)",
        r"(?<a>.(?<b>.))(.)(?:.)(?<c>.)",
    ] {
        let fre = PortableRegex::new(pattern)
            .unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::Regex::new(pattern)
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
        assert_eq!(
            fre.capture_names().collect::<Vec<_>>(),
            upstream.capture_names().collect::<Vec<_>>(),
            "{pattern:?}"
        );
    }
}

#[test]
fn capture_cardinality_metadata_matches_pinned_bytes_across_every_portable_plan() {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    let cases = [
        (
            "(Sherlock)",
            PlanKind::ExactLiteral,
            PortableBuilder::new("(Sherlock)").unicode(false).build(),
        ),
        (
            "a|(ab)",
            PlanKind::PackedLiteralSet,
            PortableBuilder::new("a|(ab)").unicode(false).build(),
        ),
        (
            "(foobar)|foobaz|fooquux",
            PlanKind::LiteralSetDfa,
            PortableBuilder::new("(foobar)|foobaz|fooquux")
                .unicode(false)
                .limits(dfa_limits)
                .build(),
        ),
        (
            "([a-z]+Z)",
            PlanKind::RequiredLiteral,
            PortableBuilder::new("([a-z]+Z)").unicode(false).build(),
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
            "((?:ab)+)",
            PlanKind::K0,
            PortableBuilder::new("((?:ab)+)")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
        ),
    ];

    for (pattern, expected_plan, built) in cases {
        let fre = built.unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(pattern == r"\b\w{2,}\b")
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
        assert_eq!(fre.build_report().plan, expected_plan, "{pattern:?}");
        assert_eq!(fre.captures_len(), upstream.captures_len(), "{pattern:?}");
        assert_eq!(
            fre.static_captures_len(),
            upstream.static_captures_len(),
            "{pattern:?}"
        );
        assert_eq!(fre.build_report().captures_len, fre.captures_len());
        assert_eq!(
            fre.build_report().static_captures_len,
            fre.static_captures_len()
        );
    }
}

#[test]
fn capture_cardinality_matches_every_pinned_doctest_shape() {
    for pattern in ["foo", "(foo)", r"(?<a>.(?<b>.))(.)(?:.)(?<c>.)", r"[a&&b]"] {
        let fre = PortableBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::Regex::new(pattern)
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
        assert_eq!(fre.captures_len(), upstream.captures_len(), "{pattern:?}");
    }
}

#[test]
fn static_capture_cardinality_matches_every_pinned_doctest_shape() {
    for pattern in [
        "a",
        "(a)",
        "(a)|(b)",
        "(a)(b)|(c)(d)",
        "(a)|b",
        "a|(b)",
        "(b)*",
        "(b)+",
    ] {
        let fre = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
        assert_eq!(fre.captures_len(), upstream.captures_len(), "{pattern:?}");
        assert_eq!(
            fre.static_captures_len(),
            upstream.static_captures_len(),
            "{pattern:?}"
        );
    }
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

        let (actual, offset_accounting) = fre
            .find(haystack, fre::SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("FRE search failed for {name}: {error}"));
        let actual = actual.unwrap_or_else(|| panic!("FRE found no match for {name}"));
        let (borrowed, borrowed_accounting) = fre
            .find_borrowed(haystack, fre::SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("FRE borrowed search failed for {name}: {error}"));
        let borrowed =
            borrowed.unwrap_or_else(|| panic!("FRE borrowed search found no match for {name}"));
        let expected = upstream
            .find(haystack)
            .unwrap_or_else(|| panic!("pinned regex found no match for {name}"));

        assert_eq!(actual.start(), expected.start(), "{name}");
        assert_eq!(actual.end(), expected.end(), "{name}");
        assert_eq!(actual.is_empty(), expected.is_empty(), "{name}");
        assert_eq!(actual.len(), expected.len(), "{name}");
        assert_eq!(actual.range(), expected.range(), "{name}");
        assert_eq!(&haystack[actual.range()], expected.as_bytes(), "{name}");

        assert_eq!(borrowed.start(), expected.start(), "{name}");
        assert_eq!(borrowed.end(), expected.end(), "{name}");
        assert_eq!(borrowed.is_empty(), expected.is_empty(), "{name}");
        assert_eq!(borrowed.len(), expected.len(), "{name}");
        assert_eq!(borrowed.range(), expected.range(), "{name}");
        assert_eq!(borrowed.as_bytes(), expected.as_bytes(), "{name}");
        let borrowed_bytes: &[u8] = borrowed.into();
        let borrowed_range: core::ops::Range<usize> = borrowed.into();
        assert_eq!(borrowed_bytes, expected.as_bytes(), "{name}");
        assert_eq!(borrowed_range, expected.range(), "{name}");
        assert_eq!(borrowed_accounting, offset_accounting, "{name}");
    }
}

#[test]
fn borrowed_match_debug_matches_pinned_utf8_and_byte_escaping() {
    fn assert_debug(pattern: &str, unicode: bool, haystack: &[u8]) {
        let fre = PortableBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .unwrap_or_else(|error| panic!("failed to build {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));

        let (actual, _) = fre
            .find_borrowed(haystack, fre::SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("FRE search failed for {pattern:?}: {error}"));
        let actual = actual.unwrap_or_else(|| panic!("FRE found no match for {pattern:?}"));
        let expected = upstream
            .find(haystack)
            .unwrap_or_else(|| panic!("pinned regex found no match for {pattern:?}"));

        let pinned = format!("{expected:?}");
        let pinned_pretty = format!("{expected:#?}");
        assert_eq!(
            format!("{actual:?}"),
            format!(
                "ByteMatch{}",
                pinned
                    .strip_prefix("Match")
                    .expect("pinned byte match Debug prefix")
            ),
            "pattern={pattern:?}, haystack={haystack:?}"
        );
        assert_eq!(
            format!("{actual:#?}"),
            format!(
                "ByteMatch{}",
                pinned_pretty
                    .strip_prefix("Match")
                    .expect("pinned pretty byte match Debug prefix")
            ),
            "pretty pattern={pattern:?}, haystack={haystack:?}"
        );
    }

    assert_debug("Sherlock", false, b"prefix Sherlock suffix");
    assert_debug(
        r"\p{Greek}+",
        true,
        "Greek: \u{3b1}\u{3b2}\u{3b3}\u{3b4}".as_bytes(),
    );
    assert_debug("^", false, b"\xFF");

    let every_byte: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    assert_debug("(?s:.)+", false, &every_byte);

    let malformed_utf8: &[&[u8]] = &[
        b"\xC2",
        b"\xC2A",
        b"\xE2\x82",
        b"\xE2(\xA1",
        b"\xF0\x9F\x92",
        b"\xF0(\x8C\xBC",
        b"\xED\xA0\x80",
        b"\xC0\xAF",
    ];
    for haystack in malformed_utf8 {
        assert_debug("(?s:.)+", false, haystack);
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
#[allow(
    clippy::too_many_lines,
    reason = "the clone gate deliberately covers every stored portable plan variant"
)]
fn clone_matches_pinned_bytes_and_preserves_exact_plan_identity() {
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
            b"\xFFSherlock".as_slice(),
        ),
        (
            "packed literal set",
            PlanKind::PackedLiteralSet,
            PortableBuilder::new("a|ab").unicode(false).build(),
            regex::bytes::RegexBuilder::new("a|ab")
                .unicode(false)
                .build(),
            b"\xFFab".as_slice(),
        ),
        (
            "literal set DFA",
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
            "forced fixed end",
            PlanKind::ForwardAnchored,
            PortableBuilder::new(r"\A[a-z]+Z\z")
                .unicode(false)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build(),
            regex::bytes::RegexBuilder::new(r"\A[a-z]+Z\z")
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
            "automatic K0",
            PlanKind::K0,
            PortableBuilder::new("^a+$")
                .unicode(false)
                .multi_line(true)
                .line_terminator(b'\r')
                .build(),
            regex::bytes::RegexBuilder::new("^a+$")
                .unicode(false)
                .multi_line(true)
                .line_terminator(b'\r')
                .build(),
            b"x\raaa\r".as_slice(),
        ),
        (
            "forced K0",
            PlanKind::K0,
            PortableBuilder::new("Sherlock")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build(),
            regex::bytes::RegexBuilder::new("Sherlock")
                .unicode(false)
                .build(),
            b"\xFFSherlock".as_slice(),
        ),
    ];

    for (name, expected_plan, fre, upstream, haystack) in cases {
        let fre = fre.unwrap_or_else(|error| panic!("failed to build {name}: {error}"));
        let upstream =
            upstream.unwrap_or_else(|error| panic!("pinned regex rejected {name}: {error}"));
        assert_eq!(fre.build_report().plan, expected_plan, "{name}");

        let cloned = fre.clone();
        let upstream_cloned = upstream.clone();
        assert_eq!(cloned.as_str(), fre.as_str(), "{name}");
        assert_eq!(cloned.profile(), fre.profile(), "{name}");
        assert_eq!(cloned.build_report(), fre.build_report(), "{name}");
        assert_eq!(
            cloned.runtime_implementation_id(),
            fre.runtime_implementation_id(),
            "{name}"
        );
        assert_eq!(
            cloned.capture_names().collect::<Vec<_>>(),
            fre.capture_names().collect::<Vec<_>>(),
            "{name}"
        );

        for start in 0..=haystack.len() {
            let expected = upstream_cloned
                .find_at(haystack, start)
                .map(|matched| matched.range());
            for candidate in [&fre, &cloned] {
                let actual = candidate
                    .find_at(haystack, start, fre::SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!("FRE clone search failed for {name} at {start}: {error}")
                    })
                    .0
                    .map(fre::Match::range);
                assert_eq!(actual, expected, "{name} at {start}");
            }
        }
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
fn set_persistent_limit_charges_matcher_source_and_capture_name_identity() {
    let patterns = vec!["(?P<one>a)".to_owned(), "(?P<pair>bc)|de".to_owned()];
    let probe = PortableRegexSet::new(&patterns).expect("set source accounting probe");
    let report = probe.build_report();
    let expected_matcher_sources = patterns.iter().map(String::len).sum::<usize>();
    assert_eq!(report.matcher_source_bytes, expected_matcher_sources);
    let expected_capture_names = patterns
        .iter()
        .map(|pattern| {
            let regex = PortableRegex::new(pattern).expect("capture-name accounting probe");
            regex.build_report().capture_name_storage_bytes
        })
        .sum::<usize>();
    assert_eq!(report.capture_name_storage_bytes, expected_capture_names);
    assert_eq!(
        report.charged_persistent_bytes,
        report.source_capacity_bytes
            + report.regex_capacity_bytes
            + report.matcher_source_bytes
            + report.capture_name_storage_bytes
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
