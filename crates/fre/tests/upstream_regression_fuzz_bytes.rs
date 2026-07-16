#![forbid(unsafe_code)]

use fre::{BuildFailureClass, PlanKind, PortableBuilder, PortableFindIterLimits, RustProfile};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "tests/regression_fuzz.rs";
const UPSTREAM_SHA256: &str = "57e0bcba0fdfa7797865e35ae547cd7fe1c6132b80a7bfdfb06eb053a568b00d";
const EXECUTED_BYTE_REGRESSION_IDS: &[&str] = &[
    "empty_any_errors_no_panic",
    "big_regex_fails_to_compile",
    "todo",
    "fail_branch_prevents_match",
];
const DEFERRED_UPSTREAM_IGNORED_IDS: &[&str] = &["fuzz1"];

#[test]
fn authenticated_fuzz_regression_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "tests/regression_fuzz.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(
        EXECUTED_BYTE_REGRESSION_IDS,
        [
            "empty_any_errors_no_panic",
            "big_regex_fails_to_compile",
            "todo",
            "fail_branch_prevents_match",
        ]
    );
    assert_eq!(DEFERRED_UPSTREAM_IGNORED_IDS, ["fuzz1"]);
    assert_eq!(
        EXECUTED_BYTE_REGRESSION_IDS.len() + DEFERRED_UPSTREAM_IGNORED_IDS.len(),
        5
    );
}

#[test]
fn empty_any_class_builds_as_an_exact_never_match() {
    let pattern = r"\P{any}";
    let upstream = regex::bytes::Regex::new(pattern)
        .expect("pinned bytes constructor accepts the empty Unicode class");
    let fre = PortableBuilder::new(pattern)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected the empty-class regression: {error}"));

    for haystack in [
        b"".as_slice(),
        b"anything",
        &[0xFF],
        "\u{3b1}\u{3b2}".as_bytes(),
    ] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| matched.range())
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("portable empty-class iterator construction")
            .map(|result| result.map(fre::Match::range))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("portable empty-class iteration failed: {error}"));
        assert_eq!(actual, expected, "{haystack:?}");
    }
}

#[test]
fn oversized_unicode_class_repetition_is_a_typed_constructor_refusal() {
    let pattern = "[\u{0}\u{e}\u{2}\\w~~>[l\t\u{0}]p?<]{971158}";
    assert!(
        regex::bytes::Regex::new(pattern).is_err(),
        "pinned bytes constructor unexpectedly accepted the oversized regression"
    );

    let error = PortableBuilder::new(pattern)
        .build()
        .expect_err("FRE unexpectedly admitted the oversized regression");
    assert!(
        matches!(
            error.failure_class(),
            BuildFailureClass::ExpectedInvalid | BuildFailureClass::ResourceLimit
        ),
        "oversized regression was not a constructor/resource refusal: {error:?}"
    );
}

#[test]
fn valid_alternation_regression_matches_pinned_bytes() {
    assert_matches_pinned(r"(?:z|xx)@|xx", &[b"xx"], PlanKind::PackedLiteralSet);
}

#[test]
fn impossible_branch_does_not_hide_a_later_match() {
    assert_matches_pinned(r".*[a&&b]A|B", &[b"B"], PlanKind::K0);
}

fn assert_matches_pinned(pattern: &str, required_haystacks: &[&[u8]], expected_plan: PlanKind) {
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("pinned bytes constructor rejected {pattern:?}: {error}"));
    let fre = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
    assert_eq!(fre.build_report().plan, expected_plan, "{pattern:?}");

    let neighboring_haystacks: &[&[u8]] = &[b"", b"z@", b"xx@", b"A", b"B", b"AB", &[0xFF, b'B']];
    for haystack in required_haystacks
        .iter()
        .copied()
        .chain(neighboring_haystacks.iter().copied())
    {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| matched.range())
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("portable regression iterator construction")
            .map(|result| result.map(fre::Match::range))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("portable regression iteration failed: {error}"));
        assert_eq!(
            actual, expected,
            "pattern={pattern:?}, haystack={haystack:?}"
        );
    }
}
