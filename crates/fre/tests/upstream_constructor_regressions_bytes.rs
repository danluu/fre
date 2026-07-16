#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildFailureClass, BuildLimits, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterLimits, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "tests/regression.rs";
const UPSTREAM_SHA256: &str = "3490aac99fdbf3f0949ba1f338d5184a84b505ebd96d0b6d6145c610587aa60b";
const PORTED_BYTE_REGRESSION_IDS: &[&str] = &[
    "invalid_regexes_no_crash",
    "regression_many_repeat_stack_overflow",
    "regression_invalid_repetition_expr",
    "regression_invalid_flags_expression",
    "regression_nfa_stops1",
    "regression_big_regex_overflow",
    "regression_complete_literals_suffix_incorrect",
];
const DEFERRED_TEXT_CAPTURE_IDS: &[&str] = &[
    "regression_captures_rep",
    "regression_bad_word_boundary",
    "regression_unicode_perl_not_enabled",
];

#[test]
fn authenticated_constructor_regression_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "tests/regression.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(
        PORTED_BYTE_REGRESSION_IDS,
        [
            "invalid_regexes_no_crash",
            "regression_many_repeat_stack_overflow",
            "regression_invalid_repetition_expr",
            "regression_invalid_flags_expression",
            "regression_nfa_stops1",
            "regression_big_regex_overflow",
            "regression_complete_literals_suffix_incorrect",
        ]
    );
    assert_eq!(
        DEFERRED_TEXT_CAPTURE_IDS,
        [
            "regression_captures_rep",
            "regression_bad_word_boundary",
            "regression_unicode_perl_not_enabled",
        ]
    );
    assert_eq!(
        PORTED_BYTE_REGRESSION_IDS.len() + DEFERRED_TEXT_CAPTURE_IDS.len(),
        10
    );
}

#[test]
fn large_counted_repetition_builds_and_matches_without_stack_growth() {
    let pattern = "^.{1,2500}";
    let upstream = regex::bytes::Regex::new(pattern).expect("pinned large-repetition regression");
    let fre = PortableBuilder::new(pattern)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected large-repetition regression: {error}"));
    assert_eq!(fre.build_report().plan, PlanKind::K0);

    let long = vec![b'a'; 2501];
    for haystack in [b"".as_slice(), b"a", long.as_slice()] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| matched.range())
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("portable iterator construction")
            .map(|result| result.map(fre::Match::range))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("portable large-repetition iteration failed: {error}"));
        assert_eq!(actual, expected, "haystack length {}", haystack.len());
    }
}

#[test]
fn invalid_constructor_regressions_have_a_stable_expected_invalid_class() {
    for pattern in ["(*)", "(?:?)", "(?)", "*", "(?m){1,1}"] {
        assert!(
            regex::bytes::Regex::new(pattern).is_err(),
            "pinned bytes constructor unexpectedly accepted {pattern:?}"
        );
        let error = PortableBuilder::new(pattern)
            .build()
            .expect_err("FRE unexpectedly accepted invalid regression pattern");
        assert_eq!(
            error.failure_class(),
            BuildFailureClass::ExpectedInvalid,
            "{pattern:?}: {error}"
        );
    }
}

#[test]
fn valid_flags_and_large_repetition_regressions_never_become_internal_failures() {
    let valid = "(((?x)))";
    assert!(regex::bytes::Regex::new(valid).is_ok());
    PortableBuilder::new(valid)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected valid flag expression: {error}"));

    let too_large = r" {2147483516}{2147483416}{5}";
    assert!(regex::bytes::Regex::new(too_large).is_err());
    let error = PortableBuilder::new(too_large)
        .build()
        .expect_err("FRE accepted oversized repetition regression");
    assert!(
        matches!(
            error.failure_class(),
            BuildFailureClass::ExpectedInvalid | BuildFailureClass::ResourceLimit
        ),
        "oversized repetition was misclassified: {error:?}"
    );
}

#[test]
fn failure_classifier_separates_capability_limit_configuration_and_fault() {
    let unsupported = PortableBuilder::new("a")
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect_err("forced shape mismatch unexpectedly built");
    assert_eq!(unsupported.failure_class(), BuildFailureClass::Unsupported);

    let limited = PortableBuilder::new("a")
        .limits(BuildLimits {
            max_persistent_bytes: 0,
            ..BuildLimits::default()
        })
        .build()
        .expect_err("zero persistent-byte limit unexpectedly built");
    assert_eq!(limited.failure_class(), BuildFailureClass::ResourceLimit);

    let mut profile = RustProfile::regex_1_12_4();
    let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } = &mut profile.constructor
    else {
        panic!("pinned high-level profile lost its RegexBuilder constructor");
    };
    *size_limit = 1;
    let invalid_configuration = PortableBuilder::new("a")
        .profile(profile)
        .build()
        .expect_err("invalid constructor profile unexpectedly built");
    assert_eq!(
        invalid_configuration.failure_class(),
        BuildFailureClass::InvalidConfiguration
    );

    assert_eq!(
        BuildError::InternalInvariant("classification fixture").failure_class(),
        BuildFailureClass::InternalFailure
    );
}

#[test]
fn invalid_byte_word_boundary_regression_matches_pinned_bytes() {
    let pattern = r"\bs(?:[ab])";
    let haystacks: &[&[u8]] = &[b"s\xE4", b"sa", b" sb", b"xsab", &[0xFF, b's', b'b']];
    let upstream = regex::bytes::Regex::new(pattern).expect("pinned word-boundary regression");
    let fre = PortableBuilder::new(pattern)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected word-boundary regression: {error}"));

    for haystack in haystacks {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| matched.range())
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("portable iterator construction")
            .map(|result| result.map(fre::Match::range))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("portable iteration failed: {error}"));
        assert_eq!(actual, expected, "{haystack:?}");
    }
}

#[test]
fn complete_literal_suffix_regression_matches_pinned_bytes() {
    let pattern = (b'a'..=b'z')
        .map(|byte| format!("{}A", char::from(byte)))
        .collect::<Vec<_>>()
        .join("|");
    let upstream = regex::bytes::Regex::new(&pattern).expect("pinned literal regression");
    let fre = PortableBuilder::new(&pattern)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected literal regression: {error}"));

    for haystack in [b"FUBAR".as_slice(), b"zA", b"--aA--zA", &[0xFF, b'a', b'A']] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| matched.range())
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("portable iterator construction")
            .map(|result| result.map(fre::Match::range))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("portable iteration failed: {error}"));
        assert_eq!(actual, expected, "{haystack:?}");
    }
}
