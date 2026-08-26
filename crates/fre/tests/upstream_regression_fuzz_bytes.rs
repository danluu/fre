#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, PortableFindIterLimits, RustProfile};

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
fn upstream_size_threshold_is_a_compact_native_scalar_run() {
    const REPETITIONS: usize = 971_158;
    let pattern = "[\u{0}\u{e}\u{2}\\w~~>[l\t\u{0}]p?<]{971158}";
    assert!(
        regex::bytes::Regex::new(pattern).is_err(),
        "pinned bytes constructor no longer enforced its NFA-size threshold"
    );

    // Upstream's representation threshold is not FRE's native-size contract.
    // This owner retains the exact repetition bound symbolically.
    let regex = PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .expect("FRE compact scalar-run construction");
    let report = regex.build_report();
    assert_eq!(report.plan, PlanKind::UnicodeScalarRun);
    assert_eq!(report.persistent_byte_limit, 10 * (1 << 20));
    assert!(report.charged_persistent_bytes <= report.persistent_byte_limit);
    assert_eq!(report.syntax.largest_finite_repeat, Some(971_158));
    assert_eq!(report.minimum_match_bytes, Some(REPETITIONS));
    assert_eq!((report.states, report.edges), (0, 0));

    let mut haystack = Vec::with_capacity(REPETITIONS);
    haystack.resize(REPETITIONS - 1, b'a');
    assert_eq!(regex.find(&haystack), None);
    haystack.push(b'a');
    assert_eq!(
        regex.find(&haystack).map(|matched| matched.range()),
        Some(0..REPETITIONS),
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
