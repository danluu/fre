#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, PortableFindIterLimits, RustProfile, SearchLimits};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/regression.toml";
const UPSTREAM_SHA256: &str = "6006ef4fcfbfd7155ce5ce8b8427904f7261c5549396f20cb065c0294733686d";
const QUALIFIED_IDS: &[&str] = &["i429-0", "i429-2", "i429-3", "i429-8", "i429-12"];

struct Case<'a> {
    id: &'static str,
    pattern: &'static str,
    haystack: &'a [u8],
    expected: &'static [(usize, usize)],
}

#[test]
fn authenticated_issue_429_nullable_repeat_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/regression.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(
        QUALIFIED_IDS,
        ["i429-0", "i429-2", "i429-3", "i429-8", "i429-12"]
    );
    assert_eq!(QUALIFIED_IDS.len(), 5);
}

#[test]
fn qualified_issue_429_byte_adapter_matches_pinned_upstream() {
    let scalar = "\u{fef80}";
    let cases = [
        Case {
            id: "i429-0",
            pattern: r"(?:(?-u:\b)|(?u:h))+",
            haystack: b"h",
            expected: &[(0, 0), (1, 1)],
        },
        Case {
            id: "i429-2",
            pattern: r"(?:(?u:\b)|(?s-u:.))+",
            haystack: b"oB",
            expected: &[(0, 0), (1, 2)],
        },
        Case {
            id: "i429-3",
            pattern: r"(?:(?-u:\B)|(?su:.))+",
            haystack: scalar.as_bytes(),
            expected: &[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)],
        },
        Case {
            id: "i429-8",
            pattern: r"(?:(?-u:\b)|(?u:[\u{0}-W]))+",
            haystack: b"0",
            expected: &[(0, 0), (1, 1)],
        },
        Case {
            id: "i429-12",
            pattern: r"(?:(?u:\b)|(?-u:.))+",
            haystack: b"0",
            expected: &[(0, 0), (1, 1)],
        },
    ];

    for case in cases {
        let mut upstream = regex::bytes::RegexBuilder::new(case.pattern);
        upstream.unicode(true);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("{}: pinned upstream build: {error}", case.id));
        let expected = upstream
            .find_iter(case.haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(expected, case.expected, "{} upstream fixture", case.id);

        let fre = PortableBuilder::new(case.pattern)
            .unicode(true)
            .build()
            .unwrap_or_else(|error| panic!("{}: FRE build: {error}", case.id));
        assert_eq!(fre.build_report().plan, PlanKind::K0, "{}", case.id);
        assert_eq!(
            fre.build_report()
                .lowering
                .expect("K0 lowering report")
                .normalized_nullable_repetitions(),
            1,
            "{}",
            case.id
        );
        let expected_is_match = upstream.is_match(case.haystack);
        assert!(expected_is_match, "{} upstream is-match fixture", case.id);
        let (actual_is_match, accounting) = fre
            .is_match(case.haystack, SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("{}: FRE is-match: {error}", case.id));
        assert_eq!(accounting.plan(), PlanKind::K0, "{}", case.id);
        assert_eq!(actual_is_match, expected_is_match, "{} is-match", case.id);
        let actual = fre
            .find_iter(case.haystack, PortableFindIterLimits::unlimited())
            .unwrap_or_else(|error| panic!("{}: FRE iterator construction: {error}", case.id))
            .map(|result| result.map(|matched| (matched.start(), matched.end())))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("{}: FRE iterator: {error}", case.id));
        assert_eq!(actual, expected, "{}", case.id);
    }
}
