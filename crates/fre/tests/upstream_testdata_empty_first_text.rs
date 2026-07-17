#![forbid(unsafe_code)]

use fre::{PlanKind, PortableFindIterLimits, PortableTextRegex, RustProfile};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/empty.toml";
const UPSTREAM_SHA256: &str = "738dbe92fbd8971385a1cf3affb0e956e5b692c858b9b48439d718f10801c08e";
const QUALIFIED_IDS: &[&str] = &["600", "610"];
const EXPECTED: &[(usize, usize)] = &[(0, 0), (1, 1), (2, 2), (3, 3)];

struct Case {
    id: &'static str,
    pattern: &'static str,
}

const CASES: &[Case] = &[
    Case {
        id: "600",
        pattern: r"(?:|a)*",
    },
    Case {
        id: "610",
        pattern: r"(?:|a)+",
    },
];

fn fre_spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
    regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .expect("qualified text iterator construction")
        .map(|matched| {
            let matched = matched.expect("qualified text iteration");
            (matched.start(), matched.end())
        })
        .collect()
}

#[test]
fn authenticated_empty_first_repeat_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/empty.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    let case_ids = CASES.iter().map(|case| case.id).collect::<Vec<_>>();
    assert_eq!(case_ids, QUALIFIED_IDS);
}

#[test]
fn empty_first_repeat_text_cases_match_pinned_upstream_iteration() {
    for case in CASES {
        let upstream = regex::Regex::new(case.pattern)
            .unwrap_or_else(|error| panic!("{}: pinned upstream build: {error}", case.id));
        let expected = upstream
            .find_iter("aaa")
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(expected, EXPECTED, "{} upstream fixture", case.id);

        let fre = PortableTextRegex::new(case.pattern)
            .unwrap_or_else(|error| panic!("{}: FRE text build: {error}", case.id));
        assert_eq!(
            fre.build_report().portable.plan,
            PlanKind::K0,
            "{}",
            case.id
        );
        assert_eq!(
            fre.build_report()
                .portable
                .lowering
                .expect("K0 lowering report")
                .normalized_nullable_repetitions(),
            1,
            "{}",
            case.id
        );
        assert_eq!(fre_spans(&fre, "aaa"), expected, "{}", case.id);
    }
}
