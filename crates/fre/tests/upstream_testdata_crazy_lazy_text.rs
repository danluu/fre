#![forbid(unsafe_code)]

use fre::{PlanKind, PortableTextRegex, RustProfile, SearchLimits, SearchWindow};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/crazy.toml";
const UPSTREAM_SHA256: &str = "a146e2d2e23f1a57168979d9b1fc193c2ba38dca66294b61140d6d2a2958ec86";

const CASES: &[(&str, &str)] = &[
    ("lazy-many-many", r"(?:(?:.*)*?)="),
    ("lazy-one-many-many", r"(?:(?:.*)+?)="),
    ("lazy-one-many-optional", r"(?:(?:.?)+?)="),
    ("lazy-range-min-many", r"(?:(?:.*){1,}?)="),
];

fn fre_spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0_usize;
    while start <= haystack.len() {
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new(start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .expect("qualified nested-lazy text search executes");
        let Some(matched) = matched else {
            break;
        };
        assert!(!matched.is_empty());
        spans.push((matched.start(), matched.end()));
        start = matched.end();
    }
    spans
}

#[test]
fn authenticated_nested_lazy_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/crazy.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(CASES.len(), 4);
}

#[test]
fn nested_lazy_text_cases_match_pinned_upstream_iteration() {
    for &(id, pattern) in CASES {
        let upstream = regex::Regex::new(pattern)
            .unwrap_or_else(|error| panic!("{id}: pinned upstream build: {error}"));
        assert_eq!(
            upstream
                .find("a=b")
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 2)),
            "{id}: authenticated fixture"
        );
        let fre = PortableTextRegex::new(pattern)
            .unwrap_or_else(|error| panic!("{id}: FRE build: {error}"));
        assert_eq!(fre.build_report().portable.plan, PlanKind::K0, "{id}");
        assert_eq!(
            fre.build_report()
                .portable
                .lowering
                .expect("nested-lazy K0 lowering")
                .normalized_nullable_repetitions(),
            1,
            "{id}"
        );

        for haystack in ["", "a=b", "a=b=c", "=b=c", "abc=", "none", "東京=雪="] {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            assert_eq!(fre_spans(&fre, haystack), expected, "{id}: {haystack:?}");
        }
    }
}
