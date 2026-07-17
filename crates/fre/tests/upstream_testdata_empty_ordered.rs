#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableFindIterLimits, PortableTextRegex, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/empty.toml";
const UPSTREAM_SHA256: &str = "738dbe92fbd8971385a1cf3affb0e956e5b692c858b9b48439d718f10801c08e";
const QUALIFIED_IDS: &[&str] = &["600", "610"];

#[test]
fn authenticated_empty_first_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/empty.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(QUALIFIED_IDS, ["600", "610"]);
}

#[test]
fn empty_first_corpus_iterators_match_pinned_upstream() {
    for (id, pattern) in [("600", r"(?:|a)*"), ("610", r"(?:|a)+")] {
        let haystack = "aaa";
        let upstream = regex::Regex::new(pattern)
            .unwrap_or_else(|error| panic!("{id}: pinned upstream build: {error}"));
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(expected, vec![(0, 0), (1, 1), (2, 2), (3, 3)], "{id}");

        let fre = PortableTextRegex::new(pattern)
            .unwrap_or_else(|error| panic!("{id}: FRE text build: {error}"));
        assert_eq!(fre.build_report().portable.plan, PlanKind::K0, "{id}");
        assert_eq!(
            fre.build_report()
                .portable
                .lowering
                .expect("K0 lowering report")
                .normalized_nullable_repetitions(),
            1,
            "{id}"
        );
        assert_eq!(text_spans(&fre, haystack), expected, "{id}");

        let bytes = fre::PortableBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("{id}: FRE bytes build: {error}"));
        let actual = bytes
            .find_iter(haystack.as_bytes(), PortableFindIterLimits::unlimited())
            .expect("portable bytes iterator construction")
            .map(|result| result.map(|matched| (matched.start(), matched.end())))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("{id}: FRE bytes iteration: {error}"));
        assert_eq!(actual, expected, "{id}");
    }
}

fn text_spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
    regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .expect("qualified text iterator construction")
        .map(|matched| {
            let matched = matched.expect("qualified text iteration");
            (matched.start(), matched.end())
        })
        .collect()
}
