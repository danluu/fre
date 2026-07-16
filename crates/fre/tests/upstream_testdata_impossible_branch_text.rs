#![forbid(unsafe_code)]

use fre::{PortableTextProof, PortableTextRegex, RustProfile, SearchLimits, SearchWindow};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/regression.toml";
const UPSTREAM_SHA256: &str = "6006ef4fcfbfd7155ce5ce8b8427904f7261c5549396f20cb065c0294733686d";
const CASE_ID: &str = "impossible-branch";
const PATTERN: &str = r".*[^\s\S]A|B";

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
            .expect("qualified impossible-branch text search executes");
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
fn authenticated_impossible_branch_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/regression.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(CASE_ID, "impossible-branch");
}

#[test]
fn impossible_branch_text_case_matches_pinned_upstream_iteration() {
    let upstream = regex::Regex::new(PATTERN).expect("pinned upstream accepts fixture");
    let fre = PortableTextRegex::new(PATTERN).expect("FRE proves impossible branch equivalence");
    assert!(matches!(
        fre.build_report().proof,
        PortableTextProof::ImpossibleAlternativesElidedUtf8Hir {
            minimum_match_bytes: 1,
            elided_alternatives: 1,
        }
    ));

    for haystack in ["", "B", "A B", "βB東京B", "no match", "B\nB"] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(fre_spans(&fre, haystack), expected, "haystack={haystack:?}");
    }
}
