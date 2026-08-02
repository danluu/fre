#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableTextBuilder, PortableTextProof, RustProfile, SearchLimits, SearchWindow,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/word-boundary-special.toml";
const UPSTREAM_SHA256: &str = "7d0ea2f796478d1ca2a6954430cb1cfbd04031a182f8611cb50a7c73e443ce33";

const CASES: &[(&str, &str, &str)] = &[
    ("word-start-half-ascii-010", r"\b{start-half}", "a"),
    ("word-start-half-ascii-020", r"\b{start-half}", "a "),
    ("word-start-half-ascii-030", r"\b{start-half}", " a "),
    ("word-start-half-ascii-040", r"\b{start-half}", ""),
    ("word-start-half-ascii-050", r"\b{start-half}", "ab"),
    ("word-start-half-ascii-060", r"\b{start-half}", "𝛃"),
    ("word-start-half-ascii-070", r"\b{start-half}", " 𝛃 "),
    ("word-start-half-ascii-080", r"\b{start-half}", "𝛃𐆀"),
    ("word-start-half-ascii-090", r"\b{start-half}", "𝛃b"),
    ("word-start-half-ascii-110", r"\b{start-half}", "b𝛃"),
    ("word-end-half-ascii-010", r"\b{end-half}", "a"),
    ("word-end-half-ascii-020", r"\b{end-half}", "a "),
    ("word-end-half-ascii-030", r"\b{end-half}", " a "),
    ("word-end-half-ascii-040", r"\b{end-half}", ""),
    ("word-end-half-ascii-050", r"\b{end-half}", "ab"),
    ("word-end-half-ascii-060", r"\b{end-half}", "𝛃"),
    ("word-end-half-ascii-070", r"\b{end-half}", " 𝛃 "),
    ("word-end-half-ascii-080", r"\b{end-half}", "𝛃𐆀"),
    ("word-end-half-ascii-090", r"\b{end-half}", "𝛃b"),
    ("word-end-half-ascii-110", r"\b{end-half}", "b𝛃"),
];

#[test]
fn authenticated_ascii_half_word_text_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/word-boundary-special.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(CASES.len(), 20);
    for (index, (id, _, _)) in CASES.iter().enumerate() {
        let direction = if index < 10 { "start" } else { "end" };
        assert!(id.starts_with(&format!("word-{direction}-half-ascii-")));
        assert!(!id.ends_with("-noutf8"));
        assert!(!id.ends_with("-bounds"));
    }
}

#[test]
fn ascii_half_word_text_cases_match_pinned_upstream_iteration() {
    for &(id, pattern, haystack) in CASES {
        let mut upstream = regex::RegexBuilder::new(pattern);
        upstream.unicode(false);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("{id}: pinned upstream build: {error}"));
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();

        let fre = PortableTextBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("{id}: FRE build: {error}"));
        assert!(matches!(
            fre.build_report().proof,
            PortableTextProof::Utf8StartBoundaryGuardedHir { .. }
        ));
        assert_eq!(fre.build_report().portable.plan, PlanKind::K0);
        assert!(
            fre.build_report()
                .portable
                .lowering
                .expect("guarded text K0 lowering")
                .utf8_start_guarded()
        );

        let mut actual = Vec::new();
        let mut start = 0_usize;
        let mut last_match_end = None;
        loop {
            let (windowed, windowed_accounting) = fre
                .find_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .unwrap_or_else(|error| panic!("{id}: FRE search: {error}"));
            let (matched, ranged_accounting) = fre
                .find_at(haystack, start, SearchLimits::unlimited())
                .unwrap_or_else(|error| panic!("{id}: FRE ranged search: {error}"));
            assert_eq!(matched, windowed, "{id}: ranged/windowed span");
            let (repeated_windowed, repeated_windowed_accounting) = fre
                .find_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .unwrap_or_else(|error| panic!("{id}: repeated FRE search: {error}"));
            assert_eq!(repeated_windowed, windowed, "{id}: repeated windowed span");
            // The first windowed call retains cold semantic coverage. Compare
            // accounting only between calls made after optional K0 plan-side
            // specialization has been published.
            assert_eq!(
                ranged_accounting, repeated_windowed_accounting,
                "{id}: ranged/windowed accounting"
            );
            assert_eq!(windowed_accounting.plan(), ranged_accounting.plan());
            let Some(matched) = matched else {
                break;
            };
            assert!(haystack.is_char_boundary(matched.start()), "{id}");
            assert!(haystack.is_char_boundary(matched.end()), "{id}");
            if matched.is_empty() && last_match_end == Some(matched.end()) {
                let Some(character) = haystack[start..].chars().next() else {
                    break;
                };
                start = start.saturating_add(character.len_utf8());
                continue;
            }
            actual.push((matched.start(), matched.end()));
            start = matched.end();
            last_match_end = Some(matched.end());
        }
        assert_eq!(actual, expected, "{id}");
    }
}
