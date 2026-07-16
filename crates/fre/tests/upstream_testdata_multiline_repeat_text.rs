#![forbid(unsafe_code)]

use fre::{PlanKind, PortableTextRegex, RustProfile, SearchLimits, SearchWindow};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "testdata/multiline.toml";
const UPSTREAM_SHA256: &str = "eb07cf5427e6ddbcf61f4cc64c2d74ff41b5ef75ef857959651b20196f3cd157";
const QUALIFIED_IDS: &[&str] = &[
    "repeat2",
    "repeat2-crlf",
    "repeat2-crlf-cr",
    "repeat2-no-multi",
    "repeat2-no-multi-crlf",
    "repeat2-no-multi-crlf-cr",
    "repeat3",
    "repeat3-crlf",
    "repeat3-crlf-cr",
    "repeat3-no-multi",
    "repeat3-no-multi-crlf",
    "repeat3-no-multi-crlf-cr",
];

struct Case {
    id: &'static str,
    pattern: &'static str,
    haystack: &'static str,
    expected: &'static [(usize, usize)],
}

const PLUS_MULTILINE: &[(usize, usize)] = &[(0, 0), (2, 2), (3, 5), (6, 6)];
const PLUS_SINGLELINE: &[(usize, usize)] = &[(0, 0), (2, 5)];
const STAR_MULTILINE: &[(usize, usize)] = &[(0, 0), (1, 1), (2, 2), (3, 5), (6, 6)];
const STAR_SINGLELINE: &[(usize, usize)] = &[(0, 0), (1, 1), (2, 5), (6, 6)];

fn cases() -> [Case; 12] {
    [
        Case {
            id: "repeat2",
            pattern: r"(?m)(?:^|a)+",
            haystack: "a\naaa\n",
            expected: PLUS_MULTILINE,
        },
        Case {
            id: "repeat2-crlf",
            pattern: r"(?Rm)(?:^|a)+",
            haystack: "a\naaa\n",
            expected: PLUS_MULTILINE,
        },
        Case {
            id: "repeat2-crlf-cr",
            pattern: r"(?Rm)(?:^|a)+",
            haystack: "a\raaa\r",
            expected: PLUS_MULTILINE,
        },
        Case {
            id: "repeat2-no-multi",
            pattern: r"(?:^|a)+",
            haystack: "a\naaa\n",
            expected: PLUS_SINGLELINE,
        },
        Case {
            id: "repeat2-no-multi-crlf",
            pattern: r"(?R)(?:^|a)+",
            haystack: "a\naaa\n",
            expected: PLUS_SINGLELINE,
        },
        Case {
            id: "repeat2-no-multi-crlf-cr",
            pattern: r"(?R)(?:^|a)+",
            haystack: "a\raaa\r",
            expected: PLUS_SINGLELINE,
        },
        Case {
            id: "repeat3",
            pattern: r"(?m)(?:^|a)*",
            haystack: "a\naaa\n",
            expected: STAR_MULTILINE,
        },
        Case {
            id: "repeat3-crlf",
            pattern: r"(?Rm)(?:^|a)*",
            haystack: "a\naaa\n",
            expected: STAR_MULTILINE,
        },
        Case {
            id: "repeat3-crlf-cr",
            pattern: r"(?Rm)(?:^|a)*",
            haystack: "a\raaa\r",
            expected: STAR_MULTILINE,
        },
        Case {
            id: "repeat3-no-multi",
            pattern: r"(?:^|a)*",
            haystack: "a\naaa\n",
            expected: STAR_SINGLELINE,
        },
        Case {
            id: "repeat3-no-multi-crlf",
            pattern: r"(?R)(?:^|a)*",
            haystack: "a\naaa\n",
            expected: STAR_SINGLELINE,
        },
        Case {
            id: "repeat3-no-multi-crlf-cr",
            pattern: r"(?R)(?:^|a)*",
            haystack: "a\raaa\r",
            expected: STAR_SINGLELINE,
        },
    ]
}

fn fre_spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    let mut last_match_end = None;
    loop {
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new(start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .expect("qualified multiline text search executes");
        let Some(matched) = matched else {
            break;
        };
        if matched.is_empty() && last_match_end == Some(matched.end()) {
            let Some(character) = haystack[start..].chars().next() else {
                break;
            };
            start = start.saturating_add(character.len_utf8());
            continue;
        }
        spans.push((matched.start(), matched.end()));
        start = matched.end();
        last_match_end = Some(matched.end());
    }
    spans
}

#[test]
fn authenticated_multiline_repeat_partition_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "testdata/multiline.toml");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    let case_ids = cases().map(|case| case.id);
    assert_eq!(case_ids.as_slice(), QUALIFIED_IDS);
}

#[test]
fn multiline_repeat_text_cases_match_pinned_upstream_iteration() {
    for case in cases() {
        let upstream = regex::Regex::new(case.pattern)
            .unwrap_or_else(|error| panic!("{}: pinned upstream build: {error}", case.id));
        let expected = upstream
            .find_iter(case.haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(expected, case.expected, "{} upstream fixture", case.id);

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
        assert_eq!(fre_spans(&fre, case.haystack), expected, "{}", case.id);
    }
}
