use fre::{PortableBuilder, PortableFindIterRunLimits, RustProfile, SearchSessionLimits};
use regex::bytes::RegexBuilder;

struct Case {
    pattern: &'static str,
    unicode: bool,
    case_insensitive: bool,
}

const CASES: &[Case] = &[
    Case {
        pattern: ".*.*=.*",
        unicode: false,
        case_insensitive: false,
    },
    Case {
        pattern: r"(?s)^((.*)()()($))",
        unicode: true,
        case_insensitive: false,
    },
    Case {
        pattern: r"(?:# [Nn][Oo][Qq][Aa])(?::\s?(([A-Z]+[0-9]+(?:[,\s]+)?)+))?",
        unicode: false,
        case_insensitive: false,
    },
    Case {
        pattern: r"^(?P<spaces>\s*)#!(?P<directive>.*)",
        unicode: true,
        case_insensitive: false,
    },
    Case {
        pattern: r"foo[0-9]{1,4}bar",
        unicode: false,
        case_insensitive: true,
    },
];

const HAYSTACKS: &[&[u8]] = &[
    b"",
    b"foo12bar\n# noqa: A1, B2\n#!/usr/bin/env sh\nleft=right",
    b"\xff=\0\nNO MATCH\nfoo99999bar",
];

fn build(case: &Case, pattern: impl Into<String>) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(case.unicode)
        .case_insensitive(case.case_insensitive)
        .build()
        .unwrap()
}

fn spans(regex: &fre::PortableRegex, haystack: &[u8]) -> Vec<(usize, usize)> {
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    session
        .find_iter_value(haystack, PortableFindIterRunLimits::unlimited())
        .map(|result| {
            let matched = result.unwrap();
            (matched.start(), matched.end())
        })
        .collect()
}

fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("hir-equivalent-plan-invariance".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn noncapturing_source_wrappers_cannot_change_selected_plan_family() {
    with_large_stack(|| {
        for case in CASES {
            let wrapped = format!("(?:(?:{}))", case.pattern);
            let original = build(case, case.pattern);
            let equivalent = build(case, wrapped.clone());

            assert_eq!(
                original.build_report().plan,
                equivalent.build_report().plan,
                "raw spelling changed plan kind for {:?}",
                case.pattern,
            );
            assert_eq!(
                original.runtime_implementation_id(),
                equivalent.runtime_implementation_id(),
                "raw spelling changed runtime for {:?}",
                case.pattern,
            );
            assert_eq!(
                original.span_visit_runtime_implementation_id(),
                equivalent.span_visit_runtime_implementation_id(),
                "raw spelling changed complete-span route for {:?}",
                case.pattern,
            );

            let oracle = RegexBuilder::new(case.pattern)
                .unicode(case.unicode)
                .case_insensitive(case.case_insensitive)
                .build()
                .unwrap();
            for &haystack in HAYSTACKS {
                let expected: Vec<_> = oracle
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect();
                assert_eq!(expected, spans(&original, haystack), "{:?}", case.pattern);
                assert_eq!(expected, spans(&equivalent, haystack), "{wrapped:?}");
            }
        }
    });
}
