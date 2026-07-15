#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is over exhaustive test inputs of at most three bytes"
)]

use fre::{
    BuildError, PlanKind, PlanSelection, PortableBuilder, RustProfile, SearchLimits, SearchWindow,
};
use fre_lower::{LowerError, UnsupportedFeature};
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};
use regex_syntax::hir::Look;

const ASSERTION_CASES: [(Look, &str); 10] = [
    (Look::Start, r"\A"),
    (Look::End, r"\z"),
    (Look::StartLF, r"(?m:^)"),
    (Look::EndLF, r"(?m:$)"),
    (Look::WordAscii, r"\b"),
    (Look::WordAsciiNegate, r"\B"),
    (Look::WordStartAscii, r"\b{start}"),
    (Look::WordEndAscii, r"\b{end}"),
    (Look::WordStartHalfAscii, r"\b{start-half}"),
    (Look::WordEndHalfAscii, r"\b{end-half}"),
];

fn portable(pattern: &str, selection: PlanSelection) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(selection)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn pinned(pattern: &str) -> MetaRegex {
    pinned_with_unicode(pattern, false)
}

fn pinned_with_unicode(pattern: &str, unicode: bool) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(unicode))
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned oracle rejected {pattern:?}: {error}"))
}

fn independent_is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_digit() || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
}

fn independent_assertion(look: Look, haystack: &[u8], at: usize) -> bool {
    assert!(at <= haystack.len());
    let before = at.checked_sub(1).and_then(|index| haystack.get(index));
    let after = haystack.get(at);
    let word_before = before.is_some_and(|&byte| independent_is_ascii_word(byte));
    let word_after = after.is_some_and(|&byte| independent_is_ascii_word(byte));
    match look {
        Look::Start => at == 0,
        Look::End => at == haystack.len(),
        Look::StartLF => at == 0 || before.is_some_and(|&byte| byte == b'\n'),
        Look::EndLF => at == haystack.len() || after.is_some_and(|&byte| byte == b'\n'),
        Look::WordAscii => word_before != word_after,
        Look::WordAsciiNegate => word_before == word_after,
        Look::WordStartAscii => !word_before && word_after,
        Look::WordEndAscii => word_before && !word_after,
        Look::WordStartHalfAscii => !word_before,
        Look::WordEndHalfAscii => !word_after,
        unsupported => panic!("independent oracle received unsupported look {unsupported:?}"),
    }
}

fn byte_strings(max_len: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

#[test]
fn every_portable_assertion_matches_pinned_ranges_and_an_independent_oracle() {
    let mut haystacks = byte_strings(3, &[b'a', b'Z', b'9', b'_', b'-', b'\n', 0xFF]);
    haystacks.extend((u8::MIN..=u8::MAX).map(|byte| vec![byte]));
    haystacks.sort();
    haystacks.dedup();
    assert_eq!(haystacks.len(), 649);

    for (look, pattern) in ASSERTION_CASES {
        let fre = portable(pattern, PlanSelection::ForceK0);
        let upstream = pinned(pattern);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        assert_eq!(fre.build_report().lowering.unwrap().states(), 2);

        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let independent = (start..=end)
                        .find(|&at| independent_assertion(look, haystack, at))
                        .map(|at| (at, at));
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        expected, independent,
                        "pinned/independent {look:?}/{haystack:?}/{start}..{end}"
                    );

                    let (actual, accounting) = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("K0 search failed {look:?}/{haystack:?}/{start}..{end}: {error}")
                        });
                    assert_eq!(accounting.plan(), PlanKind::K0);
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        independent,
                        "portable/independent {look:?}/{haystack:?}/{start}..{end}"
                    );
                }
            }
        }
    }
}

#[test]
fn assertions_composed_with_consumption_match_pinned_ranged_search() {
    const PATTERNS: &[&str] = &[
        r"(?m:^)[A-Za-z_]+",
        r"[A-Za-z_]+(?m:$)",
        r"\b[0-9A-Za-z_]+\b",
        r"\B-\B",
        r"\b{start}[A-Za-z_]+",
        r"[A-Za-z_]+\b{end}",
        r"\b{start-half}.",
        r".\b{end-half}",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"-a-",
        b"aa",
        b"\na\n",
        b"x\na\nx",
        &[0xFF],
        &[b'a', 0xFF, b'-', b'_', b'\n'],
    ];

    for pattern in PATTERNS {
        let fre = portable(pattern, PlanSelection::ForceK0);
        let upstream = pinned(pattern);
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "portable search failed {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        })
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn generic_ascii_word_and_lf_line_shapes_route_without_approximation() {
    let cases: &[(&str, &[&[u8]])] = &[
        (
            r"\b[0-9A-Za-z_]{12,}\b",
            &[
                b"tiny words",
                b"a sufficiently_long_identifier here",
                b"joined_sufficiently_long_identifier_tail",
                &[b'-', 0xFF, b'a', b'b', b'c'],
            ],
        ),
        (
            r"(?m)^Sherlock Holmes$",
            &[
                b"Sherlock Holmes",
                b"prefix Sherlock Holmes suffix",
                b"prefix\nSherlock Holmes\nsuffix",
                b"Sherlock Holmes\r\n",
            ],
        ),
    ];

    for &(pattern, haystacks) in cases {
        let fre = portable(pattern, PlanSelection::Auto);
        let upstream = pinned(pattern);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        for &haystack in haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = fre
                .find(haystack, SearchLimits::unlimited())
                .unwrap_or_else(|error| panic!("portable search failed for {pattern:?}: {error}"));
            assert_eq!(accounting.plan(), PlanKind::K0);
            assert_eq!(
                actual.map(|matched| (matched.start(), matched.end())),
                expected,
                "{pattern:?}/{haystack:?}"
            );
        }
    }
}

#[test]
fn unicode_scalar_classes_match_pinned_ranges_without_consuming_invalid_utf8() {
    const RUFF: &str = r"^[ \t\f]*#.*?coding[:=][ \t]*utf-?8";
    let patterns = [".", "[α-ω]+", RUFF];
    let haystacks: &[&[u8]] = &[
        b"",
        "αβ x".as_bytes(),
        "😀".as_bytes(),
        &[0xFF, b'x'],
        &[0xCE],
        &[0xC0, 0x80],
        &[0xED, 0xA0, 0x80],
        b"# -*- coding: utf-8 -*-",
        b"x # coding: utf-8",
        &[
            b'#', b' ', 0xFF, b'c', b'o', b'd', b'i', b'n', b'g', b':', b' ', b'u', b't', b'f',
            b'-', b'8',
        ],
    ];

    for pattern in patterns {
        let fre = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("Unicode K0 build failed for {pattern:?}: {error}"));
        let upstream = pinned_with_unicode(pattern, true);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "Unicode K0 search failed {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        })
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn positive_unicode_word_boundary_matches_pinned_ranges_on_arbitrary_bytes() {
    const PATTERN: &str = r"\b(?-u:[A-Za-z]{2,})\b";
    let fre = PortableBuilder::new(PATTERN)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("positive Unicode boundary around a byte-stable body lowers");
    let upstream = pinned_with_unicode(PATTERN, true);
    let haystacks: &[&[u8]] = &[
        b"",
        b"-ab-",
        "☃ab☃".as_bytes(),
        "\u{11011}ab-".as_bytes(),
        "😀ab😀".as_bytes(),
        "βab-".as_bytes(),
        "-abβ".as_bytes(),
        &[0xFF, b'a', b'b', 0xFF],
        &[0xC0, 0x80, b'a', b'b'],
        &[b'a', b'b', 0xED, 0xA0, 0x80],
    ];

    assert_eq!(fre.build_report().plan, PlanKind::K0);
    for &haystack in haystacks {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = upstream
                    .find(Input::new(haystack).span(start..end))
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre
                    .find_window(
                        haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "Unicode boundary search failed {haystack:?}/{start}..{end}: {error}"
                        )
                    })
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(actual, expected, "{haystack:?}/{start}..{end}");
            }
        }
    }
}

#[test]
fn combined_unicode_word_boundary_and_scalar_class_match_pinned_ranges() {
    const PATTERN: &str = r"\b\w{25,}\b";
    let fre = PortableBuilder::new(PATTERN)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("positive Unicode boundaries compose with Unicode scalar classes");
    let upstream = pinned_with_unicode(PATTERN, true);
    let haystacks: &[&[u8]] = &[
        b"",
        b"short words",
        b" abcdefghijklmnopqrstuvwxyz ",
        " αβγδεζηθικλμνξοπρστυφχψωα ".as_bytes(),
        &[0xFF, b'a', b'b', b'c', 0xFF],
    ];

    assert_eq!(fre.build_report().plan, PlanKind::K0);
    for &haystack in haystacks {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = upstream
                    .find(Input::new(haystack).span(start..end))
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre
                    .find_window(
                        haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("combined Unicode search failed {haystack:?}/{start}..{end}: {error}")
                    })
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(actual, expected, "{haystack:?}/{start}..{end}");
            }
        }
    }
}

#[test]
fn crlf_and_uncertified_unicode_looks_remain_exact_typed_refusals() {
    let crlf = PortableBuilder::new(r"(?mR:$)")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect_err("CRLF-aware end assertion must remain unsupported");
    assert!(matches!(
        crlf,
        BuildError::Lower(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
            Look::EndCRLF
        )))
    ));

    let mut custom_line = RustProfile::regex_1_12_4();
    custom_line.options.line_terminator = b'\r';
    let custom = PortableBuilder::new(r"(?m:^a)")
        .profile(custom_line.clone())
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect_err("a non-LF line assertion must remain a typed refusal");
    assert!(matches!(
        custom,
        BuildError::UnsupportedLineTerminator {
            line_terminator: b'\r'
        }
    ));
    PortableBuilder::new("literal")
        .profile(custom_line)
        .unicode(false)
        .build()
        .expect("a custom terminator does not affect assertion-free literals");

    let local_ascii_pattern = r"(?-u:\b)a";
    let local_ascii = PortableBuilder::new(local_ascii_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("a locally ASCII assertion remains exact in a Unicode profile");
    let haystack: &[u8] = &[0xFF, b'a'];
    let expected = pinned_with_unicode(local_ascii_pattern, true)
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()));
    let actual = local_ascii
        .find(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(actual, expected);

    let unicode_negate = PortableBuilder::new(r"\B")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect_err("negated Unicode word boundary must remain unsupported");
    assert!(matches!(
        unicode_negate,
        BuildError::Lower(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
            Look::WordUnicodeNegate
        )))
    ));
}
