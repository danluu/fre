use fre::{
    AggregateBuilder, AggregateOperation, LiteralReplacementErrorSource, LiteralReplacementLimits,
    RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "tests/replace.rs";
const UPSTREAM_SHA256: &str = "78ff9bf7f78783ad83a78041bb7ee0705c7efc85b4d12301581d0ce5b2a59325";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Capability {
    LiteralNoExpand,
    CaptureExpansion,
    FunctionalReplacer,
    ReplacerTypeSurface,
}

impl Capability {
    const fn id(self) -> &'static str {
        match self {
            Self::LiteralNoExpand => "replacement.literal-no-expand",
            Self::CaptureExpansion => "replacement.capture-expansion",
            Self::FunctionalReplacer => "replacement.functional-replacer",
            Self::ReplacerTypeSurface => "replacement.replacer-type-surface",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct InventoryCase {
    id: &'static str,
    capability: Capability,
}

const INVENTORY: &[InventoryCase] = &[
    InventoryCase {
        id: "first",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "plus",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "all",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "groups",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "double_dollar",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "named",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "trim",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "number_hyphen",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "simple_expand",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "literal_dollar1",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "literal_dollar2",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "no_expand1",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "no_expand2",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "closure_returning_reference",
        capability: Capability::FunctionalReplacer,
    },
    InventoryCase {
        id: "closure_returning_value",
        capability: Capability::FunctionalReplacer,
    },
    InventoryCase {
        id: "match_at_start_replace_with_empty",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "single_empty_match",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "capture_longest_possible_name",
        capability: Capability::CaptureExpansion,
    },
    InventoryCase {
        id: "impl_string",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "impl_string_ref",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "impl_cow_str_borrowed",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "impl_cow_str_borrowed_ref",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "impl_cow_str_owned",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "impl_cow_str_owned_ref",
        capability: Capability::ReplacerTypeSurface,
    },
    InventoryCase {
        id: "replacen_no_captures",
        capability: Capability::LiteralNoExpand,
    },
    InventoryCase {
        id: "replacen_with_captures",
        capability: Capability::CaptureExpansion,
    },
];

#[derive(Clone, Copy, Debug)]
enum ReplaceMode {
    First,
    All,
    N(usize),
}

#[derive(Clone, Copy, Debug)]
struct SupportedCase {
    id: &'static str,
    pattern: &'static str,
    haystack: &'static [u8],
    replacement: &'static [u8],
    mode: ReplaceMode,
    expected: &'static [u8],
    replacements: usize,
}

const SUPPORTED_CASES: &[SupportedCase] = &[
    SupportedCase {
        id: "first",
        pattern: r"[0-9]",
        haystack: b"age: 26",
        replacement: b"Z",
        mode: ReplaceMode::First,
        expected: b"age: Z6",
        replacements: 1,
    },
    SupportedCase {
        id: "plus",
        pattern: r"[0-9]+",
        haystack: b"age: 26",
        replacement: b"Z",
        mode: ReplaceMode::First,
        expected: b"age: Z",
        replacements: 1,
    },
    SupportedCase {
        id: "all",
        pattern: r"[0-9]",
        haystack: b"age: 26",
        replacement: b"Z",
        mode: ReplaceMode::All,
        expected: b"age: ZZ",
        replacements: 2,
    },
    SupportedCase {
        id: "trim",
        pattern: "^[ \t]+|[ \t]+$",
        haystack: b" \t  trim me\t   \t",
        replacement: b"",
        mode: ReplaceMode::All,
        expected: b"trim me",
        replacements: 2,
    },
    SupportedCase {
        id: "no_expand1",
        pattern: r"([^ ]+)[ ]+([^ ]+)",
        haystack: b"w1 w2",
        replacement: b"$2 $1",
        mode: ReplaceMode::First,
        expected: b"$2 $1",
        replacements: 1,
    },
    SupportedCase {
        id: "no_expand2",
        pattern: r"([^ ]+)[ ]+([^ ]+)",
        haystack: b"w1 w2",
        replacement: b"$$1",
        mode: ReplaceMode::First,
        expected: b"$$1",
        replacements: 1,
    },
    SupportedCase {
        id: "match_at_start_replace_with_empty",
        pattern: r"foo",
        haystack: b"foobar",
        replacement: b"",
        mode: ReplaceMode::All,
        expected: b"bar",
        replacements: 1,
    },
    SupportedCase {
        id: "single_empty_match",
        pattern: r"^",
        haystack: b"bar",
        replacement: b"foo",
        mode: ReplaceMode::First,
        expected: b"foobar",
        replacements: 1,
    },
    SupportedCase {
        id: "replacen_no_captures",
        pattern: r"[0-9]",
        haystack: b"age: 1234",
        replacement: b"Z",
        mode: ReplaceMode::N(2),
        expected: b"age: ZZ34",
        replacements: 2,
    },
];

const PORTED_TYPE_SURFACE_IDS: &[&str] = &[
    "impl_string",
    "impl_string_ref",
    "impl_cow_str_borrowed",
    "impl_cow_str_borrowed_ref",
    "impl_cow_str_owned",
    "impl_cow_str_owned_ref",
];

#[test]
fn authenticated_upstream_replacement_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "tests/replace.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(INVENTORY.len(), 26);

    let mut ids: Vec<_> = INVENTORY.iter().map(|case| case.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), INVENTORY.len(), "duplicate upstream case ID");

    let supported: Vec<_> = INVENTORY
        .iter()
        .filter(|case| case.capability == Capability::LiteralNoExpand)
        .map(|case| case.id)
        .collect();
    let ported: Vec<_> = SUPPORTED_CASES.iter().map(|case| case.id).collect();
    assert_eq!(ported, supported);
    assert_eq!(supported.len(), 9);
    let type_surface: Vec<_> = INVENTORY
        .iter()
        .filter(|case| case.capability == Capability::ReplacerTypeSurface)
        .map(|case| case.id)
        .collect();
    assert_eq!(type_surface, PORTED_TYPE_SURFACE_IDS);
    assert_eq!(
        INVENTORY
            .iter()
            .filter(|case| case.capability == Capability::CaptureExpansion)
            .count(),
        9
    );
    assert_eq!(
        INVENTORY
            .iter()
            .filter(|case| case.capability == Capability::FunctionalReplacer)
            .count(),
        2
    );
    assert_eq!(
        INVENTORY
            .iter()
            .filter(|case| case.capability == Capability::ReplacerTypeSurface)
            .count(),
        6
    );
    for case in INVENTORY {
        assert!(case.capability.id().starts_with("replacement."));
    }
}

#[test]
fn ported_upstream_replacer_type_surface_cases_pass() {
    use std::borrow::Cow;

    let regex = AggregateBuilder::new(r"[0-9]")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("upstream replacer type-surface selector");
    let expected = b"age: Z6";
    let limits = LiteralReplacementLimits::default();

    let string = "Z".to_owned();
    let actual = regex
        .replace_literal(b"age: 26", string, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[0]);
    assert_eq!(actual.as_bytes(), expected);

    let string = "Z".to_owned();
    let actual = regex
        .replace_literal(b"age: 26", &string, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[1]);
    assert_eq!(actual.as_bytes(), expected);

    let borrowed = Cow::<'_, str>::Borrowed("Z");
    let actual = regex
        .replace_literal(b"age: 26", borrowed, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[2]);
    assert_eq!(actual.as_bytes(), expected);

    let borrowed = Cow::<'_, str>::Borrowed("Z");
    let actual = regex
        .replace_literal(b"age: 26", &borrowed, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[3]);
    assert_eq!(actual.as_bytes(), expected);

    let owned = Cow::<'_, str>::Owned("Z".to_owned());
    let actual = regex
        .replace_literal(b"age: 26", owned, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[4]);
    assert_eq!(actual.as_bytes(), expected);

    let owned = Cow::<'_, str>::Owned("Z".to_owned());
    let actual = regex
        .replace_literal(b"age: 26", &owned, limits)
        .expect(PORTED_TYPE_SURFACE_IDS[5]);
    assert_eq!(actual.as_bytes(), expected);
}

#[test]
fn ported_upstream_literal_and_no_expand_replacement_cases_pass() {
    for case in SUPPORTED_CASES {
        let regex = AggregateBuilder::new(case.pattern)
            .profile(RustProfile::regex_1_12_4())
            .build_spans()
            .unwrap_or_else(|error| {
                panic!(
                    "upstream replacement case {} failed to build from {UPSTREAM_PATH} at \
                     {UPSTREAM_REVISION} ({UPSTREAM_SHA256}): {error}",
                    case.id
                )
            });
        let result = match case.mode {
            ReplaceMode::First => regex.replace_literal(
                case.haystack,
                case.replacement,
                LiteralReplacementLimits::default(),
            ),
            ReplaceMode::All => regex.replace_all_literal(
                case.haystack,
                case.replacement,
                LiteralReplacementLimits::default(),
            ),
            ReplaceMode::N(max) => regex.replacen_literal(
                case.haystack,
                max,
                case.replacement,
                LiteralReplacementLimits::default(),
            ),
        }
        .unwrap_or_else(|error| panic!("upstream replacement case {} failed: {error}", case.id));
        assert_eq!(
            result.as_bytes(),
            case.expected,
            "upstream case {}",
            case.id
        );
        assert_eq!(
            result.report().accounting.replacements,
            case.replacements,
            "upstream case {}",
            case.id
        );
        assert_eq!(
            result.report().identity.selector.operation,
            AggregateOperation::Spans
        );
        assert_eq!(result.report().accounting.output_bytes, case.expected.len());
    }
}

#[test]
fn literal_replacen_matches_pinned_bytes_oracle_on_empty_progress_and_invalid_bytes() {
    const HAYSTACKS: &[&[u8]] = &[
        b"",
        b"ab",
        b"aaaa",
        b"aaaab",
        &[b'a', 0xFF, b'b', b'c'],
        b"a\naa\nb",
    ];
    const PATTERNS: &[&str] = &["", "a*?", r"(?:a+b|a)", r"[a-c\xFF]+", r"(?m:^a+$)"];
    const REPLACEMENTS: &[&[u8]] = &[b"", b"X", b"$1", &[0xFF, b'Z']];
    const MAX_REPLACEMENTS: &[usize] = &[0, 1, 2, usize::MAX];

    for pattern in PATTERNS {
        let fre = AggregateBuilder::new(*pattern)
            .profile(RustProfile::regex_1_12_4())
            .unicode(false)
            .build_spans()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        for haystack in HAYSTACKS {
            for replacement in REPLACEMENTS {
                for max in MAX_REPLACEMENTS {
                    let expected =
                        upstream.replacen(haystack, *max, regex::bytes::NoExpand(replacement));
                    let actual = fre
                        .replacen_literal(
                            haystack,
                            *max,
                            replacement,
                            LiteralReplacementLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "FRE replacement failed for {pattern:?}/{haystack:?}/\
                                 {replacement:?}/{max}: {error}"
                            )
                        });
                    assert_eq!(
                        actual.as_bytes(),
                        expected.as_ref(),
                        "{pattern:?}/{haystack:?}/{replacement:?}/{max}"
                    );
                }
            }
        }
    }

    let unicode_haystack = "Ⅰ1Ⅱ2".as_bytes();
    let fre = AggregateBuilder::new("")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("Unicode empty replacement selector");
    let upstream = regex::bytes::Regex::new("").expect("pinned Unicode bytes regex");
    let expected = upstream.replace_all(unicode_haystack, regex::bytes::NoExpand(b"_"));
    let actual = fre
        .replace_all_literal(unicode_haystack, b"_", LiteralReplacementLimits::default())
        .expect("Unicode-enabled byte-profile replacement");
    assert_eq!(actual.as_bytes(), expected.as_ref());
    assert_eq!(actual.report().accounting.replacements, 9);
}

#[test]
fn output_limit_is_exact_and_accounting_retains_complete_selection() {
    let regex = AggregateBuilder::new(r"[0-9]")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("replacement selector");
    let exact_limits = LiteralReplacementLimits {
        max_output_bytes: 9,
        ..LiteralReplacementLimits::default()
    };
    let exact = regex
        .replace_literal(b"age: 26", b"XYZ", exact_limits)
        .expect("exact output limit");
    assert_eq!(exact.as_bytes(), b"age: XYZ6");
    assert_eq!(exact.report().accounting.selected_matches, 2);
    assert_eq!(exact.report().accounting.replacements, 1);
    assert_eq!(exact.report().accounting.span_visits, 2);
    assert_eq!(exact.report().accounting.haystack_bytes_copied, 6);
    assert_eq!(exact.report().accounting.replacement_bytes_copied, 3);

    let below = LiteralReplacementLimits {
        max_output_bytes: 8,
        ..LiteralReplacementLimits::default()
    };
    let error = regex
        .replace_literal(b"age: 26", b"XYZ", below)
        .expect_err("one below exact output must fail");
    assert!(matches!(
        error.source,
        LiteralReplacementErrorSource::OutputBytesLimit {
            needed: 9,
            limit: 8
        }
    ));
    assert_eq!(error.identity.limit, 1);
    assert_eq!(error.identity.replacement_bytes, 3);
    assert_eq!(error.identity.selector.operation, AggregateOperation::Spans);

    let zero = regex
        .replacen_literal(b"age: 26", 0, b"XYZ", LiteralReplacementLimits::default())
        .expect("zero means replace all");
    assert_eq!(zero.as_bytes(), b"age: XYZXYZ");
    assert_eq!(zero.report().accounting.selected_matches, 2);
    assert_eq!(zero.report().accounting.replacements, 2);
    assert_eq!(zero.report().accounting.span_visits, 4);
}
