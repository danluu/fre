use fre::{
    AggregateBuilder, AggregateOperation, CaptureExpansionError, CaptureExpansionLimits,
    FunctionalReplacementErrorSource, LiteralReplacementErrorSource, LiteralReplacementLimits,
    NoExpand, PortableBuilder, RustProfile,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "tests/replace.rs";
const UPSTREAM_SHA256: &str = "78ff9bf7f78783ad83a78041bb7ee0705c7efc85b4d12301581d0ce5b2a59325";
const UPSTREAM_BYTES_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_BYTES_SHA256: &str =
    "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_API_IDS: &[&str] = &["bytes_no_expand"];

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

const PORTED_CAPTURE_TEMPLATE_IDS: &[&str] = &[
    "groups",
    "double_dollar",
    "named",
    "number_hyphen",
    "simple_expand",
    "literal_dollar1",
    "literal_dollar2",
    "capture_longest_possible_name",
    "replacen_with_captures",
];

const PORTED_FUNCTIONAL_MATCH_IDS: &[&str] =
    &["closure_returning_reference", "closure_returning_value"];

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
    assert_eq!(UPSTREAM_BYTES_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_BYTES_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS, ["bytes_no_expand"]);
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
    let capture_templates: Vec<_> = INVENTORY
        .iter()
        .filter(|case| case.capability == Capability::CaptureExpansion)
        .map(|case| case.id)
        .collect();
    assert_eq!(capture_templates, PORTED_CAPTURE_TEMPLATE_IDS);
    assert_eq!(
        INVENTORY
            .iter()
            .filter(|case| case.capability == Capability::FunctionalReplacer)
            .map(|case| case.id)
            .collect::<Vec<_>>(),
        PORTED_FUNCTIONAL_MATCH_IDS
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
fn pinned_bytes_no_expand_doctest_passes_through_bounded_literal_replacement() {
    let pattern = r"(?<last>[^,\s]+),\s+(\S+)";
    let haystack = b"Springsteen, Bruce";
    let replacement = b"$2 $last";
    let regex = AggregateBuilder::new(pattern)
        .build_spans()
        .expect("NoExpand doctest selector");

    let actual = regex
        .replace_literal(
            haystack,
            NoExpand(replacement),
            LiteralReplacementLimits::default(),
        )
        .expect("bounded NoExpand replacement");
    let upstream = regex::bytes::Regex::new(pattern).expect("pinned NoExpand doctest pattern");
    let expected = upstream.replace(haystack, regex::bytes::NoExpand(replacement));

    assert_eq!(actual.as_bytes(), expected.as_ref());
    assert_eq!(actual.as_bytes(), replacement);
    assert_eq!(actual.report().accounting.replacements, 1);
    assert_eq!(
        actual.report().accounting.replacement_bytes_copied,
        replacement.len()
    );

    let wrapper = NoExpand(replacement);
    assert_eq!(wrapper.clone().0, wrapper.0);
    assert_eq!(
        format!("{wrapper:?}"),
        r"NoExpand([36, 50, 32, 36, 108, 97, 115, 116])"
    );
}

#[test]
fn ported_upstream_functional_replacer_cases_pass() {
    let limits = LiteralReplacementLimits::default();

    let returning_reference = AggregateBuilder::new(r"([0-9]+)")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("functional borrowed replacement selector");
    let mut reference_calls = 0_usize;
    let actual = returning_reference
        .replace_with_match(
            b"age: 26",
            |matched, haystack| {
                reference_calls = reference_calls.saturating_add(1);
                &haystack[matched.start()..matched.start().saturating_add(1)]
            },
            limits,
        )
        .expect(PORTED_FUNCTIONAL_MATCH_IDS[0]);
    assert_eq!(actual.as_bytes(), b"age: 2");
    assert_eq!(reference_calls, 1);
    assert_eq!(actual.report().accounting.replacements, 1);

    let returning_value = AggregateBuilder::new(r"[0-9]+")
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .expect("functional owned replacement selector");
    let mut value_calls = 0_usize;
    let actual = returning_value
        .replace_with_match(
            b"age: 26",
            |_, _| {
                value_calls = value_calls.saturating_add(1);
                "Z".to_owned()
            },
            limits,
        )
        .expect(PORTED_FUNCTIONAL_MATCH_IDS[1]);
    assert_eq!(actual.as_bytes(), b"age: Z");
    assert_eq!(value_calls, 1);
    assert_eq!(actual.report().accounting.replacements, 1);
}

#[test]
fn functional_replacen_matches_pinned_bytes_on_empty_progress_and_invalid_bytes() {
    let haystacks: &[&[u8]] = &[b"", b"ab", b"aaaa", &[b'a', 0xFF, b'b']];
    let patterns = ["", "a*?", r"[a-c\xFF]+"];
    let limits = [0, 1, 2, usize::MAX];

    for pattern in patterns {
        let fre = AggregateBuilder::new(pattern)
            .profile(RustProfile::regex_1_12_4())
            .unicode(false)
            .build_spans()
            .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));

        for &haystack in haystacks {
            for &limit in &limits {
                let expected =
                    upstream.replacen(haystack, limit, |captures: &regex::bytes::Captures<'_>| {
                        let matched = captures.get(0).expect("whole-match capture");
                        vec![
                            u8::try_from(matched.start() & 0xFF).expect("masked start fits u8"),
                            u8::try_from(matched.len() & 0xFF).expect("masked length fits u8"),
                        ]
                    });
                let actual = fre
                    .replacen_with_match(
                        haystack,
                        limit,
                        |matched, _| {
                            vec![
                                u8::try_from(matched.start() & 0xFF).expect("masked start fits u8"),
                                u8::try_from(matched.len() & 0xFF).expect("masked length fits u8"),
                            ]
                        },
                        LiteralReplacementLimits::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "functional replacement failed for {pattern:?}/{haystack:?}/{limit}: \
                             {error}"
                        )
                    });
                assert_eq!(
                    actual.as_bytes(),
                    expected.as_ref(),
                    "{pattern:?}/{haystack:?}/{limit}"
                );
            }
        }
    }
}

#[test]
fn functional_replacement_output_limit_and_accounting_are_exact() {
    let regex = AggregateBuilder::new("a")
        .unicode(false)
        .build_spans()
        .expect("functional resource-bound selector");
    let baseline = regex
        .replace_all_with_match(
            b"aba",
            |_, _| b"XYZ".as_slice(),
            LiteralReplacementLimits::default(),
        )
        .expect("functional accounting baseline");
    assert_eq!(baseline.as_bytes(), b"XYZbXYZ");
    assert_eq!(baseline.report().accounting.selected_matches, 2);
    assert_eq!(baseline.report().accounting.replacements, 2);
    assert_eq!(baseline.report().accounting.span_visits, 2);
    assert_eq!(baseline.report().accounting.haystack_bytes_copied, 1);
    assert_eq!(baseline.report().accounting.replacement_bytes_copied, 6);
    assert_eq!(baseline.report().accounting.output_bytes, 7);

    let exact = LiteralReplacementLimits {
        max_output_bytes: baseline.report().accounting.output_bytes,
        ..LiteralReplacementLimits::default()
    };
    regex
        .replace_all_with_match(b"aba", |_, _| b"XYZ".as_slice(), exact)
        .expect("exact functional output limit");

    let mut calls = 0_usize;
    let error = regex
        .replace_all_with_match(
            b"aba",
            |_, _| {
                calls = calls.saturating_add(1);
                b"XYZ".as_slice()
            },
            LiteralReplacementLimits {
                max_output_bytes: exact.max_output_bytes - 1,
                ..exact
            },
        )
        .expect_err("one below exact functional output must refuse");
    assert_eq!(calls, 2, "each attempted replacement invokes once");
    assert!(matches!(
        error.source,
        FunctionalReplacementErrorSource::OutputBytesLimit {
            needed: 7,
            limit: 6
        }
    ));
    assert_eq!(error.identity.max_output_bytes, 6);

    let mut limited_calls = 0_usize;
    let limited = regex
        .replacen_with_match(
            b"aba",
            1,
            |_, _| {
                limited_calls = limited_calls.saturating_add(1);
                b"XYZ".as_slice()
            },
            exact,
        )
        .expect("functional replacen limit");
    assert_eq!(limited.as_bytes(), b"XYZba");
    assert_eq!(limited_calls, 1);
    assert_eq!(limited.report().accounting.selected_matches, 2);
    assert_eq!(limited.report().accounting.replacements, 1);
}

fn assert_capture_template_matches_pinned(
    pattern: &str,
    haystack: &[u8],
    replacement: &[u8],
) -> usize {
    let fre = PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("pinned regex rejected {pattern:?}: {error}"));
    let mut matches = 0_usize;
    for captures in upstream.captures_iter(haystack) {
        let values: Vec<_> = captures
            .iter()
            .map(|matched| matched.map(|matched| matched.as_bytes()))
            .collect();
        let mut expected = Vec::new();
        captures.expand(replacement, &mut expected);
        let actual = fre
            .expand_capture_template(&values, replacement, CaptureExpansionLimits::default())
            .unwrap_or_else(|error| {
                panic!("FRE expansion failed for {pattern:?}/{haystack:?}/{replacement:?}: {error}")
            });
        assert_eq!(
            actual.as_bytes(),
            expected,
            "{pattern:?}/{haystack:?}/{replacement:?}"
        );
        assert_eq!(actual.report().capture_slots, captures.len());
        assert_eq!(actual.report().replacement_bytes, replacement.len());
        assert_eq!(
            actual.report().accounting.output_bytes,
            actual.as_bytes().len()
        );
        matches = matches.saturating_add(1);
    }
    matches
}

#[test]
fn every_pinned_capture_replacement_template_expands_exactly() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        (r"([^ ]+)[ ]+([^ ]+)", b"w1 w2", b"$2 $1"),
        (r"([^ ]+)[ ]+([^ ]+)", b"w1 w2", b"$2 $$1"),
        (
            r"(?P<first>[^ ]+)[ ]+(?P<last>[^ ]+)(?P<space>[ ]*)",
            b"w1 w2 w3 w4",
            b"$last $first$space",
        ),
        (r"(.)(.)", b"ab", b"$1-$2"),
        (r"([a-z]) ([a-z])", b"a b", b"$2 $1"),
        (r"([a-z]+) ([a-z]+)", b"a b", b"$$1"),
        (r"([a-z]+) ([a-z]+)", b"a b", b"$2 $$c $1"),
        (r"(.)", b"b", b"${1}a $1a"),
        (r"([0-9])", b"age: 1234", b"${1}Z"),
    ];
    let mut executed = 0_usize;
    for &(pattern, haystack, replacement) in cases {
        assert!(assert_capture_template_matches_pinned(pattern, haystack, replacement) > 0);
        executed = executed.saturating_add(1);
    }
    assert_eq!(executed, PORTED_CAPTURE_TEMPLATE_IDS.len());
}

#[test]
fn capture_template_grammar_matches_pinned_bytes_on_malformed_and_invalid_inputs() {
    let pattern = r"(?P<first>a)(?P<optional>b)?(?P<last>c)";
    let haystack = b"ac";
    let replacements: &[&[u8]] = &[
        b"",
        b"$0/$1/$2/$3/$4",
        b"$first/$optional/$last/$missing",
        b"${first}/${optional}/${last}/${missing}",
        b"$$ $$$ $$$$ $",
        b"$1a/${1}a/$01/${01}",
        b"${}/${unterminated/$-/$!",
        b"${unterminated/$1",
        b"prefix\xFF$last\xFE${missing}suffix",
        b"${\xFF}$last",
        b"${\xFF${1}}",
        b"$999999999999999999999999999999999999999999999999999999999999",
    ];
    for replacement in replacements {
        assert_eq!(
            assert_capture_template_matches_pinned(pattern, haystack, replacement),
            1,
            "{replacement:?}"
        );
    }
}

#[test]
fn nested_malformed_capture_templates_have_linear_work_bounds() {
    let fre = PortableBuilder::new(r"(a)")
        .unicode(false)
        .build()
        .expect("bounded capture-template pattern");
    let captures = [Some(b"a".as_slice()), Some(b"a".as_slice())];
    let upstream = regex::bytes::RegexBuilder::new(r"(a)")
        .unicode(false)
        .build()
        .expect("pinned capture-template pattern");
    let upstream_captures = upstream
        .captures(b"a")
        .expect("pinned capture-template match");
    let unterminated = b"${".repeat(4_096);
    let mut invalid_utf8 = unterminated.clone();
    invalid_utf8.extend_from_slice(&[0xFF, b'}']);

    for replacement in [&unterminated, &invalid_utf8] {
        let template_scan_work = replacement
            .len()
            .checked_mul(10)
            .expect("small fixture scan work");
        let exact_work = template_scan_work
            .checked_add(replacement.len())
            .expect("small fixture total work");
        let limits = CaptureExpansionLimits {
            max_output_bytes: replacement.len(),
            max_work: exact_work,
        };
        let actual = fre
            .expand_capture_template(&captures, replacement, limits)
            .expect("nested malformed template stays within a linear work bound");
        let mut expected = Vec::new();
        upstream_captures.expand(replacement, &mut expected);

        assert_eq!(actual.as_bytes(), expected);
        assert_eq!(expected, replacement.as_slice());
        assert_eq!(
            actual.report().accounting.template_bytes_scanned,
            template_scan_work
        );
        assert_eq!(actual.report().accounting.capture_references, 0);
        assert_eq!(actual.report().accounting.work, exact_work);

        let error = fre
            .expand_capture_template(
                &captures,
                replacement,
                CaptureExpansionLimits {
                    max_work: exact_work - 1,
                    ..limits
                },
            )
            .expect_err("one below the certified linear work must refuse");
        assert!(matches!(
            error,
            CaptureExpansionError::WorkLimit { needed, limit }
                if needed == exact_work && limit + 1 == needed
        ));
    }
}

#[test]
fn capture_template_output_and_work_limits_are_exact_before_publication() {
    let pattern = r"(?P<first>a)(?P<optional>b)?(?P<last>c)";
    let fre = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("bounded capture-template pattern");
    let captures = [Some(b"ac".as_slice()), Some(b"a"), None, Some(b"c")];
    let replacement = b"$last-$$-${1}-$missing-$optional";
    let baseline = fre
        .expand_capture_template(&captures, replacement, CaptureExpansionLimits::default())
        .expect("capture-template accounting baseline");
    assert_eq!(baseline.as_bytes(), b"c-$-a--");
    assert_eq!(baseline.report().accounting.capture_references, 4);
    assert_eq!(baseline.report().accounting.participating_references, 2);
    assert_eq!(
        baseline.report().accounting.literal_bytes_copied
            + baseline.report().accounting.capture_bytes_copied,
        baseline.report().accounting.output_bytes
    );

    let exact = CaptureExpansionLimits {
        max_output_bytes: baseline.report().accounting.output_bytes,
        max_work: baseline.report().accounting.work,
    };
    let admitted = fre
        .expand_capture_template(&captures, replacement, exact)
        .expect("exact capture-template limits");
    assert_eq!(admitted.as_bytes(), baseline.as_bytes());
    assert_eq!(admitted.report().limits, exact);

    let output_error = fre
        .expand_capture_template(
            &captures,
            replacement,
            CaptureExpansionLimits {
                max_output_bytes: exact.max_output_bytes - 1,
                ..exact
            },
        )
        .expect_err("one below exact output must refuse");
    assert!(matches!(
        output_error,
        CaptureExpansionError::OutputBytesLimit { needed, limit }
            if needed == exact.max_output_bytes && limit + 1 == needed
    ));

    let work_error = fre
        .expand_capture_template(
            &captures,
            replacement,
            CaptureExpansionLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
        )
        .expect_err("one below exact work must refuse");
    assert!(matches!(
        work_error,
        CaptureExpansionError::WorkLimit { needed, limit }
            if needed == exact.max_work && limit + 1 == needed
    ));

    let slot_error = fre
        .expand_capture_template(&captures[..3], replacement, exact)
        .expect_err("capture records must retain every pattern slot");
    assert_eq!(
        slot_error,
        CaptureExpansionError::CaptureSlotCount {
            expected: 4,
            actual: 3,
        }
    );
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
    assert_eq!(
        exact.report().accounting.output_capacity_bytes,
        exact.capacity_bytes()
    );
    assert!(exact.capacity_bytes() >= exact.report().accounting.output_bytes);

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

    let observed_capacity = exact.capacity_bytes();
    let capacity_below = LiteralReplacementLimits {
        max_output_bytes: 9,
        max_output_capacity_bytes: observed_capacity
            .checked_sub(1)
            .expect("nonempty output capacity"),
        ..LiteralReplacementLimits::default()
    };
    let error = regex
        .replace_literal(b"age: 26", b"XYZ", capacity_below)
        .expect_err("one below observed output capacity must fail before copying");
    assert!(matches!(
        error.source,
        LiteralReplacementErrorSource::OutputCapacityBytesLimit {
            needed,
            limit
        } if needed == observed_capacity && limit + 1 == needed
    ));
    assert_eq!(error.identity.max_output_bytes, 9);
    assert_eq!(
        error.identity.max_output_capacity_bytes,
        observed_capacity - 1
    );

    let zero = regex
        .replacen_literal(b"age: 26", 0, b"XYZ", LiteralReplacementLimits::default())
        .expect("zero means replace all");
    assert_eq!(zero.as_bytes(), b"age: XYZXYZ");
    assert_eq!(zero.report().accounting.selected_matches, 2);
    assert_eq!(zero.report().accounting.replacements, 2);
    assert_eq!(zero.report().accounting.span_visits, 4);
}
