#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegexSetExecutionError, PortableRegexSetRunLimits, PortableTextProof,
    PortableTextRegexSet,
};

#[test]
fn immutable_value_existence_matches_accounted_and_upstream_at_every_utf8_offset() {
    let patterns = ["!", "[a-z]+", "é", "東京", r"\bbar\b", r"(?m)^bar$"];
    let set = PortableTextRegexSet::new(patterns).expect("mixed text set");
    let upstream = regex::RegexSet::new(patterns).expect("upstream text set");
    let limits = PortableRegexSetRunLimits {
        max_output_matches: 0,
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };

    for haystack in ["", "!", "é\nbar\n東京", "🦀 none"] {
        for start in 0..=haystack.len() {
            let expected = upstream.is_match_at(haystack, start);
            assert_eq!(
                set.is_match_at(haystack, start, limits)
                    .unwrap_or_else(|error| panic!("accounted {haystack:?}/{start}: {error}"))
                    .0,
                expected,
                "accounted {haystack:?}/{start}",
            );
            assert_eq!(
                set.is_match_value_at_unlimited(haystack, start)
                    .unwrap_or_else(|error| panic!("value {haystack:?}/{start}: {error}")),
                expected,
                "value {haystack:?}/{start}",
            );
        }
        assert_eq!(
            set.is_match_value_unlimited(haystack)
                .expect("whole-haystack value search"),
            upstream.is_match(haystack),
        );
    }

    let invalid = "é".len() + 1;
    assert_eq!(
        set.is_match_value_at_unlimited("é", invalid)
            .expect_err("invalid value start"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: "é".len(),
        },
    );
    let empty = PortableTextRegexSet::empty();
    assert!(
        !empty
            .is_match_value_unlimited("anything")
            .expect("empty value search")
    );
}

#[test]
fn immutable_value_existence_preserves_assertion_context_and_source_order() {
    let patterns = ["never", r"(?m)^(?:ab|cd)+Z$", "[a-z][0-9]"];
    let set = PortableTextRegexSet::new(patterns).expect("ordered assertion text set");
    let asserted = set.pattern_build_report(1).expect("asserted report");
    assert_eq!(asserted.portable.plan, PlanKind::K0);
    assert!(matches!(
        &asserted.proof,
        PortableTextProof::IdenticalUtf8Hir {
            has_look_assertions: true,
            ..
        }
    ));
    let upstream = regex::RegexSet::new(patterns).expect("upstream assertion text set");
    let limits = PortableRegexSetRunLimits::unlimited();

    for (haystack, start) in [
        ("ababZ", 0),
        ("x\ncdZ\ny", 1),
        ("x\ncdZ\ny", 3),
        ("a7", 0),
        ("none", 0),
        ("é\na7", 1),
    ] {
        let expected = upstream.is_match_at(haystack, start);
        assert_eq!(
            set.is_match_value_at_unlimited(haystack, start)
                .expect("ordered ranged value search"),
            expected,
        );
        assert_eq!(
            set.is_match_at(haystack, start, limits)
                .expect("ordered ranged accounted search")
                .0,
            expected,
        );
    }
}
