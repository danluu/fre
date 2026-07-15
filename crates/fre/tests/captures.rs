use fre::{
    CaptureAggregateLimits, CaptureBuilder, CaptureResource, CaptureRunLimits, CaptureSearchError,
    CaptureSearchLimits,
};
use regex::bytes::RegexBuilder;

fn reference_count(pattern: &str, haystack: &[u8]) -> usize {
    let regex = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("reference pattern");
    regex
        .captures_iter(haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum()
}

fn assert_count(pattern: &str, haystack: &[u8]) {
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("capture build");
    let result = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("capture reduction");
    assert_eq!(result.accounting.count, reference_count(pattern, haystack));
    assert_eq!(
        result.identity.plan,
        regex.cache_identity(CaptureRunLimits::default()).plan
    );
}

#[test]
fn cross_family_capture_reducers_match_pinned_rust_bytes() {
    let cases: &[(&str, &[u8])] = &[
        (r"(a)(b)?", b"a ab"),
        (r"((a)|(b))+", b"abba cab"),
        (r"(?:fn is_(\w+)|fn as_(\w+))", b"fn is_a fn as_b"),
        (
            r"^\s*fn\s+(is_([^\(]+))\(([^)]+)\) -> bool \{$",
            b"fn is_even(x: u8) -> bool {",
        ),
        (r"(()a)", b"a"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        assert_count(pattern, haystack);
    }
}

#[test]
fn persistent_history_reports_fanout_and_refuses_node_starvation() {
    let pattern = r"(?:(a+)|(b+)|(c+)|(d+)|(e+)|(f+)|(g+)|(h+)|(i+)|(j+)|(k+)|(l+)|(m+)|(n+)|(o+)|(p+)|(q+)|(r+)|(s+)|(t+)|(u+)|(v+)|(w+)|(x+)|(y+)|(z+))";
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("fanout build");
    assert_eq!(regex.build_report().engine.captures, 26);
    let result = regex
        .count_captures(b"aaabbbccc", CaptureRunLimits::default())
        .expect("fanout reduction");
    assert!(result.accounting.total_history_nodes <= result.accounting.total_state_visits);

    let starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            per_search: CaptureSearchLimits {
                max_history_nodes: 0,
                ..CaptureSearchLimits::default()
            },
            max_total_history_nodes: 0,
            ..CaptureAggregateLimits::default()
        },
    };
    let error = regex
        .count_captures(b"a", starved)
        .expect_err("history starvation must refuse");
    assert!(matches!(
        error.source,
        CaptureSearchError::Resource {
            kind: CaptureResource::HistoryNodes,
            ..
        }
    ));
}

#[test]
fn uncertified_unicode_and_word_look_remain_typed_refusals() {
    assert!(
        CaptureBuilder::new(r"(\p{L}+)")
            .unicode(true)
            .build()
            .is_err()
    );
    assert!(
        CaptureBuilder::new(r"\b(a)\b")
            .unicode(false)
            .build()
            .is_err()
    );
}

#[test]
fn source_and_execution_limits_remain_in_capture_identity() {
    let python_name = CaptureBuilder::new(r"(?P<letter>a)")
        .unicode(false)
        .build()
        .expect("Python-name spelling");
    let angle_name = CaptureBuilder::new(r"(?<letter>a)")
        .unicode(false)
        .build()
        .expect("angle-name spelling");
    assert_ne!(
        python_name.build_report().plan_identity,
        angle_name.build_report().plan_identity
    );

    let default_identity = python_name.cache_identity(CaptureRunLimits::default());
    let constrained = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_events: 1,
            ..CaptureAggregateLimits::default()
        },
    };
    assert_ne!(default_identity, python_name.cache_identity(constrained));
}
