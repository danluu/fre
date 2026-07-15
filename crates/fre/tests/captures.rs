use fre::{
    CaptureAggregateLimits, CaptureBuilder, CaptureExecutionSource, CaptureResource,
    CaptureRunLimits, CaptureSearchError, CaptureSearchLimits,
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
        (r"(?:\A(a)|(a))", b"xax"),
        (r"(?:(a)\z|(a))", b"xax"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        assert_count(pattern, haystack);
    }
}

fn adversarial_operation_work(size: usize) -> (usize, usize) {
    let regex = CaptureBuilder::new(r"(?:a.*z|a)")
        .unicode(false)
        .build()
        .expect("adversarial selector build");
    let haystack = vec![b'a'; size];
    let result = regex
        .count_captures(&haystack, CaptureRunLimits::default())
        .expect("operation-wide capture reduction");
    assert_eq!(size, result.accounting.matches);
    assert_eq!(size, result.accounting.count);
    assert_eq!(size, result.selector_certificate.output_matches);
    let state_visits = result
        .selector_accounting
        .state_evaluations
        .saturating_add(result.selector_accounting.replay_steps)
        .saturating_add(result.accounting.total_state_visits);
    (state_visits, result.accounting.total_history_nodes)
}

#[test]
fn operation_wide_selector_removes_quadratic_restart_work() {
    let samples = [64_usize, 128, 256, 512].map(adversarial_operation_work);
    for pair in samples.windows(2) {
        let (smaller_visits, smaller_histories) = pair[0];
        let (larger_visits, larger_histories) = pair[1];
        assert!(
            larger_visits <= smaller_visits.saturating_mul(5).div_ceil(2),
            "doubling input grew state visits from {smaller_visits} to {larger_visits}"
        );
        assert!(
            larger_histories <= smaller_histories.saturating_mul(5).div_ceil(2),
            "doubling input grew history nodes from {smaller_histories} to {larger_histories}"
        );
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
        ..CaptureRunLimits::default()
    };
    let error = regex
        .count_captures(b"a", starved)
        .expect_err("history starvation must refuse");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::HistoryNodes,
            ..
        })
    ));
}

#[test]
fn combined_peak_caps_retained_selector_output_plus_replay_scratch() {
    let regex = CaptureBuilder::new(r"(a)")
        .unicode(false)
        .build()
        .expect("combined-peak build");
    let admitted = regex
        .count_captures(b"a", CaptureRunLimits::default())
        .expect("combined-peak baseline");
    assert!(
        admitted.combined_peak_bytes > admitted.selector_accounting.peak_bytes,
        "fixture must expose retained spans plus replay scratch"
    );
    assert!(
        admitted.combined_peak_bytes <= CaptureRunLimits::default().max_combined_peak_bytes
    );

    let constrained = CaptureRunLimits {
        max_combined_peak_bytes: admitted.selector_accounting.peak_bytes,
        ..CaptureRunLimits::default()
    };
    let error = regex
        .count_captures(b"a", constrained)
        .expect_err("combined peak must constrain replay before allocation");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::ScratchBytes,
            ..
        })
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
        ..CaptureRunLimits::default()
    };
    assert_ne!(default_identity, python_name.cache_identity(constrained));
}
