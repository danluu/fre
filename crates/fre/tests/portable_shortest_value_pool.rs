#![forbid(unsafe_code)]

use fre::{K0SearchError, PlanKind, PlanSelection, PortableBuilder, SearchError, SearchLimits};

fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
    for _ in 0..maximum_len {
        let previous = words.clone();
        for prefix in previous {
            for &byte in alphabet {
                let mut word = prefix.clone();
                word.push(byte);
                words.push(word);
            }
        }
    }
    words.sort();
    words.dedup();
    words
}

#[test]
fn immutable_k0_shortest_values_match_pinned_bytes_across_warm_calls_and_starts() {
    let haystacks = words(b"abz\n\x80", 4);
    for pattern in [
        r"(?-u:(?:ab|ac)+z)",
        r"(?-u:(?:a?)*)",
        r"(?m:^a+)",
        r"(?-u:(?:a|aa)*b)",
        r"(?-u:(?:\x80|a)+z?)",
    ] {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("forced K0 pattern {pattern:?}: {error}"));
        assert_eq!(portable.build_report().plan, PlanKind::K0);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();

        for pass in 0..2 {
            for haystack in &haystacks {
                assert_eq!(
                    portable
                        .shortest_match_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                    upstream.shortest_match(haystack),
                    "full pattern={pattern:?} haystack={haystack:?} pass={pass}",
                );
                for start in 0..=haystack.len() {
                    assert_eq!(
                        portable
                            .shortest_match_at_value(haystack, start, SearchLimits::unlimited(),)
                            .unwrap(),
                        upstream.shortest_match_at(haystack, start),
                        "pattern={pattern:?} haystack={haystack:?} start={start} pass={pass}",
                    );
                }
            }
        }
    }
}

#[test]
fn shortest_value_pool_preserves_custom_limits_invalid_windows_and_earliest_semantics() {
    let regex = PortableBuilder::new(r"(?-u:a+)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let haystack = b"aaa";

    assert_eq!(
        regex
            .shortest_match_value(haystack, SearchLimits::unlimited())
            .unwrap(),
        Some(1),
    );
    assert_eq!(
        regex
            .selected_end_value(haystack, SearchLimits::unlimited())
            .unwrap(),
        Some(3),
    );

    for limits in [
        SearchLimits::default(),
        SearchLimits {
            max_work: 10_000,
            max_scratch_bytes: 1 << 20,
        },
    ] {
        assert_eq!(
            regex.shortest_match_value(haystack, limits),
            regex
                .shortest_match(haystack, limits)
                .map(|(value, _)| value),
        );
    }

    let refused = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(matches!(
        regex.shortest_match_value(haystack, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        regex.shortest_match_at_value(haystack, haystack.len() + 1, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow { .. }))
    ));
}
