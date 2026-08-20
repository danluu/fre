#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegexSet, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    SearchLimits,
};

const K0_PATTERNS: [&str; 4] = [
    "(?:ab|cd|ef)+X",
    "(?:ab|cd|ef)+Y",
    "(?:ab|cd|ef)+Z",
    "(?:ab|cd|ef)+Q",
];

fn compare(
    set: &PortableRegexSet,
    haystack: &[u8],
    start: usize,
    limits: PortableRegexSetRunLimits,
    initial: &[bool],
) {
    let mut accounted = initial.to_vec();
    let mut value = initial.to_vec();
    let expected = set
        .matches_read_at(&mut accounted, haystack, start, limits)
        .map(|(matched, _report)| matched);
    assert_eq!(
        set.matches_read_at_value(&mut value, haystack, start, limits),
        expected,
    );
    assert_eq!(value, accounted);

    let mut alias = initial.to_vec();
    assert_eq!(
        set.read_matches_at_value(&mut alias, haystack, start, limits),
        expected,
    );
    assert_eq!(alias, accounted);
}

#[test]
fn caller_buffer_values_match_accounted_results_for_every_start_and_plan_mix() {
    let cases: &[(&[&str], &[u8])] = &[
        (&K0_PATTERNS, b"xxababX-cdcdY-efefZ-abcdQyy"),
        (&["needle", "[a-z]+", r"(?-u:[0-9]+)"], b"needle abc 123"),
        (&["a*", "(?:b+|)", "c?", "(?:de)*"], b"xyz"),
        (&[r"\b[a-z]+\b", r"(?m:^anchor)", r"z$"], b" anchor z"),
    ];
    for &(patterns, haystack) in cases {
        let set = PortableRegexSet::new(patterns.iter().copied()).expect("portable set");
        for start in 0..=haystack.len() {
            let mut initial = vec![false; set.len() + 2];
            for index in (1..initial.len()).step_by(2) {
                initial[index] = true;
            }
            compare(
                &set,
                haystack,
                start,
                PortableRegexSetRunLimits::unlimited(),
                &initial,
            );
        }
    }
}

#[test]
fn finite_limits_and_validation_replay_the_exact_accounted_contract() {
    let set = PortableRegexSet::new(K0_PATTERNS).expect("K0 set");
    assert!((0..set.len()).all(|index| {
        set.pattern_build_report(index)
            .expect("pattern report")
            .plan
            == PlanKind::K0
    }));
    let haystack = b"ababX-cdcdY-efefZ-abcdQ";
    let mut probe_flags = vec![false; set.len()];
    let (_, report) = set
        .matches_read_at(
            &mut probe_flags,
            haystack,
            0,
            PortableRegexSetRunLimits::unlimited(),
        )
        .expect("work probe");
    assert!(report.work > 0);

    let exact = PortableRegexSetRunLimits {
        max_total_work: report.work,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let refused = PortableRegexSetRunLimits {
        max_total_work: report.work - 1,
        ..exact
    };
    let output_refused = PortableRegexSetRunLimits {
        max_output_matches: 2,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let search_refused = PortableRegexSetRunLimits {
        max_pattern_searches: 2,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let scratch_refused = PortableRegexSetRunLimits {
        pattern: SearchLimits {
            max_scratch_bytes: 0,
            ..SearchLimits::unlimited()
        },
        ..PortableRegexSetRunLimits::unlimited()
    };
    for limits in [
        exact,
        refused,
        output_refused,
        search_refused,
        scratch_refused,
    ] {
        compare(
            &set,
            haystack,
            0,
            limits,
            &[false, true, false, false, true],
        );
    }

    let hostile = PortableRegexSetRunLimits {
        pattern: SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        },
        max_pattern_searches: 0,
        max_total_work: 0,
        max_output_matches: 0,
        max_output_bytes: 0,
    };
    let empty = PortableRegexSet::empty();
    compare(&empty, b"anything", 0, hostile, &[true, false]);

    let mut invalid = [false; 1];
    assert_eq!(
        set.matches_read_at_value(&mut invalid, haystack, haystack.len() + 1, hostile),
        Err(PortableRegexSetExecutionError::InvalidStart {
            start: haystack.len() + 1,
            haystack_len: haystack.len(),
        }),
    );
    assert_eq!(invalid, [false]);

    let mut short = [false; 3];
    assert_eq!(
        set.matches_read_at_value(&mut short, haystack, 0, hostile),
        Err(PortableRegexSetExecutionError::MatchBufferTooSmall {
            needed: K0_PATTERNS.len(),
            available: short.len(),
        }),
    );
    assert_eq!(short, [false; 3]);
}
