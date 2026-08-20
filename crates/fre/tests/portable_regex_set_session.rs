#![forbid(unsafe_code)]

use core::mem::size_of;

use fre::{
    PlanKind, PortableRegexSet, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    PortableRegexSetSearchSession, PortableRegexSetSessionError, PortableRegexSetSessionLimits,
    PortableSearchSession, PortableTextRegexSet, PortableTextRegexSetSearchSession,
    PortableTextSearchSession, SearchLimits, SearchSessionLimits,
};

const K0_PATTERNS: [&str; 4] = [
    "(?:ab|cd|ef)+X",
    "(?:ab|cd|ef)+Y",
    "(?:ab|cd|ef)+Z",
    "(?:ab|cd|ef)+Q",
];

fn byte_ids(
    session: &mut PortableRegexSetSearchSession<'_>,
    haystack: &[u8],
    start: usize,
) -> Vec<usize> {
    session
        .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
        .expect("byte set-session match search")
        .into_iter()
        .collect()
}

fn text_ids(
    session: &mut PortableTextRegexSetSearchSession<'_>,
    haystack: &str,
    start: usize,
) -> Vec<usize> {
    session
        .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
        .expect("text set-session match search")
        .into_iter()
        .collect()
}

#[test]
fn empty_set_sessions_publish_zero_receipts_and_preserve_empty_semantics() {
    let bytes = PortableRegexSet::empty();
    let mut byte_session = bytes
        .search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            },
            max_pattern_sessions: 0,
            max_total_setup_work: 0,
            max_total_retained_bytes: 0,
        })
        .expect("zero-cost empty byte session");
    let byte_setup = byte_session.setup_report();
    assert_eq!(byte_setup.pattern_sessions, 0);
    assert_eq!(byte_setup.session_capacity_bytes, 0);
    assert_eq!(byte_setup.session_initialization_work, 0);
    assert_eq!(byte_setup.workspace_setup_work, 0);
    assert_eq!(byte_setup.workspace_allocated_bytes, 0);
    assert_eq!(byte_setup.workspace_initialized_bytes, 0);
    assert_eq!(byte_setup.workspace_retained_bytes, 0);
    assert_eq!(byte_setup.charged_setup_work, 0);
    assert_eq!(byte_setup.charged_retained_bytes, 0);
    assert!(byte_session.is_empty());
    assert_eq!(byte_session.len(), 0);
    assert!(byte_session.patterns().is_empty());
    assert_eq!(byte_ids(&mut byte_session, b"anything", 0), []);
    assert_eq!(
        byte_session
            .is_match(b"anything", PortableRegexSetRunLimits::unlimited())
            .expect("empty byte is_match")
            .0,
        false
    );

    let text = PortableTextRegexSet::empty();
    let mut text_session = text
        .search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            },
            max_pattern_sessions: 0,
            max_total_setup_work: 0,
            max_total_retained_bytes: 0,
        })
        .expect("zero-cost empty text session");
    assert_eq!(text_session.setup_report(), byte_setup);
    assert!(text_session.is_empty());
    assert_eq!(text_session.len(), 0);
    assert!(text_session.patterns().is_empty());
    assert_eq!(text_ids(&mut text_session, "anything", 0), []);
}

#[test]
fn construction_receipts_close_over_full_descriptor_vector_and_k0_workspaces() {
    let bytes = PortableRegexSet::new(K0_PATTERNS).expect("K0 byte set");
    assert!((0..bytes.len()).all(|index| {
        bytes.pattern_build_report(index).expect("byte report").plan == PlanKind::K0
    }));
    let byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("K0 byte set session");
    let byte_setup = byte_session.setup_report();
    assert_eq!(byte_setup.pattern_sessions, K0_PATTERNS.len());
    let byte_logical = K0_PATTERNS.len() * size_of::<PortableSearchSession<'_>>();
    assert!(byte_setup.session_capacity_bytes >= byte_logical);
    assert_eq!(
        byte_setup.session_capacity_bytes % size_of::<PortableSearchSession<'_>>(),
        0
    );
    assert_eq!(
        byte_setup.session_initialization_work,
        u64::try_from(K0_PATTERNS.len()).unwrap()
    );
    assert!(byte_setup.workspace_setup_work > 0);
    assert!(byte_setup.workspace_allocated_bytes > 0);
    assert!(byte_setup.workspace_initialized_bytes > 0);
    assert!(byte_setup.workspace_retained_bytes > 0);
    assert_eq!(
        byte_setup.charged_setup_work,
        byte_setup.session_initialization_work + byte_setup.workspace_setup_work
    );
    assert_eq!(
        byte_setup.charged_retained_bytes,
        byte_setup.session_capacity_bytes + byte_setup.workspace_retained_bytes
    );

    let text = PortableTextRegexSet::new(K0_PATTERNS).expect("K0 text set");
    assert!((0..text.len()).all(|index| {
        text.pattern_build_report(index)
            .expect("text report")
            .portable
            .plan
            == PlanKind::K0
    }));
    let text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("K0 text set session");
    let text_setup = text_session.setup_report();
    assert_eq!(text_setup.pattern_sessions, K0_PATTERNS.len());
    let text_logical = K0_PATTERNS.len() * size_of::<PortableTextSearchSession<'_>>();
    assert!(text_setup.session_capacity_bytes >= text_logical);
    assert_eq!(
        text_setup.session_capacity_bytes % size_of::<PortableTextSearchSession<'_>>(),
        0
    );
    assert_eq!(
        text_setup.charged_setup_work,
        text_setup.session_initialization_work + text_setup.workspace_setup_work
    );
    assert_eq!(
        text_setup.charged_retained_bytes,
        text_setup.session_capacity_bytes + text_setup.workspace_retained_bytes
    );
}

#[test]
fn construction_limits_admit_exact_receipts_and_reject_below_descriptor_floors() {
    fn minimum_u64(upper: u64, mut admits: impl FnMut(u64) -> bool) -> u64 {
        assert!(admits(upper));
        let mut low = 0_u64;
        let mut high = upper;
        while low < high {
            let middle = low + (high - low) / 2;
            if admits(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    fn minimum_usize(upper: usize, mut admits: impl FnMut(usize) -> bool) -> usize {
        assert!(admits(upper));
        let mut low = 0_usize;
        let mut high = upper;
        while low < high {
            let middle = low + (high - low) / 2;
            if admits(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    let bytes = PortableRegexSet::new(K0_PATTERNS).expect("K0 byte set");
    let byte_probe = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("byte setup probe")
        .setup_report();
    let byte_exact = PortableRegexSetSessionLimits {
        pattern: SearchSessionLimits::unlimited(),
        max_pattern_sessions: K0_PATTERNS.len(),
        max_total_setup_work: byte_probe.charged_setup_work,
        max_total_retained_bytes: byte_probe.charged_retained_bytes,
    };
    assert_eq!(
        bytes
            .search_session(byte_exact)
            .expect("exact byte setup limits")
            .setup_report()
            .charged_setup_work,
        byte_probe.charged_setup_work
    );
    let byte_minimum_setup = minimum_u64(byte_probe.charged_setup_work, |maximum| {
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_setup_work: maximum,
                ..byte_exact
            })
            .is_ok()
    });
    assert!(byte_minimum_setup > 0);
    assert_eq!(
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_setup_work: byte_minimum_setup,
                ..byte_exact
            })
            .expect("exact minimum byte setup")
            .setup_report()
            .charged_setup_work,
        byte_minimum_setup,
    );
    assert!(bytes
        .search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: byte_minimum_setup - 1,
            ..byte_exact
        })
        .is_err());
    let byte_minimum_retained = minimum_usize(byte_probe.charged_retained_bytes, |maximum| {
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_retained_bytes: maximum,
                ..byte_exact
            })
            .is_ok()
    });
    assert!(byte_minimum_retained > 0);
    assert_eq!(
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_retained_bytes: byte_minimum_retained,
                ..byte_exact
            })
            .expect("exact minimum byte retention")
            .setup_report()
            .charged_retained_bytes,
        byte_minimum_retained,
    );
    assert!(bytes
        .search_session(PortableRegexSetSessionLimits {
            max_total_retained_bytes: byte_minimum_retained - 1,
            ..byte_exact
        })
        .is_err());
    assert!(matches!(
        bytes.search_session(PortableRegexSetSessionLimits {
            max_pattern_sessions: K0_PATTERNS.len() - 1,
            ..byte_exact
        }),
        Err(PortableRegexSetSessionError::PatternSessionLimit {
            needed: 4,
            limit: 3
        })
    ));
    assert!(
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_setup_work: byte_probe.session_initialization_work - 1,
                ..byte_exact
            })
            .is_err()
    );
    assert!(
        bytes
            .search_session(PortableRegexSetSessionLimits {
                max_total_retained_bytes: byte_probe.session_capacity_bytes - 1,
                ..byte_exact
            })
            .is_err()
    );

    let text = PortableTextRegexSet::new(K0_PATTERNS).expect("K0 text set");
    let text_probe = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("text setup probe")
        .setup_report();
    let text_exact = PortableRegexSetSessionLimits {
        pattern: SearchSessionLimits::unlimited(),
        max_pattern_sessions: K0_PATTERNS.len(),
        max_total_setup_work: text_probe.charged_setup_work,
        max_total_retained_bytes: text_probe.charged_retained_bytes,
    };
    let exact = text
        .search_session(text_exact)
        .expect("exact text setup limits")
        .setup_report();
    assert_eq!(exact.charged_setup_work, text_probe.charged_setup_work);
    assert_eq!(
        exact.charged_retained_bytes,
        text_probe.charged_retained_bytes
    );
    let text_minimum_setup = minimum_u64(text_probe.charged_setup_work, |maximum| {
        text.search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: maximum,
            ..text_exact
        })
        .is_ok()
    });
    assert!(text_minimum_setup > 0);
    assert_eq!(
        text.search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: text_minimum_setup,
            ..text_exact
        })
        .expect("exact minimum text setup")
        .setup_report()
        .charged_setup_work,
        text_minimum_setup,
    );
    assert!(text
        .search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: text_minimum_setup - 1,
            ..text_exact
        })
        .is_err());
    let text_minimum_retained = minimum_usize(text_probe.charged_retained_bytes, |maximum| {
        text.search_session(PortableRegexSetSessionLimits {
            max_total_retained_bytes: maximum,
            ..text_exact
        })
        .is_ok()
    });
    assert!(text_minimum_retained > 0);
    assert_eq!(
        text.search_session(PortableRegexSetSessionLimits {
            max_total_retained_bytes: text_minimum_retained,
            ..text_exact
        })
        .expect("exact minimum text retention")
        .setup_report()
        .charged_retained_bytes,
        text_minimum_retained,
    );
    assert!(text
        .search_session(PortableRegexSetSessionLimits {
            max_total_retained_bytes: text_minimum_retained - 1,
            ..text_exact
        })
        .is_err());
    assert!(
        text.search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: text_probe.session_initialization_work - 1,
            ..text_exact
        })
        .is_err()
    );
    assert!(
        text.search_session(PortableRegexSetSessionLimits {
            max_total_retained_bytes: text_probe.session_capacity_bytes - 1,
            ..text_exact
        })
        .is_err()
    );
}

#[test]
fn duplicate_and_overlapping_patterns_keep_independent_membership_in_both_facades() {
    let patterns = ["a", "ab", "a", "b"];
    let bytes = PortableRegexSet::new(patterns).expect("overlapping byte set");
    let mut byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("overlapping byte session");
    let text = PortableTextRegexSet::new(patterns).expect("overlapping text set");
    let mut text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("overlapping text session");
    let upstream_bytes = regex::bytes::RegexSet::new(patterns).expect("upstream byte set");
    let upstream_text = regex::RegexSet::new(patterns).expect("upstream text set");

    for (haystack, expected) in [("ab", vec![0, 1, 2, 3]), ("a", vec![0, 2]), ("x", vec![])] {
        assert_eq!(
            byte_ids(&mut byte_session, haystack.as_bytes(), 0),
            expected
        );
        assert_eq!(text_ids(&mut text_session, haystack, 0), expected);
        assert_eq!(
            upstream_bytes
                .matches(haystack.as_bytes())
                .into_iter()
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            upstream_text
                .matches(haystack)
                .into_iter()
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn session_calls_retain_short_circuit_search_and_output_contracts() {
    let patterns = ["a", "ab", "a", "z"];
    let bytes = PortableRegexSet::new(patterns).expect("byte set");
    let mut session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("byte set session");
    let one_search = PortableRegexSetRunLimits {
        max_pattern_searches: 1,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let (matched, report) = session
        .is_match(b"ab", one_search)
        .expect("is_match may short-circuit after one search");
    assert!(matched);
    assert_eq!(report.patterns_searched, 1);
    assert_eq!(report.matched_patterns, 1);
    assert!(matches!(
        session.matches(b"ab", one_search),
        Err(PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 2,
            limit: 1
        })
    ));

    let mut caller_flags = [false, false, false, false, true];
    assert!(matches!(
        session.matches_read_at(&mut caller_flags, b"ab", 0, one_search),
        Err(PortableRegexSetExecutionError::PatternSearchLimit {
            needed: 2,
            limit: 1
        })
    ));
    assert_eq!(caller_flags, [true, false, false, false, true]);

    let too_few_outputs = PortableRegexSetRunLimits {
        max_output_matches: 2,
        ..PortableRegexSetRunLimits::unlimited()
    };
    assert!(matches!(
        session.matches(b"ab", too_few_outputs),
        Err(PortableRegexSetExecutionError::OutputMatchesLimit {
            needed: 3,
            limit: 2
        })
    ));
    assert!(matches!(
        session.matches(
            b"ab",
            PortableRegexSetRunLimits {
                max_output_bytes: patterns.len() - 1,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ),
        Err(PortableRegexSetExecutionError::OutputBytesLimit { .. })
    ));
    let mut too_small = [false; 3];
    assert!(matches!(
        session.matches_read_at(
            &mut too_small,
            b"ab",
            0,
            PortableRegexSetRunLimits::unlimited()
        ),
        Err(PortableRegexSetExecutionError::MatchBufferTooSmall {
            needed: 4,
            available: 3
        })
    ));
}

#[test]
fn cumulative_session_work_sums_constituents_and_zero_total_is_refused() {
    let bytes = PortableRegexSet::new(K0_PATTERNS).expect("K0 byte set");
    let haystack = b"ababcdcdefef-no-terminal";
    let exact_work = {
        let mut probe = bytes
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("work probe session");
        let matches = probe
            .matches(haystack, PortableRegexSetRunLimits::unlimited())
            .expect("work probe");
        assert!(matches.iter().next().is_none());
        matches.report().work
    };
    assert!(exact_work > 0);
    let mut constituent_sum = 0_u64;
    for pattern in K0_PATTERNS {
        let singleton = PortableRegexSet::new([pattern]).expect("singleton K0 set");
        let mut singleton_session = singleton
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("singleton K0 session");
        let work = singleton_session
            .matches(haystack, PortableRegexSetRunLimits::unlimited())
            .expect("singleton work")
            .report()
            .work;
        constituent_sum = constituent_sum.checked_add(work).unwrap();
    }
    assert_eq!(exact_work, constituent_sum);

    let mut refused = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("zero-total session");
    assert_eq!(
        match refused.matches(
            haystack,
            PortableRegexSetRunLimits {
                max_total_work: 0,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ) {
            Err(PortableRegexSetExecutionError::Pattern {
                index: 0,
                total_work_before,
                remaining_total_work,
                ..
            }) => (total_work_before, remaining_total_work),
            other => panic!("zero total work unexpectedly returned {other:?}"),
        },
        (0, 0)
    );
}

#[test]
fn mid_set_work_refusal_does_not_poison_byte_or_text_session_reuse() {
    let patterns = ["literal-never", K0_PATTERNS[0]];
    let byte_haystack = b"ababX";
    let first_byte_work = {
        let singleton = PortableRegexSet::new([patterns[0]]).expect("byte work singleton");
        let mut session = singleton
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("byte singleton session");
        session
            .matches(byte_haystack, PortableRegexSetRunLimits::unlimited())
            .expect("byte singleton search")
            .report()
            .work
    };
    let bytes = PortableRegexSet::new(patterns).expect("mixed byte set");
    let mut byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("mixed byte session");
    assert!(matches!(
        byte_session.matches(
            byte_haystack,
            PortableRegexSetRunLimits {
                max_total_work: first_byte_work,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ),
        Err(PortableRegexSetExecutionError::Pattern {
            index: 1,
            total_work_before,
            remaining_total_work: 0,
            ..
        }) if total_work_before == first_byte_work
    ));
    assert_eq!(byte_ids(&mut byte_session, byte_haystack, 0), [1]);

    let text_haystack = "ababX";
    let first_text_work = {
        let singleton = PortableTextRegexSet::new([patterns[0]]).expect("text work singleton");
        let mut session = singleton
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("text singleton session");
        session
            .matches(text_haystack, PortableRegexSetRunLimits::unlimited())
            .expect("text singleton search")
            .report()
            .work
    };
    let text = PortableTextRegexSet::new(patterns).expect("mixed text set");
    let mut text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("mixed text session");
    assert!(matches!(
        text_session.matches(
            text_haystack,
            PortableRegexSetRunLimits {
                max_total_work: first_text_work,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ),
        Err(PortableRegexSetExecutionError::Pattern {
            index: 1,
            total_work_before,
            remaining_total_work: 0,
            ..
        }) if total_work_before == first_text_work
    ));
    assert_eq!(text_ids(&mut text_session, text_haystack, 0), [1]);
}

#[test]
fn text_sessions_preserve_interior_utf8_start_normalization_and_original_start_reports() {
    let patterns = ["", "é", "東京", r"\bbar\b", r"(?m)^bar$"];
    let set = PortableTextRegexSet::new(patterns).expect("text offset set");
    let mut session = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("text offset session");
    let upstream = regex::RegexSet::new(patterns).expect("upstream text offset set");
    let haystack = "é\nbar\n東京";
    for start in 0..=haystack.len() {
        let expected = upstream
            .matches_at(haystack, start)
            .into_iter()
            .collect::<Vec<_>>();
        let actual = session
            .matches_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .unwrap_or_else(|error| panic!("session offset {start} failed: {error}"));
        assert_eq!(actual.iter().collect::<Vec<_>>(), expected, "start {start}");
        assert_eq!(actual.report().start, start);
        let (matched, report) = session
            .is_match_at(haystack, start, PortableRegexSetRunLimits::unlimited())
            .unwrap_or_else(|error| panic!("session is_match offset {start} failed: {error}"));
        assert_eq!(
            matched,
            upstream.is_match_at(haystack, start),
            "start {start}"
        );
        assert_eq!(report.start, start);
    }

    let error = session
        .matches_at(
            haystack,
            haystack.len() + 1,
            PortableRegexSetRunLimits {
                max_output_bytes: 0,
                ..PortableRegexSetRunLimits::unlimited()
            },
        )
        .expect_err("invalid start must precede output admission");
    assert!(matches!(
        error,
        PortableRegexSetExecutionError::InvalidStart { .. }
    ));
}

#[test]
fn session_reuse_alternates_sources_without_retaining_positions_or_results() {
    let bytes = PortableRegexSet::new(K0_PATTERNS).expect("K0 byte set");
    let mut byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("K0 byte set session");
    let text = PortableTextRegexSet::new(K0_PATTERNS).expect("K0 text set");
    let mut text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("K0 text set session");
    let cases = [
        ("ababX", vec![0]),
        ("cdcdefY", vec![1]),
        ("none", vec![]),
        ("efefZ", vec![2]),
        ("ababQ", vec![3]),
        ("ababX", vec![0]),
    ];
    for (haystack, expected) in cases {
        assert_eq!(
            byte_ids(&mut byte_session, haystack.as_bytes(), 0),
            expected
        );
        assert_eq!(text_ids(&mut text_session, haystack, 0), expected);
    }
}

#[test]
fn native_constituents_still_charge_descriptor_slots_but_no_workspace_receipt() {
    let patterns = ["a", "ab", "xyz"];
    let bytes = PortableRegexSet::new(patterns).expect("native byte set");
    assert!((0..bytes.len()).all(|index| {
        bytes.pattern_build_report(index).expect("byte report").plan != PlanKind::K0
    }));
    let setup = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("native set session")
        .setup_report();
    let logical = patterns.len() * size_of::<PortableSearchSession<'_>>();
    assert!(setup.session_capacity_bytes >= logical);
    assert_eq!(
        setup.session_capacity_bytes % size_of::<PortableSearchSession<'_>>(),
        0
    );
    assert_eq!(setup.session_initialization_work, 3);
    assert_eq!(setup.workspace_setup_work, 0);
    assert_eq!(setup.workspace_allocated_bytes, 0);
    assert_eq!(setup.workspace_initialized_bytes, 0);
    assert_eq!(setup.workspace_retained_bytes, 0);
    assert_eq!(setup.charged_setup_work, 3);
    assert_eq!(setup.charged_retained_bytes, setup.session_capacity_bytes);

    let exact = PortableRegexSetSessionLimits {
        pattern: SearchSessionLimits {
            max_setup_work: 0,
            max_scratch_bytes: 0,
        },
        max_pattern_sessions: patterns.len(),
        max_total_setup_work: setup.charged_setup_work,
        max_total_retained_bytes: setup.charged_retained_bytes,
    };
    assert!(bytes.search_session(exact).is_ok());
    assert!(matches!(
        bytes.search_session(PortableRegexSetSessionLimits {
            max_total_setup_work: setup.charged_setup_work - 1,
            ..exact
        }),
        Err(PortableRegexSetSessionError::SetupWorkLimit {
            needed: 3,
            limit: 2
        })
    ));
}

#[test]
fn per_pattern_session_limit_is_delegated_under_the_aggregate_residual() {
    let index_zero =
        PortableRegexSet::new([K0_PATTERNS[0], K0_PATTERNS[1]]).expect("two K0 byte matchers");
    assert!(matches!(
        index_zero.search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: usize::MAX,
            },
            max_pattern_sessions: 2,
            max_total_setup_work: u64::MAX,
            max_total_retained_bytes: usize::MAX,
        }),
        Err(PortableRegexSetSessionError::Pattern {
            index: 0,
            total_setup_work_before: 0,
            reserved_session_initialization_work: 2,
            delegated_setup_work: 0,
            ..
        })
    ));

    let later = PortableRegexSet::new(["a", K0_PATTERNS[0]]).expect("native-prefix K0 byte set");
    assert!(matches!(
        later.search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: usize::MAX,
            },
            max_pattern_sessions: 2,
            max_total_setup_work: u64::MAX,
            max_total_retained_bytes: usize::MAX,
        }),
        Err(PortableRegexSetSessionError::Pattern {
            index: 1,
            total_setup_work_before: 1,
            reserved_session_initialization_work: 1,
            delegated_setup_work: 0,
            ..
        })
    ));

    let bytes = PortableRegexSet::new([K0_PATTERNS[0]]).expect("one K0 byte matcher");
    let setup = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("setup probe")
        .setup_report();
    assert!(setup.workspace_setup_work > 0);
    assert!(matches!(
        bytes.search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: usize::MAX,
            },
            max_pattern_sessions: 1,
            max_total_setup_work: u64::MAX,
            max_total_retained_bytes: usize::MAX,
        }),
        Err(PortableRegexSetSessionError::Pattern { index: 0, .. })
    ));
    assert!(matches!(
        bytes.search_session(PortableRegexSetSessionLimits {
            pattern: SearchSessionLimits {
                max_setup_work: u64::MAX,
                max_scratch_bytes: 0,
            },
            max_pattern_sessions: 1,
            max_total_setup_work: u64::MAX,
            max_total_retained_bytes: usize::MAX,
        }),
        Err(PortableRegexSetSessionError::Pattern { index: 0, .. })
    ));
}

#[test]
fn per_pattern_execution_limit_and_total_limit_remain_independent() {
    let bytes = PortableRegexSet::new([K0_PATTERNS[0]]).expect("one K0 byte matcher");
    let haystack = b"ababX";
    let exact_work = {
        let mut probe = bytes
            .search_session(PortableRegexSetSessionLimits::unlimited())
            .expect("work probe session");
        probe
            .is_match(haystack, PortableRegexSetRunLimits::unlimited())
            .expect("work probe")
            .1
            .work
    };
    assert!(exact_work > 0);
    let mut per_pattern = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("per-pattern refusal session");
    assert!(matches!(
        per_pattern.is_match(
            haystack,
            PortableRegexSetRunLimits {
                pattern: SearchLimits {
                    max_work: 0,
                    ..SearchLimits::unlimited()
                },
                max_total_work: u64::MAX,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ),
        Err(PortableRegexSetExecutionError::Pattern { index: 0, .. })
    ));

    let mut aggregate = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("aggregate refusal session");
    assert!(matches!(
        aggregate.is_match(
            haystack,
            PortableRegexSetRunLimits {
                pattern: SearchLimits::unlimited(),
                max_total_work: 0,
                ..PortableRegexSetRunLimits::unlimited()
            }
        ),
        Err(PortableRegexSetExecutionError::Pattern {
            index: 0,
            total_work_before: 0,
            remaining_total_work: 0,
            ..
        })
    ));
}
