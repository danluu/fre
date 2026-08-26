#![forbid(unsafe_code)]

use fre_aot_regex::{
    CompileError, CompileMode, REGEX_SET_EXACT64_MAX_PATTERNS, RegexSetCompileError,
    RegexSetCompileRequest, RegexSetExact64CompileDisposition, RegexSetExact64CompileError,
    RegexSetExact64Decline, RegexSetExact64Limits, RegexSetExact64Program, RegexSetExact64Resource,
    RegexSetExact64RunError, RegexSetSessionLimits, SearchWindow, compile_regex_set,
    compile_regex_set_exact64_reported,
};
use regex_automata::{Input, MatchKind, PatternSet, meta::Regex as MetaRegex};

fn request(patterns: &[String]) -> RegexSetCompileRequest {
    RegexSetCompileRequest::new(patterns.to_vec())
}

fn selected(patterns: &[String], limits: RegexSetExact64Limits) -> RegexSetExact64Program {
    match compile_regex_set_exact64_reported(request(patterns), limits).expect("exact64 compile") {
        RegexSetExact64CompileDisposition::Selected(program) => program,
        RegexSetExact64CompileDisposition::Declined { reason, .. } => {
            panic!("unexpected exact64 decline: {reason}")
        }
    }
}

fn stock_oracle(patterns: &[String]) -> MetaRegex {
    MetaRegex::builder()
        .configure(
            MetaRegex::config()
                .match_kind(MatchKind::All)
                .utf8_empty(false),
        )
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(true),
        )
        .build_many(patterns)
        .expect("stock regex-set oracle")
}

fn stock_mask(oracle: &MetaRegex, haystack: &[u8], window: SearchWindow) -> u64 {
    let input = Input::new(haystack).span(window.start()..window.end());
    let mut matches = PatternSet::new(oracle.pattern_len());
    oracle.which_overlapping_matches(&input, &mut matches);
    matches
        .iter()
        .fold(0_u64, |mask, pattern| mask | (1_u64 << pattern.as_usize()))
}

fn assert_matches_fallback(
    program: &RegexSetExact64Program,
    haystack: &[u8],
    window: SearchWindow,
) {
    let fallback = program.fallback();
    let mut session = fallback
        .prepare_session(RegexSetSessionLimits::unlimited())
        .expect("fallback session");
    let mut expected = [u64::MAX];
    fallback
        .fill_matches_with_session(&mut session, haystack, window, &mut expected)
        .expect("fallback fill");

    let mut actual = 0xfeed_face_dead_beef;
    let report = program
        .fill_matches(haystack, window, &mut actual)
        .expect("shared fill");
    assert_eq!(expected[0], actual);
    assert_eq!(actual, report.matched_mask());
    assert_eq!(actual.count_ones(), report.matched_count());
    assert_eq!(actual != 0, report.any());
}

#[test]
fn generated_public_cardinalities_match_independent_rows() {
    for pattern_count in [2, 3, 5, 8, 63, 64] {
        let patterns = (0..pattern_count)
            .map(|ordinal| format!("public{ordinal:02}tail"))
            .collect::<Vec<_>>();
        let program = selected(&patterns, RegexSetExact64Limits::default());
        assert_eq!(
            u8::try_from(pattern_count).unwrap(),
            program.receipt().pattern_count()
        );
        assert_eq!(
            pattern_count == 64,
            program.receipt().all_pattern_mask() == u64::MAX
        );

        let negative = b"a generated negative control";
        assert_matches_fallback(&program, negative, SearchWindow::full(negative));
        let late = format!("negative-prefix-{}", patterns[pattern_count - 1]);
        assert_matches_fallback(
            &program,
            late.as_bytes(),
            SearchWindow::full(late.as_bytes()),
        );

        let dense = patterns.join("|");
        assert_matches_fallback(
            &program,
            dense.as_bytes(),
            SearchWindow::full(dense.as_bytes()),
        );
    }
}

#[test]
fn duplicates_prefixes_and_failure_outputs_keep_every_source_bit() {
    let patterns = ["he", "she", "hers", "he", "e"].map(str::to_owned).to_vec();
    let program = selected(&patterns, RegexSetExact64Limits::default());

    let mut output = 0;
    program
        .fill_matches(b"she", SearchWindow::new(0, 3), &mut output)
        .unwrap();
    assert_eq!(
        0b1_1011, output,
        "`she` inherits `he` and `e`, including duplicate `he`"
    );
    assert_matches_fallback(&program, b"ushers", SearchWindow::new(0, 6));
    assert_matches_fallback(&program, b"nomatch", SearchWindow::new(0, 7));
}

#[test]
fn generated_small_inputs_match_the_independent_stock_set_oracle() {
    let patterns = ["he", "she", "e", "he"].map(str::to_owned).to_vec();
    let program = selected(&patterns, RegexSetExact64Limits::default());
    let oracle = stock_oracle(&patterns);
    let alphabet = [b'h', b's', b'e', b'x'];
    let mut haystacks = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..4 {
        let mut next_frontier = Vec::new();
        for haystack in &frontier {
            for &byte in &alphabet {
                let mut next = haystack.clone();
                next.push(byte);
                haystacks.push(next.clone());
                next_frontier.push(next);
            }
        }
        frontier = next_frontier;
    }

    for haystack in haystacks {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = SearchWindow::new(start, end);
                let mut actual = u64::MAX;
                program
                    .fill_matches(&haystack, window, &mut actual)
                    .expect("exact64 oracle fill");
                assert_eq!(
                    stock_mask(&oracle, &haystack, window),
                    actual,
                    "haystack={haystack:?} window={start}..{end}"
                );
            }
        }
    }
}

#[test]
fn byte_literals_and_window_boundaries_match_the_semantic_incumbent() {
    let patterns = [r"(?-u:\x00\xFF)", r"\n", r"(?-u:\xFF)"]
        .map(str::to_owned)
        .to_vec();
    let program = selected(&patterns, RegexSetExact64Limits::default());
    let haystack = [b'x', 0, 0xff, b'\n', b'y'];
    for (start, end) in [(0, 5), (1, 3), (2, 4), (3, 3), (4, 5)] {
        assert_matches_fallback(&program, &haystack, SearchWindow::new(start, end));
    }

    let boundary_patterns = ["abc".to_owned(), "bc".to_owned()];
    let boundary = selected(&boundary_patterns, RegexSetExact64Limits::default());
    let haystack = b"xabcx";
    for (start, end) in [(0, 5), (1, 4), (2, 4), (1, 3), (4, 4)] {
        assert_matches_fallback(&boundary, haystack, SearchWindow::new(start, end));
    }
}

#[test]
fn canonical_capture_concat_and_fixed_repetition_shapes_select() {
    let patterns = [r"(?:ab){2}", r"(?P<label>cd)", r"x(?:yz)q"]
        .map(str::to_owned)
        .to_vec();
    let program = selected(&patterns, RegexSetExact64Limits::default());
    for haystack in [
        b"negative".as_slice(),
        b"prefix-abab-suffix".as_slice(),
        b"cd and xyzq".as_slice(),
    ] {
        assert_matches_fallback(&program, haystack, SearchWindow::full(haystack));
    }
}

#[test]
fn invalid_window_is_transactional() {
    let patterns = ["ab".to_owned(), "bc".to_owned()];
    let program = selected(&patterns, RegexSetExact64Limits::default());
    let sentinel = 0xfeed_face_dead_beef;
    let mut output = sentinel;
    assert!(matches!(
        program.fill_matches(b"abc", SearchWindow::new(2, 4), &mut output),
        Err(RegexSetExact64RunError::InvalidWindow {
            start: 2,
            end: 4,
            haystack_len: 3,
        })
    ));
    assert_eq!(sentinel, output);
}

#[test]
fn semantic_ineligibility_declines_to_the_exact_incumbent() {
    let fast_patterns = ["a".to_owned(), "b".to_owned()];
    let fast = request(&fast_patterns).mode(CompileMode::Fast);
    assert!(matches!(
        compile_regex_set_exact64_reported(fast, RegexSetExact64Limits::default()).unwrap(),
        RegexSetExact64CompileDisposition::Declined {
            reason: RegexSetExact64Decline::RequiresOptimizing {
                actual: CompileMode::Fast,
            },
            ..
        }
    ));

    for patterns in [
        Vec::new(),
        vec!["only".to_owned()],
        (0..=REGEX_SET_EXACT64_MAX_PATTERNS)
            .map(|ordinal| format!("row{ordinal}"))
            .collect(),
    ] {
        let count = patterns.len();
        assert!(matches!(
            compile_regex_set_exact64_reported(
                request(&patterns),
                RegexSetExact64Limits::default()
            )
            .unwrap(),
            RegexSetExact64CompileDisposition::Declined {
                reason: RegexSetExact64Decline::PatternCount { needed, .. },
                ..
            } if needed == count
        ));
    }

    for (patterns, declined_pattern) in [
        (vec!["a|b".to_owned(), "c".to_owned()], 0),
        (vec!["a".to_owned(), String::new()], 1),
        (vec!["a".to_owned(), "^b".to_owned()], 1),
        (vec!["a".to_owned(), "(?i:b)".to_owned()], 1),
    ] {
        let ordinary = compile_regex_set(request(&patterns)).unwrap();
        let disposition = compile_regex_set_exact64_reported(
            request(&patterns),
            RegexSetExact64Limits::default(),
        )
        .unwrap();
        let RegexSetExact64CompileDisposition::Declined { program, reason } = disposition else {
            panic!("ineligible source selected exact64");
        };
        assert_eq!(ordinary.artifact_identity(), program.artifact_identity());
        assert_eq!(
            RegexSetExact64Decline::RowNotExactSingleton {
                pattern: declined_pattern,
            },
            reason
        );
    }

    let assertive = ["^public".to_owned(), "tail".to_owned()];
    for limits in [
        RegexSetExact64Limits {
            max_literal_bytes: 0,
            ..RegexSetExact64Limits::default()
        },
        RegexSetExact64Limits {
            max_states: 0,
            ..RegexSetExact64Limits::default()
        },
        RegexSetExact64Limits {
            max_transition_cells: 0,
            ..RegexSetExact64Limits::default()
        },
    ] {
        assert!(matches!(
            compile_regex_set_exact64_reported(request(&assertive), limits).unwrap(),
            RegexSetExact64CompileDisposition::Declined {
                reason: RegexSetExact64Decline::RowNotExactSingleton { pattern: 0 },
                ..
            }
        ));
    }

    let later_alternation = ["xx".to_owned(), "a|b".to_owned()];
    assert!(matches!(
        compile_regex_set_exact64_reported(
            request(&later_alternation),
            RegexSetExact64Limits {
                max_literal_bytes: 1,
                ..RegexSetExact64Limits::default()
            },
        )
        .unwrap(),
        RegexSetExact64CompileDisposition::Declined {
            reason: RegexSetExact64Decline::RowNotExactSingleton { pattern: 1 },
            ..
        }
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one generated matrix exercises every exact and one-under numeric boundary"
)]
fn only_explicit_numeric_caps_decline_after_candidate_proof() {
    let single_byte_patterns = ["a".to_owned(), "b".to_owned()];
    for (limits, expected_resource) in [
        (
            RegexSetExact64Limits {
                max_literal_bytes: 1,
                ..RegexSetExact64Limits::default()
            },
            RegexSetExact64Resource::LiteralBytes,
        ),
        (
            RegexSetExact64Limits {
                max_states: 1,
                ..RegexSetExact64Limits::default()
            },
            RegexSetExact64Resource::States,
        ),
        (
            RegexSetExact64Limits {
                max_transition_cells: 0,
                ..RegexSetExact64Limits::default()
            },
            RegexSetExact64Resource::TransitionCells,
        ),
    ] {
        assert!(matches!(
            compile_regex_set_exact64_reported(request(&single_byte_patterns), limits).unwrap(),
            RegexSetExact64CompileDisposition::Declined {
                reason: RegexSetExact64Decline::Resource { resource, .. },
                ..
            } if resource == expected_resource
        ));
    }

    let no_failure_work = selected(
        &single_byte_patterns,
        RegexSetExact64Limits {
            max_failure_steps: 0,
            ..RegexSetExact64Limits::default()
        },
    );
    assert_eq!(0, no_failure_work.receipt().failure_steps());

    let patterns = ["ab".to_owned(), "ac".to_owned()];
    let selected_default = selected(&patterns, RegexSetExact64Limits::default());
    let receipt = selected_default.receipt();
    assert!(receipt.failure_steps() > 0);

    let exact = RegexSetExact64Limits {
        max_literal_bytes: usize::try_from(receipt.literal_bytes()).unwrap(),
        max_states: usize::try_from(receipt.state_count()).unwrap(),
        max_transition_cells: usize::try_from(receipt.transition_count()).unwrap(),
        max_failure_steps: receipt.failure_steps(),
    };
    let at_limit = selected(&patterns, exact);
    assert_eq!(receipt.state_count(), at_limit.receipt().state_count());

    let cases = [
        (
            RegexSetExact64Limits {
                max_literal_bytes: exact.max_literal_bytes - 1,
                ..exact
            },
            RegexSetExact64Resource::LiteralBytes,
        ),
        (
            RegexSetExact64Limits {
                max_states: exact.max_states - 1,
                ..exact
            },
            RegexSetExact64Resource::States,
        ),
        (
            RegexSetExact64Limits {
                max_transition_cells: exact.max_transition_cells - 1,
                ..exact
            },
            RegexSetExact64Resource::TransitionCells,
        ),
        (
            RegexSetExact64Limits {
                max_failure_steps: exact.max_failure_steps - 1,
                ..exact
            },
            RegexSetExact64Resource::FailureSteps,
        ),
    ];
    for (limits, expected_resource) in cases {
        let disposition = compile_regex_set_exact64_reported(request(&patterns), limits).unwrap();
        let RegexSetExact64CompileDisposition::Declined { reason, .. } = disposition else {
            panic!("one-under resource ceiling unexpectedly selected exact64");
        };
        let RegexSetExact64Decline::Resource {
            resource,
            needed,
            limit,
        } = reason
        else {
            panic!("one-under resource ceiling returned a semantic decline");
        };
        assert_eq!(expected_resource, resource);
        assert_eq!(limit.checked_add(1), Some(needed));
    }
}

#[test]
fn identity_is_deterministic_and_binds_source_order() {
    let first_patterns = ["alpha".to_owned(), "beta".to_owned()];
    let reverse_patterns = ["beta".to_owned(), "alpha".to_owned()];
    let ordinary = compile_regex_set(request(&first_patterns)).unwrap();
    let first = selected(&first_patterns, RegexSetExact64Limits::default());
    let independent = selected(&first_patterns, RegexSetExact64Limits::default());
    let reverse = selected(&reverse_patterns, RegexSetExact64Limits::default());
    assert_eq!(
        first.receipt().artifact_identity(),
        independent.receipt().artifact_identity()
    );
    assert_eq!(
        ordinary.artifact_identity(),
        first.fallback().artifact_identity(),
    );
    assert_ne!(
        first.receipt().artifact_identity(),
        reverse.receipt().artifact_identity()
    );
    assert_ne!(
        first.receipt().source_mapping_digest(),
        reverse.receipt().source_mapping_digest()
    );
}

#[test]
fn constituent_compile_failures_remain_closed_and_indexed() {
    for patterns in [
        ["a".to_owned(), "(".to_owned(), "b".to_owned()],
        ["a|b".to_owned(), "(".to_owned(), "c".to_owned()],
    ] {
        assert!(matches!(
            compile_regex_set_exact64_reported(
                request(&patterns),
                RegexSetExact64Limits::default()
            ),
            Err(RegexSetExact64CompileError::RegexSet(
                RegexSetCompileError::Pattern {
                    pattern: 1,
                    source: CompileError::Syntax(_),
                }
            ))
        ));
    }

    let outside_cardinality = ["(".to_owned()];
    assert!(matches!(
        compile_regex_set_exact64_reported(
            request(&outside_cardinality),
            RegexSetExact64Limits::default(),
        ),
        Err(RegexSetExact64CompileError::RegexSet(
            RegexSetCompileError::Pattern {
                pattern: 0,
                source: CompileError::Syntax(_),
            }
        ))
    ));

    let fast_invalid = ["a".to_owned(), "(".to_owned()];
    assert!(matches!(
        compile_regex_set_exact64_reported(
            request(&fast_invalid).mode(CompileMode::Fast),
            RegexSetExact64Limits::default(),
        ),
        Err(RegexSetExact64CompileError::RegexSet(
            RegexSetCompileError::Pattern {
                pattern: 1,
                source: CompileError::Syntax(_),
            }
        ))
    ));
}
