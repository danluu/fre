#![forbid(unsafe_code)]

use fre_aot_regex::{
    CompileError, CompileMode, RegexSetCompileError, RegexSetCompileLimits, RegexSetCompileRequest,
    RegexSetOutputError, RegexSetRunError, RegexSetSessionLimits, SearchWindow, compile_regex_set,
};
use regex_automata::{Input, MatchKind, PatternSet, meta::Regex as MetaRegex};

fn strings(patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

fn compile(patterns: &[&str]) -> fre_aot_regex::RegexSetProgram {
    compile_regex_set(RegexSetCompileRequest::new(strings(patterns)).mode(CompileMode::Fast))
        .expect("regex-set program")
}

fn oracle(patterns: &[&str]) -> MetaRegex {
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
        .expect("regex-automata set oracle")
}

fn oracle_ids(oracle: &MetaRegex, haystack: &[u8], window: SearchWindow) -> Vec<usize> {
    let input = Input::new(haystack).span(window.start()..window.end());
    let mut matches = PatternSet::new(oracle.pattern_len());
    oracle.which_overlapping_matches(&input, &mut matches);
    matches.iter().map(|pattern| pattern.as_usize()).collect()
}

fn byte_strings(max_len: usize) -> Vec<Vec<u8>> {
    let alphabet = [b'a', b'b', b'\n', 0xff];
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in &alphabet {
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
fn independently_compiled_exists_rows_match_window_aware_set_oracle() {
    let patterns = [
        "a",
        "a",
        "(a)",
        "",
        "a?",
        r"(?-u:\xFF)",
        ".",
        r"(?-u:.)",
        r"\A.",
        r"(?m:^b$)",
    ];
    let oracle = oracle(&patterns);
    for mode in [CompileMode::Fast, CompileMode::Optimizing] {
        let program = compile_regex_set(RegexSetCompileRequest::new(strings(&patterns)).mode(mode))
            .expect("regex-set program");
        let mut session = program
            .prepare_session(RegexSetSessionLimits::unlimited())
            .expect("set session");
        let mut output = vec![u64::MAX; program.required_words()];

        for haystack in byte_strings(3) {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    output.fill(u64::MAX);
                    let report = program
                        .fill_matches_with_session(&mut session, &haystack, window, &mut output)
                        .expect("set fill");
                    let expected = oracle_ids(&oracle, &haystack, window);
                    let actual = program
                        .matching_pattern_ids(&output)
                        .expect("valid published bits")
                        .collect::<Vec<_>>();
                    assert_eq!(
                        expected, actual,
                        "mode={mode:?} patterns={patterns:?} haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(expected.len(), report.matched_count());
                    assert_eq!(program.required_words(), report.word_count());
                    assert_eq!(!expected.is_empty(), report.any());
                }
            }
        }
    }
}

#[test]
fn zero_patterns_are_valid_and_still_validate_the_window() {
    let program = compile(&[]);
    assert!(program.is_empty());
    assert_eq!(0, program.required_words());
    let mut session = program
        .prepare_session(RegexSetSessionLimits::default())
        .unwrap();
    let report = program
        .fill_matches_with_session(&mut session, b"abc", SearchWindow::new(1, 2), &mut [])
        .unwrap();
    assert_eq!(
        (0, 0, false),
        (report.matched_count(), report.word_count(), report.any())
    );
    assert_eq!(
        Vec::<usize>::new(),
        program
            .matching_pattern_ids(&[])
            .unwrap()
            .collect::<Vec<_>>()
    );

    assert!(matches!(
        program.fill_matches_with_session(&mut session, b"abc", SearchWindow::new(2, 4), &mut [],),
        Err(RegexSetRunError::InvalidWindow {
            start: 2,
            end: 4,
            haystack_len: 3
        })
    ));
}

#[test]
fn more_than_128_patterns_have_distinct_source_bits_and_zero_tail() {
    let patterns = ["a"; 129];
    let below = RegexSetCompileLimits {
        max_patterns: 128,
        ..RegexSetCompileLimits::default()
    };
    assert!(matches!(
        compile_regex_set(
            RegexSetCompileRequest::new(strings(&patterns))
                .mode(CompileMode::Fast)
                .limits(below)
        ),
        Err(RegexSetCompileError::PatternLimit {
            needed: 129,
            limit: 128
        })
    ));

    let program = compile(&patterns);
    assert_eq!((129, 3), (program.len(), program.required_words()));
    let mut session = program
        .prepare_session(RegexSetSessionLimits::unlimited())
        .unwrap();
    let mut output = vec![u64::MAX; 3];
    let report = program
        .fill_matches_with_session(&mut session, b"a", SearchWindow::new(0, 1), &mut output)
        .unwrap();
    assert_eq!(129, report.matched_count());
    assert_eq!([u64::MAX, u64::MAX, 1], output.as_slice());
    assert_eq!(
        (0..129).collect::<Vec<_>>(),
        program
            .matching_pattern_ids(&output)
            .unwrap()
            .collect::<Vec<_>>()
    );
}

#[test]
fn stable_identity_binds_order_while_sessions_require_clone_lineage() {
    let first = compile(&["a", "b"]);
    let independent = compile(&["a", "b"]);
    let reversed = compile(&["b", "a"]);
    assert_eq!(first.artifact_identity(), independent.artifact_identity());
    assert_ne!(first.artifact_identity(), reversed.artifact_identity());

    let mut session = first
        .prepare_session(RegexSetSessionLimits::unlimited())
        .unwrap();
    let mut output = [0xfeed_face_dead_beef];
    assert!(matches!(
        independent.fill_matches_with_session(
            &mut session,
            b"a",
            SearchWindow::new(0, 1),
            &mut output,
        ),
        Err(RegexSetRunError::SessionProgramMismatch {
            clone_lineage_matches: false,
            ..
        })
    ));
    assert_eq!([0xfeed_face_dead_beef], output);

    let cloned = first.clone();
    cloned
        .fill_matches_with_session(&mut session, b"a", SearchWindow::new(0, 1), &mut output)
        .expect("clone-lineage session reuse");
    assert_eq!([1], output);
}

#[test]
fn strict_output_and_source_limits_fail_without_partial_publication() {
    let program = compile(&["a", "b"]);
    let limits = RegexSetSessionLimits {
        max_source_bytes: 1,
        ..RegexSetSessionLimits::unlimited()
    };
    let mut session = program.prepare_session(limits).unwrap();

    let mut short: [u64; 0] = [];
    assert!(matches!(
        program.fill_matches_with_session(&mut session, b"a", SearchWindow::new(0, 1), &mut short,),
        Err(RegexSetRunError::OutputWordCount {
            expected: 1,
            actual: 0
        })
    ));
    assert!(short.is_empty());

    let sentinel = 0xf0f0_f0f0_f0f0_f0f0;
    let mut exact = [sentinel];
    assert!(matches!(
        program
            .fill_matches_with_session(&mut session, b"ab", SearchWindow::new(0, 2), &mut exact,),
        Err(RegexSetRunError::SourceBytesLimit {
            needed: 2,
            limit: 1
        })
    ));
    assert_eq!([sentinel], exact);

    let mut long = [sentinel; 2];
    assert!(matches!(
        program.fill_matches_with_session(&mut session, b"a", SearchWindow::new(0, 1), &mut long,),
        Err(RegexSetRunError::OutputWordCount {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!([sentinel; 2], long);
}

#[test]
fn standalone_bit_iteration_rejects_capacity_and_nonzero_tail() {
    let program = compile(&["a", "b"]);
    assert!(matches!(
        program.matching_pattern_ids(&[]),
        Err(RegexSetOutputError::WordCount {
            expected: 1,
            actual: 0
        })
    ));
    assert!(matches!(
        program.matching_pattern_ids(&[1_u64 << 63]),
        Err(RegexSetOutputError::NonZeroTailBits {
            word: 0,
            allowed_mask: 3,
            ..
        })
    ));
    let mut ids = program.matching_pattern_ids(&[3]).unwrap();
    assert_eq!(2, ids.len());
    assert_eq!(Some(0), ids.next());
    assert_eq!(1, ids.len());
    assert_eq!(Some(1), ids.next());
    assert_eq!(None, ids.next());
}

#[test]
fn compile_and_prepare_limits_report_exact_indexed_failures() {
    assert!(matches!(
        compile_regex_set(
            RegexSetCompileRequest::new(strings(&["a", "(", "b"])).mode(CompileMode::Fast)
        ),
        Err(RegexSetCompileError::Pattern {
            pattern: 1,
            source: CompileError::Syntax(_)
        })
    ));

    let source_limits = RegexSetCompileLimits {
        max_pattern_bytes: 1,
        ..RegexSetCompileLimits::default()
    };
    assert!(matches!(
        compile_regex_set(
            RegexSetCompileRequest::new(strings(&["a", "b"]))
                .mode(CompileMode::Fast)
                .limits(source_limits)
        ),
        Err(RegexSetCompileError::PatternBytesLimit {
            pattern: 1,
            needed: 2,
            limit: 1
        })
    ));

    let program = compile(&["a"]);
    let bytes = program.stats().serialized_program_bytes;
    let byte_limits = RegexSetCompileLimits {
        max_total_program_bytes: bytes - 1,
        ..RegexSetCompileLimits::default()
    };
    assert!(matches!(
        compile_regex_set(
            RegexSetCompileRequest::new(strings(&["a"]))
                .mode(CompileMode::Fast)
                .limits(byte_limits)
        ),
        Err(RegexSetCompileError::TotalProgramBytesLimit {
            pattern: 0,
            needed,
            limit
        }) if needed == bytes && limit == bytes - 1
    ));

    let workspace_limits = RegexSetSessionLimits {
        max_workspace_rows: 0,
        ..RegexSetSessionLimits::unlimited()
    };
    assert!(matches!(
        program.prepare_session(workspace_limits),
        Err(fre_aot_regex::RegexSetPrepareError::WorkspaceRowsLimit {
            needed: 1,
            limit: 0
        })
    ));
    let staging_limits = RegexSetSessionLimits {
        max_staging_words: 0,
        ..RegexSetSessionLimits::unlimited()
    };
    assert!(matches!(
        program.prepare_session(staging_limits),
        Err(fre_aot_regex::RegexSetPrepareError::StagingWordsLimit {
            needed: 1,
            limit: 0
        })
    ));
}

#[test]
fn aggregate_admission_failure_remains_unindexed() {
    let mut profile = fre_syntax::RustProfile::regex_set_1_12_4();
    let fre_syntax::RustConstructor::RegexSetBuilder { size_limit, .. } = &mut profile.constructor
    else {
        unreachable!("set profile constructor")
    };
    *size_limit = 0;
    assert!(matches!(
        compile_regex_set(
            RegexSetCompileRequest::new(strings(&["a"]))
                .profile(profile)
                .mode(CompileMode::Fast)
        ),
        Err(RegexSetCompileError::AggregateAdmission { .. })
    ));
}
