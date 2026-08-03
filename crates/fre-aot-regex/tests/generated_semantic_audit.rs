//! Broad, deterministic generated semantic audit for the general AOT compiler.
//!
//! This is deliberately ignored because it checks millions of windows. Run it with:
//! `cargo test -p fre-aot-regex --test generated_semantic_audit --release -- --ignored --nocapture --test-threads=1`
//!
//! All patterns and haystacks are constructed below. This test does not consume an
//! external benchmark corpus.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "the audit intentionally checks exact bounded wire offsets and coverage counters"
)]
#![allow(
    clippy::field_reassign_with_default,
    reason = "one-field mutations make adjacent exact and one-less resource-limit cases readable"
)]
#![allow(
    clippy::similar_names,
    reason = "DFA and NFA variant counts are intentionally parallel audit outputs"
)]
#![allow(
    clippy::too_many_lines,
    reason = "keeping each wire-format and differential audit phase together makes failures local"
)]

use std::collections::{BTreeMap, HashSet};

use fre_aot_regex::{
    CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompileResource, CompiledProgram,
    CompiledRegex, DeterminizeLimits, DfaStats, EngineKind, MatchResult, OutputContract,
    SearchWindow, SectionKind, Target, compile,
};
use regex::bytes::{Regex, RegexBuilder};

const NO_STATE: u32 = u32::MAX;

#[derive(Debug)]
struct ParsedDfa {
    build_work: u64,
    classes: usize,
    forward_states: usize,
    forward_transitions: usize,
    reverse_states: usize,
    reverse_transitions: usize,
}

fn add_pattern(patterns: &mut Vec<String>, seen: &mut HashSet<String>, pattern: String) {
    if seen.insert(pattern.clone()) {
        patterns.push(pattern);
    }
}

fn patterns() -> Vec<String> {
    let mut patterns = Vec::new();
    let mut seen = HashSet::new();
    for pattern in [
        "",
        "a",
        "a?",
        "a??",
        "a*",
        "a*?",
        "a+",
        "a+?",
        "a{0,2}",
        "a{0,2}?",
        "a{1,3}",
        "a{1,3}?",
        "a|aa",
        "aa|a",
        "a|ab",
        "ab|a",
        "(?:a|aa)+",
        "(?:aa|a)+",
        "(?:a|aa)+?",
        "(?:aa|a)+?",
        "(?:a??a)*",
        "(?:a??|aa)*?",
        "(?:a*|b)*",
        "(?:a*?|b)*?",
        "(?:|a)+",
        "(?:a|)*",
        "(?:a??a)*",
        "(?:a?a)+?",
        "(?:ab|a)+b",
        "(?:a|ab)+b",
        "(?:ab|a)+?b",
        "(?:a|ab)+?b",
        "[a-cx-z]+",
        "(?-u:[\\x00-\\x02\\x80-\\x82])+",
        "(?-u:\\x80)+?",
        "é+",
        "(?:é|éa)+",
        "(?:éa|é)+?",
        "\\p{Greek}+",
        "(?:\\p{Greek}|a)+?",
    ] {
        add_pattern(&mut patterns, &mut seen, pattern.to_owned());
    }

    let atoms = [
        "a",
        "b",
        "aa",
        "ab",
        "ba",
        "[ab]",
        "[a-c]",
        "(?-u:\\x80)",
        "é",
        "(?:a|ab)",
        "(?:ab|a)",
        "a?",
        "a??",
        "a*",
        "a*?",
    ];
    for atom in atoms {
        for suffix in [
            "?", "??", "*", "*?", "+", "+?", "{0,2}", "{0,2}?", "{1,3}", "{1,3}?",
        ] {
            add_pattern(&mut patterns, &mut seen, format!("(?:{atom}){suffix}"));
        }
    }

    let pair_atoms = [
        "a",
        "b",
        "aa",
        "ab",
        "[ab]",
        "a?",
        "a??",
        "(?:a|ab)",
        "(?:ab|a)",
        "(?-u:\\x80)",
        "é",
    ];
    for left in pair_atoms {
        for right in pair_atoms {
            for pattern in [
                format!("(?:{left})(?:{right})"),
                format!("(?:{left})|(?:{right})"),
                format!("(?:(?:{left})|(?:{right}))+"),
                format!("(?:(?:{left})|(?:{right}))+?"),
            ] {
                add_pattern(&mut patterns, &mut seen, pattern);
            }
        }
    }
    patterns
}

fn insert_words(
    output: &mut HashSet<Vec<u8>>,
    alphabet: &[u8],
    max_len: usize,
    current: &mut Vec<u8>,
) {
    output.insert(current.clone());
    if current.len() == max_len {
        return;
    }
    for &byte in alphabet {
        current.push(byte);
        insert_words(output, alphabet, max_len, current);
        current.pop();
    }
}

fn haystacks() -> Vec<Vec<u8>> {
    let mut set = HashSet::new();
    insert_words(&mut set, b"abx", 4, &mut Vec::new());
    insert_words(&mut set, &[0, b'a', 0x80, 0xff], 3, &mut Vec::new());
    insert_words(
        &mut set,
        &[b'a', 0xc3, 0xa9, 0xce, 0xb1],
        3,
        &mut Vec::new(),
    );
    for value in 0_u16..=255 {
        let byte = u8::try_from(value).unwrap();
        set.insert(vec![byte]);
        set.insert(vec![byte, b'a']);
        set.insert(vec![b'a', byte]);
    }
    for bytes in [
        b"aaaaab".as_slice(),
        b"ababaa".as_slice(),
        b"xxababa".as_slice(),
        "ééa".as_bytes(),
        "xαβa".as_bytes(),
        &[0xff, 0xc3, 0xa9, 0x80],
    ] {
        set.insert(bytes.to_vec());
    }
    let mut result: Vec<_> = set.into_iter().collect();
    result.sort_by(|left, right| left.len().cmp(&right.len()).then(left.cmp(right)));
    result
}

fn regex(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .build()
        .unwrap_or_else(|error| panic!("oracle rejected generated pattern {pattern:?}: {error}"))
}

fn compile_one(
    pattern: &str,
    mode: CompileMode,
    output: OutputContract,
    limits: CompileLimitsV1,
) -> CompiledRegex {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(mode)
            .output(output)
            .limits(limits),
    )
    .unwrap_or_else(|error| {
        panic!("compile failed: pattern={pattern:?} mode={mode:?} output={output:?}: {error}")
    })
}

fn oracle(regex: &Regex, haystack: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    regex
        .find_at(&haystack[..end], start)
        .map(|matched| (matched.start(), matched.end()))
}

fn rodata(compiled: &CompiledRegex) -> &[u8] {
    let sections: Vec<_> = compiled
        .module()
        .sections()
        .iter()
        .filter(|section| section.kind == SectionKind::ReadOnlyData)
        .collect();
    assert_eq!(sections.len(), 1);
    sections[0].bytes()
}

fn get_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    let end = cursor.checked_add(4).expect("u32 cursor");
    let value = u32::from_le_bytes(bytes[*cursor..end].try_into().expect("u32 bytes"));
    *cursor = end;
    value
}

fn get_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let end = cursor.checked_add(8).expect("u64 cursor");
    let value = u64::from_le_bytes(bytes[*cursor..end].try_into().expect("u64 bytes"));
    *cursor = end;
    value
}

fn skip(bytes: &[u8], cursor: &mut usize, count: usize) {
    *cursor = cursor.checked_add(count).expect("skip cursor");
    assert!(*cursor <= bytes.len(), "serialized field exceeds payload");
}

fn parse_serialized(
    compiled: &CompiledRegex,
    expected_output: OutputContract,
) -> Option<ParsedDfa> {
    let serialized = compiled.program().serialize().expect("serialize program");
    let bytes = serialized.as_slice();
    assert_eq!(bytes.len(), compiled.receipt().program_bytes);
    assert_eq!(&bytes[..8], b"FREGAOT\0");
    let mut cursor = 8;
    assert_eq!(get_u32(bytes, &mut cursor), 3);
    let engine = bytes[cursor];
    cursor += 1;
    assert_eq!(
        engine,
        match compiled.receipt().engine {
            EngineKind::OrderedNfa | EngineKind::OrderedContextDfa => 0,
            EngineKind::OrderedDfa => 1,
        }
    );
    assert_eq!(
        bytes[cursor],
        match expected_output {
            OutputContract::Exists => 0,
            OutputContract::SelectedEnd => 1,
            OutputContract::Span => 2,
        }
    );
    cursor += 1;
    assert_eq!(&bytes[cursor..cursor + 2], &[b'\n', 0]);
    cursor += 2;
    assert_eq!(
        usize::try_from(get_u64(bytes, &mut cursor)).expect("program total usize"),
        bytes.len()
    );

    let _start = get_u32(bytes, &mut cursor);
    let roles = usize::try_from(get_u64(bytes, &mut cursor)).expect("roles usize");
    let offsets = usize::try_from(get_u64(bytes, &mut cursor)).expect("offsets usize");
    let targets = usize::try_from(get_u64(bytes, &mut cursor)).expect("targets usize");
    let kinds = usize::try_from(get_u64(bytes, &mut cursor)).expect("kinds usize");
    let starts = usize::try_from(get_u64(bytes, &mut cursor)).expect("starts usize");
    let ends = usize::try_from(get_u64(bytes, &mut cursor)).expect("ends usize");
    skip(bytes, &mut cursor, roles);
    skip(
        bytes,
        &mut cursor,
        offsets.checked_mul(4).expect("offset bytes"),
    );
    skip(
        bytes,
        &mut cursor,
        targets.checked_mul(4).expect("target bytes"),
    );
    skip(bytes, &mut cursor, kinds);
    skip(bytes, &mut cursor, starts);
    skip(bytes, &mut cursor, ends);

    let dfa_len = usize::try_from(get_u64(bytes, &mut cursor)).expect("dfa usize");
    assert_eq!(bytes.len() - cursor, dfa_len);
    if engine == 0 {
        assert_eq!(dfa_len, 0);
        assert_eq!(cursor, bytes.len());
        return None;
    }

    let dfa_begin = cursor;
    let build_work = get_u64(bytes, &mut cursor);
    assert_ne!(build_work, 0);
    let classes = usize::try_from(get_u32(bytes, &mut cursor)).expect("classes");
    assert!((1..=256).contains(&classes));
    let byte_map = &bytes[cursor..cursor + 256];
    assert!(byte_map.iter().all(|&class| usize::from(class) < classes));
    cursor += 256;
    let representatives = &bytes[cursor..cursor + classes];
    cursor += classes;
    for (class, &representative) in representatives.iter().enumerate() {
        assert_eq!(usize::from(byte_map[usize::from(representative)]), class);
    }

    let forward_states = usize::try_from(get_u32(bytes, &mut cursor)).expect("forward states");
    let forward_transitions =
        usize::try_from(get_u64(bytes, &mut cursor)).expect("forward transitions");
    assert_eq!(
        forward_transitions,
        forward_states.checked_mul(classes).expect("forward shape")
    );
    assert!(matches!(bytes[cursor], 0 | 1));
    assert!(matches!(bytes[cursor + 1], 0 | 1));
    assert_eq!(&bytes[cursor + 2..cursor + 4], &[0, 0]);
    cursor += 4;
    let forward_states_before_minimization =
        usize::try_from(get_u32(bytes, &mut cursor)).expect("forward pre-min states");
    assert!(forward_states_before_minimization >= forward_states);
    for _ in 0..forward_transitions {
        let next = get_u32(bytes, &mut cursor);
        assert!(next == NO_STATE || usize::try_from(next).unwrap() < forward_states);
        assert!(matches!(bytes[cursor], 0 | 1));
        assert_eq!(&bytes[cursor + 1..cursor + 4], &[0, 0, 0]);
        cursor += 4;
    }

    let reverse_states = usize::try_from(get_u32(bytes, &mut cursor)).expect("reverse states");
    let reverse_transitions =
        usize::try_from(get_u64(bytes, &mut cursor)).expect("reverse transitions");
    assert_eq!(
        reverse_transitions,
        reverse_states.checked_mul(classes).expect("reverse shape")
    );
    let reverse_present = bytes[cursor];
    assert!(matches!(reverse_present, 0 | 1));
    assert_eq!(&bytes[cursor + 1..cursor + 4], &[0, 0, 0]);
    cursor += 4;
    let reverse_states_before_minimization =
        usize::try_from(get_u32(bytes, &mut cursor)).expect("reverse pre-min states");
    assert!(reverse_states_before_minimization >= reverse_states);
    assert_eq!(reverse_present == 1, reverse_states != 0);
    for _ in 0..reverse_transitions {
        let next = get_u32(bytes, &mut cursor);
        assert!(next == NO_STATE || usize::try_from(next).unwrap() < reverse_states);
        assert!(matches!(bytes[cursor], 0 | 1));
        assert_eq!(&bytes[cursor + 1..cursor + 4], &[0, 0, 0]);
        cursor += 4;
    }
    assert_eq!(cursor - dfa_begin, dfa_len);
    assert_eq!(cursor, bytes.len());
    Some(ParsedDfa {
        build_work,
        classes,
        forward_states,
        forward_transitions,
        reverse_states,
        reverse_transitions,
    })
}

fn roundtrip(compiled: &CompiledRegex) -> CompiledProgram {
    let bytes = compiled.program().serialize().expect("serialize roundtrip");
    assert_eq!(
        CompiledProgram::serialized_len_from_header(&bytes[..fre_aot_regex::PROGRAM_HEADER_LEN])
            .unwrap(),
        bytes.len()
    );
    let restored = CompiledProgram::deserialize(&bytes).expect("deserialize roundtrip");
    assert_eq!(
        restored.output_contract(),
        compiled.program().output_contract()
    );
    assert_eq!(restored.engine_kind(), compiled.program().engine_kind());
    assert_eq!(restored.serialize().unwrap(), bytes);
    restored
}

fn assert_stats(stats: DfaStats) {
    assert!((1..=256).contains(&stats.boundary_classes));
    assert!((1..=stats.boundary_classes).contains(&stats.alphabet_classes));
    assert_eq!(
        stats.forward_transitions,
        stats.forward_states * stats.alphabet_classes
    );
    assert_eq!(
        stats.reverse_transitions,
        stats.reverse_states * stats.alphabet_classes
    );
}

fn differential_spans(patterns: &[String], haystacks: &[Vec<u8>]) -> (usize, usize) {
    let mut windows = 0_usize;
    let mut coalesced = 0_usize;
    for (pattern_index, pattern) in patterns.iter().enumerate() {
        let oracle_regex = regex(pattern);
        let fast = compile_one(
            pattern,
            CompileMode::Fast,
            OutputContract::Span,
            CompileLimitsV1::default(),
        );
        let optimized = compile_one(
            pattern,
            CompileMode::Optimizing,
            OutputContract::Span,
            CompileLimitsV1::default(),
        );
        assert_eq!(fast.receipt().engine, EngineKind::OrderedNfa, "{pattern:?}");
        assert_eq!(
            optimized.receipt().engine,
            EngineKind::OrderedDfa,
            "default determinization unexpectedly declined {pattern:?}"
        );
        assert!(parse_serialized(&fast, OutputContract::Span).is_none());
        let fast_restored = roundtrip(&fast);
        let parsed = parse_serialized(&optimized, OutputContract::Span).expect("DFA payload");
        let optimized_restored = roundtrip(&optimized);
        let stats = optimized.receipt().dfa.expect("DFA stats");
        assert_eq!(stats.alphabet_classes, parsed.classes);
        assert_eq!(stats.build_work, parsed.build_work);
        assert_eq!(stats.forward_states, parsed.forward_states);
        assert_eq!(stats.forward_transitions, parsed.forward_transitions);
        assert_eq!(stats.reverse_states, parsed.reverse_states);
        assert_eq!(stats.reverse_transitions, parsed.reverse_transitions);
        assert_stats(stats);
        let native_data = rodata(&optimized);
        assert!(!native_data.is_empty(), "native data for {pattern:?}");
        assert_eq!(
            native_data.len(),
            optimized.receipt().data_bytes,
            "native data receipt for {pattern:?}"
        );
        coalesced += usize::from(stats.alphabet_classes < stats.boundary_classes);
        let mut fast_workspace = fast.program().prepare_workspace().unwrap();
        let mut optimized_workspace = optimized.program().prepare_workspace().unwrap();
        let mut fast_restored_workspace = fast_restored.prepare_workspace().unwrap();
        let mut optimized_restored_workspace = optimized_restored.prepare_workspace().unwrap();

        let check_contracts = pattern_index < 48;
        let contracts = check_contracts.then(|| {
            (
                compile_one(
                    pattern,
                    CompileMode::Fast,
                    OutputContract::Exists,
                    CompileLimitsV1::default(),
                ),
                compile_one(
                    pattern,
                    CompileMode::Optimizing,
                    OutputContract::Exists,
                    CompileLimitsV1::default(),
                ),
                compile_one(
                    pattern,
                    CompileMode::Fast,
                    OutputContract::SelectedEnd,
                    CompileLimitsV1::default(),
                ),
                compile_one(
                    pattern,
                    CompileMode::Optimizing,
                    OutputContract::SelectedEnd,
                    CompileLimitsV1::default(),
                ),
            )
        });
        if let Some((fast_exists, opt_exists, fast_end, opt_end)) = contracts.as_ref() {
            assert!(parse_serialized(fast_exists, OutputContract::Exists).is_none());
            assert!(parse_serialized(opt_exists, OutputContract::Exists).is_some());
            let _ = roundtrip(fast_exists);
            let _ = roundtrip(opt_exists);
            let exists_data = rodata(opt_exists);
            assert!(!exists_data.is_empty());
            assert_eq!(
                exists_data.len(),
                opt_exists.receipt().data_bytes,
                "Exists native data receipt for {pattern:?}"
            );
            assert!(parse_serialized(fast_end, OutputContract::SelectedEnd).is_none());
            assert!(parse_serialized(opt_end, OutputContract::SelectedEnd).is_some());
            let _ = roundtrip(fast_end);
            let _ = roundtrip(opt_end);
            let end_data = rodata(opt_end);
            assert!(!end_data.is_empty());
            assert_eq!(
                end_data.len(),
                opt_end.receipt().data_bytes,
                "SelectedEnd native data receipt for {pattern:?}"
            );
        }

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    windows += 1;
                    let expected_span = oracle(&oracle_regex, haystack, start, end);
                    let window = SearchWindow::new(start, end);
                    let expected = MatchResult::Span(expected_span);
                    let fast_result = fast
                        .program()
                        .search_with_workspace(haystack, window, &mut fast_workspace)
                        .unwrap_or_else(|error| {
                            panic!(
                                "fast search error: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}: {error}"
                            )
                        });
                    let optimized_result = optimized
                        .program()
                        .search_with_workspace(haystack, window, &mut optimized_workspace)
                        .unwrap_or_else(|error| {
                            panic!(
                                "optimized search error: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}: {error}"
                            )
                        });
                    assert_eq!(
                        fast_result, expected,
                        "fast mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                    );
                    assert_eq!(
                        optimized_result, expected,
                        "optimized mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                    );
                    assert_eq!(
                        fast_restored
                            .search_with_workspace(haystack, window, &mut fast_restored_workspace,)
                            .unwrap(),
                        expected,
                        "roundtripped fast mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                    );
                    assert_eq!(
                        optimized_restored
                            .search_with_workspace(
                                haystack,
                                window,
                                &mut optimized_restored_workspace,
                            )
                            .unwrap(),
                        expected,
                        "roundtripped optimized mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                    );

                    if let Some((fast_exists, opt_exists, fast_end, opt_end)) = contracts.as_ref() {
                        let expected_exists = MatchResult::Exists(expected_span.is_some());
                        let expected_end =
                            MatchResult::SelectedEnd(expected_span.map(|(_, end)| end));
                        assert_eq!(
                            fast_exists.search(haystack, window).unwrap(),
                            expected_exists,
                            "fast Exists mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                        );
                        assert_eq!(
                            opt_exists.search(haystack, window).unwrap(),
                            expected_exists,
                            "optimized Exists mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                        );
                        assert_eq!(
                            fast_end.search(haystack, window).unwrap(),
                            expected_end,
                            "fast SelectedEnd mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                        );
                        assert_eq!(
                            opt_end.search(haystack, window).unwrap(),
                            expected_end,
                            "optimized SelectedEnd mismatch: pattern={pattern:?} haystack={haystack:02x?} window={start}..{end}"
                        );
                    }
                }
            }
        }
    }
    (windows, coalesced)
}

fn fallback_limits(haystacks: &[Vec<u8>]) -> (usize, usize, usize) {
    let patterns = [
        "a",
        "a|ab",
        "ab|a",
        "a*",
        "a*?",
        "(?:a??a)*",
        "(?:ab|a)+?b",
        "[a-cx-z]+",
        "(?-u:[\\x00-\\x02\\x80-\\x82])+",
        "(?:é|éa)+",
    ];
    let mut checked = 0;
    let mut dfa_variants = 0;
    let mut nfa_variants = 0;
    for pattern in patterns {
        let reference = compile_one(
            pattern,
            CompileMode::Fast,
            OutputContract::Span,
            CompileLimitsV1::default(),
        );
        let baseline = compile_one(
            pattern,
            CompileMode::Optimizing,
            OutputContract::Span,
            CompileLimitsV1::default(),
        );
        let stats = baseline.receipt().dfa.expect("baseline DFA");
        let construction_states = stats
            .forward_states_before_minimization
            .saturating_add(stats.reverse_states_before_minimization);
        let mut variants = Vec::new();
        for determinize in [
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_transitions: 0,
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_work: 0,
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_states: construction_states,
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_states: construction_states.saturating_sub(1),
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_work: stats.build_work,
                ..DeterminizeLimits::default()
            },
            DeterminizeLimits {
                max_work: stats.build_work.saturating_sub(1),
                ..DeterminizeLimits::default()
            },
        ] {
            let mut limits = CompileLimitsV1::default();
            limits.determinize = determinize;
            variants.push(compile_one(
                pattern,
                CompileMode::Optimizing,
                OutputContract::Span,
                limits,
            ));
        }
        assert_eq!(variants[0].receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(variants[1].receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(variants[2].receipt().engine, EngineKind::OrderedNfa);
        assert_eq!(variants[3].receipt().engine, EngineKind::OrderedDfa);
        assert_eq!(
            variants[4].receipt().engine,
            EngineKind::OrderedNfa,
            "one-less state limit did not decline {pattern:?}"
        );
        assert_eq!(variants[5].receipt().engine, EngineKind::OrderedDfa);
        assert_eq!(
            variants[6].receipt().engine,
            EngineKind::OrderedNfa,
            "one-less work limit did not decline {pattern:?}"
        );
        dfa_variants += variants
            .iter()
            .filter(|variant| variant.receipt().engine == EngineKind::OrderedDfa)
            .count();
        nfa_variants += variants
            .iter()
            .filter(|variant| variant.receipt().engine == EngineKind::OrderedNfa)
            .count();

        for haystack in haystacks.iter().take(180) {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = reference.search(haystack, window).unwrap();
                    for variant in &variants {
                        checked += 1;
                        assert_eq!(
                            variant.search(haystack, window).unwrap(),
                            expected,
                            "fallback mismatch: pattern={pattern:?} engine={:?} haystack={haystack:02x?} window={start}..{end}",
                            variant.receipt().engine
                        );
                    }
                }
            }
        }
    }
    (checked, dfa_variants, nfa_variants)
}

fn serialization_resource_boundaries() -> usize {
    let patterns = [
        "",
        "a|ab",
        "(?:ab|a)+?b",
        "[a-cx-z]+",
        "(?-u:[\\x00-\\x02\\x80-\\x82])+",
        "(?:é|éa)+",
    ];
    let mut checks = 0;
    for pattern in patterns {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let baseline = compile_one(
                pattern,
                mode,
                OutputContract::Span,
                CompileLimitsV1::default(),
            );
            let expected_bytes = baseline.receipt().program_bytes;
            let baseline_program = baseline.program().serialize().unwrap();
            assert_eq!(baseline_program.len(), expected_bytes);
            let _ = roundtrip(&baseline);

            let mut exact_limits = CompileLimitsV1::default();
            exact_limits.max_program_bytes = expected_bytes;
            let exact = compile_one(pattern, mode, OutputContract::Span, exact_limits);
            assert_eq!(exact.program().serialize().unwrap(), baseline_program);
            assert_eq!(
                exact.module().entry_symbol(),
                baseline.module().entry_symbol()
            );
            checks += 1;

            if expected_bytes != 0 {
                let mut short_limits = CompileLimitsV1::default();
                short_limits.max_program_bytes = expected_bytes - 1;
                match compile(
                    CompileRequest::new(pattern, Target::x86_64_linux())
                        .mode(mode)
                        .output(OutputContract::Span)
                        .limits(short_limits),
                ) {
                    Err(CompileError::Resource {
                        resource: CompileResource::ProgramBytes,
                        limit,
                        required,
                    }) => {
                        assert_eq!(limit, expected_bytes - 1);
                        assert_eq!(required, expected_bytes);
                    }
                    other => panic!(
                        "unexpected max_program_bytes result: pattern={pattern:?} mode={mode:?}: {other:?}"
                    ),
                }
                checks += 1;
            }

            let repeated = compile_one(
                pattern,
                mode,
                OutputContract::Span,
                CompileLimitsV1::default(),
            );
            assert_eq!(baseline_program, repeated.program().serialize().unwrap());
            assert_eq!(
                baseline.module().entry_symbol(),
                repeated.module().entry_symbol()
            );
            checks += 1;
        }
    }
    checks
}

fn malformed_dfa_is_rejected() -> usize {
    let compiled = compile_one(
        "a",
        CompileMode::Optimizing,
        OutputContract::Span,
        CompileLimitsV1::default(),
    );
    let mut bytes = compiled.program().serialize().unwrap();
    let mut cursor = fre_aot_regex::PROGRAM_HEADER_LEN;
    skip(&bytes, &mut cursor, 4);
    let roles = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    let offsets = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    let targets = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    let kinds = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    let starts = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    let ends = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    skip(&bytes, &mut cursor, roles);
    skip(&bytes, &mut cursor, offsets * 4);
    skip(&bytes, &mut cursor, targets * 4);
    skip(&bytes, &mut cursor, kinds + starts + ends);
    let dfa_len = usize::try_from(get_u64(&bytes, &mut cursor)).unwrap();
    assert_eq!(bytes.len() - cursor, dfa_len);
    let build_work = get_u64(&bytes, &mut cursor);
    assert_ne!(build_work, 0);
    let classes = usize::try_from(get_u32(&bytes, &mut cursor)).unwrap();
    skip(&bytes, &mut cursor, 256 + classes);

    let forward_states_offset = cursor;
    let forward_cells_offset = cursor + 4;
    let forged_states = 500_000_u32;
    let forged_cells = u64::from(forged_states) * u64::try_from(classes).unwrap();
    bytes[forward_states_offset..forward_states_offset + 4]
        .copy_from_slice(&forged_states.to_le_bytes());
    bytes[forward_cells_offset..forward_cells_offset + 8]
        .copy_from_slice(&forged_cells.to_le_bytes());

    assert!(
        CompiledProgram::deserialize(&bytes).is_err(),
        "truncated forged DFA unexpectedly deserialized"
    );
    bytes.len()
}

fn raw_end(bytes: &[u8]) -> usize {
    let mut cursor = fre_aot_regex::PROGRAM_HEADER_LEN;
    skip(bytes, &mut cursor, 4);
    let roles = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    let offsets = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    let targets = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    let kinds = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    let starts = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    let ends = usize::try_from(get_u64(bytes, &mut cursor)).unwrap();
    skip(bytes, &mut cursor, roles);
    skip(bytes, &mut cursor, offsets * 4);
    skip(bytes, &mut cursor, targets * 4);
    skip(bytes, &mut cursor, kinds + starts + ends);
    cursor
}

fn inconsistent_raw_dfa_is_rejected() {
    let compiled = compile_one(
        "a|aa",
        CompileMode::Optimizing,
        OutputContract::Span,
        CompileLimitsV1::default(),
    );
    let mut dfa_bytes = compiled.program().serialize().unwrap();
    let donor = compile_one(
        "aa|a",
        CompileMode::Fast,
        OutputContract::Span,
        CompileLimitsV1::default(),
    );
    let donor_bytes = donor.program().serialize().unwrap();
    let dfa_raw_end = raw_end(&dfa_bytes);
    let donor_raw_end = raw_end(&donor_bytes);
    assert_eq!(dfa_raw_end, donor_raw_end);
    dfa_bytes[fre_aot_regex::PROGRAM_HEADER_LEN..dfa_raw_end]
        .copy_from_slice(&donor_bytes[fre_aot_regex::PROGRAM_HEADER_LEN..donor_raw_end]);

    assert!(
        CompiledProgram::deserialize(&dfa_bytes).is_err(),
        "raw plan from `aa|a` was accepted with the DFA payload for `a|aa`"
    );
}

#[test]
#[ignore = "checks more than five million generated search windows"]
fn broad_generated_semantic_audit() {
    let generated = patterns();
    let mut skipped = 0_usize;
    let mut refusals = BTreeMap::<String, usize>::new();
    let patterns: Vec<_> = generated
        .into_iter()
        .filter(|pattern| {
            let request = CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span);
            match compile(request) {
                Ok(_) => true,
                Err(CompileError::Lower(error)) => {
                    skipped += 1;
                    *refusals.entry(error.to_string()).or_default() += 1;
                    false
                }
                Err(error) => panic!("unexpected preflight failure for {pattern:?}: {error}"),
            }
        })
        .collect();
    let haystacks = haystacks();
    assert_eq!(patterns.len(), 673, "generated pattern coverage changed");
    assert_eq!(skipped, 0, "general lowering refused a generated pattern");
    assert_eq!(
        haystacks.len(),
        1_098,
        "generated haystack coverage changed"
    );
    eprintln!(
        "generated {} supported patterns ({} unsupported nullable-repeat forms skipped) and {} byte haystacks",
        patterns.len(),
        skipped,
        haystacks.len()
    );
    eprintln!("lowering refusals: {refusals:?}");
    let (windows, coalesced) = differential_spans(&patterns, &haystacks);
    let (fallback_searches, fallback_dfa_variants, fallback_nfa_variants) =
        fallback_limits(&haystacks);
    let serialization_checks = serialization_resource_boundaries();
    let malformed_bytes = malformed_dfa_is_rejected();
    inconsistent_raw_dfa_is_rejected();
    assert_eq!(windows, 5_060_960, "all-window coverage changed");
    assert_eq!(coalesced, 672, "alphabet coalescing coverage changed");
    assert_eq!(fallback_searches, 37_660);
    assert_eq!(fallback_dfa_variants, 20);
    assert_eq!(fallback_nfa_variants, 50);
    assert_eq!(serialization_checks, 36);
    println!(
        "PASS patterns={} default_dfa={} default_nfa=0 skipped={} haystacks={} all_windows={} coalesced_patterns={} fallback_searches={} fallback_dfa_variants={} fallback_nfa_variants={} serialization_checks={} malformed_bytes={} malformed_dfa=rejected inconsistent_raw_dfa=rejected",
        patterns.len(),
        patterns.len(),
        skipped,
        haystacks.len(),
        windows,
        coalesced,
        fallback_searches,
        fallback_dfa_variants,
        fallback_nfa_variants,
        serialization_checks,
        malformed_bytes
    );
}
