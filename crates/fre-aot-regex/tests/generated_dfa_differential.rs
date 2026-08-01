//! Deterministic generated differential coverage for the complete ordered DFA.
//!
//! There is no random seed: the AST-like pattern families and byte languages
//! below are enumerated in a stable order.

use std::collections::BTreeSet;

use fre_aot_regex::{
    CompileLimitsV1, CompileMode, CompileRequest, CompiledRegex, EngineKind, MatchResult,
    OutputContract, SearchWindow, Target, compile,
};
use regex::bytes::RegexBuilder;

fn compile_span(pattern: &str, mode: CompileMode) -> CompiledRegex {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(mode)
            .output(OutputContract::Span),
    )
    .unwrap_or_else(|error| panic!("{mode:?} compilation failed for {pattern:?}: {error}"))
}

fn patterns() -> Vec<String> {
    let mut patterns = BTreeSet::new();
    for pattern in [
        "",
        "a|aa",
        "aa|a",
        "a|ab",
        "ab|a",
        "(?:a|aa)+",
        "(?:aa|a)+?",
        "(?:a??a)*",
        "(?:ab|a)+?b",
        "[a-cx-z]+",
        "(?-u:[\\x00-\\x02\\x80-\\x82])+",
        "(?:é|éa)+",
        "(?:éa|é)+?",
        "\\p{Greek}+",
    ] {
        patterns.insert(pattern.to_owned());
    }
    let atoms = ["a", "b", "ab", "[ab]", "(?-u:\\x80)", "é"];
    for atom in atoms {
        for suffix in ["?", "??", "*", "*?", "+", "+?", "{0,2}", "{0,2}?"] {
            patterns.insert(format!("(?:{atom}){suffix}"));
        }
    }
    for left in ["a", "aa", "ab", "(?:a|ab)", "(?:ab|a)"] {
        for right in ["a", "aa", "ab", "(?:a|ab)", "(?:ab|a)"] {
            patterns.insert(format!("(?:{left})(?:{right})"));
            patterns.insert(format!("(?:{left})|(?:{right})"));
        }
    }
    patterns.into_iter().collect()
}

fn words(output: &mut BTreeSet<Vec<u8>>, alphabet: &[u8], max: usize, word: &mut Vec<u8>) {
    output.insert(word.clone());
    if word.len() == max {
        return;
    }
    for &byte in alphabet {
        word.push(byte);
        words(output, alphabet, max, word);
        word.pop();
    }
}

fn haystacks() -> Vec<Vec<u8>> {
    let mut haystacks = BTreeSet::new();
    words(&mut haystacks, b"abx", 3, &mut Vec::new());
    words(&mut haystacks, &[0, b'a', 0x80, 0xff], 2, &mut Vec::new());
    for value in 0_u16..=255 {
        haystacks.insert(vec![u8::try_from(value).unwrap()]);
    }
    for bytes in [
        b"aaaaab".as_slice(),
        b"xxababa".as_slice(),
        "ééa".as_bytes(),
        "xαβa".as_bytes(),
        &[0xff, 0xc3, 0xa9, 0x80],
    ] {
        haystacks.insert(bytes.to_vec());
    }
    haystacks.into_iter().collect()
}

#[test]
fn generated_dfa_matches_fast_regex_and_roundtrip_for_all_windows() {
    let patterns = patterns();
    let haystacks = haystacks();
    assert_eq!(patterns.len(), 112);
    assert_eq!(haystacks.len(), 313);

    for pattern in patterns {
        let oracle = RegexBuilder::new(&pattern).build().unwrap();
        let fast = compile_span(&pattern, CompileMode::Fast);
        let optimized = compile_span(&pattern, CompileMode::Optimizing);
        assert_eq!(fast.receipt().engine, EngineKind::OrderedNfa, "{pattern:?}");
        assert_eq!(
            optimized.receipt().engine,
            EngineKind::OrderedDfa,
            "{pattern:?}"
        );

        let fast_bytes = fast.program().serialize().unwrap();
        let optimized_bytes = optimized.program().serialize().unwrap();
        let fast_roundtrip = fre_aot_regex::CompiledProgram::deserialize(&fast_bytes).unwrap();
        let optimized_roundtrip =
            fre_aot_regex::CompiledProgram::deserialize(&optimized_bytes).unwrap();
        assert_eq!(fast_roundtrip.serialize().unwrap(), fast_bytes);
        assert_eq!(optimized_roundtrip.serialize().unwrap(), optimized_bytes);

        let mut fast_workspace = fast.program().prepare_workspace().unwrap();
        let mut optimized_workspace = optimized.program().prepare_workspace().unwrap();
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = MatchResult::Span(
                        oracle
                            .find_at(&haystack[..end], start)
                            .map(|matched| (matched.start(), matched.end())),
                    );
                    assert_eq!(
                        fast.program()
                            .search_with_workspace(haystack, window, &mut fast_workspace)
                            .unwrap(),
                        expected,
                        "Fast {pattern:?} {haystack:02x?} {start}..{end}"
                    );
                    assert_eq!(
                        optimized
                            .program()
                            .search_with_workspace(haystack, window, &mut optimized_workspace)
                            .unwrap(),
                        expected,
                        "Optimizing {pattern:?} {haystack:02x?} {start}..{end}"
                    );
                    assert_eq!(fast_roundtrip.search(haystack, window).unwrap(), expected);
                    assert_eq!(
                        optimized_roundtrip.search(haystack, window).unwrap(),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn zero_state_limit_falls_back_without_changing_semantics() {
    let pattern = "(?:ab|a)+?b";
    let fast = compile_span(pattern, CompileMode::Fast);
    let mut limits = CompileLimitsV1::default();
    limits.determinize.max_states = 0;
    let fallback = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span)
            .limits(limits),
    )
    .unwrap();
    assert_eq!(fallback.receipt().engine, EngineKind::OrderedNfa);
    for haystack in [b"".as_slice(), b"aaab", b"xxabab", b"nomatch"] {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = SearchWindow::new(start, end);
                assert_eq!(
                    fallback.search(haystack, window).unwrap(),
                    fast.search(haystack, window).unwrap()
                );
            }
        }
    }
}
