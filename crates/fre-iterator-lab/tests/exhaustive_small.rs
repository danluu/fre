use std::collections::HashSet;

use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, RepeatAtom, Span};

#[test]
fn exhaustive_small_ordered_asts_match_upstream_and_oracle() {
    let asts = generated_asts();
    let haystacks = generated_haystacks(3, &[b'a', b'b', b'\n', 0xFF]);
    assert_eq!(asts.len(), 666, "generator unexpectedly changed");
    assert_eq!(haystacks.len(), 85);
    for ast in &asts {
        let pattern = render(ast);
        let upstream = regex::bytes::RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        let compiled = CompiledRegex::new(ast, generous_limits())
            .unwrap_or_else(|error| panic!("laboratory rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| Span {
                    start: matched.start(),
                    end: matched.end(),
                })
                .collect::<Vec<_>>();
            let full = compiled
                .find_all_full_dp(haystack)
                .unwrap_or_else(|error| panic!("full DP {pattern:?} {haystack:?}: {error}"));
            let logged = compiled
                .find_all_decision_log(haystack)
                .unwrap_or_else(|error| panic!("decision log {pattern:?} {haystack:?}: {error}"));
            let oracle = compiled
                .find_all_oracle(haystack)
                .unwrap_or_else(|error| panic!("oracle {pattern:?} {haystack:?}: {error}"));
            let sequential = compiled
                .find_all_sequential_row_log(haystack)
                .unwrap_or_else(|error| panic!("row log {pattern:?} {haystack:?}: {error}"));
            assert_eq!(expected, full.matches, "full DP {pattern:?} {haystack:?}");
            assert_eq!(
                expected, logged.matches,
                "decision log {pattern:?} {haystack:?}"
            );
            assert_eq!(expected, oracle.matches, "oracle {pattern:?} {haystack:?}");
            assert_eq!(
                expected, sequential.matches,
                "row log {pattern:?} {haystack:?}"
            );
        }
    }
}

fn generous_limits() -> CompileLimits {
    CompileLimits {
        max_work: 10_000_000,
        ..CompileLimits::default()
    }
}

fn generated_asts() -> Vec<Ast> {
    let mut atoms = vec![
        Ast::Empty,
        Ast::Byte(b'a'),
        Ast::Byte(b'b'),
        Ast::Byte(0xFF),
        Ast::AnyByte,
        Ast::StartText,
        Ast::EndText,
    ];
    for (body, greed) in [
        (vec![RepeatAtom::Empty], Greed::Greedy),
        (vec![RepeatAtom::Empty], Greed::Lazy),
        (vec![RepeatAtom::Byte(b'a')], Greed::Greedy),
        (vec![RepeatAtom::Byte(b'a')], Greed::Lazy),
        (
            vec![RepeatAtom::Empty, RepeatAtom::Byte(b'a')],
            Greed::Greedy,
        ),
        (
            vec![RepeatAtom::Byte(b'a'), RepeatAtom::Empty],
            Greed::Greedy,
        ),
        (vec![RepeatAtom::Empty, RepeatAtom::Byte(b'a')], Greed::Lazy),
        (vec![RepeatAtom::Byte(b'a'), RepeatAtom::Empty], Greed::Lazy),
        (vec![RepeatAtom::AnyByte, RepeatAtom::Empty], Greed::Greedy),
        (
            vec![RepeatAtom::StartText, RepeatAtom::Byte(b'a')],
            Greed::Greedy,
        ),
        (
            vec![RepeatAtom::EndText, RepeatAtom::Byte(b'a')],
            Greed::Greedy,
        ),
    ] {
        atoms.push(Ast::Repeat { body, greed });
    }
    let mut generated = atoms.clone();
    for left in &atoms {
        for right in &atoms {
            generated.push(Ast::Concat(vec![left.clone(), right.clone()]));
            generated.push(Ast::Alt(vec![left.clone(), right.clone()]));
        }
    }
    let mut seen = HashSet::new();
    generated.retain(|ast| seen.insert(ast.clone()));
    generated
}

fn generated_haystacks(max_len: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
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

fn render(ast: &Ast) -> String {
    match ast {
        Ast::Empty => "(?:)".to_owned(),
        Ast::Byte(byte) => format!(r"\x{byte:02X}"),
        Ast::AnyByte => "(?s:.)".to_owned(),
        Ast::StartText => r"\A".to_owned(),
        Ast::EndText => r"\z".to_owned(),
        Ast::Concat(children) => children.iter().map(render).collect(),
        Ast::Alt(children) => format!(
            "(?:{})",
            children.iter().map(render).collect::<Vec<_>>().join("|")
        ),
        Ast::Repeat { body, greed } => {
            let body = body
                .iter()
                .map(|atom| match atom {
                    RepeatAtom::Empty => "(?:)".to_owned(),
                    RepeatAtom::Byte(byte) => format!(r"\x{byte:02X}"),
                    RepeatAtom::AnyByte => "(?s:.)".to_owned(),
                    RepeatAtom::StartText => r"\A".to_owned(),
                    RepeatAtom::EndText => r"\z".to_owned(),
                })
                .collect::<Vec<_>>()
                .join("|");
            let suffix = match greed {
                Greed::Greedy => "*",
                Greed::Lazy => "*?",
            };
            format!("(?:{body}){suffix}")
        }
        Ast::Repetition {
            child,
            min,
            max,
            greed,
        } => {
            let quantifier = match (*min, *max) {
                (0, None) => "*".to_owned(),
                (1, None) => "+".to_owned(),
                (0, Some(1)) => "?".to_owned(),
                (minimum, None) => format!("{{{minimum},}}"),
                (minimum, Some(maximum)) if minimum == maximum => {
                    format!("{{{minimum}}}")
                }
                (minimum, Some(maximum)) => format!("{{{minimum},{maximum}}}"),
            };
            let lazy = matches!(greed, Greed::Lazy).then_some("?").unwrap_or("");
            format!("(?:{}){quantifier}{lazy}", render(child))
        }
    }
}
