use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, GuardedRegex, Span};

#[test]
fn exhaustive_nested_repetition_asts_match_upstream_and_all_executors() {
    let asts = generated_asts(4);
    let haystacks = generated_haystacks(2, &[b'a', b'b', b'\n', 0xFF]);
    assert_eq!(asts.len(), 5_310, "general AST generator changed");
    assert_eq!(haystacks.len(), 21, "haystack generator changed");
    for ast in &asts {
        let pattern = render(ast);
        let upstream = regex::bytes::RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        let compiled = CompiledRegex::new(ast, generous_limits())
            .unwrap_or_else(|error| panic!("compiler rejected {pattern:?}: {error}"));
        let guarded = GuardedRegex::new(ast, generous_limits())
            .unwrap_or_else(|error| panic!("guarded compiler rejected {pattern:?}: {error}"));
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
                .unwrap_or_else(|error| panic!("log {pattern:?} {haystack:?}: {error}"));
            let oracle = compiled
                .find_all_oracle(haystack)
                .unwrap_or_else(|error| panic!("oracle {pattern:?} {haystack:?}: {error}"));
            let guarded_result = guarded
                .find_all_guarded_dp(haystack)
                .unwrap_or_else(|error| panic!("guarded {pattern:?} {haystack:?}: {error}"));
            let sequential = compiled
                .find_all_sequential_row_log(haystack)
                .unwrap_or_else(|error| panic!("row log {pattern:?} {haystack:?}: {error}"));
            assert_eq!(expected, full.matches, "full DP {pattern:?} {haystack:?}");
            assert_eq!(expected, logged.matches, "log {pattern:?} {haystack:?}");
            assert_eq!(expected, oracle.matches, "oracle {pattern:?} {haystack:?}");
            assert_eq!(
                expected, guarded_result.matches,
                "guarded {pattern:?} {haystack:?}"
            );
            assert_eq!(
                expected, sequential.matches,
                "row log {pattern:?} {haystack:?}"
            );
        }
    }
}

fn generous_limits() -> CompileLimits {
    CompileLimits {
        max_work: 20_000_000,
        ..CompileLimits::default()
    }
}

fn generated_asts(max_size: usize) -> Vec<Ast> {
    let slots = max_size.checked_add(1).expect("small generator bound");
    let mut exact = vec![Vec::new(); slots];
    exact[1] = vec![
        Ast::Empty,
        Ast::Byte(b'a'),
        Ast::Byte(b'b'),
        Ast::AnyByte,
        Ast::StartText,
        Ast::EndText,
    ];
    let quantifiers = [
        (0, None, Greed::Greedy),
        (0, None, Greed::Lazy),
        (1, None, Greed::Greedy),
        (1, None, Greed::Lazy),
        (0, Some(1), Greed::Greedy),
        (0, Some(1), Greed::Lazy),
        (1, Some(2), Greed::Greedy),
        (1, Some(2), Greed::Lazy),
    ];
    for size in 2..=max_size {
        let previous = size.checked_sub(1).expect("size starts at two");
        for child in exact[previous].clone() {
            for (min, max, greed) in quantifiers {
                exact[size].push(Ast::Repetition {
                    child: Box::new(child.clone()),
                    min,
                    max,
                    greed,
                });
            }
        }
        for left_size in 1..previous {
            let right_size = previous
                .checked_sub(left_size)
                .expect("left size is below previous");
            for left in exact[left_size].clone() {
                for right in exact[right_size].clone() {
                    exact[size].push(Ast::Concat(vec![left.clone(), right.clone()]));
                    exact[size].push(Ast::Alt(vec![left.clone(), right]));
                }
            }
        }
    }
    exact.into_iter().flatten().collect()
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
            let rendered = body
                .iter()
                .map(|atom| format!("{atom:?}"))
                .collect::<Vec<_>>()
                .join("|");
            panic!("legacy Repeat is absent from this generator: {rendered} {greed:?}")
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
            format!(
                "(?:{}){quantifier}{}",
                render(child),
                matches!(greed, Greed::Lazy).then_some("?").unwrap_or("")
            )
        }
    }
}
