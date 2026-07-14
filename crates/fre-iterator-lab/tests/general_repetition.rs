use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, GuardedRegex, Span};

fn repetition(child: Ast, min: u32, max: Option<u32>, greed: Greed) -> Ast {
    Ast::Repetition {
        child: Box::new(child),
        min,
        max,
        greed,
    }
}

fn compare(ast: &Ast, haystack: &[u8]) -> Vec<Span> {
    let pattern = render(ast);
    let upstream = regex::bytes::RegexBuilder::new(&pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
    let expected = upstream
        .find_iter(haystack)
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect::<Vec<_>>();
    let compiled = CompiledRegex::new(ast, CompileLimits::default())
        .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
    let full = compiled.find_all_full_dp(haystack).expect("full DP");
    let logged = compiled
        .find_all_decision_log(haystack)
        .expect("decision log");
    let oracle = compiled.find_all_oracle(haystack).expect("oracle");
    let sequential = compiled
        .find_all_sequential_row_log(haystack)
        .expect("sequential row log");
    let guarded = GuardedRegex::new(ast, CompileLimits::default())
        .expect("guarded compile")
        .find_all_guarded_dp(haystack)
        .expect("guarded DP");
    assert_eq!(expected, full.matches, "full DP for {pattern:?}");
    assert_eq!(expected, logged.matches, "decision log for {pattern:?}");
    assert_eq!(expected, oracle.matches, "oracle for {pattern:?}");
    assert_eq!(expected, sequential.matches, "row log for {pattern:?}");
    assert_eq!(expected, guarded.matches, "guarded DP for {pattern:?}");
    expected
}

#[test]
fn arbitrary_nullable_alternative_order_is_preserved() {
    let empty_first = repetition(
        Ast::Alt(vec![Ast::Empty, Ast::Byte(b'a')]),
        0,
        None,
        Greed::Greedy,
    );
    let byte_first = repetition(
        Ast::Alt(vec![Ast::Byte(b'a'), Ast::Empty]),
        0,
        None,
        Greed::Greedy,
    );
    assert_eq!(
        compare(&empty_first, b"a"),
        vec![Span { start: 0, end: 0 }, Span { start: 1, end: 1 }]
    );
    assert_eq!(compare(&byte_first, b"a"), vec![Span { start: 0, end: 1 }]);
}

#[test]
fn nested_nullable_stars_and_lazy_continuations_are_exact() {
    let optional_a = repetition(Ast::Byte(b'a'), 0, Some(1), Greed::Greedy);
    let outer = repetition(optional_a, 0, None, Greed::Greedy);
    assert_eq!(compare(&outer, b"aa"), vec![Span { start: 0, end: 2 }]);

    let inner_star = repetition(Ast::Byte(b'a'), 0, None, Greed::Lazy);
    let lazy_outer = repetition(inner_star, 0, None, Greed::Lazy);
    let with_continuation = Ast::Concat(vec![lazy_outer, Ast::Byte(b'b')]);
    assert_eq!(
        compare(&with_continuation, b"aab"),
        vec![Span { start: 0, end: 3 }]
    );
}

#[test]
fn nested_empty_first_and_consuming_first_loops_stay_distinct() {
    let empty_first_inner = repetition(
        Ast::Alt(vec![Ast::Empty, Ast::Byte(b'a')]),
        0,
        None,
        Greed::Greedy,
    );
    let consuming_first_inner = repetition(
        Ast::Alt(vec![Ast::Byte(b'a'), Ast::Empty]),
        0,
        None,
        Greed::Greedy,
    );
    let empty_first_outer = repetition(empty_first_inner, 0, None, Greed::Greedy);
    let consuming_first_outer = repetition(consuming_first_inner, 0, None, Greed::Greedy);
    assert_eq!(
        compare(&empty_first_outer, b"a"),
        vec![Span { start: 0, end: 0 }, Span { start: 1, end: 1 }]
    );
    assert_eq!(
        compare(&consuming_first_outer, b"a"),
        vec![Span { start: 0, end: 1 }]
    );
}

#[test]
fn plus_optional_and_finite_ranges_count_empty_iterations() {
    let child = Ast::Alt(vec![Ast::Empty, Ast::Byte(b'a')]);
    for ast in [
        repetition(child.clone(), 1, None, Greed::Greedy),
        repetition(child.clone(), 0, Some(1), Greed::Lazy),
        repetition(child.clone(), 2, Some(4), Greed::Greedy),
        repetition(child, 2, Some(4), Greed::Lazy),
    ] {
        for haystack in [b"".as_slice(), b"a".as_slice(), b"aab".as_slice()] {
            compare(&ast, haystack);
        }
    }
}

#[test]
fn anchors_inside_nested_nullable_repetition_keep_original_context() {
    let anchored = repetition(
        Ast::Alt(vec![
            Ast::Concat(vec![Ast::StartText, Ast::Empty]),
            Ast::Byte(b'a'),
            Ast::EndText,
        ]),
        0,
        None,
        Greed::Greedy,
    );
    let ast = Ast::Concat(vec![anchored, Ast::Byte(b'b')]);
    for haystack in [b"ab".as_slice(), b"aab".as_slice(), b"b".as_slice()] {
        compare(&ast, haystack);
    }
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
                    fre_iterator_lab::RepeatAtom::Empty => "(?:)".to_owned(),
                    fre_iterator_lab::RepeatAtom::Byte(byte) => format!(r"\x{byte:02X}"),
                    fre_iterator_lab::RepeatAtom::AnyByte => "(?s:.)".to_owned(),
                    fre_iterator_lab::RepeatAtom::StartText => r"\A".to_owned(),
                    fre_iterator_lab::RepeatAtom::EndText => r"\z".to_owned(),
                })
                .collect::<Vec<_>>()
                .join("|");
            format!(
                "(?:{body})*{}",
                matches!(greed, Greed::Lazy).then_some("?").unwrap_or("")
            )
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
