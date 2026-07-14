use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, RepeatAtom, Span};

fn compile(ast: &Ast) -> CompiledRegex {
    CompiledRegex::new(ast, CompileLimits::default()).expect("valid laboratory AST")
}

fn all_three(ast: &Ast, haystack: &[u8]) -> Vec<Span> {
    let regex = compile(ast);
    let full = regex.find_all_full_dp(haystack).expect("full DP");
    let logged = regex.find_all_decision_log(haystack).expect("decision log");
    let oracle = regex.find_all_oracle(haystack).expect("oracle");
    let sequential = regex
        .find_all_sequential_row_log(haystack)
        .expect("sequential row log");
    assert_eq!(full.matches, logged.matches);
    assert_eq!(full.matches, oracle.matches);
    assert_eq!(full.matches, sequential.matches);
    full.matches
}

#[test]
fn nullable_repeat_branch_priority_is_retained() {
    let empty_first = Ast::Repeat {
        body: vec![RepeatAtom::Empty, RepeatAtom::Byte(b'a')],
        greed: Greed::Greedy,
    };
    let byte_first = Ast::Repeat {
        body: vec![RepeatAtom::Byte(b'a'), RepeatAtom::Empty],
        greed: Greed::Greedy,
    };
    assert_eq!(
        all_three(&empty_first, b"a"),
        vec![Span { start: 0, end: 0 }, Span { start: 1, end: 1 }]
    );
    assert_eq!(
        all_three(&byte_first, b"a"),
        vec![Span { start: 0, end: 1 }]
    );
}

#[test]
fn adjacent_empty_after_nonempty_is_suppressed() {
    let ast = Ast::Alt(vec![Ast::Byte(b'a'), Ast::Empty]);
    assert_eq!(all_three(&ast, b"a"), vec![Span { start: 0, end: 1 }]);
}

#[test]
fn anchors_use_original_haystack_context() {
    let ast = Ast::Alt(vec![Ast::StartText, Ast::EndText, Ast::Byte(b'a')]);
    assert_eq!(
        all_three(&ast, b"a"),
        vec![Span { start: 0, end: 0 }, Span { start: 1, end: 1 }]
    );
}

#[test]
fn lazy_nullable_loop_backtracks_to_make_continuation_succeed() {
    let ast = Ast::Concat(vec![
        Ast::Repeat {
            body: vec![RepeatAtom::Empty, RepeatAtom::Byte(b'a')],
            greed: Greed::Lazy,
        },
        Ast::Byte(b'b'),
    ]);
    assert_eq!(all_three(&ast, b"aab"), vec![Span { start: 0, end: 3 }]);
}
