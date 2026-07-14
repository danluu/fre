use fre_re2_syntax::{
    Ast, ClassItem, NodeId, NodeKind, Options, ParseErrorCode, ParseLimits, ParseOutcome,
    PatternSpan, parse,
};

fn assert_parsed(pattern: &[u8], options: Options) {
    let outcome = parse(pattern, options, ParseLimits::default());
    assert!(
        matches!(outcome, ParseOutcome::Parsed { .. }),
        "expected source-valid pattern {pattern:?}, got {outcome:?}"
    );
}

fn assert_rejected(pattern: &[u8], options: Options, expected: ParseErrorCode) {
    let outcome = parse(pattern, options, ParseLimits::default());
    let ParseOutcome::Rejected(error) = outcome else {
        panic!("expected source-invalid pattern {pattern:?}, got {outcome:?}");
    };
    assert_eq!(error.code, expected, "pattern {pattern:?}");
}

#[test]
fn source_derived_valid_matrix() {
    let perl: &[&[u8]] = &[
        b"",
        b"a",
        b"a.",
        b"ab",
        b"a|^",
        b"a|b",
        b"(a)",
        b"(a)|b",
        b"a*",
        b"a+",
        b"a?",
        b"a{2}",
        b"a{2,}",
        b"a{2,4}",
        b"^$",
        br"\|\(\)\*\+\?\.\^\$\\",
        b"[ace]",
        b"[a-z]",
        b"[^a]",
        b"[a-b-c]",
        br"\d\D\s\S\w\W",
        br"\C",
        br"\p{Braille}\P{Braille}\p{^Braille}\P{^Braille}",
        b"a{,2}",
        b"a*{",
        b"(?:ab)*",
        b"(?P<name>a)",
        b"(?<name>a)",
        br"\Q+|*?{[\E",
        br"\A.*\z",
        b"(?im-sU:a)",
        b"a{01}",
        b"a{1000000000}",
        br"\08",
        br"\x00\x{10ffff}\400",
        b"[[:alnum:][:^space:]]",
    ];
    for pattern in perl {
        assert_parsed(pattern, Options::default());
    }

    for pattern in [
        &b"a++"[..],
        &b"a**"[..],
        &b"a?*"[..],
        &b"a+*"[..],
        &b"a{1}*"[..],
    ] {
        assert_parsed(pattern, Options::posix());
    }
}

#[test]
fn source_derived_error_category_matrix() {
    let cases: &[(&[u8], ParseErrorCode)] = &[
        (b"(", ParseErrorCode::MissingParen),
        (b")", ParseErrorCode::UnexpectedParen),
        (b"(a", ParseErrorCode::MissingParen),
        (b"[a-z", ParseErrorCode::MissingBracket),
        (b"x{1001}", ParseErrorCode::RepeatSize),
        (b"[a-Z]", ParseErrorCode::BadCharRange),
        (b"a{2,1}", ParseErrorCode::RepeatSize),
        (b"*", ParseErrorCode::RepeatArgument),
        (b"\\", ParseErrorCode::TrailingBackslash),
        (br"\q", ParseErrorCode::BadEscape),
        (br"\1", ParseErrorCode::BadEscape),
        (br"\x{110000}", ParseErrorCode::BadEscape),
        (b"(?P<name", ParseErrorCode::BadNamedCapture),
        (b"(?P<name>", ParseErrorCode::MissingParen),
        (b"(?P<x y>a)", ParseErrorCode::BadNamedCapture),
        (b"(?P<>a)", ParseErrorCode::BadNamedCapture),
        (b"(?=foo)", ParseErrorCode::BadPerlOp),
        (b"(?<=foo)", ParseErrorCode::BadPerlOp),
        (b"a++", ParseErrorCode::RepeatOp),
        (br"\Q\E*", ParseErrorCode::RepeatArgument),
        (b"[[:not_a_group:]]", ParseErrorCode::BadCharRange),
        (br"\p{not_a_group}", ParseErrorCode::BadCharRange),
    ];
    for &(pattern, code) in cases {
        assert_rejected(pattern, Options::default(), code);
    }
    assert_rejected(&[0xFF], Options::default(), ParseErrorCode::BadUtf8);
}

#[test]
fn short_perl_operators_follow_pinned_size_guards() {
    assert_rejected(b"(?=", Options::default(), ParseErrorCode::BadPerlOp);
    assert_rejected(b"(?<", Options::default(), ParseErrorCode::BadPerlOp);
    assert_rejected(b"(?P<", Options::default(), ParseErrorCode::BadPerlOp);
    assert_rejected(b"(?<=", Options::default(), ParseErrorCode::BadNamedCapture);
}

#[test]
fn multibyte_error_arguments_consume_whole_runes_like_parse_cc() {
    for pattern in ["(?é)".as_bytes(), r"\xé0".as_bytes(), r"\x{é}".as_bytes()] {
        let outcome = parse(pattern, Options::default(), ParseLimits::default());
        let ParseOutcome::Rejected(error) = outcome else {
            panic!("expected multibyte syntax rejection: {pattern:?}");
        };
        assert!(core::str::from_utf8(&error.argument_bytes).is_ok());
        let scalar_end = pattern
            .windows("é".len())
            .position(|window| window == "é".as_bytes())
            .unwrap()
            .saturating_add("é".len());
        assert!(error.argument.end >= scalar_end);
    }
}

fn assert_id(ast: &Ast, id: NodeId) {
    assert!(usize::try_from(id.0).is_ok_and(|index| index < ast.nodes.len()));
}

fn validate_ast(ast: &Ast) {
    assert_id(ast, ast.root);
    let mut class_items = 0usize;
    for node in &ast.nodes {
        assert!(node.span.start <= node.span.end);
        assert!(node.span.end <= ast.pattern.len());
        match &node.kind {
            NodeKind::Concat { children } => {
                for &child in children {
                    assert_id(ast, child);
                }
            }
            NodeKind::Alternation { branches } => {
                for &branch in branches {
                    assert_id(ast, branch);
                }
            }
            NodeKind::Capture { child, .. } | NodeKind::Repeat { child, .. } => {
                assert_id(ast, *child);
            }
            NodeKind::Class { items, .. } => {
                class_items = class_items.saturating_add(items.len());
                for item in items {
                    let span = match item {
                        ClassItem::Range { span, .. }
                        | ClassItem::Perl { span, .. }
                        | ClassItem::Posix { span, .. }
                        | ClassItem::Unicode { span, .. } => *span,
                    };
                    assert!(span.start <= span.end && span.end <= ast.pattern.len());
                }
            }
            _ => {}
        }
    }
    for token in &ast.tokens {
        assert!(token.span.start <= token.span.end);
        assert!(token.span.end <= ast.pattern.len());
    }
    assert!(class_items <= ast.nodes.len().saturating_mul(ast.pattern.len().max(1)));
}

#[test]
fn exhaustive_small_byte_patterns_are_total_and_structurally_sound() {
    const ALPHABET: &[u8] = b"a()|*?{}\\";
    let limits = ParseLimits {
        max_pattern_bytes: 16,
        max_nodes: 128,
        max_tokens: 128,
        max_nesting: 16,
        max_captures: 16,
        max_class_items: 128,
        max_work: 256,
    };
    let profiles = [Options::default(), Options::posix(), Options::latin1()];
    let mut generation = vec![Vec::new()];
    for length in 0..=5 {
        for pattern in &generation {
            for options in profiles {
                match parse(pattern, options, limits) {
                    ParseOutcome::Parsed { ast, usage } => {
                        validate_ast(&ast);
                        assert_eq!(usage.nodes, ast.nodes.len());
                        assert_eq!(usage.tokens, ast.tokens.len());
                        assert!(usage.work <= limits.max_work);
                    }
                    ParseOutcome::Rejected(error) => {
                        assert!(error.argument.start <= error.argument.end);
                        assert!(error.argument.end <= pattern.len());
                        assert!(error.usage.work <= limits.max_work);
                    }
                    ParseOutcome::NotYetImplemented(incomplete) => {
                        assert!(incomplete.span.start <= incomplete.span.end);
                        assert!(incomplete.span.end <= pattern.len());
                        assert!(incomplete.usage.work <= limits.max_work);
                    }
                }
            }
        }
        if length == 5 {
            break;
        }
        let mut next = Vec::with_capacity(generation.len().saturating_mul(ALPHABET.len()));
        for prefix in &generation {
            for &byte in ALPHABET {
                let mut pattern = prefix.clone();
                pattern.push(byte);
                next.push(pattern);
            }
        }
        generation = next;
    }
}

#[test]
fn large_and_deep_patterns_do_not_require_recursion() {
    let literal = vec![b'a'; 100_000];
    let ParseOutcome::Parsed { ast, usage } =
        parse(&literal, Options::default(), ParseLimits::default())
    else {
        panic!("large linear literal did not parse");
    };
    assert_eq!(usage.source_bytes, literal.len());
    assert_eq!(ast.tokens.len(), literal.len());

    let depth = 10_000usize;
    let mut nested = Vec::with_capacity(depth.saturating_mul(2).saturating_add(1));
    nested.extend(core::iter::repeat_n(b'(', depth));
    nested.push(b'a');
    nested.extend(core::iter::repeat_n(b')', depth));
    let ParseOutcome::Parsed { ast, usage } =
        parse(&nested, Options::default(), ParseLimits::default())
    else {
        panic!("deep iterative pattern did not parse");
    };
    assert_eq!(ast.capture_count, u32::try_from(depth).unwrap());
    assert_eq!(usage.maximum_nesting, depth);
}

#[test]
fn source_spans_for_whole_pattern_errors_are_stable() {
    for pattern in [&b")"[..], &b"(a"[..]] {
        let outcome = parse(pattern, Options::default(), ParseLimits::default());
        let ParseOutcome::Rejected(error) = outcome else {
            panic!("expected rejection");
        };
        assert_eq!(error.argument, PatternSpan::new(0, pattern.len()));
    }
}
