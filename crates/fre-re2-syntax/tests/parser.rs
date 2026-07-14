use fre_re2_syntax::{
    AnchorKind, ClassItem, Encoding, Greediness, LimitKind, NodeKind, Options, ParseErrorCode,
    ParseLimits, ParseOutcome, PatternSpan, PosixClass, RepeatRange, SyntaxMode,
    UnsupportedFeature, parse,
};

fn parsed(pattern: &[u8], options: Options) -> fre_re2_syntax::Ast {
    match parse(pattern, options, ParseLimits::default()) {
        ParseOutcome::Parsed { ast, .. } => ast,
        outcome => panic!("expected parsed outcome for {pattern:?}, got {outcome:?}"),
    }
}

fn rejection(pattern: &[u8], options: Options) -> fre_re2_syntax::ParseError {
    match parse(pattern, options, ParseLimits::default()) {
        ParseOutcome::Rejected(error) => error,
        outcome => panic!("expected rejection for {pattern:?}, got {outcome:?}"),
    }
}

#[test]
fn precedence_capture_and_source_bytes_are_preserved() {
    let ast = parsed(b"ab|c(d+)", Options::default());
    assert_eq!(&*ast.pattern, b"ab|c(d+)");
    assert_eq!(ast.capture_count, 1);
    assert_eq!(
        ast.source(ast.nodes[usize::try_from(ast.root.0).unwrap()].span),
        Some(&b"ab|c(d+)"[..])
    );
    let NodeKind::Alternation { branches } = &ast.node(ast.root).unwrap().kind else {
        panic!("root was not alternation: {:?}", ast.node(ast.root));
    };
    assert_eq!(branches.len(), 2);
}

#[test]
fn named_capture_maps_follow_source_numbering() {
    let ast = parsed(b"(a)(?P<word>b)(?<word>c)", Options::default());
    assert_eq!(ast.capture_count, 3);
    assert_eq!(ast.named_captures().get("word"), Some(&2));
    assert_eq!(
        ast.capture_names().get(&2).map(String::as_str),
        Some("word")
    );
    assert_eq!(
        ast.capture_names().get(&3).map(String::as_str),
        Some("word")
    );

    let nested = parsed(b"(?P<x>(?P<x>a))", Options::default());
    assert_eq!(nested.named_captures().get("x"), Some(&1));
}

#[test]
fn default_and_posix_option_gates_are_distinct() {
    let perl = parsed(b"(?:a)\\d\\b\\A\\z\\C", Options::default());
    assert_eq!(perl.capture_count, 0);

    let posix = Options::posix();
    assert_eq!(
        rejection(b"(?:a)", posix).code,
        ParseErrorCode::RepeatArgument
    );
    assert_eq!(rejection(br"\d", posix).code, ParseErrorCode::BadEscape);
    let posix_extensions = Options {
        perl_classes: true,
        word_boundary: true,
        ..posix
    };
    let ast = parsed(br"\d\b", posix_extensions);
    assert_eq!(ast.capture_count, 0);
}

#[test]
fn perl_rejects_but_posix_squashes_stacked_simple_repeats() {
    let error = rejection(b"a++", Options::default());
    assert_eq!(error.code, ParseErrorCode::RepeatOp);
    assert_eq!(error.argument, PatternSpan::new(1, 3));

    let ast = parsed(b"a++", Options::posix());
    let NodeKind::Repeat { range, .. } = ast.node(ast.root).unwrap().kind else {
        panic!("POSIX stacked plus was not a repeat");
    };
    assert_eq!(range, RepeatRange { min: 1, max: None });

    let grouped = parsed(b"(?:(?:a)*)+", Options::default());
    let NodeKind::Repeat { child, range, .. } = grouped.node(grouped.root).unwrap().kind else {
        panic!("group-separated repeats were not squashed");
    };
    assert_eq!(range, RepeatRange { min: 0, max: None });
    assert!(matches!(
        grouped.node(child).unwrap().kind,
        NodeKind::Literal { .. }
    ));

    let flag_distinct = parsed(b"(?:(?U:a*))+", Options::default());
    let NodeKind::Repeat { child, .. } = flag_distinct.node(flag_distinct.root).unwrap().kind
    else {
        panic!("expected outer repeat");
    };
    assert!(matches!(
        flag_distinct.node(child).unwrap().kind,
        NodeKind::Repeat { .. }
    ));
}

#[test]
fn counted_repeat_grammar_and_nested_product_match_re2_rules() {
    assert_eq!(
        rejection(b"x{1001}", Options::default()).code,
        ParseErrorCode::RepeatSize
    );
    let literal_braces = parsed(b"a{,2}", Options::default());
    let NodeKind::Concat { .. } = literal_braces.node(literal_braces.root).unwrap().kind else {
        panic!("invalid counted suffix should have become literal concatenation");
    };
    let nested = b"((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})";
    assert_eq!(
        rejection(nested, Options::default()).code,
        ParseErrorCode::RepeatSize
    );
}

#[test]
fn nongreedy_flag_edits_and_suffix_toggle() {
    let ast = parsed(b"(?U:a*?b+)", Options::default());
    let NodeKind::Concat { children } = &ast.node(ast.root).unwrap().kind else {
        panic!("expected concatenation");
    };
    let NodeKind::Repeat {
        greediness: first, ..
    } = ast.node(children[0]).unwrap().kind
    else {
        panic!("expected first repetition");
    };
    let NodeKind::Repeat {
        greediness: second, ..
    } = ast.node(children[1]).unwrap().kind
    else {
        panic!("expected second repetition");
    };
    assert_eq!(first, Greediness::Greedy);
    assert_eq!(second, Greediness::NonGreedy);
}

#[test]
fn anchors_follow_one_line_and_inline_m() {
    let ast = parsed(b"^$(?m:^$)\\A\\z", Options::default());
    let anchors: Vec<_> = ast
        .nodes
        .iter()
        .filter_map(|node| match node.kind {
            NodeKind::Anchor(anchor) => Some(anchor),
            _ => None,
        })
        .collect();
    assert_eq!(
        anchors,
        vec![
            AnchorKind::BeginText,
            AnchorKind::EndText,
            AnchorKind::BeginLine,
            AnchorKind::EndLine,
            AnchorKind::BeginText,
            AnchorKind::EndText,
        ]
    );
}

#[test]
fn explicit_classes_and_core_escapes_are_directly_represented() {
    let ast = parsed(br"[a-c\x44\141]\x{263a}\077", Options::default());
    let class = ast
        .nodes
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::Class { items, .. } => Some(items),
            _ => None,
        })
        .unwrap();
    assert!(class.contains(&ClassItem::Range {
        lo: u32::from(b'a'),
        hi: u32::from(b'c'),
        span: PatternSpan::new(1, 4),
    }));
    assert_eq!(
        rejection(b"[z-a]", Options::default()).code,
        ParseErrorCode::BadCharRange
    );
    assert_eq!(
        rejection(br"\q", Options::default()).code,
        ParseErrorCode::BadEscape
    );
}

#[test]
fn pinned_unicode_and_posix_names_are_symbolic_and_invalid_names_reject() {
    let unicode = parsed(br"\p{Han}\P{^Braille}", Options::default());
    assert!(unicode.nodes.iter().any(|node| matches!(
        &node.kind,
        NodeKind::Class { items, .. }
            if items.iter().any(|item| matches!(item,
                ClassItem::Unicode { name, negated: false, .. } if name == "Han"))
    )));
    let posix = parsed(b"[[:lower:][:^digit:]]", Options::default());
    assert!(posix.nodes.iter().any(|node| matches!(
        &node.kind,
        NodeKind::Class { items, .. }
            if items.iter().any(|item| matches!(item,
                ClassItem::Posix { class: PosixClass::Lower, negated: false, .. }))
    )));
    assert_eq!(
        rejection(br"\p{Definitely_Not_RE2}", Options::default()).code,
        ParseErrorCode::BadCharRange
    );
    assert_eq!(
        rejection(b"[[:definitely_not_re2:]]", Options::default()).code,
        ParseErrorCode::BadCharRange
    );

    match parse(
        "(?P<é>a)".as_bytes(),
        Options::default(),
        ParseLimits::default(),
    ) {
        ParseOutcome::NotYetImplemented(incomplete) => {
            assert_eq!(incomplete.feature, UnsupportedFeature::UnicodeCaptureName);
        }
        outcome => panic!("unexpected Unicode capture-name outcome: {outcome:?}"),
    }
}

#[test]
fn utf8_and_latin1_are_separate_profiles() {
    assert_eq!(
        rejection(&[0xFF], Options::default()).code,
        ParseErrorCode::BadUtf8
    );
    let ast = parsed(&[0xFF], Options::latin1());
    let NodeKind::Literal { value, .. } = ast.node(ast.root).unwrap().kind else {
        panic!("Latin-1 byte was not literal");
    };
    assert_eq!(value, 0xFF);
    assert_eq!(
        rejection(br"\x{100}", Options::latin1()).code,
        ParseErrorCode::BadEscape
    );
    let error = rejection(&[b'[', 0xFF, b'-', b'a', b']'], Options::latin1());
    assert_eq!(error.code, ParseErrorCode::BadCharRange);
    assert_eq!(&*error.argument_bytes, &[0xC3, 0xBF, b'-', b'a']);
    assert_eq!(
        error.re2_status_text().as_deref(),
        Some(&b"invalid character class range: \xC3\xBF-a"[..])
    );
}

#[test]
fn lookaround_diagnostics_retain_pinned_error_arguments() {
    for (pattern, end) in [
        (&b"(?=foo)"[..], 3),
        (&b"(?!foo)"[..], 3),
        (&b"(?<=foo)"[..], 4),
        (&b"(?<!foo)"[..], 4),
    ] {
        let error = rejection(pattern, Options::default());
        assert_eq!(error.code, ParseErrorCode::BadPerlOp);
        assert_eq!(error.argument, PatternSpan::new(0, end));
    }
}

#[test]
fn literal_and_never_capture_options_are_frozen_in_ast() {
    let literal = parsed(
        b"(|)^$.[*+?]{5,10},\\",
        Options {
            literal: true,
            ..Options::default()
        },
    );
    assert_eq!(literal.capture_count, 0);
    let no_capture = parsed(
        b"((a))",
        Options {
            never_capture: true,
            ..Options::default()
        },
    );
    assert_eq!(no_capture.capture_count, 0);
}

#[test]
fn each_resource_has_an_explicit_failure() {
    let limits = ParseLimits {
        max_nodes: 1,
        ..ParseLimits::default()
    };
    let ParseOutcome::Rejected(error) = parse(b"ab", Options::default(), limits) else {
        panic!("node cap was not enforced");
    };
    assert_eq!(error.code, ParseErrorCode::PatternTooLarge);
    assert_eq!(error.limit, Some(LimitKind::AstNodes));

    let limits = ParseLimits {
        max_nesting: 0,
        ..ParseLimits::default()
    };
    let ParseOutcome::Rejected(error) = parse(b"(a)", Options::default(), limits) else {
        panic!("nesting cap was not enforced");
    };
    assert_eq!(error.limit, Some(LimitKind::Nesting));
    assert_eq!(error.observed, Some(1));

    let limits = ParseLimits {
        max_work: 1,
        ..ParseLimits::default()
    };
    let ParseOutcome::Rejected(error) = parse(b"ab", Options::default(), limits) else {
        panic!("work cap was not enforced");
    };
    assert_eq!(error.limit, Some(LimitKind::Work));
}

#[test]
fn profile_identity_includes_mode_and_encoding() {
    let options = Options {
        encoding: Encoding::Latin1,
        syntax: SyntaxMode::Posix,
        ..Options::default()
    };
    let ast = parsed(b"a", options);
    assert_eq!(ast.options, options);
}
