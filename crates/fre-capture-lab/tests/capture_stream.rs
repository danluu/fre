use std::sync::Arc;

use fre_capture_lab::{
    Ast, BuildLimits, CaptureStream, CaptureStreamDomains, CaptureStreamError, CaptureStreamLimits,
    CaptureStreamProjection, CaptureStreamResource, Greed, Program,
};

fn compile(ast: &Ast) -> Arc<Program> {
    Arc::new(Program::compile(ast, BuildLimits::default()).expect("program"))
}

fn exact_limits(program: &Program, haystack_len: usize) -> CaptureStreamLimits {
    let prospective = CaptureStream::prospective(program, haystack_len).expect("prospective");
    // Rebar line domains dominate the whole-input operation envelope and make
    // this fixture an exact source-free admission for either public domain.
    let operation = CaptureStream::operation_prospective(
        program,
        haystack_len,
        CaptureStreamDomains::RebarLines,
    )
    .expect("operation prospective");
    CaptureStreamLimits {
        max_source_bytes: prospective.source_bytes,
        max_states: prospective.states,
        max_build_work: prospective.build_work,
        max_persistent_bytes: prospective.persistent_bytes,
        max_combined_peak_bytes: prospective.combined_peak_bytes,
        max_allocations: prospective.allocations,
        max_line_domains: operation.line_domains,
        max_searches: operation.searches,
        max_matches: operation.matches,
        max_bytes_examined: operation.bytes_examined,
        max_starts_injected: operation.starts_injected,
        max_state_visits: operation.state_visits,
        max_tag_actions: operation.tag_actions,
        max_history_nodes: operation.history_nodes,
        max_history_walk: operation.history_walk,
        max_history_reads: operation.history_reads,
        max_materialization_reads: operation.materialization_reads,
        max_materialization_writes: operation.materialization_writes,
        max_materialization_preview_writes: operation.materialization_preview_writes,
        max_mask_states: operation.mask_states,
        max_mask_word_copies: operation.mask_word_copies,
        max_mask_word_reads: operation.mask_word_reads,
        max_reset_cells: operation.reset_cells,
        max_capture_events: operation.capture_events,
        max_capture_count: operation.capture_count,
        max_line_source_reads: operation.line_source_reads,
        max_work: operation.work,
    }
}

fn execute(
    ast: &Ast,
    haystack: &[u8],
    domains: CaptureStreamDomains,
) -> fre_capture_lab::CaptureStreamReport {
    let program = compile(ast);
    let limits = exact_limits(&program, haystack.len());
    let mut stream = CaptureStream::new(program, haystack.len(), domains, limits).expect("stream");
    let report = stream.execute(haystack).expect("execute");
    assert!(report.closes(limits));
    report
}

#[test]
fn participation_quotient_preserves_priority_optional_and_repeated_groups() {
    let captured_first = Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'a')]);
    let uncaptured_first = Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'a').capture(1)]);
    assert_eq!(
        execute(&captured_first, b"a", CaptureStreamDomains::Whole)
            .captures
            .count,
        2
    );
    assert_eq!(
        execute(&uncaptured_first, b"a", CaptureStreamDomains::Whole)
            .captures
            .count,
        1
    );

    let optional = Ast::concat([
        Ast::Byte(b'a').capture(1),
        Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Greedy),
    ]);
    let missing = execute(&optional, b"a", CaptureStreamDomains::Whole);
    assert_eq!(missing.captures.count, 2);
    assert_eq!(missing.capture_events, 3);
    let present = execute(&optional, b"ab", CaptureStreamDomains::Whole);
    assert_eq!(present.captures.count, 3);
    assert_eq!(present.capture_events, 3);

    let repeated =
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]).repeat(1, None, Greed::Greedy);
    let report = execute(&repeated, b"abb", CaptureStreamDomains::Whole);
    assert_eq!(report.captures.matches, 1);
    assert_eq!(report.captures.count, 2);
    assert_eq!(report.capture_events, 2);

    let delayed_priority = Ast::alt([
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'a')]).capture(1),
        Ast::Byte(b'a'),
    ]);
    let delayed = execute(&delayed_priority, b"aa", CaptureStreamDomains::Whole);
    assert_eq!(delayed.captures.matches, 1);
    assert_eq!(delayed.captures.count, 2);
    assert_eq!(
        delayed.first_match,
        Some(fre_capture_lab::Span { start: 0, end: 2 })
    );
    assert_eq!(delayed.last_match, delayed.first_match);

    let empty_capture = Ast::concat([Ast::Empty.capture(1), Ast::Byte(b'a')]);
    assert_eq!(
        execute(&empty_capture, b"a", CaptureStreamDomains::Whole)
            .captures
            .count,
        2
    );
}

#[test]
fn grep_domains_match_bstr_lf_and_crlf_contract_without_synthetic_tail() {
    let atom = Ast::Byte(b'x');
    let cases: &[(&[u8], usize)] = &[
        (b"", 0),
        (b"\n", 1),
        (b"\n\n", 2),
        (b"a\n", 1),
        (b"a\r\n", 1),
        (b"a\r", 1),
        (b"\r\r\n", 1),
        (b"x\nx\r\nx\r", 3),
    ];
    for &(haystack, expected_domains) in cases {
        let report = execute(&atom, haystack, CaptureStreamDomains::RebarLines);
        assert_eq!(
            report.accounting.line_domains, expected_domains,
            "haystack={haystack:?}"
        );
        assert_eq!(report.accounting.line_source_reads, haystack.len());
    }
}

#[test]
fn grep_anchors_and_word_context_are_line_local_but_offsets_stay_absolute() {
    let anchored_word = Ast::concat([
        Ast::Start,
        Ast::Assert(fre_capture_lab::Assertion::WordStartUnicode),
        Ast::Class(vec![(b'a', b'z')])
            .repeat(1, None, Greed::Greedy)
            .capture(1),
        Ast::Assert(fre_capture_lab::Assertion::WordEndUnicode),
        Ast::End,
    ]);
    let haystack = b"abc\r\nx\nbad!\n";
    let report = execute(&anchored_word, haystack, CaptureStreamDomains::RebarLines);
    assert_eq!(report.accounting.line_domains, 3);
    assert_eq!(report.captures.matches, 2);
    assert_eq!(report.captures.count, 4);
    assert_eq!(report.capture_events, 4);

    let cyrillic_word = Ast::concat([
        Ast::Assert(fre_capture_lab::Assertion::WordStartUnicode),
        Ast::concat([Ast::Byte(0xD0), Ast::Byte(0xB6)]),
        Ast::Assert(fre_capture_lab::Assertion::WordEndUnicode),
    ])
    .capture(1);
    let cyrillic = execute(
        &cyrillic_word,
        b"x\n\xD0\xB6\r\n \xD0\xB6\n",
        CaptureStreamDomains::RebarLines,
    );
    assert_eq!(cyrillic.captures.matches, 2);
    assert_eq!(cyrillic.captures.count, 4);
    assert_eq!(
        cyrillic.first_match,
        Some(fre_capture_lab::Span { start: 2, end: 4 })
    );
    assert_eq!(
        cyrillic.last_match,
        Some(fre_capture_lab::Span { start: 7, end: 9 })
    );
}

#[test]
fn wide_schema_selects_bounded_persistent_history_before_source_access() {
    for user_groups in [65_u32, 129] {
        let mut parts = Vec::new();
        for group in 1..=user_groups {
            parts.push(Ast::Byte(b'a').capture(group));
        }
        let ast = Ast::concat(parts);
        let program = Arc::new(
            Program::compile(
                &ast,
                BuildLimits {
                    max_captures: 256,
                    ..BuildLimits::default()
                },
            )
            .expect("wide program"),
        );
        let source_bytes = usize::try_from(user_groups).expect("u32 group count fits usize");
        let prospective = CaptureStream::prospective(&program, source_bytes).expect("prospective");
        assert_eq!(
            prospective.projection,
            CaptureStreamProjection::PersistentHistory
        );
        let limits = exact_limits(&program, source_bytes);
        let mut stream =
            CaptureStream::new(program, source_bytes, CaptureStreamDomains::Whole, limits)
                .expect("stream");
        let report = stream.execute(&vec![b'a'; source_bytes]).expect("execute");
        let expected_captures = source_bytes.checked_add(1).expect("group zero");
        assert_eq!(report.captures.matches, 1);
        assert_eq!(report.captures.count, expected_captures);
        assert_eq!(report.capture_events, expected_captures);
        assert!(report.accounting.history_nodes > 0);
        assert!(report.accounting.history_walk > 0);
        assert_eq!(report.operation.mask_word_reads, 0);
        assert_eq!(
            report.accounting.mask_word_reads, 0,
            "persistent winner reduction must not depend on mask-word width"
        );
    }
}

#[test]
fn wide_persistent_history_preserves_sparse_and_retained_winners() {
    let mut delayed_high = vec![Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'a')]).capture(1)];
    for group in 2..=65_u32 {
        delayed_high.push(
            Ast::Byte(b'z')
                .capture(group)
                .repeat(0, Some(1), Greed::Greedy),
        );
    }
    let sparse = Ast::alt([Ast::concat(delayed_high), Ast::Byte(b'a')]);
    let sparse_program = Arc::new(
        Program::compile(
            &sparse,
            BuildLimits {
                max_captures: 128,
                ..BuildLimits::default()
            },
        )
        .expect("sparse wide program"),
    );
    let sparse_limits = exact_limits(&sparse_program, 2);
    let mut sparse_stream = CaptureStream::new(
        sparse_program,
        2,
        CaptureStreamDomains::Whole,
        sparse_limits,
    )
    .expect("sparse stream");
    let sparse_report = sparse_stream.execute(b"aa").expect("sparse execute");
    assert_eq!(
        sparse_report.prospective.projection,
        CaptureStreamProjection::PersistentHistory
    );
    assert_eq!(sparse_report.captures.matches, 1);
    assert_eq!(sparse_report.captures.count, 2);
    assert_eq!(sparse_report.capture_events, 66);

    let mut retained = vec![
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]).repeat(1, None, Greed::Greedy),
    ];
    for group in 2..=65_u32 {
        retained.push(
            Ast::Byte(b'z')
                .capture(group)
                .repeat(0, Some(1), Greed::Greedy),
        );
    }
    let retained = Ast::concat(retained);
    let retained_program = Arc::new(
        Program::compile(
            &retained,
            BuildLimits {
                max_captures: 128,
                ..BuildLimits::default()
            },
        )
        .expect("retained wide program"),
    );
    let retained_limits = exact_limits(&retained_program, 3);
    let mut retained_stream = CaptureStream::new(
        retained_program,
        3,
        CaptureStreamDomains::Whole,
        retained_limits,
    )
    .expect("retained stream");
    let retained_report = retained_stream.execute(b"abb").expect("retained execute");
    assert_eq!(retained_report.captures.count, 2);
}

#[test]
fn wide_rebar_lines_use_constant_time_winner_summary() {
    let mut repeated_line_parts = vec![Ast::Byte(b'a').capture(1)];
    for group in 2..=65_u32 {
        repeated_line_parts.push(
            Ast::Byte(b'z')
                .capture(group)
                .repeat(0, Some(1), Greed::Greedy),
        );
    }
    let repeated_line_program = Arc::new(
        Program::compile(
            &Ast::concat(repeated_line_parts),
            BuildLimits {
                max_captures: 128,
                ..BuildLimits::default()
            },
        )
        .expect("wide repeated-line program"),
    );
    let repeated_line_haystack = b"a\na\na";
    let repeated_line_limits = exact_limits(&repeated_line_program, repeated_line_haystack.len());
    let mut repeated_line_stream = CaptureStream::new(
        repeated_line_program,
        repeated_line_haystack.len(),
        CaptureStreamDomains::RebarLines,
        repeated_line_limits,
    )
    .expect("wide repeated-line stream");
    let repeated_line_report = repeated_line_stream
        .execute(repeated_line_haystack)
        .expect("wide repeated-line execute");
    assert!(repeated_line_report.closes(repeated_line_limits));
    assert_eq!(repeated_line_report.captures.matches, 3);
    assert_eq!(repeated_line_report.captures.count, 6);
    assert_eq!(repeated_line_report.accounting.mask_word_reads, 0);
}

#[test]
fn construction_and_operation_limits_refuse_at_exact_one_below_before_source_access() {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1),
        Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Greedy),
    ]);
    let program = compile(&ast);
    let prospective = CaptureStream::prospective(&program, 2).expect("prospective");
    let mut limits = exact_limits(&program, 2);
    limits.max_persistent_bytes = prospective
        .persistent_bytes
        .checked_sub(1)
        .expect("positive bytes");
    assert_eq!(
        CaptureStream::new(Arc::clone(&program), 2, CaptureStreamDomains::Whole, limits)
            .expect_err("one below"),
        CaptureStreamError::Resource {
            resource: CaptureStreamResource::PersistentBytes,
            required: prospective.persistent_bytes,
            limit: prospective.persistent_bytes - 1,
        }
    );

    let exact = exact_limits(&program, 2);
    let mut stream =
        CaptureStream::new(Arc::clone(&program), 2, CaptureStreamDomains::Whole, exact)
            .expect("exact stream");
    let report = stream.execute(b"ab").expect("baseline");
    assert!(report.closes(exact));
    let operation = CaptureStream::operation_prospective(&program, 2, CaptureStreamDomains::Whole)
        .expect("operation prospective");
    let mut one_below = exact;
    one_below.max_state_visits = operation
        .state_visits
        .checked_sub(1)
        .expect("positive visits");
    assert!(matches!(
        CaptureStream::new(program, 2, CaptureStreamDomains::Whole, one_below)
            .expect_err("source-free operation admission must reject"),
        CaptureStreamError::Resource {
            resource: CaptureStreamResource::StateVisits,
            required,
            limit,
        } if required == operation.state_visits && limit == one_below.max_state_visits
    ));
}

#[test]
fn prepared_workspace_reuses_exact_storage_without_dynamic_allocations() {
    let ast = Ast::Byte(b'a').capture(1);
    let program = compile(&ast);
    let limits = exact_limits(&program, 5);
    let mut stream =
        CaptureStream::new(program, 5, CaptureStreamDomains::Whole, limits).expect("stream");
    let first = stream.execute(b"abaca").expect("first");
    let steady = stream.execute(b"abaca").expect("steady");
    assert_eq!(first, steady);
    assert_eq!(first.accounting.allocations, 0);
    assert_eq!(first.captures.count, 6);
}

#[test]
fn fixed_program_restart_envelope_is_published_before_source_and_contains_adversarial_scaling() {
    let ast = Ast::alt([
        Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Class(vec![(u8::MIN, u8::MAX)]).repeat(0, None, Greed::Greedy),
            Ast::Byte(b'z'),
        ]),
        Ast::Byte(b'a').capture(2),
    ]);
    let program = compile(&ast);
    let mut samples = Vec::new();
    for source_bytes in [64_usize, 128, 256] {
        let operation = CaptureStream::operation_prospective(
            &program,
            source_bytes,
            CaptureStreamDomains::Whole,
        )
        .expect("source-free restart envelope");
        assert_eq!(
            operation.bytes_examined,
            source_bytes
                .checked_mul(source_bytes.checked_add(1).expect("next boundary"))
                .and_then(|value| value.checked_div(2))
                .expect("triangle")
        );
        let limits = exact_limits(&program, source_bytes);
        let mut stream = CaptureStream::new(
            Arc::clone(&program),
            source_bytes,
            CaptureStreamDomains::Whole,
            limits,
        )
        .expect("admitted stream");
        let report = stream
            .execute(&vec![b'a'; source_bytes])
            .expect("adversarial execution");
        assert!(report.closes(limits));
        assert!(report.accounting.bytes_examined <= operation.bytes_examined);
        assert!(report.accounting.work <= operation.work);
        assert_eq!(report.captures.matches, source_bytes);
        samples.push(operation);
    }
    for pair in samples.windows(2) {
        assert!(
            pair[1].bytes_examined
                >= pair[0]
                    .bytes_examined
                    .checked_mul(3)
                    .expect("quadratic lower scaling")
        );
        assert!(
            pair[1].bytes_examined
                <= pair[0]
                    .bytes_examined
                    .checked_mul(5)
                    .expect("quadratic upper scaling")
        );
    }
}
