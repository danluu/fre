use fre_capture_lab::{
    Assertion, Ast, BuildLimits, CaptureRecord, Greed, HistoryRegex, LineMode, LineScanner,
    SearchLimits, TagAction, TagRunLimits, TagWorkspace, TagWorkspaceLimits,
    TagWorkspaceProspective, Window,
};

fn build_limits(prospective: TagWorkspaceProspective) -> TagWorkspaceLimits {
    TagWorkspaceLimits {
        max_groups: prospective.groups,
        max_history_nodes: prospective.history_nodes,
        max_mask_states: prospective.mask_states,
        max_mask_words: prospective.mask_words,
        max_build_work: prospective.build_work,
        max_initialized_bytes: prospective.initialized_bytes,
        max_copied_bytes: prospective.copied_bytes,
        max_scratch_bytes: prospective.scratch_bytes,
        max_persistent_bytes: prospective.persistent_bytes,
        max_peak_bytes: prospective.peak_bytes,
        max_allocator_bytes: prospective.allocator_bytes,
        max_allocations: prospective.allocations,
    }
}

fn reset_cells(prospective: TagWorkspaceProspective) -> usize {
    let presence_words = prospective
        .slots
        .checked_add(63)
        .and_then(|value| value.checked_div(64))
        .expect("presence words");
    prospective
        .slots
        .checked_add(presence_words)
        .expect("reset cells")
}

fn run_limits(prospective: TagWorkspaceProspective, actions: usize) -> TagRunLimits {
    let mask_word_copies = actions
        .checked_mul(2)
        .and_then(|value| value.checked_mul(prospective.mask_words))
        .expect("mask copy envelope");
    TagRunLimits {
        max_history_nodes: actions,
        max_history_walk: actions.checked_mul(2).expect("two-pass history walk"),
        max_history_reads: actions
            .checked_mul(2)
            .and_then(|value| value.checked_add(actions))
            .expect("history read envelope"),
        max_materialization_reads: actions
            .checked_mul(2)
            .expect("two-pass materialization reads"),
        max_materialization_writes: actions.checked_mul(2).expect("materialization writes"),
        max_materialization_preview_writes: actions,
        max_mask_states: actions,
        max_mask_word_copies: mask_word_copies,
        max_mask_word_reads: usize::MAX,
        max_tag_actions: actions.checked_mul(2).expect("two projections"),
        max_reset_cells: reset_cells(prospective),
        max_work: usize::MAX,
    }
}

fn enumerate_haystacks(remaining: usize, haystack: &mut Vec<u8>, visit: &mut impl FnMut(&[u8])) {
    visit(haystack);
    if remaining == 0 {
        return;
    }
    for byte in [b'a', b'b', b'\n', 0xFF] {
        haystack.push(byte);
        enumerate_haystacks(
            remaining.checked_sub(1).expect("positive depth"),
            haystack,
            visit,
        );
        haystack.pop();
    }
}

fn adversarial_line_report(bytes: usize, mode: LineMode) -> fre_capture_lab::LineScanReport {
    let haystack = [b'\r', b'\n', b'x', 0xFF]
        .iter()
        .copied()
        .cycle()
        .take(bytes)
        .collect::<Vec<_>>();
    let prospective = LineScanner::prospective(bytes, mode).expect("prospective");
    let scanner = LineScanner::new(
        bytes,
        mode,
        fre_capture_lab::LineScanLimits {
            max_source_bytes: prospective.source_bytes,
            max_partitions: prospective.partitions,
            max_work: prospective.work,
        },
    )
    .expect("scanner");
    let report = scanner.scan(&haystack, |_| {}).expect("scan");
    assert!(report.closes_prospective());
    assert_eq!(report.source_reads, bytes);
    assert_eq!(
        report.loop_checks,
        bytes.checked_add(1).expect("terminal loop check")
    );
    assert_eq!(
        report.partition_writes,
        report.partitions.checked_mul(2).expect("partition writes")
    );
    report
}

fn assert_workspace_projection(
    ast: &Ast,
    haystack: &[u8],
    captures: &CaptureRecord,
    expected_mask: u64,
    expected_count: usize,
) {
    let action_count = captures
        .groups
        .iter()
        .filter(|group| group.span.is_some())
        .count()
        .checked_mul(2)
        .expect("tag actions");
    let prospective = TagWorkspace::prospective(captures.groups.len(), action_count, action_count)
        .expect("prospective");
    let mut workspace = TagWorkspace::new(
        captures.groups.len(),
        action_count,
        action_count,
        build_limits(prospective),
    )
    .expect("workspace");
    workspace
        .begin_run(run_limits(prospective, action_count))
        .expect("begin run");

    let mut history = None;
    let mut participation = workspace.participation_root().expect("root");
    for group in &captures.groups {
        let Some(span) = group.span else {
            continue;
        };
        let start = TagAction::start(group.index).expect("start tag");
        let end = TagAction::end(group.index).expect("end tag");
        history = Some(
            workspace
                .record_history(history, start, span.start)
                .expect("history start"),
        );
        history = Some(
            workspace
                .record_history(history, end, span.end)
                .expect("history end"),
        );
        participation = workspace
            .apply_participation(participation, start)
            .expect("participation start");
        participation = workspace
            .apply_participation(participation, end)
            .expect("participation end");
    }

    {
        let snapshot = workspace
            .materialize_history(history.expect("non-empty history"))
            .expect("snapshot");
        for group in &captures.groups {
            assert_eq!(
                snapshot
                    .span(usize::try_from(group.index).expect("group index"))
                    .expect("snapshot group"),
                group.span,
                "capture projection: ast={ast:?}, haystack={haystack:?}"
            );
        }
    }
    let mut mask = workspace
        .participation_mask(participation)
        .expect("participation mask");
    for group in &captures.groups {
        let bit = 1_u64.checked_shl(group.index).expect("inline group");
        assert_eq!(
            mask.contains(usize::try_from(group.index).expect("group index"))
                .expect("mask group"),
            expected_mask & bit != 0,
            "participation projection: ast={ast:?}, haystack={haystack:?}"
        );
    }
    assert!(mask.accepts_complete_match().expect("complete-match query"));
    assert_eq!(
        mask.user_capture_count().expect("capture-count query"),
        expected_count
    );
    assert_eq!(workspace.accounting().allocations, 0);
    assert_eq!(workspace.accounting().history_nodes, action_count);
    assert_eq!(
        workspace.accounting().history_walk,
        action_count.checked_mul(2).expect("two-pass history walk")
    );
}

#[test]
fn capture_vectors_and_participation_masks_project_identically() {
    let patterns = [
        Ast::Empty.capture(1),
        Ast::Byte(b'a').capture(1).repeat(0, Some(1), Greed::Greedy),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Lazy),
        Ast::Byte(b'a').capture(2).capture(1),
        Ast::alt([
            Ast::Byte(b'a'),
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'a')]),
        ])
        .capture(1),
        Ast::concat([
            Ast::Assert(Assertion::StartCrlf),
            Ast::Byte(b'a').capture(1),
            Ast::Assert(Assertion::EndCrlf),
        ]),
    ];

    for ast in patterns {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).expect("compile");
        enumerate_haystacks(3, &mut Vec::new(), &mut |haystack| {
            let full = regex
                .captures(haystack, Window::all(haystack), SearchLimits::default())
                .expect("full captures");
            let Some(captures) = full.captures else {
                return;
            };
            let overall = captures.overall().expect("group zero");
            let old_participation = regex
                .captures_participation_exact(
                    haystack,
                    Window::all(haystack),
                    overall,
                    SearchLimits::default(),
                )
                .expect("existing participation");
            let expected_mask = old_participation
                .participation_mask
                .expect("accepted exact span");
            assert_workspace_projection(
                &ast,
                haystack,
                &captures,
                expected_mask,
                old_participation
                    .participating_captures
                    .expect("accepted exact span"),
            );
        });
    }
}

#[test]
fn line_scan_work_is_linear_and_source_reads_are_exact() {
    for mode in [LineMode::Lf, LineMode::Crlf, LineMode::Byte(0xFF)] {
        let small = adversarial_line_report(64, mode);
        let large = adversarial_line_report(128, mode);
        assert_eq!(
            large.source_reads,
            small.source_reads.checked_mul(2).expect("double source")
        );
        assert!(
            large.work
                <= small
                    .work
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(3))
                    .expect("linear envelope")
        );
    }
}
