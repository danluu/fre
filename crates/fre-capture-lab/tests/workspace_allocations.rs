#![forbid(unsafe_code)]

use std::{alloc::System, sync::Arc};

use fre_capture_lab::{
    Ast, BuildLimits, CaptureStream, CaptureStreamDomains, CaptureStreamLimits, LineMode,
    LineScanLimits, LineScanner, TagAction, TagRunLimits, TagWorkspace, TagWorkspaceLimits,
    TagWorkspaceProspective,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn census<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
    let region = Region::new(GLOBAL);
    let value = operation();
    (value, region.change())
}

fn exact_limits(prospective: TagWorkspaceProspective) -> TagWorkspaceLimits {
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

fn assert_construction_census() {
    let prospective = TagWorkspace::prospective(65, 8, 8).expect("prospective");
    let exact = exact_limits(prospective);
    let (workspace, stats) = census(|| TagWorkspace::new(65, 8, 8, exact).expect("workspace"));
    assert_eq!(stats.allocations, prospective.allocations);
    assert_eq!(stats.bytes_allocated, prospective.allocator_bytes);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(stats.deallocations, 0);
    assert_eq!(stats.bytes_reallocated, 0);
    assert!(prospective.closes());
    drop(workspace);

    let mut groups = exact;
    groups.max_groups = prospective.groups.checked_sub(1).expect("one below");
    let mut history = exact;
    history.max_history_nodes = prospective.history_nodes.checked_sub(1).expect("one below");
    let mut mask_state_limits = exact;
    mask_state_limits.max_mask_states = prospective.mask_states.checked_sub(1).expect("one below");
    let mut words = exact;
    words.max_mask_words = prospective.mask_words.checked_sub(1).expect("one below");
    let mut work = exact;
    work.max_build_work = prospective.build_work.checked_sub(1).expect("one below");
    let mut initialized = exact;
    initialized.max_initialized_bytes = prospective
        .initialized_bytes
        .checked_sub(1)
        .expect("one below");
    let mut bytes = exact;
    bytes.max_persistent_bytes = prospective
        .persistent_bytes
        .checked_sub(1)
        .expect("one below");
    let mut peak = exact;
    peak.max_peak_bytes = prospective.peak_bytes.checked_sub(1).expect("one below");
    let mut allocator_bytes = exact;
    allocator_bytes.max_allocator_bytes = prospective
        .allocator_bytes
        .checked_sub(1)
        .expect("one below");
    let mut allocations = exact;
    allocations.max_allocations = prospective.allocations.checked_sub(1).expect("one below");

    for one_below in [
        groups,
        history,
        mask_state_limits,
        words,
        work,
        initialized,
        bytes,
        peak,
        allocator_bytes,
        allocations,
    ] {
        let (result, stats) = census(|| TagWorkspace::new(65, 8, 8, one_below));
        assert!(result.is_err());
        assert_eq!(stats, Stats::default());
    }
}

fn assert_reuse_census() {
    let prospective = TagWorkspace::prospective(65, 8, 8).expect("prospective");
    let mut workspace = TagWorkspace::new(65, 8, 8, exact_limits(prospective)).expect("workspace");
    let run_limits = TagRunLimits {
        max_history_nodes: 8,
        max_history_walk: 8,
        max_history_reads: 32,
        max_materialization_reads: 8,
        max_materialization_writes: 16,
        max_materialization_preview_writes: 8,
        max_mask_states: 8,
        max_mask_word_copies: 32,
        max_mask_word_reads: 32,
        max_tag_actions: 8,
        max_reset_cells: usize::MAX,
        max_work: usize::MAX,
    };
    workspace.begin_run(run_limits).expect("warmup");

    let ((), stats) = census(|| {
        let history = workspace
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("history start");
        let history = workspace
            .record_history(Some(history), TagAction::end(0).expect("tag"), 0)
            .expect("history end");
        let state = workspace
            .apply_participation(
                workspace.participation_root().expect("root"),
                TagAction::start(64).expect("tag"),
            )
            .expect("mask start");
        let _state = workspace
            .apply_participation(state, TagAction::end(64).expect("tag"))
            .expect("mask end");
        workspace.materialize_history(history).expect("materialize");
        workspace.begin_run(run_limits).expect("reuse");
    });
    assert_eq!(stats, Stats::default());
    assert_eq!(workspace.accounting().allocations, 0);
}

fn assert_line_census() {
    let prospective = LineScanner::prospective(8, LineMode::Crlf).expect("prospective");
    let scanner = LineScanner::new(
        8,
        LineMode::Crlf,
        LineScanLimits {
            max_source_bytes: prospective.source_bytes,
            max_partitions: prospective.partitions,
            max_work: prospective.work,
        },
    )
    .expect("scanner");
    for haystack in [b"a\r\nb\rc\nx".as_slice(), b"\r\r\n\nxxxx"] {
        let mut partitions = 0_usize;
        let (report, stats) = census(|| {
            scanner
                .scan(haystack, |_| {
                    partitions = partitions.checked_add(1).expect("partition count");
                })
                .expect("scan")
        });
        assert_eq!(stats, Stats::default());
        assert_eq!(partitions, report.partitions);
        assert_eq!(report.allocations, 0);
    }
}

fn assert_capture_stream_census() {
    let program = Arc::new(
        fre_capture_lab::Program::compile(
            &Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]),
            BuildLimits::default(),
        )
        .expect("program"),
    );
    let prospective =
        CaptureStream::operation_prospective(&program, 4, CaptureStreamDomains::Whole)
            .expect("whole operation prospective")
            .construction;
    let established = CaptureStream::prospective(&program, 4).expect("established prospective");
    let limits = CaptureStreamLimits {
        max_source_bytes: prospective.source_bytes,
        max_states: prospective.states,
        max_build_work: prospective.build_work,
        max_persistent_bytes: prospective.persistent_bytes,
        max_combined_peak_bytes: prospective.combined_peak_bytes,
        max_allocations: prospective.allocations,
        ..CaptureStreamLimits::default()
    };
    let (stream, stats) = census(|| {
        CaptureStream::new(Arc::clone(&program), 4, CaptureStreamDomains::Whole, limits)
            .expect("stream")
    });
    assert_eq!(stats.allocations, prospective.allocations);
    assert_eq!(stats.bytes_allocated, prospective.allocator_bytes);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(stats.deallocations, 0);
    assert_eq!(stats.bytes_reallocated, 0);
    assert!(prospective.closes());
    assert_eq!(
        prospective.allocations,
        established
            .allocations
            .checked_add(8)
            .expect("cache allocation count")
    );

    let (line_stream, stats) = census(|| {
        CaptureStream::new(
            Arc::clone(&program),
            4,
            CaptureStreamDomains::RebarLines,
            limits,
        )
        .expect("line stream")
    });
    assert_eq!(line_stream.build_report(), established);
    assert_eq!(stats.allocations, established.allocations);
    assert_eq!(stats.bytes_allocated, established.allocator_bytes);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(stats.deallocations, 0);
    assert_eq!(stats.bytes_reallocated, 0);

    let mut stream = stream;
    for _ in 0..2 {
        let (report, stats) = census(|| stream.execute(b"abxx").expect("execute"));
        assert_eq!(stats, Stats::default());
        assert_eq!(report.accounting.allocations, 0);
        assert!(report.closes(limits));
    }

    let mut source = limits;
    source.max_source_bytes = prospective.source_bytes.checked_sub(1).expect("source");
    let mut state_limit = limits;
    state_limit.max_states = prospective.states.checked_sub(1).expect("states");
    let mut work = limits;
    work.max_build_work = prospective.build_work.checked_sub(1).expect("work");
    let mut bytes = limits;
    bytes.max_persistent_bytes = prospective.persistent_bytes.checked_sub(1).expect("bytes");
    let mut peak = limits;
    peak.max_combined_peak_bytes = prospective
        .combined_peak_bytes
        .checked_sub(1)
        .expect("peak");
    let mut allocations = limits;
    allocations.max_allocations = prospective.allocations.checked_sub(1).expect("allocations");
    let mut cache_cells = limits;
    cache_cells.max_mask_states = prospective
        .participation_cache_cells()
        .checked_sub(1)
        .expect("participation cache cells");
    for one_below in [
        source,
        state_limit,
        work,
        bytes,
        peak,
        allocations,
        cache_cells,
    ] {
        let (result, stats) = census(|| {
            CaptureStream::new(
                Arc::clone(&program),
                4,
                CaptureStreamDomains::Whole,
                one_below,
            )
        });
        assert!(result.is_err());
        assert_eq!(stats, Stats::default());
    }
}

fn assert_exact_capture_replay_census() {
    let program = Arc::new(
        fre_capture_lab::Program::compile(
            &Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]),
            BuildLimits::default(),
        )
        .expect("program"),
    );
    let prospective = CaptureStream::prospective(&program, 4).expect("prospective");
    let limits = CaptureStreamLimits {
        max_source_bytes: prospective.source_bytes,
        max_states: prospective.states,
        max_build_work: prospective.build_work,
        max_persistent_bytes: prospective.persistent_bytes,
        max_combined_peak_bytes: prospective.combined_peak_bytes,
        max_allocations: prospective.allocations,
        ..CaptureStreamLimits::default()
    };
    let (stream, stats) =
        census(|| CaptureStream::new_exact(Arc::clone(&program), 4, limits).expect("exact stream"));
    assert_eq!(stats.allocations, prospective.allocations);
    assert_eq!(stats.bytes_allocated, prospective.allocator_bytes);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(stats.deallocations, 0);
    assert_eq!(stats.bytes_reallocated, 0);

    let mut stream = stream;
    for _ in 0..2 {
        let ((entries, accounting), stats) = census(|| {
            stream
                .execute_exact_span(b"abxx", fre_capture_lab::Span { start: 0, end: 2 })
                .expect("exact replay")
        });
        assert_eq!(2, entries);
        assert_eq!(stats, Stats::default());
        assert_eq!(accounting.allocations, 0);
    }
}

#[test]
fn exact_storage_and_reused_execution_match_the_allocator_census() {
    assert_construction_census();
    assert_reuse_census();
    assert_line_census();
    assert_capture_stream_census();
    assert_exact_capture_replay_census();
}
