/// Exact observed compiler dimensions and charged work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompileAccounting {
    pub hir_nodes: usize,
    pub hir_depth: usize,
    pub peak_hir_stack_items: usize,
    /// Capture annotations observed exactly once by validation and erased only
    /// by the explicit whole-match compiler entry point.
    pub captures_erased: usize,
    /// Transparent capture-node visits across validation and lowering. This
    /// is a subset of `work`, not an additional uncharged counter.
    pub capture_erasure_work: usize,
    pub literal_bytes: usize,
    pub class_ranges: usize,
    /// Supported zero-width look nodes observed exactly once during bounded
    /// validation. Repetition expansion is accounted separately by states.
    pub look_assertions: usize,
    pub program_states: usize,
    pub temporary_states_peak: usize,
    pub program_bytes: usize,
    pub work: usize,
}

/// Exact observed execution counters. Storage fields are logical byte counts
/// of the fixed-size buffers actually requested from the allocator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutionAccounting {
    pub state_evaluations: usize,
    pub transition_checks: usize,
    /// Evaluations of the shared absolute-boundary assertion predicate during
    /// table/row construction and sequential-row replay.
    pub assertion_checks: usize,
    pub root_probes: usize,
    pub replay_steps: usize,
    pub successful_paths: usize,
    pub suppressed_empty: usize,
    pub emitted_matches: usize,
    pub sequential_bytes_written: usize,
    pub sequential_bytes_read: usize,
    pub random_access_peak_bytes: usize,
    pub scratch_peak_bytes: usize,
    pub log_bytes: usize,
    pub output_bytes: usize,
    pub peak_bytes: usize,
    pub work: usize,
}
