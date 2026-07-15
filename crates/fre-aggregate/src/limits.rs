/// Hard limits for one HIR compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    pub max_hir_nodes: usize,
    pub max_hir_depth: usize,
    pub max_hir_stack_items: usize,
    pub max_literal_bytes: usize,
    pub max_class_ranges: usize,
    pub max_look_assertions: usize,
    pub max_repeat_bound: u32,
    pub max_program_states: usize,
    pub max_temporary_states: usize,
    pub max_program_bytes: usize,
    pub max_work: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_hir_nodes: 4_096,
            max_hir_depth: 64,
            max_hir_stack_items: 4_096,
            max_literal_bytes: 1 << 20,
            max_class_ranges: 1 << 16,
            max_look_assertions: 1 << 16,
            max_repeat_bound: 1_000,
            max_program_states: 1 << 16,
            max_temporary_states: 1 << 17,
            max_program_bytes: 16 << 20,
            max_work: 16 << 20,
        }
    }
}

/// Hard limits for one complete admitted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationLimits {
    pub max_boundaries: usize,
    pub max_table_cells: usize,
    pub max_random_access_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_log_bytes: usize,
    pub max_sequential_bytes: usize,
    pub max_match_events: usize,
    pub max_output_matches: usize,
    pub max_output_bytes: usize,
    pub max_span_sum: usize,
    pub max_peak_bytes: usize,
    pub max_work: usize,
}

impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            max_boundaries: 1_048_577,
            max_table_cells: 16_777_216,
            max_random_access_bytes: 256 << 20,
            max_scratch_bytes: 256 << 20,
            max_log_bytes: 128 << 20,
            max_sequential_bytes: 512 << 20,
            max_match_events: 2_097_154,
            max_output_matches: 1_048_576,
            max_output_bytes: 64 << 20,
            max_span_sum: usize::MAX,
            max_peak_bytes: 512 << 20,
            max_work: 1 << 29,
        }
    }
}

/// Hard limits for capture reconstruction after whole-match admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    /// Group slots per match, including whole-match group zero.
    pub max_capture_slots: usize,
    /// `(input boundary, program state)` cells in the fixed replay scratch.
    pub max_replay_cells: usize,
    /// Immutable capture-action history nodes retained during one replay.
    pub max_history_nodes: usize,
    /// Logical bytes in all returned group-slot arrays.
    pub max_output_bytes: usize,
    /// Capture replay and history-reconstruction steps.
    pub max_work: usize,
    /// Fixed replay scratch plus logical returned capture bytes.
    pub max_peak_bytes: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_capture_slots: 4_096,
            max_replay_cells: 16_777_216,
            max_history_nodes: 16_777_216,
            max_output_bytes: 256 << 20,
            max_work: 1 << 29,
            max_peak_bytes: 512 << 20,
        }
    }
}
