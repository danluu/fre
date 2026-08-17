/// Hard limits for one HIR compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    /// Whether optional workload-specific execution intrinsics may be
    /// recognized. Disabling these intrinsics preserves the accepted HIR and
    /// compiles it through the generic complete continuation path.
    pub allow_workload_specific_intrinsics: bool,
    pub max_hir_nodes: usize,
    pub max_hir_depth: usize,
    pub max_hir_stack_items: usize,
    pub max_literal_bytes: usize,
    pub max_class_ranges: usize,
    /// Maximum canonical UTF-8 paths censused while validating Unicode scalar ranges.
    pub max_utf8_sequences: usize,
    /// Maximum byte ranges across the canonical UTF-8 validation census.
    pub max_utf8_byte_ranges: usize,
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
            allow_workload_specific_intrinsics: true,
            max_hir_nodes: 4_096,
            max_hir_depth: 64,
            max_hir_stack_items: 4_096,
            max_literal_bytes: 1 << 20,
            max_class_ranges: 1 << 16,
            max_utf8_sequences: 1 << 18,
            max_utf8_byte_ranges: 1 << 20,
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
