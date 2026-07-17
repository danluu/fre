//! Independent checked resource limits.

/// Compiler admission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Maximum AST nodes.
    pub max_ast_nodes: usize,
    /// Maximum AST nesting depth.
    pub max_ast_depth: usize,
    /// Maximum user capture count, excluding group zero.
    pub max_captures: usize,
    /// Maximum expansion count for any counted repetition.
    pub max_repeat_expansion: usize,
    /// Maximum Thompson states.
    pub max_states: usize,
    /// Maximum simultaneously retained patch entries.
    pub max_patch_entries: usize,
    /// Maximum metered compiler operations.
    pub max_compile_work: usize,
    /// Maximum conservative immutable-program bytes.
    pub max_program_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_ast_nodes: 4_096,
            max_ast_depth: 128,
            max_captures: 64,
            max_repeat_expansion: 1_024,
            max_states: 65_536,
            max_patch_entries: 65_536,
            max_compile_work: 1_000_000,
            max_program_bytes: 16 * 1_024 * 1_024,
        }
    }
}

/// Per-search resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    /// Maximum state visits.
    pub max_state_visits: usize,
    /// Maximum logical capture-slot copies for the inline executor.
    pub max_slot_copies: usize,
    /// Maximum history nodes for the persistent-history executor.
    pub max_history_nodes: usize,
    /// Maximum nodes walked while materializing the winning history.
    pub max_history_walk: usize,
    /// Maximum conservative scratch bytes.
    pub max_scratch_bytes: usize,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            // The largest pinned counted-capture program has a conservative
            // 110,926,836-visit admission bound. This ceiling is charged but
            // does not allocate state-visit storage.
            max_state_visits: 200_000_000,
            max_slot_copies: 1_000_000_000,
            max_history_nodes: 100_000_000,
            max_history_walk: 100_000_000,
            max_scratch_bytes: 256 * 1_024 * 1_024,
        }
    }
}

/// Separate limits for repeated-search aggregate iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateLimits {
    /// Limits applied independently to each search.
    pub per_search: SearchLimits,
    /// Maximum number of searches.
    pub max_searches: usize,
    /// Maximum number of returned capture records.
    pub max_results: usize,
    /// Maximum state visits accumulated over all searches.
    pub max_total_state_visits: usize,
    /// Maximum slot copies accumulated over all searches.
    pub max_total_slot_copies: usize,
    /// Maximum history nodes accumulated over all searches.
    pub max_total_history_nodes: usize,
    /// Maximum history reconstruction steps accumulated over all searches.
    pub max_total_history_walk: usize,
    /// Maximum group entries inspected by a capture reducer.
    pub max_capture_events: usize,
    /// Maximum participating-group sum returned by a capture reducer.
    pub max_capture_count: usize,
}

impl Default for AggregateLimits {
    fn default() -> Self {
        Self {
            per_search: SearchLimits::default(),
            max_searches: 1_000_000,
            max_results: 1_000_000,
            max_total_state_visits: 1_000_000_000,
            max_total_slot_copies: 10_000_000_000,
            max_total_history_nodes: 1_000_000_000,
            max_total_history_walk: 1_000_000_000,
            max_capture_events: 1_000_000_000,
            max_capture_count: 1_000_000_000,
        }
    }
}
