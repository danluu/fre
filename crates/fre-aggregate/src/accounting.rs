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
    /// Canonical variable-width UTF-8 paths censused while validating scalar ranges.
    pub utf8_sequences: usize,
    /// Byte ranges across the canonical UTF-8 validation census.
    pub utf8_byte_ranges: usize,
    /// Supported zero-width look nodes observed exactly once during bounded
    /// validation. Repetition expansion is accounted separately by states.
    pub look_assertions: usize,
    /// Nonempty suffix alternatives proved to terminate every match and
    /// retained as an optional sparse-execution seed.
    pub required_suffixes: usize,
    /// Total bytes across `required_suffixes`.
    pub required_suffix_bytes: usize,
    /// Structurally derived internal-anchor candidate stream retained for a
    /// bounded count verifier. Zero means the dense continuation route.
    pub required_internal_anchors: usize,
    pub required_internal_anchor_bytes: usize,
    pub required_internal_anchor_optional_stages: usize,
    /// Exact logical work observed while constructing the admitted plan.
    pub required_internal_anchor_build_work: usize,
    /// Work charged prospectively before any plan descriptor/source traversal.
    pub required_internal_anchor_build_work_upper_bound: usize,
    pub required_internal_anchor_persistent_bytes: usize,
    pub program_states: usize,
    pub temporary_states_peak: usize,
    pub program_bytes: usize,
    /// Exact maximum logical bytes simultaneously owned by compilation.
    /// This includes observed vector capacities, deeply owned scalar ranges,
    /// retained required-suffix storage, and phase-local validation,
    /// repetition-product, and certification scratch.
    pub construction_peak_bytes: usize,
    /// Exact work to evaluate every state once at one input boundary,
    /// including each state's worst-case transition checks.
    pub execution_state_work: usize,
    /// Whether row construction decodes one candidate scalar per boundary.
    pub has_scalar_transitions: bool,
    /// Worst-case binary-search comparisons for one scalar transition.
    pub max_scalar_search_checks: usize,
    /// Instruction-property checks performed during the already-budgeted
    /// plan-identity traversal to cache Unicode-word admission requirements.
    pub unicode_word_boundary_checks: usize,
    /// Whether execution must prospectively charge and validate the complete
    /// haystack before evaluating Unicode word-boundary assertions.
    pub requires_utf8_validation: bool,
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
    pub required_anchor_candidates: usize,
    pub required_anchor_prefix_steps: usize,
    pub required_anchor_continuation_steps: usize,
    pub required_anchor_source_accesses: usize,
    pub required_anchor_queue_peak: usize,
    pub required_anchor_frontier_peak: usize,
    pub replay_steps: usize,
    pub successful_paths: usize,
    pub suppressed_empty: usize,
    pub emitted_matches: usize,
    /// Bytes prospectively charged before whole-haystack UTF-8 validation.
    pub utf8_validation_work: usize,
    pub sequential_bytes_written: usize,
    pub sequential_bytes_read: usize,
    /// Exact logical input bytes read through backward/random access.
    pub random_access_bytes_read: usize,
    pub random_access_peak_bytes: usize,
    pub scratch_peak_bytes: usize,
    pub log_bytes: usize,
    pub output_bytes: usize,
    pub peak_bytes: usize,
    pub work: usize,
}
