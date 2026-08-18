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
    /// Canonical HIR-derived ASCII byte sets that every match must intersect.
    pub required_literal_sets: usize,
    /// Full-source sequential passes prospectively charged by the selected
    /// required-literal scan services.
    ///
    /// Small retained sets use one bounded native service per set. Any wider
    /// set selects the single fused scalar pass instead.
    pub required_literal_source_passes: usize,
    /// Complete fixed inline storage retained for the required-literal proof.
    pub required_literal_proof_bytes: usize,
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
    /// Strictly certified URL aggregate plans retained by this artifact.
    pub url_aggregate_plans: usize,
    /// Compile-only artifacts whose authoritative URL plan is the complete
    /// semantic owner and whose retained continuation program is deliberately
    /// a minimal fail-closed shell. Zero preserves the ordinary full program.
    pub url_only_compile_artifacts: usize,
    /// Ordered finite TLD alternatives retained by the URL aggregate trie.
    pub url_aggregate_tlds: usize,
    pub url_aggregate_tld_bytes: usize,
    pub url_aggregate_build_work: usize,
    pub url_aggregate_persistent_bytes: usize,
    /// Structurally certified byte-topology plans retained exclusively for
    /// allocation-free whole-match `SpanSum` reduction.
    pub state_byte_span_sum_plans: usize,
    pub state_byte_span_sum_literal_bytes: usize,
    pub state_byte_span_sum_build_work: usize,
    /// Complete fixed inline `Option<StateByteSpanSumPlan>` storage retained
    /// by every compiled artifact, including ineligible and ordered-root
    /// shapes.
    pub state_byte_span_sum_persistent_bytes: usize,
    /// Source-independent mirrored bounded-span plans retained for direct
    /// whole-match `SpanSum` reduction.
    pub ordered_bounded_span_sum_plans: usize,
    /// Fixed anchor bytes retained by the ordered bounded-span theorem.
    pub ordered_bounded_span_sum_anchor_bytes: usize,
    /// Finite middle-chunk ceiling retained by the theorem.
    pub ordered_bounded_span_sum_max_chunks: usize,
    /// Exact logical work used to recognize and retain the theorem.
    pub ordered_bounded_span_sum_build_work: usize,
    /// Complete fixed inline `Option<OrderedBoundedSpanSumPlan>` storage
    /// retained by every compiled artifact, including ineligible and
    /// ordered-root shapes.
    pub ordered_bounded_span_sum_persistent_bytes: usize,
    /// Bytes in the mandatory leading literal retained by the unbounded
    /// terminal-frontier certificate.
    pub terminal_frontier_prefix_bytes: usize,
    /// Alternatives in the retained terminal byte class.
    pub terminal_frontier_bytes: usize,
    /// Direct root alternatives covered by the retained candidate scheduler.
    /// Zero preserves the established dense continuation route.
    pub candidate_entries: usize,
    /// Exact retained bytes for candidate entries, first-byte buckets, and
    /// any certified fixed-continuation descriptor and token tables.
    pub candidate_bytes: usize,
    /// Bytes in the retained inline whole-match minimum-width proof.
    ///
    /// The `Option<usize>` representation preserves the empty-language,
    /// nullable, and positive-width distinction used by operation admission.
    pub minimum_match_bytes_proof_bytes: usize,
    /// Exact whole-match minimum width authenticated by the canonical HIR.
    ///
    /// This repeats the retained proof value in compile accounting so
    /// downstream resource adapters can bind match-count-dependent envelopes
    /// without trusting an independently supplied width.
    pub minimum_match_bytes: Option<usize>,
    /// Bytes in the retained maximum-nonaccepting-run proof.
    ///
    /// The combined two-word slot stores one sentinel-encoded finite compiler
    /// certificate and the nullable scalar-owner-table handle. This preserves
    /// the incumbent `Option<usize>` byte charge without retaining
    /// certification scratch or enlarging the outer program.
    pub continuation_nonaccepting_run_proof_bytes: usize,
    /// Bytes in the retained mandatory-start-domain proof.
    ///
    /// The inline enum distinguishes unrestricted starts, absolute text start,
    /// and line-partitioned LF/CRLF-aware starts without retaining HIR data.
    /// This exact count is compact because every supported representation is
    /// statically bounded by the one-byte inline proof.
    pub start_domain_proof_bytes: u8,
    /// Bytes in the compiler-retained exact root-assertion proof.
    ///
    /// `None` means the continuation is not exactly one assertion followed
    /// by acceptance. `Some` retains the already-lowered assertion variant
    /// and permits the allocation-free Count/`SpanSum` physical route.
    pub root_assertion_proof_bytes: u8,
    pub program_states: usize,
    pub temporary_states_peak: usize,
    /// Compatibility-logical retained program bytes used for admission and
    /// exact replay. Repeated scalar references each retain their incumbent
    /// range-byte charge even when the compile-only construction policy proves
    /// that immutable physical owners may be shared. The construction receipt
    /// is authoritative for exact physical retained bytes.
    pub program_bytes: usize,
    /// Exact maximum compatibility-logical bytes simultaneously owned by
    /// compilation. This includes observed vector capacities, per-state
    /// scalar-range charges,
    /// retained required-suffix storage, and phase-local validation,
    /// repetition-product, and certification scratch.
    pub construction_peak_bytes: usize,
    /// Exact work to evaluate every state once at one input boundary,
    /// including each state's worst-case transition checks.
    pub execution_state_work: usize,
    /// Exact compiler certificate for the longest finite run that can keep a
    /// higher-priority continuation live after a lower-priority acceptance.
    ///
    /// `None` is an authenticated unbounded/uncertified result, not an absent
    /// accounting field. Rebar binds this value to any retained continuation
    /// sweep envelope so an equal-state envelope from another program cannot
    /// understate replay work.
    pub continuation_max_nonaccepting_run: Option<usize>,
    /// Exact raw successor edges retained by the continuation program.
    pub predecessor_edges: usize,
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

impl CompileAccounting {
    /// Exact retained bytes for the mandatory-start-domain proof.
    ///
    /// The public accessor keeps byte-count arithmetic in `usize` while the
    /// stored counter remains object-size neutral for enclosing reports and
    /// terminal error receipts.
    #[must_use]
    pub fn start_domain_proof_bytes(self) -> usize {
        usize::from(self.start_domain_proof_bytes)
    }

    /// Exact retained bytes for the root-assertion proof.
    #[must_use]
    pub fn root_assertion_proof_bytes(self) -> usize {
        usize::from(self.root_assertion_proof_bytes)
    }
}

#[cfg(test)]
mod compile_accounting_layout_tests {
    use super::CompileAccounting;

    #[test]
    fn scalar_sharing_preserves_legacy_compile_accounting_layout() {
        // 50 `usize` fields, two `Option<usize>` fields and four byte fields,
        // rounded to the eight-byte aggregate alignment.
        assert_eq!(core::mem::size_of::<CompileAccounting>(), 440);
        assert_eq!(core::mem::align_of::<CompileAccounting>(), 8);
    }
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
    /// Source bytes visited by the required-literal pre-continuation proof.
    pub required_literal_source_bytes: usize,
    /// Membership comparisons against retained required byte sets.
    pub required_literal_comparisons: usize,
    pub required_anchor_candidates: usize,
    pub required_anchor_scan_windows: usize,
    pub required_anchor_anchor_comparisons: usize,
    pub required_anchor_prefix_steps: usize,
    pub required_anchor_continuation_steps: usize,
    pub required_anchor_source_accesses: usize,
    pub required_anchor_queue_peak: usize,
    pub required_anchor_frontier_peak: usize,
    /// Exact counters from the strictly certified URL aggregate route. These
    /// remain zero for every generic continuation execution.
    pub url_segments: usize,
    pub url_dot_probes: usize,
    pub url_tld_transitions: usize,
    pub url_tld_candidates: usize,
    pub url_scheme_probes: usize,
    pub url_ipv4_candidates: usize,
    pub url_prefix_steps: usize,
    pub url_suffix_steps: usize,
    pub url_candidate_insertions: usize,
    pub url_candidate_visits: usize,
    pub replay_steps: usize,
    pub successful_paths: usize,
    pub suppressed_empty: usize,
    pub emitted_matches: usize,
    /// Bytes prospectively charged before whole-haystack UTF-8 validation.
    pub utf8_validation_work: usize,
    /// Peak number of live continuation states in a terminal frontier.
    pub frontier_peak_states: usize,
    /// Candidate-set insertion attempts, including duplicate attempts.
    pub frontier_insertions: usize,
    /// Continuation states evaluated after ordered frontier selection.
    pub frontier_evaluations: usize,
    /// Haystack bytes admitted to and visited by the reverse frontier sweep.
    pub frontier_source_bytes: usize,
    /// Retained random-access bytes allocated for the frontier and its index.
    pub frontier_bytes: usize,
    /// Frontier indexing, source, insertion, pop, and clearing work not
    /// already represented by state or transition counters.
    pub frontier_bookkeeping: usize,
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
