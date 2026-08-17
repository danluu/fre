//! Sparse reducers and complete-span visitation for large ordered finite byte languages.
//!
//! Count and span-sum literals are inserted in reverse into a trie whose sorted
//! outgoing edges are retained in compressed-sparse-row form. Aho-Corasick
//! failure links make one right-to-left haystack traversal report the lowest
//! source-index literal starting at every position. The same bounded
//! dynamic-program ring as the dense ordered-literal kernel then implements
//! successive non-overlapping leftmost-first matches. Complete-span plans build
//! the same sparse representation forward and settle each leftmost candidate
//! after bounded maximum-width lookahead.
//!
//! Count normally retains only `O(min(source, maximum-pattern-width))` reverse
//! DP state. Its optional fixed-source trace sidecar retains one compact choice
//! per source boundary, or `O(source)`, because the reverse automaton discovers
//! choices in the opposite order from forward trace publication. This is a
//! reusable semantic baseline, not a claim that full choice retention is the
//! best route for every language or source size.
//!
//! Construction consumes one concrete `Vec<&[u8]>` into the same
//! length-prefixed owned encoding retained for cache identity. The source
//! vector capacity is included in scratch and peak accounting; the pointed-to
//! immutable bytes remain caller-owned and are excluded by type. Restricting
//! the source to this concrete representation prevents arbitrary iterator or
//! `AsRef` code from running ahead of a charge. Trie insertion then reads only
//! the authenticated encoding. Every retained and temporary vector is fallibly
//! reserved. `build_work` is an exact charge in the documented abstract model:
//! one unit per source pattern and explicit byte visit, per sibling comparison,
//! per created temporary state or edge,
//! per CSR node or edge visit, per failure-BFS state or edge visit, per failure
//! hop, per sparse binary-search comparison, and per final non-root state
//! degree scan.
//! The fixed root table additionally charges one unit per initialized byte
//! entry. A charge is checked before the corresponding work.

use core::{cmp::Ordering, fmt, mem::size_of};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const UNSET: u32 = u32::MAX;
const TARGET_MASK: u32 = 0x00FF_FFFF;
const MAX_REPRESENTABLE_STATES: usize = 0x0100_0000;
const ROOT_TRANSITIONS: usize = 256;
const CACHE_FORMAT_VERSION: u32 = 2;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();

/// Stable reverse-DP strategy identity shared by the scalar reducers.
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.reverse-sparse-ac-root256-dp.v2";
/// Stable forward sparse strategy identity for complete-span visitation.
pub const SPANS_ALGORITHM_ID: &str =
    "ordered-literal-aggregate.forward-sparse-ac-root256-span-visit.v1";
/// Stable identity for the count-specialized plan.
pub const COUNT_PLAN_ID: &str = "ordered-literal-aggregate.count.reverse-sparse-ac-root256-dp.v2";
/// Stable identity for the span-sum-specialized plan.
pub const SPAN_SUM_PLAN_ID: &str =
    "ordered-literal-aggregate.span-sum.reverse-sparse-ac-root256-dp.v2";
/// Stable identity for the complete-span visitor.
pub const SPANS_PLAN_ID: &str =
    "ordered-literal-aggregate.spans.forward-sparse-ac-root256-span-visit.v1";
/// Stable fixed-source trace execution strategy identity.
pub const TRACE_ALGORITHM_ID: &str =
    "ordered-literal-aggregate.reverse-sparse-ac-root256-fixed-source-trace.v1";
/// Stable identity for the count trace execution specialization.
pub const TRACE_PLAN_ID: &str =
    "ordered-literal-aggregate.count-trace.reverse-sparse-ac-root256-fixed-source.v1";
/// Stable accounting identity for one reusable fixed-source count trace.
pub const TRACE_WORKSPACE_ACCOUNTING_ID: &str =
    "fre-kernels.sparse-ordered-literal-count-trace-workspace.v1";
/// Version of the receipt-bearing sparse construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 1;
/// Version of the partial-actual sparse construction ledger.
///
/// Version two includes the count plan's process-unique workspace-binding
/// identity in its inline persistent-byte charge.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 2;

static NEXT_COUNT_PLAN_IDENTITY: AtomicU64 = AtomicU64::new(1);

const TRACE_TRAVERSAL_KIND: &str =
    "single reverse sparse-AC choice-materialization pass plus fixed-source forward trace scan";

fn next_count_plan_identity() -> u64 {
    NEXT_COUNT_PLAN_IDENTITY
        .fetch_update(
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
            |identity| identity.checked_add(1),
        )
        .unwrap_or_else(|_| panic!("sparse ordered-literal count plan identity space exhausted"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
    Spans,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSemantics {
    LeftmostFirst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IterationSemantics {
    NonOverlapping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    EveryByteUnicodeOffSuppressAdjacentEmpty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Semantics {
    pub match_semantics: MatchSemantics,
    pub iteration_semantics: IterationSemantics,
    pub boundary_semantics: BoundarySemantics,
}

impl Semantics {
    const RUST_BYTES_UNICODE_OFF: Self = Self {
        match_semantics: MatchSemantics::LeftmostFirst,
        iteration_semantics: IterationSemantics::NonOverlapping,
        boundary_semantics: BoundarySemantics::EveryByteUnicodeOffSuppressAdjacentEmpty,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub transition_kind: &'static str,
    pub traversal_kind: &'static str,
    pub semantics: Semantics,
    pub encoded_patterns: &'a [u8],
}

/// Limits for one sparse automaton construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_trie_states: usize,
    pub max_sparse_edges: usize,
    pub max_build_work: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_trie_states: usize::MAX,
            max_sparse_edges: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 1_000_000,
            max_pattern_bytes: 4 * 1024 * 1024,
            max_identity_bytes: 8 * 1024 * 1024,
            max_trie_states: 4_194_304,
            max_sparse_edges: 4_194_303,
            max_build_work: 64 * 1024 * 1024,
            max_scratch_bytes: 32 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 96 * 1024 * 1024,
        }
    }
}

/// Exact charged work and observed vector-capacity accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub trie_states_upper_bound: usize,
    pub trie_states_actual: usize,
    pub sparse_edges_upper_bound: usize,
    pub sparse_edges_actual: usize,
    pub build_work: u64,
    pub max_pattern_bytes: usize,
    pub min_nonempty_pattern_bytes: Option<usize>,
    pub has_empty_pattern: bool,
    pub max_edge_search_checks: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_transitions: usize,
    pub max_edge_lookups: usize,
    pub max_edge_search_checks: u64,
    pub max_failure_steps: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_ring_initializations: usize,
    pub max_total_work: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_transitions: usize::MAX,
            max_edge_lookups: usize::MAX,
            max_edge_search_checks: u64::MAX,
            max_failure_steps: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_ring_initializations: usize::MAX,
            max_total_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_transitions: 128 * 1024 * 1024,
            max_edge_lookups: 256 * 1024 * 1024,
            max_edge_search_checks: 2 * 1024 * 1024 * 1024,
            max_failure_steps: 128 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_ring_initializations: 64 * 1024 * 1024,
            max_total_work: 3 * 1024 * 1024 * 1024,
            max_scratch_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub transitions: usize,
    pub edge_lookups: usize,
    pub edge_search_checks: u64,
    pub failure_steps: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub ring_entries: usize,
    pub ring_initializations: usize,
    pub total_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub transitions: usize,
    pub edge_lookups: usize,
    pub edge_search_checks: u64,
    pub failure_steps: usize,
    pub reducer_steps: usize,
    pub ring_initializations: usize,
    pub total_work: u64,
    pub match_events: u64,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

/// Construction limits for one reusable fixed-source sparse count trace.
///
/// These limits cover only caller-owned workspace setup. Every execution is
/// independently admitted under fresh [`ReduceLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceWorkspaceLimits {
    pub max_setup_work: u64,
    pub max_allocation_attempts: usize,
    pub max_retained_bytes: usize,
    pub max_peak_bytes: usize,
}

impl TraceWorkspaceLimits {
    /// Disable caller-selected setup caps while retaining checked arithmetic
    /// and fallible reservations.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_setup_work: u64::MAX,
            max_allocation_attempts: usize::MAX,
            max_retained_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for TraceWorkspaceLimits {
    fn default() -> Self {
        Self {
            max_setup_work: 128 * 1024 * 1024,
            max_allocation_attempts: 2,
            max_retained_bytes: 128 * 1024 * 1024,
            max_peak_bytes: 192 * 1024 * 1024,
        }
    }
}

/// Exact retained resources of one fixed-source sparse count trace workspace.
///
/// Byte counts are the sum of observed private vector capacities. They omit
/// allocator metadata and size-class rounding, so this is a logical accounting
/// receipt rather than an allocator receipt. Setup work charges one unit per
/// initialized choice slot and one unit per nonempty vector reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceWorkspaceAccounting {
    pub accounting_id: &'static str,
    pub source_bytes: usize,
    pub pattern_count: usize,
    pub has_empty_pattern: bool,
    pub min_nonempty_pattern_bytes: Option<usize>,
    pub plan_persistent_bytes: usize,
    pub choice_slots: usize,
    pub choice_capacity: usize,
    pub trace_slots: usize,
    pub trace_capacity: usize,
    pub retained_logical_bytes: usize,
    pub peak_bytes: usize,
    pub setup_work: u64,
    pub allocation_attempts: usize,
}

impl TraceWorkspaceAccounting {
    /// Verify every self-contained arithmetic relationship in this receipt.
    #[must_use]
    pub fn closes(self) -> bool {
        let expected_choices = self.source_bytes.checked_add(1);
        let expected_trace = if self.has_empty_pattern {
            expected_choices
        } else {
            self.min_nonempty_pattern_bytes
                .filter(|&minimum| minimum != 0)
                .and_then(|minimum| self.source_bytes.checked_div(minimum))
        };
        let choice_bytes = self.choice_capacity.checked_mul(size_of::<Output>());
        let trace_bytes = self
            .trace_capacity
            .checked_mul(size_of::<SparseOrderedLiteralTraceMatch>());
        let retained =
            choice_bytes.and_then(|bytes| trace_bytes.and_then(|trace| bytes.checked_add(trace)));
        let peak = retained.and_then(|bytes| self.plan_persistent_bytes.checked_add(bytes));
        let allocations =
            usize::from(self.choice_slots != 0).checked_add(usize::from(self.trace_slots != 0));
        let setup_work = u64::try_from(self.choice_slots).ok().and_then(|work| {
            u64::try_from(self.allocation_attempts)
                .ok()
                .and_then(|attempts| work.checked_add(attempts))
        });
        self.accounting_id == TRACE_WORKSPACE_ACCOUNTING_ID
            && self.pattern_count != 0
            && self
                .min_nonempty_pattern_bytes
                .is_none_or(|minimum| minimum != 0)
            && expected_choices == Some(self.choice_slots)
            && expected_trace == Some(self.trace_slots)
            && self.choice_slots <= self.choice_capacity
            && self.trace_slots <= self.trace_capacity
            && retained == Some(self.retained_logical_bytes)
            && peak == Some(self.peak_bytes)
            && allocations == Some(self.allocation_attempts)
            && setup_work == Some(self.setup_work)
    }
}

/// One source-priority selected literal and its non-overlapping byte span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseOrderedLiteralTraceMatch {
    ordinal: u32,
    start: usize,
    end: usize,
}

impl SparseOrderedLiteralTraceMatch {
    /// Zero-based source-pattern ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    /// Inclusive start byte offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive end byte offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Opaque caller-owned storage for repeated traces at one exact source length.
///
/// The workspace is bound to one immutable count-plan instance. A failed run
/// may leave private choices and a private trace prefix populated, but publishes
/// no borrow. The next run overwrites every choice and clears the trace before
/// it can publish another report.
pub struct SparseOrderedLiteralTraceWorkspace {
    plan_identity: u64,
    accounting: TraceWorkspaceAccounting,
    choices: Vec<Output>,
    trace: Vec<SparseOrderedLiteralTraceMatch>,
}

impl fmt::Debug for SparseOrderedLiteralTraceWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SparseOrderedLiteralTraceWorkspace")
            .field("accounting", &self.accounting)
            .finish_non_exhaustive()
    }
}

impl SparseOrderedLiteralTraceWorkspace {
    /// Exact source length admitted during construction.
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.accounting.source_bytes
    }

    /// Exact successful workspace-construction ledger.
    #[must_use]
    pub const fn accounting(&self) -> TraceWorkspaceAccounting {
        self.accounting
    }
}

/// One allocation-free sparse count result borrowing a reusable trace.
#[derive(Debug)]
pub struct SparseOrderedLiteralTraceWorkspaceReport<'plan, 'workspace> {
    accounting: ReduceAccounting<'plan>,
    workspace_accounting: TraceWorkspaceAccounting,
    matches: &'workspace [SparseOrderedLiteralTraceMatch],
    selected_span_bytes: u64,
    selected_ordinal_sum: u64,
}

impl<'plan, 'workspace> SparseOrderedLiteralTraceWorkspaceReport<'plan, 'workspace> {
    /// Number of selected non-overlapping matches.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.accounting.actual.match_events
    }

    /// Complete execution prospective and actual counters.
    #[must_use]
    pub const fn accounting(&self) -> ReduceAccounting<'plan> {
        self.accounting
    }

    /// Workspace receipt authenticated before this run read source bytes.
    #[must_use]
    pub const fn workspace_accounting(&self) -> TraceWorkspaceAccounting {
        self.workspace_accounting
    }

    /// Selected source ordinals and spans in forward encounter order.
    #[must_use]
    pub const fn matches(&self) -> &'workspace [SparseOrderedLiteralTraceMatch] {
        self.matches
    }

    /// Exact sum of selected non-empty span widths.
    #[must_use]
    pub const fn selected_span_bytes(&self) -> u64 {
        self.selected_span_bytes
    }

    /// Exact sum of selected zero-based source ordinals.
    #[must_use]
    pub const fn selected_ordinal_sum(&self) -> u64 {
        self.selected_ordinal_sum
    }

    /// Verify the borrowed result against its fixed workspace and P/A ledgers
    /// without traversing the trace a second time.
    #[must_use]
    pub fn closes(&self) -> bool {
        let matches = u64::try_from(self.matches.len()).ok();
        let maximum_ordinal = u64::try_from(self.workspace_accounting.pattern_count)
            .ok()
            .and_then(|patterns| patterns.checked_sub(1));
        let ordinal_upper = maximum_ordinal
            .and_then(|ordinal| matches.and_then(|count| ordinal.checked_mul(count)));
        self.accounting.identity.algorithm_id == TRACE_ALGORITHM_ID
            && self.accounting.identity.operation == Operation::Count
            && self.accounting.identity.plan_id == TRACE_PLAN_ID
            && self.accounting.identity.cache_format_version == CACHE_FORMAT_VERSION
            && self.accounting.identity.traversal_kind == TRACE_TRAVERSAL_KIND
            && self.accounting.identity.semantics == Semantics::RUST_BYTES_UNICODE_OFF
            && ordinal_upper.is_some_and(|limit| self.selected_ordinal_sum <= limit)
            && trace_accounting_closes(
                self.workspace_accounting,
                self.matches.len(),
                self.selected_span_bytes,
                self.accounting.actual,
                self.accounting.upper_bounds,
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

/// One complete non-overlapping match span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary and accounting for one complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult<'a> {
    pub matches: usize,
    pub span_sum: usize,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPatternSet,
    /// The forward visitor is deliberately limited to non-empty languages.
    EmptyPatternSpanVisitUnsupported,
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    IdentityBytesLimit {
        needed: usize,
        limit: usize,
    },
    TrieStatesLimit {
        needed: usize,
        limit: usize,
    },
    SparseEdgesLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    RepresentationLimit {
        structure: &'static str,
        needed: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sparse ordered-literal build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

/// Immutable identity and caller envelope for one sparse construction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptIdentity {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub limits: BuildLimits,
    pub algorithm_version: u32,
    pub accounting_version: u32,
}

/// Exact effects committed through the last admitted sparse construction step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildAttemptActual {
    pub work: u64,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub live_scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// One success-or-failure sparse construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptReceipt {
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
    accounting: Option<BuildAccounting>,
    published: bool,
}

impl BuildAttemptReceipt {
    #[must_use]
    pub const fn identity(&self) -> BuildAttemptIdentity {
        self.identity
    }

    #[must_use]
    pub const fn actual(&self) -> BuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub const fn accounting(&self) -> Option<BuildAccounting> {
        self.accounting
    }

    #[must_use]
    pub const fn published(&self) -> bool {
        self.published
    }

    #[must_use]
    pub fn contains_actual(&self) -> bool {
        self.identity.algorithm_id == algorithm_id(self.identity.operation)
            && self.identity.algorithm_version == BUILD_ATTEMPT_ALGORITHM_VERSION
            && self.identity.accounting_version == BUILD_ATTEMPT_ACCOUNTING_VERSION
            && self.actual.work <= self.identity.limits.max_build_work
            && self.actual.live_persistent_bytes <= self.identity.limits.max_persistent_bytes
            && self.actual.live_scratch_bytes <= self.identity.limits.max_scratch_bytes
            && self.actual.peak_bytes <= self.identity.limits.max_peak_bytes
            && self.actual.copied_bytes <= self.actual.initialized_bytes
            && self.actual.peak_bytes
                >= self
                    .actual
                    .live_persistent_bytes
                    .saturating_add(self.actual.live_scratch_bytes)
    }

    fn closes_success(&self, operation: Operation, accounting: BuildAccounting) -> bool {
        self.published
            && self.identity.operation == operation
            && self.identity.plan_id
                == match operation {
                    Operation::Count => COUNT_PLAN_ID,
                    Operation::SpanSum => SPAN_SUM_PLAN_ID,
                    Operation::Spans => SPANS_PLAN_ID,
                }
            && self.accounting == Some(accounting)
            && self.contains_actual()
            && self.actual.work == accounting.build_work
            && self.actual.live_persistent_bytes == accounting.persistent_bytes
            && self.actual.live_scratch_bytes == 0
            && self.actual.peak_bytes <= accounting.peak_bytes
    }

    fn closes_failure(&self) -> bool {
        !self.published && self.accounting.is_none() && self.contains_actual()
    }
}

const fn algorithm_id(operation: Operation) -> &'static str {
    match operation {
        Operation::Count | Operation::SpanSum => ALGORITHM_ID,
        Operation::Spans => SPANS_ALGORITHM_ID,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildFailureKind {
    EmptyPatternSet,
    EmptyPatternSpanVisitUnsupported,
    PatternLimit,
    PatternBytesLimit,
    IdentityBytesLimit,
    TrieStatesLimit,
    SparseEdgesLimit,
    WorkLimit,
    ScratchLimit,
    PersistentLimit,
    PeakLimit,
    RepresentationLimit,
    AllocationFailed,
    InternalInvariant,
    ArithmeticOverflow,
}

impl BuildFailureKind {
    const fn from_error(error: &BuildError) -> Self {
        match error {
            BuildError::EmptyPatternSet => Self::EmptyPatternSet,
            BuildError::EmptyPatternSpanVisitUnsupported => Self::EmptyPatternSpanVisitUnsupported,
            BuildError::PatternLimit { .. } => Self::PatternLimit,
            BuildError::PatternBytesLimit { .. } => Self::PatternBytesLimit,
            BuildError::IdentityBytesLimit { .. } => Self::IdentityBytesLimit,
            BuildError::TrieStatesLimit { .. } => Self::TrieStatesLimit,
            BuildError::SparseEdgesLimit { .. } => Self::SparseEdgesLimit,
            BuildError::WorkLimit { .. } => Self::WorkLimit,
            BuildError::ScratchLimit { .. } => Self::ScratchLimit,
            BuildError::PersistentLimit { .. } => Self::PersistentLimit,
            BuildError::PeakLimit { .. } => Self::PeakLimit,
            BuildError::RepresentationLimit { .. } => Self::RepresentationLimit,
            BuildError::AllocationFailed { .. } => Self::AllocationFailed,
            BuildError::InternalInvariant { .. } => Self::InternalInvariant,
            BuildError::ArithmeticOverflow { .. } => Self::ArithmeticOverflow,
        }
    }
}

/// Terminal sparse construction failure with its immutable partial actuals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildAttemptError {
    source: BuildError,
    receipt: BuildAttemptReceipt,
    seal: BuildFailureKind,
}

impl BuildAttemptError {
    fn new(source: BuildError, identity: BuildAttemptIdentity, actual: BuildAttemptActual) -> Self {
        let seal = BuildFailureKind::from_error(&source);
        Self {
            source,
            receipt: BuildAttemptReceipt {
                identity,
                actual,
                accounting: None,
                published: false,
            },
            seal,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &BuildError {
        &self.source
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.seal == BuildFailureKind::from_error(&self.source) && self.receipt.closes_failure()
    }

    #[must_use]
    pub fn into_source(self) -> BuildError {
        self.source
    }
}

impl fmt::Display for BuildAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for BuildAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Copy)]
enum BuildAllocationClass {
    Persistent,
    Scratch,
}

struct BuildAttemptTracker {
    actual: BuildAttemptActual,
}

impl BuildAttemptTracker {
    fn new() -> Self {
        Self {
            actual: BuildAttemptActual::default(),
        }
    }

    fn publish_inline(&mut self, bytes: usize) -> Result<(), BuildError> {
        let live_persistent_bytes = self.actual.live_persistent_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "published inline plan bytes",
            },
        )?;
        let initialized_bytes = self.actual.initialized_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "published inline initialized bytes",
            },
        )?;
        self.actual.live_persistent_bytes = live_persistent_bytes;
        self.actual.initialized_bytes = initialized_bytes;
        self.actual.peak_bytes = self.actual.peak_bytes.max(live_persistent_bytes);
        Ok(())
    }

    fn sync_work(&mut self, work: &BuildWork) {
        self.actual.work = work.used;
    }

    fn observe_copy(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.copied_bytes =
            self.actual
                .copied_bytes
                .checked_add(bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual copied bytes",
                })?;
        self.observe_initialization(bytes)
    }

    fn observe_initialization(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.initialized_bytes = self.actual.initialized_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "actual initialized bytes",
            },
        )?;
        Ok(())
    }

    fn add_external_scratch(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.live_scratch_bytes = self.actual.live_scratch_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "borrowed source live scratch",
            },
        )?;
        self.observe_peak()
    }

    fn release_external_scratch(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.live_scratch_bytes = self.actual.live_scratch_bytes.checked_sub(bytes).ok_or(
            BuildError::InternalInvariant {
                detail: "borrowed source scratch was live",
            },
        )?;
        Ok(())
    }

    fn observe_reserve<T>(
        &mut self,
        before_capacity: usize,
        after_capacity: usize,
        class: BuildAllocationClass,
    ) -> Result<(), BuildError> {
        if after_capacity <= before_capacity {
            return Ok(());
        }
        let before =
            before_capacity
                .checked_mul(size_of::<T>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "previous allocation capacity bytes",
                })?;
        let after =
            after_capacity
                .checked_mul(size_of::<T>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "observed allocation capacity bytes",
                })?;
        self.actual.allocations =
            self.actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual build allocation count",
                })?;
        self.actual.allocated_bytes = self.actual.allocated_bytes.checked_add(after).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "cumulative allocated bytes",
            },
        )?;
        let live = match class {
            BuildAllocationClass::Persistent => &mut self.actual.live_persistent_bytes,
            BuildAllocationClass::Scratch => &mut self.actual.live_scratch_bytes,
        };
        *live = live
            .checked_sub(before)
            .and_then(|bytes| bytes.checked_add(after))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed live allocation bytes",
            })?;
        self.observe_peak()
    }

    fn release<T>(
        &mut self,
        capacity: usize,
        class: BuildAllocationClass,
    ) -> Result<(), BuildError> {
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "released allocation capacity bytes",
            })?;
        let live = match class {
            BuildAllocationClass::Persistent => &mut self.actual.live_persistent_bytes,
            BuildAllocationClass::Scratch => &mut self.actual.live_scratch_bytes,
        };
        *live = live
            .checked_sub(bytes)
            .ok_or(BuildError::InternalInvariant {
                detail: "released build capacity was live",
            })?;
        Ok(())
    }

    fn observe_peak(&mut self) -> Result<(), BuildError> {
        let live = self
            .actual
            .live_persistent_bytes
            .checked_add(self.actual.live_scratch_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual construction live bytes",
            })?;
        self.actual.peak_bytes = self.actual.peak_bytes.max(live);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    /// A caller-owned trace workspace belongs to another count plan, source
    /// length, or private fixed-capacity layout.
    TraceWorkspaceMismatch {
        detail: &'static str,
    },
    TraceWorkspaceSetupWorkLimit {
        needed: u64,
        limit: u64,
    },
    TraceWorkspaceAllocationAttemptsLimit {
        needed: usize,
        limit: usize,
    },
    TransitionLimit {
        needed: usize,
        limit: usize,
    },
    EdgeLookupLimit {
        needed: usize,
        limit: usize,
    },
    EdgeSearchChecksLimit {
        needed: u64,
        limit: u64,
    },
    FailureStepsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    ReducerStepsLimit {
        needed: usize,
        limit: usize,
    },
    RingInitializationLimit {
        needed: usize,
        limit: usize,
    },
    TotalWorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sparse ordered-literal reduce refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct Output {
    pattern: u32,
    length: u32,
}

impl Output {
    fn min_priority(self, other: Self) -> Self {
        if self.pattern <= other.pattern {
            self
        } else {
            other
        }
    }

    fn earliest_start_at_end(self, other: Self) -> Self {
        match self.length.cmp(&other.length) {
            Ordering::Greater => self,
            Ordering::Less => other,
            Ordering::Equal => self.min_priority(other),
        }
    }
}

#[derive(Debug)]
struct SparseAc {
    /// Root trie targets indexed by byte. Zero denotes an absent edge, which
    /// is unambiguous because every trie edge targets a non-root state.
    root_transitions: [u32; ROOT_TRANSITIONS],
    offsets: Vec<u32>,
    edges: Vec<u32>,
    failure: Vec<u32>,
    output: Vec<Output>,
}

#[derive(Default)]
struct SearchCounters {
    edge_lookups: usize,
    edge_search_checks: u64,
    failure_steps: usize,
}

impl SparseAc {
    fn state_count(&self) -> usize {
        self.output.len()
    }

    fn edge_with_work(
        &self,
        state: u32,
        byte: u8,
        work: &mut BuildWork,
    ) -> Result<Option<u32>, BuildError> {
        let state = usize::try_from(state).expect("u32 state fits usize");
        let start = usize::try_from(self.offsets[state]).expect("u32 edge offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(self.offsets[next_state]).expect("u32 edge offset fits usize");
        let mut low = start;
        let mut high = end;
        while low < high {
            work.charge(1)?;
            let middle = low
                .checked_add(
                    high.checked_sub(low)
                        .expect("binary-search bounds are ordered")
                        / 2,
                )
                .expect("binary-search midpoint remains within the edge slice");
            match edge_byte(self.edges[middle]).cmp(&byte) {
                Ordering::Less => {
                    low = middle
                        .checked_add(1)
                        .expect("binary-search midpoint is below the slice end");
                }
                Ordering::Equal => return Ok(Some(edge_target(self.edges[middle]))),
                Ordering::Greater => high = middle,
            }
        }
        Ok(None)
    }

    fn nonroot_edge_counted(
        &self,
        state: u32,
        byte: u8,
        counters: &mut SearchCounters,
    ) -> Option<u32> {
        debug_assert_ne!(state, 0);
        counters.edge_lookups = counters
            .edge_lookups
            .checked_add(1)
            .expect("preflight proves at most two sparse lookups per input byte");
        let state = usize::try_from(state).expect("u32 state fits usize");
        let start = usize::try_from(self.offsets[state]).expect("u32 edge offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(self.offsets[next_state]).expect("u32 edge offset fits usize");
        let mut low = start;
        let mut high = end;
        while low < high {
            counters.edge_search_checks = counters
                .edge_search_checks
                .checked_add(1)
                .expect("preflight proves sparse comparison accounting fits u64");
            let middle = low
                .checked_add(
                    high.checked_sub(low)
                        .expect("binary-search bounds are ordered")
                        / 2,
                )
                .expect("binary-search midpoint remains within the edge slice");
            match edge_byte(self.edges[middle]).cmp(&byte) {
                Ordering::Less => {
                    low = middle
                        .checked_add(1)
                        .expect("binary-search midpoint is below the slice end");
                }
                Ordering::Equal => return Some(edge_target(self.edges[middle])),
                Ordering::Greater => high = middle,
            }
        }
        None
    }

    fn next(&self, mut state: u32, byte: u8, counters: &mut SearchCounters) -> u32 {
        loop {
            if state == 0 {
                counters.edge_lookups = counters
                    .edge_lookups
                    .checked_add(1)
                    .expect("preflight proves at most two sparse lookups per input byte");
                return self.root_transitions[usize::from(byte)];
            }
            if let Some(next) = self.nonroot_edge_counted(state, byte, counters) {
                return next;
            }
            state = self.failure[usize::try_from(state).expect("u32 state fits usize")];
            counters.failure_steps = counters
                .failure_steps
                .checked_add(1)
                .expect("AC depth amortization proves at most one failure per input byte");
        }
    }

    fn output(&self, state: u32) -> Option<(u32, usize)> {
        let output = self.output[usize::try_from(state).expect("u32 state fits usize")];
        (output.pattern != UNSET).then(|| {
            (
                output.pattern,
                usize::try_from(output.length).expect("u32 length fits usize"),
            )
        })
    }
}

#[derive(Debug)]
struct PlanCore {
    automaton: SparseAc,
    encoded_patterns: Vec<u8>,
    build: BuildAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstructionTraversal {
    Reverse,
    Forward,
}

#[derive(Debug)]
pub struct SparseOrderedLiteralCountPlan {
    core: PlanCore,
    identity: u64,
}

#[derive(Debug)]
pub struct SparseOrderedLiteralSpanSumPlan {
    core: PlanCore,
    operation: Operation,
}

/// Complete-span specialization of the shared sparse span plan owner.
pub type SparseOrderedLiteralSpansPlan = SparseOrderedLiteralSpanSumPlan;

/// Successful sparse count-plan construction and its closed receipt.
#[derive(Debug)]
pub struct CountBuildAttempt {
    plan: SparseOrderedLiteralCountPlan,
    receipt: BuildAttemptReceipt,
}

impl CountBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &SparseOrderedLiteralCountPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt
            .closes_success(Operation::Count, self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (SparseOrderedLiteralCountPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> SparseOrderedLiteralCountPlan {
        self.plan
    }
}

/// Successful sparse span-sum-plan construction and its closed receipt.
#[derive(Debug)]
pub struct SpanSumBuildAttempt {
    plan: SparseOrderedLiteralSpanSumPlan,
    receipt: BuildAttemptReceipt,
}

/// Successful sparse complete-span-plan construction and its closed receipt.
#[derive(Debug)]
pub struct SpansBuildAttempt {
    plan: SparseOrderedLiteralSpansPlan,
    receipt: BuildAttemptReceipt,
}

impl SpansBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &SparseOrderedLiteralSpansPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt
            .closes_success(Operation::Spans, self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (SparseOrderedLiteralSpansPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> SparseOrderedLiteralSpansPlan {
        self.plan
    }
}

impl SpanSumBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &SparseOrderedLiteralSpanSumPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt
            .closes_success(Operation::SpanSum, self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (SparseOrderedLiteralSpanSumPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> SparseOrderedLiteralSpanSumPlan {
        self.plan
    }
}

impl SparseOrderedLiteralCountPlan {
    /// Consume a concrete borrowed-pattern vector into a checked owned encoding.
    pub fn build(patterns: Vec<&[u8]>, limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_attempt(patterns, limits)
            .map(CountBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    /// Build while retaining exact success or partial-failure construction
    /// effects.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so reporting a failed allocation never needs another allocation"
    )]
    pub fn build_attempt(
        patterns: Vec<&[u8]>,
        limits: BuildLimits,
    ) -> Result<CountBuildAttempt, BuildAttemptError> {
        let identity = BuildAttemptIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id: COUNT_PLAN_ID,
            operation: Operation::Count,
            limits,
            algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
            accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
        };
        PlanCore::build_attempt(
            patterns,
            limits,
            size_of::<Self>(),
            identity,
            ConstructionTraversal::Reverse,
        )
        .map(|(core, receipt)| CountBuildAttempt {
            plan: Self {
                core,
                identity: next_count_plan_identity(),
            },
            receipt,
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::Count)
    }

    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let mut upper = self
            .core
            .preflight_reduce::<CountState>(haystack.len(), false, limits)?;
        let mut ring = reserve_ring::<CountState>(upper.ring_entries, "count DP ring")?;
        self.core.finish_scratch_preflight(
            &mut upper,
            ring.capacity(),
            size_of::<CountState>(),
            limits,
        )?;
        ring.resize(upper.ring_entries, CountState::default());
        let actual = self.core.execute_count(haystack, &mut ring, upper)?;
        Ok(CountResult {
            count: actual.match_events,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

impl SparseOrderedLiteralCountPlan {
    /// Immutable identity of the fixed-source trace execution strategy.
    ///
    /// The trace shares this plan's encoded language and sparse transitions,
    /// but its full choice materialization and forward publication are not the
    /// scalar count DP-ring traversal.
    #[must_use]
    pub fn trace_cache_identity(&self) -> CacheIdentity<'_> {
        let mut identity = self.cache_identity();
        identity.algorithm_id = TRACE_ALGORITHM_ID;
        identity.plan_id = TRACE_PLAN_ID;
        identity.traversal_kind = TRACE_TRAVERSAL_KIND;
        identity
    }

    /// Preallocate every source-boundary choice and possible selected-match
    /// slot needed by repeated traces at one exact source length.
    pub fn prepare_trace_workspace(
        &self,
        source_bytes: usize,
        limits: TraceWorkspaceLimits,
    ) -> Result<SparseOrderedLiteralTraceWorkspace, ReduceError> {
        let requested = self.trace_workspace_accounting(
            source_bytes,
            source_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace workspace choice slots",
                })?,
            self.trace_slots(source_bytes)?,
        )?;
        check_trace_workspace_limits(requested, limits)?;

        // Arithmetic and caller resource gates precede the first retained
        // allocation. Any later failure drops only unpublished local owners.
        let mut choices = reserve_trace_vec::<Output>(
            requested.choice_slots,
            "sparse ordered-literal trace choices",
        )?;
        choices.resize(
            requested.choice_slots,
            Output {
                pattern: UNSET,
                length: 0,
            },
        );
        let after_choices = self.trace_workspace_accounting(
            source_bytes,
            choices.capacity(),
            requested.trace_slots,
        )?;
        check_trace_workspace_limits(after_choices, limits)?;

        let trace = reserve_trace_vec::<SparseOrderedLiteralTraceMatch>(
            requested.trace_slots,
            "sparse ordered-literal trace entries",
        )?;
        let accounting =
            self.trace_workspace_accounting(source_bytes, choices.capacity(), trace.capacity())?;
        check_trace_workspace_limits(accounting, limits)?;
        if !accounting.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "trace workspace accounting did not close",
            });
        }
        Ok(SparseOrderedLiteralTraceWorkspace {
            plan_identity: self.identity,
            accounting,
            choices,
            trace,
        })
    }

    /// Execute the exact source-priority trace through fixed-capacity
    /// caller-owned storage without allocating or growing it.
    ///
    /// Plan binding, source length, private layout, every prospective
    /// arithmetic bound, and every caller limit are checked before the first
    /// source byte is read.
    #[allow(
        clippy::too_many_lines,
        reason = "preflight, reverse choice discovery, forward publication, and exact receipt construction form one atomic trace transaction"
    )]
    pub fn execute_trace_with_workspace<'plan, 'workspace>(
        &'plan self,
        haystack: &[u8],
        limits: ReduceLimits,
        workspace: &'workspace mut SparseOrderedLiteralTraceWorkspace,
    ) -> Result<SparseOrderedLiteralTraceWorkspaceReport<'plan, 'workspace>, ReduceError> {
        let workspace_accounting = self.validate_trace_workspace(haystack.len(), workspace)?;
        let upper = self.trace_reduce_upper_bounds(haystack.len(), workspace_accounting, limits)?;

        // The traced prospective includes one fixed work unit for resetting
        // this Copy-only retained prefix. Clearing does not visit its entries.
        workspace.trace.clear();
        let mut state = 0_u32;
        let mut search = SearchCounters::default();
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self
                    .core
                    .automaton
                    .next(state, haystack[position], &mut search);
            }
            workspace.choices[position] =
                self.core.automaton.output[usize::try_from(state).expect("u32 state fits usize")];
        }

        let mut next_eligible = 0_usize;
        let mut last_end = None::<usize>;
        let mut selected_span_bytes = 0_u64;
        let mut selected_ordinal_sum = 0_u64;
        for position in 0..workspace_accounting.choice_slots {
            if position < next_eligible {
                continue;
            }
            let choice = workspace.choices[position];
            if choice.pattern == UNSET {
                continue;
            }
            let length =
                usize::try_from(choice.length).map_err(|_| ReduceError::InternalInvariant {
                    detail: "trace choice length fits usize",
                })?;
            if length == 0 && last_end == Some(position) {
                continue;
            }
            let end = position
                .checked_add(length)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace selected end",
                })?;
            if end > haystack.len() {
                return Err(ReduceError::InternalInvariant {
                    detail: "trace choice ends within its exact source",
                });
            }
            if workspace.trace.len() >= workspace_accounting.trace_slots {
                return Err(ReduceError::InternalInvariant {
                    detail: "trace exceeded its admitted logical slots",
                });
            }
            workspace.trace.push(SparseOrderedLiteralTraceMatch {
                ordinal: choice.pattern,
                start: position,
                end,
            });
            trace_execution_probe::after_match()?;
            selected_span_bytes = selected_span_bytes
                .checked_add(u64::try_from(length).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "trace selected span width",
                    }
                })?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace selected span sum",
                })?;
            selected_ordinal_sum = selected_ordinal_sum
                .checked_add(u64::from(choice.pattern))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace selected ordinal sum",
                })?;
            next_eligible = end;
            last_end = Some(end);
        }

        let match_events =
            u64::try_from(workspace.trace.len()).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "trace match count as u64",
            })?;
        let reducer_steps = workspace_accounting
            .choice_slots
            .checked_mul(2)
            .and_then(|steps| steps.checked_add(workspace.trace.len()))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual trace reducer steps",
            })?;
        let total_work = u64::try_from(haystack.len())
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(search.edge_lookups).ok()?))
            .and_then(|work| work.checked_add(search.edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(search.failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(reducer_steps).ok()?))
            .and_then(|work| work.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual sparse trace work",
            })?;
        let actual = ReduceActualCounters {
            transitions: haystack.len(),
            edge_lookups: search.edge_lookups,
            edge_search_checks: search.edge_search_checks,
            failure_steps: search.failure_steps,
            reducer_steps,
            ring_initializations: 0,
            total_work,
            match_events,
            count: Some(match_events),
            span_sum: Some(selected_span_bytes),
            scratch_bytes: workspace_accounting.retained_logical_bytes,
            peak_bytes: workspace_accounting.peak_bytes,
        };
        if !trace_accounting_closes(
            workspace_accounting,
            workspace.trace.len(),
            selected_span_bytes,
            actual,
            upper,
        ) {
            return Err(ReduceError::InternalInvariant {
                detail: "sparse trace counters escaped their admitted bounds",
            });
        }
        let report = SparseOrderedLiteralTraceWorkspaceReport {
            accounting: ReduceAccounting {
                identity: self.trace_cache_identity(),
                upper_bounds: upper,
                actual,
            },
            workspace_accounting,
            matches: &workspace.trace,
            selected_span_bytes,
            selected_ordinal_sum,
        };
        if !report.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "sparse trace report did not close",
            });
        }
        Ok(report)
    }

    fn trace_slots(&self, source_bytes: usize) -> Result<usize, ReduceError> {
        if self.core.build.has_empty_pattern {
            source_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace empty-match slots",
                })
        } else {
            source_bytes
                .checked_div(self.core.build.min_nonempty_pattern_bytes.ok_or(
                    ReduceError::InternalInvariant {
                        detail: "nonempty trace language retains a minimum width",
                    },
                )?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace nonempty match slots",
                })
        }
    }

    fn trace_workspace_accounting(
        &self,
        source_bytes: usize,
        choice_capacity: usize,
        trace_capacity: usize,
    ) -> Result<TraceWorkspaceAccounting, ReduceError> {
        let choice_slots = source_bytes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace workspace choice slots",
            })?;
        let trace_slots = self.trace_slots(source_bytes)?;
        if choice_capacity < choice_slots || trace_capacity < trace_slots {
            return Err(ReduceError::TraceWorkspaceMismatch {
                detail: "trace workspace capacities are smaller than their logical slots",
            });
        }
        let choice_bytes = choice_capacity.checked_mul(size_of::<Output>()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "trace workspace choice capacity bytes",
            },
        )?;
        let trace_bytes = trace_capacity
            .checked_mul(size_of::<SparseOrderedLiteralTraceMatch>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace workspace match capacity bytes",
            })?;
        let retained_logical_bytes =
            choice_bytes
                .checked_add(trace_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "trace workspace retained logical bytes",
                })?;
        let peak_bytes = self
            .core
            .build
            .persistent_bytes
            .checked_add(retained_logical_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace workspace peak bytes",
            })?;
        let allocation_attempts = usize::from(choice_slots != 0)
            .checked_add(usize::from(trace_slots != 0))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace workspace allocation attempts",
            })?;
        let setup_work = u64::try_from(choice_slots)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(allocation_attempts).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace workspace setup work",
            })?;
        Ok(TraceWorkspaceAccounting {
            accounting_id: TRACE_WORKSPACE_ACCOUNTING_ID,
            source_bytes,
            pattern_count: self.core.build.patterns,
            has_empty_pattern: self.core.build.has_empty_pattern,
            min_nonempty_pattern_bytes: self.core.build.min_nonempty_pattern_bytes,
            plan_persistent_bytes: self.core.build.persistent_bytes,
            choice_slots,
            choice_capacity,
            trace_slots,
            trace_capacity,
            retained_logical_bytes,
            peak_bytes,
            setup_work,
            allocation_attempts,
        })
    }

    fn validate_trace_workspace(
        &self,
        source_bytes: usize,
        workspace: &SparseOrderedLiteralTraceWorkspace,
    ) -> Result<TraceWorkspaceAccounting, ReduceError> {
        if workspace.plan_identity != self.identity {
            return Err(ReduceError::TraceWorkspaceMismatch {
                detail: "trace workspace belongs to another immutable count plan",
            });
        }
        if workspace.accounting.source_bytes != source_bytes {
            return Err(ReduceError::TraceWorkspaceMismatch {
                detail: "trace workspace was prepared for another source length",
            });
        }
        let expected = self.trace_workspace_accounting(
            source_bytes,
            workspace.choices.capacity(),
            workspace.trace.capacity(),
        )?;
        if workspace.accounting != expected
            || workspace.choices.len() != expected.choice_slots
            || workspace.trace.len() > expected.trace_slots
            || !expected.closes()
        {
            return Err(ReduceError::TraceWorkspaceMismatch {
                detail: "trace workspace private layout differs from its authenticated plan",
            });
        }
        Ok(expected)
    }

    fn trace_reduce_upper_bounds(
        &self,
        source_bytes: usize,
        workspace: TraceWorkspaceAccounting,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let mut upper =
            self.core
                .preflight_reduce::<()>(source_bytes, false, ReduceLimits::unlimited())?;
        upper.reducer_steps = workspace
            .choice_slots
            .checked_mul(2)
            .and_then(|steps| steps.checked_add(workspace.trace_slots))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace reducer-step upper bound",
            })?;
        upper.ring_entries = 0;
        upper.ring_initializations = 0;
        upper.total_work = u64::try_from(upper.transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(upper.edge_lookups).ok()?))
            .and_then(|work| work.checked_add(upper.edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(upper.failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(upper.reducer_steps).ok()?))
            .and_then(|work| work.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse trace total-work upper bound",
            })?;
        upper.scratch_bytes = workspace.retained_logical_bytes;
        upper.peak_bytes = workspace.peak_bytes;
        let maximum_ordinal = u64::try_from(self.core.build.patterns)
            .ok()
            .and_then(|patterns| patterns.checked_sub(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace maximum source ordinal",
            })?;
        maximum_ordinal
            .checked_mul(upper.count)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "trace ordinal-sum upper bound",
            })?;
        // Unlike the count-only entry point, this report publishes selected
        // spans, so its prospective span sum is part of the caller envelope.
        check_reduce_limits(upper, true, limits)?;
        Ok(upper)
    }
}

impl SparseOrderedLiteralSpanSumPlan {
    /// Consume a concrete borrowed-pattern vector into a checked owned encoding.
    pub fn build(patterns: Vec<&[u8]>, limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_attempt(patterns, limits)
            .map(SpanSumBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    /// Build while retaining exact success or partial-failure construction
    /// effects.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so reporting a failed allocation never needs another allocation"
    )]
    pub fn build_attempt(
        patterns: Vec<&[u8]>,
        limits: BuildLimits,
    ) -> Result<SpanSumBuildAttempt, BuildAttemptError> {
        let identity = BuildAttemptIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id: SPAN_SUM_PLAN_ID,
            operation: Operation::SpanSum,
            limits,
            algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
            accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
        };
        PlanCore::build_attempt(
            patterns,
            limits,
            size_of::<Self>(),
            identity,
            ConstructionTraversal::Reverse,
        )
        .map(|(core, receipt)| SpanSumBuildAttempt {
            plan: Self {
                core,
                operation: Operation::SpanSum,
            },
            receipt,
        })
    }

    /// Build a non-empty complete-span visitor over the same checked sparse
    /// construction envelope.
    pub fn build_spans(
        patterns: Vec<&[u8]>,
        limits: BuildLimits,
    ) -> Result<SparseOrderedLiteralSpansPlan, BuildError> {
        Self::build_spans_attempt(patterns, limits)
            .map(SpansBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    /// Receipt-bearing complete-span construction.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so reporting a failed allocation never needs another allocation"
    )]
    pub fn build_spans_attempt(
        patterns: Vec<&[u8]>,
        limits: BuildLimits,
    ) -> Result<SpansBuildAttempt, BuildAttemptError> {
        let identity = BuildAttemptIdentity {
            algorithm_id: SPANS_ALGORITHM_ID,
            plan_id: SPANS_PLAN_ID,
            operation: Operation::Spans,
            limits,
            algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
            accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
        };
        PlanCore::build_attempt(
            patterns,
            limits,
            size_of::<Self>(),
            identity,
            ConstructionTraversal::Forward,
        )
        .map(|(core, receipt)| SpansBuildAttempt {
            plan: Self {
                core,
                operation: Operation::Spans,
            },
            receipt,
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(self.operation)
    }

    pub fn span_sum<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult<'a>, ReduceError> {
        if self.operation != Operation::SpanSum {
            return Err(ReduceError::InternalInvariant {
                detail: "span-sum execution requires a span-sum sparse plan",
            });
        }
        let mut upper = self
            .core
            .preflight_reduce::<SpanState>(haystack.len(), true, limits)?;
        let mut ring = reserve_ring::<SpanState>(upper.ring_entries, "span-sum DP ring")?;
        self.core.finish_scratch_preflight(
            &mut upper,
            ring.capacity(),
            size_of::<SpanState>(),
            limits,
        )?;
        ring.resize(upper.ring_entries, SpanState::default());
        let actual = self.core.execute_span(haystack, &mut ring, upper)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum.expect("span plan publishes span sum"),
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Visit every source-priority, non-overlapping match in forward source
    /// order without allocating a span collection.
    pub fn visit_spans<'a, F>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
        visitor: F,
    ) -> Result<SpanVisitResult<'a>, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        if self.operation != Operation::Spans {
            return Err(ReduceError::InternalInvariant {
                detail: "complete-span execution requires a spans sparse plan",
            });
        }
        let upper = self.core.preflight_visit(haystack.len(), limits)?;
        let (matches, span_sum, actual) = self.core.execute_visit(haystack, upper, visitor)?;
        Ok(SpanVisitResult {
            matches,
            span_sum,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CountState {
    initial: u64,
    progressed: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SpanState {
    initial_count: u64,
    progressed_count: u64,
    span_sum: u64,
}

#[derive(Clone, Copy, Debug)]
struct SpanCandidate {
    pattern: u32,
    start: usize,
    end: usize,
}

impl SpanCandidate {
    fn preferred_to(self, other: Self) -> bool {
        self.start < other.start || (self.start == other.start && self.pattern < other.pattern)
    }
}

#[derive(Clone, Copy, Debug)]
struct RawNode {
    first_edge: u32,
    terminal_pattern_or_queue_next: u32,
    terminal_length: u32,
}

impl RawNode {
    const EMPTY: Self = Self {
        first_edge: UNSET,
        terminal_pattern_or_queue_next: UNSET,
        terminal_length: 0,
    };
}

#[derive(Clone, Copy, Debug)]
struct RawEdge {
    packed: u32,
    next_sibling: u32,
}

#[derive(Clone, Copy, Debug)]
struct BuildPreflight {
    patterns: usize,
    pattern_bytes: usize,
    identity_bytes: usize,
    trie_states_upper_bound: usize,
    sparse_edges_upper_bound: usize,
    max_pattern_bytes: usize,
    min_nonempty_pattern_bytes: Option<usize>,
    has_empty_pattern: bool,
}

#[derive(Debug)]
struct BuildWork {
    used: u64,
    limit: u64,
}

impl BuildWork {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let units = u64::try_from(units).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "construction charge as u64",
        })?;
        let needed = self
            .used
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "construction work",
            })?;
        if needed > self.limit {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.used = needed;
        Ok(())
    }
}

impl PlanCore {
    fn identity(&self, operation: Operation) -> CacheIdentity<'_> {
        CacheIdentity {
            algorithm_id: algorithm_id(operation),
            plan_id: match operation {
                Operation::Count => COUNT_PLAN_ID,
                Operation::SpanSum => SPAN_SUM_PLAN_ID,
                Operation::Spans => SPANS_PLAN_ID,
            },
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            transition_kind: "direct 256-entry root table plus sorted sparse-CSR byte edges and u32 failure links",
            traversal_kind: match operation {
                Operation::Count | Operation::SpanSum => {
                    "single reverse sparse-AC pass plus bounded initial/progressed DP ring"
                }
                Operation::Spans => {
                    "forward sparse-AC searches with bounded source-priority lookahead"
                }
            },
            semantics: Semantics::RUST_BYTES_UNICODE_OFF,
            encoded_patterns: &self.encoded_patterns,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps all exact work and capacity checks adjacent"
    )]
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so reporting a failed allocation never needs another allocation"
    )]
    fn build_attempt(
        patterns: Vec<&[u8]>,
        limits: BuildLimits,
        inline_bytes: usize,
        identity: BuildAttemptIdentity,
        traversal: ConstructionTraversal,
    ) -> Result<(Self, BuildAttemptReceipt), BuildAttemptError> {
        let mut work = BuildWork::new(limits.max_build_work);
        let mut tracker = BuildAttemptTracker::new();
        let result = (|| -> Result<Self, BuildError> {
            let (preflight, encoded_patterns, source_scratch_bytes, encoding_peak_bytes) =
                encode_owned_patterns(patterns, limits, inline_bytes, &mut work, &mut tracker)?;
            if traversal == ConstructionTraversal::Forward && preflight.has_empty_pattern {
                return Err(BuildError::EmptyPatternSpanVisitUnsupported);
            }

            let logical_scratch = preflight
                .trie_states_upper_bound
                .checked_mul(size_of::<RawNode>())
                .and_then(|bytes| {
                    bytes.checked_add(
                        preflight
                            .sparse_edges_upper_bound
                            .checked_mul(size_of::<RawEdge>())?,
                    )
                })
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "logical build scratch",
                })?;
            check_scratch(logical_scratch, limits)?;
            let persistent_floor = inline_bytes.checked_add(preflight.identity_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent floor",
                },
            )?;
            check_persistent_peak(persistent_floor, logical_scratch, limits)?;

            let mut raw_nodes = reserve_build_vec::<RawNode>(
                preflight.trie_states_upper_bound,
                "temporary trie nodes",
                BuildAllocationClass::Scratch,
                &mut tracker,
            )?;
            let mut raw_edges = reserve_build_vec::<RawEdge>(
                preflight.sparse_edges_upper_bound,
                "temporary trie edges",
                BuildAllocationClass::Scratch,
                &mut tracker,
            )?;
            work.charge(1)?;
            checked_push(&mut raw_nodes, RawNode::EMPTY, "root node reservation")?;
            tracker.observe_initialization(size_of::<RawNode>())?;

            let trie_scratch_bytes = capacity_bytes(&raw_nodes)?
                .checked_add(capacity_bytes(&raw_edges)?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "observed build scratch",
                })?;
            check_scratch(trie_scratch_bytes, limits)?;
            let persistent_floor = inline_bytes
                .checked_add(encoded_patterns.capacity())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "observed persistent floor",
                })?;
            check_persistent_peak(persistent_floor, trie_scratch_bytes, limits)?;

            insert_owned_patterns(
                preflight,
                &encoded_patterns,
                &mut raw_nodes,
                &mut raw_edges,
                &mut work,
                &mut tracker,
                traversal,
            )?;
            let state_count = raw_nodes.len();
            let edge_count = raw_edges.len();

            let offset_count =
                state_count
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "CSR offset count",
                    })?;
            let requested_persistent = inline_bytes
                .checked_add(encoded_patterns.capacity())
                .and_then(|bytes| bytes.checked_add(offset_count.checked_mul(size_of::<u32>())?))
                .and_then(|bytes| bytes.checked_add(edge_count.checked_mul(size_of::<u32>())?))
                .and_then(|bytes| bytes.checked_add(state_count.checked_mul(size_of::<u32>())?))
                .and_then(|bytes| bytes.checked_add(state_count.checked_mul(size_of::<Output>())?))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "requested sparse persistent bytes",
                })?;
            check_persistent_peak(requested_persistent, trie_scratch_bytes, limits)?;

            work.charge(ROOT_TRANSITIONS)?;
            let mut root_transitions = [0_u32; ROOT_TRANSITIONS];
            tracker.observe_initialization(
                ROOT_TRANSITIONS.checked_mul(size_of::<u32>()).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "root transition initialized bytes",
                    },
                )?,
            )?;
            let mut offsets = reserve_build_vec::<u32>(
                offset_count,
                "CSR offsets",
                BuildAllocationClass::Persistent,
                &mut tracker,
            )?;
            let mut edges = reserve_build_vec::<u32>(
                edge_count,
                "CSR edges",
                BuildAllocationClass::Persistent,
                &mut tracker,
            )?;
            let mut failure = reserve_build_vec::<u32>(
                state_count,
                "failure links",
                BuildAllocationClass::Persistent,
                &mut tracker,
            )?;
            let mut output = reserve_build_vec::<Output>(
                state_count,
                "outputs",
                BuildAllocationClass::Persistent,
                &mut tracker,
            )?;

            let persistent_bytes = inline_bytes
                .checked_add(encoded_patterns.capacity())
                .and_then(|bytes| bytes.checked_add(capacity_bytes(&offsets).ok()?))
                .and_then(|bytes| bytes.checked_add(capacity_bytes(&edges).ok()?))
                .and_then(|bytes| bytes.checked_add(capacity_bytes(&failure).ok()?))
                .and_then(|bytes| bytes.checked_add(capacity_bytes(&output).ok()?))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "observed sparse persistent bytes",
                })?;
            let trie_peak_bytes =
                check_persistent_peak(persistent_bytes, trie_scratch_bytes, limits)?;
            let scratch_bytes = trie_scratch_bytes.max(source_scratch_bytes);
            let peak_bytes = trie_peak_bytes.max(encoding_peak_bytes);

            for node in &raw_nodes {
                work.charge(1)?;
                checked_push(
                    &mut output,
                    Output {
                        pattern: node.terminal_pattern_or_queue_next,
                        length: node.terminal_length,
                    },
                    "output reservation",
                )?;
                checked_push(&mut failure, 0, "failure reservation")?;
                tracker.observe_initialization(
                    size_of::<Output>().checked_add(size_of::<u32>()).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "sparse state initialized bytes",
                        },
                    )?,
                )?;
            }
            for (state, node) in raw_nodes.iter().enumerate() {
                work.charge(1)?;
                checked_push(
                    &mut offsets,
                    u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
                        structure: "CSR edge offsets",
                        needed: edges.len(),
                    })?,
                    "CSR offset reservation",
                )?;
                tracker.observe_initialization(size_of::<u32>())?;
                let mut edge = node.first_edge;
                while edge != UNSET {
                    work.charge(1)?;
                    let raw = raw_edges[usize::try_from(edge).expect("u32 edge fits usize")];
                    checked_push(&mut edges, raw.packed, "CSR edge reservation")?;
                    tracker.observe_initialization(size_of::<u32>())?;
                    if state == 0 {
                        let byte = usize::from(edge_byte(raw.packed));
                        let target = edge_target(raw.packed);
                        if target == 0 || root_transitions[byte] != 0 {
                            return Err(BuildError::InternalInvariant {
                                detail: "root table has one non-root target per byte",
                            });
                        }
                        root_transitions[byte] = target;
                    }
                    edge = raw.next_sibling;
                }
            }
            checked_push(
                &mut offsets,
                u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
                    structure: "CSR edge offsets",
                    needed: edges.len(),
                })?,
                "terminal CSR offset reservation",
            )?;
            tracker.observe_initialization(size_of::<u32>())?;
            if edges.len() != edge_count {
                return Err(BuildError::InternalInvariant {
                    detail: "CSR contains every temporary edge exactly once",
                });
            }

            let mut automaton = SparseAc {
                root_transitions,
                offsets,
                edges,
                failure,
                output,
            };
            build_failure_links(&mut automaton, &mut raw_nodes, &mut work, traversal)?;

            let max_edge_search_checks = max_search_checks(&automaton, &mut work)?;
            let build = BuildAccounting {
                patterns: preflight.patterns,
                pattern_bytes: preflight.pattern_bytes,
                identity_bytes: preflight.identity_bytes,
                identity_capacity_bytes: encoded_patterns.capacity(),
                trie_states_upper_bound: preflight.trie_states_upper_bound,
                trie_states_actual: state_count,
                sparse_edges_upper_bound: preflight.sparse_edges_upper_bound,
                sparse_edges_actual: edge_count,
                build_work: work.used,
                max_pattern_bytes: preflight.max_pattern_bytes,
                min_nonempty_pattern_bytes: preflight.min_nonempty_pattern_bytes,
                has_empty_pattern: preflight.has_empty_pattern,
                max_edge_search_checks,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            };
            let raw_nodes_capacity = raw_nodes.capacity();
            let raw_edges_capacity = raw_edges.capacity();
            drop(raw_nodes);
            drop(raw_edges);
            tracker.release::<RawNode>(raw_nodes_capacity, BuildAllocationClass::Scratch)?;
            tracker.release::<RawEdge>(raw_edges_capacity, BuildAllocationClass::Scratch)?;
            tracker.publish_inline(inline_bytes)?;
            Ok(Self {
                automaton,
                encoded_patterns,
                build,
            })
        })();
        tracker.sync_work(&work);
        match result {
            Ok(core) => {
                let receipt = BuildAttemptReceipt {
                    identity,
                    actual: tracker.actual,
                    accounting: Some(core.build),
                    published: true,
                };
                if !receipt.closes_success(identity.operation, core.build) {
                    return Err(BuildAttemptError::new(
                        BuildError::InternalInvariant {
                            detail: "sparse build success did not close its receipt",
                        },
                        identity,
                        tracker.actual,
                    ));
                }
                Ok((core, receipt))
            }
            Err(source) => Err(BuildAttemptError::new(source, identity, tracker.actual)),
        }
    }

    fn preflight_reduce<T>(
        &self,
        haystack_len: usize,
        check_span: bool,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let transitions = haystack_len;
        let failure_steps = haystack_len;
        let edge_lookups = haystack_len
            .checked_mul(2)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse edge lookups",
            })?;
        let edge_search_checks = u64::try_from(edge_lookups)
            .ok()
            .and_then(|lookups| {
                lookups.checked_mul(u64::try_from(self.build.max_edge_search_checks).ok()?)
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse edge search checks",
            })?;
        let reducer_steps = haystack_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reverse reducer positions",
            })?;
        let match_events = if self.build.has_empty_pattern {
            reducer_steps
        } else {
            haystack_len
                .checked_div(self.build.min_nonempty_pattern_bytes.ok_or(
                    ReduceError::InternalInvariant {
                        detail: "nonempty language retains a minimum length",
                    },
                )?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "nonempty event quotient",
                })?
        };
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match events as u64",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span upper bound as u64",
            })?;
        let ring_entries = self
            .build
            .max_pattern_bytes
            .min(haystack_len)
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "DP ring entries",
            })?;
        let ring_initializations = ring_entries;
        let total_work = u64::try_from(transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(edge_lookups).ok()?))
            .and_then(|work| work.checked_add(edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(reducer_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(ring_initializations).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse reducer total work",
            })?;
        let scratch_bytes =
            ring_entries
                .checked_mul(size_of::<T>())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "logical DP scratch",
                })?;
        let peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(scratch_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "logical reducer peak",
            })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            transitions,
            edge_lookups,
            edge_search_checks,
            failure_steps,
            match_events,
            count,
            span_sum,
            reducer_steps,
            ring_entries,
            ring_initializations,
            total_work,
            scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        };
        check_reduce_limits(upper, check_span, limits)?;
        Ok(upper)
    }

    fn preflight_visit(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let minimum =
            self.build
                .min_nonempty_pattern_bytes
                .ok_or(ReduceError::InternalInvariant {
                    detail: "complete-span sparse plan retains a non-empty minimum width",
                })?;
        if self.build.has_empty_pattern || minimum == 0 {
            return Err(ReduceError::InternalInvariant {
                detail: "complete-span sparse plan excludes empty patterns",
            });
        }
        let match_events =
            haystack_len
                .checked_div(minimum)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "complete-span event quotient",
                })?;
        let effective_maximum = self.build.max_pattern_bytes.min(haystack_len);
        let overlap_per_match = effective_maximum.saturating_sub(minimum);
        let transitions = match_events
            .checked_mul(overlap_per_match)
            .and_then(|overlap| haystack_len.checked_add(overlap))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete-span forward transition bound",
            })?;
        let edge_lookups = transitions
            .checked_mul(2)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete-span sparse edge lookups",
            })?;
        let edge_search_checks = u64::try_from(edge_lookups)
            .ok()
            .and_then(|lookups| {
                lookups.checked_mul(u64::try_from(self.build.max_edge_search_checks).ok()?)
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete-span sparse edge search checks",
            })?;
        let failure_steps = transitions;
        let reducer_steps = transitions
            .checked_add(match_events)
            .and_then(|steps| steps.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete-span reducer steps",
            })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "complete-span count bound as u64",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "complete-span sum bound as u64",
            })?;
        let total_work = u64::try_from(transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(edge_lookups).ok()?))
            .and_then(|work| work.checked_add(edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(reducer_steps).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete-span sparse total work",
            })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            transitions,
            edge_lookups,
            edge_search_checks,
            failure_steps,
            match_events,
            count,
            span_sum,
            reducer_steps,
            ring_entries: 0,
            ring_initializations: 0,
            total_work,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        check_reduce_limits(upper, true, limits)?;
        Ok(upper)
    }

    fn execute_visit<F>(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        mut visitor: F,
    ) -> Result<(usize, usize, ReduceActualCounters), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let maximum = self.build.max_pattern_bytes;
        if maximum == 0 || self.build.has_empty_pattern {
            return Err(ReduceError::InternalInvariant {
                detail: "complete-span sparse plan retains only non-empty patterns",
            });
        }
        let mut search = SearchCounters::default();
        let mut transitions = 0_usize;
        let mut reducer_steps = 1_usize;
        let mut matches = 0_usize;
        let mut span_sum = 0_usize;
        let mut search_start = 0_usize;

        while search_start < haystack.len() {
            let mut state = 0_u32;
            let mut candidate = None::<SpanCandidate>;
            let mut position = search_start;
            while position < haystack.len() {
                state = self.automaton.next(state, haystack[position], &mut search);
                transitions =
                    transitions
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual complete-span transitions",
                        })?;
                reducer_steps =
                    reducer_steps
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual complete-span reducer steps",
                        })?;
                let end = position
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual complete-span end",
                    })?;
                if let Some((pattern, length)) = self.automaton.output(state) {
                    if length == 0 || length > end {
                        return Err(ReduceError::InternalInvariant {
                            detail: "forward sparse output is a non-empty in-bounds suffix",
                        });
                    }
                    let found = SpanCandidate {
                        pattern,
                        start: end - length,
                        end,
                    };
                    if found.start < search_start {
                        return Err(ReduceError::InternalInvariant {
                            detail: "reset forward sparse search cannot cross its start",
                        });
                    }
                    if candidate.is_none_or(|old| found.preferred_to(old)) {
                        candidate = Some(found);
                    }
                }
                position = end;
                if candidate.is_some_and(|best| {
                    let settled = best.start.saturating_add(maximum).min(haystack.len());
                    position >= settled
                }) {
                    break;
                }
            }

            let Some(selected) = candidate else {
                break;
            };
            if selected.end <= search_start || selected.end > haystack.len() {
                return Err(ReduceError::InternalInvariant {
                    detail: "complete-span selection makes bounded non-empty progress",
                });
            }
            matches = matches
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual complete-span count",
                })?;
            reducer_steps =
                reducer_steps
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual complete-span emission steps",
                    })?;
            span_sum = span_sum.checked_add(selected.end - selected.start).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "actual complete-span sum",
                },
            )?;
            visitor(CompleteSpan {
                start: selected.start,
                end: selected.end,
            });
            search_start = selected.end;
        }

        let match_events = u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual complete-span count as u64",
        })?;
        let span_sum_u64 =
            u64::try_from(span_sum).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual complete-span sum as u64",
            })?;
        let total_work = u64::try_from(transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(search.edge_lookups).ok()?))
            .and_then(|work| work.checked_add(search.edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(search.failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(reducer_steps).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual complete-span sparse work",
            })?;
        if transitions > upper.transitions
            || search.edge_lookups > upper.edge_lookups
            || search.edge_search_checks > upper.edge_search_checks
            || search.failure_steps > upper.failure_steps
            || matches > upper.match_events
            || span_sum_u64 > upper.span_sum
            || reducer_steps > upper.reducer_steps
            || total_work > upper.total_work
        {
            return Err(ReduceError::InternalInvariant {
                detail: "complete-span sparse counters fit their admitted bounds",
            });
        }
        Ok((
            matches,
            span_sum,
            ReduceActualCounters {
                transitions,
                edge_lookups: search.edge_lookups,
                edge_search_checks: search.edge_search_checks,
                failure_steps: search.failure_steps,
                reducer_steps,
                ring_initializations: 0,
                total_work,
                match_events,
                count: Some(match_events),
                span_sum: Some(span_sum_u64),
                scratch_bytes: 0,
                peak_bytes: self.build.persistent_bytes,
            },
        ))
    }

    fn finish_scratch_preflight(
        &self,
        upper: &mut ReduceUpperBounds,
        capacity: usize,
        element_size: usize,
        limits: ReduceLimits,
    ) -> Result<(), ReduceError> {
        upper.scratch_bytes =
            capacity
                .checked_mul(element_size)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "observed DP scratch",
                })?;
        upper.peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(upper.scratch_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "observed reducer peak",
            })?;
        check_reduce_limits(*upper, false, limits)
    }

    fn execute_count(
        &self,
        haystack: &[u8],
        ring: &mut [CountState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut search = SearchCounters::default();
        let mut next_initial = 0_u64;
        let mut current_slot =
            haystack
                .len()
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "initial count DP ring slot",
                })?;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.automaton.next(state, haystack[position], &mut search);
            }
            let value = match self.automaton.output(state) {
                None => CountState {
                    initial: next_initial,
                    progressed: next_initial,
                },
                Some((_, 0)) => CountState {
                    initial: next_initial.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual empty count",
                        },
                    )?,
                    progressed: next_initial,
                },
                Some((_, length)) => {
                    let target = checked_dp_target_slot(
                        position,
                        current_slot,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let count = ring[target].progressed.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual nonempty count",
                        },
                    )?;
                    CountState {
                        initial: count,
                        progressed: count,
                    }
                }
            };
            ring[current_slot] = value;
            next_initial = value.initial;
            if position != 0 {
                current_slot = previous_dp_ring_slot(current_slot, ring.len())?;
            }
        }
        Self::finish_actual(&search, next_initial, Some(next_initial), None, upper)
    }

    fn execute_span(
        &self,
        haystack: &[u8],
        ring: &mut [SpanState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut search = SearchCounters::default();
        let mut next_initial = SpanState::default();
        let mut current_slot =
            haystack
                .len()
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "initial span-sum DP ring slot",
                })?;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.automaton.next(state, haystack[position], &mut search);
            }
            let value = match self.automaton.output(state) {
                None => SpanState {
                    initial_count: next_initial.initial_count,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, 0)) => SpanState {
                    initial_count: next_initial.initial_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual empty span count",
                        },
                    )?,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, length)) => {
                    let target = checked_dp_target_slot(
                        position,
                        current_slot,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let future = ring[target];
                    let count = future.progressed_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual nonempty span count",
                        },
                    )?;
                    let length =
                        u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
                            computation: "actual span length as u64",
                        })?;
                    SpanState {
                        initial_count: count,
                        progressed_count: count,
                        span_sum: future.span_sum.checked_add(length).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "actual span sum",
                            },
                        )?,
                    }
                }
            };
            ring[current_slot] = value;
            next_initial = value;
            if position != 0 {
                current_slot = previous_dp_ring_slot(current_slot, ring.len())?;
            }
        }
        Self::finish_actual(
            &search,
            next_initial.initial_count,
            Some(next_initial.initial_count),
            Some(next_initial.span_sum),
            upper,
        )
    }

    fn finish_actual(
        search: &SearchCounters,
        match_events: u64,
        count: Option<u64>,
        span_sum: Option<u64>,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let total_work = u64::try_from(upper.transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(search.edge_lookups).ok()?))
            .and_then(|work| work.checked_add(search.edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(search.failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(upper.reducer_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(upper.ring_initializations).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual sparse reducer work",
            })?;
        if search.edge_lookups > upper.edge_lookups
            || search.edge_search_checks > upper.edge_search_checks
            || search.failure_steps > upper.failure_steps
            || total_work > upper.total_work
        {
            return Err(ReduceError::InternalInvariant {
                detail: "amortized sparse-AC counters fit their admitted bounds",
            });
        }
        Ok(ReduceActualCounters {
            transitions: upper.transitions,
            edge_lookups: search.edge_lookups,
            edge_search_checks: search.edge_search_checks,
            failure_steps: search.failure_steps,
            reducer_steps: upper.reducer_steps,
            ring_initializations: upper.ring_initializations,
            total_work,
            match_events,
            count,
            span_sum,
            scratch_bytes: upper.scratch_bytes,
            peak_bytes: upper.peak_bytes,
        })
    }
}

#[derive(Default)]
struct OwnedPatternStats {
    count: usize,
    pattern_bytes: usize,
    max_pattern_bytes: usize,
    min_nonempty_pattern_bytes: Option<usize>,
    has_empty_pattern: bool,
}

impl OwnedPatternStats {
    fn observe(&mut self, pattern_bytes: usize, limits: BuildLimits) -> Result<(), BuildError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "pattern count",
            })?;
        if self.count > limits.max_patterns {
            return Err(BuildError::PatternLimit {
                needed: self.count,
                limit: limits.max_patterns,
            });
        }
        if self.count > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
            return Err(BuildError::RepresentationLimit {
                structure: "pattern identifiers",
                needed: self.count,
            });
        }
        if pattern_bytes > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
            return Err(BuildError::RepresentationLimit {
                structure: "pattern lengths",
                needed: pattern_bytes,
            });
        }
        self.pattern_bytes = self.pattern_bytes.checked_add(pattern_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "pattern bytes",
            },
        )?;
        if self.pattern_bytes > limits.max_pattern_bytes {
            return Err(BuildError::PatternBytesLimit {
                needed: self.pattern_bytes,
                limit: limits.max_pattern_bytes,
            });
        }
        let trie_states =
            self.pattern_bytes
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "trie state upper bound",
                })?;
        if trie_states > limits.max_trie_states {
            return Err(BuildError::TrieStatesLimit {
                needed: trie_states,
                limit: limits.max_trie_states,
            });
        }
        if trie_states > MAX_REPRESENTABLE_STATES {
            return Err(BuildError::RepresentationLimit {
                structure: "packed sparse trie states",
                needed: trie_states,
            });
        }
        if self.pattern_bytes > limits.max_sparse_edges {
            return Err(BuildError::SparseEdgesLimit {
                needed: self.pattern_bytes,
                limit: limits.max_sparse_edges,
            });
        }
        self.max_pattern_bytes = self.max_pattern_bytes.max(pattern_bytes);
        if pattern_bytes == 0 {
            self.has_empty_pattern = true;
        } else {
            self.min_nonempty_pattern_bytes = Some(
                self.min_nonempty_pattern_bytes
                    .map_or(pattern_bytes, |old| old.min(pattern_bytes)),
            );
        }
        Ok(())
    }

    fn finish(self, identity_bytes: usize) -> Result<BuildPreflight, BuildError> {
        if self.count == 0 {
            return Err(BuildError::EmptyPatternSet);
        }
        check_pattern_representation(self.count, self.max_pattern_bytes)?;
        let trie_states_upper_bound =
            self.pattern_bytes
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "trie state upper bound",
                })?;
        Ok(BuildPreflight {
            patterns: self.count,
            pattern_bytes: self.pattern_bytes,
            identity_bytes,
            trie_states_upper_bound,
            sparse_edges_upper_bound: self.pattern_bytes,
            max_pattern_bytes: self.max_pattern_bytes,
            min_nonempty_pattern_bytes: self.min_nonempty_pattern_bytes,
            has_empty_pattern: self.has_empty_pattern,
        })
    }
}

fn begin_owned_pattern_encoding(
    limits: BuildLimits,
    inline_bytes: usize,
    source_scratch_bytes: usize,
    work: &mut BuildWork,
    tracker: &mut BuildAttemptTracker,
) -> Result<Vec<u8>, BuildError> {
    if LENGTH_PREFIX_BYTES > limits.max_identity_bytes {
        return Err(BuildError::IdentityBytesLimit {
            needed: LENGTH_PREFIX_BYTES,
            limit: limits.max_identity_bytes,
        });
    }
    let initial_persistent =
        inline_bytes
            .checked_add(LENGTH_PREFIX_BYTES)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "initial identity allocation",
            })?;
    check_persistent_peak(initial_persistent, source_scratch_bytes, limits)?;
    tracker.add_external_scratch(source_scratch_bytes)?;
    work.charge(LENGTH_PREFIX_BYTES)?;
    let mut encoded = reserve_build_vec::<u8>(
        LENGTH_PREFIX_BYTES,
        "cache identity",
        BuildAllocationClass::Persistent,
        tracker,
    )?;
    let observed_initial =
        inline_bytes
            .checked_add(encoded.capacity())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed initial identity allocation",
            })?;
    check_persistent_peak(observed_initial, source_scratch_bytes, limits)?;
    checked_extend(
        &mut encoded,
        &[0_u8; LENGTH_PREFIX_BYTES],
        "identity count prefix reservation",
    )?;
    tracker.observe_copy(LENGTH_PREFIX_BYTES)?;
    Ok(encoded)
}

fn reserve_owned_pattern_identity(
    encoded: &mut Vec<u8>,
    pattern_bytes: usize,
    limits: BuildLimits,
    inline_bytes: usize,
    source_scratch_bytes: usize,
    tracker: &mut BuildAttemptTracker,
) -> Result<(), BuildError> {
    let identity_bytes = encoded
        .len()
        .checked_add(LENGTH_PREFIX_BYTES)
        .and_then(|length| length.checked_add(pattern_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "identity bytes",
        })?;
    if identity_bytes > limits.max_identity_bytes {
        return Err(BuildError::IdentityBytesLimit {
            needed: identity_bytes,
            limit: limits.max_identity_bytes,
        });
    }
    let requested_persistent =
        inline_bytes
            .checked_add(identity_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "requested identity allocation",
            })?;
    check_persistent_peak(requested_persistent, source_scratch_bytes, limits)?;
    let additional =
        LENGTH_PREFIX_BYTES
            .checked_add(pattern_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "identity reservation increment",
            })?;
    let before_capacity = encoded.capacity();
    build_allocation_probe::before("cache identity", additional)?;
    encoded
        .try_reserve_exact(additional)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "cache identity",
            additional,
        })?;
    tracker.observe_reserve::<u8>(
        before_capacity,
        encoded.capacity(),
        BuildAllocationClass::Persistent,
    )?;
    let observed_persistent =
        inline_bytes
            .checked_add(encoded.capacity())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed identity allocation",
            })?;
    check_persistent_peak(observed_persistent, source_scratch_bytes, limits)?;
    Ok(())
}

fn finish_owned_pattern_encoding(
    stats: OwnedPatternStats,
    mut encoded: Vec<u8>,
    work: &mut BuildWork,
    tracker: &mut BuildAttemptTracker,
) -> Result<(BuildPreflight, Vec<u8>), BuildError> {
    let preflight = stats.finish(encoded.len())?;
    let count_prefix = u64::try_from(preflight.patterns)
        .map_err(|_| BuildError::ArithmeticOverflow {
            computation: "identity pattern count",
        })?
        .to_le_bytes();
    work.charge(LENGTH_PREFIX_BYTES)?;
    encoded[..LENGTH_PREFIX_BYTES].copy_from_slice(&count_prefix);
    tracker.observe_copy(LENGTH_PREFIX_BYTES)?;
    Ok((preflight, encoded))
}

fn encode_owned_patterns(
    patterns: Vec<&[u8]>,
    limits: BuildLimits,
    inline_bytes: usize,
    work: &mut BuildWork,
    tracker: &mut BuildAttemptTracker,
) -> Result<(BuildPreflight, Vec<u8>, usize, usize), BuildError> {
    let source_scratch_bytes = patterns.capacity().checked_mul(size_of::<&[u8]>()).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "borrowed pattern source capacity",
        },
    )?;
    check_scratch(source_scratch_bytes, limits)?;
    let mut encoded =
        begin_owned_pattern_encoding(limits, inline_bytes, source_scratch_bytes, work, tracker)?;
    let mut stats = OwnedPatternStats::default();
    let mut index = 0_usize;
    while index < patterns.len() {
        work.charge(1)?;
        let bytes = patterns[index];
        stats.observe(bytes.len(), limits)?;
        reserve_owned_pattern_identity(
            &mut encoded,
            bytes.len(),
            limits,
            inline_bytes,
            source_scratch_bytes,
            tracker,
        )?;
        work.charge(LENGTH_PREFIX_BYTES)?;
        let length = u64::try_from(bytes.len()).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "identity pattern length",
        })?;
        checked_extend(
            &mut encoded,
            &length.to_le_bytes(),
            "identity length reservation",
        )?;
        tracker.observe_copy(LENGTH_PREFIX_BYTES)?;
        work.charge(bytes.len())?;
        checked_extend(&mut encoded, bytes, "identity byte reservation")?;
        tracker.observe_copy(bytes.len())?;
        index = index.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "borrowed pattern source index",
        })?;
    }
    let encoding_peak_bytes = inline_bytes
        .checked_add(encoded.capacity())
        .and_then(|bytes| bytes.checked_add(source_scratch_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "observed source encoding peak",
        })?;
    let (preflight, encoded) = finish_owned_pattern_encoding(stats, encoded, work, tracker)?;
    drop(patterns);
    tracker.release_external_scratch(source_scratch_bytes)?;
    Ok((
        preflight,
        encoded,
        source_scratch_bytes,
        encoding_peak_bytes,
    ))
}

fn check_pattern_representation(count: usize, max_pattern_bytes: usize) -> Result<(), BuildError> {
    if count > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern identifiers",
            needed: count,
        });
    }
    if max_pattern_bytes > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern lengths",
            needed: max_pattern_bytes,
        });
    }
    Ok(())
}

fn insert_owned_patterns(
    expected: BuildPreflight,
    encoded: &[u8],
    nodes: &mut Vec<RawNode>,
    edges: &mut Vec<RawEdge>,
    work: &mut BuildWork,
    tracker: &mut BuildAttemptTracker,
    traversal: ConstructionTraversal,
) -> Result<(), BuildError> {
    let mut count = 0_usize;
    let mut identity_offset = LENGTH_PREFIX_BYTES;
    while count < expected.patterns {
        work.charge(1)?;
        work.charge(LENGTH_PREFIX_BYTES)?;
        let length_end = identity_offset.checked_add(LENGTH_PREFIX_BYTES).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "identity validation length",
            },
        )?;
        let stored_length =
            encoded
                .get(identity_offset..length_end)
                .ok_or(BuildError::InternalInvariant {
                    detail: "owned identity contains every length prefix",
                })?;
        let stored_length = usize::try_from(u64::from_le_bytes(stored_length.try_into().map_err(
            |_| BuildError::InternalInvariant {
                detail: "owned identity length prefix has fixed width",
            },
        )?))
        .map_err(|_| BuildError::InternalInvariant {
            detail: "owned identity pattern length fits usize",
        })?;
        identity_offset = length_end;
        let bytes_end =
            identity_offset
                .checked_add(stored_length)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "identity validation bytes",
                })?;
        let bytes =
            encoded
                .get(identity_offset..bytes_end)
                .ok_or(BuildError::InternalInvariant {
                    detail: "owned identity contains every pattern byte",
                })?;
        identity_offset = bytes_end;
        let pattern_id = u32::try_from(count).map_err(|_| BuildError::RepresentationLimit {
            structure: "pattern identifiers",
            needed: count,
        })?;
        let length = u32::try_from(bytes.len()).map_err(|_| BuildError::RepresentationLimit {
            structure: "pattern lengths",
            needed: bytes.len(),
        })?;
        let mut state = 0_u32;
        match traversal {
            ConstructionTraversal::Reverse => {
                for &byte in bytes.iter().rev() {
                    work.charge(1)?;
                    state = child_or_insert(state, byte, nodes, edges, work, tracker)?;
                }
            }
            ConstructionTraversal::Forward => {
                for &byte in bytes {
                    work.charge(1)?;
                    state = child_or_insert(state, byte, nodes, edges, work, tracker)?;
                }
            }
        }
        work.charge(1)?;
        let terminal = &mut nodes[usize::try_from(state).expect("u32 state fits usize")];
        if pattern_id < terminal.terminal_pattern_or_queue_next {
            terminal.terminal_pattern_or_queue_next = pattern_id;
            terminal.terminal_length = length;
        }
        count = count.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "inserted pattern count",
        })?;
    }
    if identity_offset != encoded.len() {
        return Err(BuildError::InternalInvariant {
            detail: "owned identity has no trailing bytes",
        });
    }
    Ok(())
}

fn child_or_insert(
    state: u32,
    byte: u8,
    nodes: &mut Vec<RawNode>,
    edges: &mut Vec<RawEdge>,
    work: &mut BuildWork,
    tracker: &mut BuildAttemptTracker,
) -> Result<u32, BuildError> {
    let state_index = usize::try_from(state).expect("u32 state fits usize");
    let mut previous = UNSET;
    let mut current = nodes[state_index].first_edge;
    while current != UNSET {
        work.charge(1)?;
        let edge_index = usize::try_from(current).expect("u32 edge fits usize");
        let existing = edge_byte(edges[edge_index].packed);
        match existing.cmp(&byte) {
            Ordering::Less => {
                previous = current;
                current = edges[edge_index].next_sibling;
            }
            Ordering::Equal => return Ok(edge_target(edges[edge_index].packed)),
            Ordering::Greater => break,
        }
    }
    work.charge(2)?;
    let target = u32::try_from(nodes.len()).map_err(|_| BuildError::RepresentationLimit {
        structure: "packed sparse trie states",
        needed: nodes.len(),
    })?;
    if target > TARGET_MASK {
        let needed = nodes
            .len()
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "packed trie state refusal",
            })?;
        return Err(BuildError::RepresentationLimit {
            structure: "packed sparse trie states",
            needed,
        });
    }
    let edge_id = u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
        structure: "temporary sparse edges",
        needed: edges.len(),
    })?;
    checked_push(nodes, RawNode::EMPTY, "temporary trie node reservation")?;
    checked_push(
        edges,
        RawEdge {
            packed: pack_edge(byte, target),
            next_sibling: current,
        },
        "temporary trie edge reservation",
    )?;
    tracker.observe_initialization(
        size_of::<RawNode>()
            .checked_add(size_of::<RawEdge>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "temporary trie initialized bytes",
            })?,
    )?;
    if previous == UNSET {
        nodes[state_index].first_edge = edge_id;
    } else {
        edges[usize::try_from(previous).expect("u32 edge fits usize")].next_sibling = edge_id;
    }
    Ok(target)
}

fn build_failure_links(
    automaton: &mut SparseAc,
    raw_nodes: &mut [RawNode],
    work: &mut BuildWork,
    traversal: ConstructionTraversal,
) -> Result<(), BuildError> {
    let mut head = UNSET;
    let mut tail = UNSET;
    let root_start = usize::try_from(automaton.offsets[0]).expect("u32 offset fits usize");
    let root_end = usize::try_from(automaton.offsets[1]).expect("u32 offset fits usize");
    for edge_index in root_start..root_end {
        work.charge(1)?;
        let child = edge_target(automaton.edges[edge_index]);
        enqueue(raw_nodes, &mut head, &mut tail, child);
    }
    while head != UNSET {
        let state = charged_dequeue(raw_nodes, &mut head, &mut tail, work)?.ok_or(
            BuildError::InternalInvariant {
                detail: "nonempty failure queue yields one state",
            },
        )?;
        let state_index = usize::try_from(state).expect("u32 state fits usize");
        let inherited = automaton.output
            [usize::try_from(automaton.failure[state_index]).expect("u32 state fits usize")];
        automaton.output[state_index] = match traversal {
            ConstructionTraversal::Reverse => automaton.output[state_index].min_priority(inherited),
            ConstructionTraversal::Forward => {
                automaton.output[state_index].earliest_start_at_end(inherited)
            }
        };
        let start = usize::try_from(automaton.offsets[state_index]).expect("u32 offset fits usize");
        let next_state = state_index
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(automaton.offsets[next_state]).expect("u32 offset fits usize");
        for edge_index in start..end {
            work.charge(1)?;
            let packed = automaton.edges[edge_index];
            let byte = edge_byte(packed);
            let child = edge_target(packed);
            let mut candidate = automaton.failure[state_index];
            let failure = loop {
                if let Some(found) = automaton.edge_with_work(candidate, byte, work)? {
                    break found;
                }
                if candidate == 0 {
                    break 0;
                }
                work.charge(1)?;
                candidate =
                    automaton.failure[usize::try_from(candidate).expect("u32 state fits usize")];
            };
            automaton.failure[usize::try_from(child).expect("u32 state fits usize")] = failure;
            enqueue(raw_nodes, &mut head, &mut tail, child);
        }
    }
    if tail != UNSET {
        return Err(BuildError::InternalInvariant {
            detail: "drained failure queue has consistent empty ends",
        });
    }
    Ok(())
}

fn charged_dequeue(
    nodes: &[RawNode],
    head: &mut u32,
    tail: &mut u32,
    work: &mut BuildWork,
) -> Result<Option<u32>, BuildError> {
    work.charge(1)?;
    dequeue(nodes, head, tail)
}

fn enqueue(nodes: &mut [RawNode], head: &mut u32, tail: &mut u32, state: u32) {
    let state_index = usize::try_from(state).expect("u32 state fits usize");
    nodes[state_index].terminal_pattern_or_queue_next = UNSET;
    if *tail == UNSET {
        *head = state;
    } else {
        nodes[usize::try_from(*tail).expect("u32 state fits usize")]
            .terminal_pattern_or_queue_next = state;
    }
    *tail = state;
}

fn dequeue(nodes: &[RawNode], head: &mut u32, tail: &mut u32) -> Result<Option<u32>, BuildError> {
    if *head == UNSET {
        if *tail != UNSET {
            return Err(BuildError::InternalInvariant {
                detail: "intrusive failure queue has consistent empty ends",
            });
        }
        return Ok(None);
    }
    let state = *head;
    *head =
        nodes[usize::try_from(state).expect("u32 state fits usize")].terminal_pattern_or_queue_next;
    if *head == UNSET {
        *tail = UNSET;
    }
    Ok(Some(state))
}

fn max_search_checks(automaton: &SparseAc, work: &mut BuildWork) -> Result<usize, BuildError> {
    let mut maximum = 0_usize;
    for state in 1..automaton.state_count() {
        work.charge(1)?;
        let start = usize::try_from(automaton.offsets[state]).expect("u32 offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(automaton.offsets[next_state]).expect("u32 offset fits usize");
        let degree = end
            .checked_sub(start)
            .ok_or(BuildError::InternalInvariant {
                detail: "CSR offsets are monotonic",
            })?;
        let checks = if degree == 0 {
            0
        } else {
            usize::try_from(
                usize::BITS
                    .checked_sub(degree.leading_zeros())
                    .expect("a nonzero degree has a positive bit width"),
            )
            .expect("bit width fits usize")
        };
        maximum = maximum.max(checks);
    }
    Ok(maximum)
}

fn check_scratch(needed: usize, limits: BuildLimits) -> Result<(), BuildError> {
    if needed > limits.max_scratch_bytes {
        return Err(BuildError::ScratchLimit {
            needed,
            limit: limits.max_scratch_bytes,
        });
    }
    Ok(())
}

fn check_persistent_peak(
    persistent: usize,
    scratch: usize,
    limits: BuildLimits,
) -> Result<usize, BuildError> {
    if persistent > limits.max_persistent_bytes {
        return Err(BuildError::PersistentLimit {
            needed: persistent,
            limit: limits.max_persistent_bytes,
        });
    }
    let peak = persistent
        .checked_add(scratch)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build peak bytes",
        })?;
    if peak > limits.max_peak_bytes {
        return Err(BuildError::PeakLimit {
            needed: peak,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(peak)
}

fn check_reduce_limits(
    upper: ReduceUpperBounds,
    check_span: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    if upper.transitions > limits.max_transitions {
        return Err(ReduceError::TransitionLimit {
            needed: upper.transitions,
            limit: limits.max_transitions,
        });
    }
    if upper.edge_lookups > limits.max_edge_lookups {
        return Err(ReduceError::EdgeLookupLimit {
            needed: upper.edge_lookups,
            limit: limits.max_edge_lookups,
        });
    }
    if upper.edge_search_checks > limits.max_edge_search_checks {
        return Err(ReduceError::EdgeSearchChecksLimit {
            needed: upper.edge_search_checks,
            limit: limits.max_edge_search_checks,
        });
    }
    if upper.failure_steps > limits.max_failure_steps {
        return Err(ReduceError::FailureStepsLimit {
            needed: upper.failure_steps,
            limit: limits.max_failure_steps,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if check_span && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(ReduceError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.ring_initializations > limits.max_ring_initializations {
        return Err(ReduceError::RingInitializationLimit {
            needed: upper.ring_initializations,
            limit: limits.max_ring_initializations,
        });
    }
    if upper.total_work > limits.max_total_work {
        return Err(ReduceError::TotalWorkLimit {
            needed: upper.total_work,
            limit: limits.max_total_work,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: upper.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

fn check_trace_workspace_limits(
    accounting: TraceWorkspaceAccounting,
    limits: TraceWorkspaceLimits,
) -> Result<(), ReduceError> {
    if accounting.setup_work > limits.max_setup_work {
        return Err(ReduceError::TraceWorkspaceSetupWorkLimit {
            needed: accounting.setup_work,
            limit: limits.max_setup_work,
        });
    }
    if accounting.allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::TraceWorkspaceAllocationAttemptsLimit {
            needed: accounting.allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    if accounting.retained_logical_bytes > limits.max_retained_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: accounting.retained_logical_bytes,
            limit: limits.max_retained_bytes,
        });
    }
    if accounting.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: accounting.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

fn trace_actual_fits_upper(actual: ReduceActualCounters, upper: ReduceUpperBounds) -> bool {
    u64::try_from(upper.match_events).is_ok_and(|matches| actual.match_events <= matches)
        && actual.transitions <= upper.transitions
        && actual.edge_lookups <= upper.edge_lookups
        && actual.edge_search_checks <= upper.edge_search_checks
        && actual.failure_steps <= upper.failure_steps
        && actual.reducer_steps <= upper.reducer_steps
        && actual.ring_initializations <= upper.ring_initializations
        && actual.total_work <= upper.total_work
        && actual.count.is_some_and(|count| count <= upper.count)
        && actual
            .span_sum
            .is_some_and(|span_sum| span_sum <= upper.span_sum)
        && actual.scratch_bytes == upper.scratch_bytes
        && actual.peak_bytes == upper.peak_bytes
}

fn trace_accounting_closes(
    workspace: TraceWorkspaceAccounting,
    trace_len: usize,
    selected_span_bytes: u64,
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> bool {
    let upper_count = u64::try_from(workspace.trace_slots).ok();
    let actual_count = u64::try_from(trace_len).ok();
    let span_upper = u64::try_from(workspace.source_bytes).ok();
    let edge_lookups = workspace.source_bytes.checked_mul(2);
    let upper_reducer_steps = workspace
        .choice_slots
        .checked_mul(2)
        .and_then(|steps| steps.checked_add(workspace.trace_slots));
    let actual_reducer_steps = workspace
        .choice_slots
        .checked_mul(2)
        .and_then(|steps| steps.checked_add(trace_len));
    let upper_total_work = u64::try_from(upper.transitions)
        .ok()
        .and_then(|work| work.checked_add(u64::try_from(upper.edge_lookups).ok()?))
        .and_then(|work| work.checked_add(upper.edge_search_checks))
        .and_then(|work| work.checked_add(u64::try_from(upper.failure_steps).ok()?))
        .and_then(|work| work.checked_add(u64::try_from(upper.reducer_steps).ok()?))
        .and_then(|work| work.checked_add(1));
    let actual_total_work = u64::try_from(actual.transitions)
        .ok()
        .and_then(|work| work.checked_add(u64::try_from(actual.edge_lookups).ok()?))
        .and_then(|work| work.checked_add(actual.edge_search_checks))
        .and_then(|work| work.checked_add(u64::try_from(actual.failure_steps).ok()?))
        .and_then(|work| work.checked_add(u64::try_from(actual.reducer_steps).ok()?))
        .and_then(|work| work.checked_add(1));
    workspace.closes()
        && upper.haystack_bytes == workspace.source_bytes
        && upper.transitions == workspace.source_bytes
        && edge_lookups == Some(upper.edge_lookups)
        && upper.failure_steps == workspace.source_bytes
        && upper.match_events == workspace.trace_slots
        && upper_count == Some(upper.count)
        && span_upper == Some(upper.span_sum)
        && upper_reducer_steps == Some(upper.reducer_steps)
        && upper.ring_entries == 0
        && upper.ring_initializations == 0
        && upper_total_work == Some(upper.total_work)
        && upper.scratch_bytes == workspace.retained_logical_bytes
        && upper.persistent_bytes == workspace.plan_persistent_bytes
        && upper.peak_bytes == workspace.peak_bytes
        && actual.transitions == upper.transitions
        && actual_reducer_steps == Some(actual.reducer_steps)
        && actual.ring_initializations == 0
        && actual_total_work == Some(actual.total_work)
        && actual_count == Some(actual.match_events)
        && actual_count == actual.count
        && actual.span_sum == Some(selected_span_bytes)
        && trace_len <= workspace.trace_slots
        && selected_span_bytes <= upper.span_sum
        && actual.scratch_bytes == upper.scratch_bytes
        && actual.peak_bytes == upper.peak_bytes
        && trace_actual_fits_upper(actual, upper)
}

#[inline]
fn pack_edge(byte: u8, target: u32) -> u32 {
    (u32::from(byte) << 24) | target
}

#[inline]
const fn edge_byte(packed: u32) -> u8 {
    packed.to_be_bytes()[0]
}

#[inline]
const fn edge_target(packed: u32) -> u32 {
    packed & TARGET_MASK
}

#[cfg(not(test))]
mod build_allocation_probe {
    use super::BuildError;

    #[allow(
        clippy::unnecessary_wraps,
        reason = "production and test probes intentionally share one fallible call-site contract"
    )]
    pub(super) const fn before(
        _structure: &'static str,
        _additional: usize,
    ) -> Result<(), BuildError> {
        Ok(())
    }
}

#[cfg(not(test))]
mod trace_allocation_probe {
    use super::ReduceError;

    #[allow(
        clippy::unnecessary_wraps,
        reason = "production and test probes intentionally share one fallible call-site contract"
    )]
    pub(super) const fn before(
        _structure: &'static str,
        _additional: usize,
    ) -> Result<(), ReduceError> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod trace_allocation_probe {
    use std::cell::Cell;

    use super::ReduceError;

    std::thread_local! {
        static FAIL_AT: Cell<usize> = const { Cell::new(usize::MAX) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_AT.set(usize::MAX);
            CALLS.set(0);
        }
    }

    pub(crate) fn fail_at(ordinal: usize) -> Guard {
        FAIL_AT.set(ordinal);
        CALLS.set(0);
        Guard
    }

    pub(super) fn before(structure: &'static str, additional: usize) -> Result<(), ReduceError> {
        let ordinal = CALLS.get();
        CALLS.set(ordinal.saturating_add(1));
        if ordinal == FAIL_AT.get() {
            return Err(ReduceError::AllocationFailed {
                structure,
                additional,
            });
        }
        Ok(())
    }
}

#[cfg(not(test))]
mod trace_execution_probe {
    use super::ReduceError;

    #[allow(
        clippy::unnecessary_wraps,
        reason = "production and test probes intentionally share one fallible call-site contract"
    )]
    pub(super) const fn after_match() -> Result<(), ReduceError> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod trace_execution_probe {
    use std::cell::Cell;

    use super::ReduceError;

    std::thread_local! {
        static FAIL_AT: Cell<usize> = const { Cell::new(usize::MAX) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_AT.set(usize::MAX);
            CALLS.set(0);
        }
    }

    pub(crate) fn fail_at(ordinal: usize) -> Guard {
        FAIL_AT.set(ordinal);
        CALLS.set(0);
        Guard
    }

    pub(super) fn after_match() -> Result<(), ReduceError> {
        let ordinal = CALLS.get();
        CALLS.set(ordinal.saturating_add(1));
        if ordinal == FAIL_AT.get() {
            return Err(ReduceError::InternalInvariant {
                detail: "injected post-clear trace execution failure",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod build_allocation_probe {
    use std::cell::Cell;

    use super::BuildError;

    std::thread_local! {
        static FAIL_AT: Cell<usize> = const { Cell::new(usize::MAX) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_AT.set(usize::MAX);
            CALLS.set(0);
        }
    }

    pub(crate) fn fail_at(ordinal: usize) -> Guard {
        FAIL_AT.set(ordinal);
        CALLS.set(0);
        Guard
    }

    pub(super) fn before(structure: &'static str, additional: usize) -> Result<(), BuildError> {
        let ordinal = CALLS.get();
        CALLS.set(ordinal.saturating_add(1));
        if ordinal == FAIL_AT.get() {
            return Err(BuildError::AllocationFailed {
                structure,
                additional,
            });
        }
        Ok(())
    }
}

fn reserve_build_vec<T>(
    additional: usize,
    structure: &'static str,
    class: BuildAllocationClass,
    tracker: &mut BuildAttemptTracker,
) -> Result<Vec<T>, BuildError> {
    let mut values = Vec::new();
    build_allocation_probe::before(structure, additional)?;
    let before = values.capacity();
    values
        .try_reserve_exact(additional)
        .map_err(|_| BuildError::AllocationFailed {
            structure,
            additional,
        })?;
    tracker.observe_reserve::<T>(before, values.capacity(), class)?;
    Ok(values)
}

fn reserve_ring<T>(additional: usize, structure: &'static str) -> Result<Vec<T>, ReduceError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(additional)
        .map_err(|_| ReduceError::AllocationFailed {
            structure,
            additional,
        })?;
    Ok(values)
}

fn reserve_trace_vec<T>(additional: usize, structure: &'static str) -> Result<Vec<T>, ReduceError> {
    let mut values = Vec::new();
    if additional == 0 {
        return Ok(values);
    }
    trace_allocation_probe::before(structure, additional)?;
    values
        .try_reserve_exact(additional)
        .map_err(|_| ReduceError::AllocationFailed {
            structure,
            additional,
        })?;
    Ok(values)
}

fn capacity_bytes<T>(values: &Vec<T>) -> Result<usize, BuildError> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "vector capacity bytes",
        })
}

fn checked_push<T>(values: &mut Vec<T>, value: T, detail: &'static str) -> Result<(), BuildError> {
    if values.len() >= values.capacity() {
        return Err(BuildError::InternalInvariant { detail });
    }
    values.push(value);
    Ok(())
}

fn checked_extend(
    values: &mut Vec<u8>,
    bytes: &[u8],
    detail: &'static str,
) -> Result<(), BuildError> {
    let end = values
        .len()
        .checked_add(bytes.len())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "vector extension length",
        })?;
    if end > values.capacity() {
        return Err(BuildError::InternalInvariant { detail });
    }
    values.extend_from_slice(bytes);
    Ok(())
}

fn validate_ring(actual: usize, expected: usize) -> Result<(), ReduceError> {
    if actual == 0 || actual != expected {
        return Err(ReduceError::InternalInvariant {
            detail: "DP ring has its admitted nonzero length",
        });
    }
    Ok(())
}

fn checked_dp_target_slot(
    position: usize,
    current_slot: usize,
    length: usize,
    haystack_len: usize,
    max_pattern_len: usize,
    ring_len: usize,
) -> Result<usize, ReduceError> {
    if current_slot >= ring_len || length == 0 || length > max_pattern_len || length >= ring_len {
        return Err(ReduceError::InternalInvariant {
            detail: "automaton output fits the admitted DP ring",
        });
    }
    let target = position
        .checked_add(length)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "DP target position",
        })?;
    if target > haystack_len {
        return Err(ReduceError::InternalInvariant {
            detail: "automaton output ends within the haystack",
        });
    }
    let unwrapped = current_slot
        .checked_add(length)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "DP target ring slot",
        })?;
    Ok(if unwrapped >= ring_len {
        unwrapped
            .checked_sub(ring_len)
            .expect("wrapped DP slot is at least one ring length")
    } else {
        unwrapped
    })
}

fn previous_dp_ring_slot(current_slot: usize, ring_len: usize) -> Result<usize, ReduceError> {
    if current_slot >= ring_len {
        return Err(ReduceError::InternalInvariant {
            detail: "current DP slot fits the ring",
        });
    }
    Ok(if current_slot == 0 {
        ring_len
            .checked_sub(1)
            .ok_or(ReduceError::InternalInvariant {
                detail: "DP ring is nonempty",
            })?
    } else {
        current_slot
            .checked_sub(1)
            .expect("nonzero DP slot has a predecessor")
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "small fixtures and exact one-below adversaries use values whose positivity and capacity are established in each test"
    )]

    use core::mem::size_of;
    use std::fmt::Write as _;

    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        BuildError, BuildLimits, BuildWork, Output, ROOT_TRANSITIONS, RawEdge, RawNode,
        ReduceError, ReduceLimits, SparseAc, SparseOrderedLiteralCountPlan,
        SparseOrderedLiteralSpanSumPlan, SparseOrderedLiteralSpansPlan, TraceWorkspaceLimits,
        UNSET, build_allocation_probe, build_failure_links, charged_dequeue, pack_edge,
        trace_allocation_probe, trace_execution_probe,
    };

    #[test]
    fn build_attempt_receipts_close_success_and_partial_identity_failure() {
        let patterns = vec![b"ab".as_slice(), b"ac".as_slice()];
        let attempt = SparseOrderedLiteralCountPlan::build_attempt(
            patterns.clone(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(attempt.closes());
        let accounting = attempt.plan().build_accounting();
        let receipt = attempt.receipt();
        let actual = receipt.actual();
        assert_eq!(receipt.identity().accounting_version, 2);
        assert!(receipt.published());
        assert_eq!(receipt.accounting(), Some(accounting));
        assert_eq!(actual.work, accounting.build_work);
        assert!(actual.allocations > 0);
        assert!(actual.allocated_bytes >= accounting.identity_capacity_bytes);
        assert!(actual.copied_bytes > 0);
        assert!(actual.initialized_bytes >= actual.copied_bytes);
        assert_eq!(actual.live_persistent_bytes, accounting.persistent_bytes);
        assert_eq!(actual.live_scratch_bytes, 0);

        let guard = build_allocation_probe::fail_at(1);
        let failure = SparseOrderedLiteralCountPlan::build_attempt(
            patterns.clone(),
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        drop(guard);
        assert!(matches!(
            failure.source(),
            BuildError::AllocationFailed {
                structure: "cache identity",
                ..
            }
        ));
        assert!(failure.closes());
        let partial = failure.receipt().actual();
        assert!(!failure.receipt().published());
        assert_eq!(failure.receipt().accounting(), None);
        assert_eq!(partial.allocations, 1);
        assert!(partial.allocated_bytes > 0);
        assert!(partial.work > 0);
        assert!(partial.copied_bytes > 0);
        assert_eq!(partial.initialized_bytes, partial.copied_bytes);

        let guard = build_allocation_probe::fail_at(1);
        let legacy =
            SparseOrderedLiteralCountPlan::build(patterns, BuildLimits::unlimited()).unwrap_err();
        drop(guard);
        assert!(matches!(
            legacy,
            BuildError::AllocationFailed {
                structure: "cache identity",
                ..
            }
        ));

        let refusal = SparseOrderedLiteralCountPlan::build_attempt(
            vec![b"ab".as_slice(), b"ac".as_slice()],
            BuildLimits {
                max_persistent_bytes: 0,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(
            refusal.source(),
            BuildError::PersistentLimit { .. }
        ));
        assert!(refusal.closes());
    }

    fn regex(patterns: &[Vec<u8>]) -> Regex {
        let mut source = String::from("(?:");
        for (index, pattern) in patterns.iter().enumerate() {
            if index != 0 {
                source.push('|');
            }
            for &byte in pattern {
                write!(&mut source, "\\x{byte:02X}").unwrap();
            }
        }
        source.push(')');
        RegexBuilder::new(&source).unicode(false).build().unwrap()
    }

    fn sequence(plan: &SparseOrderedLiteralCountPlan, haystack: &[u8]) -> Vec<(u32, usize, usize)> {
        let mut choices = vec![None; haystack.len() + 1];
        let mut state = 0_u32;
        let mut counters = super::SearchCounters::default();
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = plan
                    .core
                    .automaton
                    .next(state, haystack[position], &mut counters);
            }
            choices[position] = plan.core.automaton.output(state);
        }
        let mut matches = Vec::new();
        let mut start = 0_usize;
        let mut last_end = None;
        while start <= haystack.len() {
            let Some(position) =
                (start..=haystack.len()).find(|&position| choices[position].is_some())
            else {
                break;
            };
            let (pattern, length) = choices[position].unwrap();
            if length == 0 && last_end == Some(position) {
                start = position + 1;
                continue;
            }
            let end = position + length;
            matches.push((pattern, position, end));
            start = end;
            last_end = Some(end);
        }
        matches
    }

    fn traced_sequence(
        plan: &SparseOrderedLiteralCountPlan,
        haystack: &[u8],
    ) -> Vec<(u32, usize, usize)> {
        let mut workspace = plan
            .prepare_trace_workspace(haystack.len(), TraceWorkspaceLimits::unlimited())
            .unwrap();
        let report = plan
            .execute_trace_with_workspace(haystack, ReduceLimits::unlimited(), &mut workspace)
            .unwrap();
        assert!(report.closes());
        report
            .matches()
            .iter()
            .map(|matched| (matched.ordinal(), matched.start(), matched.end()))
            .collect()
    }

    #[test]
    fn trace_workspace_matches_exact_priority_sequence_and_count() {
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[b"ab", b"a", b"ab"], b"ababa"),
            (&[b"a", b"ab", b"a"], b"ababa"),
            (&[b"abab", b"bab", b"ab", b"b"], b"xababab"),
            (&[b"", b"aa", b"a"], b"aaa"),
            (&[b"aa", b"", b"a"], b"aaa"),
            (&[b""], b""),
            (&[b"long"], b"x"),
            (&[b"\xFF\x00", b"\xFF", b"\x80"], b"\xFF\x00\x80\xFF"),
        ];
        for &(patterns, haystack) in cases {
            let plan =
                SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                    .unwrap();
            let expected = sequence(&plan, haystack);
            let actual = traced_sequence(&plan, haystack);
            assert_eq!(
                actual, expected,
                "patterns={patterns:?}, haystack={haystack:?}"
            );
            assert_eq!(
                u64::try_from(actual.len()).unwrap(),
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count
            );
        }
    }

    #[test]
    fn trace_workspace_matches_sequence_across_small_binary_sources() {
        let languages: &[&[&[u8]]] = &[
            &[b"a", b"ab", b"a"],
            &[b"ab", b"a", b"b"],
            &[b"aba", b"ba", b"a"],
            &[b"", b"aa", b"a"],
            &[b"aa", b"", b"a"],
        ];
        for &patterns in languages {
            let plan =
                SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                    .unwrap();
            for source_bytes in 0..=7 {
                for bits in 0..(1_usize << source_bytes) {
                    let haystack = (0..source_bytes)
                        .map(|shift| if bits & (1 << shift) == 0 { b'a' } else { b'b' })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        traced_sequence(&plan, &haystack),
                        sequence(&plan, &haystack),
                        "patterns={patterns:?}, haystack={haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn trace_workspace_setup_closes_and_every_limit_refuses_one_below() {
        let plan = SparseOrderedLiteralCountPlan::build(
            vec![b"".as_slice(), b"ab".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let workspace = plan
            .prepare_trace_workspace(7, TraceWorkspaceLimits::unlimited())
            .unwrap();
        let accounting = workspace.accounting();
        assert!(accounting.closes());
        assert_eq!(
            accounting.accounting_id,
            "fre-kernels.sparse-ordered-literal-count-trace-workspace.v1"
        );
        assert_eq!(accounting.source_bytes, 7);
        assert_eq!(accounting.choice_slots, 8);
        assert_eq!(accounting.trace_slots, 8);
        assert_eq!(accounting.allocation_attempts, 2);
        assert_eq!(accounting.setup_work, 10);
        let exact = TraceWorkspaceLimits {
            max_setup_work: accounting.setup_work,
            max_allocation_attempts: accounting.allocation_attempts,
            max_retained_bytes: accounting.retained_logical_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        plan.prepare_trace_workspace(7, exact).unwrap();

        assert!(matches!(
            plan.prepare_trace_workspace(
                7,
                TraceWorkspaceLimits {
                    max_setup_work: exact.max_setup_work - 1,
                    ..exact
                }
            ),
            Err(ReduceError::TraceWorkspaceSetupWorkLimit { needed, limit })
                if needed == accounting.setup_work && limit + 1 == needed
        ));
        assert!(matches!(
            plan.prepare_trace_workspace(
                7,
                TraceWorkspaceLimits {
                    max_allocation_attempts: exact.max_allocation_attempts - 1,
                    ..exact
                }
            ),
            Err(ReduceError::TraceWorkspaceAllocationAttemptsLimit { needed, limit })
                if needed == accounting.allocation_attempts && limit + 1 == needed
        ));
        assert!(matches!(
            plan.prepare_trace_workspace(
                7,
                TraceWorkspaceLimits {
                    max_retained_bytes: exact.max_retained_bytes - 1,
                    ..exact
                }
            ),
            Err(ReduceError::ScratchLimit { needed, limit })
                if needed == accounting.retained_logical_bytes && limit + 1 == needed
        ));
        assert!(matches!(
            plan.prepare_trace_workspace(
                7,
                TraceWorkspaceLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                }
            ),
            Err(ReduceError::PeakLimit { needed, limit })
                if needed == accounting.peak_bytes && limit + 1 == needed
        ));

        let no_match_plan = SparseOrderedLiteralCountPlan::build(
            vec![b"long".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let no_match = no_match_plan
            .prepare_trace_workspace(1, TraceWorkspaceLimits::unlimited())
            .unwrap();
        assert!(no_match.accounting().closes());
        assert_eq!(no_match.accounting().trace_slots, 0);
        assert_eq!(no_match.accounting().trace_capacity, 0);
        assert_eq!(no_match.accounting().allocation_attempts, 1);
    }

    #[test]
    fn trace_workspace_allocation_failures_publish_nothing_and_retry() {
        let plan =
            SparseOrderedLiteralCountPlan::build(vec![b"a".as_slice()], BuildLimits::unlimited())
                .unwrap();
        for ordinal in 0..2 {
            let guard = trace_allocation_probe::fail_at(ordinal);
            let error = plan
                .prepare_trace_workspace(3, TraceWorkspaceLimits::unlimited())
                .unwrap_err();
            let (expected_structure, expected_additional) = if ordinal == 0 {
                ("sparse ordered-literal trace choices", 4)
            } else {
                ("sparse ordered-literal trace entries", 3)
            };
            assert!(matches!(
                error,
                ReduceError::AllocationFailed {
                    structure,
                    additional,
                } if structure == expected_structure && additional == expected_additional
            ));
            drop(guard);
            let workspace = plan
                .prepare_trace_workspace(3, TraceWorkspaceLimits::unlimited())
                .unwrap();
            assert!(workspace.accounting().closes());
        }
    }

    #[test]
    fn trace_workspace_rejects_foreign_source_and_limits_before_private_mutation() {
        let plan =
            SparseOrderedLiteralCountPlan::build(vec![b"a".as_slice()], BuildLimits::unlimited())
                .unwrap();
        let foreign =
            SparseOrderedLiteralCountPlan::build(vec![b"a".as_slice()], BuildLimits::unlimited())
                .unwrap();
        let mut workspace = plan
            .prepare_trace_workspace(3, TraceWorkspaceLimits::unlimited())
            .unwrap();
        plan.execute_trace_with_workspace(b"aaa", ReduceLimits::unlimited(), &mut workspace)
            .unwrap();
        assert_eq!(workspace.trace.len(), 3);

        assert!(matches!(
            foreign
                .execute_trace_with_workspace(b"aaa", ReduceLimits::unlimited(), &mut workspace,),
            Err(ReduceError::TraceWorkspaceMismatch { .. })
        ));
        assert_eq!(workspace.trace.len(), 3);
        assert!(matches!(
            plan.execute_trace_with_workspace(b"aa", ReduceLimits::unlimited(), &mut workspace,),
            Err(ReduceError::TraceWorkspaceMismatch { .. })
        ));
        assert_eq!(workspace.trace.len(), 3);
        assert!(matches!(
            plan.execute_trace_with_workspace(
                b"aaa",
                ReduceLimits {
                    max_transitions: 2,
                    ..ReduceLimits::unlimited()
                },
                &mut workspace,
            ),
            Err(ReduceError::TransitionLimit { .. })
        ));
        assert_eq!(workspace.trace.len(), 3);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "every trace-specific execution limit stays explicit beside its pre-source preservation assertion"
    )]
    fn trace_execution_exact_workspace_bounds_and_one_below_are_pre_source() {
        let plan = SparseOrderedLiteralCountPlan::build(
            vec![b"ab".as_slice(), b"a".as_slice(), b"".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"ababab";
        let mut workspace = plan
            .prepare_trace_workspace(haystack.len(), TraceWorkspaceLimits::unlimited())
            .unwrap();
        let baseline = plan
            .execute_trace_with_workspace(haystack, ReduceLimits::unlimited(), &mut workspace)
            .unwrap();
        let trace_identity = baseline.accounting().identity;
        assert_eq!(trace_identity, plan.trace_cache_identity());
        assert_eq!(
            trace_identity.algorithm_id,
            "ordered-literal-aggregate.reverse-sparse-ac-root256-fixed-source-trace.v1"
        );
        assert_eq!(
            trace_identity.plan_id,
            "ordered-literal-aggregate.count-trace.reverse-sparse-ac-root256-fixed-source.v1"
        );
        assert_eq!(
            trace_identity.traversal_kind,
            "single reverse sparse-AC choice-materialization pass plus fixed-source forward trace scan"
        );
        let scalar_identity = plan.cache_identity();
        assert_eq!(
            scalar_identity.algorithm_id,
            "ordered-literal-aggregate.reverse-sparse-ac-root256-dp.v2"
        );
        assert_eq!(
            scalar_identity.plan_id,
            "ordered-literal-aggregate.count.reverse-sparse-ac-root256-dp.v2"
        );
        assert_eq!(
            scalar_identity.traversal_kind,
            "single reverse sparse-AC pass plus bounded initial/progressed DP ring"
        );
        assert_ne!(trace_identity.algorithm_id, scalar_identity.algorithm_id);
        assert_ne!(trace_identity.plan_id, scalar_identity.plan_id);
        assert_eq!(
            trace_identity.cache_format_version,
            scalar_identity.cache_format_version
        );
        assert_eq!(
            trace_identity.transition_kind,
            scalar_identity.transition_kind
        );
        assert_eq!(trace_identity.semantics, scalar_identity.semantics);
        assert_eq!(
            trace_identity.encoded_patterns,
            scalar_identity.encoded_patterns
        );
        let upper = baseline.accounting().upper_bounds;
        assert_eq!(upper.ring_entries, 0);
        assert_eq!(upper.ring_initializations, 0);
        assert_eq!(
            baseline.accounting().actual.span_sum,
            Some(baseline.selected_span_bytes())
        );
        let exact = ReduceLimits {
            max_transitions: upper.transitions,
            max_edge_lookups: upper.edge_lookups,
            max_edge_search_checks: upper.edge_search_checks,
            max_failure_steps: upper.failure_steps,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_ring_initializations: 0,
            max_total_work: upper.total_work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        plan.execute_trace_with_workspace(haystack, exact, &mut workspace)
            .unwrap();
        assert_eq!(workspace.trace.len(), 3);

        macro_rules! assert_pre_source_refusal {
            ($limits:expr, $variant:pat) => {{
                let error = plan
                    .execute_trace_with_workspace(haystack, $limits, &mut workspace)
                    .unwrap_err();
                assert!(matches!(error, $variant), "unexpected refusal: {error:?}");
                assert_eq!(workspace.trace.len(), 3);
            }};
        }
        assert_pre_source_refusal!(
            ReduceLimits {
                max_transitions: exact.max_transitions - 1,
                ..exact
            },
            ReduceError::TransitionLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_edge_lookups: exact.max_edge_lookups - 1,
                ..exact
            },
            ReduceError::EdgeLookupLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_edge_search_checks: exact.max_edge_search_checks - 1,
                ..exact
            },
            ReduceError::EdgeSearchChecksLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_failure_steps: exact.max_failure_steps - 1,
                ..exact
            },
            ReduceError::FailureStepsLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_match_events: exact.max_match_events - 1,
                ..exact
            },
            ReduceError::MatchEventsLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_count: exact.max_count - 1,
                ..exact
            },
            ReduceError::CountLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_span_sum: exact.max_span_sum - 1,
                ..exact
            },
            ReduceError::SpanSumLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_reducer_steps: exact.max_reducer_steps - 1,
                ..exact
            },
            ReduceError::ReducerStepsLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_total_work: exact.max_total_work - 1,
                ..exact
            },
            ReduceError::TotalWorkLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_scratch_bytes: exact.max_scratch_bytes - 1,
                ..exact
            },
            ReduceError::ScratchLimit { .. }
        );
        assert_pre_source_refusal!(
            ReduceLimits {
                max_peak_bytes: exact.max_peak_bytes - 1,
                ..exact
            },
            ReduceError::PeakLimit { .. }
        );
    }

    #[test]
    fn trace_workspace_recovers_after_post_clear_execution_failure() {
        let plan =
            SparseOrderedLiteralCountPlan::build(vec![b"a".as_slice()], BuildLimits::unlimited())
                .unwrap();
        let mut workspace = plan
            .prepare_trace_workspace(3, TraceWorkspaceLimits::unlimited())
            .unwrap();
        let guard = trace_execution_probe::fail_at(0);
        assert!(matches!(
            plan.execute_trace_with_workspace(b"aaa", ReduceLimits::unlimited(), &mut workspace,),
            Err(ReduceError::InternalInvariant {
                detail: "injected post-clear trace execution failure"
            })
        ));
        drop(guard);
        assert_eq!(workspace.trace.len(), 1);

        let recovered = plan
            .execute_trace_with_workspace(b"aaa", ReduceLimits::unlimited(), &mut workspace)
            .unwrap();
        assert!(recovered.closes());
        assert_eq!(recovered.count(), 3);
        assert_eq!(recovered.matches().len(), 3);
    }

    fn choice_at_start(
        plan: &SparseOrderedLiteralCountPlan,
        haystack: &[u8],
    ) -> Option<(u32, usize)> {
        let mut state = 0_u32;
        let mut counters = super::SearchCounters::default();
        for &byte in haystack.iter().rev() {
            state = plan.core.automaton.next(state, byte, &mut counters);
        }
        plan.core.automaton.output(state)
    }

    #[test]
    fn prefixes_duplicates_failure_chains_empty_and_arbitrary_bytes_match_regex() {
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[b"ab", b"a", b"ab"], b"ababa"),
            (&[b"a", b"ab", b"a"], b"ababa"),
            (&[b"abab", b"bab", b"ab", b"b"], b"xababab"),
            (&[b"", b"aa", b"a"], b"aaa"),
            (&[b"aa", b"", b"a"], b"aaa"),
            (&[b"\xFF\x00", b"\xFF", b"\x80"], b"\xFF\x00\x80\xFF"),
        ];
        for &(patterns, haystack) in cases {
            let owned = patterns
                .iter()
                .map(|pattern| pattern.to_vec())
                .collect::<Vec<_>>();
            let expected = regex(&owned)
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let plan =
                SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                    .unwrap();
            let actual = sequence(&plan, haystack)
                .into_iter()
                .map(|(_, start, end)| (start, end))
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "patterns={patterns:?}, haystack={haystack:?}"
            );
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                u64::try_from(expected.len()).unwrap()
            );
            let expected_span_sum = expected
                .iter()
                .map(|(start, end)| u64::try_from(end - start).unwrap())
                .sum::<u64>();
            let span =
                SparseOrderedLiteralSpanSumPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                    .unwrap();
            assert_eq!(
                span.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected_span_sum
            );
            let spans = SparseOrderedLiteralSpansPlan::build_spans(
                patterns.to_vec(),
                BuildLimits::unlimited(),
            );
            if patterns.iter().any(|pattern| pattern.is_empty()) {
                assert!(matches!(
                    spans,
                    Err(BuildError::EmptyPatternSpanVisitUnsupported)
                ));
                continue;
            }
            let spans = spans.unwrap();
            let mut visited = Vec::new();
            let result = spans
                .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                    visited.push((span.start, span.end));
                })
                .unwrap();
            assert_eq!(visited, expected);
            assert_eq!(result.matches, expected.len());
            assert_eq!(result.span_sum, usize::try_from(expected_span_sum).unwrap());
            assert_eq!(result.accounting.actual.scratch_bytes, 0);
        }
    }

    #[test]
    fn source_index_priority_covers_terminal_and_failure_outputs() {
        let long_first = SparseOrderedLiteralCountPlan::build(
            vec![b"ab".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&long_first, b"ab"), Some((0, 2)));

        let short_first = SparseOrderedLiteralCountPlan::build(
            vec![b"a".as_slice(), b"ab".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&short_first, b"ab"), Some((0, 1)));

        let duplicates = SparseOrderedLiteralCountPlan::build(
            vec![b"abc".as_slice(), b"abc".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&duplicates, b"abc"), Some((0, 3)));
    }

    #[test]
    fn complete_span_visit_matches_small_exhaustive_oracles_and_refuses_before_callback() {
        let languages: &[&[&[u8]]] = &[
            &[b"a", b"ab"],
            &[b"ab", b"a"],
            &[b"b", b"ab"],
            &[b"ab", b"b"],
            &[b"aba", b"ba", b"b"],
            &[b"aa", b"aaa", b"a"],
        ];
        for &patterns in languages {
            let owned = patterns
                .iter()
                .map(|pattern| pattern.to_vec())
                .collect::<Vec<_>>();
            let oracle = regex(&owned);
            let plan = SparseOrderedLiteralSpansPlan::build_spans(
                patterns.to_vec(),
                BuildLimits::unlimited(),
            )
            .unwrap();
            for length in 0_u32..=7 {
                for bits in 0_u32..(1_u32 << length) {
                    let haystack = (0..length)
                        .map(|shift| if bits & (1 << shift) == 0 { b'a' } else { b'b' })
                        .collect::<Vec<_>>();
                    let expected = oracle
                        .find_iter(&haystack)
                        .map(|matched| (matched.start(), matched.end()))
                        .collect::<Vec<_>>();
                    let mut actual = Vec::new();
                    plan.visit_spans(&haystack, ReduceLimits::unlimited(), |span| {
                        actual.push((span.start, span.end));
                    })
                    .unwrap();
                    assert_eq!(
                        actual, expected,
                        "patterns={patterns:?}, haystack={haystack:?}"
                    );
                }
            }

            let haystack = b"abababab";
            let admitted = plan
                .visit_spans(haystack, ReduceLimits::unlimited(), |_| {})
                .unwrap();
            let mut callbacks = 0_usize;
            let error = plan
                .visit_spans(
                    haystack,
                    ReduceLimits {
                        max_transitions: admitted.accounting.upper_bounds.transitions - 1,
                        ..ReduceLimits::unlimited()
                    },
                    |_| callbacks += 1,
                )
                .unwrap_err();
            assert_eq!(callbacks, 0);
            assert!(matches!(error, ReduceError::TransitionLimit { .. }));
        }
    }

    #[test]
    fn concrete_borrowed_source_capacity_is_bounded_and_consumed_once() {
        let patterns = [b"alpha".as_slice(), b"beta".as_slice(), b"a".as_slice()];
        let mut oversized_source = Vec::with_capacity(32);
        oversized_source.extend(patterns);
        let source_scratch = oversized_source.capacity() * size_of::<&[u8]>();
        assert!(matches!(
            SparseOrderedLiteralCountPlan::build(
                oversized_source,
                BuildLimits {
                    max_scratch_bytes: source_scratch - 1,
                    ..BuildLimits::unlimited()
                }
            ),
            Err(BuildError::ScratchLimit { needed, limit })
                if needed == source_scratch && limit == source_scratch - 1
        ));

        let count =
            SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        let span =
            SparseOrderedLiteralSpanSumPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        assert_eq!(
            count
                .count(b"alpha beta alpha", ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );
        assert_eq!(
            span.span_sum(b"alpha beta alpha", ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            14
        );
    }

    #[test]
    fn failure_queue_refusal_precedes_dequeue_mutation() {
        let nodes = [RawNode::EMPTY];
        let mut head = 0;
        let mut tail = 0;
        let mut refused = BuildWork::new(0);
        assert!(matches!(
            charged_dequeue(&nodes, &mut head, &mut tail, &mut refused),
            Err(BuildError::WorkLimit {
                needed: 1,
                limit: 0
            })
        ));
        assert_eq!((head, tail), (0, 0));

        let mut admitted = BuildWork::new(1);
        assert_eq!(
            charged_dequeue(&nodes, &mut head, &mut tail, &mut admitted).unwrap(),
            Some(0)
        );
        assert_eq!((head, tail), (UNSET, UNSET));
        assert_eq!(admitted.used, 1);
    }

    #[test]
    fn failure_link_builder_boundary_preserves_output_before_dequeue() {
        let child_output = Output {
            pattern: 7,
            length: 1,
        };
        let mut automaton = SparseAc {
            root_transitions: [0; ROOT_TRANSITIONS],
            offsets: vec![0, 1, 1],
            edges: vec![pack_edge(b'a', 1)],
            failure: vec![0, 0],
            output: vec![
                Output {
                    pattern: 0,
                    length: 0,
                },
                child_output,
            ],
        };
        let mut nodes = vec![RawNode::EMPTY; 2];
        let mut work = BuildWork::new(1);
        assert!(matches!(
            build_failure_links(
                &mut automaton,
                &mut nodes,
                &mut work,
                super::ConstructionTraversal::Reverse,
            ),
            Err(BuildError::WorkLimit {
                needed: 2,
                limit: 1
            })
        ));
        assert_eq!(work.used, 1);
        assert_eq!(automaton.output[1].pattern, child_output.pattern);
        assert_eq!(automaton.output[1].length, child_output.length);
        assert_eq!(automaton.failure, vec![0, 0]);
    }

    #[test]
    fn hand_calculated_sparse_build_and_reduce_work_are_exact_and_refuse_one_below() {
        // Owned encoding: 8-byte count prefix written twice, one pattern
        // visit, one 8-byte length prefix and one byte copy = 26. Trie/CSR:
        // root 1, insertion 13, root-table initialization 256, two output
        // nodes 2, CSR nodes/edge 3, failure root/state 2, and one non-root
        // degree scan 1, for 304 total.
        const BUILD_WORK: u64 = 304;
        // One input byte admits 1 transition, at most 2 edge lookups, no
        // non-root edge comparisons, 1 failure step, 2 reducer positions and
        // 2 ring initializations.
        const REDUCE_WORK: u64 = 8;

        // Independent capacity arithmetic for one borrowed one-byte pattern:
        // source pointer vector, two raw trie nodes plus one raw edge, and the
        // retained identity/CSR/failure/output vectors.
        let source_scratch = size_of::<&[u8]>();
        let trie_scratch = 2 * size_of::<RawNode>() + size_of::<RawEdge>();
        let scratch_bytes = source_scratch.max(trie_scratch);
        let persistent_bytes = size_of::<SparseOrderedLiteralCountPlan>()
            + 17
            + 3 * size_of::<u32>()
            + size_of::<u32>()
            + 2 * size_of::<u32>()
            + 2 * size_of::<Output>();
        let peak_bytes = persistent_bytes + trie_scratch;

        let patterns = [b"a".as_slice()];
        let exact_build = BuildLimits {
            max_patterns: 1,
            max_pattern_bytes: 1,
            max_identity_bytes: 17,
            max_trie_states: 2,
            max_sparse_edges: 1,
            max_build_work: BUILD_WORK,
            max_scratch_bytes: scratch_bytes,
            max_persistent_bytes: persistent_bytes,
            max_peak_bytes: peak_bytes,
        };
        let plan = SparseOrderedLiteralCountPlan::build(patterns.to_vec(), exact_build).unwrap();
        let build = plan.build_accounting();
        assert_eq!(build.build_work, BUILD_WORK);
        assert_eq!(build.scratch_bytes, scratch_bytes);
        assert_eq!(build.persistent_bytes, persistent_bytes);
        assert_eq!(build.peak_bytes, peak_bytes);
        assert!(matches!(
            SparseOrderedLiteralCountPlan::build(
                patterns.to_vec(),
                BuildLimits {
                    max_build_work: BUILD_WORK - 1,
                    ..exact_build
                }
            ),
            Err(BuildError::WorkLimit {
                needed: BUILD_WORK,
                limit
            }) if limit == BUILD_WORK - 1
        ));

        let exact_reduce = ReduceLimits {
            max_transitions: 1,
            max_edge_lookups: 2,
            max_edge_search_checks: 0,
            max_failure_steps: 1,
            max_match_events: 1,
            max_count: 1,
            max_span_sum: 1,
            max_reducer_steps: 2,
            max_ring_initializations: 2,
            max_total_work: REDUCE_WORK,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        };
        let result = plan.count(b"a", exact_reduce).unwrap();
        assert_eq!(result.count, 1);
        assert_eq!(result.accounting.upper_bounds.total_work, REDUCE_WORK);
        assert_eq!(result.accounting.actual.edge_lookups, 1);
        assert_eq!(result.accounting.actual.edge_search_checks, 0);
        assert_eq!(result.accounting.actual.failure_steps, 0);
        assert_eq!(result.accounting.actual.total_work, 6);
        assert!(matches!(
            plan.count(
                b"a",
                ReduceLimits {
                    max_total_work: REDUCE_WORK - 1,
                    ..exact_reduce
                }
            ),
            Err(ReduceError::TotalWorkLimit {
                needed: REDUCE_WORK,
                limit
            }) if limit == REDUCE_WORK - 1
        ));
    }

    fn generated_patterns(count: usize) -> Vec<[u8; 8]> {
        (0..count)
            .map(|index| {
                let value = u64::try_from(index).unwrap().wrapping_mul(0x9E37_79B9);
                value.to_le_bytes()
            })
            .collect()
    }

    #[test]
    fn sparse_storage_and_work_scale_linearly_without_dense_alphabet_rows() {
        let small_patterns = generated_patterns(1_024);
        let large_patterns = generated_patterns(2_048);
        let small_source = small_patterns
            .iter()
            .map(<[u8; 8]>::as_slice)
            .collect::<Vec<_>>();
        let large_source = large_patterns
            .iter()
            .map(<[u8; 8]>::as_slice)
            .collect::<Vec<_>>();
        let small =
            SparseOrderedLiteralCountPlan::build(small_source, BuildLimits::unlimited()).unwrap();
        let large =
            SparseOrderedLiteralCountPlan::build(large_source, BuildLimits::unlimited()).unwrap();
        let a = small.build_accounting();
        let b = large.build_accounting();
        assert_eq!(a.sparse_edges_actual + 1, a.trie_states_actual);
        assert_eq!(b.sparse_edges_actual + 1, b.trie_states_actual);
        assert!(b.persistent_bytes < a.persistent_bytes * 3);
        assert!(b.build_work < a.build_work * 3);
        assert!(b.max_edge_search_checks <= 9);
        let dense_transition_bytes = b.trie_states_actual * 256 * size_of::<u32>();
        assert!(b.persistent_bytes * 16 < dense_transition_bytes);
    }

    #[test]
    fn root_table_dispatches_hits_and_misses_without_binary_search() {
        for fanout in [127_usize, 128, 255, 256] {
            let patterns = (0..fanout)
                .map(|byte| [u8::try_from(byte).unwrap()])
                .collect::<Vec<_>>();
            let source = patterns.iter().map(<[u8; 1]>::as_slice).collect::<Vec<_>>();
            let plan =
                SparseOrderedLiteralCountPlan::build(source, BuildLimits::unlimited()).unwrap();
            assert_eq!(
                plan.build_accounting().max_edge_search_checks,
                0,
                "fanout={fanout}"
            );

            for byte in 0_u8..=u8::MAX {
                let mut counters = super::SearchCounters::default();
                let state = plan.core.automaton.next(0, byte, &mut counters);
                assert_eq!(
                    state != 0,
                    usize::from(byte) < fanout,
                    "fanout={fanout}, byte={byte}"
                );
                assert_eq!(counters.edge_lookups, 1);
                assert_eq!(counters.edge_search_checks, 0);
                assert_eq!(counters.failure_steps, 0);
            }

            let haystack = b"\x00\x7E\x7F\x80\xFE\xFF";
            let result = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
            let expected = haystack
                .iter()
                .filter(|&&byte| usize::from(byte) < fanout)
                .count();
            assert_eq!(result.count, u64::try_from(expected).unwrap());
            assert_eq!(result.accounting.actual.edge_search_checks, 0);
            assert!(
                result.accounting.actual.total_work <= result.accounting.upper_bounds.total_work
            );
        }
    }

    fn exact_build_limits(plan: &SparseOrderedLiteralCountPlan) -> BuildLimits {
        let build = plan.build_accounting();
        BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_trie_states: build.trie_states_upper_bound,
            max_sparse_edges: build.sparse_edges_upper_bound,
            max_build_work: build.build_work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        }
    }

    #[test]
    fn every_build_dimension_has_exact_limit_and_one_below() {
        let patterns = [
            b"".as_slice(),
            b"ababa".as_slice(),
            b"aba".as_slice(),
            b"\xFF\x00".as_slice(),
        ];
        let baseline =
            SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        let exact = exact_build_limits(&baseline);
        SparseOrderedLiteralCountPlan::build(patterns.to_vec(), exact).unwrap();
        macro_rules! assert_one_below {
            ($field:ident, $variant:ident) => {{
                let limit = exact.$field.checked_sub(1).unwrap();
                let error = SparseOrderedLiteralCountPlan::build(
                    patterns.to_vec(),
                    BuildLimits {
                        $field: limit,
                        ..exact
                    },
                )
                .unwrap_err();
                assert!(
                    matches!(error, BuildError::$variant { limit: actual, .. } if actual == limit),
                    "one-below {} returned {error:?}",
                    stringify!($field)
                );
                let terminal = SparseOrderedLiteralCountPlan::build_attempt(
                    patterns.to_vec(),
                    BuildLimits {
                        $field: limit,
                        ..exact
                    },
                )
                .unwrap_err();
                assert!(
                    terminal.closes(),
                    "one-below {} returned an unclosed attempt receipt: {terminal:?}",
                    stringify!($field)
                );
            }};
        }
        assert_one_below!(max_patterns, PatternLimit);
        assert_one_below!(max_pattern_bytes, PatternBytesLimit);
        assert_one_below!(max_identity_bytes, IdentityBytesLimit);
        assert_one_below!(max_trie_states, TrieStatesLimit);
        assert_one_below!(max_sparse_edges, SparseEdgesLimit);
        assert_one_below!(max_build_work, WorkLimit);
        assert_one_below!(max_scratch_bytes, ScratchLimit);
        assert_one_below!(max_persistent_bytes, PersistentLimit);
        assert_one_below!(max_peak_bytes, PeakLimit);
    }

    fn exact_reduce_limits(upper: super::ReduceUpperBounds, max_span_sum: u64) -> ReduceLimits {
        ReduceLimits {
            max_transitions: upper.transitions,
            max_edge_lookups: upper.edge_lookups,
            max_edge_search_checks: upper.edge_search_checks,
            max_failure_steps: upper.failure_steps,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_ring_initializations: upper.ring_initializations,
            max_total_work: upper.total_work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all sparse reducer limits remain explicit in the exact/one-below table"
    )]
    fn every_reduce_dimension_has_exact_limit_and_one_below() {
        let patterns = [b"ababa".as_slice(), b"aba".as_slice(), b"a".as_slice()];
        let haystack = b"xxababababax";
        let count =
            SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        let span =
            SparseOrderedLiteralSpanSumPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        let counted = count.count(haystack, ReduceLimits::unlimited()).unwrap();
        let summed = span.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let count_exact = exact_reduce_limits(counted.accounting.upper_bounds, u64::MAX);
        let span_exact = exact_reduce_limits(
            summed.accounting.upper_bounds,
            summed.accounting.upper_bounds.span_sum,
        );
        count.count(haystack, count_exact).unwrap();
        span.span_sum(haystack, span_exact).unwrap();

        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_transitions: count_exact.max_transitions - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::TransitionLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_edge_lookups: count_exact.max_edge_lookups - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::EdgeLookupLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_edge_search_checks: count_exact.max_edge_search_checks - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::EdgeSearchChecksLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_failure_steps: count_exact.max_failure_steps - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::FailureStepsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_match_events: count_exact.max_match_events - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_count: count_exact.max_count - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            span.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span_exact.max_span_sum - 1,
                    ..span_exact
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: count_exact.max_reducer_steps - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_ring_initializations: count_exact.max_ring_initializations - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::RingInitializationLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_total_work: count_exact.max_total_work - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::TotalWorkLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_scratch_bytes: count_exact.max_scratch_bytes - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::ScratchLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: count_exact.max_peak_bytes - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));
    }

    #[test]
    fn upper_bound_covers_failure_chain_and_manual_binary_search_counters() {
        let patterns = [
            b"aaaaaaaaab".as_slice(),
            b"aaaaaaaab".as_slice(),
            b"aaaaaaab".as_slice(),
            b"baaaaaaa".as_slice(),
        ];
        let plan =
            SparseOrderedLiteralCountPlan::build(patterns.to_vec(), BuildLimits::unlimited())
                .unwrap();
        let result = plan
            .count(b"aaaaaaaaaaaaaaaaaaaa", ReduceLimits::unlimited())
            .unwrap();
        let actual = result.accounting.actual;
        let upper = result.accounting.upper_bounds;
        assert!(actual.edge_lookups <= upper.edge_lookups);
        assert!(actual.edge_search_checks <= upper.edge_search_checks);
        assert!(actual.failure_steps <= upper.failure_steps);
        assert!(actual.total_work <= upper.total_work);
        assert_eq!(upper.edge_lookups, upper.haystack_bytes * 2);
    }
}
