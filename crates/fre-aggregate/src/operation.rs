use core::marker::PhantomData;
use core::ops::Range;

use fre_exact_alloc::{CopyError, ExactVec, zeroed_exact};
use fre_kernels::{
    RequiredInternalAnchorCountActual, RequiredInternalAnchorCountError,
    RequiredInternalAnchorCountLimits, RequiredInternalAnchorCountUpperBounds,
    RequiredInternalAnchorPlan, UrlAggregatePlan, UrlAggregateReduceAccounting,
    UrlAggregateReduceError, UrlAggregateReduceLimits, UrlAggregateReduceUpperBounds,
};
use sha2::{Digest, Sha256};

use crate::accounting::ExecutionAccounting;
use crate::candidate;
use crate::compile::{
    CompiledRegex, PlanId, RequiredLiteralSets, RequiredSuffixes, StateByteSpanSumPlan,
    StateByteSpanSumTopology, TerminalFrontierSeed,
};
use crate::error::{add, enforce, mul};
use crate::program::{
    Assertion, AssertionContext, Inst, NO_SPLIT_RANK, Program, ScalarSet, decode_first_scalar,
};
use crate::sweep::{self, ContinuationSweepWorkspace, SweepKind, SweepOutcome};
use crate::{Error, OperationLimits, Resource};

mod ordered_bounded_span_sum;
mod terminal_frontier;

/// Half-open absolute byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Forced whole-operation storage formulation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Strategy {
    /// Materialize one endpoint word per `(input boundary, program state)`.
    FullTable,
    /// Materialize construction-selected fixed-size split/root decisions or
    /// reachable endpoints in reverse boundary order and consume them through
    /// a forward-only sequential reader.
    ReverseSequentialRows,
}

/// Exact source-free storage retained by one caller-owned cached Count
/// session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachedCountSessionFootprint {
    /// Exact number of retained heap buffers.
    pub allocations: usize,
    /// Boundary-state bytes bound to the session's exact input length.
    pub boundary_bytes: usize,
    /// Interned frontier, transition, and replay-buffer bytes.
    pub cache_bytes: usize,
    /// Complete boundary-log traffic ceiling for one Count operation.
    pub sequential_bytes: usize,
    /// Maximum simultaneously retained bytes.
    pub retained_bytes: usize,
}

/// Caller-owned reusable storage for the byte Count executor.
///
/// A session is bound to one compiled plan, one exact operation policy, and
/// one exact haystack length. It retains only Boolean frontier images,
/// source-independent transition keys, and source-derived work buffers that
/// are reset or overwritten before reuse. It never retains haystack bytes,
/// spans, or reducer results.
#[derive(Debug)]
pub struct CachedCountSession {
    plan_id: PlanId,
    haystack_len: usize,
    limits_id: OperationLimitsId,
    footprint: CachedCountSessionFootprint,
    cache: CachedFrontierStore,
}

/// Construction-selected record stored by [`Strategy::ReverseSequentialRows`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RowStorage {
    /// One preferred/fallback bit per split plus one reachable-root bit.
    SplitDecisions,
    /// The selected reachable endpoint, encoded in the fewest whole bytes
    /// required by the admitted input boundary count.
    ReachableEndpoints,
}

/// Marker for complete span iteration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanIteration;

/// Marker for match counting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MatchCount;

/// Marker for checked matched-byte summation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanSum;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum OperationKind {
    Spans,
    Count,
    Sum,
}

/// Explicit generic route requested by a receipt-bearing Count operation.
/// `None` at the executor boundary retains the incumbent automatic selector;
/// these variants bypass every specialized Count fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericCountRoute {
    CachedFrontier,
    Dense,
    StartDomain,
    TerminalFrontier,
    OrderedRoot,
    RequiredSuffix,
    Candidate,
}

/// Stable identity of a regex plan, forced strategy and operation type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId([u8; 16]);

impl OperationId {
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for OperationId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Stable identity of every caller-supplied operation limit.
///
/// The physical operation ID is derivable from the other attempt fields, so
/// the receipt retains this independent full-policy seal in the same fixed
/// footprint instead of duplicating that operation ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationLimitsId([u8; 16]);

impl OperationLimitsId {
    /// Canonically seal every field of one exact caller policy.
    #[must_use]
    pub fn from_limits(limits: OperationLimits) -> Self {
        operation_limits_identity(limits)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for OperationLimitsId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Whole-operation certificate checked before a result handle is published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCertificate {
    pub regex_plan_id: PlanId,
    /// Stable seal over every exact caller-supplied operation limit.
    pub operation_limits_id: OperationLimitsId,
    pub strategy: Strategy,
    /// Operation whose prospective and actual accounting this certifies.
    pub operation: OperationAttemptKind,
    /// Exact executor selected before source access.
    pub physical_route: OperationPhysicalRoute,
    /// Explicit implementation version for the selected continuation route.
    pub algorithm_version: u8,
    /// Explicit schema version for prospective/actual accounting.
    pub accounting_version: u8,
    /// Construction- and invocation-derived route-selection edge exhausted
    /// before the physical route and prospective were published.
    pub prepublication_fallback: OperationPrepublicationFallback,
    /// Allocation upper bound published before source access, compact under
    /// the accounting-version structural route theorem.
    pub prospective_allocations: u8,
    /// Exact successful operation-local allocations committed on success.
    pub actual_allocations: u8,
    pub range: Range<usize>,
    pub states: usize,
    pub table_cells: usize,
    pub row_storage: Option<RowStorage>,
    pub row_record_bytes: usize,
    /// Whether HIR-certified terminal candidates fed a bounded ordered
    /// frontier instead of evaluating every program state at every boundary.
    pub terminal_frontier: bool,
    pub work_bound: usize,
    pub random_access_bytes: usize,
    pub scratch_bytes: usize,
    pub log_bytes: usize,
    pub sequential_bytes_bound: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub output_bytes: usize,
    pub span_sum: usize,
    pub peak_bytes: usize,
}

impl OperationCertificate {
    fn retain_published_prospective(
        &mut self,
        prospective: &OperationProspective,
        actual_allocations: usize,
    ) -> Result<(), Error> {
        self.prospective_allocations = compact_operation_allocation_count(prospective.allocations)?;
        self.actual_allocations = compact_operation_allocation_count(actual_allocations)?;
        self.states = prospective.states;
        self.table_cells = prospective.table_cells;
        self.row_storage = prospective.row_storage;
        self.row_record_bytes = prospective.row_record_bytes;
        self.terminal_frontier = prospective.terminal_frontier;
        self.work_bound = prospective.work_bound;
        self.random_access_bytes = prospective.random_access_bytes;
        self.scratch_bytes = prospective.scratch_bytes;
        self.log_bytes = prospective.log_bytes;
        self.sequential_bytes_bound = prospective.sequential_bytes;
        self.match_events = prospective.match_events;
        self.output_matches = prospective.output_matches;
        self.output_bytes = prospective.output_bytes;
        self.span_sum = prospective.span_sum;
        self.peak_bytes = prospective.peak_bytes;
        Ok(())
    }

    fn retains_published_prospective(&self, prospective: &OperationProspective) -> bool {
        self.states == prospective.states
            && self.boundaries() == prospective.boundaries
            && self.table_cells == prospective.table_cells
            && self.row_storage == prospective.row_storage
            && self.row_record_bytes == prospective.row_record_bytes
            && self.terminal_frontier == prospective.terminal_frontier
            && self.work_bound == prospective.work_bound
            && self.random_access_bytes == prospective.random_access_bytes
            && self.scratch_bytes == prospective.scratch_bytes
            && self.log_bytes == prospective.log_bytes
            && self.sequential_bytes_bound == prospective.sequential_bytes
            && self.match_events == prospective.match_events
            && self.output_matches == prospective.output_matches
            && self.output_bytes == prospective.output_bytes
            && self.span_sum == prospective.span_sum
            && usize::from(self.prospective_allocations) == prospective.allocations
            && self.peak_bytes == prospective.peak_bytes
    }

    /// Number of input boundaries certified by this valid half-open range.
    #[must_use]
    pub fn boundaries(&self) -> usize {
        self.range
            .end
            .checked_sub(self.range.start)
            .and_then(|bytes| bytes.checked_add(1))
            .expect("valid published operation certificate range must have a boundary count")
    }

    /// Derive the physical operation identity from the retained plan, logical
    /// operation, strategy, and selected physical route.
    #[must_use]
    pub fn operation_id(&self) -> OperationId {
        operation_identity(
            self.regex_plan_id,
            self.strategy,
            operation_kind(self.operation),
            self.physical_route,
        )
    }

    /// Verify every exact caller limit against this certificate's stable seal.
    #[must_use]
    pub fn authenticates_limits(&self, limits: OperationLimits) -> bool {
        self.operation_limits_id == operation_limits_identity(limits)
    }
}

/// Public operation tag retained by a receipt-bearing execution attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationAttemptKind {
    Spans,
    Count,
    SpanSum,
}

const fn operation_kind(kind: OperationAttemptKind) -> OperationKind {
    match kind {
        OperationAttemptKind::Spans => OperationKind::Spans,
        OperationAttemptKind::Count => OperationKind::Count,
        OperationAttemptKind::SpanSum => OperationKind::Sum,
    }
}

const fn operation_attempt_kind(kind: OperationKind) -> OperationAttemptKind {
    match kind {
        OperationKind::Spans => OperationAttemptKind::Spans,
        OperationKind::Count => OperationAttemptKind::Count,
        OperationKind::Sum => OperationAttemptKind::SpanSum,
    }
}

/// Version of the continuation execution algorithm bound into every attempt.
pub const CONTINUATION_OPERATION_ALGORITHM_VERSION: u8 = 6;

/// Version of the continuation prospective/actual accounting schema.
pub const CONTINUATION_OPERATION_ACCOUNTING_VERSION: u8 = 8;

/// Maximum allocation count representable by every route in accounting v8.
///
/// Terminal-frontier execution owns at most eight nonempty operation-local
/// buffers; a receipt-bearing Spans result can add one exact output buffer.
/// Adding a route with a larger structural maximum requires a new accounting
/// schema and certificate layout.
pub const CONTINUATION_OPERATION_MAX_ALLOCATIONS: u8 = 9;

fn compact_operation_allocation_count(allocations: usize) -> Result<u8, Error> {
    if allocations > usize::from(CONTINUATION_OPERATION_MAX_ALLOCATIONS) {
        return Err(Error::InternalInvariant(
            "continuation allocation count exceeds its accounting-version structural maximum",
        ));
    }
    u8::try_from(allocations).map_err(|_| {
        Error::InternalInvariant(
            "continuation allocation count does not fit its certificate encoding",
        )
    })
}

/// Physical executor selected before a continuation attempt reads its source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationPhysicalRoute {
    /// Complete endpoint table or reverse sequential rows.
    DenseRows,
    /// Reverse rows with source-ordered root-arm selection batched per row.
    OrderedRootRows,
    /// Reverse rows seeded by the construction-retained required suffixes.
    RequiredSuffixRows,
    /// Reverse rows seeded by the construction-retained terminal frontier.
    TerminalFrontierRows,
    /// Bounded observed-work frontier cache.
    CachedFrontier,
    /// Certified required-internal-anchor candidate stream.
    RequiredInternalAnchor,
    /// Certified URL aggregate executor.
    UrlAggregate,
    /// Certified allocation-free byte-topology Count/`SpanSum` reducer.
    StateByteSpanSum,
    /// Construction-retained byte candidate scheduler.
    Candidate,
    /// Forward continuation execution at compiler-proved start boundaries.
    StartDomain,
    /// Source-independent mirrored finite-chunk `SpanSum` frontier.
    OrderedBoundedSpanSum,
    /// Exact two-anchor event stream with algebraic bounded-middle ranks.
    OrderedBoundedSpanSumEvents,
    /// Compiler-retained exact root zero-width assertion reducer.
    RootAssertion,
}

/// The only route-selection edge allowed before an attempt publishes its
/// selected route and prospective. Once publication occurs, no fallback is
/// permitted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationPrepublicationFallback {
    None,
    TerminalFrontierThenDense,
    DenseThenRequiredSuffix,
    DenseThenCachedFrontier,
    OrderedBoundedEventsThenFrontier,
}

/// Work-admission mode used by a receipt-bearing execution attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationWorkMode {
    /// Reserve the complete conservative replay bound before execution.
    ConservativeAdmission,
    /// Enforce the caller's work limit against each exact observed charge.
    Observed,
}

/// Immutable identity of a receipt-bearing continuation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationAttemptIdentity {
    pub regex_plan_id: PlanId,
    /// Stable seal over every exact caller-supplied operation limit.
    pub operation_limits_id: OperationLimitsId,
    pub strategy: Strategy,
    pub operation: OperationAttemptKind,
    pub work_mode: OperationWorkMode,
    /// Selected physical route. This is absent only before route publication.
    pub physical_route: Option<OperationPhysicalRoute>,
    pub algorithm_version: u8,
    pub accounting_version: u8,
    /// Construction- and invocation-derived route selection edge. This edge
    /// is exhausted before `physical_route` and P are published.
    pub prepublication_fallback: OperationPrepublicationFallback,
}

impl OperationAttemptIdentity {
    /// Derive the incumbent physical operation ID once a route is published.
    #[must_use]
    pub fn operation_id(self) -> Option<OperationId> {
        self.physical_route.map(|physical_route| {
            operation_identity(
                self.regex_plan_id,
                self.strategy,
                operation_kind(self.operation),
                physical_route,
            )
        })
    }

    /// Verify every exact caller limit against this attempt's stable seal.
    #[must_use]
    pub fn authenticates_limits(self, limits: OperationLimits) -> bool {
        self.operation_limits_id == operation_limits_identity(limits)
    }
}

/// Original-haystack invocation bound to an operation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationInvocation {
    pub range: Range<usize>,
    pub haystack_len: usize,
}

/// Complete input-only upper-bound certificate published before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationProspective {
    pub states: usize,
    pub boundaries: usize,
    pub table_cells: usize,
    pub row_storage: Option<RowStorage>,
    pub row_record_bytes: usize,
    pub terminal_frontier: bool,
    pub work_bound: usize,
    pub random_access_bytes: usize,
    pub scratch_bytes: usize,
    pub log_bytes: usize,
    pub sequential_bytes: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub output_bytes: usize,
    pub span_sum: usize,
    pub allocations: usize,
    pub peak_bytes: usize,
    /// Componentwise upper bounds for every public actual-accounting field.
    pub accounting: ExecutionAccounting,
}

impl OperationProspective {
    /// Admit every operation-limit dimension exposed by this certificate.
    /// Structural metadata such as `states` and `row_record_bytes` is already
    /// represented in the derived table, storage, byte, peak, and work
    /// dimensions below.
    fn enforce_limits(self, limits: OperationLimits) -> Result<(), Error> {
        enforce(self.boundaries, limits.max_boundaries, Resource::Boundaries)?;
        enforce(
            self.table_cells,
            limits.max_table_cells,
            Resource::TableCells,
        )?;
        enforce(
            self.random_access_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            self.scratch_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(self.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            self.sequential_bytes,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(
            self.match_events,
            limits.max_match_events,
            Resource::MatchEvents,
        )?;
        enforce(
            self.output_matches,
            limits.max_output_matches,
            Resource::OutputMatches,
        )?;
        enforce(
            self.output_bytes,
            limits.max_output_bytes,
            Resource::OutputBytes,
        )?;
        enforce(self.span_sum, limits.max_span_sum, Resource::SpanSum)?;
        enforce(self.peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
        enforce(self.work_bound, limits.max_work, Resource::ExecutionWork)
    }

    /// Check every public execution-accounting dimension against this bound.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the componentwise certificate check intentionally names every public accounting field"
    )]
    pub fn contains(self, actual: ExecutionAccounting) -> bool {
        let ExecutionAccounting {
            state_evaluations,
            transition_checks,
            assertion_checks,
            root_probes,
            required_literal_source_bytes,
            required_literal_comparisons,
            required_anchor_candidates,
            required_anchor_scan_windows,
            required_anchor_anchor_comparisons,
            required_anchor_prefix_steps,
            required_anchor_continuation_steps,
            required_anchor_source_accesses,
            required_anchor_queue_peak,
            required_anchor_frontier_peak,
            url_segments,
            url_dot_probes,
            url_tld_transitions,
            url_tld_candidates,
            url_scheme_probes,
            url_ipv4_candidates,
            url_prefix_steps,
            url_suffix_steps,
            url_candidate_insertions,
            url_candidate_visits,
            replay_steps,
            successful_paths,
            suppressed_empty,
            emitted_matches,
            utf8_validation_work,
            frontier_peak_states,
            frontier_insertions,
            frontier_evaluations,
            frontier_source_bytes,
            frontier_bytes,
            frontier_bookkeeping,
            sequential_bytes_written,
            sequential_bytes_read,
            random_access_bytes_read,
            random_access_peak_bytes,
            scratch_peak_bytes,
            log_bytes,
            output_bytes,
            peak_bytes,
            work,
        } = actual;
        let upper = self.accounting;
        macro_rules! at_most {
            ($($field:ident),+ $(,)?) => {
                true $(&& $field <= upper.$field)+
            };
        }
        let componentwise = at_most!(
            state_evaluations,
            transition_checks,
            assertion_checks,
            root_probes,
            required_literal_source_bytes,
            required_literal_comparisons,
            required_anchor_candidates,
            required_anchor_scan_windows,
            required_anchor_anchor_comparisons,
            required_anchor_prefix_steps,
            required_anchor_continuation_steps,
            required_anchor_source_accesses,
            required_anchor_queue_peak,
            required_anchor_frontier_peak,
            url_segments,
            url_dot_probes,
            url_tld_transitions,
            url_tld_candidates,
            url_scheme_probes,
            url_ipv4_candidates,
            url_prefix_steps,
            url_suffix_steps,
            url_candidate_insertions,
            url_candidate_visits,
            replay_steps,
            successful_paths,
            suppressed_empty,
            emitted_matches,
            utf8_validation_work,
            frontier_peak_states,
            frontier_insertions,
            frontier_evaluations,
            frontier_source_bytes,
            frontier_bytes,
            frontier_bookkeeping,
            sequential_bytes_written,
            sequential_bytes_read,
            random_access_bytes_read,
            random_access_peak_bytes,
            scratch_peak_bytes,
            log_bytes,
            output_bytes,
            peak_bytes,
            work,
        );
        let sequential_total = sequential_bytes_written.checked_add(sequential_bytes_read);
        componentwise
            && sequential_total.is_some_and(|bytes| bytes <= self.sequential_bytes)
            && random_access_peak_bytes <= self.random_access_bytes
            && scratch_peak_bytes <= self.scratch_bytes
            && log_bytes <= self.log_bytes
            && emitted_matches <= self.output_matches
            && output_bytes <= self.output_bytes
            && peak_bytes <= self.peak_bytes
            && work <= self.work_bound
    }
}

/// Identity, invocation, prospective certificate, and cumulative actual
/// counters for one receipt-bearing continuation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAttemptReceipt {
    pub identity: OperationAttemptIdentity,
    pub invocation: OperationInvocation,
    pub prospective: Option<OperationProspective>,
    pub actual: ExecutionAccounting,
    /// U1-scoped allocation ceiling for the forced-generic scalar residual.
    /// Ordinary receipt-bearing callers use `usize::MAX`.
    pub allocation_limit: usize,
    /// Successful operation-local allocations committed by this attempt.
    pub actual_allocations: usize,
    authentication: Option<OperationAttemptReceiptAuthentication>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationAttemptReceiptAuthentication {
    identity: OperationAttemptIdentity,
    invocation: OperationInvocation,
    prospective: Option<OperationProspective>,
    actual: ExecutionAccounting,
    allocation_limit: usize,
    actual_allocations: usize,
    terminal: OperationAttemptTerminalAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OperationAttemptTerminalAuthentication {
    Success,
    Failure(Error),
}

impl OperationAttemptReceiptAuthentication {
    fn new(
        receipt: &OperationAttemptReceipt,
        terminal: OperationAttemptTerminalAuthentication,
    ) -> Self {
        Self {
            identity: receipt.identity,
            invocation: receipt.invocation.clone(),
            prospective: receipt.prospective,
            actual: receipt.actual,
            allocation_limit: receipt.allocation_limit,
            actual_allocations: receipt.actual_allocations,
            terminal,
        }
    }

    fn matches(&self, receipt: &OperationAttemptReceipt) -> bool {
        self.identity == receipt.identity
            && self.invocation == receipt.invocation
            && self.prospective == receipt.prospective
            && self.actual == receipt.actual
            && self.allocation_limit == receipt.allocation_limit
            && self.actual_allocations == receipt.actual_allocations
    }
}

impl OperationAttemptReceipt {
    fn authenticate_terminal(&mut self, terminal: OperationAttemptTerminalAuthentication) {
        debug_assert!(
            self.authentication.is_none(),
            "operation attempt terminal was authenticated more than once"
        );
        self.authentication = Some(OperationAttemptReceiptAuthentication::new(self, terminal));
    }

    /// Authenticate the exact immutable identity, invocation, P/A, and
    /// allocation fields published by the operation executor.
    #[must_use]
    pub fn authenticates_canonical(&self) -> bool {
        self.authentication
            .as_ref()
            .is_some_and(|authentication| authentication.matches(self))
            && self.identity.algorithm_version == CONTINUATION_OPERATION_ALGORITHM_VERSION
            && self.identity.accounting_version == CONTINUATION_OPERATION_ACCOUNTING_VERSION
            && match self.prospective {
                None => {
                    self.identity.physical_route.is_none()
                        && self.actual == ExecutionAccounting::default()
                        && self.actual_allocations == 0
                }
                Some(prospective) => {
                    self.identity.physical_route.is_some()
                        && prospective.contains(self.actual)
                        && self.actual_allocations <= prospective.allocations
                        && self.actual_allocations <= self.allocation_limit
                }
            }
    }

    /// Authenticate a successful terminal and all of its exact public fields.
    #[must_use]
    pub fn authenticates_success(&self) -> bool {
        self.authentication.as_ref().is_some_and(|authentication| {
            self.authenticates_canonical()
                && self.has_valid_invocation()
                && authentication.terminal == OperationAttemptTerminalAuthentication::Success
        })
    }

    /// Authenticate the exact typed failure paired with this terminal receipt.
    #[must_use]
    pub fn authenticates_source(&self, source: &Error) -> bool {
        self.authentication.as_ref().is_some_and(|authentication| {
            self.authenticates_canonical()
                && self.invocation_authenticates_source(source)
                && matches!(
                    &authentication.terminal,
                    OperationAttemptTerminalAuthentication::Failure(authenticated)
                        if authenticated == source
                )
        })
    }

    fn has_valid_invocation(&self) -> bool {
        self.invocation.range.start <= self.invocation.range.end
            && self.invocation.range.end <= self.invocation.haystack_len
    }

    fn invocation_authenticates_source(&self, source: &Error) -> bool {
        match *source {
            Error::InvalidRange {
                start,
                end,
                haystack_len,
            } => {
                self.invocation.range == (start..end)
                    && self.invocation.haystack_len == haystack_len
                    && (start > end || end > haystack_len)
            }
            _ => self.has_valid_invocation(),
        }
    }
}

/// Terminal failure from a receipt-bearing continuation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAttemptError {
    pub source: Error,
    pub receipt: OperationAttemptReceipt,
}

impl OperationAttemptError {
    fn new(source: Error, mut receipt: OperationAttemptReceipt) -> Self {
        receipt.authenticate_terminal(OperationAttemptTerminalAuthentication::Failure(
            source.clone(),
        ));
        Self { source, receipt }
    }

    /// Authenticate the exact public terminal source and immutable receipt.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.authenticates_source(&self.source)
    }
}

impl core::fmt::Display for OperationAttemptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for OperationAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Version of the optional, post-operation structural counter projection.
///
/// This deliberately versioned projection is separate from continuation
/// accounting. It never participates in route selection, admission, or the
/// value-only hot loop; it is reconstructed from an already authenticated
/// terminal receipt after the operation completes.
pub const OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION: u8 = 1;

/// Value emitted by an optional structural counter receipt.
///
/// Keeping the logical reducer kind beside the result makes an attribution
/// record self-describing without accepting any external benchmark, fixture,
/// expected-result, or timing metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCounterValue {
    Count(usize),
    SpanSum(usize),
}

impl OperationCounterValue {
    const fn operation(self) -> OperationAttemptKind {
        match self {
            Self::Count(_) => OperationAttemptKind::Count,
            Self::SpanSum(_) => OperationAttemptKind::SpanSum,
        }
    }

    /// Value-only reducer result retained by this receipt.
    #[must_use]
    pub const fn value(self) -> usize {
        match self {
            Self::Count(value) | Self::SpanSum(value) => value,
        }
    }
}

/// Optional structural counters projected from one authenticated continuation
/// attempt.
///
/// Fields that are not present in the capture-free continuation executor are
/// explicitly zero rather than omitted. In particular, accounting v8 has no
/// DFA cache, line-domain, persistent-history, or reusable-scratch-clear
/// facility. This makes a zero an auditable statement about the selected
/// implementation rather than an absent measurement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationStructuralCounters {
    /// Candidate occurrences accepted by the certified internal-anchor route.
    pub candidate_occurrences: usize,
    /// Bytes accessed while verifying accepted internal-anchor candidates.
    pub verified_bytes: usize,
    /// Exact transition checks performed by the selected continuation route.
    pub state_transitions: usize,
    /// Cache misses in a DFA cache. Accounting v8 has no DFA cache.
    pub dfa_cache_misses: usize,
    /// One whole-operation selector invocation, published before source use.
    pub selector_invocations: usize,
    /// Line domains visited. The continuation executor is whole-input only.
    pub line_domains: usize,
    /// Persistent capture-history nodes. This executor is capture-free.
    pub history_nodes: usize,
    /// Exact operation-local allocations committed by the attempt.
    pub allocations: usize,
    /// Reusable scratch clears. Accounting v5 owns no reusable scratch arena.
    pub scratch_clears: usize,
    /// Complete output events emitted by the reducer.
    pub output_events: usize,
}

impl OperationStructuralCounters {
    fn from_attempt(attempt: &OperationAttemptReceipt) -> Self {
        Self {
            candidate_occurrences: attempt.actual.required_anchor_candidates,
            verified_bytes: attempt.actual.required_anchor_source_accesses,
            state_transitions: attempt.actual.transition_checks,
            dfa_cache_misses: 0,
            selector_invocations: 1,
            line_domains: 0,
            history_nodes: 0,
            allocations: attempt.actual_allocations,
            scratch_clears: 0,
            output_events: attempt.actual.emitted_matches,
        }
    }

    fn from_certificate(
        certificate: &OperationCertificate,
        accounting: &ExecutionAccounting,
    ) -> Self {
        Self {
            candidate_occurrences: accounting.required_anchor_candidates,
            verified_bytes: accounting.required_anchor_source_accesses,
            state_transitions: accounting.transition_checks,
            dfa_cache_misses: 0,
            selector_invocations: 1,
            line_domains: 0,
            history_nodes: 0,
            allocations: usize::from(certificate.actual_allocations),
            scratch_clears: 0,
            output_events: accounting.emitted_matches,
        }
    }
}

/// Immutable attribution and optional structural counters for one successful
/// value-only continuation operation.
///
/// The contained [`OperationAttemptReceipt`] remains the source of truth for
/// selected route, invocation, exact caller-limit seal, prospective resource
/// bounds, and actual accounting. This wrapper adds no selector inputs and is
/// created only after that receipt has authenticated a successful terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCounterReceipt {
    /// Schema for the structural projection, independent from accounting v8.
    pub schema_version: u8,
    /// Sealed route, invocation, prospective bounds, and actual accounting.
    pub attempt: OperationAttemptReceipt,
    /// Logical reducer result paired with the sealed operation kind.
    pub value: OperationCounterValue,
    /// Optional counters already collected by the selected operation.
    pub counters: OperationStructuralCounters,
    authentication: OperationCounterReceiptAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationCounterReceiptAuthentication {
    schema_version: u8,
    attempt: OperationAttemptReceipt,
    value: OperationCounterValue,
    counters: OperationStructuralCounters,
}

impl OperationCounterReceipt {
    fn new(attempt: OperationAttemptReceipt, value: OperationCounterValue) -> Result<Self, Error> {
        if !attempt_counter_components_close(&attempt, value) {
            return Err(Error::InternalInvariant(
                "structural counter receipt requires one sealed successful continuation attempt",
            ));
        }
        let counters = OperationStructuralCounters::from_attempt(&attempt);
        let schema_version = OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION;
        Ok(Self {
            schema_version,
            authentication: OperationCounterReceiptAuthentication {
                schema_version,
                attempt: attempt.clone(),
                value,
                counters,
            },
            attempt,
            value,
            counters,
        })
    }

    /// Verify the sealed attempt, reducer kind, exact P/A relation, and every
    /// projected counter. Mutating any public field makes this return `false`.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.schema_version == OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION
            && self.authentication
                == (OperationCounterReceiptAuthentication {
                    schema_version: self.schema_version,
                    attempt: self.attempt.clone(),
                    value: self.value,
                    counters: self.counters,
                })
            && attempt_counter_components_close(&self.attempt, self.value)
            && self.counters == OperationStructuralCounters::from_attempt(&self.attempt)
    }
}

fn attempt_counter_components_close(
    attempt: &OperationAttemptReceipt,
    value: OperationCounterValue,
) -> bool {
    attempt.authenticates_success()
        && attempt.identity.operation == value.operation()
        && attempt.prospective.is_some_and(|prospective| {
            prospective.contains(attempt.actual)
                && match value {
                    // Count is already an exact actual-accounting component.
                    OperationCounterValue::Count(matches) => {
                        matches == attempt.actual.emitted_matches
                    }
                    // The SpanSum value is sealed by SpanSumValueAttempt before
                    // this projection is constructed. The P/A receipt retains
                    // its exact resource ceiling, so recheck that bound here.
                    OperationCounterValue::SpanSum(span_sum) => span_sum <= prospective.span_sum,
                }
        })
}

/// Immutable optional counters from the ordinary value-only hot path.
///
/// Unlike [`OperationCounterReceipt`], this receipt is intentionally derived
/// from the same non-receipt-bearing execution path as `count_value` and
/// `span_sum_value`. It therefore preserves the incumbent selected route and
/// merely publishes the certificate and accounting that the completed hot
/// operation already produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationHotCounterReceipt {
    /// Schema for the structural projection, independent from accounting v8.
    pub schema_version: u8,
    /// Exact route certificate emitted by the ordinary value-only operation.
    pub certificate: OperationCertificate,
    /// Exact structural counters collected by that operation.
    pub accounting: ExecutionAccounting,
    /// Logical reducer result paired with the certificate operation.
    pub value: OperationCounterValue,
    /// Optional counters projected after the hot loop completes.
    pub counters: OperationStructuralCounters,
    authentication: OperationHotCounterReceiptAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationHotCounterReceiptAuthentication {
    schema_version: u8,
    certificate: OperationCertificate,
    accounting: ExecutionAccounting,
    value: OperationCounterValue,
    counters: OperationStructuralCounters,
}

impl OperationHotCounterReceipt {
    fn new(
        certificate: OperationCertificate,
        accounting: &ExecutionAccounting,
        value: OperationCounterValue,
    ) -> Result<Self, Error> {
        if !hot_counter_components_close(&certificate, accounting, value) {
            return Err(Error::InternalInvariant(
                "value-only counter receipt diverged from its completed operation certificate",
            ));
        }
        let counters = OperationStructuralCounters::from_certificate(&certificate, accounting);
        let schema_version = OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION;
        Ok(Self {
            schema_version,
            authentication: OperationHotCounterReceiptAuthentication {
                schema_version,
                certificate: certificate.clone(),
                accounting: *accounting,
                value,
                counters,
            },
            certificate,
            accounting: *accounting,
            value,
            counters,
        })
    }

    /// Verify the ordinary hot-path certificate, actual counters, reducer
    /// kind, and post-operation counter projection. Mutating any public
    /// field makes this return `false`.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.schema_version == OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION
            && self.authentication
                == (OperationHotCounterReceiptAuthentication {
                    schema_version: self.schema_version,
                    certificate: self.certificate.clone(),
                    accounting: self.accounting,
                    value: self.value,
                    counters: self.counters,
                })
            && hot_counter_components_close(&self.certificate, &self.accounting, self.value)
            && self.counters
                == OperationStructuralCounters::from_certificate(
                    &self.certificate,
                    &self.accounting,
                )
    }
}

fn hot_counter_components_close(
    certificate: &OperationCertificate,
    accounting: &ExecutionAccounting,
    value: OperationCounterValue,
) -> bool {
    let sequential = accounting
        .sequential_bytes_written
        .checked_add(accounting.sequential_bytes_read);
    certificate.operation == value.operation()
        && certificate.actual_allocations <= certificate.prospective_allocations
        && sequential.is_some_and(|bytes| bytes <= certificate.sequential_bytes_bound)
        && accounting.random_access_peak_bytes <= certificate.random_access_bytes
        && accounting.scratch_peak_bytes <= certificate.scratch_bytes
        && accounting.log_bytes <= certificate.log_bytes
        && accounting.output_bytes <= certificate.output_bytes
        && accounting.peak_bytes <= certificate.peak_bytes
        && accounting.work <= certificate.work_bound
        && accounting.emitted_matches <= certificate.output_matches
        && match value {
            OperationCounterValue::Count(matches) => matches == accounting.emitted_matches,
            // Some ordinary routes retain a prospective span bound in the
            // certificate, while others retain their actual span sum. The
            // completed reducer result is sealed below, so its relationship
            // to either representation is necessarily an upper-bound check.
            OperationCounterValue::SpanSum(span_sum) => span_sum <= certificate.span_sum,
        }
}

#[derive(Debug)]
struct Common<K> {
    certificate: OperationCertificate,
    accounting: ExecutionAccounting,
    marker: PhantomData<K>,
}

struct AttemptPublication<'a> {
    identity: &'a mut OperationAttemptIdentity,
    prospective: &'a mut Option<OperationProspective>,
}

/// Receipt-bearing generic counts must derive one intrinsic route envelope
/// before any caller resource limit can refuse it. These limits are used only
/// while selecting and deriving that envelope; the published prospective is
/// immediately checked against every caller limit before source access or
/// allocation.
const fn intrinsic_attempt_limits() -> OperationLimits {
    OperationLimits {
        max_boundaries: usize::MAX,
        max_table_cells: usize::MAX,
        max_random_access_bytes: usize::MAX,
        max_scratch_bytes: usize::MAX,
        max_log_bytes: usize::MAX,
        max_sequential_bytes: usize::MAX,
        max_match_events: usize::MAX,
        max_output_matches: usize::MAX,
        max_output_bytes: usize::MAX,
        max_span_sum: usize::MAX,
        max_peak_bytes: usize::MAX,
        max_work: usize::MAX,
    }
}

#[cfg(test)]
mod allocation_fault {
    use std::cell::Cell;

    std::thread_local! {
        static STATE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    }

    #[derive(Debug)]
    pub(super) struct Guard {
        previous: Option<(usize, usize)>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.with(|state| state.set(self.previous));
        }
    }

    pub(super) fn arm(failing_ordinal: usize) -> Guard {
        let previous = STATE.with(|state| state.replace(Some((failing_ordinal, 0))));
        Guard { previous }
    }

    pub(super) fn calls() -> usize {
        STATE.with(|state| state.get().map_or(0, |(_, calls)| calls))
    }

    pub(super) fn should_fail() -> bool {
        STATE.with(|state| {
            let Some((failing, next)) = state.get() else {
                return false;
            };
            state.set(Some((failing, next.saturating_add(1))));
            next == failing
        })
    }
}

/// Fully admitted immutable span sequence.
#[derive(Debug)]
pub struct AdmittedSpans {
    common: Common<SpanIteration>,
    spans: Vec<Span>,
}

/// Successfully admitted complete spans and their complete P/A attempt
/// receipt.
#[derive(Debug)]
pub struct AdmittedSpansAttempt {
    pub admitted: AdmittedSpans,
    pub receipt: OperationAttemptReceipt,
}

impl AdmittedSpans {
    #[must_use]
    pub fn iter(&self) -> SpanIter<'_> {
        SpanIter {
            inner: self.spans.iter(),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Span] {
        &self.spans
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

impl<'a> IntoIterator for &'a AdmittedSpans {
    type Item = Span;
    type IntoIter = SpanIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Pull iterator over a sequence whose complete operation was already
/// admitted. Pulling performs no regex work and cannot fail.
#[derive(Clone, Debug)]
pub struct SpanIter<'a> {
    inner: core::slice::Iter<'a, Span>,
}

impl Iterator for SpanIter<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SpanIter<'_> {}
impl core::iter::FusedIterator for SpanIter<'_> {}

/// Fully admitted count reducer.
#[derive(Debug)]
pub struct AdmittedCount {
    common: Common<MatchCount>,
    value: usize,
}

/// Successfully admitted diagnostic Count together with the same P/A attempt
/// receipt used for terminal failures.
#[derive(Debug)]
pub struct AdmittedCountAttempt {
    pub admitted: AdmittedCount,
    pub receipt: OperationAttemptReceipt,
}

/// Successfully evaluated value-only Count and its complete P/A receipt.
#[derive(Debug)]
pub struct CountValueAttempt {
    pub value: usize,
    pub receipt: OperationAttemptReceipt,
    authenticated_value: usize,
}

impl CountValueAttempt {
    /// Publish optional immutable structural counters after this value-only
    /// operation has completed. The hot loop has already finished; this
    /// projection cannot influence route selection or source consumption.
    pub fn into_counter_receipt(self) -> Result<OperationCounterReceipt, Error> {
        if self.value != self.authenticated_value
            || self.value != self.receipt.actual.emitted_matches
        {
            return Err(Error::InternalInvariant(
                "structural counter receipt Count value differs from its sealed terminal result",
            ));
        }
        OperationCounterReceipt::new(self.receipt, OperationCounterValue::Count(self.value))
    }
}

/// Successfully evaluated ordinary value-only Count with optional structural
/// counters published after the hot loop completes.
#[derive(Debug)]
pub struct CountValueCounterAttempt {
    pub value: usize,
    pub receipt: OperationHotCounterReceipt,
}

impl AdmittedCount {
    #[must_use]
    pub const fn value(&self) -> usize {
        self.value
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

/// Fully admitted checked matched-byte sum reducer.
#[derive(Debug)]
pub struct AdmittedSpanSum {
    common: Common<SpanSum>,
    value: usize,
}

/// Successfully admitted `SpanSum` and its complete P/A attempt receipt.
#[derive(Debug)]
pub struct AdmittedSpanSumAttempt {
    pub admitted: AdmittedSpanSum,
    pub receipt: OperationAttemptReceipt,
}

/// Successfully evaluated value-only `SpanSum` and its complete P/A receipt.
#[derive(Debug)]
pub struct SpanSumValueAttempt {
    pub value: usize,
    pub receipt: OperationAttemptReceipt,
    authenticated_value: usize,
}

impl SpanSumValueAttempt {
    /// Publish optional immutable structural counters after this value-only
    /// operation has completed. The hot loop has already finished; this
    /// projection cannot influence route selection or source consumption.
    pub fn into_counter_receipt(self) -> Result<OperationCounterReceipt, Error> {
        if self.value != self.authenticated_value {
            return Err(Error::InternalInvariant(
                "structural counter receipt SpanSum value differs from its sealed terminal result",
            ));
        }
        OperationCounterReceipt::new(self.receipt, OperationCounterValue::SpanSum(self.value))
    }
}

/// Successfully evaluated ordinary value-only `SpanSum` with optional
/// structural counters published after the hot loop completes.
#[derive(Debug)]
pub struct SpanSumValueCounterAttempt {
    pub value: usize,
    pub receipt: OperationHotCounterReceipt,
}

impl AdmittedSpanSum {
    #[must_use]
    pub const fn value(&self) -> usize {
        self.value
    }

    #[must_use]
    pub const fn certificate(&self) -> &OperationCertificate {
        &self.common.certificate
    }

    #[must_use]
    pub const fn accounting(&self) -> ExecutionAccounting {
        self.common.accounting
    }
}

impl CompiledRegex {
    /// Whether compilation retained the exact HIR-derived terminal-frontier
    /// proof required by the explicit receipt-bearing Count route.
    #[doc(hidden)]
    #[must_use]
    pub fn has_terminal_frontier(&self) -> bool {
        !self.terminal_frontier.is_empty()
    }

    /// Construction-selected bounded route for a receipt-bearing observed
    /// Count used by the uniform capture reducer.
    ///
    /// The result depends only on retained compiler proofs. Calling the
    /// corresponding forced entry point therefore cannot introduce a
    /// source-dependent fallback after the enclosing capture owner is sealed.
    #[doc(hidden)]
    #[must_use]
    pub fn uniform_capture_count_route(&self) -> OperationPhysicalRoute {
        let strong_fixed_candidate = self.minimum_match_bytes.is_some_and(|minimum| minimum > 1)
            && self.candidate.as_ref().is_some_and(|plan| {
                candidate::executable_for(&self.program)
                    && candidate::has_complete_shared_fixed_filter(plan)
            });
        if strong_fixed_candidate {
            // A complete fixed-prefix candidate proof is strictly more
            // selective than the retained terminal class frontier: it scans
            // the source once for at most three anchor bytes and verifies only
            // starts passing the entire eight-byte prefix. The proof, not the
            // source, determines this route before the capture owner is sealed.
            OperationPhysicalRoute::Candidate
        } else if self.program.start_domain.is_sparse() && candidate::executable_for(&self.program)
        {
            OperationPhysicalRoute::StartDomain
        } else if !self.terminal_frontier.is_empty() {
            OperationPhysicalRoute::TerminalFrontierRows
        } else if !self.required_suffixes.is_empty() {
            if self.minimum_match_bytes.is_some_and(|minimum| minimum > 1)
                && self.candidate.as_ref().is_some_and(|plan| {
                    plan.fixed_continuation().is_none() && candidate::executable_for(&self.program)
                })
            {
                OperationPhysicalRoute::Candidate
            } else {
                OperationPhysicalRoute::RequiredSuffixRows
            }
        } else {
            OperationPhysicalRoute::DenseRows
        }
    }

    /// Admit and evaluate a complete non-overlapping span sequence.
    pub fn admit_spans(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpans, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Spans, limits)?;
        Ok(AdmittedSpans {
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
            spans: result.spans,
        })
    }

    /// Admit and evaluate a complete non-overlapping span sequence while
    /// enforcing execution work against the exact observed charge. This
    /// retains the full certificate, accounting, and spans required by an
    /// enclosing reducer that must validate match-level invariants.
    pub fn admit_spans_observed(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpans, Error> {
        let result =
            self.execute::<true>(haystack, range, strategy, OperationKind::Spans, limits)?;
        Ok(AdmittedSpans {
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
            spans: result.spans,
        })
    }

    /// Admit observed-work spans through the bounded cached frontier only
    /// when its complete fixed initialization is clearly amortized by the
    /// generic dense continuation envelope. This source-independent route
    /// choice is intended for enclosing reducers that have already proved
    /// their own candidate-domain reduction.
    #[doc(hidden)]
    pub fn admit_spans_observed_cached_when_amortized(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpans, Error> {
        let use_cached = if strategy == Strategy::ReverseSequentialRows
            && range.start <= range.end
            && range.end <= haystack.len()
        {
            let input_bytes =
                range
                    .end
                    .checked_sub(range.start)
                    .ok_or(Error::InternalInvariant(
                        "validated cached span range reversed",
                    ))?;
            let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
            match Requirements::new::<true>(&self.program, boundaries, strategy, 2, limits) {
                Ok(dense) => {
                    cached_frontier_amortizes_dense(&self.program, boundaries, 2, limits, dense)?
                        .is_some()
                }
                Err(_) => false,
            }
        } else {
            false
        };
        let result = if use_cached {
            let mut accounting = ExecutionAccounting::default();
            let mut actual_allocations = 0_usize;
            self.execute_tracked::<true>(
                haystack,
                range,
                strategy,
                OperationKind::Spans,
                Some(GenericCountRoute::CachedFrontier),
                limits,
                &mut accounting,
                &mut actual_allocations,
                usize::MAX,
                None,
                None,
                None,
            )?
        } else {
            self.execute::<true>(haystack, range, strategy, OperationKind::Spans, limits)?
        };
        Ok(AdmittedSpans {
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
            spans: result.spans,
        })
    }

    /// Admit and evaluate the ordinary construction-selected continuation
    /// Spans route while retaining one complete success or terminal P/A
    /// receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_spans_with_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpansAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Spans,
            None,
            limits,
            usize::MAX,
            None,
        )?;
        Ok(AdmittedSpansAttempt {
            admitted: AdmittedSpans {
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
                spans: result.spans,
            },
            receipt,
        })
    }

    /// Admit and evaluate a complete match-count reduction.
    pub fn admit_count(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedCount, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Count, limits)?;
        Ok(AdmittedCount {
            value: result.summary.matches,
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
        })
    }

    /// Admit and evaluate the ordinary construction-selected continuation
    /// Count route while retaining one complete success or terminal P/A
    /// receipt. Unlike [`Self::admit_count_with_receipt`], this preserves
    /// construction-selected specialized and frontier routes.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_attempt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            None,
            limits,
            usize::MAX,
            None,
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Admit and evaluate a generic continuation count while retaining a
    /// complete failure attempt receipt. This entry point deliberately uses
    /// the shared continuation executor rather than an optional specialized
    /// count accelerator, so every terminal error shares one P/A ledger.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_with_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Dense),
            limits,
            usize::MAX,
            None,
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Forced-generic count attempt with an outer pre-source prospective
    /// observer. This is the narrow seam used by the fixed scalar composite.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_with_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Dense),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Forced-generic Count that requires and consumes the immutable
    /// terminal-frontier proof retained by compilation. The route has no
    /// dense or specialized fallback: an absent proof is refused before any
    /// source byte is inspected.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_with_terminal_frontier_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::TerminalFrontier),
            limits,
            usize::MAX,
            None,
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Terminal-frontier Count with the same pre-source prospective observer
    /// seam used by enclosing receipt-bearing reducers.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_with_terminal_frontier_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::TerminalFrontier),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Source- and allocation-free prospective for the exact dense generic
    /// route used by the fixed scalar composite observer seam.
    #[doc(hidden)]
    pub fn fixed_scalar_dense_count_prospective(
        &self,
        haystack_len: usize,
        strategy: Strategy,
    ) -> Result<OperationProspective, Error> {
        let prospective_limits = intrinsic_attempt_limits();
        let utf8_validation =
            preflight_unicode_word_utf8_bytes(&self.program, haystack_len, prospective_limits)?;
        let boundaries = add(haystack_len, 1, Resource::Boundaries)?;
        let mut engine_limits = prospective_limits;
        engine_limits.max_work = engine_limits.max_work.checked_sub(utf8_validation).ok_or(
            Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            },
        )?;
        engine_limits.max_sequential_bytes = engine_limits
            .max_sequential_bytes
            .checked_sub(utf8_validation)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::SequentialBytes,
            })?;
        let requirements =
            Requirements::new::<false>(&self.program, boundaries, strategy, 1, engine_limits)?
                .with_prefix::<false>(utf8_validation, utf8_validation, prospective_limits)?;
        requirements.operation_prospective(
            &self.program,
            boundaries,
            utf8_validation,
            RequiredLiteralScan::default(),
            OperationKind::Count,
            self.minimum_match_bytes,
        )
    }

    /// Admit and evaluate a complete checked matched-byte sum reduction.
    pub fn admit_span_sum(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpanSum, Error> {
        let result =
            self.execute::<false>(haystack, range, strategy, OperationKind::Sum, limits)?;
        Ok(AdmittedSpanSum {
            value: result.summary.span_sum,
            common: Common {
                certificate: result.certificate,
                accounting: result.accounting,
                marker: PhantomData,
            },
        })
    }

    /// Admit and evaluate the ordinary construction-selected continuation
    /// `SpanSum` route while retaining one complete success or terminal P/A
    /// receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_span_sum_with_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<AdmittedSpanSumAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<false>(
            haystack,
            range,
            strategy,
            OperationKind::Sum,
            None,
            limits,
            usize::MAX,
            None,
        )?;
        Ok(AdmittedSpanSumAttempt {
            admitted: AdmittedSpanSum {
                value: result.summary.span_sum,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Evaluate a complete match-count reduction while enforcing execution
    /// work against the exact observed charge instead of the conservative
    /// replay upper bound used by an admitted diagnostic result.
    pub fn count_value(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<usize, Error> {
        if strategy == Strategy::ReverseSequentialRows
            && let Some(assertion) = self.program.root_assertion()
        {
            return self.root_assertion_value(assertion, haystack, &range, limits);
        }
        if strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.state_byte_span_sum
            && let Some((matches, _)) = Self::state_byte_reducer_value(
                plan,
                haystack,
                &range,
                OperationKind::Count,
                limits,
            )?
        {
            return Ok(matches);
        }
        self.execute::<true>(haystack, range, strategy, OperationKind::Count, limits)
            .map(|result| result.summary.matches)
    }

    /// Attempt the reusable ordered-DFA continuation route for a value-only
    /// Count.
    ///
    /// `Ok(None)` is a source-free structural or fixed-resource refusal. An
    /// admitted call learns direct transitions in its caller workspace and
    /// enforces value work as observed, so it can return an exact resource
    /// error after source access. Cache saturation carries the current ordered
    /// frontier inline without rereading an earlier source position or
    /// restarting through the incumbent.
    #[doc(hidden)]
    pub fn count_value_with_sweep_workspace(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        workspace: &mut ContinuationSweepWorkspace,
    ) -> Result<Option<usize>, Error> {
        if !self.sweep_value_route_eligible(strategy) {
            return Ok(None);
        }
        let outcome = sweep::reduce_lazy(
            self.plan_id(),
            &self.program,
            haystack,
            range,
            SweepKind::Count,
            self.minimum_match_bytes,
            limits,
            workspace,
        )?;
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        let SweepOutcome::Complete(value) = outcome;
        Ok(Some(value.count))
    }

    /// Evaluate through the same ordinary value-only Count path as
    /// [`Self::count_value`] and publish structural counters only after that
    /// operation has completed. This does not make the selected route
    /// receipt-bearing and cannot alter its admission or fallback behavior.
    pub fn count_value_with_counters(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<CountValueCounterAttempt, Error> {
        let result =
            self.execute::<true>(haystack, range, strategy, OperationKind::Count, limits)?;
        let value = result.summary.matches;
        let receipt = OperationHotCounterReceipt::new(
            result.certificate,
            &result.accounting,
            OperationCounterValue::Count(value),
        )?;
        Ok(CountValueCounterAttempt { value, receipt })
    }

    /// Evaluate full-haystack Count through one caller-owned cached byte
    /// session and publish immutable structural counters after the hot
    /// operation succeeds.
    ///
    /// The session route never allocates and never switches to another
    /// executor. A saturated cache returns a typed refusal before reading the
    /// next haystack so an enclosing owner can perform its authenticated cold
    /// replay.
    pub fn count_value_with_cached_session_and_counters(
        &self,
        session: &mut CachedCountSession,
        haystack: &[u8],
        limits: OperationLimits,
    ) -> Result<CountValueCounterAttempt, Error> {
        let result = self.execute_with_cached_count_session(session, haystack, limits)?;
        let value = result.summary.matches;
        let receipt = OperationHotCounterReceipt::new(
            result.certificate,
            &result.accounting,
            OperationCounterValue::Count(value),
        )?;
        Ok(CountValueCounterAttempt { value, receipt })
    }

    /// Evaluate the ordinary construction-selected continuation Count route
    /// with observed-work admission and a complete P/A receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn count_value_attempt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<CountValueAttempt, OperationAttemptError> {
        self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            None,
            limits,
            usize::MAX,
            None,
        )
        .map(|(result, receipt)| {
            let value = result.summary.matches;
            CountValueAttempt {
                value,
                receipt,
                authenticated_value: value,
            }
        })
    }

    /// Evaluate a generic continuation count with observed-work admission
    /// while retaining a complete failure attempt receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn count_value_with_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<CountValueAttempt, OperationAttemptError> {
        self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Dense),
            limits,
            usize::MAX,
            None,
        )
        .map(|(result, receipt)| {
            let value = result.summary.matches;
            CountValueAttempt {
                value,
                receipt,
                authenticated_value: value,
            }
        })
    }

    /// Observed-work variant of the fixed scalar composite observer seam.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn count_value_with_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<CountValueAttempt, OperationAttemptError> {
        self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Dense),
            limits,
            allocation_limit,
            Some(&mut observer),
        )
        .map(|(result, receipt)| {
            let value = result.summary.matches;
            CountValueAttempt {
                value,
                receipt,
                authenticated_value: value,
            }
        })
    }

    /// Observed-work generic continuation count that retains the complete
    /// admitted result and P/A receipt for an enclosing receipt-bearing
    /// reducer.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Dense),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work generic continuation count forced onto the bounded
    /// cached-frontier representation. The caller must own a construction
    /// proof that selects this physical route before source access.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_cached_frontier_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::CachedFrontier),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work terminal-frontier Count with a complete admitted result,
    /// P/A receipt, and outer pre-source observer.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_terminal_frontier_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::TerminalFrontier),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work Count forced onto the compiler-retained required-suffix
    /// rows, with a complete admitted result, P/A receipt, and outer
    /// pre-source observer.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_required_suffix_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::RequiredSuffix),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work Count forced onto the compiler-retained candidate
    /// scheduler, with a complete admitted result, P/A receipt, and outer
    /// pre-source observer.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_candidate_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::Candidate),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work Count forced onto the compiler-retained start-domain
    /// executor, with a complete admitted result, P/A receipt, and outer
    /// pre-source observer.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_count_observed_with_start_domain_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::StartDomain),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Observed-work Count for a compiler-proved ordered root alternation,
    /// retaining the complete admitted result and nested P/A receipt.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn admit_ordered_root_count_observed_with_receipt_observer(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        allocation_limit: usize,
        mut observer: impl FnMut(OperationProspective) -> Result<(), Error>,
    ) -> Result<AdmittedCountAttempt, OperationAttemptError> {
        let (result, receipt) = self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Count,
            Some(GenericCountRoute::OrderedRoot),
            limits,
            allocation_limit,
            Some(&mut observer),
        )?;
        Ok(AdmittedCountAttempt {
            admitted: AdmittedCount {
                value: result.summary.matches,
                common: Common {
                    certificate: result.certificate,
                    accounting: result.accounting,
                    marker: PhantomData,
                },
            },
            receipt,
        })
    }

    /// Evaluate a complete checked matched-byte sum while enforcing execution
    /// work against the exact observed charge instead of the conservative
    /// replay upper bound used by an admitted diagnostic result.
    pub fn span_sum_value(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<usize, Error> {
        if strategy == Strategy::ReverseSequentialRows
            && let Some(assertion) = self.program.root_assertion()
        {
            self.root_assertion_value(assertion, haystack, &range, limits)?;
            return Ok(0);
        }
        if strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.state_byte_span_sum
            && let Some((_, span_sum)) =
                Self::state_byte_reducer_value(plan, haystack, &range, OperationKind::Sum, limits)?
        {
            return Ok(span_sum);
        }
        self.execute::<true>(haystack, range, strategy, OperationKind::Sum, limits)
            .map(|result| result.summary.span_sum)
    }

    /// Attempt the reusable ordered-DFA continuation route for a value-only
    /// matched-byte sum.
    ///
    /// See [`Self::count_value_with_sweep_workspace`] for the fixed-resource
    /// refusal, observed-work, and no-replay saturation contract.
    #[doc(hidden)]
    pub fn span_sum_value_with_sweep_workspace(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        workspace: &mut ContinuationSweepWorkspace,
    ) -> Result<Option<usize>, Error> {
        if !self.sweep_value_route_eligible(strategy) {
            return Ok(None);
        }
        let outcome = sweep::reduce_lazy(
            self.plan_id(),
            &self.program,
            haystack,
            range,
            SweepKind::SpanSum,
            self.minimum_match_bytes,
            limits,
            workspace,
        )?;
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        let SweepOutcome::Complete(value) = outcome;
        Ok(Some(value.span_sum))
    }

    /// Publish the fixed workspace envelope only when this compiled artifact
    /// can actually select the value-only continuation sweep.
    ///
    /// An arithmetic overflow in the optional fixed-arena calculation returns
    /// `Ok(None)` so an otherwise valid incumbent operation remains selectable.
    ///
    /// # Errors
    ///
    /// Returns a non-arithmetic internal error if the authenticated program
    /// dimensions cannot be projected.
    #[doc(hidden)]
    pub fn continuation_sweep_upper_bounds(
        &self,
        strategy: Strategy,
    ) -> Result<Option<crate::sweep::ContinuationSweepUpperBounds>, Error> {
        if !self.sweep_value_route_eligible(strategy) {
            return Ok(None);
        }
        match crate::sweep::continuation_sweep_upper_bounds_with_run(
            self.program.insts.len(),
            self.program.continuation_nonaccepting_run(),
            self.minimum_match_bytes,
        ) {
            Ok(bounds) => Ok(Some(bounds)),
            Err(Error::ArithmeticOverflow { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn sweep_value_route_eligible(&self, strategy: Strategy) -> bool {
        if strategy != Strategy::ReverseSequentialRows
            || self
                .minimum_match_bytes
                .is_none_or(|minimum| minimum == 0)
            || self.program.root_assertion().is_some()
            || self.program.contains_assertion()
            || self.program.contains_unicode_word_boundary()
            || self.program.start_domain.is_sparse()
            || self.required_internal_anchor.is_some()
            // A retained state/byte reducer is the incumbent value route for
            // both Count and SpanSum. It already executes one source pass
            // with fixed scalar state, so interposing a forward transition
            // cache (and a reverse cache for SpanSum) cannot reduce its
            // authenticated asymptotic work. Preserve that strictly cheaper
            // compiled route instead of allocating or consulting a sweep
            // workspace.
            || self.state_byte_span_sum.is_some()
            // A disjoint shared-fixed/global candidate retains two independent
            // mandatory byte domains: one source-wide scan can reject before
            // the fixed candidate scan or any program verification. Feeding
            // every byte through a DFA discards that construction theorem, so
            // preserve the candidate economics for both value reductions
            // without consulting or allocating a sweep workspace.
            || self.candidate.as_ref().is_some_and(|plan| {
                plan.fixed_continuation().is_none()
                    && candidate::executable_for(&self.program)
                    && candidate::has_disjoint_shared_fixed_global_filter(plan)
            })
            // The incumbent two-row byte kernel is already dense and cheap
            // for very small programs. Avoid a persistent DFA workspace and
            // its first-call determinization until the program is large
            // enough for direct indexed transitions to amortize that cost.
            || self.program.insts.len() <= 16
        {
            return false;
        }
        true
    }

    /// Evaluate through the same ordinary value-only `SpanSum` path as
    /// [`Self::span_sum_value`] and publish structural counters only after
    /// that operation has completed. This does not make the selected route
    /// receipt-bearing and cannot alter its admission or fallback behavior.
    pub fn span_sum_value_with_counters(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<SpanSumValueCounterAttempt, Error> {
        let result = self.execute::<true>(haystack, range, strategy, OperationKind::Sum, limits)?;
        let value = result.summary.span_sum;
        let receipt = OperationHotCounterReceipt::new(
            result.certificate,
            &result.accounting,
            OperationCounterValue::SpanSum(value),
        )?;
        Ok(SpanSumValueCounterAttempt { value, receipt })
    }

    /// Evaluate the ordinary construction-selected continuation `SpanSum` route
    /// with observed-work admission and a complete P/A receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the public failure deliberately retains the complete fixed-layout P/A receipt"
    )]
    pub fn span_sum_value_with_receipt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
    ) -> Result<SpanSumValueAttempt, OperationAttemptError> {
        self.execute_with_receipt::<true>(
            haystack,
            range,
            strategy,
            OperationKind::Sum,
            None,
            limits,
            usize::MAX,
            None,
        )
        .map(|(result, receipt)| {
            let value = result.summary.span_sum;
            SpanSumValueAttempt {
                value,
                receipt,
                authenticated_value: value,
            }
        })
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_arguments,
        reason = "the internal result preserves the complete fixed-layout P/A receipt for its public callers"
    )]
    fn execute_with_receipt<const OBSERVED_WORK: bool>(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        forced_generic_count_route: Option<GenericCountRoute>,
        limits: OperationLimits,
        allocation_limit: usize,
        prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<(ExecutionResult, OperationAttemptReceipt), OperationAttemptError> {
        let mut receipt = OperationAttemptReceipt {
            identity: OperationAttemptIdentity {
                regex_plan_id: self.plan_id(),
                operation_limits_id: operation_limits_identity(limits),
                strategy,
                operation: operation_attempt_kind(kind),
                work_mode: if OBSERVED_WORK {
                    OperationWorkMode::Observed
                } else {
                    OperationWorkMode::ConservativeAdmission
                },
                physical_route: None,
                algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
                accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
                prepublication_fallback: OperationPrepublicationFallback::None,
            },
            invocation: OperationInvocation {
                range: range.clone(),
                haystack_len: haystack.len(),
            },
            prospective: None,
            actual: ExecutionAccounting::default(),
            allocation_limit,
            actual_allocations: 0,
            authentication: None,
        };
        let result = {
            let publication = AttemptPublication {
                identity: &mut receipt.identity,
                prospective: &mut receipt.prospective,
            };
            self.execute_tracked::<OBSERVED_WORK>(
                haystack,
                range,
                strategy,
                kind,
                forced_generic_count_route,
                limits,
                &mut receipt.actual,
                &mut receipt.actual_allocations,
                allocation_limit,
                Some(publication),
                prospective_observer,
                None,
            )
        };
        match result {
            Ok(mut result) => {
                if let Some(prospective) = receipt.prospective.as_ref()
                    && let Err(source) = result
                        .certificate
                        .retain_published_prospective(prospective, receipt.actual_allocations)
                {
                    return Err(OperationAttemptError::new(source, receipt));
                }
                let valid = receipt.prospective.as_ref().is_some_and(|upper| {
                    (*upper).contains(receipt.actual)
                        && result.certificate.retains_published_prospective(upper)
                        && receipt.actual_allocations <= upper.allocations
                        && receipt.actual_allocations <= receipt.allocation_limit
                        && usize::from(result.certificate.actual_allocations)
                            == receipt.actual_allocations
                }) && receipt.identity.authenticates_limits(limits)
                    && result.certificate.authenticates_limits(limits)
                    && receipt.identity.operation_limits_id
                        == result.certificate.operation_limits_id
                    && receipt.identity.operation == result.certificate.operation
                    && receipt.identity.operation_id() == Some(result.certificate.operation_id())
                    && receipt.identity.physical_route == Some(result.certificate.physical_route)
                    && receipt.identity.algorithm_version == result.certificate.algorithm_version
                    && receipt.identity.accounting_version == result.certificate.accounting_version
                    && receipt.identity.prepublication_fallback
                        == result.certificate.prepublication_fallback;
                if !valid || receipt.actual != result.accounting {
                    return Err(OperationAttemptError::new(
                        Error::InternalInvariant(
                            "continuation success route or actual counters diverged from its prospective certificate",
                        ),
                        receipt,
                    ));
                }
                receipt.authenticate_terminal(OperationAttemptTerminalAuthentication::Success);
                Ok((result, receipt))
            }
            Err(mut source) => {
                if !receipt.identity.authenticates_limits(limits)
                    || receipt.prospective.is_some_and(|upper| {
                        !upper.contains(receipt.actual)
                            || receipt.actual_allocations > upper.allocations
                            || receipt.actual_allocations > receipt.allocation_limit
                    })
                {
                    source = Error::InternalInvariant(
                        "continuation attempt route or actual counters diverged from its prospective certificate",
                    );
                }
                Err(OperationAttemptError::new(source, receipt))
            }
        }
    }

    fn execute<const OBSERVED_WORK: bool>(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
    ) -> Result<ExecutionResult, Error> {
        let mut accounting = ExecutionAccounting::default();
        let mut actual_allocations = 0_usize;
        self.execute_tracked::<OBSERVED_WORK>(
            haystack,
            range,
            strategy,
            kind,
            None,
            limits,
            &mut accounting,
            &mut actual_allocations,
            usize::MAX,
            None,
            None,
            None,
        )
    }

    fn execute_with_cached_count_session(
        &self,
        session: &mut CachedCountSession,
        haystack: &[u8],
        limits: OperationLimits,
    ) -> Result<ExecutionResult, Error> {
        let mut accounting = ExecutionAccounting::default();
        let mut actual_allocations = 0_usize;
        self.execute_tracked::<true>(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationKind::Count,
            Some(GenericCountRoute::CachedFrontier),
            limits,
            &mut accounting,
            &mut actual_allocations,
            usize::MAX,
            None,
            None,
            Some(session),
        )
    }

    /// Evaluate the compiler-proved root assertion without materializing the
    /// receipt-only certificate and component accounting carried by
    /// [`ExecutionResult`]. The admission order and observed-work charges are
    /// the same as the ordinary non-receipt root-assertion route.
    fn root_assertion_value(
        &self,
        assertion: Assertion,
        haystack: &[u8],
        range: &Range<usize>,
        limits: OperationLimits,
    ) -> Result<usize, Error> {
        if range.start > range.end || range.end > haystack.len() {
            return Err(Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            });
        }
        let input_bytes = range
            .end
            .checked_sub(range.start)
            .ok_or(Error::InternalInvariant(
                "validated root-assertion range underflow",
            ))?;
        let envelope =
            root_assertion_envelope::<true>(assertion, haystack.len(), input_bytes, limits)?;

        // Keep the ordinary malformed-UTF-8 precedence: validation admission
        // and the complete validation read precede the remaining prospective
        // envelope.
        let preflight = preflight_unicode_word_utf8_bytes(&self.program, haystack.len(), limits)?;
        if preflight != envelope.utf8_validation {
            return Err(Error::InternalInvariant(
                "root-assertion UTF-8 preflight diverged from retained assertion",
            ));
        }
        enforce(
            envelope.utf8_validation,
            envelope.work_bound,
            Resource::ExecutionWork,
        )?;
        if envelope.utf8_validation != 0 && core::str::from_utf8(haystack).is_err() {
            return Err(Error::InvalidUtf8ForUnicodeWordBoundary);
        }

        // This is `OperationProspective::enforce_limits` in the same field
        // order, specialized to the zero-allocation root-assertion envelope.
        enforce(
            envelope.boundaries,
            limits.max_boundaries,
            Resource::Boundaries,
        )?;
        enforce(0, limits.max_table_cells, Resource::TableCells)?;
        enforce(
            envelope.random_access_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(0, limits.max_scratch_bytes, Resource::ScratchBytes)?;
        enforce(0, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            envelope.utf8_validation,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(
            envelope.boundaries,
            limits.max_match_events,
            Resource::MatchEvents,
        )?;
        enforce(
            envelope.boundaries,
            limits.max_output_matches,
            Resource::OutputMatches,
        )?;
        enforce(0, limits.max_output_bytes, Resource::OutputBytes)?;
        enforce(0, limits.max_span_sum, Resource::SpanSum)?;
        enforce(0, limits.max_peak_bytes, Resource::PeakBytes)?;
        enforce(
            envelope.work_bound,
            limits.max_work,
            Resource::ExecutionWork,
        )?;

        let assertions = AssertionContext::new(haystack, range.start, input_bytes)?;
        let mut work = envelope.utf8_validation;
        let mut matches = 0_usize;
        for position in 0..=input_bytes {
            try_charge_value_work(&mut work, envelope.work_bound)?;
            try_charge_value_work(&mut work, envelope.work_bound)?;
            if assertions.is_match(assertion, position)? {
                try_charge_value_work(&mut work, envelope.work_bound)?;
                matches = add(matches, 1, Resource::MatchEvents)?;
            }
        }
        enforce(work, limits.max_work, Resource::ExecutionWork)?;
        Ok(matches)
    }

    /// Evaluate a compiler-proved state-byte reduction while retaining only
    /// the scalar values needed by the ordinary Count/`SpanSum` APIs.
    fn state_byte_reducer_value(
        plan: &StateByteSpanSumPlan,
        haystack: &[u8],
        range: &Range<usize>,
        kind: OperationKind,
        limits: OperationLimits,
    ) -> Result<Option<(usize, usize)>, Error> {
        if range.start > range.end || range.end > haystack.len() {
            return Err(Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            });
        }
        let local = &haystack[range.clone()];
        if plan.topology() == StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair
            && !local.is_ascii()
        {
            return Ok(None);
        }
        let envelope = state_byte_reducer_envelope::<true>(plan, local.len(), limits)?;
        enforce(
            envelope.boundaries,
            limits.max_boundaries,
            Resource::Boundaries,
        )?;
        enforce(0, limits.max_table_cells, Resource::TableCells)?;
        enforce(
            0,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(0, limits.max_scratch_bytes, Resource::ScratchBytes)?;
        enforce(0, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            envelope.sequential_bytes_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(local.len(), limits.max_match_events, Resource::MatchEvents)?;
        enforce(
            local.len(),
            limits.max_output_matches,
            Resource::OutputMatches,
        )?;
        enforce(0, limits.max_output_bytes, Resource::OutputBytes)?;
        enforce(
            if kind == OperationKind::Sum {
                local.len()
            } else {
                0
            },
            limits.max_span_sum,
            Resource::SpanSum,
        )?;
        enforce(0, limits.max_peak_bytes, Resource::PeakBytes)?;
        enforce(
            envelope.work_bound,
            limits.max_work,
            Resource::ExecutionWork,
        )?;
        if envelope.structural_work_bound > limits.max_work {
            return Ok(None);
        }

        // Once the complete structural work envelope fits, no individual
        // charge can refuse. The value-only route can therefore monomorphize
        // the shared reducer against a zero-sized meter while receipt and
        // counter callers retain exact component accounting.
        let mut accounting = StateByteValueMeter;
        let (matches, span_sum) = match plan.topology() {
            StateByteSpanSumTopology::GreedyPrefixLiteralSuffix => {
                reduce_greedy_prefix_literal_suffix_value(
                    plan,
                    local,
                    envelope.work_bound,
                    &mut accounting,
                )?
            }
            StateByteSpanSumTopology::DisjointRunsLiteral => {
                reduce_disjoint_runs_literal(plan, local, envelope.work_bound, &mut accounting)?
            }
            StateByteSpanSumTopology::DisjointInternalRuns
            | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => {
                reduce_disjoint_internal_runs(plan, local, envelope.work_bound, &mut accounting)?
            }
            StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
                reduce_repeated_lazy_delimiter_suffix(
                    plan,
                    local,
                    envelope.work_bound,
                    &mut accounting,
                )?
            }
            StateByteSpanSumTopology::BoundedLiteralPair
            | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
                reduce_ascii_bounded_literal_pair(
                    plan,
                    local,
                    envelope.work_bound,
                    &mut accounting,
                )?
            }
        };
        Ok(Some((matches, span_sum)))
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the certified route receives the shared publication and accounting state explicitly"
    )]
    fn execute_state_byte_reducer<const OBSERVED_WORK: bool>(
        &self,
        plan: &StateByteSpanSumPlan,
        local: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let prospective = state_byte_reducer_prospective::<OBSERVED_WORK>(
            &self.program,
            plan,
            local.len(),
            kind,
            limits,
        )?;
        if let Some(publication) = attempt.as_mut() {
            let physical_route = OperationPhysicalRoute::StateByteSpanSum;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
        }
        enforce(
            prospective.allocations,
            allocation_limit,
            Resource::Allocations,
        )?;
        prospective.enforce_limits(limits)?;

        // The complete input-only envelope is now admitted. The compact
        // executor owns no allocation and publishes no fallback after source
        // access begins.
        *actual_allocations = 0;
        let (matches, span_sum) = match plan.topology() {
            StateByteSpanSumTopology::GreedyPrefixLiteralSuffix => {
                reduce_greedy_prefix_literal_suffix(
                    plan,
                    local,
                    prospective.work_bound,
                    attempt_accounting,
                )?
            }
            StateByteSpanSumTopology::DisjointRunsLiteral => reduce_disjoint_runs_literal(
                plan,
                local,
                prospective.work_bound,
                attempt_accounting,
            )?,
            StateByteSpanSumTopology::DisjointInternalRuns
            | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => {
                reduce_disjoint_internal_runs(
                    plan,
                    local,
                    prospective.work_bound,
                    attempt_accounting,
                )?
            }
            StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
                reduce_repeated_lazy_delimiter_suffix(
                    plan,
                    local,
                    prospective.work_bound,
                    attempt_accounting,
                )?
            }
            StateByteSpanSumTopology::BoundedLiteralPair
            | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
                reduce_ascii_bounded_literal_pair(
                    plan,
                    local,
                    prospective.work_bound,
                    attempt_accounting,
                )?
            }
        };
        validate_admitted_work(attempt_accounting, prospective.work_bound, limits.max_work)?;
        if !prospective.contains(*attempt_accounting) {
            return Err(Error::InternalInvariant(
                "state-byte reducer actual accounting exceeds its prospective",
            ));
        }
        let span_sum = if kind == OperationKind::Sum {
            span_sum
        } else {
            0
        };
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::StateByteSpanSum,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: 0,
            actual_allocations: 0,
            range,
            states: prospective.states,
            table_cells: prospective.table_cells,
            row_storage: prospective.row_storage,
            row_record_bytes: prospective.row_record_bytes,
            terminal_frontier: prospective.terminal_frontier,
            work_bound: prospective.work_bound,
            random_access_bytes: prospective.random_access_bytes,
            scratch_bytes: prospective.scratch_bytes,
            log_bytes: prospective.log_bytes,
            sequential_bytes_bound: prospective.sequential_bytes,
            match_events: prospective.match_events,
            output_matches: prospective.output_matches,
            output_bytes: prospective.output_bytes,
            span_sum: prospective.span_sum,
            peak_bytes: prospective.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: *attempt_accounting,
            summary: ScanSummary {
                matches,
                events: matches,
                suppressed: 0,
                span_sum,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the certified route receives the shared publication and accounting state explicitly"
    )]
    fn execute_root_assertion<const OBSERVED_WORK: bool>(
        &self,
        assertion: Assertion,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let input_bytes = range
            .end
            .checked_sub(range.start)
            .ok_or(Error::InternalInvariant(
                "validated root-assertion range underflow",
            ))?;
        let prospective = root_assertion_prospective::<OBSERVED_WORK>(
            &self.program,
            assertion,
            haystack.len(),
            input_bytes,
            limits,
        )?;
        let receipt_bearing = attempt.is_some();
        if let Some(publication) = attempt.as_mut() {
            publication.identity.physical_route = Some(OperationPhysicalRoute::RootAssertion);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
        }
        let utf8_validation = if assertion.is_unicode_word() {
            haystack.len()
        } else {
            0
        };
        if !receipt_bearing {
            // Preserve the ordinary continuation's established malformed
            // UTF-8 precedence: preflight only validation work/source bytes,
            // read and validate the complete haystack, and then enforce the
            // remaining operation envelope.
            let preflight =
                preflight_unicode_word_utf8_bytes(&self.program, haystack.len(), limits)?;
            if preflight != utf8_validation {
                return Err(Error::InternalInvariant(
                    "root-assertion UTF-8 preflight diverged from retained assertion",
                ));
            }
            enforce(
                utf8_validation,
                prospective.work_bound,
                Resource::ExecutionWork,
            )?;
            validate_unicode_word_utf8(haystack, utf8_validation, attempt_accounting)?;
        }
        enforce(
            prospective.allocations,
            allocation_limit,
            Resource::Allocations,
        )?;
        prospective.enforce_limits(limits)?;

        // Route and complete input-only envelope are fixed. No source-aware
        // fallback is permitted beyond this point.
        *actual_allocations = 0;
        if receipt_bearing {
            enforce(
                utf8_validation,
                prospective.work_bound,
                Resource::ExecutionWork,
            )?;
            validate_unicode_word_utf8(haystack, utf8_validation, attempt_accounting)?;
        }

        let assertions = AssertionContext::new(haystack, range.start, input_bytes)?;
        let mut matches = 0_usize;
        for position in 0..=input_bytes {
            try_charge_root(attempt_accounting, prospective.work_bound)?;
            try_charge_assertion(attempt_accounting, prospective.work_bound)?;
            if assertion_matches(assertions, assertion, position, attempt_accounting, true)? {
                try_charge_event(attempt_accounting, prospective.work_bound)?;
                matches = add(matches, 1, Resource::MatchEvents)?;
                attempt_accounting.emitted_matches = add(
                    attempt_accounting.emitted_matches,
                    1,
                    Resource::OutputMatches,
                )?;
            }
        }
        validate_admitted_work(attempt_accounting, prospective.work_bound, limits.max_work)?;
        if !prospective.contains(*attempt_accounting) {
            return Err(Error::InternalInvariant(
                "root-assertion actual accounting exceeds its prospective",
            ));
        }
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::RootAssertion,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: 0,
            actual_allocations: 0,
            range,
            states: prospective.states,
            table_cells: prospective.table_cells,
            row_storage: prospective.row_storage,
            row_record_bytes: prospective.row_record_bytes,
            terminal_frontier: prospective.terminal_frontier,
            work_bound: prospective.work_bound,
            random_access_bytes: prospective.random_access_bytes,
            scratch_bytes: prospective.scratch_bytes,
            log_bytes: prospective.log_bytes,
            sequential_bytes_bound: prospective.sequential_bytes,
            match_events: prospective.match_events,
            output_matches: prospective.output_matches,
            output_bytes: prospective.output_bytes,
            span_sum: prospective.span_sum,
            peak_bytes: prospective.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: *attempt_accounting,
            summary: ScanSummary {
                matches,
                events: matches,
                suppressed: 0,
                span_sum: 0,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "whole-operation admission keeps failure-before-publication ordering auditable"
    )]
    fn execute_tracked<const OBSERVED_WORK: bool>(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        forced_generic_count_route: Option<GenericCountRoute>,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut attempt: Option<AttemptPublication<'_>>,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
        session: Option<&mut CachedCountSession>,
    ) -> Result<ExecutionResult, Error> {
        if range.start > range.end || range.end > haystack.len() {
            return Err(Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            });
        }
        let session_cache = if let Some(session) = session {
            session.validate(self, haystack.len(), limits)?;
            if range.start != 0
                || range.end != haystack.len()
                || strategy != Strategy::ReverseSequentialRows
                || kind != OperationKind::Count
                || forced_generic_count_route != Some(GenericCountRoute::CachedFrontier)
            {
                return Err(Error::InternalInvariant(
                    "cached Count session requires full-range observed Count",
                ));
            }
            if session.cache.saturated {
                return Err(Error::SessionCacheSaturated);
            }
            Some(&mut session.cache)
        } else {
            None
        };
        let session_cache_active = session_cache.is_some();
        match forced_generic_count_route {
            Some(_)
                if (kind != OperationKind::Count
                    && !(kind == OperationKind::Spans
                        && attempt.is_none()
                        && forced_generic_count_route
                            == Some(GenericCountRoute::CachedFrontier)))
                    || (attempt.is_none()
                        && !(session_cache_active
                            && forced_generic_count_route
                                == Some(GenericCountRoute::CachedFrontier))
                        && kind == OperationKind::Count) =>
            {
                return Err(Error::InternalInvariant(
                    "forced generic route requires its authenticated operation boundary",
                ));
            }
            Some(GenericCountRoute::TerminalFrontier)
                if strategy != Strategy::ReverseSequentialRows =>
            {
                return Err(Error::InternalInvariant(
                    "terminal-frontier Count requires reverse sequential rows",
                ));
            }
            Some(GenericCountRoute::CachedFrontier)
                if !OBSERVED_WORK || strategy != Strategy::ReverseSequentialRows =>
            {
                return Err(Error::InternalInvariant(
                    "cached-frontier Count requires observed reverse sequential rows",
                ));
            }
            Some(GenericCountRoute::TerminalFrontier) if self.terminal_frontier.is_empty() => {
                return Err(Error::InternalInvariant(
                    "terminal-frontier Count requires its compiled HIR proof",
                ));
            }
            Some(GenericCountRoute::RequiredSuffix)
                if strategy != Strategy::ReverseSequentialRows
                    || self.required_suffixes.is_empty() =>
            {
                return Err(Error::InternalInvariant(
                    "required-suffix Count requires its compiled HIR proof and reverse rows",
                ));
            }
            Some(GenericCountRoute::Candidate)
                if !OBSERVED_WORK
                    || strategy != Strategy::ReverseSequentialRows
                    || self
                        .candidate
                        .as_ref()
                        .is_none_or(|plan| plan.fixed_continuation().is_some())
                    || !candidate::executable_for(&self.program) =>
            {
                return Err(Error::InternalInvariant(
                    "candidate Count requires its compiled HIR proof and observed reverse execution",
                ));
            }
            Some(GenericCountRoute::StartDomain)
                if !OBSERVED_WORK
                    || strategy != Strategy::ReverseSequentialRows
                    || !self.program.start_domain.is_sparse()
                    || !candidate::executable_for(&self.program) =>
            {
                return Err(Error::InternalInvariant(
                    "start-domain Count requires its compiled HIR proof and observed reverse execution",
                ));
            }
            Some(GenericCountRoute::OrderedRoot)
                if strategy != Strategy::ReverseSequentialRows
                    || self.program.root_alternation_arms() < 2
                    || self.program.root_split_count().checked_add(1)
                        != Some(self.program.root_alternation_arms()) =>
            {
                return Err(Error::InternalInvariant(
                    "ordered-root Count requires its compiled root proof",
                ));
            }
            Some(_) | None => {}
        }
        let local = &haystack[range.clone()];
        if forced_generic_count_route.is_none()
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && let Some(assertion) = self.program.root_assertion()
        {
            return self.execute_root_assertion::<OBSERVED_WORK>(
                assertion,
                haystack,
                range,
                strategy,
                kind,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        if forced_generic_count_route.is_none()
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.state_byte_span_sum
            // The Unicode bounded-pair theorem is intentionally value-only:
            // its ASCII/non-ASCII choice is source dependent. Receipt-bearing
            // operations keep the incumbent continuation so publication
            // never falls back after inspecting source bytes.
            && plan.topology() != StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair
        {
            return self.execute_state_byte_reducer::<OBSERVED_WORK>(
                plan,
                local,
                range,
                strategy,
                kind,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        if forced_generic_count_route.is_none()
            && kind == OperationKind::Sum
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.ordered_bounded_span_sum
        {
            return self.execute_ordered_bounded_span_sum(
                plan,
                local,
                ordered_bounded_span_sum::RouteInvocation {
                    range,
                    strategy,
                    limits,
                    allocation_limit,
                },
                ordered_bounded_span_sum::RouteEffects {
                    attempt: attempt.as_mut(),
                    accounting,
                    actual_allocations,
                    prospective_observer,
                },
            );
        }
        if matches!(
            forced_generic_count_route,
            None | Some(GenericCountRoute::StartDomain)
        ) && OBSERVED_WORK
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && self.program.start_domain.is_sparse()
            && candidate::executable_for(&self.program)
        {
            return self.execute_start_domain(
                haystack,
                range,
                strategy,
                kind,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        if forced_generic_count_route.is_none()
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.url_aggregate
        {
            return self.execute_url_aggregate(
                plan,
                local,
                range,
                strategy,
                kind,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        if forced_generic_count_route.is_none()
            && kind == OperationKind::Count
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.required_internal_anchor
        {
            return self.execute_required_internal_anchor(
                plan,
                local,
                range,
                strategy,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        if forced_generic_count_route.is_none()
            && OBSERVED_WORK
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && self.terminal_frontier.is_empty()
            && self.required_suffixes.is_empty()
            && let Some(plan) = &self.candidate
            && let Some(fixed) = plan.fixed_continuation()
        {
            let boundaries = add(local.len(), 1, Resource::Boundaries)?;
            let candidate_work =
                candidate::fixed_continuation_upper(fixed, local.len(), boundaries)?.work;
            let dense_work_floor = dense_reduction_work_floor(&self.program, boundaries)?;
            // The candidate quantity is a complete source-independent upper
            // bound. The dense quantity is the unavoidable construction and
            // scan work, excluding only optional replay. Publish the
            // specialized route only when its worst case strictly beats that
            // generic floor; equality and every unproved shape retain the
            // generic continuation without a post-publication fallback.
            if fixed_continuation_beats_dense(candidate_work, dense_work_floor) {
                return self.execute_fixed_continuation_candidate::<OBSERVED_WORK>(
                    fixed,
                    local,
                    range,
                    strategy,
                    kind,
                    limits,
                    attempt.as_mut(),
                    accounting,
                    actual_allocations,
                    allocation_limit,
                    prospective_observer,
                );
            }
        }
        if matches!(
            forced_generic_count_route,
            None | Some(GenericCountRoute::Candidate)
        ) && OBSERVED_WORK
            && matches!(kind, OperationKind::Count | OperationKind::Sum)
            && strategy == Strategy::ReverseSequentialRows
            && let Some(plan) = &self.candidate
            && plan.fixed_continuation().is_none()
            && candidate::executable_for(&self.program)
        {
            return self.execute_candidate(
                plan,
                haystack,
                range,
                strategy,
                kind,
                limits,
                attempt.as_mut(),
                accounting,
                actual_allocations,
                allocation_limit,
                prospective_observer,
            );
        }
        let receipt_bearing = attempt.is_some();
        let force_intrinsic_dense = prospective_observer.is_some()
            && forced_generic_count_route == Some(GenericCountRoute::Dense);
        let prospective_limits = if receipt_bearing {
            intrinsic_attempt_limits()
        } else {
            limits
        };
        let utf8_validation =
            preflight_unicode_word_utf8_bytes(&self.program, haystack.len(), prospective_limits)?;
        // Value reducers use observed-work execution without a full attempt
        // receipt. Keep their negative census enabled independently of
        // `receipt_bearing`; admitted diagnostic paths retain their existing
        // accounting unless they explicitly requested a receipt.
        let required_literal_scan_enabled = (OBSERVED_WORK || receipt_bearing)
            && forced_generic_count_route.is_none()
            && strategy == Strategy::ReverseSequentialRows
            && !self.required_literals.is_empty();
        let required_literal_scan = if required_literal_scan_enabled {
            RequiredLiteralScan::prospective(local.len(), self.required_literals)?
        } else {
            RequiredLiteralScan::default()
        };
        let required_literal_work = required_literal_scan.work()?;
        let prefix_work = add(
            utf8_validation,
            required_literal_work,
            Resource::ExecutionWork,
        )?;
        let prefix_sequential_bytes = add(
            utf8_validation,
            required_literal_scan.source_bytes,
            Resource::SequentialBytes,
        )?;
        if !receipt_bearing {
            // Preserve the incumbent continuation's established refusal
            // ordering. Only the new receipt-bearing entry point delays this
            // source read until after P is published and every represented
            // caller limit has admitted it.
            validate_unicode_word_utf8(haystack, utf8_validation, accounting)?;
        }
        let mut engine_limits = prospective_limits;
        engine_limits.max_work =
            engine_limits
                .max_work
                .checked_sub(prefix_work)
                .ok_or(Error::ArithmeticOverflow {
                    resource: Resource::ExecutionWork,
                })?;
        engine_limits.max_sequential_bytes = engine_limits
            .max_sequential_bytes
            .checked_sub(prefix_sequential_bytes)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::SequentialBytes,
            })?;
        let mut selection_limits = limits;
        if receipt_bearing {
            // Selection predicates may observe the caller's remaining budget,
            // but they cannot reject before the selected route publishes P.
            selection_limits.max_work = selection_limits.max_work.saturating_sub(prefix_work);
            selection_limits.max_sequential_bytes = selection_limits
                .max_sequential_bytes
                .saturating_sub(prefix_sequential_bytes);
        } else {
            selection_limits = engine_limits;
        }
        let assertion_context = AssertionContext::new(haystack, range.start, local.len())?;
        let boundaries = add(local.len(), 1, Resource::Boundaries)?;
        enforce(
            boundaries,
            prospective_limits.max_boundaries,
            Resource::Boundaries,
        )?;
        let passes = if kind == OperationKind::Spans { 2 } else { 1 };
        let terminal_seed = match forced_generic_count_route {
            Some(GenericCountRoute::TerminalFrontier) => {
                Some(SparseSeed::TerminalFrontier(&self.terminal_frontier))
            }
            None if strategy == Strategy::ReverseSequentialRows
                && !self.terminal_frontier.is_empty() =>
            {
                Some(SparseSeed::TerminalFrontier(&self.terminal_frontier))
            }
            Some(
                GenericCountRoute::CachedFrontier
                | GenericCountRoute::Dense
                | GenericCountRoute::StartDomain
                | GenericCountRoute::OrderedRoot
                | GenericCountRoute::RequiredSuffix
                | GenericCountRoute::Candidate,
            )
            | None => None,
        };
        let fallback_seed = if forced_generic_count_route == Some(GenericCountRoute::RequiredSuffix)
        {
            Some(SparseSeed::RequiredSuffixes(&self.required_suffixes))
        } else if forced_generic_count_route.is_some() || self.required_suffixes.is_empty() {
            None
        } else {
            Some(SparseSeed::RequiredSuffixes(&self.required_suffixes))
        };
        let prefer_unicode_suffix_domains = forced_generic_count_route.is_none()
            && strategy == Strategy::ReverseSequentialRows
            && self.required_suffixes.prefers_sparse_verification();
        // Automatic Unicode suffix verification owns a deterministic sparse
        // route. Derive its construction envelope from intrinsic engine
        // limits so a caller storage policy cannot reject before route and P
        // publish. Sparse observed work is different: its exact construction
        // ledger is deliberately capped by the caller's residual work quota,
        // so preserve that one selection input instead of publishing the
        // intrinsic `usize::MAX` ceiling as P.
        let unicode_suffix_limits = OperationLimits {
            max_work: selection_limits.max_work,
            ..engine_limits
        };
        let dense = || {
            Requirements::new::<OBSERVED_WORK>(
                &self.program,
                boundaries,
                strategy,
                passes,
                engine_limits,
            )
        };
        let (requirements, sparse_seed) = if forced_generic_count_route
            == Some(GenericCountRoute::CachedFrontier)
        {
            (
                if session_cache_active {
                    Requirements::new_session_cached(
                        &self.program,
                        boundaries,
                        passes,
                        engine_limits,
                    )?
                } else {
                    Requirements::new_forced_cached(
                        &self.program,
                        boundaries,
                        passes,
                        engine_limits,
                    )?
                },
                None,
            )
        } else if forced_generic_count_route == Some(GenericCountRoute::OrderedRoot) {
            (
                Requirements::new_ordered_root::<OBSERVED_WORK>(
                    &self.program,
                    boundaries,
                    strategy,
                    passes,
                    engine_limits,
                )?,
                None,
            )
        } else if forced_generic_count_route == Some(GenericCountRoute::TerminalFrontier) {
            let seed = terminal_seed.ok_or(Error::InternalInvariant(
                "terminal-frontier Count lost its compiled HIR proof",
            ))?;
            let SparseSeed::TerminalFrontier(seed) = seed else {
                return Err(Error::InternalInvariant(
                    "terminal-frontier Count proof changed route",
                ));
            };
            (
                Requirements::new_terminal_frontier_prospective(
                    &self.program,
                    boundaries,
                    strategy,
                    passes,
                    seed,
                )?,
                Some(SparseSeed::TerminalFrontier(seed)),
            )
        } else if forced_generic_count_route == Some(GenericCountRoute::RequiredSuffix) {
            let seed = fallback_seed.ok_or(Error::InternalInvariant(
                "required-suffix Count lost its compiled HIR proof",
            ))?;
            (
                Requirements::new_for_seed(
                    &self.program,
                    boundaries,
                    strategy,
                    passes,
                    engine_limits,
                    seed,
                )?,
                Some(seed),
            )
        } else if prefer_unicode_suffix_domains {
            let seed = fallback_seed.ok_or(Error::InternalInvariant(
                "Unicode suffix-domain verification lost its compiled HIR proof",
            ))?;
            (
                Requirements::new_for_seed(
                    &self.program,
                    boundaries,
                    strategy,
                    passes,
                    unicode_suffix_limits,
                    seed,
                )?,
                Some(seed),
            )
        } else if receipt_bearing && forced_generic_count_route == Some(GenericCountRoute::Dense) {
            let dense = dense()?;
            if !force_intrinsic_dense
                && OBSERVED_WORK
                && dense.work_bound > selection_limits.max_work
                && strategy == Strategy::ReverseSequentialRows
            {
                (
                    Requirements::cached(&self.program, boundaries, passes, selection_limits)?
                        .unwrap_or(dense),
                    None,
                )
            } else {
                (dense, None)
            }
        } else if receipt_bearing {
            if let Some(seed) = terminal_seed {
                (
                    Requirements::new_for_seed(
                        &self.program,
                        boundaries,
                        strategy,
                        passes,
                        engine_limits,
                        seed,
                    )?,
                    Some(seed),
                )
            } else {
                let dense = dense()?;
                if dense.work_bound > selection_limits.max_work
                    && strategy == Strategy::ReverseSequentialRows
                {
                    if let Some(seed) = fallback_seed {
                        (
                            Requirements::new_for_seed(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                engine_limits,
                                seed,
                            )?,
                            Some(seed),
                        )
                    } else {
                        (
                            Requirements::cached(
                                &self.program,
                                boundaries,
                                passes,
                                selection_limits,
                            )?
                            .unwrap_or(dense),
                            None,
                        )
                    }
                } else {
                    (dense, None)
                }
            }
        } else if let Some(seed) = terminal_seed {
            let dense = dense();
            match Requirements::new_for_seed(
                &self.program,
                boundaries,
                strategy,
                passes,
                engine_limits,
                seed,
            ) {
                Ok(requirements) => (requirements, Some(seed)),
                Err(terminal_error) => match dense {
                    Ok(requirements)
                        if !OBSERVED_WORK || requirements.work_bound <= engine_limits.max_work =>
                    {
                        (requirements, None)
                    }
                    Ok(_) | Err(_) => return Err(terminal_error),
                },
            }
        } else {
            let dense = dense();
            match dense {
                Ok(requirements)
                    if OBSERVED_WORK
                        && requirements.work_bound > selection_limits.max_work
                        && strategy == Strategy::ReverseSequentialRows =>
                {
                    if let Some(seed) = fallback_seed {
                        (
                            Requirements::new_for_seed(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                selection_limits,
                                seed,
                            )?,
                            Some(seed),
                        )
                    } else {
                        (
                            Requirements::new_cached::<OBSERVED_WORK>(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                selection_limits,
                            )?,
                            None,
                        )
                    }
                }
                Ok(requirements) => (requirements, None),
                Err(
                    error @ Error::ResourceLimit {
                        resource: Resource::ExecutionWork,
                        ..
                    },
                ) if strategy == Strategy::ReverseSequentialRows => {
                    if let Some(seed) = fallback_seed {
                        (
                            Requirements::new_for_seed(
                                &self.program,
                                boundaries,
                                strategy,
                                passes,
                                selection_limits,
                                seed,
                            )?,
                            Some(seed),
                        )
                    } else {
                        (
                            Requirements::new_cached_after_refusal(
                                error,
                                &self.program,
                                boundaries,
                                passes,
                                selection_limits,
                            )?,
                            None,
                        )
                    }
                }
                Err(error) => return Err(error),
            }
        };
        let mut requirements = requirements.with_prefix::<OBSERVED_WORK>(
            prefix_work,
            prefix_sequential_bytes,
            prospective_limits,
        )?;
        // Capture the complete structural proof before receipt publication
        // clamps P to the caller's observed-work ceiling. After that clamp,
        // comparing P to the caller limit cannot distinguish full admission
        // from an intentionally partial observed execution.
        let fully_admitted_work = !OBSERVED_WORK || requirements.work_bound <= limits.max_work;
        if receipt_bearing && OBSERVED_WORK {
            // Every receipt-bearing observed route executes against the same
            // work ceiling it publishes. This includes sparse, terminal, and
            // cached builders whose internal meters use `Requirements`
            // directly rather than the generic per-charge caller argument.
            //
            // UTF-8 validation and the required-literal census are mandatory
            // pre-engine prefixes. Preserve them in P even when the caller
            // cannot admit them, so every represented limit refuses before
            // either prefix reads source bytes.
            let engine_work = requirements.work_bound.checked_sub(prefix_work).ok_or(
                Error::InternalInvariant("operation work prefix exceeds its prospective total"),
            )?;
            let caller_engine_work = limits.max_work.saturating_sub(prefix_work);
            let mandatory_engine_work = requirements
                .frontier
                .map_or(0, terminal_frontier::FrontierRequirements::minimum_work);
            let admitted_engine_work = if caller_engine_work < mandatory_engine_work {
                // A selected terminal frontier has a fixed minimum census.
                // Retain that mandatory amount in P so a lower caller refuses
                // before any source access or allocation.
                mandatory_engine_work
            } else {
                engine_work.min(caller_engine_work)
            };
            if let Some(frontier) = requirements.frontier {
                requirements.frontier =
                    Some(frontier.with_observed_work_limit(admitted_engine_work));
            }
            requirements.work_bound =
                add(prefix_work, admitted_engine_work, Resource::ExecutionWork)?;
        }
        let prepublication_fallback = if forced_generic_count_route.is_some() {
            OperationPrepublicationFallback::None
        } else if terminal_seed.is_some() {
            OperationPrepublicationFallback::TerminalFrontierThenDense
        } else if prefer_unicode_suffix_domains {
            OperationPrepublicationFallback::None
        } else if fallback_seed.is_some() {
            OperationPrepublicationFallback::DenseThenRequiredSuffix
        } else if strategy == Strategy::ReverseSequentialRows {
            OperationPrepublicationFallback::DenseThenCachedFrontier
        } else {
            OperationPrepublicationFallback::None
        };
        let physical_route = if forced_generic_count_route == Some(GenericCountRoute::OrderedRoot) {
            OperationPhysicalRoute::OrderedRootRows
        } else if requirements.terminal_frontier {
            OperationPhysicalRoute::TerminalFrontierRows
        } else if requirements.cached_frontier.is_some() {
            OperationPhysicalRoute::CachedFrontier
        } else if matches!(sparse_seed, Some(SparseSeed::RequiredSuffixes(_))) {
            OperationPhysicalRoute::RequiredSuffixRows
        } else {
            OperationPhysicalRoute::DenseRows
        };
        if let Some(publication) = attempt.as_mut() {
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = prepublication_fallback;
            let prospective = requirements.operation_prospective(
                &self.program,
                boundaries,
                utf8_validation,
                required_literal_scan,
                kind,
                self.minimum_match_bytes,
            )?;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
            enforce(
                prospective.allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            prospective.enforce_limits(limits)?;
        }
        if receipt_bearing {
            validate_unicode_word_utf8(haystack, utf8_validation, accounting)?;
        }
        if required_literal_scan_enabled {
            let observed = scan_required_literals(self, local, accounting)?;
            if !observed.all_present {
                validate_admitted_work(accounting, requirements.work_bound, limits.max_work)?;
                let certificate = OperationCertificate {
                    regex_plan_id: self.plan_id(),
                    operation_limits_id: operation_limits_identity(limits),
                    strategy,
                    operation: operation_attempt_kind(kind),
                    physical_route,
                    algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
                    accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
                    prepublication_fallback,
                    prospective_allocations: compact_operation_allocation_count(
                        requirements.operation_allocation_bound(kind)?,
                    )?,
                    actual_allocations: 0,
                    range,
                    states: self.program.insts.len(),
                    table_cells: requirements.table_cells,
                    row_storage: requirements.row_storage,
                    row_record_bytes: requirements.record_bytes,
                    terminal_frontier: requirements.terminal_frontier,
                    work_bound: requirements.work_bound,
                    random_access_bytes: 0,
                    scratch_bytes: 0,
                    log_bytes: 0,
                    sequential_bytes_bound: requirements.sequential_bound,
                    match_events: 0,
                    output_matches: 0,
                    output_bytes: 0,
                    span_sum: 0,
                    peak_bytes: 0,
                };
                return Ok(ExecutionResult {
                    certificate,
                    accounting: *accounting,
                    summary: ScanSummary::empty(),
                    spans: Vec::new(),
                });
            }
        }
        let mut engine = if forced_generic_count_route == Some(GenericCountRoute::OrderedRoot) {
            Engine::build_ordered_root::<OBSERVED_WORK>(
                &self.program,
                local,
                assertion_context,
                strategy,
                requirements,
                limits,
                receipt_bearing,
                fully_admitted_work,
                accounting,
                actual_allocations,
            )?
        } else {
            Engine::build::<OBSERVED_WORK>(
                &self.program,
                local,
                assertion_context,
                strategy,
                requirements,
                sparse_seed,
                limits,
                receipt_bearing,
                fully_admitted_work,
                session_cache,
                accounting,
                actual_allocations,
            )?
        };
        let summary = engine.scan::<OBSERVED_WORK>(
            &self.program,
            local,
            assertion_context,
            requirements.work_bound,
            limits.max_work,
            receipt_bearing,
            accounting,
            |_| Ok(()),
        )?;
        enforce(
            summary.events,
            limits.max_match_events,
            Resource::MatchEvents,
        )?;
        enforce(
            summary.matches,
            limits.max_output_matches,
            Resource::OutputMatches,
        )?;
        if kind == OperationKind::Sum {
            enforce(summary.span_sum, limits.max_span_sum, Resource::SpanSum)?;
        }
        let requested_output_bytes = if kind == OperationKind::Spans {
            mul(
                summary.matches,
                core::mem::size_of::<Span>(),
                Resource::OutputBytes,
            )?
        } else {
            0
        };
        enforce(
            requested_output_bytes,
            limits.max_output_bytes,
            Resource::OutputBytes,
        )?;
        let requested_peak = engine.peak_with_output(requested_output_bytes)?;
        enforce(requested_peak, limits.max_peak_bytes, Resource::PeakBytes)?;
        let mut spans = Vec::new();
        if kind == OperationKind::Spans {
            let requested_allocations = (*actual_allocations)
                .checked_add(usize::from(summary.matches != 0))
                .ok_or(Error::ArithmeticOverflow {
                    resource: Resource::Allocations,
                })?;
            enforce(
                requested_allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            spans
                .try_reserve_exact(summary.matches)
                .map_err(|_| Error::AllocationFailed {
                    resource: Resource::OutputBytes,
                    items: summary.matches,
                })?;
            record_allocation(actual_allocations, spans.capacity())?;
            let allocated_output_bytes = mul(
                spans.capacity(),
                core::mem::size_of::<Span>(),
                Resource::OutputBytes,
            )?;
            enforce(
                allocated_output_bytes,
                limits.max_output_bytes,
                Resource::OutputBytes,
            )?;
            let allocated_peak = engine.peak_with_output(allocated_output_bytes)?;
            enforce(allocated_peak, limits.max_peak_bytes, Resource::PeakBytes)?;
            let repeated = engine.scan::<OBSERVED_WORK>(
                &self.program,
                local,
                assertion_context,
                requirements.work_bound,
                limits.max_work,
                receipt_bearing,
                accounting,
                |span| {
                    spans.push(span);
                    Ok(())
                },
            )?;
            if repeated != summary || spans.len() != summary.matches {
                return Err(Error::InternalInvariant(
                    "second admitted replay changed the match sequence",
                ));
            }
            accounting.output_bytes = allocated_output_bytes;
            accounting.peak_bytes = allocated_peak;
        } else {
            accounting.peak_bytes = engine.peak_with_output(0)?;
        }
        validate_admitted_work(accounting, requirements.work_bound, limits.max_work)?;
        accounting.emitted_matches = summary.matches;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback,
            prospective_allocations: compact_operation_allocation_count(
                requirements.operation_allocation_bound(kind)?,
            )?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: requirements.table_cells,
            row_storage: requirements.row_storage,
            row_record_bytes: requirements.record_bytes,
            terminal_frontier: requirements.terminal_frontier,
            work_bound: requirements.work_bound,
            random_access_bytes: accounting.random_access_peak_bytes,
            scratch_bytes: accounting.scratch_peak_bytes,
            log_bytes: accounting.log_bytes,
            sequential_bytes_bound: requirements.sequential_bound,
            match_events: summary.events,
            output_matches: summary.matches,
            output_bytes: accounting.output_bytes,
            span_sum: summary.span_sum,
            peak_bytes: accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: *accounting,
            summary,
            spans,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the specialized route keeps publication, admission, execution, and terminal accounting in one auditable closure boundary"
    )]
    fn execute_url_aggregate(
        &self,
        plan: &UrlAggregatePlan,
        local: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let upper = UrlAggregatePlan::reduce_upper_bounds(local.len())
            .map_err(|error| map_url_reduce_error(&error))?;
        let boundaries = upper.boundaries;
        if let Some(publication) = attempt.as_mut() {
            let prospective =
                url_aggregate_prospective(&self.program, upper, kind, limits.max_work);
            let physical_route = OperationPhysicalRoute::UrlAggregate;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
            enforce(
                prospective.allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            prospective.enforce_limits(limits)?;
        } else {
            enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
        }
        let result = match plan.span_sum_attempt(
            local,
            0..local.len(),
            UrlAggregateReduceLimits {
                max_input_bytes: local.len(),
                max_boundaries: limits.max_boundaries,
                max_candidates: limits.max_work,
                max_match_events: limits.max_match_events,
                max_output_matches: limits.max_output_matches,
                max_span_sum: if kind == OperationKind::Sum {
                    limits.max_span_sum
                } else {
                    usize::MAX
                },
                max_sequential_bytes: limits.max_sequential_bytes,
                max_random_access_bytes: usize::MAX,
                max_random_access_storage_bytes: limits.max_random_access_bytes,
                max_work: limits.max_work,
                max_scratch_bytes: limits.max_scratch_bytes,
                max_peak_bytes: limits.max_peak_bytes,
            },
        ) {
            Ok(result) => result,
            Err(failure) => {
                *attempt_accounting = url_aggregate_execution_accounting(failure.accounting);
                *actual_allocations = failure.actual_allocations;
                return Err(map_url_reduce_error(&failure.source));
            }
        };
        let actual = result.accounting;
        let accounting = url_aggregate_execution_accounting(actual);
        *attempt_accounting = accounting;
        *actual_allocations = usize::from(upper.candidate_records != 0);
        let span_sum = if kind == OperationKind::Sum {
            result.value
        } else {
            0
        };
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::UrlAggregate,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: compact_operation_allocation_count(usize::from(
                upper.candidate_records != 0,
            ))?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: actual.work,
            random_access_bytes: actual.random_access_storage_bytes,
            scratch_bytes: actual.scratch_bytes,
            log_bytes: 0,
            sequential_bytes_bound: actual.sequential_bytes,
            match_events: result.matches,
            output_matches: result.matches,
            output_bytes: 0,
            span_sum,
            peak_bytes: actual.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting,
            summary: ScanSummary {
                matches: result.matches,
                events: result.matches,
                suppressed: 0,
                span_sum,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the specialized route receives the shared attempt publication and accounting state explicitly"
    )]
    fn execute_start_domain(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let input_bytes = range
            .end
            .checked_sub(range.start)
            .ok_or(Error::InternalInvariant(
                "start-domain range reversed before execution",
            ))?;
        let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
        if let Some(publication) = attempt.as_mut() {
            let prospective = start_domain_prospective(&self.program, boundaries, kind, limits)?;
            let physical_route = OperationPhysicalRoute::StartDomain;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
            enforce(
                prospective.allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            prospective.enforce_limits(limits)?;
        }
        let result = match candidate::start_domain_attempt(
            &self.program,
            haystack,
            range.clone(),
            self.program.start_domain,
            kind == OperationKind::Sum,
            limits,
        ) {
            Ok(result) => result,
            Err(failure) => {
                *attempt_accounting = failure.accounting;
                *actual_allocations = failure.actual_allocations;
                return Err(failure.source);
            }
        };
        *attempt_accounting = result.accounting;
        *actual_allocations = result.actual_allocations;
        let span_sum = if kind == OperationKind::Sum {
            result.span_sum
        } else {
            0
        };
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::StartDomain,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: compact_operation_allocation_count(
                candidate::START_DOMAIN_EXECUTION_ALLOCATIONS,
            )?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: limits.max_work,
            random_access_bytes: result.accounting.random_access_peak_bytes,
            scratch_bytes: result.accounting.scratch_peak_bytes,
            log_bytes: 0,
            sequential_bytes_bound: 0,
            match_events: result.events,
            output_matches: result.matches,
            output_bytes: 0,
            span_sum,
            peak_bytes: result.accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: result.accounting,
            summary: ScanSummary {
                matches: result.matches,
                events: result.events,
                suppressed: result.suppressed,
                span_sum,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the specialized route receives the shared attempt publication and accounting state explicitly"
    )]
    fn execute_required_internal_anchor(
        &self,
        plan: &RequiredInternalAnchorPlan,
        local: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let prospective_limits = if attempt.is_some() {
            intrinsic_attempt_limits()
        } else {
            limits
        };
        let (boundaries, upper) =
            preflight_required_internal_anchor(plan, local.len(), prospective_limits)?;
        if let Some(publication) = attempt.as_mut() {
            let prospective =
                required_internal_anchor_prospective(&self.program, boundaries, upper)?;
            let physical_route = OperationPhysicalRoute::RequiredInternalAnchor;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
            enforce(
                prospective.allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            prospective.enforce_limits(limits)?;
        }
        let result = match plan.count_attempt(local, exact_required_anchor_limits(upper, limits)) {
            Ok(result) => result,
            Err(failure) => {
                *actual_allocations = failure.actual.allocations;
                *attempt_accounting =
                    required_internal_anchor_execution_accounting(failure.actual)?;
                return Err(map_required_anchor_error(&failure.source));
            }
        };
        let matches = usize::try_from(result.count).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::OutputMatches,
        })?;
        let actual = result.accounting.actual;
        let accounting = required_internal_anchor_execution_accounting(actual)?;
        *attempt_accounting = accounting;
        *actual_allocations = actual.allocations;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: OperationAttemptKind::Count,
            physical_route: OperationPhysicalRoute::RequiredInternalAnchor,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: compact_operation_allocation_count(upper.allocations)?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: upper.work,
            random_access_bytes: upper.random_access_bytes,
            scratch_bytes: 0,
            log_bytes: 0,
            sequential_bytes_bound: upper.sequential_bytes,
            match_events: matches,
            output_matches: matches,
            output_bytes: 0,
            span_sum: 0,
            peak_bytes: upper.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting,
            summary: ScanSummary {
                matches,
                events: matches,
                suppressed: 0,
                span_sum: 0,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the specialized route receives the shared attempt publication and accounting state explicitly"
    )]
    fn execute_candidate(
        &self,
        plan: &candidate::Plan,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let boundaries = add(
            range
                .end
                .checked_sub(range.start)
                .ok_or(Error::InternalInvariant("candidate range reversed"))?,
            1,
            Resource::Boundaries,
        )?;
        if let Some(publication) = attempt.as_mut() {
            let input_bytes =
                range
                    .end
                    .checked_sub(range.start)
                    .ok_or(Error::InternalInvariant(
                        "candidate range reversed before publication",
                    ))?;
            let prospective =
                candidate_prospective(plan, &self.program, input_bytes, boundaries, kind, limits)?;
            let physical_route = OperationPhysicalRoute::Candidate;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
            enforce(
                prospective.allocations,
                allocation_limit,
                Resource::Allocations,
            )?;
            prospective.enforce_limits(limits)?;
        }
        let reduction = match kind {
            OperationKind::Count => candidate::ReductionKind::Count,
            OperationKind::Sum => candidate::ReductionKind::SpanSum,
            OperationKind::Spans => {
                return Err(Error::InternalInvariant(
                    "candidate reducer cannot materialize spans",
                ));
            }
        };
        let result = match candidate::reduce_attempt(
            reduction,
            plan,
            &self.program,
            haystack,
            range.clone(),
            limits,
        ) {
            Ok(result) => result,
            Err(failure) => {
                *attempt_accounting = failure.accounting;
                *actual_allocations = failure.actual_allocations;
                return Err(failure.source);
            }
        };
        *attempt_accounting = result.accounting;
        *actual_allocations = CANDIDATE_EXECUTION_ALLOCATIONS;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::Candidate,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: compact_operation_allocation_count(
                CANDIDATE_EXECUTION_ALLOCATIONS,
            )?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: result.accounting.work,
            random_access_bytes: result.accounting.random_access_peak_bytes,
            scratch_bytes: result.accounting.scratch_peak_bytes,
            log_bytes: 0,
            sequential_bytes_bound: result.accounting.sequential_bytes_read,
            match_events: result.matches,
            output_matches: result.matches,
            output_bytes: 0,
            span_sum: result.span_sum,
            peak_bytes: result.accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: result.accounting,
            summary: ScanSummary {
                matches: result.matches,
                events: result.matches,
                suppressed: 0,
                span_sum: result.span_sum,
            },
            spans: Vec::new(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the cost-selected proof route receives publication and terminal ledgers explicitly"
    )]
    fn execute_fixed_continuation_candidate<const OBSERVED_WORK: bool>(
        &self,
        plan: &candidate::FixedContinuation,
        local: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        kind: OperationKind,
        limits: OperationLimits,
        mut attempt: Option<&mut AttemptPublication<'_>>,
        attempt_accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        allocation_limit: usize,
        mut prospective_observer: Option<&mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
    ) -> Result<ExecutionResult, Error> {
        let boundaries = add(local.len(), 1, Resource::Boundaries)?;
        let mut prospective = fixed_continuation_candidate_prospective(
            plan,
            &self.program,
            local.len(),
            boundaries,
            kind,
        )?;
        if attempt.is_some() && OBSERVED_WORK {
            prospective.work_bound = prospective.work_bound.min(limits.max_work);
            prospective.accounting.work = prospective.work_bound;
        }
        if let Some(publication) = attempt.as_mut() {
            publication.identity.physical_route = Some(OperationPhysicalRoute::Candidate);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
            *publication.prospective = Some(prospective);
            if let Some(observer) = prospective_observer.as_mut() {
                observer(prospective)?;
            }
        }
        enforce(
            candidate::FIXED_CONTINUATION_EXECUTION_ALLOCATIONS,
            allocation_limit,
            Resource::Allocations,
        )?;
        if attempt.is_some() {
            prospective.enforce_limits(limits)?;
        }
        let reduction = match kind {
            OperationKind::Count => candidate::ReductionKind::Count,
            OperationKind::Sum => candidate::ReductionKind::SpanSum,
            OperationKind::Spans => {
                return Err(Error::InternalInvariant(
                    "fixed-continuation candidate cannot materialize spans",
                ));
            }
        };
        let result = match candidate::reduce_fixed_continuation_attempt(
            reduction,
            plan,
            local,
            0..local.len(),
            limits,
        ) {
            Ok(result) => result,
            Err(failure) => {
                *attempt_accounting = failure.accounting;
                *actual_allocations = failure.actual_allocations;
                return Err(failure.source);
            }
        };
        *attempt_accounting = result.accounting;
        *actual_allocations = candidate::FIXED_CONTINUATION_EXECUTION_ALLOCATIONS;
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(limits),
            strategy,
            operation: operation_attempt_kind(kind),
            physical_route: OperationPhysicalRoute::Candidate,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: compact_operation_allocation_count(
                candidate::FIXED_CONTINUATION_EXECUTION_ALLOCATIONS,
            )?,
            actual_allocations: compact_operation_allocation_count(*actual_allocations)?,
            range,
            states: self.program.insts.len(),
            table_cells: 0,
            row_storage: None,
            row_record_bytes: 0,
            terminal_frontier: false,
            work_bound: result.accounting.work,
            random_access_bytes: result.accounting.random_access_peak_bytes,
            scratch_bytes: result.accounting.scratch_peak_bytes,
            log_bytes: 0,
            sequential_bytes_bound: result.accounting.sequential_bytes_read,
            match_events: result.candidates,
            output_matches: result.matches,
            output_bytes: 0,
            span_sum: result.span_sum,
            peak_bytes: result.accounting.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: result.accounting,
            summary: ScanSummary {
                matches: result.matches,
                events: result.matches,
                suppressed: 0,
                span_sum: result.span_sum,
            },
            spans: Vec::new(),
        })
    }
}

fn dense_reduction_work_floor(program: &Program, boundaries: usize) -> Result<usize, Error> {
    let per_boundary = add(
        program.execution_state_work(),
        usize::from(program.contains_scalar_transition()),
        Resource::ExecutionWork,
    )?;
    let build = mul(per_boundary, boundaries, Resource::ExecutionWork)?;
    let scan = mul(boundaries, 4, Resource::ExecutionWork)?;
    add(build, scan, Resource::ExecutionWork)
}

// Cached rows pay a fixed, source-independent initialization before their
// first transition hit. Do not speculate on a marginal win: select them
// proactively only when that complete fixed cost occupies at most one eighth
// of the already-admitted dense work envelope. The cached executor remains
// bounded by the same caller policy and retains its exact observed-work
// accounting; this gate only avoids making cache success depend on an
// artificially low caller work limit.
const CACHED_FRONTIER_DENSE_AMORTIZATION: usize = 8;

fn cached_frontier_amortizes_dense(
    program: &Program,
    boundaries: usize,
    passes: usize,
    limits: OperationLimits,
    dense: Requirements,
) -> Result<Option<Requirements>, Error> {
    let Some(cached) = Requirements::cached(program, boundaries, passes, limits)? else {
        return Ok(None);
    };
    let initialization = cached
        .cached_frontier
        .ok_or(Error::InternalInvariant(
            "cached requirements lost their frontier shape",
        ))?
        .initialization_work()?;
    let amortized = mul(
        initialization,
        CACHED_FRONTIER_DENSE_AMORTIZATION,
        Resource::ExecutionWork,
    )?;
    Ok((amortized < dense.work_bound).then_some(cached))
}

const fn fixed_continuation_beats_dense(
    candidate_work_upper: usize,
    dense_work_floor: usize,
) -> bool {
    candidate_work_upper < dense_work_floor
}

fn root_assertion_envelope<const OBSERVED_WORK: bool>(
    assertion: Assertion,
    haystack_bytes: usize,
    input_bytes: usize,
    limits: OperationLimits,
) -> Result<RootAssertionEnvelope, Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    let utf8_validation = if assertion.is_unicode_word() {
        haystack_bytes
    } else {
        0
    };
    // One root probe and one assertion transition are charged at every
    // operation boundary. Every successful zero-width path adds one event.
    let boundary_work = mul(boundaries, 3, Resource::ExecutionWork)?;
    let structural_work_bound = add(utf8_validation, boundary_work, Resource::ExecutionWork)?;
    let work_bound = if OBSERVED_WORK {
        structural_work_bound.min(limits.max_work)
    } else {
        structural_work_bound
    };
    let source_factor = match assertion {
        Assertion::StartText | Assertion::EndText => 0,
        Assertion::StartLf
        | Assertion::EndLf
        | Assertion::WordStartHalfAscii
        | Assertion::WordEndHalfAscii => 1,
        Assertion::StartCrlf
        | Assertion::EndCrlf
        | Assertion::WordAscii
        | Assertion::WordAsciiNegate
        | Assertion::WordStartAscii
        | Assertion::WordEndAscii => 2,
        Assertion::WordUnicode
        | Assertion::WordUnicodeNegate
        | Assertion::WordStartUnicode
        | Assertion::WordEndUnicode
        | Assertion::WordStartHalfUnicode
        | Assertion::WordEndHalfUnicode => 8,
    };
    let random_access_bytes = mul(boundaries, source_factor, Resource::RandomAccessBytes)?;
    Ok(RootAssertionEnvelope {
        boundaries,
        utf8_validation,
        work_bound,
        random_access_bytes,
    })
}

#[derive(Clone, Copy)]
struct RootAssertionEnvelope {
    boundaries: usize,
    utf8_validation: usize,
    work_bound: usize,
    random_access_bytes: usize,
}

fn root_assertion_prospective<const OBSERVED_WORK: bool>(
    program: &Program,
    assertion: Assertion,
    haystack_bytes: usize,
    input_bytes: usize,
    limits: OperationLimits,
) -> Result<OperationProspective, Error> {
    let envelope =
        root_assertion_envelope::<OBSERVED_WORK>(assertion, haystack_bytes, input_bytes, limits)?;
    let accounting = ExecutionAccounting {
        transition_checks: envelope.boundaries.min(envelope.work_bound),
        assertion_checks: envelope.boundaries.min(envelope.work_bound),
        root_probes: envelope.boundaries.min(envelope.work_bound),
        successful_paths: envelope.boundaries.min(envelope.work_bound),
        emitted_matches: envelope.boundaries.min(envelope.work_bound),
        utf8_validation_work: envelope.utf8_validation.min(envelope.work_bound),
        sequential_bytes_read: envelope.utf8_validation,
        random_access_bytes_read: envelope.random_access_bytes,
        work: envelope.work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries: envelope.boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound: envelope.work_bound,
        random_access_bytes: envelope.random_access_bytes,
        scratch_bytes: 0,
        log_bytes: 0,
        sequential_bytes: envelope.utf8_validation,
        match_events: envelope.boundaries,
        output_matches: envelope.boundaries,
        output_bytes: 0,
        span_sum: 0,
        allocations: 0,
        peak_bytes: 0,
        accounting,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the prospective keeps every topology's complete resource envelope adjacent"
)]
fn state_byte_reducer_envelope<const OBSERVED_WORK: bool>(
    plan: &StateByteSpanSumPlan,
    input_bytes: usize,
    limits: OperationLimits,
) -> Result<StateByteReducerEnvelope, Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    let work_factor = match plan.topology() {
        StateByteSpanSumTopology::GreedyPrefixLiteralSuffix => 6,
        StateByteSpanSumTopology::DisjointRunsLiteral => {
            if plan.literal().len() > 1 {
                add(
                    mul(plan.literal().len(), 2, Resource::ExecutionWork)?,
                    12,
                    Resource::ExecutionWork,
                )?
            } else {
                add(plan.literal().len(), 7, Resource::ExecutionWork)?
            }
        }
        StateByteSpanSumTopology::DisjointInternalRuns
        | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => 12,
        StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
            add(plan.literal().len(), 4, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::BoundedLiteralPair
        | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
            let (left, right) = plan.bounded_pair_anchors().ok_or(Error::InternalInvariant(
                "state-byte bounded-pair plan lost its anchors",
            ))?;
            let literal_max = left.len().max(right.len());
            add(
                mul(
                    add(literal_max, 1, Resource::ExecutionWork)?,
                    4,
                    Resource::ExecutionWork,
                )?,
                6,
                Resource::ExecutionWork,
            )?
        }
    };
    let structural_work_bound = mul(input_bytes, work_factor, Resource::ExecutionWork)?;
    let work_bound = if OBSERVED_WORK {
        structural_work_bound.min(limits.max_work)
    } else {
        structural_work_bound
    };
    let state_transition_factor = match plan.topology() {
        StateByteSpanSumTopology::DisjointRunsLiteral if plan.literal().len() > 1 => 4,
        StateByteSpanSumTopology::DisjointInternalRuns
        | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => 4,
        StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => 0,
        StateByteSpanSumTopology::BoundedLiteralPair
        | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => 2,
        _ => 2,
    };
    let state_transition_bound = mul(
        input_bytes,
        state_transition_factor,
        Resource::ExecutionWork,
    )?;
    let root_probe_bound = match plan.topology() {
        StateByteSpanSumTopology::DisjointRunsLiteral => {
            let factor = if plan.literal().len() > 1 {
                add(plan.literal().len(), 1, Resource::ExecutionWork)?
            } else {
                plan.literal().len()
            };
            mul(input_bytes, factor, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::GreedyPrefixLiteralSuffix
        | StateByteSpanSumTopology::DisjointInternalRuns
        | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => {
            mul(input_bytes, 2, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
            let factor = add(plan.literal().len(), 3, Resource::ExecutionWork)?;
            mul(input_bytes, factor, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::BoundedLiteralPair
        | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
            let (left, right) = plan.bounded_pair_anchors().ok_or(Error::InternalInvariant(
                "state-byte bounded-pair plan lost its anchors",
            ))?;
            let factor = mul(
                add(left.len().max(right.len()), 1, Resource::ExecutionWork)?,
                4,
                Resource::ExecutionWork,
            )?;
            mul(input_bytes, factor, Resource::ExecutionWork)?
        }
    };
    let random_access_bytes_read = match plan.topology() {
        StateByteSpanSumTopology::GreedyPrefixLiteralSuffix => input_bytes,
        StateByteSpanSumTopology::DisjointRunsLiteral => {
            let factor = if plan.literal().len() > 1 {
                add(plan.literal().len(), 3, Resource::ExecutionWork)?
            } else {
                add(plan.literal().len(), 1, Resource::ExecutionWork)?
            };
            mul(input_bytes, factor, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::DisjointInternalRuns
        | StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => {
            mul(input_bytes, 4, Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
            mul(input_bytes, plan.literal().len(), Resource::ExecutionWork)?
        }
        StateByteSpanSumTopology::BoundedLiteralPair
        | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
            mul(input_bytes, 2, Resource::ExecutionWork)?
        }
    };
    let sequential_bytes_bound = match plan.topology() {
        StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix => {
            let factor = add(plan.literal().len(), 1, Resource::SequentialBytes)?;
            mul(input_bytes, factor, Resource::SequentialBytes)?
        }
        StateByteSpanSumTopology::BoundedLiteralPair
        | StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair => {
            let (left, right) = plan.bounded_pair_anchors().ok_or(Error::InternalInvariant(
                "state-byte bounded-pair plan lost its anchors",
            ))?;
            let literal_scans = mul(
                add(left.len().max(right.len()), 1, Resource::SequentialBytes)?,
                4,
                Resource::SequentialBytes,
            )?;
            mul(
                input_bytes,
                add(literal_scans, 1, Resource::SequentialBytes)?,
                Resource::SequentialBytes,
            )?
        }
        _ => input_bytes,
    };
    Ok(StateByteReducerEnvelope {
        boundaries,
        structural_work_bound,
        work_bound,
        state_transition_bound,
        root_probe_bound,
        random_access_bytes_read,
        sequential_bytes_bound,
    })
}

#[derive(Clone, Copy)]
struct StateByteReducerEnvelope {
    boundaries: usize,
    structural_work_bound: usize,
    work_bound: usize,
    state_transition_bound: usize,
    root_probe_bound: usize,
    random_access_bytes_read: usize,
    sequential_bytes_bound: usize,
}

fn state_byte_reducer_prospective<const OBSERVED_WORK: bool>(
    program: &Program,
    plan: &StateByteSpanSumPlan,
    input_bytes: usize,
    kind: OperationKind,
    limits: OperationLimits,
) -> Result<OperationProspective, Error> {
    let envelope = state_byte_reducer_envelope::<OBSERVED_WORK>(plan, input_bytes, limits)?;
    let accounting = ExecutionAccounting {
        state_evaluations: envelope.state_transition_bound.min(envelope.work_bound),
        transition_checks: envelope.state_transition_bound.min(envelope.work_bound),
        root_probes: envelope.root_probe_bound.min(envelope.work_bound),
        successful_paths: input_bytes.min(envelope.work_bound),
        emitted_matches: input_bytes.min(envelope.work_bound),
        sequential_bytes_read: envelope.sequential_bytes_bound.min(envelope.work_bound),
        random_access_bytes_read: envelope.random_access_bytes_read.min(envelope.work_bound),
        work: envelope.work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries: envelope.boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound: envelope.work_bound,
        random_access_bytes: 0,
        scratch_bytes: 0,
        log_bytes: 0,
        sequential_bytes: envelope.sequential_bytes_bound,
        match_events: input_bytes,
        output_matches: input_bytes,
        output_bytes: 0,
        span_sum: if kind == OperationKind::Sum {
            input_bytes
        } else {
            0
        },
        allocations: 0,
        peak_bytes: 0,
        accounting,
    })
}

trait StateByteMeter {
    fn work(&self) -> usize;

    fn record_scan(
        &mut self,
        scanned: usize,
        work_limit: usize,
        transactional: bool,
    ) -> Result<(), Error>;

    fn classify(
        &mut self,
        class: crate::program::ByteSet,
        haystack: &[u8],
        index: usize,
        access: StateByteSourceAccess,
        work_limit: usize,
    ) -> Result<StateByteClassification, Error>;

    fn compare_source(
        &mut self,
        haystack: &[u8],
        index: usize,
        expected: u8,
        work_limit: usize,
    ) -> Result<bool, Error>;

    fn compare_cached(&mut self, byte: u8, expected: u8, work_limit: usize) -> Result<bool, Error>;

    fn event(&mut self, work_limit: usize) -> Result<(), Error>;
}

impl StateByteMeter for ExecutionAccounting {
    fn work(&self) -> usize {
        self.work
    }

    fn record_scan(
        &mut self,
        scanned: usize,
        work_limit: usize,
        transactional: bool,
    ) -> Result<(), Error> {
        if transactional {
            let sequential_bytes_read = add(
                self.sequential_bytes_read,
                scanned,
                Resource::SequentialBytes,
            )?;
            let root_probes = add(self.root_probes, scanned, Resource::ExecutionWork)?;
            let work = add(self.work, scanned, Resource::ExecutionWork)?;
            enforce(work, work_limit, Resource::ExecutionWork)?;
            self.sequential_bytes_read = sequential_bytes_read;
            self.root_probes = root_probes;
            self.work = work;
        } else {
            self.sequential_bytes_read = add(
                self.sequential_bytes_read,
                scanned,
                Resource::SequentialBytes,
            )?;
            self.root_probes = add(self.root_probes, scanned, Resource::ExecutionWork)?;
            self.work = add(self.work, scanned, Resource::ExecutionWork)?;
            enforce(self.work, work_limit, Resource::ExecutionWork)?;
        }
        Ok(())
    }

    fn classify(
        &mut self,
        class: crate::program::ByteSet,
        haystack: &[u8],
        index: usize,
        access: StateByteSourceAccess,
        work_limit: usize,
    ) -> Result<StateByteClassification, Error> {
        let state_evaluations = add(self.state_evaluations, 1, Resource::ExecutionWork)?;
        let transition_checks = add(self.transition_checks, 1, Resource::ExecutionWork)?;
        let work = add(self.work, 2, Resource::ExecutionWork)?;
        enforce(work, work_limit, Resource::ExecutionWork)?;
        let (sequential_bytes_read, random_access_bytes_read) = match access {
            StateByteSourceAccess::Sequential => (
                add(self.sequential_bytes_read, 1, Resource::SequentialBytes)?,
                self.random_access_bytes_read,
            ),
            StateByteSourceAccess::Random => (
                self.sequential_bytes_read,
                add(
                    self.random_access_bytes_read,
                    1,
                    Resource::RandomAccessBytes,
                )?,
            ),
        };
        let byte = *haystack.get(index).ok_or(Error::InternalInvariant(
            "state-byte classification index exceeds admitted source",
        ))?;
        self.state_evaluations = state_evaluations;
        self.transition_checks = transition_checks;
        self.sequential_bytes_read = sequential_bytes_read;
        self.random_access_bytes_read = random_access_bytes_read;
        self.work = work;
        Ok(StateByteClassification {
            byte,
            matches: class.contains(byte),
        })
    }

    fn compare_source(
        &mut self,
        haystack: &[u8],
        index: usize,
        expected: u8,
        work_limit: usize,
    ) -> Result<bool, Error> {
        let root_probes = add(self.root_probes, 1, Resource::ExecutionWork)?;
        let random_access_bytes_read = add(
            self.random_access_bytes_read,
            1,
            Resource::RandomAccessBytes,
        )?;
        let work = add(self.work, 1, Resource::ExecutionWork)?;
        enforce(work, work_limit, Resource::ExecutionWork)?;
        let byte = *haystack.get(index).ok_or(Error::InternalInvariant(
            "state-byte literal index exceeds admitted source",
        ))?;
        self.root_probes = root_probes;
        self.random_access_bytes_read = random_access_bytes_read;
        self.work = work;
        Ok(byte == expected)
    }

    fn compare_cached(&mut self, byte: u8, expected: u8, work_limit: usize) -> Result<bool, Error> {
        let root_probes = add(self.root_probes, 1, Resource::ExecutionWork)?;
        let work = add(self.work, 1, Resource::ExecutionWork)?;
        enforce(work, work_limit, Resource::ExecutionWork)?;
        self.root_probes = root_probes;
        self.work = work;
        Ok(byte == expected)
    }

    fn event(&mut self, work_limit: usize) -> Result<(), Error> {
        let successful_paths = add(self.successful_paths, 1, Resource::MatchEvents)?;
        let emitted_matches = add(self.emitted_matches, 1, Resource::OutputMatches)?;
        let work = add(self.work, 1, Resource::ExecutionWork)?;
        enforce(work, work_limit, Resource::ExecutionWork)?;
        self.successful_paths = successful_paths;
        self.emitted_matches = emitted_matches;
        self.work = work;
        Ok(())
    }
}

#[derive(Default)]
struct StateByteValueMeter;

impl StateByteMeter for StateByteValueMeter {
    #[inline]
    fn work(&self) -> usize {
        0
    }

    #[inline]
    fn record_scan(
        &mut self,
        _scanned: usize,
        _work_limit: usize,
        _transactional: bool,
    ) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn classify(
        &mut self,
        class: crate::program::ByteSet,
        haystack: &[u8],
        index: usize,
        _access: StateByteSourceAccess,
        _work_limit: usize,
    ) -> Result<StateByteClassification, Error> {
        let byte = *haystack.get(index).ok_or(Error::InternalInvariant(
            "state-byte classification index exceeds admitted source",
        ))?;
        Ok(StateByteClassification {
            byte,
            matches: class.contains(byte),
        })
    }

    #[inline]
    fn compare_source(
        &mut self,
        haystack: &[u8],
        index: usize,
        expected: u8,
        _work_limit: usize,
    ) -> Result<bool, Error> {
        let byte = *haystack.get(index).ok_or(Error::InternalInvariant(
            "state-byte literal index exceeds admitted source",
        ))?;
        Ok(byte == expected)
    }

    #[inline]
    fn compare_cached(
        &mut self,
        byte: u8,
        expected: u8,
        _work_limit: usize,
    ) -> Result<bool, Error> {
        Ok(byte == expected)
    }

    #[inline]
    fn event(&mut self, _work_limit: usize) -> Result<(), Error> {
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete guarded candidate, gap, greedy suffix, and non-overlap transaction stays adjacent"
)]
fn reduce_ascii_bounded_literal_pair(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    debug_assert!(
        plan.topology() == StateByteSpanSumTopology::BoundedLiteralPair || haystack.is_ascii()
    );
    let (left, right) = plan.bounded_pair_anchors().ok_or(Error::InternalInvariant(
        "state-byte bounded-pair plan lost its anchors",
    ))?;
    let (gap_min, gap_max) = plan
        .bounded_pair_gap_bounds()
        .ok_or(Error::InternalInvariant(
            "state-byte bounded-pair plan lost its gap bounds",
        ))?;
    if left.is_empty() || right.is_empty() || left[0] == right[0] || gap_min > gap_max {
        return Err(Error::InternalInvariant(
            "state-byte bounded-pair descriptor is not canonical",
        ));
    }

    // Prefix and suffix roles need independent monotone occurrence streams:
    // each direction's suffix lower bound is monotone even when the two
    // literals have different widths and their merged prefix ends are not.
    // Four native literal streams plus two monotone class cursors retain a
    // source-linear bound without rescanning the finite gap for every start.
    let mut left_prefixes = StateByteLiteralStream::new(left);
    let mut right_prefixes = StateByteLiteralStream::new(right);
    let mut left_suffixes = StateByteLiteralStream::new(left);
    let mut right_suffixes = StateByteLiteralStream::new(right);
    let mut left_class = StateByteClassRunCursor::new();
    let mut right_class = StateByteClassRunCursor::new();
    let mut match_floor = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    loop {
        let left_start =
            left_prefixes.peek_at_least(haystack, match_floor, work_limit, accounting)?;
        let right_start =
            right_prefixes.peek_at_least(haystack, match_floor, work_limit, accounting)?;
        let (start, prefix, suffix, suffixes, class_cursor) = match (left_start, right_start) {
            (None, None) => break,
            (Some(start), None) => {
                left_prefixes.consume_pending(start)?;
                (start, left, right, &mut right_suffixes, &mut left_class)
            }
            (Some(start), Some(other)) if start <= other => {
                left_prefixes.consume_pending(start)?;
                (start, left, right, &mut right_suffixes, &mut left_class)
            }
            (_, Some(start)) => {
                right_prefixes.consume_pending(start)?;
                (start, right, left, &mut left_suffixes, &mut right_class)
            }
        };
        let Some(prefix_end) = start.checked_add(prefix.len()) else {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::Boundaries,
            });
        };
        if prefix_end > haystack.len() {
            continue;
        }
        let lower = add(prefix_end, gap_min, Resource::Boundaries)?;
        if lower > haystack.len() {
            continue;
        }
        let upper = add(prefix_end, gap_max, Resource::Boundaries)?.min(haystack.len());
        let class_end = class_cursor.end_at_most(
            plan.first(),
            haystack,
            prefix_end,
            upper,
            work_limit,
            accounting,
        )?;
        if lower > class_end {
            continue;
        }
        let Some(suffix_start) =
            suffixes.farthest_between(haystack, lower, class_end, work_limit, accounting)?
        else {
            continue;
        };
        let end = add(suffix_start, suffix.len(), Resource::Boundaries)?;

        state_byte_event(work_limit, accounting)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            end.checked_sub(start).ok_or(Error::InternalInvariant(
                "state-byte bounded pair selected a reversed span",
            ))?,
            Resource::SpanSum,
        )?;
        match_floor = end;
    }
    Ok((matches, span_sum))
}

struct StateByteLiteralStream<'a> {
    literal: &'a [u8],
    search: usize,
    pending: Option<usize>,
    exhausted: bool,
}

impl<'a> StateByteLiteralStream<'a> {
    const fn new(literal: &'a [u8]) -> Self {
        Self {
            literal,
            search: 0,
            pending: None,
            exhausted: false,
        }
    }

    fn peek_at_least(
        &mut self,
        haystack: &[u8],
        lower: usize,
        work_limit: usize,
        accounting: &mut impl StateByteMeter,
    ) -> Result<Option<usize>, Error> {
        loop {
            if let Some(pending) = self.pending {
                if pending >= lower {
                    return Ok(Some(pending));
                }
                self.pending = None;
                continue;
            }
            if self.exhausted {
                return Ok(None);
            }
            let Some(found) = state_byte_find_literal(
                self.literal,
                haystack,
                self.search,
                work_limit,
                accounting,
            )?
            else {
                self.exhausted = true;
                return Ok(None);
            };
            self.search = add(found, 1, Resource::Boundaries)?;
            self.pending = Some(found);
        }
    }

    fn consume_pending(&mut self, expected: usize) -> Result<(), Error> {
        if self.pending != Some(expected) {
            return Err(Error::InternalInvariant(
                "state-byte literal stream consumed another occurrence",
            ));
        }
        self.pending = None;
        Ok(())
    }

    fn farthest_between(
        &mut self,
        haystack: &[u8],
        lower: usize,
        upper: usize,
        work_limit: usize,
        accounting: &mut impl StateByteMeter,
    ) -> Result<Option<usize>, Error> {
        let mut selected = None;
        while let Some(next) = self.peek_at_least(haystack, lower, work_limit, accounting)? {
            if next > upper {
                break;
            }
            self.consume_pending(next)?;
            selected = Some(next);
        }
        Ok(selected)
    }
}

struct StateByteClassRunCursor {
    scanned: usize,
    barrier: Option<usize>,
}

impl StateByteClassRunCursor {
    const fn new() -> Self {
        Self {
            scanned: 0,
            barrier: None,
        }
    }

    fn end_at_most(
        &mut self,
        class: crate::program::ByteSet,
        haystack: &[u8],
        start: usize,
        upper: usize,
        work_limit: usize,
        accounting: &mut impl StateByteMeter,
    ) -> Result<usize, Error> {
        if start > upper || upper > haystack.len() {
            return Err(Error::InternalInvariant(
                "state-byte class cursor received invalid bounds",
            ));
        }
        if self.scanned < start {
            self.scanned = start;
        }
        if self.barrier.is_some_and(|barrier| barrier < start) {
            self.barrier = None;
        }
        if let Some(barrier) = self.barrier {
            return Ok(barrier.min(upper));
        }
        while self.scanned < upper {
            if !state_byte_classify(
                class,
                haystack,
                self.scanned,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
            {
                self.barrier = Some(self.scanned);
                return Ok(self.scanned);
            }
            self.scanned = add(self.scanned, 1, Resource::Boundaries)?;
        }
        Ok(upper)
    }
}

fn reduce_repeated_lazy_delimiter_suffix(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let [delimiter, suffix @ ..] = plan.literal() else {
        return Err(Error::InternalInvariant(
            "state-byte repeated delimiter plan lost its literal suffix",
        ));
    };
    if suffix.is_empty() || plan.repeat_count() == 0 {
        return Err(Error::InternalInvariant(
            "state-byte repeated delimiter plan lost its nonempty proof",
        ));
    }
    let barrier = plan.barrier();
    if !plan.second().contains(barrier) {
        return Err(Error::InternalInvariant(
            "state-byte repeated delimiter lost its barrier",
        ));
    }

    // Search the mandatory suffix first. A source with no suffix can be
    // rejected by one native literal scan without enumerating a potentially
    // dense delimiter stream. When a suffix is preceded by the delimiter,
    // advance the delimiter/barrier recurrence only through that candidate.
    // The two monotone cursors never replay recurrence state; overlapping
    // suffix searches are bounded by the retained literal width.
    let mut run_start = 0_usize;
    let mut suffix_search = 0_usize;
    let mut event_cursor = 0_usize;
    let mut delimiters = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while suffix_search < haystack.len() {
        let Some(suffix_start) =
            state_byte_find_literal(suffix, haystack, suffix_search, work_limit, accounting)?
        else {
            break;
        };
        suffix_search = add(suffix_start, 1, Resource::Boundaries)?;
        let Some(delimiter_index) = suffix_start.checked_sub(1) else {
            continue;
        };
        if !state_byte_compare_source(
            haystack,
            delimiter_index,
            *delimiter,
            work_limit,
            accounting,
        )? {
            continue;
        }

        let recurrence_source = haystack
            .get(..suffix_start)
            .ok_or(Error::InternalInvariant(
                "state-byte suffix candidate exceeds admitted source",
            ))?;
        while event_cursor < suffix_start {
            let Some((index, byte)) = state_byte_find_either(
                *delimiter,
                barrier,
                recurrence_source,
                event_cursor,
                work_limit,
                accounting,
            )?
            else {
                event_cursor = suffix_start;
                break;
            };
            event_cursor = add(index, 1, Resource::Boundaries)?;
            if state_byte_compare_cached(byte, *delimiter, work_limit, accounting)? {
                delimiters = add(delimiters, 1, Resource::Boundaries)?;
            } else {
                if byte != barrier {
                    return Err(Error::InternalInvariant(
                        "state-byte memchr2 returned an unrequested byte",
                    ));
                }
                run_start = event_cursor;
                delimiters = 0;
            }
        }
        if event_cursor != suffix_start {
            return Err(Error::InternalInvariant(
                "state-byte suffix recurrence did not reach its candidate",
            ));
        }
        if delimiters < plan.repeat_count() {
            continue;
        }

        let end = add(suffix_start, suffix.len(), Resource::Boundaries)?;
        state_byte_event(work_limit, accounting)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            end.checked_sub(run_start).ok_or(Error::InternalInvariant(
                "state-byte repeated delimiter selected a reversed span",
            ))?,
            Resource::SpanSum,
        )?;
        suffix_search = end;
        event_cursor = end;
        run_start = end;
        delimiters = 0;
    }
    Ok((matches, span_sum))
}

fn state_byte_find_either(
    first: u8,
    second: u8,
    haystack: &[u8],
    start: usize,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<Option<(usize, u8)>, Error> {
    let remaining = haystack.get(start..).ok_or(Error::InternalInvariant(
        "state-byte memchr2 start exceeds admitted source",
    ))?;
    let available_work = work_limit.saturating_sub(accounting.work());
    let admitted_len = remaining.len().min(available_work);
    let admitted = &remaining[..admitted_len];
    let relative = memchr::memchr2(first, second, admitted);
    let scanned = match relative {
        Some(offset) => add(offset, 1, Resource::SequentialBytes)?,
        None => admitted_len,
    };
    accounting.record_scan(scanned, work_limit, false)?;
    if let Some(relative) = relative {
        let index = add(start, relative, Resource::Boundaries)?;
        let byte = *haystack.get(index).ok_or(Error::InternalInvariant(
            "state-byte memchr2 result exceeds admitted source",
        ))?;
        return Ok(Some((index, byte)));
    }
    if admitted_len < remaining.len() {
        let required = add(accounting.work(), 1, Resource::ExecutionWork)?;
        enforce(required, work_limit, Resource::ExecutionWork)?;
        return Err(Error::InternalInvariant(
            "state-byte memchr2 work refusal unexpectedly admitted progress",
        ));
    }
    Ok(None)
}

fn reduce_greedy_prefix_literal_suffix(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    // On short inputs the scalar pass avoids constructing a substring
    // searcher. Larger inputs use the mandatory literal as the source
    // iterator, then visit only the adjacent proved class runs. This keeps
    // cold-start work in the measured operation while letting the native
    // memchr/memmem implementation skip non-candidates in vector-width
    // chunks.
    if haystack.len() >= 256 {
        return reduce_greedy_prefix_literal_suffix_anchored(
            plan, haystack, work_limit, accounting,
        );
    }
    reduce_greedy_prefix_literal_suffix_scalar(plan, haystack, work_limit, accounting)
}

/// Value-only long-input reduction for the compile-proved `C* L D*`
/// topology.
///
/// `L ⊆ C ⊆ D` proves that the first literal at or after the non-overlap
/// cursor selects the same whole-match span as greedy backtracking: the start
/// follows the last non-`C` byte before that literal and the end is the first
/// non-`D` byte after it. The retained byte sets can therefore drive native
/// searches for small complements. Other admitted classes keep an exact
/// scalar boundary search, so this is not a shape-selection restriction.
///
/// The complete incumbent resource envelope is admitted before this function
/// runs. Short inputs retain the established scalar loop; long inputs build
/// one reusable native literal finder for the whole operation.
fn reduce_greedy_prefix_literal_suffix_value(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut StateByteValueMeter,
) -> Result<(usize, usize), Error> {
    if haystack.len() < 256 {
        return reduce_greedy_prefix_literal_suffix_scalar(plan, haystack, work_limit, accounting);
    }

    let literal = plan.literal();
    if literal.is_empty() {
        return Err(Error::InternalInvariant(
            "state-byte greedy value plan lost its nonempty literal",
        ));
    }
    let finder = memchr::memmem::Finder::new(literal);
    let prefix_boundary = StateByteClassBoundary::new(plan.first());
    let suffix_boundary = StateByteClassBoundary::new(plan.second());
    let mut cursor = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while cursor < haystack.len() {
        let remaining = haystack.get(cursor..).ok_or(Error::InternalInvariant(
            "state-byte greedy literal cursor exceeds admitted source",
        ))?;
        let Some(relative_literal_start) = finder.find(remaining) else {
            break;
        };
        let literal_start = add(cursor, relative_literal_start, Resource::Boundaries)?;
        let literal_end = add(literal_start, literal.len(), Resource::Boundaries)?;

        let prefix_source = haystack
            .get(cursor..literal_start)
            .ok_or(Error::InternalInvariant(
                "state-byte greedy prefix window exceeds admitted source",
            ))?;
        let start = add(
            cursor,
            prefix_boundary.start_after_last_nonmember(prefix_source),
            Resource::Boundaries,
        )?;

        let suffix_source = haystack.get(literal_end..).ok_or(Error::InternalInvariant(
            "state-byte greedy suffix window exceeds admitted source",
        ))?;
        let end = add(
            literal_end,
            suffix_boundary.first_nonmember_or_len(suffix_source),
            Resource::Boundaries,
        )?;

        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            end.checked_sub(start).ok_or(Error::InternalInvariant(
                "state-byte greedy value reducer selected a reversed span",
            ))?,
            Resource::SpanSum,
        )?;
        cursor = end;
    }
    Ok((matches, span_sum))
}

#[derive(Clone, Copy, Debug)]
enum StateByteClassBoundary {
    Native { excluded: [u8; 3], excluded_len: u8 },
    Scalar(crate::program::ByteSet),
}

impl StateByteClassBoundary {
    /// Derive a bounded complement classifier from the compile-retained
    /// membership bitset. Four or more excluded bytes use the general scalar
    /// fallback; discovery therefore examines at most four set bits.
    fn new(class: crate::program::ByteSet) -> Self {
        let mut excluded = [0_u8; 3];
        let mut excluded_len = 0_usize;
        for (word_index, members) in class.0.into_iter().enumerate() {
            let mut outside = !members;
            while outside != 0 {
                if excluded_len == excluded.len() {
                    return Self::Scalar(class);
                }
                let bit = usize::try_from(outside.trailing_zeros())
                    .expect("u64 trailing-zero count fits usize");
                let byte = word_index
                    .checked_mul(
                        usize::try_from(u64::BITS).expect("u64 bit width fits target usize"),
                    )
                    .and_then(|base| base.checked_add(bit))
                    .expect("four u64 words contain exactly the byte domain");
                excluded[excluded_len] = u8::try_from(byte).expect("byte-set bit index fits u8");
                excluded_len = excluded_len
                    .checked_add(1)
                    .expect("three retained complement bytes fit usize");
                outside &= outside.wrapping_sub(1);
            }
        }
        Self::Native {
            excluded,
            excluded_len: u8::try_from(excluded_len)
                .expect("three retained complement bytes fit u8"),
        }
    }

    #[inline]
    fn first_nonmember_or_len(self, haystack: &[u8]) -> usize {
        match self {
            Self::Native {
                excluded_len: 0, ..
            } => haystack.len(),
            Self::Native {
                excluded,
                excluded_len: 1,
            } => memchr::memchr(excluded[0], haystack).unwrap_or(haystack.len()),
            Self::Native {
                excluded,
                excluded_len: 2,
            } => memchr::memchr2(excluded[0], excluded[1], haystack).unwrap_or(haystack.len()),
            Self::Native {
                excluded,
                excluded_len: 3,
            } => memchr::memchr3(excluded[0], excluded[1], excluded[2], haystack)
                .unwrap_or(haystack.len()),
            Self::Native { .. } => {
                unreachable!("native state-byte complement retains at most three bytes")
            }
            Self::Scalar(class) => haystack
                .iter()
                .position(|&byte| !class.contains(byte))
                .unwrap_or(haystack.len()),
        }
    }

    #[inline]
    fn start_after_last_nonmember(self, haystack: &[u8]) -> usize {
        let last = match self {
            Self::Native {
                excluded_len: 0, ..
            } => None,
            Self::Native {
                excluded,
                excluded_len: 1,
            } => memchr::memrchr(excluded[0], haystack),
            Self::Native {
                excluded,
                excluded_len: 2,
            } => memchr::memrchr2(excluded[0], excluded[1], haystack),
            Self::Native {
                excluded,
                excluded_len: 3,
            } => memchr::memrchr3(excluded[0], excluded[1], excluded[2], haystack),
            Self::Native { .. } => {
                unreachable!("native state-byte complement retains at most three bytes")
            }
            Self::Scalar(class) => haystack.iter().rposition(|&byte| !class.contains(byte)),
        };
        last.map_or(0, |index| {
            index
                .checked_add(1)
                .expect("a retained source index has a following boundary")
        })
    }
}

fn reduce_greedy_prefix_literal_suffix_anchored(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let prefix = plan.first();
    let suffix = plan.second();
    let literal = plan.literal();
    let mut cursor = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while cursor < haystack.len() {
        let Some(literal_start) =
            state_byte_find_literal(literal, haystack, cursor, work_limit, accounting)?
        else {
            break;
        };
        let literal_end = add(literal_start, literal.len(), Resource::Boundaries)?;

        let mut start = literal_start;
        while start > cursor {
            let previous = start.checked_sub(1).ok_or(Error::InternalInvariant(
                "positive state-byte prefix cursor lost its predecessor",
            ))?;
            if !state_byte_classify(
                prefix,
                haystack,
                previous,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
            {
                break;
            }
            start = previous;
        }

        let mut end = literal_end;
        while end < haystack.len()
            && state_byte_classify(
                suffix,
                haystack,
                end,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
        {
            end = add(end, 1, Resource::Boundaries)?;
        }

        state_byte_event(work_limit, accounting)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            end.checked_sub(start).ok_or(Error::InternalInvariant(
                "state-byte anchored reducer selected a reversed span",
            ))?,
            Resource::SpanSum,
        )?;
        cursor = end;
    }
    Ok((matches, span_sum))
}

fn reduce_greedy_prefix_literal_suffix_scalar(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let prefix = plan.first();
    let suffix = plan.second();
    let literal = plan.literal();
    let literal_failure = plan.literal_failure();
    let mut cursor = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while cursor < haystack.len() {
        if !state_byte_classify(
            suffix,
            haystack,
            cursor,
            StateByteSourceAccess::Sequential,
            work_limit,
            accounting,
        )?
        .matches
        {
            cursor = add(cursor, 1, Resource::Boundaries)?;
            continue;
        }
        let suffix_start = cursor;
        cursor = add(cursor, 1, Resource::Boundaries)?;
        while cursor < haystack.len() {
            let classified = state_byte_classify(
                suffix,
                haystack,
                cursor,
                StateByteSourceAccess::Sequential,
                work_limit,
                accounting,
            )?;
            if !classified.matches {
                break;
            }
            cursor = add(cursor, 1, Resource::Boundaries)?;
        }
        let suffix_end = cursor;
        let mut scan = suffix_start;
        let mut selected_start = None;
        let mut prefix_start = None;
        let mut literal_matched = 0_usize;
        while scan < suffix_end {
            let classified = state_byte_classify(
                prefix,
                haystack,
                scan,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?;
            if classified.matches {
                let run_start = *prefix_start.get_or_insert(scan);
                if state_byte_kmp_feed(
                    classified.byte,
                    literal,
                    literal_failure,
                    &mut literal_matched,
                    work_limit,
                    accounting,
                )? {
                    selected_start = Some(run_start);
                    break;
                }
            } else {
                prefix_start = None;
                literal_matched = 0;
            }
            scan = add(scan, 1, Resource::Boundaries)?;
        }
        if let Some(start) = selected_start {
            state_byte_event(work_limit, accounting)?;
            matches = add(matches, 1, Resource::OutputMatches)?;
            span_sum = add(
                span_sum,
                suffix_end
                    .checked_sub(start)
                    .ok_or(Error::InternalInvariant(
                        "state-byte SpanSum selected a reversed span",
                    ))?,
                Resource::SpanSum,
            )?;
        }
        // `cursor`, when not at EOF, is the already-classified byte outside
        // the maximal suffix run. Since `prefix ⊆ suffix`, it cannot start a
        // match and need not be classified a second time.
        if cursor < haystack.len() {
            cursor = add(cursor, 1, Resource::Boundaries)?;
        }
    }
    Ok((matches, span_sum))
}

fn reduce_disjoint_runs_literal(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    if plan.literal().len() > 1 {
        reduce_disjoint_runs_literal_anchored(plan, haystack, work_limit, accounting)
    } else {
        reduce_disjoint_runs_literal_scalar(plan, haystack, work_limit, accounting)
    }
}

// The singleton internal anchor is excluded from both adjacent classes.
// Consequently, monotone anchor searches partition every reverse prefix run
// and every forward suffix run. The checkpoint form retains one marker that
// belongs to the suffix class: `S+ D S+` exists exactly when the maximal
// suffix run contains `D` somewhere other than its first or last byte.
//
// The executor therefore preserves leftmost-first, greedy, non-overlapping
// whole-match semantics without replay or scratch storage. A failed
// checkpoint can skip to the end of its suffix run because that run is proved
// not to contain another anchor.
#[allow(
    clippy::too_many_lines,
    reason = "the complete anchor, prefix, suffix, checkpoint, publication, and accounting transaction stays visible"
)]
fn reduce_disjoint_internal_runs(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let prefix = plan.first();
    let suffix = plan.second();
    let anchor = *plan.literal().first().ok_or(Error::InternalInvariant(
        "state-byte internal-run plan lost its anchor",
    ))?;
    let checkpoint = match plan.topology() {
        StateByteSpanSumTopology::DisjointInternalRuns => None,
        StateByteSpanSumTopology::DisjointInternalRunsCheckpoint => {
            Some(*plan.literal().get(1).ok_or(Error::InternalInvariant(
                "state-byte checkpoint plan lost its marker",
            ))?)
        }
        _ => {
            return Err(Error::InternalInvariant(
                "non-internal state-byte topology reached internal reducer",
            ));
        }
    };

    let mut match_floor = 0_usize;
    let mut search = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while search < haystack.len() {
        let Some(anchor_index) =
            state_byte_find_anchor(anchor, haystack, search, work_limit, accounting)?
        else {
            break;
        };
        search = add(anchor_index, 1, Resource::Boundaries)?;
        if anchor_index <= match_floor {
            continue;
        }

        let mut prefix_start = anchor_index;
        while prefix_start > match_floor {
            let previous = prefix_start.checked_sub(1).ok_or(Error::InternalInvariant(
                "positive state-byte internal prefix lost its predecessor",
            ))?;
            if !state_byte_classify(
                prefix,
                haystack,
                previous,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
            {
                break;
            }
            prefix_start = previous;
        }
        if prefix_start == anchor_index {
            continue;
        }

        let suffix_start = add(anchor_index, 1, Resource::Boundaries)?;
        let mut suffix_end = suffix_start;
        let mut suffix_bytes = 0_usize;
        let mut previous_was_checkpoint = false;
        let mut interior_checkpoint = false;
        while suffix_end < haystack.len() {
            let classified = state_byte_classify(
                suffix,
                haystack,
                suffix_end,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?;
            if !classified.matches {
                break;
            }
            if previous_was_checkpoint && suffix_bytes > 1 {
                interior_checkpoint = true;
            }
            previous_was_checkpoint = if let Some(marker) = checkpoint {
                state_byte_compare_cached(classified.byte, marker, work_limit, accounting)?
            } else {
                false
            };
            suffix_bytes = add(suffix_bytes, 1, Resource::Boundaries)?;
            suffix_end = add(suffix_end, 1, Resource::Boundaries)?;
        }
        if suffix_bytes == 0 {
            continue;
        }
        search = suffix_end;
        if checkpoint.is_some() && !interior_checkpoint {
            continue;
        }

        state_byte_event(work_limit, accounting)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            suffix_end
                .checked_sub(prefix_start)
                .ok_or(Error::InternalInvariant(
                    "state-byte internal reducer selected a reversed span",
                ))?,
            Resource::SpanSum,
        )?;
        match_floor = suffix_end;
    }
    Ok((matches, span_sum))
}

// The compile-selected byte offset is a necessary literal witness, so a
// monotone `memchr` stream is overlap-complete even when the literal itself is
// bordered. After a complete literal comparison, its first byte (proved in
// `first` and therefore outside disjoint `second`) seals the preceding
// `second+` run. Scanning that run and the adjacent `first+` run backward
// yields the unique greedy start for this literal occurrence.
//
// Literal comparisons cost at most `N * L`. Candidate run scans are linear:
// every candidate start is a `first` barrier, so distinct preceding `second`
// runs cannot overlap; every accepted/rejected `second` run similarly
// partitions the adjacent `first` run. The source-independent prospective
// leaves four full classification passes, including one terminating probe per
// candidate for each run.
#[allow(
    clippy::too_many_lines,
    reason = "the monotone anchor traversal keeps literal, reverse-run, result, and resource accounting adjacent"
)]
fn reduce_disjoint_runs_literal_anchored(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let first = plan.first();
    let second = plan.second();
    let literal = plan.literal();
    let anchor_offset = plan.literal_anchor_offset();
    let anchor_byte = *literal.get(anchor_offset).ok_or(Error::InternalInvariant(
        "state-byte literal anchor offset exceeds retained literal",
    ))?;
    let mut match_floor = 0_usize;
    let mut search = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while search < haystack.len() {
        let Some(anchor_index) =
            state_byte_find_anchor(anchor_byte, haystack, search, work_limit, accounting)?
        else {
            break;
        };
        search = add(anchor_index, 1, Resource::Boundaries)?;
        let Some(candidate_start) = anchor_index.checked_sub(anchor_offset) else {
            continue;
        };
        if candidate_start < match_floor {
            continue;
        }
        let Some(candidate_end) = candidate_start.checked_add(literal.len()) else {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::Boundaries,
            });
        };
        if candidate_end > haystack.len() {
            continue;
        }
        if !state_byte_literal_matches_at(
            literal,
            anchor_offset,
            haystack,
            candidate_start,
            work_limit,
            accounting,
        )? {
            continue;
        }

        let mut second_start = candidate_start;
        while second_start > match_floor {
            let previous = second_start.checked_sub(1).ok_or(Error::InternalInvariant(
                "positive state-byte second-run cursor lost predecessor",
            ))?;
            if !state_byte_classify(
                second,
                haystack,
                previous,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
            {
                break;
            }
            second_start = previous;
        }
        if second_start == candidate_start {
            continue;
        }

        let mut first_start = second_start;
        while first_start > match_floor {
            let previous = first_start.checked_sub(1).ok_or(Error::InternalInvariant(
                "positive state-byte first-run cursor lost predecessor",
            ))?;
            if !state_byte_classify(
                first,
                haystack,
                previous,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?
            .matches
            {
                break;
            }
            first_start = previous;
        }
        if first_start == second_start {
            continue;
        }

        state_byte_event(work_limit, accounting)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            candidate_end
                .checked_sub(first_start)
                .ok_or(Error::InternalInvariant(
                    "state-byte anchored reducer selected a reversed span",
                ))?,
            Resource::SpanSum,
        )?;
        match_floor = candidate_end;
        search = candidate_end;
    }
    Ok((matches, span_sum))
}

fn reduce_disjoint_runs_literal_scalar(
    plan: &StateByteSpanSumPlan,
    haystack: &[u8],
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<(usize, usize), Error> {
    let first = plan.first();
    let second = plan.second();
    let literal = plan.literal();
    let mut cursor = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while cursor < haystack.len() {
        if !state_byte_classify(
            first,
            haystack,
            cursor,
            StateByteSourceAccess::Sequential,
            work_limit,
            accounting,
        )?
        .matches
        {
            cursor = add(cursor, 1, Resource::Boundaries)?;
            continue;
        }
        let start = cursor;
        cursor = add(cursor, 1, Resource::Boundaries)?;
        while cursor < haystack.len() {
            let classified = state_byte_classify(
                first,
                haystack,
                cursor,
                StateByteSourceAccess::Sequential,
                work_limit,
                accounting,
            )?;
            if !classified.matches {
                break;
            }
            cursor = add(cursor, 1, Resource::Boundaries)?;
        }
        let first_end = cursor;
        let mut second_end = first_end;
        let mut second_terminator = None;
        while second_end < haystack.len() {
            let classified = state_byte_classify(
                second,
                haystack,
                second_end,
                StateByteSourceAccess::Random,
                work_limit,
                accounting,
            )?;
            if !classified.matches {
                second_terminator = Some(classified.byte);
                break;
            }
            second_end = add(second_end, 1, Resource::Boundaries)?;
        }
        if second_end == first_end {
            // The first byte after the run was already proved outside
            // `first`, so it cannot begin the next match.
            cursor = if first_end < haystack.len() {
                add(first_end, 1, Resource::Boundaries)?
            } else {
                first_end
            };
            continue;
        }
        let literal_matches = state_byte_disjoint_literal_matches(
            literal,
            haystack,
            second_end,
            second_terminator,
            work_limit,
            accounting,
        )?;
        if literal_matches {
            let end = add(second_end, literal.len(), Resource::Boundaries)?;
            state_byte_event(work_limit, accounting)?;
            matches = add(matches, 1, Resource::OutputMatches)?;
            span_sum = add(
                span_sum,
                end.checked_sub(start).ok_or(Error::InternalInvariant(
                    "state-byte SpanSum selected a reversed span",
                ))?,
                Resource::SpanSum,
            )?;
            cursor = end;
        } else {
            // Every byte in the second run is disjoint from `first`, while
            // the proved first literal byte is in `first`. Resume exactly at
            // that literal candidate without rescanning the second run.
            cursor = second_end;
        }
    }
    Ok((matches, span_sum))
}

fn state_byte_find_anchor(
    anchor: u8,
    haystack: &[u8],
    start: usize,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<Option<usize>, Error> {
    let remaining = haystack.get(start..).ok_or(Error::InternalInvariant(
        "state-byte anchor search start exceeds admitted source",
    ))?;
    let available_work = work_limit.saturating_sub(accounting.work());
    let admitted_len = remaining.len().min(available_work);
    let admitted = &remaining[..admitted_len];
    let relative = memchr::memchr(anchor, admitted);
    let scanned = match relative {
        Some(offset) => add(offset, 1, Resource::SequentialBytes)?,
        None => admitted_len,
    };
    accounting.record_scan(scanned, work_limit, true)?;
    if let Some(relative) = relative {
        return Ok(Some(add(start, relative, Resource::Boundaries)?));
    }
    if admitted_len < remaining.len() {
        let required = add(accounting.work(), 1, Resource::ExecutionWork)?;
        enforce(required, work_limit, Resource::ExecutionWork)?;
        return Err(Error::InternalInvariant(
            "state-byte anchor work refusal unexpectedly admitted progress",
        ));
    }
    Ok(None)
}

fn state_byte_find_literal(
    literal: &[u8],
    haystack: &[u8],
    start: usize,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<Option<usize>, Error> {
    let [anchor] = literal else {
        let remaining = haystack.get(start..).ok_or(Error::InternalInvariant(
            "state-byte literal search start exceeds admitted source",
        ))?;
        let available_work = work_limit.saturating_sub(accounting.work());
        let admitted_len = remaining.len().min(available_work);
        let admitted = &remaining[..admitted_len];
        let relative = memchr::memmem::find(admitted, literal);
        let scanned = match relative {
            Some(offset) => add(offset, literal.len(), Resource::SequentialBytes)?,
            None => admitted_len,
        };
        accounting.record_scan(scanned, work_limit, false)?;
        if let Some(relative) = relative {
            return add(start, relative, Resource::Boundaries).map(Some);
        }
        if admitted_len < remaining.len() {
            let required = add(accounting.work(), 1, Resource::ExecutionWork)?;
            enforce(required, work_limit, Resource::ExecutionWork)?;
            return Err(Error::InternalInvariant(
                "state-byte literal work refusal unexpectedly admitted progress",
            ));
        }
        return Ok(None);
    };
    state_byte_find_anchor(*anchor, haystack, start, work_limit, accounting)
}

fn state_byte_literal_matches_at(
    literal: &[u8],
    anchor_offset: usize,
    haystack: &[u8],
    start: usize,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<bool, Error> {
    for (offset, &expected) in literal.iter().enumerate() {
        if offset == anchor_offset {
            if !state_byte_compare_cached(expected, expected, work_limit, accounting)? {
                return Err(Error::InternalInvariant(
                    "state-byte cached literal anchor compared unequal to itself",
                ));
            }
            continue;
        }
        let index = add(start, offset, Resource::Boundaries)?;
        if !state_byte_compare_source(haystack, index, expected, work_limit, accounting)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn state_byte_disjoint_literal_matches(
    literal: &[u8],
    haystack: &[u8],
    start: usize,
    classified_first: Option<u8>,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<bool, Error> {
    if haystack.len().saturating_sub(start) < literal.len() {
        return Ok(false);
    }
    let first_byte = classified_first.ok_or(Error::InternalInvariant(
        "state-byte literal candidate lost its classified first byte",
    ))?;
    if !state_byte_compare_cached(first_byte, literal[0], work_limit, accounting)? {
        return Ok(false);
    }
    for (offset, &literal_byte) in literal.iter().enumerate().skip(1) {
        let index = add(start, offset, Resource::Boundaries)?;
        if !state_byte_compare_source(haystack, index, literal_byte, work_limit, accounting)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn state_byte_classify(
    class: crate::program::ByteSet,
    haystack: &[u8],
    index: usize,
    access: StateByteSourceAccess,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<StateByteClassification, Error> {
    accounting.classify(class, haystack, index, access, work_limit)
}

fn state_byte_compare_source(
    haystack: &[u8],
    index: usize,
    expected: u8,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<bool, Error> {
    accounting.compare_source(haystack, index, expected, work_limit)
}

fn state_byte_compare_cached(
    byte: u8,
    expected: u8,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<bool, Error> {
    accounting.compare_cached(byte, expected, work_limit)
}

fn state_byte_kmp_feed(
    byte: u8,
    literal: &[u8],
    failure: &[u8],
    matched: &mut usize,
    work_limit: usize,
    accounting: &mut impl StateByteMeter,
) -> Result<bool, Error> {
    loop {
        if state_byte_compare_cached(byte, literal[*matched], work_limit, accounting)? {
            *matched = add(*matched, 1, Resource::ExecutionWork)?;
            return Ok(*matched == literal.len());
        }
        if *matched == 0 {
            return Ok(false);
        }
        let fallback_index = (*matched).checked_sub(1).ok_or(Error::InternalInvariant(
            "positive state-byte KMP prefix lost its predecessor",
        ))?;
        *matched = usize::from(failure[fallback_index]);
    }
}

#[derive(Clone, Copy)]
struct StateByteClassification {
    byte: u8,
    matches: bool,
}

#[derive(Clone, Copy)]
enum StateByteSourceAccess {
    Sequential,
    Random,
}

fn state_byte_event(work_limit: usize, accounting: &mut impl StateByteMeter) -> Result<(), Error> {
    accounting.event(work_limit)
}

fn start_domain_prospective(
    program: &Program,
    boundaries: usize,
    kind: OperationKind,
    limits: OperationLimits,
) -> Result<OperationProspective, Error> {
    let scratch_bytes = candidate::start_domain_workspace_bytes(program)?;
    let work_bound = limits.max_work;
    let random_access_bytes_read = work_bound.saturating_mul(8);
    let accounting = ExecutionAccounting {
        state_evaluations: work_bound,
        transition_checks: work_bound,
        assertion_checks: work_bound,
        root_probes: work_bound,
        successful_paths: limits.max_match_events,
        suppressed_empty: limits.max_match_events,
        emitted_matches: limits.max_output_matches,
        random_access_bytes_read,
        random_access_peak_bytes: scratch_bytes,
        scratch_peak_bytes: scratch_bytes,
        peak_bytes: scratch_bytes,
        work: work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound,
        random_access_bytes: scratch_bytes,
        scratch_bytes,
        log_bytes: 0,
        sequential_bytes: 0,
        match_events: limits.max_match_events,
        output_matches: limits.max_output_matches,
        output_bytes: 0,
        span_sum: if kind == OperationKind::Sum {
            limits.max_span_sum
        } else {
            0
        },
        allocations: candidate::START_DOMAIN_EXECUTION_ALLOCATIONS,
        peak_bytes: scratch_bytes,
        accounting,
    })
}

const CANDIDATE_EXECUTION_ALLOCATIONS: usize = 5;

fn fixed_continuation_candidate_prospective(
    plan: &candidate::FixedContinuation,
    program: &Program,
    input_bytes: usize,
    boundaries: usize,
    kind: OperationKind,
) -> Result<OperationProspective, Error> {
    let upper = candidate::fixed_continuation_upper(plan, input_bytes, boundaries)?;
    let output_matches = input_bytes;
    let span_sum = if kind == OperationKind::Sum {
        input_bytes
    } else {
        0
    };
    let accounting = ExecutionAccounting {
        root_probes: input_bytes,
        successful_paths: output_matches,
        emitted_matches: output_matches,
        sequential_bytes_read: input_bytes,
        random_access_bytes_read: upper.random_access_bytes_read,
        random_access_peak_bytes: upper.scratch_bytes,
        scratch_peak_bytes: upper.scratch_bytes,
        peak_bytes: upper.scratch_bytes,
        work: upper.work,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound: upper.work,
        random_access_bytes: upper.scratch_bytes,
        scratch_bytes: upper.scratch_bytes,
        log_bytes: 0,
        sequential_bytes: input_bytes,
        match_events: input_bytes,
        output_matches,
        output_bytes: 0,
        span_sum,
        allocations: candidate::FIXED_CONTINUATION_EXECUTION_ALLOCATIONS,
        peak_bytes: upper.scratch_bytes,
        accounting,
    })
}

fn candidate_prospective(
    plan: &candidate::Plan,
    program: &Program,
    input_bytes: usize,
    boundaries: usize,
    kind: OperationKind,
    limits: OperationLimits,
) -> Result<OperationProspective, Error> {
    let schedule = if plan.has_shared_fixed() || plan.classified_anchors().is_some() {
        1
    } else {
        add(plan.max_offset(), 1, Resource::ScratchBytes)?
    };
    let states = program.insts.len();
    let stack = add(
        mul(states, 2, Resource::ScratchBytes)?,
        1,
        Resource::ScratchBytes,
    )?;
    let scratch_bytes = add(
        mul(
            schedule,
            core::mem::size_of::<u128>(),
            Resource::ScratchBytes,
        )?,
        add(
            mul(
                add(
                    stack,
                    mul(states, 2, Resource::ScratchBytes)?,
                    Resource::ScratchBytes,
                )?,
                core::mem::size_of::<u16>(),
                Resource::ScratchBytes,
            )?,
            mul(states, core::mem::size_of::<u32>(), Resource::ScratchBytes)?,
            Resource::ScratchBytes,
        )?,
        Resource::ScratchBytes,
    )?;
    let sequential_bytes = mul(input_bytes, 2, Resource::SequentialBytes)?;
    // Candidate verification meters every state, transition, assertion, root
    // probe and source service against this attempt's immutable work ceiling.
    // The ceiling is part of the attempt identity, so it is a valid
    // pre-source bound even though candidate density is source-dependent.
    let work_bound = limits.max_work;
    let random_access_bytes_read = work_bound.saturating_mul(8);
    // The candidate verifier admits only nonempty spans and advances its
    // cursor to each accepted end, so accepted widths are disjoint and their
    // checked sum cannot exceed the operation range.
    let span_sum = if kind == OperationKind::Sum {
        input_bytes
    } else {
        0
    };
    let accounting = ExecutionAccounting {
        state_evaluations: work_bound,
        transition_checks: work_bound,
        assertion_checks: work_bound,
        root_probes: limits.max_match_events,
        successful_paths: limits.max_output_matches,
        emitted_matches: limits.max_output_matches,
        sequential_bytes_read: sequential_bytes,
        random_access_bytes_read,
        random_access_peak_bytes: scratch_bytes,
        scratch_peak_bytes: scratch_bytes,
        peak_bytes: scratch_bytes,
        work: work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states,
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound,
        random_access_bytes: scratch_bytes,
        scratch_bytes,
        log_bytes: 0,
        sequential_bytes,
        match_events: limits.max_match_events,
        output_matches: limits.max_output_matches,
        output_bytes: 0,
        span_sum,
        allocations: CANDIDATE_EXECUTION_ALLOCATIONS,
        peak_bytes: scratch_bytes,
        accounting,
    })
}

fn url_aggregate_execution_accounting(actual: UrlAggregateReduceAccounting) -> ExecutionAccounting {
    ExecutionAccounting {
        successful_paths: actual.matches,
        emitted_matches: actual.matches,
        sequential_bytes_read: actual.sequential_bytes,
        random_access_bytes_read: actual.random_access_bytes,
        random_access_peak_bytes: actual.random_access_storage_bytes,
        scratch_peak_bytes: actual.scratch_bytes,
        peak_bytes: actual.peak_bytes,
        work: actual.work,
        url_segments: actual.segments,
        url_dot_probes: actual.dot_probes,
        url_tld_transitions: actual.tld_transitions,
        url_tld_candidates: actual.tld_candidates,
        url_scheme_probes: actual.scheme_probes,
        url_ipv4_candidates: actual.ipv4_candidates,
        url_prefix_steps: actual.prefix_steps,
        url_suffix_steps: actual.suffix_steps,
        url_candidate_insertions: actual.candidate_insertions,
        url_candidate_visits: actual.candidate_visits,
        ..ExecutionAccounting::default()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive mapping keeps every kernel refusal tied to its public resource"
)]
fn map_url_reduce_error(error: &UrlAggregateReduceError) -> Error {
    match *error {
        UrlAggregateReduceError::InvalidRange {
            start,
            end,
            haystack_len,
        } => Error::InvalidRange {
            start,
            end,
            haystack_len,
        },
        UrlAggregateReduceError::Resource {
            resource: "boundaries",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::Boundaries,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "match events",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::MatchEvents,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "output matches",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::OutputMatches,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "span sum",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::SpanSum,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "sequential bytes",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::SequentialBytes,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "random access storage bytes",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::RandomAccessBytes,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "scratch bytes",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::ScratchBytes,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource {
            resource: "peak bytes",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::PeakBytes,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Resource { needed, limit, .. } => Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required: needed,
            limit,
        },
        UrlAggregateReduceError::Overflow(resource) => Error::ArithmeticOverflow {
            resource: map_url_overflow_resource(resource),
        },
        UrlAggregateReduceError::Allocation { items, .. } => Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items,
        },
        UrlAggregateReduceError::Invariant(_) => {
            Error::InternalInvariant("certified URL aggregate execution invariant failed")
        }
        _ => Error::InternalInvariant("unclassified URL aggregate execution refusal"),
    }
}

fn url_aggregate_prospective(
    program: &Program,
    upper: UrlAggregateReduceUpperBounds,
    kind: OperationKind,
    work_bound: usize,
) -> OperationProspective {
    let accounting = ExecutionAccounting {
        successful_paths: upper.output_matches,
        emitted_matches: upper.output_matches,
        sequential_bytes_read: upper.sequential_bytes,
        // Every URL random read is charged to the same bounded work meter.
        random_access_bytes_read: work_bound,
        random_access_peak_bytes: upper.random_access_storage_bytes,
        scratch_peak_bytes: upper.scratch_bytes,
        peak_bytes: upper.peak_bytes,
        work: work_bound,
        url_segments: upper.boundaries,
        url_dot_probes: work_bound,
        url_tld_transitions: work_bound,
        url_tld_candidates: work_bound,
        url_scheme_probes: work_bound,
        url_ipv4_candidates: work_bound,
        url_prefix_steps: work_bound,
        url_suffix_steps: work_bound,
        url_candidate_insertions: work_bound,
        url_candidate_visits: work_bound,
        ..ExecutionAccounting::default()
    };
    OperationProspective {
        states: program.insts.len(),
        boundaries: upper.boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: upper.candidate_record_bytes,
        terminal_frontier: false,
        work_bound,
        random_access_bytes: upper.random_access_storage_bytes,
        scratch_bytes: upper.scratch_bytes,
        log_bytes: 0,
        sequential_bytes: upper.sequential_bytes,
        match_events: upper.match_events,
        output_matches: upper.output_matches,
        output_bytes: 0,
        span_sum: if kind == OperationKind::Sum {
            upper.span_sum
        } else {
            0
        },
        allocations: usize::from(upper.candidate_records != 0),
        peak_bytes: upper.peak_bytes,
        accounting,
    }
}

#[allow(
    clippy::match_same_arms,
    reason = "named random-read overflow is proved work-dominated; unknown future counters also fail closed as execution work"
)]
fn map_url_overflow_resource(resource: &str) -> Resource {
    match resource {
        "boundaries" | "input cursor" | "segment start" => Resource::Boundaries,
        "sequential bytes" => Resource::SequentialBytes,
        "random access bytes" => Resource::ExecutionWork,
        "random access storage bytes" => Resource::RandomAccessBytes,
        "candidate records" | "scratch bytes" | "segment bytes" => Resource::ScratchBytes,
        "span sum" => Resource::SpanSum,
        "matches" => Resource::OutputMatches,
        "candidate insertions" | "candidate visits" => Resource::ExecutionWork,
        "peak bytes" => Resource::PeakBytes,
        _ => Resource::ExecutionWork,
    }
}

fn preflight_required_internal_anchor(
    plan: &RequiredInternalAnchorPlan,
    input_bytes: usize,
    limits: OperationLimits,
) -> Result<(usize, RequiredInternalAnchorCountUpperBounds), Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
    let upper = plan
        .count_upper_bounds(input_bytes)
        .map_err(|error| map_required_anchor_error(&error))?;
    enforce(
        upper.candidate_visits,
        limits.max_match_events,
        Resource::MatchEvents,
    )?;
    let count = usize::try_from(upper.count).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::OutputMatches,
    })?;
    enforce(count, limits.max_output_matches, Resource::OutputMatches)?;
    enforce(
        upper.random_access_bytes,
        limits.max_random_access_bytes,
        Resource::RandomAccessBytes,
    )?;
    enforce(
        upper.sequential_bytes,
        limits.max_sequential_bytes,
        Resource::SequentialBytes,
    )?;
    enforce(upper.work, limits.max_work, Resource::ExecutionWork)?;
    enforce(
        upper.scratch_bytes,
        limits.max_scratch_bytes,
        Resource::ScratchBytes,
    )?;
    enforce(upper.peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
    Ok((boundaries, upper))
}

fn required_internal_anchor_prospective(
    program: &Program,
    boundaries: usize,
    upper: RequiredInternalAnchorCountUpperBounds,
) -> Result<OperationProspective, Error> {
    let output_matches = usize::try_from(upper.count).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::OutputMatches,
    })?;
    let accounting = ExecutionAccounting {
        transition_checks: upper.continuation_steps,
        root_probes: upper.candidate_visits,
        required_anchor_candidates: upper.candidate_visits,
        required_anchor_scan_windows: upper.anchor_window_attempts,
        required_anchor_anchor_comparisons: upper.finder_source_accesses,
        required_anchor_prefix_steps: upper.prefix_steps,
        required_anchor_continuation_steps: upper.continuation_steps,
        required_anchor_source_accesses: upper.source_accesses,
        required_anchor_queue_peak: upper.queue_entries,
        required_anchor_frontier_peak: upper.frontier_entries,
        successful_paths: output_matches,
        emitted_matches: output_matches,
        sequential_bytes_read: upper.sequential_bytes,
        random_access_bytes_read: upper.random_access_bytes,
        scratch_peak_bytes: upper.scratch_bytes,
        peak_bytes: upper.peak_bytes,
        work: upper.work,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound: upper.work,
        random_access_bytes: upper.random_access_bytes,
        scratch_bytes: upper.scratch_bytes,
        log_bytes: 0,
        sequential_bytes: upper.sequential_bytes,
        match_events: upper.candidate_visits,
        output_matches,
        output_bytes: 0,
        span_sum: 0,
        allocations: upper.allocations,
        peak_bytes: upper.peak_bytes,
        accounting,
    })
}

fn exact_required_anchor_limits(
    upper: RequiredInternalAnchorCountUpperBounds,
    public: OperationLimits,
) -> RequiredInternalAnchorCountLimits {
    let public_count = u64::try_from(public.max_output_matches).unwrap_or(u64::MAX);
    RequiredInternalAnchorCountLimits {
        max_input_bytes: upper.input_bytes,
        max_candidate_visits: upper.candidate_visits.min(public.max_match_events),
        max_continuation_steps: upper.continuation_steps,
        max_source_accesses: upper.source_accesses,
        max_random_access_bytes: upper
            .random_access_bytes
            .min(public.max_random_access_bytes),
        max_sequential_bytes: upper.sequential_bytes.min(public.max_sequential_bytes),
        max_work: upper.work.min(public.max_work),
        max_count: upper.count.min(public_count),
        max_queue_entries: upper.queue_entries,
        max_frontier_entries: upper.frontier_entries,
        max_allocations: upper.allocations,
        max_scratch_bytes: upper.scratch_bytes,
        max_peak_bytes: upper.peak_bytes.min(public.max_peak_bytes),
    }
}

fn required_internal_anchor_execution_accounting(
    actual: RequiredInternalAnchorCountActual,
) -> Result<ExecutionAccounting, Error> {
    let matches = usize::try_from(actual.matches).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::OutputMatches,
    })?;
    Ok(ExecutionAccounting {
        transition_checks: actual.continuation_steps,
        root_probes: actual.candidate_visits,
        successful_paths: matches,
        emitted_matches: matches,
        sequential_bytes_read: actual.sequential_bytes,
        random_access_bytes_read: actual.random_access_bytes,
        peak_bytes: actual.peak_bytes,
        work: actual.work,
        required_anchor_candidates: actual.candidate_visits,
        required_anchor_scan_windows: actual.anchor_window_attempts,
        required_anchor_anchor_comparisons: actual.finder_source_accesses,
        required_anchor_prefix_steps: actual.prefix_steps,
        required_anchor_continuation_steps: actual.continuation_steps,
        required_anchor_source_accesses: actual.source_accesses,
        required_anchor_queue_peak: actual.queue_entries,
        required_anchor_frontier_peak: actual.frontier_entries,
        ..ExecutionAccounting::default()
    })
}

fn map_required_anchor_error(error: &RequiredInternalAnchorCountError) -> Error {
    match error {
        RequiredInternalAnchorCountError::Overflow(_) => Error::ArithmeticOverflow {
            resource: Resource::ExecutionWork,
        },
        RequiredInternalAnchorCountError::Resource { .. }
        | RequiredInternalAnchorCountError::CountResource { .. }
        | RequiredInternalAnchorCountError::AccountingInvariant { .. } => {
            Error::InternalInvariant("required internal-anchor admission diverged from preflight")
        }
        _ => Error::InternalInvariant("unclassified required internal-anchor execution refusal"),
    }
}

fn preflight_unicode_word_utf8_bytes(
    program: &Program,
    haystack_len: usize,
    limits: OperationLimits,
) -> Result<usize, Error> {
    if !program.contains_unicode_word_boundary() {
        return Ok(0);
    }
    let bytes = haystack_len;
    enforce(bytes, limits.max_work, Resource::ExecutionWork)?;
    enforce(
        bytes,
        limits.max_sequential_bytes,
        Resource::SequentialBytes,
    )?;
    Ok(bytes)
}

fn validate_unicode_word_utf8(
    haystack: &[u8],
    bytes: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    if bytes == 0 {
        return Ok(());
    }
    accounting.utf8_validation_work = bytes;
    accounting.work = bytes;
    accounting.sequential_bytes_read = bytes;
    if core::str::from_utf8(haystack).is_err() {
        return Err(Error::InvalidUtf8ForUnicodeWordBoundary);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RequiredLiteralScan {
    source_bytes: usize,
    comparisons: usize,
    all_present: bool,
}

impl RequiredLiteralScan {
    fn prospective(source_bytes: usize, sets: RequiredLiteralSets) -> Result<Self, Error> {
        let set_count = sets.len();
        let service_bytes = mul(
            source_bytes,
            sets.source_passes(),
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            source_bytes: service_bytes,
            comparisons: mul(source_bytes, set_count, Resource::ExecutionWork)?,
            all_present: false,
        })
    }

    fn work(self) -> Result<usize, Error> {
        add(self.source_bytes, self.comparisons, Resource::ExecutionWork)
    }
}

fn scan_required_literals(
    compiled: &CompiledRegex,
    haystack: &[u8],
    accounting: &mut ExecutionAccounting,
) -> Result<RequiredLiteralScan, Error> {
    let set_count = compiled.required_literals.len();
    if set_count == 0 {
        return Ok(RequiredLiteralScan {
            all_present: true,
            ..RequiredLiteralScan::default()
        });
    }
    if compiled.required_literals.uses_bounded_native_services() {
        let mut source_bytes = 0_usize;
        let mut comparisons = 0_usize;
        let mut all_present = true;
        for set in compiled.required_literals.iter() {
            let (present, scanned) = scan_small_required_literal_set(set, haystack)?;
            source_bytes = add(source_bytes, scanned, Resource::SequentialBytes)?;
            comparisons = add(comparisons, scanned, Resource::ExecutionWork)?;
            if !present {
                all_present = false;
                break;
            }
        }
        let observed = RequiredLiteralScan {
            source_bytes,
            comparisons,
            all_present,
        };
        record_required_literal_scan(accounting, observed)?;
        return Ok(observed);
    }
    let all_seen = (1_u8 << set_count).wrapping_sub(1);
    let mut seen = 0_u8;
    let mut source_bytes = 0_usize;
    let mut comparisons = 0_usize;
    for &byte in haystack {
        source_bytes = add(source_bytes, 1, Resource::SequentialBytes)?;
        for (index, set) in compiled.required_literals.iter().enumerate() {
            comparisons = add(comparisons, 1, Resource::ExecutionWork)?;
            if byte.is_ascii() && set & (1_u128 << byte) != 0 {
                seen |= 1_u8 << index;
            }
        }
        if seen == all_seen {
            break;
        }
    }
    let observed = RequiredLiteralScan {
        source_bytes,
        comparisons,
        all_present: seen == all_seen,
    };
    record_required_literal_scan(accounting, observed)?;
    Ok(observed)
}

fn scan_small_required_literal_set(set: u128, haystack: &[u8]) -> Result<(bool, usize), Error> {
    let mut remaining = set;
    let mut bytes = [0_u8; 3];
    let mut len = 0_usize;
    while remaining != 0 {
        let byte = u8::try_from(remaining.trailing_zeros())
            .map_err(|_| Error::InternalInvariant("ASCII required literal exceeds one byte"))?;
        let slot = bytes.get_mut(len).ok_or(Error::InternalInvariant(
            "small required-literal set exceeded three bytes",
        ))?;
        *slot = byte;
        len = add(len, 1, Resource::ExecutionWork)?;
        remaining &= remaining.saturating_sub(1);
    }
    let position = match bytes[..len] {
        [first] => memchr::memchr(first, haystack),
        [first, second] => memchr::memchr2(first, second, haystack),
        [first, second, third] => memchr::memchr3(first, second, third, haystack),
        _ => {
            return Err(Error::InternalInvariant(
                "small required-literal set is empty or oversized",
            ));
        }
    };
    let scanned = match position {
        Some(position) => add(position, 1, Resource::SequentialBytes)?,
        None => haystack.len(),
    };
    Ok((position.is_some(), scanned))
}

fn record_required_literal_scan(
    accounting: &mut ExecutionAccounting,
    observed: RequiredLiteralScan,
) -> Result<(), Error> {
    let work = observed.work()?;
    accounting.required_literal_source_bytes = add(
        accounting.required_literal_source_bytes,
        observed.source_bytes,
        Resource::ExecutionWork,
    )?;
    accounting.required_literal_comparisons = add(
        accounting.required_literal_comparisons,
        observed.comparisons,
        Resource::ExecutionWork,
    )?;
    accounting.sequential_bytes_read = add(
        accounting.sequential_bytes_read,
        observed.source_bytes,
        Resource::SequentialBytes,
    )?;
    accounting.work = add(accounting.work, work, Resource::ExecutionWork)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanSummary {
    matches: usize,
    events: usize,
    suppressed: usize,
    span_sum: usize,
}

impl ScanSummary {
    const fn empty() -> Self {
        Self {
            matches: 0,
            events: 0,
            suppressed: 0,
            span_sum: 0,
        }
    }
}

struct ExecutionResult {
    certificate: OperationCertificate,
    accounting: ExecutionAccounting,
    summary: ScanSummary,
    spans: Vec<Span>,
}

#[derive(Clone, Copy)]
enum SparseSeed<'a> {
    RequiredSuffixes(&'a RequiredSuffixes),
    TerminalFrontier(&'a TerminalFrontierSeed),
}

#[derive(Clone, Copy, Debug)]
struct Requirements {
    table_cells: usize,
    row_storage: Option<RowStorage>,
    record_bytes: usize,
    requested_log_bytes: usize,
    random_access_bound: usize,
    scratch_bound: usize,
    peak_bound: usize,
    sequential_bound: usize,
    allocations: usize,
    work_bound: usize,
    terminal_frontier: bool,
    frontier: Option<terminal_frontier::FrontierRequirements>,
    cached_frontier: Option<CachedFrontierRequirements>,
    cache_attempt_work: usize,
}

impl Requirements {
    fn operation_allocation_bound(self, kind: OperationKind) -> Result<usize, Error> {
        self.allocations
            .checked_add(usize::from(kind == OperationKind::Spans))
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::Allocations,
            })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete prospective receipt is assembled in one auditable accounting scope"
    )]
    fn operation_prospective(
        self,
        program: &Program,
        boundaries: usize,
        utf8_validation: usize,
        required_literal_scan: RequiredLiteralScan,
        kind: OperationKind,
        minimum_match_bytes: Option<usize>,
    ) -> Result<OperationProspective, Error> {
        let input_bytes = boundaries.checked_sub(1).ok_or(Error::InternalInvariant(
            "operation prospective requires the terminal input boundary",
        ))?;
        let event_passes = if kind == OperationKind::Spans { 2 } else { 1 };
        let nonempty_span_matches = match (kind, minimum_match_bytes) {
            (OperationKind::Spans, Some(minimum)) if minimum > 0 => Some(
                input_bytes
                    .checked_div(minimum)
                    .ok_or(Error::InternalInvariant(
                        "positive minimum match width rejected checked division",
                    ))?,
            ),
            _ => None,
        };
        // The public event limit applies independently to each complete
        // selector pass. A construction-authenticated positive minimum
        // tightens non-overlapping Spans to floor(N / minimum); nullable and
        // non-Spans operations retain the pre-existing boundary envelope.
        let match_events = if let Some(matches) = nonempty_span_matches {
            matches
        } else {
            mul(boundaries, 2, Resource::MatchEvents)?
        };
        let accounting_match_events = mul(match_events, event_passes, Resource::MatchEvents)?;
        let output_matches = nonempty_span_matches.unwrap_or(boundaries);
        let output_bytes = if kind == OperationKind::Spans {
            mul(
                output_matches,
                core::mem::size_of::<Span>(),
                Resource::OutputBytes,
            )?
        } else {
            0
        };
        let span_sum = if kind == OperationKind::Sum {
            input_bytes
        } else {
            0
        };
        let allocations = self.operation_allocation_bound(kind)?;
        let peak_bytes = if kind == OperationKind::Spans {
            if let Some(cache) = self.cached_frontier {
                cache.peak_bytes.max(add(
                    cache.replay_bytes()?,
                    output_bytes,
                    Resource::PeakBytes,
                )?)
            } else if self.row_storage.is_some() {
                self.peak_bound.max(add(
                    self.requested_log_bytes,
                    output_bytes,
                    Resource::PeakBytes,
                )?)
            } else {
                // Full-table selection retains the table while publishing
                // output, unlike the reverse-row and cached-frontier routes
                // whose construction scratch is gone before replay.
                add(self.peak_bound, output_bytes, Resource::PeakBytes)?
            }
        } else {
            self.peak_bound
        };
        let work = self.work_bound;
        // Every generic logical source service is paired with admitted work;
        // byte/scalar/assertion services inspect at most eight bytes per
        // charged unit (two adjacent four-byte UTF-8 scalars).
        // Intrinsic receipt derivation deliberately uses `usize::MAX` as the
        // caller-independent observed-work ceiling. Saturation is still a
        // conservative componentwise upper bound and cannot understate A.
        let random_access_bytes_read = work.saturating_mul(8);
        let accounting = ExecutionAccounting {
            state_evaluations: work,
            transition_checks: work,
            assertion_checks: work,
            root_probes: work,
            required_literal_source_bytes: required_literal_scan.source_bytes,
            required_literal_comparisons: required_literal_scan.comparisons,
            required_anchor_candidates: 0,
            required_anchor_scan_windows: 0,
            required_anchor_anchor_comparisons: 0,
            required_anchor_prefix_steps: 0,
            required_anchor_continuation_steps: 0,
            required_anchor_source_accesses: 0,
            required_anchor_queue_peak: 0,
            required_anchor_frontier_peak: 0,
            url_segments: 0,
            url_dot_probes: 0,
            url_tld_transitions: 0,
            url_tld_candidates: 0,
            url_scheme_probes: 0,
            url_ipv4_candidates: 0,
            url_prefix_steps: 0,
            url_suffix_steps: 0,
            url_candidate_insertions: 0,
            url_candidate_visits: 0,
            replay_steps: work,
            successful_paths: accounting_match_events,
            suppressed_empty: if nonempty_span_matches.is_some() {
                0
            } else {
                accounting_match_events
            },
            emitted_matches: output_matches,
            utf8_validation_work: utf8_validation,
            frontier_peak_states: work,
            frontier_insertions: work,
            frontier_evaluations: work,
            frontier_source_bytes: self.sequential_bound,
            frontier_bytes: self.random_access_bound,
            frontier_bookkeeping: work,
            sequential_bytes_written: self.sequential_bound,
            sequential_bytes_read: self.sequential_bound,
            random_access_bytes_read,
            random_access_peak_bytes: self.random_access_bound,
            scratch_peak_bytes: self.scratch_bound,
            log_bytes: self.requested_log_bytes,
            output_bytes,
            peak_bytes,
            work,
        };
        Ok(OperationProspective {
            states: program.insts.len(),
            boundaries,
            table_cells: self.table_cells,
            row_storage: self.row_storage,
            row_record_bytes: self.record_bytes,
            terminal_frontier: self.terminal_frontier,
            work_bound: self.work_bound,
            random_access_bytes: self.random_access_bound,
            scratch_bytes: self.scratch_bound,
            log_bytes: self.requested_log_bytes,
            sequential_bytes: self.sequential_bound,
            match_events,
            output_matches,
            output_bytes,
            span_sum,
            allocations,
            peak_bytes,
            accounting,
        })
    }

    fn new_for_seed(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
        seed: SparseSeed<'_>,
    ) -> Result<Self, Error> {
        match seed {
            SparseSeed::RequiredSuffixes(_) => {
                Self::new_sparse(program, boundaries, strategy, passes, limits)
            }
            SparseSeed::TerminalFrontier(_) => {
                let SparseSeed::TerminalFrontier(seed) = seed else {
                    return Err(Error::InternalInvariant("terminal seed changed variant"));
                };
                Self::new_terminal_frontier(program, boundaries, strategy, passes, seed, limits)
            }
        }
    }

    fn with_prefix<const OBSERVED_WORK: bool>(
        mut self,
        work: usize,
        sequential_bytes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        self.work_bound = add(self.work_bound, work, Resource::ExecutionWork)?;
        if !OBSERVED_WORK {
            enforce(self.work_bound, limits.max_work, Resource::ExecutionWork)?;
        }
        self.sequential_bound = add(
            self.sequential_bound,
            sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(
            self.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        Ok(self)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each storage strategy keeps its exact work and byte bounds beside admission"
    )]
    fn new<const OBSERVED_WORK: bool>(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        let states = program.insts.len();
        let per_boundary = add(
            program.execution_state_work(),
            usize::from(program.contains_scalar_transition()),
            Resource::ExecutionWork,
        )?;
        let build_work = mul(per_boundary, boundaries, Resource::ExecutionWork)?;
        let scan_base = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let (
            table_cells,
            row_storage,
            record_bytes,
            random,
            scratch,
            log,
            sequential,
            replay,
            allocations,
        ) = match strategy {
            Strategy::FullTable => {
                let cells = mul(states, boundaries, Resource::TableCells)?;
                enforce(cells, limits.max_table_cells, Resource::TableCells)?;
                let bytes = mul(
                    cells,
                    core::mem::size_of::<usize>(),
                    Resource::RandomAccessBytes,
                )?;
                (
                    cells,
                    None,
                    0,
                    bytes,
                    bytes,
                    0,
                    0,
                    0,
                    usize::from(cells != 0),
                )
            }
            Strategy::ReverseSequentialRows => {
                let rows = ReverseRowRequirements::new(program, boundaries, passes)?;
                (
                    0,
                    Some(rows.storage),
                    rows.record_bytes,
                    rows.row_bytes,
                    rows.row_bytes,
                    rows.log_bytes,
                    rows.sequential_bound,
                    rows.replay_bound,
                    usize::from(rows.log_bytes != 0)
                        .checked_add(usize::from(states != 0).saturating_mul(2))
                        .ok_or(Error::ArithmeticOverflow {
                            resource: Resource::Allocations,
                        })?,
                )
            }
        };
        enforce(
            random,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(scratch, limits.max_scratch_bytes, Resource::ScratchBytes)?;
        enforce(log, limits.max_log_bytes, Resource::LogBytes)?;
        let peak = add(log, scratch, Resource::PeakBytes)?;
        enforce(
            sequential,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        let work_bound = add(
            add(build_work, scan_base, Resource::ExecutionWork)?,
            replay,
            Resource::ExecutionWork,
        )?;
        if !OBSERVED_WORK {
            enforce(work_bound, limits.max_work, Resource::ExecutionWork)?;
        }
        Ok(Self {
            table_cells,
            row_storage,
            record_bytes,
            requested_log_bytes: log,
            random_access_bound: random,
            scratch_bound: scratch,
            peak_bound: peak,
            sequential_bound: sequential,
            allocations,
            work_bound,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    fn new_ordered_root<const OBSERVED_WORK: bool>(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows
            || program.root_alternation_arms() < 2
            || program.root_split_count().checked_add(1) != Some(program.root_alternation_arms())
        {
            return Err(Error::InternalInvariant(
                "ordered-root row requirements lack root metadata",
            ));
        }
        let rows = ReverseRowRequirements::new_ordered_root(program, boundaries, passes)?;
        enforce(
            rows.row_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            rows.row_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(rows.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            rows.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        let peak = add(rows.log_bytes, rows.row_bytes, Resource::PeakBytes)?;
        enforce(peak, limits.max_peak_bytes, Resource::PeakBytes)?;

        let skipped = mul(program.root_split_count(), 3, Resource::ExecutionWork)?;
        let ordinary_without_root =
            program
                .execution_state_work()
                .checked_sub(skipped)
                .ok_or(Error::InternalInvariant(
                    "ordered-root work exceeds certified program work",
                ))?;
        let state_work = add(
            ordinary_without_root,
            program.root_alternation_arms(),
            Resource::ExecutionWork,
        )?;
        let per_boundary = add(
            state_work,
            usize::from(program.contains_scalar_transition()),
            Resource::ExecutionWork,
        )?;
        let build_work = mul(per_boundary, boundaries, Resource::ExecutionWork)?;
        let scan_work = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let work_bound = add(build_work, scan_work, Resource::ExecutionWork)?;
        if !OBSERVED_WORK {
            enforce(work_bound, limits.max_work, Resource::ExecutionWork)?;
        }
        let allocations = usize::from(rows.log_bytes != 0)
            .checked_add(usize::from(!program.insts.is_empty()).saturating_mul(2))
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::Allocations,
            })?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            random_access_bound: rows.row_bytes,
            scratch_bound: rows.row_bytes,
            peak_bound: peak,
            sequential_bound: rows.sequential_bound,
            allocations,
            work_bound,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    fn cached(
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Option<Self>, Error> {
        let cache = CachedFrontierRequirements::new(program.insts.len(), boundaries, passes)?;
        // A caller using observed-work admission can legitimately set its
        // limit below the cache's fixed initialization cost while the dense
        // executor still fits at its exact observed charge. In that case the
        // cache is not an admissible alternative: selecting it would replace
        // a successful exact-limit replay with a larger resource refusal.
        if cache.initialization_work()? > limits.max_work {
            return Ok(None);
        }
        Ok(cache.fits(limits)?.then_some(Self {
            table_cells: 0,
            row_storage: None,
            record_bytes: cache.record_bytes,
            requested_log_bytes: cache.log_bytes,
            random_access_bound: cache.random_bytes,
            scratch_bound: cache.scratch_bytes,
            peak_bound: cache.peak_bytes,
            sequential_bound: cache.sequential_bound,
            allocations: cache.allocations(),
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: Some(cache),
            cache_attempt_work: 1,
        }))
    }

    fn new_cached<const OBSERVED_WORK: bool>(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if let Some(requirements) = Self::cached(program, boundaries, passes, limits)? {
            return Ok(requirements);
        }
        Self::new::<OBSERVED_WORK>(program, boundaries, strategy, passes, limits)
    }

    fn new_forced_cached(
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        let cache = CachedFrontierRequirements::new(program.insts.len(), boundaries, passes)?;
        cache.enforce(limits)?;
        enforce(
            cache.initialization_work()?,
            limits.max_work,
            Resource::ExecutionWork,
        )?;
        Ok(Self {
            table_cells: 0,
            row_storage: None,
            record_bytes: cache.record_bytes,
            requested_log_bytes: cache.log_bytes,
            random_access_bound: cache.random_bytes,
            scratch_bound: cache.scratch_bytes,
            peak_bound: cache.peak_bytes,
            sequential_bound: cache.sequential_bound,
            allocations: cache.allocations(),
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: Some(cache),
            cache_attempt_work: 1,
        })
    }

    fn new_session_cached(
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        let cache = CachedFrontierRequirements::new(program.insts.len(), boundaries, passes)?;
        cache.enforce(limits)?;
        Ok(Self {
            table_cells: 0,
            row_storage: None,
            record_bytes: cache.record_bytes,
            requested_log_bytes: cache.log_bytes,
            random_access_bound: cache.random_bytes,
            scratch_bound: cache.scratch_bytes,
            peak_bound: cache.peak_bytes,
            sequential_bound: cache.sequential_bound,
            // Every buffer is constructed before the operation boundary.
            allocations: 0,
            // Individual cache charges remain observed against this exact
            // caller ceiling; only fixed construction initialization is gone.
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: Some(cache),
            cache_attempt_work: 1,
        })
    }

    fn new_cached_after_refusal(
        refusal: Error,
        program: &Program,
        boundaries: usize,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        Self::cached(program, boundaries, passes, limits)?.ok_or(refusal)
    }

    fn new_sparse(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows {
            return Err(Error::InternalInvariant(
                "sparse continuation requires reverse sequential rows",
            ));
        }
        let rows = ReverseRowRequirements::new(program, boundaries, passes)?;
        enforce(
            rows.row_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            rows.row_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(rows.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        let peak = add(rows.log_bytes, rows.row_bytes, Resource::PeakBytes)?;
        let allocations = usize::from(rows.log_bytes != 0)
            .checked_add(usize::from(!program.insts.is_empty()))
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::Allocations,
            })?;
        enforce(
            rows.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            random_access_bound: rows.row_bytes,
            scratch_bound: rows.row_bytes,
            peak_bound: peak,
            sequential_bound: rows.sequential_bound,
            allocations,
            // Sparse construction charges every observed unit before it is
            // performed, so the caller's limit is its explicit admission cap.
            work_bound: limits.max_work,
            terminal_frontier: false,
            frontier: None,
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    fn new_terminal_frontier(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        seed: &TerminalFrontierSeed,
        limits: OperationLimits,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows {
            return Err(Error::InternalInvariant(
                "terminal frontier requires reverse sequential rows",
            ));
        }
        let rows = ReverseRowRequirements::new_terminal_frontier(program, boundaries, passes)?;
        let scan_work = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let post_build_work = add(scan_work, rows.replay_bound, Resource::ExecutionWork)?;
        let frontier = terminal_frontier::requirements(
            program,
            seed,
            boundaries,
            rows.log_bytes,
            post_build_work,
            limits,
        )?;
        enforce(
            frontier.bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            frontier.bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(rows.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        let source = frontier.source_bytes_bound;
        let sequential = add(rows.sequential_bound, source, Resource::SequentialBytes)?;
        enforce(
            sequential,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(
            add(rows.log_bytes, frontier.bytes, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;
        let peak = add(rows.log_bytes, frontier.bytes, Resource::PeakBytes)?;
        let allocations = terminal_frontier::allocation_count(program, rows.log_bytes)?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            random_access_bound: frontier.bytes,
            scratch_bound: frontier.bytes,
            peak_bound: peak,
            sequential_bound: sequential,
            allocations,
            work_bound: limits.max_work,
            terminal_frontier: true,
            frontier: Some(frontier),
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }

    /// Construct one caller-independent terminal-frontier envelope
    /// for a receipt-bearing Count. All retained shape and work bounds derive
    /// only from the compiled proof, program, and input length; caller limits
    /// are enforced later against the published prospective before source.
    fn new_terminal_frontier_prospective(
        program: &Program,
        boundaries: usize,
        strategy: Strategy,
        passes: usize,
        seed: &TerminalFrontierSeed,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows {
            return Err(Error::InternalInvariant(
                "terminal frontier requires reverse sequential rows",
            ));
        }
        let rows = ReverseRowRequirements::new_terminal_frontier(program, boundaries, passes)?;
        let scan_work = mul(
            mul(boundaries, 4, Resource::ExecutionWork)?,
            passes,
            Resource::ExecutionWork,
        )?;
        let post_build_work = add(scan_work, rows.replay_bound, Resource::ExecutionWork)?;
        let (frontier, work_bound) = terminal_frontier::receipt_requirements(
            program,
            seed,
            boundaries,
            rows.log_bytes,
            post_build_work,
        )?;
        let source = frontier.source_bytes_bound;
        let sequential = add(rows.sequential_bound, source, Resource::SequentialBytes)?;
        let peak = add(rows.log_bytes, frontier.bytes, Resource::PeakBytes)?;
        let allocations = terminal_frontier::allocation_count(program, rows.log_bytes)?;
        Ok(Self {
            table_cells: 0,
            row_storage: Some(rows.storage),
            record_bytes: rows.record_bytes,
            requested_log_bytes: rows.log_bytes,
            random_access_bound: frontier.bytes,
            scratch_bound: frontier.bytes,
            peak_bound: peak,
            sequential_bound: sequential,
            allocations,
            work_bound,
            terminal_frontier: true,
            frontier: Some(frontier),
            cached_frontier: None,
            cache_attempt_work: 0,
        })
    }
}

const MAX_CACHED_FRONTIERS: usize = 4_096;
const MAX_CACHED_TRANSITIONS: usize = 65_536;
const CACHED_TRANSITION_SLOTS: usize = MAX_CACHED_TRANSITIONS * 2;
const UNCACHED_FRONTIER: u16 = u16::MAX;

fn cached_frontier_words(states: usize) -> Result<usize, Error> {
    add(states, 63, Resource::ScratchBytes)?
        .checked_div(64)
        .ok_or(Error::InternalInvariant("zero cached-frontier word width"))
}

/// Prospective fixed-capacity theorem for the interned Boolean-frontier
/// executor. Every retained cache image owns exactly `ceil(Q / 64)` Boolean
/// words, the transition table has twice the maximum installed entries, and
/// every boundary owns one `u16` image ID or an uncached sentinel. A sentinel
/// is recomputed from the next retained checkpoint during replay, making both
/// caches best-effort accelerators: filling either one cannot change semantics
/// or cause a cache-capacity refusal. No allocation depends on cache hits,
/// collisions, or input contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedFrontierRequirements {
    words: usize,
    record_bytes: usize,
    state_word_capacity: usize,
    boundary_count: usize,
    log_bytes: usize,
    random_bytes: usize,
    scratch_bytes: usize,
    peak_bytes: usize,
    sequential_bound: usize,
}

impl CachedFrontierRequirements {
    fn session_footprint(self) -> CachedCountSessionFootprint {
        CachedCountSessionFootprint {
            allocations: self.allocations(),
            boundary_bytes: self.log_bytes,
            cache_bytes: self.random_bytes,
            sequential_bytes: self.sequential_bound,
            retained_bytes: self.peak_bytes,
        }
    }

    fn allocations(self) -> usize {
        [
            self.boundary_count,
            self.state_word_capacity,
            MAX_CACHED_FRONTIERS,
            CACHED_TRANSITION_SLOTS,
            self.words,
            self.words,
        ]
        .into_iter()
        .filter(|length| *length != 0)
        .count()
    }

    fn new(states: usize, boundaries: usize, passes: usize) -> Result<Self, Error> {
        let words = cached_frontier_words(states)?;
        let record_bytes = core::mem::size_of::<u16>();
        let state_word_capacity = mul(words, MAX_CACHED_FRONTIERS, Resource::ScratchBytes)?;
        let state_bytes = mul(
            state_word_capacity,
            core::mem::size_of::<u64>(),
            Resource::RandomAccessBytes,
        )?;
        let hash_bytes = mul(
            MAX_CACHED_FRONTIERS,
            core::mem::size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let transition_bytes = mul(
            CACHED_TRANSITION_SLOTS,
            core::mem::size_of::<CachedTransitionSlot>(),
            Resource::ScratchBytes,
        )?;
        let candidate_bytes = mul(
            mul(words, 2, Resource::ScratchBytes)?,
            core::mem::size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let phase_scratch_bytes = add(
            add(hash_bytes, transition_bytes, Resource::ScratchBytes)?,
            candidate_bytes,
            Resource::ScratchBytes,
        )?;
        let random_bytes = add(
            state_bytes,
            phase_scratch_bytes,
            Resource::RandomAccessBytes,
        )?;
        let scratch_bytes = random_bytes;
        let log_bytes = mul(boundaries, record_bytes, Resource::LogBytes)?;
        let peak_bytes = add(log_bytes, random_bytes, Resource::PeakBytes)?;
        let read_passes = mul(passes, 3, Resource::SequentialBytes)?;
        let sequential_bound = mul(
            log_bytes,
            add(read_passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            words,
            record_bytes,
            state_word_capacity,
            boundary_count: boundaries,
            log_bytes,
            random_bytes,
            scratch_bytes,
            peak_bytes,
            sequential_bound,
        })
    }

    fn enforce(self, limits: OperationLimits) -> Result<(), Error> {
        enforce(
            self.random_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            self.scratch_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(self.log_bytes, limits.max_log_bytes, Resource::LogBytes)?;
        enforce(
            self.sequential_bound,
            limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        enforce(self.peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)
    }

    fn fits(self, limits: OperationLimits) -> Result<bool, Error> {
        match self.enforce(limits) {
            Ok(()) => Ok(true),
            Err(Error::ResourceLimit {
                resource:
                    Resource::RandomAccessBytes
                    | Resource::ScratchBytes
                    | Resource::LogBytes
                    | Resource::SequentialBytes
                    | Resource::PeakBytes,
                ..
            }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn initialization_work(self) -> Result<usize, Error> {
        let initialized = add(
            add(
                add(
                    self.boundary_count,
                    self.state_word_capacity,
                    Resource::ExecutionWork,
                )?,
                MAX_CACHED_FRONTIERS,
                Resource::ExecutionWork,
            )?,
            add(
                CACHED_TRANSITION_SLOTS,
                mul(self.words, 2, Resource::ExecutionWork)?,
                Resource::ExecutionWork,
            )?,
            Resource::ExecutionWork,
        )?;
        add(initialized, 6, Resource::ExecutionWork)
    }

    fn replay_bytes(self) -> Result<usize, Error> {
        add(
            add(
                self.log_bytes,
                mul(
                    self.state_word_capacity,
                    core::mem::size_of::<u64>(),
                    Resource::PeakBytes,
                )?,
                Resource::PeakBytes,
            )?,
            mul(
                mul(self.words, 2, Resource::PeakBytes)?,
                core::mem::size_of::<u64>(),
                Resource::PeakBytes,
            )?,
            Resource::PeakBytes,
        )
    }
}

impl CachedCountSession {
    /// Exact source-free storage retained by this session.
    #[must_use]
    pub const fn footprint(&self) -> CachedCountSessionFootprint {
        self.footprint
    }

    /// Exact haystack length bound at construction.
    #[must_use]
    pub const fn haystack_len(&self) -> usize {
        self.haystack_len
    }

    fn validate(
        &self,
        regex: &CompiledRegex,
        haystack_len: usize,
        limits: OperationLimits,
    ) -> Result<(), Error> {
        if self.plan_id != regex.plan_id() {
            return Err(Error::SessionPlanMismatch);
        }
        if self.haystack_len != haystack_len {
            return Err(Error::SessionHaystackLengthMismatch {
                expected: self.haystack_len,
                actual: haystack_len,
            });
        }
        if self.limits_id != operation_limits_identity(limits) {
            return Err(Error::SessionLimitsMismatch);
        }
        Ok(())
    }
}

impl CompiledRegex {
    fn cached_count_session_requirements(
        &self,
        haystack_len: usize,
    ) -> Result<Option<CachedFrontierRequirements>, Error> {
        if self.program.contains_scalar_transition() {
            return Ok(None);
        }
        let boundaries = add(haystack_len, 1, Resource::Boundaries)?;
        CachedFrontierRequirements::new(self.program.insts.len(), boundaries, 1).map(Some)
    }

    /// Return the exact source-free storage and traffic envelope for a
    /// caller-owned cached Count session.
    ///
    /// Only byte-transition programs are eligible. Assertions are included in
    /// each source-derived transition symbol. This method performs no
    /// allocation and does not observe source bytes.
    pub fn cached_count_session_footprint(
        &self,
        haystack_len: usize,
    ) -> Result<Option<CachedCountSessionFootprint>, Error> {
        Ok(self
            .cached_count_session_requirements(haystack_len)?
            .map(CachedFrontierRequirements::session_footprint))
    }

    /// Construct a caller-owned cache for repeated full-haystack Count
    /// operations over one exact byte length and policy.
    ///
    /// Only byte-transition programs are eligible. Unsupported program shapes
    /// and policies return `Ok(None)` without observing source bytes.
    /// Allocation failure while creating an otherwise eligible fixed cache is
    /// a typed construction error.
    pub fn cached_count_session(
        &self,
        haystack_len: usize,
        limits: OperationLimits,
    ) -> Result<Option<CachedCountSession>, Error> {
        let Some(requirements) = self.cached_count_session_requirements(haystack_len)? else {
            return Ok(None);
        };
        if requirements.boundary_count > limits.max_boundaries || !requirements.fits(limits)? {
            return Ok(None);
        }
        let footprint = requirements.session_footprint();
        Ok(Some(CachedCountSession {
            plan_id: self.plan_id(),
            haystack_len,
            limits_id: operation_limits_identity(limits),
            footprint,
            cache: CachedFrontierStore::allocate_session(requirements)?,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct ReverseRowRequirements {
    storage: RowStorage,
    record_bytes: usize,
    row_bytes: usize,
    log_bytes: usize,
    sequential_bound: usize,
    replay_bound: usize,
}

impl ReverseRowRequirements {
    fn new(program: &Program, boundaries: usize, passes: usize) -> Result<Self, Error> {
        let bits = add(program.split_count, 1, Resource::LogBytes)?;
        let decision_record = ceil_div(bits, 8)?;
        let endpoint_record = encoded_width(boundaries);
        // Equal widths keep the established split/replay certificate. The
        // endpoint form is selected only when it strictly reduces the bounded
        // log, containing this construction change to the refusal it solves.
        let (storage, record_bytes, replay_bound) = if endpoint_record < decision_record {
            (RowStorage::ReachableEndpoints, endpoint_record, 0)
        } else {
            let replay_factor = add(
                4,
                program.max_scalar_search_checks(),
                Resource::ExecutionWork,
            )?;
            let replay = mul(
                mul(
                    mul(program.insts.len(), boundaries, Resource::ExecutionWork)?,
                    replay_factor,
                    Resource::ExecutionWork,
                )?,
                passes,
                Resource::ExecutionWork,
            )?;
            (RowStorage::SplitDecisions, decision_record, replay)
        };
        let log_bytes = mul(record_bytes, boundaries, Resource::LogBytes)?;
        let row_words = mul(program.insts.len(), 2, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let sequential_bound = mul(
            log_bytes,
            add(passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            storage,
            record_bytes,
            row_bytes,
            log_bytes,
            sequential_bound,
            replay_bound,
        })
    }

    fn new_terminal_frontier(
        program: &Program,
        boundaries: usize,
        passes: usize,
    ) -> Result<Self, Error> {
        // The frontier has already selected the exact ordered endpoint for
        // every boundary. Retain that endpoint directly: replaying split
        // decisions would re-walk every program state at every boundary and
        // discard the frontier's prospective candidate bound.
        let record_bytes = encoded_width(boundaries);
        let log_bytes = mul(record_bytes, boundaries, Resource::LogBytes)?;
        let row_words = mul(program.insts.len(), 2, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let sequential_bound = mul(
            log_bytes,
            add(passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            storage: RowStorage::ReachableEndpoints,
            record_bytes,
            row_bytes,
            log_bytes,
            sequential_bound,
            replay_bound: 0,
        })
    }

    fn new_ordered_root(
        program: &Program,
        boundaries: usize,
        passes: usize,
    ) -> Result<Self, Error> {
        if program.root_alternation_arms() < 2
            || program.root_split_count().checked_add(1) != Some(program.root_alternation_arms())
        {
            return Err(Error::InternalInvariant(
                "ordered-root row requirements lack root metadata",
            ));
        }
        let record_bytes = encoded_width(boundaries);
        let log_bytes = mul(record_bytes, boundaries, Resource::LogBytes)?;
        let row_words = mul(program.insts.len(), 2, Resource::RandomAccessBytes)?;
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let sequential_bound = mul(
            log_bytes,
            add(passes, 1, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?;
        Ok(Self {
            storage: RowStorage::ReachableEndpoints,
            record_bytes,
            row_bytes,
            log_bytes,
            sequential_bound,
            replay_bound: 0,
        })
    }
}

enum Engine<'session> {
    Full(FullTable),
    Rows(RowStore),
    SparseRows(RowStore),
    TerminalFrontier(RowStore),
    CachedFrontiers(CachedFrontierStore),
    SessionCachedFrontiers(&'session mut CachedFrontierStore),
}

impl<'session> Engine<'session> {
    #[allow(
        clippy::too_many_arguments,
        reason = "engine construction binds the exact program, range, selected route, limits, and accounting"
    )]
    fn build<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        strategy: Strategy,
        requirements: Requirements,
        sparse_seed: Option<SparseSeed<'_>>,
        limits: OperationLimits,
        track_source: bool,
        fully_admitted_work: bool,
        session_cache: Option<&'session mut CachedFrontierStore>,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        if requirements.cache_attempt_work != 0 {
            try_charge_frontier_amount(
                accounting,
                requirements.work_bound,
                requirements.cache_attempt_work,
            )?;
        }
        if let Some(cache) = requirements.cached_frontier {
            if let Some(session_cache) = session_cache {
                session_cache.populate_session(
                    program,
                    haystack,
                    assertions,
                    requirements,
                    cache,
                    limits,
                    track_source,
                    accounting,
                )?;
                return Ok(Self::SessionCachedFrontiers(session_cache));
            }
            return CachedFrontierStore::build(
                program,
                haystack,
                assertions,
                requirements,
                cache,
                limits,
                track_source,
                accounting,
                actual_allocations,
            )
            .map(Self::CachedFrontiers);
        }
        match strategy {
            Strategy::FullTable => FullTable::build::<OBSERVED_WORK>(
                program,
                haystack,
                assertions,
                requirements,
                limits,
                track_source,
                accounting,
                actual_allocations,
            )
            .map(Self::Full),
            Strategy::ReverseSequentialRows => match sparse_seed {
                Some(SparseSeed::RequiredSuffixes(seed)) => {
                    RowStore::build_sparse::<OBSERVED_WORK>(
                        program,
                        haystack,
                        assertions,
                        requirements,
                        seed,
                        limits,
                        track_source,
                        accounting,
                        actual_allocations,
                    )
                    .map(Self::SparseRows)
                }
                Some(SparseSeed::TerminalFrontier(seed)) => {
                    terminal_frontier::build::<OBSERVED_WORK>(
                        program,
                        haystack,
                        assertions,
                        requirements,
                        seed,
                        limits,
                        accounting,
                        actual_allocations,
                    )
                    .map(Self::TerminalFrontier)
                }
                None => RowStore::build::<OBSERVED_WORK, false>(
                    program,
                    haystack,
                    assertions,
                    requirements,
                    limits,
                    track_source,
                    fully_admitted_work,
                    accounting,
                    actual_allocations,
                )
                .map(Self::Rows),
            },
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "ordered-root construction binds the proved program, exact range, limits, and receipt ledger"
    )]
    fn build_ordered_root<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        strategy: Strategy,
        requirements: Requirements,
        limits: OperationLimits,
        track_source: bool,
        fully_admitted_work: bool,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        if strategy != Strategy::ReverseSequentialRows
            || requirements.cached_frontier.is_some()
            || requirements.frontier.is_some()
            || program.root_alternation_arms() < 2
            || program.root_split_count().checked_add(1) != Some(program.root_alternation_arms())
        {
            return Err(Error::InternalInvariant(
                "ordered-root Count requires proved reverse rows",
            ));
        }
        RowStore::build::<OBSERVED_WORK, true>(
            program,
            haystack,
            assertions,
            requirements,
            limits,
            track_source,
            fully_admitted_work,
            accounting,
            actual_allocations,
        )
        .map(Self::Rows)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "structural and caller work limits stay explicit at the scan admission boundary"
    )]
    fn scan<const OBSERVED_WORK: bool>(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        track_source: bool,
        accounting: &mut ExecutionAccounting,
        mut emit: impl FnMut(Span) -> Result<(), Error>,
    ) -> Result<ScanSummary, Error> {
        match self {
            Self::Full(table) => scan_sequence::<OBSERVED_WORK>(
                haystack.len(),
                assertions.base(),
                accounting,
                admitted_work_bound,
                caller_work_limit,
                |start, _| table.selected(program, start),
                &mut emit,
            ),
            Self::Rows(store) => {
                let mut reader = store.reader();
                scan_sequence::<OBSERVED_WORK>(
                    haystack.len(),
                    assertions.base(),
                    accounting,
                    admitted_work_bound,
                    caller_work_limit,
                    |start, accounting| {
                        if reader.storage == RowStorage::ReachableEndpoints {
                            return reader.endpoint(start, accounting);
                        }
                        if !reader.root(start, accounting)? {
                            return Ok(None);
                        }
                        RowStore::replay::<OBSERVED_WORK>(
                            program,
                            haystack,
                            assertions,
                            start,
                            &mut reader,
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                            track_source,
                        )
                        .map(Some)
                    },
                    &mut emit,
                )
            }
            Self::SparseRows(store) | Self::TerminalFrontier(store) => {
                let mut reader = store.reader();
                scan_sequence_sparse(
                    haystack.len(),
                    assertions.base(),
                    accounting,
                    admitted_work_bound,
                    |start, accounting| {
                        if reader.storage == RowStorage::ReachableEndpoints {
                            return reader.endpoint(start, accounting);
                        }
                        if !reader.root(start, accounting)? {
                            return Ok(None);
                        }
                        RowStore::replay_sparse(
                            program,
                            haystack,
                            assertions,
                            start,
                            &mut reader,
                            accounting,
                            admitted_work_bound,
                            track_source,
                        )
                        .map(Some)
                    },
                    &mut emit,
                )
            }
            Self::CachedFrontiers(cache) => cache.scan(
                program,
                haystack,
                assertions,
                accounting,
                admitted_work_bound,
                track_source,
                &mut emit,
            ),
            Self::SessionCachedFrontiers(cache) => cache.scan(
                program,
                haystack,
                assertions,
                accounting,
                admitted_work_bound,
                track_source,
                &mut emit,
            ),
        }
    }

    fn peak_with_output(&self, output_bytes: usize) -> Result<usize, Error> {
        match self {
            Self::Full(table) => add(table.allocated_bytes, output_bytes, Resource::PeakBytes),
            Self::Rows(store) | Self::SparseRows(store) | Self::TerminalFrontier(store) => {
                let build = add(
                    store.allocated_store_bytes,
                    store.build_scratch_bytes,
                    Resource::PeakBytes,
                )?;
                let replay = add(
                    store.allocated_store_bytes,
                    output_bytes,
                    Resource::PeakBytes,
                )?;
                Ok(build.max(replay))
            }
            Self::CachedFrontiers(cache) => {
                let replay = add(cache.replay_bytes, output_bytes, Resource::PeakBytes)?;
                Ok(cache.build_peak_bytes.max(replay))
            }
            Self::SessionCachedFrontiers(cache) => {
                let replay = add(cache.replay_bytes, output_bytes, Resource::PeakBytes)?;
                Ok(cache.build_peak_bytes.max(replay))
            }
        }
    }
}

struct FullTable {
    values: ExactVec<usize>,
    allocated_bytes: usize,
}

impl FullTable {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the table construction loop keeps every exact work charge beside its transition"
    )]
    fn build<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        limits: OperationLimits,
        track_source: bool,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        let mut values = zeroed_usizes(requirements.table_cells, Resource::RandomAccessBytes)?;
        record_allocation(actual_allocations, values.capacity())?;
        let allocated_bytes = mul(
            values.capacity(),
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        enforce(
            allocated_bytes,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            allocated_bytes,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(allocated_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
        accounting.random_access_peak_bytes = allocated_bytes;
        accounting.scratch_peak_bytes = allocated_bytes;
        accounting.peak_bytes = allocated_bytes;
        let states = program.insts.len();
        let boundaries = add(haystack.len(), 1, Resource::Boundaries)?;
        let mut row_end = values.len();
        for position in (0..boundaries).rev() {
            let row_start = row_end
                .checked_sub(states)
                .ok_or(Error::InternalInvariant("full-table row underflow"))?;
            let (through_row, later_rows) = values.split_at_mut(row_end);
            let row = through_row
                .get_mut(row_start..)
                .ok_or(Error::InternalInvariant("full-table row outside table"))?;
            // The final input boundary has no successor row, but it also has
            // no input byte and therefore cannot follow a Consume edge.
            let next_row = later_rows.get(..states).unwrap_or(&[]);
            let input = haystack.get(position).copied();
            record_source_accesses(accounting, usize::from(input.is_some()), track_source)?;
            let scalar = if program.contains_scalar_transition() {
                charge_transition::<OBSERVED_WORK>(
                    accounting,
                    requirements.work_bound,
                    limits.max_work,
                )?;
                let source = haystack.get(position..).unwrap_or_default();
                record_source_accesses(
                    accounting,
                    cached_scalar_source_accesses(source),
                    track_source,
                )?;
                decode_first_scalar(source)
            } else {
                None
            };
            for &pc in &program.epsilon_order {
                charge_state::<OBSERVED_WORK>(
                    accounting,
                    requirements.work_bound,
                    limits.max_work,
                )?;
                let value = match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => encode(position)?,
                    Inst::Consume { bytes, next } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        if input.is_some_and(|byte| bytes.contains(byte)) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                requirements.work_bound,
                                limits.max_work,
                            )
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside table row",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        charge_assertion::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        if assertion_matches(
                            assertions,
                            *assertion,
                            position,
                            accounting,
                            track_source,
                        )? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    }
                    | Inst::RootSplit {
                        preferred,
                        fallback,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            requirements.work_bound,
                            limits.max_work,
                        )?;
                        let selected = row[*preferred];
                        if selected != 0 {
                            selected
                        } else {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                requirements.work_bound,
                                limits.max_work,
                            )?;
                            row[*fallback]
                        }
                    }
                };
                row[pc] = value;
            }
            row_end = row_start;
        }
        if row_end != 0 {
            return Err(Error::InternalInvariant(
                "full-table rows did not fill table",
            ));
        }
        Ok(Self {
            values,
            allocated_bytes,
        })
    }

    fn selected(&self, program: &Program, start: usize) -> Result<Option<usize>, Error> {
        let value = *self
            .values
            .get(index(start, program.entry, program.insts.len())?)
            .ok_or(Error::InternalInvariant("full-table root outside table"))?;
        Ok(decode(value))
    }
}

struct RowStore {
    bytes: Vec<u8>,
    storage: RowStorage,
    record_bytes: usize,
    allocated_store_bytes: usize,
    build_scratch_bytes: usize,
    root_rank: usize,
}

fn exact_allocation_error(error: CopyError, resource: Resource, items: usize) -> Error {
    match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow { resource },
        CopyError::AllocationFailed => Error::AllocationFailed { resource, items },
    }
}

fn exact_filled<T: Copy>(
    length: usize,
    value: T,
    resource: Resource,
) -> Result<ExactVec<T>, Error> {
    let mut values = ExactVec::try_with_capacity(length)
        .map_err(|error| exact_allocation_error(error, resource, length))?;
    for _ in 0..length {
        values
            .try_push(value)
            .map_err(|_| Error::InternalInvariant("exact allocation changed capacity"))?;
    }
    Ok(values)
}

fn exact_reserved<T>(length: usize, resource: Resource) -> Result<ExactVec<T>, Error> {
    #[cfg(test)]
    if length != 0 && allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource,
            items: length,
        });
    }
    ExactVec::try_with_capacity(length)
        .map_err(|error| exact_allocation_error(error, resource, length))
}

fn initialize_exact_accounted<T: Copy>(
    values: &mut ExactVec<T>,
    length: usize,
    value: T,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    for _ in 0..length {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        values
            .try_push(value)
            .map_err(|_| Error::InternalInvariant("exact allocation changed capacity"))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct CachedTransitionSlot {
    symbol: u64,
    next_state: u16,
    result_state: u16,
    occupied: bool,
}

impl CachedTransitionSlot {
    const EMPTY: Self = Self {
        symbol: 0,
        next_state: 0,
        result_state: 0,
        occupied: false,
    };
}

fn cached_compute_row(
    program: &Program,
    symbol: u64,
    next_frontier: &[u64],
    row: &mut [u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, row.len())?;
    row.fill(0);
    for &pc in &program.epsilon_order {
        try_charge_state(accounting, admitted_work_bound)?;
        let present =
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "cached frontier reached an unfilled state",
                    ));
                }
                Inst::Fail => false,
                Inst::Match => cached_symbol_seeded(symbol),
                Inst::Consume { bytes, next } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    cached_symbol_byte(symbol).is_some_and(|byte| bytes.contains(byte))
                        && cached_candidate_bit(next_frontier, *next)?
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    if let Some(scalar) = cached_symbol_scalar(symbol) {
                        let matches = scalars.contains_with(scalar, || {
                            try_charge_transition(accounting, admitted_work_bound)
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside cached dispatch",
                                    ))?;
                            cached_candidate_bit(next_frontier, next)?
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                Inst::Assert { assertion, next } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    cached_symbol_assertion(symbol, *assertion) && cached_candidate_bit(row, *next)?
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    try_charge_transition(accounting, admitted_work_bound)?;
                    if cached_candidate_bit(row, *preferred)? {
                        true
                    } else {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        cached_candidate_bit(row, *fallback)?
                    }
                }
            };
        if present {
            cached_set_candidate_bit(row, pc)?;
        }
    }
    Ok(())
}

fn cached_replay_scalar(
    scalars: &ScalarSet,
    next_by_width: &[usize; 4],
    haystack: &[u8],
    position: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    track_source: bool,
) -> Result<usize, Error> {
    let source = haystack.get(position..).unwrap_or_default();
    record_source_accesses(
        accounting,
        cached_scalar_source_accesses(source),
        track_source,
    )?;
    let scalar = decode_first_scalar(source).ok_or(Error::InternalInvariant(
        "cached frontier replay selected invalid Unicode scalar",
    ))?;
    if !scalars.contains_with(scalar, || {
        try_charge_replay(accounting, admitted_work_bound)
    })? {
        return Err(Error::InternalInvariant(
            "cached frontier replay selected failing Unicode scalar",
        ));
    }
    let width_index = scalar
        .len_utf8()
        .checked_sub(1)
        .ok_or(Error::InternalInvariant(
            "Unicode scalar has zero byte width",
        ))?;
    next_by_width
        .get(width_index)
        .copied()
        .ok_or(Error::InternalInvariant(
            "Unicode scalar width outside cached replay dispatch",
        ))
}

/// Stable Boolean row images plus a bounded transition cache. Liveness is
/// sufficient during the reverse sweep: replay consults the retained row at
/// each boundary and therefore applies preferred/fallback priority exactly at
/// the original decision point.
#[derive(Debug)]
struct CachedFrontierStore {
    boundary_states: ExactVec<u16>,
    state_bits: ExactVec<u64>,
    state_hashes: ExactVec<u64>,
    transitions: ExactVec<CachedTransitionSlot>,
    replay_current: ExactVec<u64>,
    replay_next: ExactVec<u64>,
    words: usize,
    state_count: usize,
    transition_count: usize,
    saturated: bool,
    has_run: bool,
    poisoned: bool,
    used_assertions: u32,
    checkpoint_log_bytes_read: usize,
    build_peak_bytes: usize,
    replay_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CachedFrontierRow {
    Retained(u16),
    Materialized,
}

impl CachedFrontierStore {
    fn allocate_session(cache: CachedFrontierRequirements) -> Result<Self, Error> {
        Ok(Self {
            boundary_states: exact_filled(cache.boundary_count, 0_u16, Resource::LogBytes)?,
            state_bits: exact_filled(
                cache.state_word_capacity,
                0_u64,
                Resource::RandomAccessBytes,
            )?,
            state_hashes: exact_filled(MAX_CACHED_FRONTIERS, 0_u64, Resource::ScratchBytes)?,
            transitions: exact_filled(
                CACHED_TRANSITION_SLOTS,
                CachedTransitionSlot::EMPTY,
                Resource::ScratchBytes,
            )?,
            replay_current: exact_filled(cache.words, 0_u64, Resource::ScratchBytes)?,
            replay_next: exact_filled(cache.words, 0_u64, Resource::ScratchBytes)?,
            words: cache.words,
            state_count: 0,
            transition_count: 0,
            saturated: false,
            has_run: false,
            poisoned: false,
            used_assertions: 0,
            checkpoint_log_bytes_read: 0,
            build_peak_bytes: cache.peak_bytes,
            replay_bytes: cache.replay_bytes()?,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "cached-frontier construction keeps its fixed capacity, semantic key, and exact charges together"
    )]
    fn build(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        cache: CachedFrontierRequirements,
        limits: OperationLimits,
        track_source: bool,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        cache.enforce(limits)?;
        let mut boundary_states = exact_reserved(cache.boundary_count, Resource::LogBytes)?;
        record_allocation(actual_allocations, boundary_states.capacity())?;
        accounting.log_bytes = cache.log_bytes;
        accounting.peak_bytes = cache.log_bytes;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut boundary_states,
            cache.boundary_count,
            0_u16,
            accounting,
            requirements.work_bound,
        )?;
        let mut state_bits =
            exact_reserved(cache.state_word_capacity, Resource::RandomAccessBytes)?;
        record_allocation(actual_allocations, state_bits.capacity())?;
        let mut allocated_random = mul(
            cache.state_word_capacity,
            core::mem::size_of::<u64>(),
            Resource::RandomAccessBytes,
        )?;
        accounting.random_access_peak_bytes = allocated_random;
        accounting.scratch_peak_bytes = allocated_random;
        accounting.peak_bytes = add(cache.log_bytes, allocated_random, Resource::PeakBytes)?;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut state_bits,
            cache.state_word_capacity,
            0_u64,
            accounting,
            requirements.work_bound,
        )?;
        let mut state_hashes = exact_reserved(MAX_CACHED_FRONTIERS, Resource::ScratchBytes)?;
        record_allocation(actual_allocations, state_hashes.capacity())?;
        allocated_random = add(
            allocated_random,
            mul(
                MAX_CACHED_FRONTIERS,
                core::mem::size_of::<u64>(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        accounting.random_access_peak_bytes = allocated_random;
        accounting.scratch_peak_bytes = allocated_random;
        accounting.peak_bytes = add(cache.log_bytes, allocated_random, Resource::PeakBytes)?;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut state_hashes,
            MAX_CACHED_FRONTIERS,
            0_u64,
            accounting,
            requirements.work_bound,
        )?;
        let mut transitions = exact_reserved(CACHED_TRANSITION_SLOTS, Resource::ScratchBytes)?;
        record_allocation(actual_allocations, transitions.capacity())?;
        allocated_random = add(
            allocated_random,
            mul(
                CACHED_TRANSITION_SLOTS,
                core::mem::size_of::<CachedTransitionSlot>(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        accounting.random_access_peak_bytes = allocated_random;
        accounting.scratch_peak_bytes = allocated_random;
        accounting.peak_bytes = add(cache.log_bytes, allocated_random, Resource::PeakBytes)?;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut transitions,
            CACHED_TRANSITION_SLOTS,
            CachedTransitionSlot::EMPTY,
            accounting,
            requirements.work_bound,
        )?;
        let mut candidate = exact_reserved(cache.words, Resource::ScratchBytes)?;
        record_allocation(actual_allocations, candidate.capacity())?;
        allocated_random = add(
            allocated_random,
            mul(
                cache.words,
                core::mem::size_of::<u64>(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        accounting.random_access_peak_bytes = allocated_random;
        accounting.scratch_peak_bytes = allocated_random;
        accounting.peak_bytes = add(cache.log_bytes, allocated_random, Resource::PeakBytes)?;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut candidate,
            cache.words,
            0_u64,
            accounting,
            requirements.work_bound,
        )?;
        let mut next_frontier = exact_reserved(cache.words, Resource::ScratchBytes)?;
        record_allocation(actual_allocations, next_frontier.capacity())?;
        allocated_random = add(
            allocated_random,
            mul(
                cache.words,
                core::mem::size_of::<u64>(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        accounting.random_access_peak_bytes = allocated_random;
        accounting.scratch_peak_bytes = allocated_random;
        accounting.peak_bytes = add(cache.log_bytes, allocated_random, Resource::PeakBytes)?;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        initialize_exact_accounted(
            &mut next_frontier,
            cache.words,
            0_u64,
            accounting,
            requirements.work_bound,
        )?;

        // State zero is the all-failing successor beyond the terminal row.
        let mut state_count = 1_usize;
        let mut saturated = false;
        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
        state_hashes[0] = cached_row_hash(&candidate, accounting, requirements.work_bound)?;
        let mut transition_count = 0_usize;
        let mut next_state = Some(0_u16);
        let mut next_frontier_materialized = true;
        let used_assertions =
            cached_program_assertion_mask(program, accounting, requirements.work_bound)?;
        for position in (0..cache.boundary_count).rev() {
            let symbol = cached_boundary_symbol(
                program,
                assertions,
                haystack,
                position,
                used_assertions,
                accounting,
                requirements.work_bound,
                track_source,
            )?;
            let (cached, slot) = if let Some(state) = next_state {
                let (cached, slot) = cached_transition_lookup(
                    &transitions,
                    state,
                    symbol,
                    accounting,
                    requirements.work_bound,
                )?;
                (cached, Some(slot))
            } else {
                (None, None)
            };
            let (current, current_frontier_materialized) = if let Some(state) = cached {
                // A run of hits needs only interned frontier IDs. Defer the
                // retained-row copy until a following miss actually consumes
                // the Boolean successor image.
                (Some(state), false)
            } else {
                if !next_frontier_materialized {
                    let state = next_state.ok_or(Error::InternalInvariant(
                        "cached frontier lost the retained successor for a cache miss",
                    ))?;
                    cached_copy_retained_row(
                        &state_bits,
                        cache.words,
                        state,
                        &mut next_frontier,
                        accounting,
                        requirements.work_bound,
                    )?;
                }
                cached_compute_row(
                    program,
                    symbol,
                    &next_frontier,
                    &mut candidate,
                    accounting,
                    requirements.work_bound,
                )?;
                let hash = cached_row_hash(&candidate, accounting, requirements.work_bound)?;
                let mut interned = None;
                for state in 0..state_count {
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    if state_hashes[state] != hash {
                        continue;
                    }
                    let start = mul(state, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    let retained = state_bits.get(start..end).ok_or(Error::InternalInvariant(
                        "cached frontier row outside store",
                    ))?;
                    let mut equal = true;
                    for (&left, &right) in retained.iter().zip(candidate.iter()) {
                        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                        if left != right {
                            equal = false;
                            break;
                        }
                    }
                    if equal {
                        interned = Some(u16::try_from(state).map_err(|_| {
                            Error::InternalInvariant("cached frontier ID does not fit u16")
                        })?);
                        break;
                    }
                }
                let result = if let Some(state) = interned {
                    Some(state)
                } else if state_count < MAX_CACHED_FRONTIERS {
                    let required = add(state_count, 1, Resource::TableCells)?;
                    let start = mul(state_count, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, cache.words)?;
                    state_bits
                        .get_mut(start..end)
                        .ok_or(Error::InternalInvariant(
                            "cached frontier insertion outside store",
                        ))?
                        .copy_from_slice(&candidate);
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    state_hashes[state_count] = hash;
                    let state = u16::try_from(state_count).map_err(|_| {
                        Error::InternalInvariant("cached frontier ID does not fit u16")
                    })?;
                    state_count = required;
                    Some(state)
                } else {
                    saturated = true;
                    None
                };
                if let (Some(slot), Some(next_state), Some(result_state)) =
                    (slot, next_state, result)
                    && transition_count < MAX_CACHED_TRANSITIONS
                {
                    let required = add(transition_count, 1, Resource::TableCells)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    transitions[slot] = CachedTransitionSlot {
                        symbol,
                        next_state,
                        result_state,
                        occupied: true,
                    };
                    transition_count = required;
                } else if result.is_some() && transition_count >= MAX_CACHED_TRANSITIONS {
                    saturated = true;
                }
                core::mem::swap(&mut candidate, &mut next_frontier);
                (result, true)
            };
            try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
            boundary_states[position] = current.unwrap_or(UNCACHED_FRONTIER);
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                core::mem::size_of::<u16>(),
                Resource::SequentialBytes,
            )?;
            next_state = current;
            next_frontier_materialized = current_frontier_materialized;
        }

        accounting.random_access_peak_bytes = cache.random_bytes;
        accounting.scratch_peak_bytes = cache.scratch_bytes;
        accounting.log_bytes = cache.log_bytes;
        let replay_bytes = add(
            add(
                cache.log_bytes,
                mul(
                    cache.state_word_capacity,
                    core::mem::size_of::<u64>(),
                    Resource::PeakBytes,
                )?,
                Resource::PeakBytes,
            )?,
            mul(
                mul(cache.words, 2, Resource::PeakBytes)?,
                core::mem::size_of::<u64>(),
                Resource::PeakBytes,
            )?,
            Resource::PeakBytes,
        )?;
        drop(transitions);
        drop(state_hashes);
        Ok(Self {
            boundary_states,
            state_bits,
            // One-shot execution deliberately releases construction-only
            // cache metadata before replay. Caller-owned sessions retain it.
            state_hashes: fre_exact_alloc::ExactVec::default(),
            transitions: fre_exact_alloc::ExactVec::default(),
            replay_current: candidate,
            replay_next: next_frontier,
            words: cache.words,
            state_count,
            transition_count,
            saturated,
            has_run: true,
            poisoned: false,
            used_assertions,
            checkpoint_log_bytes_read: 0,
            build_peak_bytes: cache.peak_bytes,
            replay_bytes,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "session population mirrors the audited cache sweep while retaining only source-independent cache state"
    )]
    fn populate_session(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        cache: CachedFrontierRequirements,
        limits: OperationLimits,
        track_source: bool,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        cache.enforce(limits)?;
        if self.boundary_states.len() != cache.boundary_count
            || self.state_bits.len() != cache.state_word_capacity
            || self.state_hashes.len() != MAX_CACHED_FRONTIERS
            || self.transitions.len() != CACHED_TRANSITION_SLOTS
            || self.replay_current.len() != cache.words
            || self.replay_next.len() != cache.words
            || self.words != cache.words
        {
            return Err(Error::InternalInvariant(
                "cached Count session storage differs from its bound shape",
            ));
        }

        accounting.log_bytes = cache.log_bytes;
        accounting.random_access_peak_bytes = cache.random_bytes;
        accounting.scratch_peak_bytes = cache.scratch_bytes;
        accounting.peak_bytes = cache.peak_bytes;
        self.checkpoint_log_bytes_read = 0;

        // Every successful prior scan and every interrupted population may
        // leave source-derived frontier rows in these two buffers. Clear them
        // before reuse without disturbing the source-independent interner or
        // transition table. A failed first population leaves `poisoned` set,
        // so the next attempt performs the same reset.
        if self.has_run || self.poisoned {
            try_charge_frontier_amount(
                accounting,
                requirements.work_bound,
                mul(cache.words, 2, Resource::ExecutionWork)?,
            )?;
            self.replay_current.fill(0);
            self.replay_next.fill(0);
        }
        self.poisoned = true;
        if self.state_count == 0 {
            self.state_count = 1;
            try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
            self.state_hashes[0] =
                cached_row_hash(&self.replay_current, accounting, requirements.work_bound)?;
        }

        let used_assertions =
            cached_program_assertion_mask(program, accounting, requirements.work_bound)?;
        self.used_assertions = used_assertions;
        let mut next_state = Some(0_u16);
        let mut next_frontier_materialized = true;
        for position in (0..cache.boundary_count).rev() {
            let symbol = cached_boundary_symbol(
                program,
                assertions,
                haystack,
                position,
                used_assertions,
                accounting,
                requirements.work_bound,
                track_source,
            )?;
            let (cached, slot) = if let Some(state) = next_state {
                let (cached, slot) = cached_transition_lookup(
                    &self.transitions,
                    state,
                    symbol,
                    accounting,
                    requirements.work_bound,
                )?;
                (cached, Some(slot))
            } else {
                (None, None)
            };
            let (current, current_frontier_materialized) = if let Some(state) = cached {
                // Persistent cache hits need only their interned IDs. Keep
                // both work rows untouched until a following miss needs the
                // exact retained successor image.
                (Some(state), false)
            } else {
                if !next_frontier_materialized {
                    let state = next_state.ok_or(Error::InternalInvariant(
                        "session cache lost the retained successor for a cache miss",
                    ))?;
                    cached_copy_retained_row(
                        &self.state_bits,
                        cache.words,
                        state,
                        &mut self.replay_next,
                        accounting,
                        requirements.work_bound,
                    )?;
                }
                cached_compute_row(
                    program,
                    symbol,
                    &self.replay_next,
                    &mut self.replay_current,
                    accounting,
                    requirements.work_bound,
                )?;
                let hash =
                    cached_row_hash(&self.replay_current, accounting, requirements.work_bound)?;
                let mut interned = None;
                for state in 0..self.state_count {
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    if self.state_hashes[state] != hash {
                        continue;
                    }
                    let start = mul(state, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    let retained =
                        self.state_bits
                            .get(start..end)
                            .ok_or(Error::InternalInvariant(
                                "session cached frontier row outside store",
                            ))?;
                    let mut equal = true;
                    for (&left, &right) in retained.iter().zip(self.replay_current.iter()) {
                        try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                        if left != right {
                            equal = false;
                            break;
                        }
                    }
                    if equal {
                        interned = Some(u16::try_from(state).map_err(|_| {
                            Error::InternalInvariant("session cached frontier ID does not fit u16")
                        })?);
                        break;
                    }
                }
                let result = if let Some(state) = interned {
                    Some(state)
                } else if self.state_count < MAX_CACHED_FRONTIERS {
                    let required = add(self.state_count, 1, Resource::TableCells)?;
                    let start = mul(self.state_count, cache.words, Resource::ScratchBytes)?;
                    let end = add(start, cache.words, Resource::ScratchBytes)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, cache.words)?;
                    self.state_bits
                        .get_mut(start..end)
                        .ok_or(Error::InternalInvariant(
                            "session cached frontier insertion outside store",
                        ))?
                        .copy_from_slice(&self.replay_current);
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    self.state_hashes[self.state_count] = hash;
                    let state = u16::try_from(self.state_count).map_err(|_| {
                        Error::InternalInvariant("session cached frontier ID does not fit u16")
                    })?;
                    self.state_count = required;
                    Some(state)
                } else {
                    self.saturated = true;
                    None
                };
                if let (Some(slot), Some(next_state), Some(result_state)) =
                    (slot, next_state, result)
                    && self.transition_count < MAX_CACHED_TRANSITIONS
                {
                    let required = add(self.transition_count, 1, Resource::TableCells)?;
                    try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
                    self.transitions[slot] = CachedTransitionSlot {
                        symbol,
                        next_state,
                        result_state,
                        occupied: true,
                    };
                    self.transition_count = required;
                } else if result.is_some() && self.transition_count >= MAX_CACHED_TRANSITIONS {
                    self.saturated = true;
                }
                core::mem::swap(&mut self.replay_current, &mut self.replay_next);
                (result, true)
            };
            try_charge_frontier_amount(accounting, requirements.work_bound, 1)?;
            self.boundary_states[position] = current.unwrap_or(UNCACHED_FRONTIER);
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                core::mem::size_of::<u16>(),
                Resource::SequentialBytes,
            )?;
            next_state = current;
            next_frontier_materialized = current_frontier_materialized;
        }
        self.has_run = true;
        self.poisoned = false;
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the cached scan carries one explicit immutable execution context and its audited ledger"
    )]
    fn scan(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        track_source: bool,
        mut emit: impl FnMut(Span) -> Result<(), Error>,
    ) -> Result<ScanSummary, Error> {
        scan_sequence_sparse(
            haystack.len(),
            assertions.base(),
            accounting,
            admitted_work_bound,
            |start, accounting| {
                self.selected(
                    program,
                    haystack,
                    assertions,
                    start,
                    accounting,
                    admitted_work_bound,
                    track_source,
                )
            },
            &mut emit,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "cached replay keeps its source context and accounting ledger explicit at selection"
    )]
    fn selected(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        track_source: bool,
    ) -> Result<Option<usize>, Error> {
        let mut frontier = self.load_boundary(
            program,
            haystack,
            assertions,
            start,
            accounting,
            admitted_work_bound,
            track_source,
        )?;
        if !self.candidate_bit(frontier, program.entry, accounting, admitted_work_bound)? {
            return Ok(None);
        }
        let mut pc = program.entry;
        let mut position = start;
        loop {
            try_charge_replay(accounting, admitted_work_bound)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "cached frontier replay reached an unfilled state",
                    ));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant(
                        "cached frontier replay selected failure",
                    ));
                }
                Inst::Match => return Ok(Some(position)),
                Inst::Consume { bytes, next } => {
                    let input = haystack.get(position).copied();
                    record_source_accesses(accounting, usize::from(input.is_some()), track_source)?;
                    if !input.is_some_and(|byte| bytes.contains(byte)) {
                        return Err(Error::InternalInvariant(
                            "cached frontier replay selected failing byte",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    frontier = self.load_boundary(
                        program,
                        haystack,
                        assertions,
                        position,
                        accounting,
                        admitted_work_bound,
                        track_source,
                    )?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    pc = cached_replay_scalar(
                        scalars,
                        next_by_width,
                        haystack,
                        position,
                        accounting,
                        admitted_work_bound,
                        track_source,
                    )?;
                    position = add(position, 1, Resource::Boundaries)?;
                    frontier = self.load_boundary(
                        program,
                        haystack,
                        assertions,
                        position,
                        accounting,
                        admitted_work_bound,
                        track_source,
                    )?;
                }
                Inst::Assert { assertion, next } => {
                    try_charge_assertion(accounting, admitted_work_bound)?;
                    if !assertion_matches(
                        assertions,
                        *assertion,
                        position,
                        accounting,
                        track_source,
                    )? {
                        return Err(Error::InternalInvariant(
                            "cached frontier replay selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    pc = if self.candidate_bit(
                        frontier,
                        *preferred,
                        accounting,
                        admitted_work_bound,
                    )? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "boundary loading keeps every cache input and accounting ledger explicit"
    )]
    fn load_boundary(
        &mut self,
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        track_source: bool,
    ) -> Result<CachedFrontierRow, Error> {
        accounting.sequential_bytes_read = add(
            accounting.sequential_bytes_read,
            core::mem::size_of::<u16>(),
            Resource::SequentialBytes,
        )?;
        let first = self
            .boundary_states
            .get(position)
            .copied()
            .ok_or(Error::InternalInvariant(
                "cached frontier boundary outside state stream",
            ))?;
        if first != UNCACHED_FRONTIER {
            return Ok(CachedFrontierRow::Retained(first));
        }

        let mut checkpoint = add(position, 1, Resource::Boundaries)?;
        loop {
            if checkpoint == self.boundary_states.len() {
                try_charge_frontier_amount(
                    accounting,
                    admitted_work_bound,
                    self.replay_current.len(),
                )?;
                self.replay_current.fill(0);
                break;
            }
            try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
            self.checkpoint_log_bytes_read = add(
                self.checkpoint_log_bytes_read,
                core::mem::size_of::<u16>(),
                Resource::LogBytes,
            )?;
            let state = *self
                .boundary_states
                .get(checkpoint)
                .ok_or(Error::InternalInvariant(
                    "cached frontier checkpoint outside state stream",
                ))?;
            if state != UNCACHED_FRONTIER {
                cached_copy_retained_row(
                    &self.state_bits,
                    self.words,
                    state,
                    &mut self.replay_current,
                    accounting,
                    admitted_work_bound,
                )?;
                break;
            }
            checkpoint = add(checkpoint, 1, Resource::Boundaries)?;
        }

        for replay_position in (position..checkpoint).rev() {
            core::mem::swap(&mut self.replay_current, &mut self.replay_next);
            let symbol = cached_boundary_symbol(
                program,
                assertions,
                haystack,
                replay_position,
                self.used_assertions,
                accounting,
                admitted_work_bound,
                track_source,
            )?;
            cached_compute_row(
                program,
                symbol,
                &self.replay_next,
                &mut self.replay_current,
                accounting,
                admitted_work_bound,
            )?;
        }
        Ok(CachedFrontierRow::Materialized)
    }

    fn candidate_bit(
        &self,
        row: CachedFrontierRow,
        pc: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
    ) -> Result<bool, Error> {
        match row {
            CachedFrontierRow::Retained(state) => cached_retained_candidate_bit(
                &self.state_bits,
                self.words,
                state,
                pc,
                accounting,
                admitted_work_bound,
            ),
            CachedFrontierRow::Materialized => cached_candidate_bit(&self.replay_current, pc),
        }
    }
}

fn cached_transition_lookup(
    slots: &[CachedTransitionSlot],
    next_state: u16,
    symbol: u64,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(Option<u16>, usize), Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
    let mask = slots
        .len()
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("empty cached transition table"))?;
    let mut index = cached_transition_hash(next_state, symbol) & mask;
    for _ in 0..slots.len() {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        let slot = slots[index];
        if !slot.occupied {
            return Ok((None, index));
        }
        if slot.next_state == next_state && slot.symbol == symbol {
            return Ok((Some(slot.result_state), index));
        }
        index = index.wrapping_add(1) & mask;
    }
    Err(Error::InternalInvariant(
        "cached transition table has no empty slot",
    ))
}

fn cached_transition_hash(next_state: u16, symbol: u64) -> usize {
    let key = symbol ^ (u64::from(next_state) << 48);
    let mixed = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    usize::try_from(mixed ^ (mixed >> 32)).unwrap_or(0)
}

fn cached_row_hash(
    words: &[u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<u64, Error> {
    let mut hash = 0xCBF2_9CE4_8422_2325_u64;
    for &word in words {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        hash ^= word;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    Ok(hash)
}

const CACHED_ASSERTIONS: [Assertion; 18] = [
    Assertion::StartText,
    Assertion::EndText,
    Assertion::StartLf,
    Assertion::EndLf,
    Assertion::StartCrlf,
    Assertion::EndCrlf,
    Assertion::WordAscii,
    Assertion::WordAsciiNegate,
    Assertion::WordStartAscii,
    Assertion::WordEndAscii,
    Assertion::WordStartHalfAscii,
    Assertion::WordEndHalfAscii,
    Assertion::WordUnicode,
    Assertion::WordUnicodeNegate,
    Assertion::WordStartUnicode,
    Assertion::WordEndUnicode,
    Assertion::WordStartHalfUnicode,
    Assertion::WordEndHalfUnicode,
];

const CACHED_ASSERTION_SHIFT: u32 = 9;
const CACHED_SEED_SHIFT: u32 = CACHED_ASSERTION_SHIFT + 18;
const CACHED_SCALAR_SHIFT: u32 = CACHED_SEED_SHIFT + 1;
const CACHED_SCALAR_NONE: u32 = 0x11_0000;

#[allow(
    clippy::too_many_arguments,
    reason = "symbol construction keeps assertion/source charging adjacent to every inspected input"
)]
fn cached_boundary_symbol(
    program: &Program,
    assertions: AssertionContext<'_>,
    haystack: &[u8],
    position: usize,
    used_assertions: u32,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    track_source: bool,
) -> Result<u64, Error> {
    try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
    let mut assertion_mask = 0_u64;
    if used_assertions == 0 {
        let slots = CACHED_ASSERTIONS.len();
        let can_bulk_charge = accounting
            .work
            .checked_add(slots)
            .is_some_and(|required| required <= admitted_work_bound)
            && accounting.frontier_bookkeeping.checked_add(slots).is_some();
        if can_bulk_charge {
            try_charge_frontier_amount(accounting, admitted_work_bound, slots)?;
        } else {
            // Preserve the established partial receipt at a one-below work
            // bound or arithmetic edge. The admitted hot path bulk-charges
            // the same logical slots without dispatching 18 empty cases.
            for _ in 0..slots {
                try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
            }
        }
    } else {
        for assertion in CACHED_ASSERTIONS {
            try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
            let bit = 1_u32 << assertion.identity_tag();
            if used_assertions & bit == 0 {
                continue;
            }
            try_charge_assertion(accounting, admitted_work_bound)?;
            if assertion_matches(assertions, assertion, position, accounting, track_source)? {
                assertion_mask |= 1_u64 << assertion.identity_tag();
            }
        }
    }
    let byte = if let Some(byte) = haystack.get(position) {
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            1,
            Resource::RandomAccessBytes,
        )?;
        u64::from(*byte)
    } else {
        256_u64
    };
    let scalar = if program.contains_scalar_transition() {
        try_charge_transition(accounting, admitted_work_bound)?;
        let source = haystack.get(position..).unwrap_or_default();
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            cached_scalar_source_accesses(source),
            Resource::RandomAccessBytes,
        )?;
        decode_first_scalar(source).map_or(CACHED_SCALAR_NONE, u32::from)
    } else {
        CACHED_SCALAR_NONE
    };
    Ok(byte
        | (assertion_mask << CACHED_ASSERTION_SHIFT)
        | (1_u64 << CACHED_SEED_SHIFT)
        | (u64::from(scalar) << CACHED_SCALAR_SHIFT))
}

fn cached_scalar_source_accesses(bytes: &[u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return 1,
    };
    if bytes.len() < width { 1 } else { width }
}

fn cached_program_assertion_mask(
    program: &Program,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<u32, Error> {
    let mut mask = 0_u32;
    for inst in &program.insts {
        try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
        if let Inst::Assert { assertion, .. } = inst {
            mask |= 1_u32 << assertion.identity_tag();
        }
    }
    Ok(mask)
}

fn cached_symbol_byte(symbol: u64) -> Option<u8> {
    u8::try_from(symbol & 0x1ff).ok()
}

fn cached_symbol_assertion(symbol: u64, assertion: Assertion) -> bool {
    symbol & (1_u64 << (CACHED_ASSERTION_SHIFT + u32::from(assertion.identity_tag()))) != 0
}

fn cached_symbol_seeded(symbol: u64) -> bool {
    symbol & (1_u64 << CACHED_SEED_SHIFT) != 0
}

fn cached_symbol_scalar(symbol: u64) -> Option<char> {
    let encoded = u32::try_from((symbol >> CACHED_SCALAR_SHIFT) & 0x1f_ffff).ok()?;
    if encoded == CACHED_SCALAR_NONE {
        return None;
    }
    char::from_u32(encoded)
}

fn cached_copy_retained_row(
    rows: &[u64],
    words: usize,
    state: u16,
    target: &mut [u64],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    let start = mul(usize::from(state), words, Resource::ScratchBytes)?;
    let end = add(start, words, Resource::ScratchBytes)?;
    try_charge_frontier_amount(accounting, admitted_work_bound, words)?;
    target.copy_from_slice(rows.get(start..end).ok_or(Error::InternalInvariant(
        "cached frontier state outside store",
    ))?);
    Ok(())
}

fn cached_retained_candidate_bit(
    rows: &[u64],
    words: usize,
    state: u16,
    pc: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<bool, Error> {
    let row_start = mul(usize::from(state), words, Resource::ScratchBytes)?;
    let word = add(row_start, pc / 64, Resource::ScratchBytes)?;
    try_charge_frontier_amount(accounting, admitted_work_bound, 1)?;
    rows.get(word)
        .map(|bits| bits & (1_u64 << (pc % 64)) != 0)
        .ok_or(Error::InternalInvariant(
            "cached retained frontier bit outside state store",
        ))
}

fn cached_candidate_bit(row: &[u64], pc: usize) -> Result<bool, Error> {
    row.get(pc / 64)
        .map(|bits| bits & (1_u64 << (pc % 64)) != 0)
        .ok_or(Error::InternalInvariant(
            "cached frontier bit outside candidate row",
        ))
}

fn cached_set_candidate_bit(row: &mut [u64], pc: usize) -> Result<(), Error> {
    let word = row.get_mut(pc / 64).ok_or(Error::InternalInvariant(
        "cached frontier bit outside candidate row",
    ))?;
    *word |= 1_u64 << (pc % 64);
    Ok(())
}

impl RowStore {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "row construction keeps fixed-buffer lifetime and accounting in one audit unit"
    )]
    fn build<const OBSERVED_WORK: bool, const ORDERED_ROOT: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        limits: OperationLimits,
        track_source: bool,
        fully_admitted_work: bool,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        let storage = requirements.row_storage.ok_or(Error::InternalInvariant(
            "reverse rows have no selected record storage",
        ))?;
        let mut store = zeroed_bytes(requirements.requested_log_bytes, Resource::LogBytes)?;
        let allocated_store = store.capacity();
        record_allocation(actual_allocations, allocated_store)?;
        accounting.log_bytes = allocated_store;
        accounting.peak_bytes = allocated_store;
        enforce(allocated_store, limits.max_log_bytes, Resource::LogBytes)?;
        let states = program.insts.len();
        let row_count = 2;
        let mut rows: [ExactVec<usize>; 5] = core::array::from_fn(|_| ExactVec::default());
        let mut row_words = 0_usize;
        for row in &mut rows[..row_count] {
            *row = zeroed_usizes(states, Resource::RandomAccessBytes)?;
            record_allocation(actual_allocations, row.capacity())?;
            row_words = add(row_words, row.capacity(), Resource::RandomAccessBytes)?;
            let allocated_row_bytes = mul(
                row_words,
                core::mem::size_of::<usize>(),
                Resource::RandomAccessBytes,
            )?;
            accounting.random_access_peak_bytes = allocated_row_bytes;
            accounting.scratch_peak_bytes = allocated_row_bytes;
            accounting.peak_bytes = add(allocated_store, allocated_row_bytes, Resource::PeakBytes)?;
        }
        let row_bytes = mul(
            row_words,
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        let build_scratch = row_bytes;
        enforce(
            build_scratch,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            build_scratch,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(
            add(allocated_store, build_scratch, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;
        // Build the sole boundary without an input byte separately. Every
        // remaining row then has a byte, so every consuming state avoids an
        // `Option` discriminant check in the Q-by-N construction loop.
        //
        // Keep the overwhelmingly common byte-only, assertion-free row
        // transition in a compact kernel. The program shape was classified
        // by the existing charged certification traversal, and dispatch is
        // performed once per table construction.
        let byte_only_rows =
            !ORDERED_ROOT && !program.contains_scalar_transition() && !program.contains_assertion();
        let mut write_offset = requirements.record_bytes;
        {
            let terminal_record = store
                .get_mut(..write_offset)
                .ok_or(Error::InternalInvariant("terminal row outside row log"))?;
            let (row, future_rows) = rows[..row_count]
                .split_first_mut()
                .ok_or(Error::InternalInvariant("row ring is empty"))?;
            Self::build_row::<false, OBSERVED_WORK, ORDERED_ROOT>(
                program,
                haystack,
                assertions,
                haystack.len(),
                0,
                row,
                future_rows,
                terminal_record,
                storage,
                accounting,
                requirements.work_bound,
                limits.max_work,
                track_source,
            )?;
        }
        accounting.sequential_bytes_written = add(
            accounting.sequential_bytes_written,
            requirements.record_bytes,
            Resource::SequentialBytes,
        )?;
        rows[..row_count].rotate_right(1);

        if byte_only_rows {
            write_offset = match storage {
                RowStorage::SplitDecisions => {
                    Self::build_admitted_byte_rows::<OBSERVED_WORK, true>(
                        program,
                        haystack,
                        &mut rows[..row_count],
                        &mut store,
                        write_offset,
                        requirements.record_bytes,
                        accounting,
                        requirements.work_bound,
                        limits.max_work,
                        track_source,
                        fully_admitted_work,
                    )?
                }
                RowStorage::ReachableEndpoints => {
                    Self::build_admitted_byte_rows::<OBSERVED_WORK, false>(
                        program,
                        haystack,
                        &mut rows[..row_count],
                        &mut store,
                        write_offset,
                        requirements.record_bytes,
                        accounting,
                        requirements.work_bound,
                        limits.max_work,
                        track_source,
                        fully_admitted_work,
                    )?
                }
            };
        } else {
            for (position, input) in haystack.iter().copied().enumerate().rev() {
                record_source_accesses(accounting, 1, track_source)?;
                let end = add(write_offset, requirements.record_bytes, Resource::LogBytes)?;
                let record = store
                    .get_mut(write_offset..end)
                    .ok_or(Error::InternalInvariant("row-log write outside store"))?;
                let (row, future_rows) = rows[..row_count]
                    .split_first_mut()
                    .ok_or(Error::InternalInvariant("row ring is empty"))?;
                Self::build_row::<true, OBSERVED_WORK, ORDERED_ROOT>(
                    program,
                    haystack,
                    assertions,
                    position,
                    input,
                    row,
                    future_rows,
                    record,
                    storage,
                    accounting,
                    requirements.work_bound,
                    limits.max_work,
                    track_source,
                )?;
                accounting.sequential_bytes_written = add(
                    accounting.sequential_bytes_written,
                    requirements.record_bytes,
                    Resource::SequentialBytes,
                )?;
                write_offset = end;
                rows[..row_count].rotate_right(1);
            }
        }
        if write_offset != store.len() {
            return Err(Error::InternalInvariant("row-log store length mismatch"));
        }
        accounting.random_access_peak_bytes = build_scratch;
        accounting.scratch_peak_bytes = build_scratch;
        accounting.log_bytes = allocated_store;
        Ok(Self {
            bytes: store,
            storage,
            record_bytes: requirements.record_bytes,
            allocated_store_bytes: allocated_store,
            build_scratch_bytes: build_scratch,
            root_rank: program.split_count,
        })
    }

    #[inline]
    #[allow(
        clippy::too_many_arguments,
        reason = "one admission gate removes redundant per-state work checks only when the complete bound fits"
    )]
    fn build_admitted_byte_rows<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        program: &Program,
        haystack: &[u8],
        rows: &mut [ExactVec<usize>],
        store: &mut [u8],
        write_offset: usize,
        record_bytes: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        track_source: bool,
        fully_admitted_work: bool,
    ) -> Result<usize, Error> {
        debug_assert!(!fully_admitted_work || admitted_work_bound <= caller_work_limit);
        if OBSERVED_WORK && !fully_admitted_work {
            Self::build_byte_rows::<true, SPLIT_DECISIONS>(
                program,
                haystack,
                rows,
                store,
                write_offset,
                record_bytes,
                accounting,
                admitted_work_bound,
                caller_work_limit,
                track_source,
            )
        } else {
            Self::build_byte_rows::<false, SPLIT_DECISIONS>(
                program,
                haystack,
                rows,
                store,
                write_offset,
                record_bytes,
                accounting,
                admitted_work_bound,
                caller_work_limit,
                track_source,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the byte-row driver keeps exact source, log, and work accounting explicit"
    )]
    fn build_byte_rows<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        program: &Program,
        haystack: &[u8],
        rows: &mut [ExactVec<usize>],
        store: &mut [u8],
        mut write_offset: usize,
        record_bytes: usize,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        track_source: bool,
    ) -> Result<usize, Error> {
        let (row, future_rows) = rows
            .split_first_mut()
            .ok_or(Error::InternalInvariant("row ring is empty"))?;
        let next_row = future_rows
            .first_mut()
            .ok_or(Error::InternalInvariant("row ring has no future row"))?;
        let mut row = row.as_mut_slice();
        let mut next_row = next_row.as_mut_slice();
        for (position, input) in haystack.iter().copied().enumerate().rev() {
            record_source_accesses(accounting, 1, track_source)?;
            let end = add(write_offset, record_bytes, Resource::LogBytes)?;
            let record = store
                .get_mut(write_offset..end)
                .ok_or(Error::InternalInvariant("row-log write outside store"))?;
            Self::build_byte_row::<OBSERVED_WORK, SPLIT_DECISIONS>(
                program,
                position,
                input,
                row,
                next_row,
                record,
                accounting,
                admitted_work_bound,
                caller_work_limit,
            )?;
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                record_bytes,
                Resource::SequentialBytes,
            )?;
            write_offset = end;
            core::mem::swap(&mut row, &mut next_row);
        }
        Ok(write_offset)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "sparse reverse construction keeps its complete storage and work certificate local"
    )]
    fn build_sparse<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        requirements: Requirements,
        seed: &RequiredSuffixes,
        limits: OperationLimits,
        track_source: bool,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
    ) -> Result<Self, Error> {
        if seed.is_empty() {
            return Err(Error::InternalInvariant("sparse continuation has no seed"));
        }
        let storage = requirements.row_storage.ok_or(Error::InternalInvariant(
            "sparse continuation has no row storage",
        ))?;
        let mut store = zeroed_bytes(requirements.requested_log_bytes, Resource::LogBytes)?;
        let allocated_store = store.capacity();
        record_allocation(actual_allocations, allocated_store)?;
        accounting.log_bytes = allocated_store;
        accounting.peak_bytes = allocated_store;
        enforce(allocated_store, limits.max_log_bytes, Resource::LogBytes)?;
        let states = program.insts.len();
        let row_words = add(states, states, Resource::RandomAccessBytes)?;
        let mut rows = zeroed_usizes(row_words, Resource::RandomAccessBytes)?;
        record_allocation(actual_allocations, rows.capacity())?;
        let row_bytes = mul(
            rows.capacity(),
            core::mem::size_of::<usize>(),
            Resource::RandomAccessBytes,
        )?;
        accounting.random_access_peak_bytes = row_bytes;
        accounting.scratch_peak_bytes = row_bytes;
        accounting.peak_bytes = add(allocated_store, row_bytes, Resource::PeakBytes)?;
        let (mut row, mut next_row) = rows.split_at_mut(states);
        let build_scratch = row_bytes;
        enforce(
            build_scratch,
            limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        enforce(
            build_scratch,
            limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(
            add(allocated_store, build_scratch, Resource::PeakBytes)?,
            limits.max_peak_bytes,
            Resource::PeakBytes,
        )?;
        let admitted_work_bound = if OBSERVED_WORK {
            requirements.work_bound.min(limits.max_work)
        } else {
            requirements.work_bound
        };

        let mut write_offset = requirements.record_bytes;
        let mut next_any = {
            let terminal_record = store
                .get_mut(..write_offset)
                .ok_or(Error::InternalInvariant(
                    "terminal row outside sparse row log",
                ))?;
            Self::build_sparse_row(
                program,
                haystack,
                assertions,
                haystack.len(),
                None,
                seed,
                row,
                next_row,
                false,
                terminal_record,
                storage,
                accounting,
                admitted_work_bound,
                track_source,
            )?
        };
        accounting.sequential_bytes_written = add(
            accounting.sequential_bytes_written,
            requirements.record_bytes,
            Resource::SequentialBytes,
        )?;
        core::mem::swap(&mut row, &mut next_row);

        for (position, input) in haystack.iter().copied().enumerate().rev() {
            record_source_accesses(accounting, 1, track_source)?;
            let end = add(write_offset, requirements.record_bytes, Resource::LogBytes)?;
            let record = store
                .get_mut(write_offset..end)
                .ok_or(Error::InternalInvariant(
                    "sparse row-log write outside store",
                ))?;
            let row_any = Self::build_sparse_row(
                program,
                haystack,
                assertions,
                position,
                Some(input),
                seed,
                row,
                next_row,
                next_any,
                record,
                storage,
                accounting,
                admitted_work_bound,
                track_source,
            )?;
            accounting.sequential_bytes_written = add(
                accounting.sequential_bytes_written,
                requirements.record_bytes,
                Resource::SequentialBytes,
            )?;
            write_offset = end;
            core::mem::swap(&mut row, &mut next_row);
            next_any = row_any;
        }
        if write_offset != store.len() {
            return Err(Error::InternalInvariant(
                "sparse row-log store length mismatch",
            ));
        }
        accounting.random_access_peak_bytes = build_scratch;
        accounting.scratch_peak_bytes = build_scratch;
        accounting.log_bytes = allocated_store;
        Ok(Self {
            bytes: store,
            storage,
            record_bytes: requirements.record_bytes,
            allocated_store_bytes: allocated_store,
            build_scratch_bytes: build_scratch,
            root_rank: program.split_count,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one sparse-row boundary exposes every proof input and owned buffer"
    )]
    fn build_sparse_row(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        input: Option<u8>,
        seed: &RequiredSuffixes,
        row: &mut [usize],
        next_row: &[usize],
        next_any: bool,
        record: &mut [u8],
        storage: RowStorage,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        track_source: bool,
    ) -> Result<bool, Error> {
        let seeded = sparse_seed_matches(
            seed,
            haystack,
            position,
            accounting,
            admitted_work_bound,
            track_source,
        )?;
        // A required suffix can only make Match live at a suffix-ending
        // boundary. If neither that seed nor the successor row is live, this
        // entire row is provably zero. The row buffer may retain old values,
        // but every state is overwritten before a later nonempty row reads it.
        if !seeded && !next_any {
            return Ok(false);
        }
        let scalar = if next_any && program.contains_scalar_transition() {
            try_charge_transition(accounting, admitted_work_bound)?;
            let source = haystack.get(position..).unwrap_or_default();
            record_source_accesses(
                accounting,
                cached_scalar_source_accesses(source),
                track_source,
            )?;
            decode_first_scalar(source)
        } else {
            None
        };
        let mut row_any = false;
        for &pc in &program.epsilon_order {
            try_charge_state(accounting, admitted_work_bound)?;
            let value =
                match program.instruction(pc)? {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled sparse execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Match => {
                        if seeded {
                            encode(position)?
                        } else {
                            0
                        }
                    }
                    Inst::Consume { bytes, next } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        if next_any && input.is_some_and(|byte| bytes.contains(byte)) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        if !next_any {
                            row[pc] = 0;
                            continue;
                        }
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            try_charge_transition(accounting, admitted_work_bound)
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside sparse row",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Assert { assertion, next } => {
                        try_charge_assertion(accounting, admitted_work_bound)?;
                        if assertion_matches(
                            assertions,
                            *assertion,
                            position,
                            accounting,
                            track_source,
                        )? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    }
                    | Inst::RootSplit {
                        preferred,
                        fallback,
                    } => {
                        try_charge_transition(accounting, admitted_work_bound)?;
                        let preferred_value = row[*preferred];
                        if preferred_value != 0 {
                            if storage == RowStorage::SplitDecisions {
                                let rank = program.split_rank[pc];
                                if rank == NO_SPLIT_RANK {
                                    return Err(Error::InternalInvariant(
                                        "sparse split state has no decision rank",
                                    ));
                                }
                                set_bit(record, rank)?;
                            }
                            preferred_value
                        } else {
                            try_charge_transition(accounting, admitted_work_bound)?;
                            row[*fallback]
                        }
                    }
                };
            row[pc] = value;
            row_any |= value != 0;
        }
        match storage {
            RowStorage::SplitDecisions => {
                if row[program.entry] != 0 {
                    set_bit(record, program.split_count)?;
                }
            }
            RowStorage::ReachableEndpoints => write_encoded(record, row[program.entry])?,
        }
        Ok(row_any)
    }

    #[inline(never)]
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the compact byte-row kernel keeps exact accounting beside each state transition"
    )]
    fn build_byte_row<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        program: &Program,
        position: usize,
        input: u8,
        row: &mut [usize],
        next_row: &[usize],
        record: &mut [u8],
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
    ) -> Result<(), Error> {
        for &pc in &program.epsilon_order {
            let inst = program.instruction(pc)?;
            charge_state::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            let value = match inst {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled execution state"));
                }
                Inst::Fail => 0,
                Inst::Match => encode(position)?,
                Inst::Consume { bytes, next } => {
                    charge_transition::<OBSERVED_WORK>(
                        accounting,
                        admitted_work_bound,
                        caller_work_limit,
                    )?;
                    if bytes.contains(input) {
                        next_row[*next]
                    } else {
                        0
                    }
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    charge_transition::<OBSERVED_WORK>(
                        accounting,
                        admitted_work_bound,
                        caller_work_limit,
                    )?;
                    let preferred_value = row[*preferred];
                    let rank = program.split_rank[pc];
                    if rank == NO_SPLIT_RANK {
                        return Err(Error::InternalInvariant("split state has no decision rank"));
                    }
                    if preferred_value != 0 {
                        if SPLIT_DECISIONS {
                            set_bit(record, rank)?;
                        }
                        preferred_value
                    } else {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        row[*fallback]
                    }
                }
                Inst::ConsumeScalar { .. } | Inst::Assert { .. } => {
                    return Err(Error::InternalInvariant(
                        "byte-row kernel received a non-byte state",
                    ));
                }
            };
            row[pc] = value;
        }
        if SPLIT_DECISIONS {
            if row[program.entry] != 0 {
                set_bit(record, program.split_count)?;
            }
        } else {
            write_encoded(record, row[program.entry])?;
        }
        Ok(())
    }

    #[inline]
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the specialized row loop keeps borrowed buffers and exact accounting explicit"
    )]
    fn build_row<const HAS_INPUT: bool, const OBSERVED_WORK: bool, const ORDERED_ROOT: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        position: usize,
        input: u8,
        row: &mut [usize],
        future_rows: &[ExactVec<usize>],
        record: &mut [u8],
        storage: RowStorage,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        track_source: bool,
    ) -> Result<(), Error> {
        let scalar = if program.contains_scalar_transition() {
            charge_transition::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            if HAS_INPUT {
                let source = haystack.get(position..).unwrap_or_default();
                record_source_accesses(
                    accounting,
                    cached_scalar_source_accesses(source),
                    track_source,
                )?;
                decode_first_scalar(source)
            } else {
                None
            }
        } else {
            None
        };
        let next_row = future_rows
            .first()
            .map(ExactVec::as_slice)
            .unwrap_or_default();
        for &pc in &program.epsilon_order {
            let inst = program.instruction(pc)?;
            if ORDERED_ROOT && matches!(inst, Inst::RootSplit { .. }) {
                continue;
            }
            charge_state::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            let value =
                match inst {
                    Inst::Unfilled => {
                        return Err(Error::InternalInvariant("unfilled execution state"));
                    }
                    Inst::Fail => 0,
                    Inst::Consume { bytes, next } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        if HAS_INPUT && bytes.contains(input) {
                            next_row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::ConsumeScalar {
                        scalars,
                        next_by_width,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        let Some(scalar) = scalar else {
                            row[pc] = 0;
                            continue;
                        };
                        let matches = scalars.contains_with(scalar, || {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                admitted_work_bound,
                                caller_work_limit,
                            )
                        })?;
                        if matches {
                            let width_index = scalar.len_utf8().checked_sub(1).ok_or(
                                Error::InternalInvariant("Unicode scalar has zero byte width"),
                            )?;
                            let next =
                                *next_by_width
                                    .get(width_index)
                                    .ok_or(Error::InternalInvariant(
                                        "Unicode scalar width outside dispatch",
                                    ))?;
                            *next_row.get(next).ok_or(Error::InternalInvariant(
                                "scalar successor state outside row ring",
                            ))?
                        } else {
                            0
                        }
                    }
                    Inst::Match => encode(position)?,
                    Inst::Assert { assertion, next } => {
                        charge_assertion::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        if assertion_matches(
                            assertions,
                            *assertion,
                            position,
                            accounting,
                            track_source,
                        )? {
                            row[*next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    }
                    | Inst::RootSplit {
                        preferred,
                        fallback,
                    } => {
                        charge_transition::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )?;
                        let preferred_value = row[*preferred];
                        let rank = program.split_rank[pc];
                        if rank == NO_SPLIT_RANK {
                            return Err(Error::InternalInvariant(
                                "split state has no decision rank",
                            ));
                        }
                        if preferred_value != 0 {
                            if storage == RowStorage::SplitDecisions {
                                set_bit(record, rank)?;
                            }
                            preferred_value
                        } else {
                            charge_transition::<OBSERVED_WORK>(
                                accounting,
                                admitted_work_bound,
                                caller_work_limit,
                            )?;
                            row[*fallback]
                        }
                    }
                };
            row[pc] = value;
        }
        if ORDERED_ROOT {
            row[program.entry] = select_ordered_root::<OBSERVED_WORK>(
                program,
                row,
                accounting,
                admitted_work_bound,
                caller_work_limit,
            )?;
        }
        match storage {
            RowStorage::SplitDecisions => {
                if row[program.entry] != 0 {
                    set_bit(record, program.split_count)?;
                }
            }
            RowStorage::ReachableEndpoints => write_encoded(record, row[program.entry])?,
        }
        Ok(())
    }

    fn reader(&self) -> RowReader<'_> {
        RowReader {
            store: &self.bytes,
            storage: self.storage,
            record_bytes: self.record_bytes,
            current_record: &[],
            current_position: None,
            current_start: self.bytes.len(),
            root_rank: self.root_rank,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "structural and caller work limits stay explicit during sequential replay"
    )]
    fn replay<const OBSERVED_WORK: bool>(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        reader: &mut RowReader<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        caller_work_limit: usize,
        track_source: bool,
    ) -> Result<usize, Error> {
        let mut pc = program.entry;
        let mut position = start;
        loop {
            charge_replay::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled replay state"));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant("row log replayed a failing state"));
                }
                Inst::Match => return Ok(position),
                Inst::Consume { bytes, next } => {
                    let input = haystack.get(position).copied();
                    record_source_accesses(accounting, usize::from(input.is_some()), track_source)?;
                    if !input.is_some_and(|byte| bytes.contains(byte)) {
                        return Err(Error::InternalInvariant(
                            "row log selected failing byte path",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    let source = haystack.get(position..).unwrap_or_default();
                    record_source_accesses(
                        accounting,
                        cached_scalar_source_accesses(source),
                        track_source,
                    )?;
                    let scalar = decode_first_scalar(source).ok_or(Error::InternalInvariant(
                        "row log selected invalid Unicode scalar path",
                    ))?;
                    let matches = scalars.contains_with(scalar, || {
                        charge_replay::<OBSERVED_WORK>(
                            accounting,
                            admitted_work_bound,
                            caller_work_limit,
                        )
                    })?;
                    if !matches {
                        return Err(Error::InternalInvariant(
                            "row log selected failing Unicode scalar path",
                        ));
                    }
                    let width_index =
                        scalar
                            .len_utf8()
                            .checked_sub(1)
                            .ok_or(Error::InternalInvariant(
                                "Unicode scalar has zero byte width",
                            ))?;
                    pc = *next_by_width
                        .get(width_index)
                        .ok_or(Error::InternalInvariant(
                            "Unicode scalar width outside dispatch",
                        ))?;
                    position = add(position, 1, Resource::Boundaries)?;
                }
                Inst::Assert { assertion, next } => {
                    charge_assertion::<OBSERVED_WORK>(
                        accounting,
                        admitted_work_bound,
                        caller_work_limit,
                    )?;
                    if !assertion_matches(
                        assertions,
                        *assertion,
                        position,
                        accounting,
                        track_source,
                    )? {
                        return Err(Error::InternalInvariant(
                            "row log selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    let rank = program.split_rank[pc];
                    if rank == NO_SPLIT_RANK {
                        return Err(Error::InternalInvariant("split state has no decision rank"));
                    }
                    pc = if reader.decision(position, rank, accounting)? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "sparse replay keeps its source meter and admitted work ledger explicit"
    )]
    fn replay_sparse(
        program: &Program,
        haystack: &[u8],
        assertions: AssertionContext<'_>,
        start: usize,
        reader: &mut RowReader<'_>,
        accounting: &mut ExecutionAccounting,
        admitted_work_bound: usize,
        track_source: bool,
    ) -> Result<usize, Error> {
        let mut pc = program.entry;
        let mut position = start;
        loop {
            try_charge_replay(accounting, admitted_work_bound)?;
            match program.instruction(pc)? {
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant("unfilled sparse replay state"));
                }
                Inst::Fail => {
                    return Err(Error::InternalInvariant(
                        "sparse row log replayed a failing state",
                    ));
                }
                Inst::Match => return Ok(position),
                Inst::Consume { bytes, next } => {
                    let input = haystack.get(position).copied();
                    record_source_accesses(accounting, usize::from(input.is_some()), track_source)?;
                    if !input.is_some_and(|byte| bytes.contains(byte)) {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing byte path",
                        ));
                    }
                    position = add(position, 1, Resource::Boundaries)?;
                    pc = *next;
                }
                Inst::ConsumeScalar {
                    scalars,
                    next_by_width,
                } => {
                    let source = haystack.get(position..).unwrap_or_default();
                    record_source_accesses(
                        accounting,
                        cached_scalar_source_accesses(source),
                        track_source,
                    )?;
                    let scalar = decode_first_scalar(source).ok_or(Error::InternalInvariant(
                        "sparse row log selected invalid Unicode scalar path",
                    ))?;
                    let matches = scalars.contains_with(scalar, || {
                        try_charge_replay(accounting, admitted_work_bound)
                    })?;
                    if !matches {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing Unicode scalar path",
                        ));
                    }
                    let width_index =
                        scalar
                            .len_utf8()
                            .checked_sub(1)
                            .ok_or(Error::InternalInvariant(
                                "Unicode scalar has zero byte width",
                            ))?;
                    pc = *next_by_width
                        .get(width_index)
                        .ok_or(Error::InternalInvariant(
                            "Unicode scalar width outside dispatch",
                        ))?;
                    position = add(position, 1, Resource::Boundaries)?;
                }
                Inst::Assert { assertion, next } => {
                    try_charge_assertion(accounting, admitted_work_bound)?;
                    if !assertion_matches(
                        assertions,
                        *assertion,
                        position,
                        accounting,
                        track_source,
                    )? {
                        return Err(Error::InternalInvariant(
                            "sparse row log selected failing assertion",
                        ));
                    }
                    pc = *next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    let rank = program.split_rank[pc];
                    if rank == NO_SPLIT_RANK {
                        return Err(Error::InternalInvariant(
                            "sparse split state has no decision rank",
                        ));
                    }
                    pc = if reader.decision(position, rank, accounting)? {
                        *preferred
                    } else {
                        *fallback
                    };
                }
            }
        }
    }
}

fn select_ordered_root<const OBSERVED_WORK: bool>(
    program: &Program,
    row: &[usize],
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<usize, Error> {
    let mut pc = program.entry;
    let mut probes = 0_usize;
    loop {
        probes = add(probes, 1, Resource::ExecutionWork)?;
        enforce(
            probes,
            program.root_alternation_arms(),
            Resource::ExecutionWork,
        )?;
        // Charge before observing an arm endpoint so an exact one-below work
        // limit cannot inspect the unadmitted row slot.
        charge_root::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
        if probes == program.root_alternation_arms() {
            if matches!(program.instruction(pc)?, Inst::RootSplit { .. }) {
                return Err(Error::InternalInvariant(
                    "ordered-root chain exceeds its certified arm count",
                ));
            }
            return row.get(pc).copied().ok_or(Error::InternalInvariant(
                "ordered-root final arm outside row",
            ));
        }
        match program.instruction(pc)? {
            Inst::RootSplit {
                preferred,
                fallback,
            } => {
                let preferred_value = *row.get(*preferred).ok_or(Error::InternalInvariant(
                    "ordered-root preferred arm outside row",
                ))?;
                if preferred_value != 0 {
                    return Ok(preferred_value);
                }
                pc = *fallback;
            }
            _ => {
                return Err(Error::InternalInvariant(
                    "ordered-root chain ended before its certified arm count",
                ));
            }
        }
    }
}

struct RowReader<'a> {
    store: &'a [u8],
    storage: RowStorage,
    record_bytes: usize,
    current_record: &'a [u8],
    current_position: Option<usize>,
    current_start: usize,
    root_rank: usize,
}

impl RowReader<'_> {
    fn endpoint(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Option<usize>, Error> {
        if self.storage != RowStorage::ReachableEndpoints {
            return Err(Error::InternalInvariant(
                "split-decision row read as reachable endpoint",
            ));
        }
        self.ensure(position, accounting)?;
        read_encoded(self.current_record).map(decode)
    }

    fn root(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
        if self.storage != RowStorage::SplitDecisions {
            return Err(Error::InternalInvariant(
                "reachable-endpoint row read as split decisions",
            ));
        }
        self.ensure(position, accounting)?;
        read_bit(self.current_record, self.root_rank)
    }

    fn decision(
        &mut self,
        position: usize,
        rank: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<bool, Error> {
        if self.storage != RowStorage::SplitDecisions {
            return Err(Error::InternalInvariant(
                "reachable-endpoint row replayed as split decisions",
            ));
        }
        self.ensure(position, accounting)?;
        read_bit(self.current_record, rank)
    }

    fn ensure(
        &mut self,
        position: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        if self.current_position == Some(position) {
            return Ok(());
        }
        if self
            .current_position
            .is_some_and(|current| position < current)
        {
            return Err(Error::InternalInvariant("row-log reader moved backward"));
        }
        let traversed_records = match self.current_position {
            Some(current) => position
                .checked_sub(current)
                .ok_or(Error::InternalInvariant("row-log position underflow"))?,
            None => add(position, 1, Resource::SequentialBytes)?,
        };
        let traversed = mul(
            traversed_records,
            self.record_bytes,
            Resource::SequentialBytes,
        )?;
        accounting.sequential_bytes_read = add(
            accounting.sequential_bytes_read,
            traversed,
            Resource::SequentialBytes,
        )?;
        let start = self
            .current_start
            .checked_sub(traversed)
            .ok_or(Error::InternalInvariant("row-log seek outside store"))?;
        let end = add(start, self.record_bytes, Resource::LogBytes)?;
        self.current_record = self
            .store
            .get(start..end)
            .ok_or(Error::InternalInvariant("row-log read outside store"))?;
        self.current_position = Some(position);
        self.current_start = start;
        Ok(())
    }
}

fn scan_sequence<const OBSERVED_WORK: bool>(
    haystack_len: usize,
    base: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
    mut selected: impl FnMut(usize, &mut ExecutionAccounting) -> Result<Option<usize>, Error>,
    emit: &mut impl FnMut(Span) -> Result<(), Error>,
) -> Result<ScanSummary, Error> {
    let mut summary = ScanSummary::empty();
    let mut cursor = 0_usize;
    let mut previous_end = None;
    while cursor <= haystack_len {
        let mut start = cursor;
        let found = loop {
            if start > haystack_len {
                break None;
            }
            charge_root::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
            if let Some(end) = selected(start, accounting)? {
                if end < start || end > haystack_len {
                    return Err(Error::InternalInvariant("selected endpoint outside input"));
                }
                break Some((start, end));
            }
            start = start.saturating_add(1);
        };
        let Some((start, end)) = found else {
            break;
        };
        charge_event::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
        summary.events = add(summary.events, 1, Resource::MatchEvents)?;
        if start == end && previous_end == Some(start) {
            summary.suppressed = add(summary.suppressed, 1, Resource::MatchEvents)?;
            accounting.suppressed_empty =
                add(accounting.suppressed_empty, 1, Resource::MatchEvents)?;
            let Some(next) = start.checked_add(1) else {
                break;
            };
            cursor = next;
            continue;
        }
        let absolute_start = add(base, start, Resource::Boundaries)?;
        let absolute_end = add(base, end, Resource::Boundaries)?;
        let span = Span {
            start: absolute_start,
            end: absolute_end,
        };
        emit(span)?;
        summary.matches = add(summary.matches, 1, Resource::OutputMatches)?;
        let width = end
            .checked_sub(start)
            .ok_or(Error::InternalInvariant("match endpoint precedes start"))?;
        summary.span_sum = add(summary.span_sum, width, Resource::SpanSum)?;
        previous_end = Some(end);
        cursor = end;
    }
    Ok(summary)
}

fn scan_sequence_sparse(
    haystack_len: usize,
    base: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    mut selected: impl FnMut(usize, &mut ExecutionAccounting) -> Result<Option<usize>, Error>,
    emit: &mut impl FnMut(Span) -> Result<(), Error>,
) -> Result<ScanSummary, Error> {
    let mut summary = ScanSummary::empty();
    let mut cursor = 0_usize;
    let mut previous_end = None;
    while cursor <= haystack_len {
        let mut start = cursor;
        let found = loop {
            if start > haystack_len {
                break None;
            }
            try_charge_root(accounting, admitted_work_bound)?;
            if let Some(end) = selected(start, accounting)? {
                if end < start || end > haystack_len {
                    return Err(Error::InternalInvariant(
                        "sparse selected endpoint outside input",
                    ));
                }
                break Some((start, end));
            }
            start = start.saturating_add(1);
        };
        let Some((start, end)) = found else {
            break;
        };
        try_charge_event(accounting, admitted_work_bound)?;
        summary.events = add(summary.events, 1, Resource::MatchEvents)?;
        if start == end && previous_end == Some(start) {
            summary.suppressed = add(summary.suppressed, 1, Resource::MatchEvents)?;
            accounting.suppressed_empty =
                add(accounting.suppressed_empty, 1, Resource::MatchEvents)?;
            let Some(next) = start.checked_add(1) else {
                break;
            };
            cursor = next;
            continue;
        }
        let absolute_start = add(base, start, Resource::Boundaries)?;
        let absolute_end = add(base, end, Resource::Boundaries)?;
        emit(Span {
            start: absolute_start,
            end: absolute_end,
        })?;
        summary.matches = add(summary.matches, 1, Resource::OutputMatches)?;
        summary.span_sum = add(
            summary.span_sum,
            end.checked_sub(start)
                .ok_or(Error::InternalInvariant("sparse endpoint precedes start"))?,
            Resource::SpanSum,
        )?;
        previous_end = Some(end);
        cursor = end;
    }
    Ok(summary)
}

fn sparse_seed_matches(
    seed: &RequiredSuffixes,
    haystack: &[u8],
    end: usize,
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    track_source: bool,
) -> Result<bool, Error> {
    for suffix in seed.iter() {
        try_charge_transition_amount(
            accounting,
            admitted_work_bound,
            add(suffix.len(), 1, Resource::ExecutionWork)?,
        )?;
        let Some(start) = end.checked_sub(suffix.len()) else {
            continue;
        };
        let Some(got) = haystack.get(start..end) else {
            continue;
        };
        // Keep the comparison scalar and short-circuiting so receipt A records
        // the exact logical input bytes inspected, independent of a platform
        // slice-equality implementation's wider loads.
        let mut matches = true;
        for (&actual, &expected) in got.iter().zip(suffix) {
            record_source_accesses(accounting, 1, track_source)?;
            if actual != expected {
                matches = false;
                break;
            }
        }
        if matches {
            return Ok(true);
        }
    }
    Ok(false)
}

// `Requirements::new` checked the sum of every possible construction, scan
// and replay charge before allocation. Consequently each actual counter and
// their sum fit in `usize` and cannot reach the structural bound's successor.
// Diagnostic result admission rejects a caller limit below that conservative
// bound before work starts. Value-only reducers instead check each exact
// observed charge against the caller limit; the const branch is erased from
// the established diagnostic path.
#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the structural whole-operation bound proves every actual counter fits"
)]
fn charge<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    debug_assert!(OBSERVED_WORK || accounting.work < admitted_work_bound);
    if OBSERVED_WORK {
        let required = add(accounting.work, 1, Resource::ExecutionWork)?;
        enforce(required, admitted_work_bound, Resource::ExecutionWork)?;
        enforce(required, caller_work_limit, Resource::ExecutionWork)?;
    }
    accounting.work += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "state evaluations are a subset of the admitted whole-operation work bound"
)]
fn charge_state<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.state_evaluations += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "transition checks are a subset of the admitted whole-operation work bound"
)]
fn charge_transition<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.transition_checks += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "assertion checks are a subset of admitted transition checks"
)]
fn charge_assertion<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge_transition::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.assertion_checks += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "root probes are a subset of the admitted whole-operation work bound"
)]
fn charge_root<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.root_probes += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "replay steps are a subset of the admitted whole-operation work bound"
)]
fn charge_replay<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.replay_steps += 1;
    Ok(())
}

#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "successful paths are a subset of the admitted whole-operation work bound"
)]
fn charge_event<const OBSERVED_WORK: bool>(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    caller_work_limit: usize,
) -> Result<(), Error> {
    charge::<OBSERVED_WORK>(accounting, admitted_work_bound, caller_work_limit)?;
    accounting.successful_paths += 1;
    Ok(())
}

fn try_charge_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    let required = add(accounting.work, amount, Resource::ExecutionWork)?;
    enforce(required, admitted_work_bound, Resource::ExecutionWork)?;
    accounting.work = required;
    Ok(())
}

#[inline]
fn try_charge_value_work(work: &mut usize, admitted_work_bound: usize) -> Result<(), Error> {
    let required = add(*work, 1, Resource::ExecutionWork)?;
    enforce(required, admitted_work_bound, Resource::ExecutionWork)?;
    *work = required;
    Ok(())
}

fn record_source_accesses(
    accounting: &mut ExecutionAccounting,
    amount: usize,
    track_source: bool,
) -> Result<(), Error> {
    if track_source {
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            amount,
            Resource::RandomAccessBytes,
        )?;
    }
    Ok(())
}

fn record_allocation(actual_allocations: &mut usize, allocated_items: usize) -> Result<(), Error> {
    if allocated_items != 0 {
        *actual_allocations = add(*actual_allocations, 1, Resource::Allocations)?;
    }
    Ok(())
}

fn assertion_matches(
    assertions: AssertionContext<'_>,
    assertion: Assertion,
    position: usize,
    accounting: &mut ExecutionAccounting,
    track_source: bool,
) -> Result<bool, Error> {
    assertions.is_match_with_source_accesses(assertion, position, |amount| {
        record_source_accesses(accounting, amount, track_source)
    })
}

fn try_charge_frontier_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, amount)?;
    accounting.frontier_bookkeeping = add(
        accounting.frontier_bookkeeping,
        amount,
        Resource::ExecutionWork,
    )?;
    Ok(())
}

fn try_charge_state(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, 1)?;
    accounting.state_evaluations = add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn try_charge_transition(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_transition_amount(accounting, admitted_work_bound, 1)
}

fn try_charge_transition_amount(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, amount)?;
    accounting.transition_checks = add(
        accounting.transition_checks,
        amount,
        Resource::ExecutionWork,
    )?;
    Ok(())
}

fn try_charge_assertion(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_transition(accounting, admitted_work_bound)?;
    accounting.assertion_checks = add(accounting.assertion_checks, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn try_charge_root(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, 1)?;
    accounting.root_probes = add(accounting.root_probes, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn try_charge_replay(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, 1)?;
    accounting.replay_steps = add(accounting.replay_steps, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn try_charge_event(
    accounting: &mut ExecutionAccounting,
    admitted_work_bound: usize,
) -> Result<(), Error> {
    try_charge_amount(accounting, admitted_work_bound, 1)?;
    accounting.successful_paths = add(accounting.successful_paths, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn validate_admitted_work(
    accounting: &ExecutionAccounting,
    admitted_work_bound: usize,
    caller_limit: usize,
) -> Result<(), Error> {
    let observed = add(
        accounting.utf8_validation_work,
        add(
            add(
                accounting.required_literal_source_bytes,
                accounting.required_literal_comparisons,
                Resource::ExecutionWork,
            )?,
            add(
                add(
                    add(
                        accounting.state_evaluations,
                        accounting.transition_checks,
                        Resource::ExecutionWork,
                    )?,
                    accounting.root_probes,
                    Resource::ExecutionWork,
                )?,
                add(
                    add(
                        accounting.replay_steps,
                        accounting.successful_paths,
                        Resource::ExecutionWork,
                    )?,
                    accounting.frontier_bookkeeping,
                    Resource::ExecutionWork,
                )?,
                Resource::ExecutionWork,
            )?,
            Resource::ExecutionWork,
        )?,
        Resource::ExecutionWork,
    )?;
    if observed != accounting.work {
        return Err(Error::InternalInvariant(
            "admitted work counters do not sum to observed work",
        ));
    }
    enforce(observed, admitted_work_bound, Resource::ExecutionWork)?;
    enforce(observed, caller_limit, Resource::ExecutionWork)
}

fn index(position: usize, state: usize, states: usize) -> Result<usize, Error> {
    add(
        mul(position, states, Resource::TableCells)?,
        state,
        Resource::TableCells,
    )
}

fn encode(end: usize) -> Result<usize, Error> {
    add(end, 1, Resource::Boundaries)
}

fn decode(encoded: usize) -> Option<usize> {
    encoded.checked_sub(1)
}

fn ceil_div(value: usize, divisor: usize) -> Result<usize, Error> {
    let adjustment = divisor
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("zero row-log divisor"))?;
    add(value, adjustment, Resource::LogBytes)?
        .checked_div(divisor)
        .ok_or(Error::InternalInvariant("zero row-log divisor"))
}

fn encoded_width(maximum: usize) -> usize {
    maximum
        .to_le_bytes()
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(1, |index| index.saturating_add(1))
}

fn write_encoded(record: &mut [u8], value: usize) -> Result<(), Error> {
    let encoded = value.to_le_bytes();
    let source = encoded.get(..record.len()).ok_or(Error::InternalInvariant(
        "endpoint record exceeds word width",
    ))?;
    if encoded
        .get(record.len()..)
        .ok_or(Error::InternalInvariant(
            "endpoint record exceeds word width",
        ))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InternalInvariant(
            "reachable endpoint exceeds admitted record width",
        ));
    }
    record.copy_from_slice(source);
    Ok(())
}

fn read_encoded(record: &[u8]) -> Result<usize, Error> {
    let mut encoded = [0_u8; core::mem::size_of::<usize>()];
    let target = encoded
        .get_mut(..record.len())
        .ok_or(Error::InternalInvariant(
            "endpoint record exceeds word width",
        ))?;
    target.copy_from_slice(record);
    Ok(usize::from_le_bytes(encoded))
}

fn set_bit(bytes: &mut [u8], index: usize) -> Result<(), Error> {
    let byte = bytes
        .get_mut(index / 8)
        .ok_or(Error::InternalInvariant("decision bit outside row"))?;
    *byte |= 1_u8 << (index % 8);
    Ok(())
}

fn read_bit(bytes: &[u8], index: usize) -> Result<bool, Error> {
    let byte = bytes
        .get(index / 8)
        .ok_or(Error::InternalInvariant("decision bit outside row"))?;
    Ok(byte & (1_u8 << (index % 8)) != 0)
}

fn zeroed_usizes(length: usize, resource: Resource) -> Result<ExactVec<usize>, Error> {
    #[cfg(test)]
    if length != 0 && allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource,
            items: length,
        });
    }
    let mut values = ExactVec::try_with_capacity(length)
        .map_err(|error| exact_allocation_error(error, resource, length))?;
    for _ in 0..length {
        values
            .try_push(0)
            .map_err(|_| Error::InternalInvariant("exact zeroed allocation changed capacity"))?;
    }
    Ok(values)
}

fn zeroed_bytes(length: usize, resource: Resource) -> Result<Vec<u8>, Error> {
    #[cfg(test)]
    if length != 0 && allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource,
            items: length,
        });
    }
    zeroed_exact(length).map_err(|error| exact_allocation_error(error, resource, length))
}

fn operation_identity(
    plan: PlanId,
    strategy: Strategy,
    kind: OperationKind,
    physical_route: OperationPhysicalRoute,
) -> OperationId {
    let strategy_tag = match strategy {
        Strategy::FullTable => 1_u8,
        Strategy::ReverseSequentialRows => 2,
    };
    let kind_tag = match kind {
        OperationKind::Spans => 1_u8,
        OperationKind::Count => 2,
        OperationKind::Sum => 3,
    };
    // Preserve the incumbent dense and terminal-frontier tags exactly while
    // assigning every other selected physical executor its own discriminator.
    let route_tag = match physical_route {
        OperationPhysicalRoute::DenseRows => 0,
        OperationPhysicalRoute::OrderedRootRows => 131,
        OperationPhysicalRoute::RequiredSuffixRows => 17,
        OperationPhysicalRoute::TerminalFrontierRows => 43,
        OperationPhysicalRoute::CachedFrontier => 61,
        OperationPhysicalRoute::RequiredInternalAnchor => 79,
        OperationPhysicalRoute::UrlAggregate => 97,
        OperationPhysicalRoute::StateByteSpanSum => 167,
        OperationPhysicalRoute::Candidate => 113,
        OperationPhysicalRoute::StartDomain => 149,
        // StateByteSpanSum already owns 167. Keep the composed ordered route
        // independently typed so the two source-independent SpanSum proofs
        // can never authenticate the same operation identity.
        OperationPhysicalRoute::OrderedBoundedSpanSum => 181,
        OperationPhysicalRoute::OrderedBoundedSpanSumEvents => 211,
        OperationPhysicalRoute::RootAssertion => 193,
    };
    let mut bytes = plan.bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let ordinal = u8::try_from(index).unwrap_or(0);
        *byte = byte
            .wrapping_add(strategy_tag.wrapping_mul(17))
            .wrapping_add(route_tag)
            .rotate_left(u32::from(kind_tag % 8))
            ^ ordinal.wrapping_mul(29);
    }
    OperationId(bytes)
}

const OPERATION_LIMITS_IDENTITY_DOMAIN: &[u8] = b"fre.aggregate.operation-limits.identity.v1\0";

fn operation_limits_identity(limits: OperationLimits) -> OperationLimitsId {
    let fields = [
        (1_u8, limits.max_boundaries),
        (2, limits.max_table_cells),
        (3, limits.max_random_access_bytes),
        (4, limits.max_scratch_bytes),
        (5, limits.max_log_bytes),
        (6, limits.max_sequential_bytes),
        (7, limits.max_match_events),
        (8, limits.max_output_matches),
        (9, limits.max_output_bytes),
        (10, limits.max_span_sum),
        (11, limits.max_peak_bytes),
        (12, limits.max_work),
    ];
    let mut hash = Sha256::new();
    hash.update(OPERATION_LIMITS_IDENTITY_DOMAIN);
    for (tag, value) in fields {
        hash.update([tag]);
        let canonical =
            u128::try_from(value).expect("Rust usize is never wider than the canonical u128 field");
        hash.update(canonical.to_le_bytes());
    }
    let digest = hash.finalize();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    OperationLimitsId(identity)
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;
    use regex_syntax::hir::{Hir, Look};

    use crate::accounting::ExecutionAccounting;
    use crate::candidate;
    use crate::program::AssertionContext;
    use crate::{
        CompileLimits, CompiledRegex, Error, OperationLimits, Resource, RustByteProfile, Strategy,
    };

    use super::{
        CANDIDATE_EXECUTION_ALLOCATIONS, CONTINUATION_OPERATION_ACCOUNTING_VERSION,
        CONTINUATION_OPERATION_ALGORITHM_VERSION, CONTINUATION_OPERATION_MAX_ALLOCATIONS,
        CachedFrontierRequirements, CachedFrontierStore, CachedTransitionSlot,
        MAX_CACHED_FRONTIERS, OperationAttemptKind, OperationKind, OperationLimitsId,
        OperationPhysicalRoute, OperationPrepublicationFallback, OperationProspective,
        RequiredLiteralScan, Requirements, RowReader, RowStorage, RowStore, StateByteClassBoundary,
        StateByteSpanSumPlan, StateByteSpanSumTopology, UNCACHED_FRONTIER, allocation_fault,
        cached_boundary_symbol, cached_compute_row, cached_frontier_amortizes_dense,
        cached_frontier_words, cached_program_assertion_mask, cached_retained_candidate_bit,
        compact_operation_allocation_count, decode, dense_reduction_work_floor, encoded_width,
        exact_filled, fixed_continuation_beats_dense, operation_identity, read_encoded,
        scan_required_literals, write_encoded,
    };

    fn assert_byte_row_case_parity<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        compiled: &CompiledRegex,
        haystack: &[u8],
        position: usize,
        input: u8,
        future_live: bool,
        caller_work_limit: usize,
    ) -> (usize, usize) {
        let program = &compiled.program;
        let states = program.insts.len();
        let mut future =
            exact_filled(states, 0_usize, Resource::RandomAccessBytes).expect("future row");
        if future_live {
            for (index, value) in future.iter_mut().enumerate() {
                *value = (index % 2).saturating_add(1);
            }
        }
        let future_rows = [future];
        let mut incumbent_row = vec![0_usize; states];
        let mut byte_row = incumbent_row.clone();
        let record_bytes = if SPLIT_DECISIONS {
            program.split_count.saturating_add(8) / 8
        } else {
            encoded_width(haystack.len().saturating_add(1))
        };
        let mut incumbent_record = vec![0_u8; record_bytes];
        let mut byte_record = incumbent_record.clone();
        let mut incumbent_accounting = ExecutionAccounting::default();
        let mut byte_accounting = ExecutionAccounting::default();
        let assertions =
            AssertionContext::new(haystack, 0, haystack.len()).expect("assertion context");
        let storage = if SPLIT_DECISIONS {
            RowStorage::SplitDecisions
        } else {
            RowStorage::ReachableEndpoints
        };
        let incumbent = RowStore::build_row::<true, OBSERVED_WORK, false>(
            program,
            haystack,
            assertions,
            position,
            input,
            &mut incumbent_row,
            &future_rows,
            &mut incumbent_record,
            storage,
            &mut incumbent_accounting,
            usize::MAX,
            caller_work_limit,
            false,
        );
        let specialized = RowStore::build_byte_row::<OBSERVED_WORK, SPLIT_DECISIONS>(
            program,
            position,
            input,
            &mut byte_row,
            &future_rows[0],
            &mut byte_record,
            &mut byte_accounting,
            usize::MAX,
            caller_work_limit,
        );
        assert_eq!(specialized, incumbent);
        assert_eq!(byte_row, incumbent_row);
        assert_eq!(byte_record, incumbent_record);
        assert_eq!(byte_accounting, incumbent_accounting);
        (byte_accounting.work, byte_row[program.entry])
    }

    fn assert_byte_row_mode_parity<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        compiled: &CompiledRegex,
    ) {
        let haystack = b"acz";
        let mut saw_root_success = false;
        let mut saw_root_failure = false;
        for future_live in [false, true] {
            for (position, input) in haystack.iter().copied().enumerate() {
                let (exact_work, root) =
                    assert_byte_row_case_parity::<OBSERVED_WORK, SPLIT_DECISIONS>(
                        compiled,
                        haystack,
                        position,
                        input,
                        future_live,
                        usize::MAX,
                    );
                saw_root_success |= root != 0;
                saw_root_failure |= root == 0;
                let _ = assert_byte_row_case_parity::<OBSERVED_WORK, SPLIT_DECISIONS>(
                    compiled,
                    haystack,
                    position,
                    input,
                    future_live,
                    exact_work,
                );
                if OBSERVED_WORK && exact_work > 0 {
                    let _ = assert_byte_row_case_parity::<OBSERVED_WORK, SPLIT_DECISIONS>(
                        compiled,
                        haystack,
                        position,
                        input,
                        future_live,
                        exact_work.saturating_sub(1),
                    );
                }
            }
        }
        assert!(saw_root_success);
        assert!(saw_root_failure);
    }

    fn run_byte_rows_case<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        compiled: &CompiledRegex,
        haystack: &[u8],
        caller_work_limit: usize,
        specialized: bool,
    ) -> (Result<usize, Error>, Vec<u8>, ExecutionAccounting) {
        let program = &compiled.program;
        let states = program.insts.len();
        let first = exact_filled(states, 0_usize, Resource::RandomAccessBytes).unwrap();
        let second = exact_filled(states, 0_usize, Resource::RandomAccessBytes).unwrap();
        let mut rows = [first, second];
        let storage = if SPLIT_DECISIONS {
            RowStorage::SplitDecisions
        } else {
            RowStorage::ReachableEndpoints
        };
        let record_bytes = if SPLIT_DECISIONS {
            program.split_count.saturating_add(8) / 8
        } else {
            encoded_width(haystack.len().saturating_add(1))
        };
        let store_bytes = record_bytes
            .checked_mul(haystack.len().saturating_add(1))
            .expect("tiny test row log fits usize");
        let mut store = vec![0_u8; store_bytes];
        let mut accounting = ExecutionAccounting::default();
        let assertions =
            AssertionContext::new(haystack, 0, haystack.len()).expect("assertion context");
        let result = (|| {
            let terminal_record = store
                .get_mut(..record_bytes)
                .ok_or(Error::InternalInvariant("terminal row outside row log"))?;
            let (row, future_rows) = rows
                .split_first_mut()
                .ok_or(Error::InternalInvariant("row ring is empty"))?;
            RowStore::build_row::<false, OBSERVED_WORK, false>(
                program,
                haystack,
                assertions,
                haystack.len(),
                0,
                row,
                future_rows,
                terminal_record,
                storage,
                &mut accounting,
                usize::MAX,
                caller_work_limit,
                true,
            )?;
            accounting.sequential_bytes_written = super::add(
                accounting.sequential_bytes_written,
                record_bytes,
                Resource::SequentialBytes,
            )?;
            rows.rotate_right(1);

            if specialized {
                return RowStore::build_byte_rows::<OBSERVED_WORK, SPLIT_DECISIONS>(
                    program,
                    haystack,
                    &mut rows,
                    &mut store,
                    record_bytes,
                    record_bytes,
                    &mut accounting,
                    usize::MAX,
                    caller_work_limit,
                    true,
                );
            }

            let mut write_offset = record_bytes;
            for (position, input) in haystack.iter().copied().enumerate().rev() {
                super::record_source_accesses(&mut accounting, 1, true)?;
                let end = super::add(write_offset, record_bytes, Resource::LogBytes)?;
                let record = store
                    .get_mut(write_offset..end)
                    .ok_or(Error::InternalInvariant("row-log write outside store"))?;
                let (row, future_rows) = rows
                    .split_first_mut()
                    .ok_or(Error::InternalInvariant("row ring is empty"))?;
                RowStore::build_row::<true, OBSERVED_WORK, false>(
                    program,
                    haystack,
                    assertions,
                    position,
                    input,
                    row,
                    future_rows,
                    record,
                    storage,
                    &mut accounting,
                    usize::MAX,
                    caller_work_limit,
                    true,
                )?;
                accounting.sequential_bytes_written = super::add(
                    accounting.sequential_bytes_written,
                    record_bytes,
                    Resource::SequentialBytes,
                )?;
                write_offset = end;
                rows.rotate_right(1);
            }
            Ok(write_offset)
        })();
        (result, store, accounting)
    }

    fn assert_byte_rows_mode_parity<const OBSERVED_WORK: bool, const SPLIT_DECISIONS: bool>(
        compiled: &CompiledRegex,
        haystack: &[u8],
    ) {
        let specialized = run_byte_rows_case::<OBSERVED_WORK, SPLIT_DECISIONS>(
            compiled,
            haystack,
            usize::MAX,
            true,
        );
        let incumbent = run_byte_rows_case::<OBSERVED_WORK, SPLIT_DECISIONS>(
            compiled,
            haystack,
            usize::MAX,
            false,
        );
        assert_eq!(specialized, incumbent);
        assert!(specialized.0.is_ok());
        let exact_work = specialized.2.work;
        let one_below_work = exact_work
            .checked_sub(1)
            .expect("nonzero test work has a predecessor");

        for caller_work_limit in [exact_work, one_below_work] {
            let specialized = run_byte_rows_case::<OBSERVED_WORK, SPLIT_DECISIONS>(
                compiled,
                haystack,
                caller_work_limit,
                true,
            );
            let incumbent = run_byte_rows_case::<OBSERVED_WORK, SPLIT_DECISIONS>(
                compiled,
                haystack,
                caller_work_limit,
                false,
            );
            assert_eq!(specialized, incumbent);
            if OBSERVED_WORK && caller_work_limit < exact_work {
                assert!(specialized.0.is_err());
            } else {
                assert!(specialized.0.is_ok());
            }
        }
    }

    #[test]
    fn dense_byte_row_kernel_matches_incumbent_modes_and_work_boundaries() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"(?:ab|ac|d)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(!compiled.program.contains_scalar_transition());
        assert!(!compiled.program.contains_assertion());
        assert!(compiled.program.split_count > 0);
        let asserted = start_domain_regex(r"^a");
        assert!(asserted.program.contains_assertion());
        assert_byte_row_mode_parity::<false, false>(&compiled);
        assert_byte_row_mode_parity::<false, true>(&compiled);
        assert_byte_row_mode_parity::<true, false>(&compiled);
        assert_byte_row_mode_parity::<true, true>(&compiled);
    }

    #[test]
    fn dense_byte_rows_ping_pong_matches_generic_odd_even_modes_and_work_boundaries() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"(?:ab|ac|d)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(!compiled.program.contains_scalar_transition());
        assert!(!compiled.program.contains_assertion());
        assert!(compiled.program.split_count > 0);
        for haystack in [b"acz".as_slice(), b"dacadz".as_slice()] {
            assert_byte_rows_mode_parity::<false, false>(&compiled, haystack);
            assert_byte_rows_mode_parity::<false, true>(&compiled, haystack);
            assert_byte_rows_mode_parity::<true, false>(&compiled, haystack);
            assert_byte_rows_mode_parity::<true, true>(&compiled, haystack);
        }
    }

    #[test]
    fn dense_byte_rows_keep_preclamp_work_admission_and_partial_receipt_exact() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"(?:ab|ac|d)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(!compiled.program.contains_scalar_transition());
        assert!(!compiled.program.contains_assertion());
        let haystack = b"dacadzacz";
        let boundaries = haystack.len() + 1;
        let limits = OperationLimits::default();
        let structural = Requirements::new::<true>(
            &compiled.program,
            boundaries,
            Strategy::ReverseSequentialRows,
            1,
            limits,
        )
        .unwrap();
        assert!(structural.work_bound <= limits.max_work);

        let admitted = compiled
            .count_value_with_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
                usize::MAX,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(
            admitted.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::DenseRows)
        );
        let exact_work = admitted.receipt.actual.work;
        assert!(exact_work < structural.work_bound);

        let exact = compiled
            .count_value_with_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: exact_work,
                    ..limits
                },
                usize::MAX,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(exact.value, admitted.value);
        assert_eq!(exact.receipt.actual, admitted.receipt.actual);
        assert_eq!(exact.receipt.prospective.unwrap().work_bound, exact_work);

        // The terminal row consumes one complete program-state charge set.
        // Admit one further charge so refusal occurs inside the first input
        // row, where the fully-admitted specialization must remain disabled.
        let partial_limit = compiled
            .program
            .execution_state_work()
            .checked_add(1)
            .unwrap();
        assert!(partial_limit < exact_work);
        let partial = compiled
            .count_value_with_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: partial_limit,
                    ..limits
                },
                usize::MAX,
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(
            partial.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: partial_limit + 1,
                limit: partial_limit,
            }
        );
        assert_eq!(
            partial.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::DenseRows)
        );
        let prospective = partial.receipt.prospective.unwrap();
        assert_eq!(prospective.work_bound, partial_limit);
        assert_eq!(partial.receipt.actual.work, partial_limit);
        assert!(prospective.contains(partial.receipt.actual));
    }

    fn endpoint_scalar_repeat() -> CompiledRegex {
        let hir = ParserBuilder::new().build().parse(r"^.{249}$").unwrap();
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn terminal_frontier_count() -> CompiledRegex {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"cargo[\\/].*[\\/]")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(!compiled.terminal_frontier.is_empty());
        compiled
    }

    fn candidate_count() -> CompiledRegex {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"a|ab|x{1,3}z|q.r|[0-9]+-x")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(compiled.candidate.is_some());
        compiled
    }

    fn start_domain_regex(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn required_literal_regex(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(compiled.required_literals.len() >= 2);
        compiled
    }

    #[test]
    fn required_literal_miss_precedes_reverse_rows_with_complete_receipts() {
        let haystack = b"bcdefghijklmnopq".repeat(500);
        for pattern in [r".[A-Z][a-z]+efghijklmnopq", r".[a-z]+[A-Z]efghijklmnopq"] {
            let compiled = required_literal_regex(pattern);
            assert_eq!(
                compiled.compile_accounting().required_literal_source_passes,
                1
            );
            let admitted = compiled
                .span_sum_value_with_receipt(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(admitted.value, 0);
            assert!(admitted.receipt.authenticates_success());
            assert_eq!(admitted.receipt.actual_allocations, 0);
            assert_eq!(
                admitted.receipt.actual.required_literal_source_bytes,
                haystack.len()
            );
            assert!(
                admitted.receipt.actual.required_literal_comparisons
                    >= haystack.len().checked_mul(2).unwrap()
            );
            assert_eq!(admitted.receipt.actual.state_evaluations, 0);
            assert_eq!(admitted.receipt.actual.random_access_bytes_read, 0);
            assert_eq!(admitted.receipt.actual.log_bytes, 0);
            let prospective = admitted.receipt.prospective.unwrap();
            assert!(prospective.contains(admitted.receipt.actual));
            assert_eq!(
                prospective.accounting.required_literal_source_bytes,
                haystack.len()
            );

            let hot_count = compiled
                .count_value_with_counters(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(hot_count.value, 0);
            assert!(hot_count.receipt.closes());
            assert_eq!(
                hot_count.receipt.accounting.required_literal_source_bytes,
                haystack.len()
            );
            assert_eq!(hot_count.receipt.accounting.state_evaluations, 0);
            assert_eq!(hot_count.receipt.accounting.random_access_bytes_read, 0);

            let hot_span_sum = compiled
                .span_sum_value_with_counters(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(hot_span_sum.value, 0);
            assert!(hot_span_sum.receipt.closes());
            assert_eq!(
                hot_span_sum
                    .receipt
                    .accounting
                    .required_literal_source_bytes,
                haystack.len()
            );
            assert_eq!(hot_span_sum.receipt.accounting.state_evaluations, 0);
            assert_eq!(hot_span_sum.receipt.accounting.random_access_bytes_read, 0);

            let work_one_below = compiled
                .span_sum_value_with_receipt(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_work: admitted.receipt.actual.work - 1,
                        ..OperationLimits::default()
                    },
                )
                .unwrap_err();
            assert!(matches!(
                work_one_below.source,
                Error::ResourceLimit {
                    resource: Resource::ExecutionWork,
                    ..
                }
            ));
            assert_eq!(
                work_one_below.receipt.actual,
                ExecutionAccounting::default()
            );
            assert!(
                work_one_below
                    .receipt
                    .authenticates_source(&work_one_below.source)
            );

            let sequential_one_below = compiled
                .span_sum_value_with_receipt(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_sequential_bytes: prospective.sequential_bytes - 1,
                        ..OperationLimits::default()
                    },
                )
                .unwrap_err();
            assert!(matches!(
                sequential_one_below.source,
                Error::ResourceLimit {
                    resource: Resource::SequentialBytes,
                    ..
                }
            ));
            assert_eq!(
                sequential_one_below.receipt.actual,
                ExecutionAccounting::default()
            );
            assert!(
                sequential_one_below
                    .receipt
                    .authenticates_source(&sequential_one_below.source)
            );
        }
    }

    #[test]
    fn small_required_literal_sets_use_bounded_native_services() {
        // The trailing repetition keeps this fixture on the required-literal
        // rejection route instead of the exact repeated-delimiter reducer.
        let pattern = r"(.*?,){13}z+";
        let compiled = required_literal_regex(pattern);
        assert_eq!(compiled.required_literals.len(), 2);
        assert_eq!(
            compiled.compile_accounting().required_literal_source_passes,
            2
        );
        assert!(compiled.required_literals.iter().all(u128::is_power_of_two));
        let haystack = b"a,".repeat(2048);
        let prospective =
            RequiredLiteralScan::prospective(haystack.len(), compiled.required_literals).unwrap();
        assert_eq!(
            prospective.source_bytes,
            haystack.len().checked_mul(2).unwrap()
        );
        assert_eq!(prospective.comparisons, prospective.source_bytes);

        let mut accounting = ExecutionAccounting::default();
        let observed = scan_required_literals(&compiled, &haystack, &mut accounting).unwrap();
        assert!(!observed.all_present);
        assert_eq!(observed.source_bytes, haystack.len() + 2);
        assert_eq!(observed.comparisons, observed.source_bytes);
        assert_eq!(
            accounting.required_literal_source_bytes,
            observed.source_bytes
        );
        assert_eq!(
            accounting.required_literal_comparisons,
            observed.comparisons
        );
        assert_eq!(accounting.sequential_bytes_read, observed.source_bytes);
        assert_eq!(accounting.work, observed.work().unwrap());
        assert!(prospective.source_bytes >= observed.source_bytes);
        assert!(prospective.comparisons >= observed.comparisons);

        let admitted = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(admitted.value, 0);
        assert_eq!(admitted.receipt.actual.state_evaluations, 0);
        assert_eq!(
            admitted.receipt.actual.required_literal_source_bytes,
            observed.source_bytes
        );
        assert!(admitted.receipt.authenticates_success());
        assert!(
            admitted
                .receipt
                .prospective
                .unwrap()
                .contains(admitted.receipt.actual)
        );
    }

    #[test]
    fn required_literal_hit_preserves_count_span_sum_and_span_priority() {
        let pattern = r".[A-Z][a-z]+efghijklmnopq";
        let haystack = b"--_Qzzefghijklmnopq--_Axyefghijklmnopq--";
        let compiled = required_literal_regex(pattern);
        let reference = RegexBuilder::new(pattern).build().unwrap();
        let expected = reference
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| end - start)
            .sum::<usize>();

        let count = compiled
            .admit_count_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(count.admitted.value(), expected.len());
        assert!(count.receipt.authenticates_success());
        assert!(count.receipt.actual.required_literal_source_bytes > 0);
        assert!(count.receipt.actual.state_evaluations > 0);

        let sum = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(sum.value, expected_sum);
        assert!(sum.receipt.authenticates_success());

        let spans = compiled
            .admit_spans_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            spans
                .admitted
                .as_slice()
                .iter()
                .map(|span| (span.start, span.end))
                .collect::<Vec<_>>(),
            expected
        );
        assert!(spans.receipt.authenticates_success());
    }

    fn assert_start_domain_range_parity(
        compiled: &CompiledRegex,
        haystack: &[u8],
        range: core::ops::Range<usize>,
    ) {
        let expected = compiled
            .admit_spans(
                haystack,
                range.clone(),
                Strategy::FullTable,
                OperationLimits::default(),
            )
            .unwrap();
        let expected_sum = expected
            .as_slice()
            .iter()
            .map(|span| {
                span.end
                    .checked_sub(span.start)
                    .expect("admitted span endpoints are ordered")
            })
            .sum::<usize>();
        let count = compiled
            .count_value_attempt(
                haystack,
                range.clone(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(count.value, expected.as_slice().len());
        assert_eq!(
            count.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StartDomain)
        );
        assert!(count.receipt.authenticates_success());
        let sum = compiled
            .span_sum_value_with_receipt(
                haystack,
                range,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(sum.value, expected_sum);
        assert_eq!(
            sum.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StartDomain)
        );
        assert!(sum.receipt.authenticates_success());
    }

    #[test]
    fn start_domain_matches_dense_for_absolute_line_ranges_and_empty_languages() {
        let cases: [(&str, &[u8]); 5] = [
            (r"\A(?:ab|a)*?\z", b"aba"),
            (r"\A(?:ab|a)*?\z", b"xaba"),
            (r"(?m:^a*)", b"\r\naa\n\ra\r\n"),
            (r"(?Rm:^a*)", b"\r\naa\n\ra\r\n"),
            (r"(?m:^)(?:ab|a)+", b"ab\nx\naaa\n"),
        ];
        for (pattern, haystack) in cases {
            let compiled = start_domain_regex(pattern);
            assert!(
                compiled.program.start_domain.is_sparse(),
                "pattern={pattern:?}"
            );
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    assert_start_domain_range_parity(&compiled, haystack, start..end);
                }
            }
        }

        let empty_hir = Hir::concat(vec![Hir::look(Look::Start), Hir::fail()]);
        let empty = CompiledRegex::from_hir(
            &empty_hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert_start_domain_range_parity(&empty, b"", 0..0);
        assert_start_domain_range_parity(&empty, b"abc", 0..3);
        assert_start_domain_range_parity(&empty, b"abc", 1..3);
    }

    #[test]
    fn start_domain_priority_and_empty_match_differential_is_exhaustive_on_small_inputs() {
        let patterns = [
            r"\A(?:a|ab)*b?",
            r"\A(?:a*?b|ab*)",
            r"\A(?:|a)*",
            r"(?m:^)(?:a|ab)*b?",
            r"(?m:^)(?:a*?b|ab*)",
            r"(?Rm:^)(?:a|ab)*?b?",
        ];
        let alphabet = [b'a', b'b', b'\r', b'\n', 0xFF];
        let mut haystack = Vec::new();
        for pattern in patterns {
            let compiled = start_domain_regex(pattern);
            for encoded in 0_usize..512 {
                haystack.clear();
                let mut value = encoded;
                let length = encoded % 7;
                for _ in 0..length {
                    haystack.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_start_domain_range_parity(&compiled, &haystack, start..end);
                    }
                }
            }
        }
    }

    #[test]
    fn captures_erased_selector_retains_and_executes_line_start_domain() {
        let compiled = start_domain_regex(r"(?m:^ *(\w+) +(\w+) +(\w+))");
        assert_eq!(
            compiled.uniform_capture_count_route(),
            OperationPhysicalRoute::StartDomain
        );
        let haystack = b"one two three\nbad\na  bb   ccc\n";
        assert_start_domain_range_parity(&compiled, haystack, 0..haystack.len());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test audits every exact and one-below start-domain receipt dimension"
    )]
    fn start_domain_receipts_close_exact_and_one_below_limits() {
        let compiled = start_domain_regex(r"(?m:^a*)");
        let haystack = b"aa\nx\na\n";
        let baseline = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let actual = baseline.receipt.actual;
        let exact = OperationLimits {
            max_boundaries: haystack.len() + 1,
            max_random_access_bytes: actual.random_access_peak_bytes,
            max_scratch_bytes: actual.scratch_peak_bytes,
            max_log_bytes: 0,
            max_sequential_bytes: 0,
            max_match_events: actual.successful_paths,
            max_output_matches: actual.emitted_matches,
            max_output_bytes: 0,
            max_span_sum: 0,
            max_peak_bytes: actual.peak_bytes,
            max_work: actual.work,
            ..OperationLimits::default()
        };
        let exact_attempt = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_attempt.value, baseline.value);
        assert_eq!(exact_attempt.receipt.actual, actual);
        assert!(exact_attempt.receipt.authenticates_success());
        assert_eq!(
            exact_attempt.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StartDomain)
        );
        let mut observed = None;
        let allocation_exact = compiled
            .admit_count_observed_with_start_domain_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
                candidate::START_DOMAIN_EXECUTION_ALLOCATIONS,
                |prospective| {
                    observed = Some(prospective);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(allocation_exact.admitted.value(), baseline.value);
        assert_eq!(
            allocation_exact.receipt.actual_allocations,
            candidate::START_DOMAIN_EXECUTION_ALLOCATIONS
        );
        assert_eq!(
            observed.unwrap().allocations,
            candidate::START_DOMAIN_EXECUTION_ALLOCATIONS
        );
        assert!(allocation_exact.receipt.authenticates_success());

        let mut refusal_observed = None;
        let allocation_refusal = compiled
            .admit_count_observed_with_start_domain_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
                candidate::START_DOMAIN_EXECUTION_ALLOCATIONS - 1,
                |prospective| {
                    refusal_observed = Some(prospective);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(matches!(
            allocation_refusal.source,
            Error::ResourceLimit {
                resource: Resource::Allocations,
                required: candidate::START_DOMAIN_EXECUTION_ALLOCATIONS,
                limit,
            } if limit == candidate::START_DOMAIN_EXECUTION_ALLOCATIONS - 1
        ));
        assert_eq!(
            refusal_observed.unwrap().allocations,
            candidate::START_DOMAIN_EXECUTION_ALLOCATIONS
        );
        assert_eq!(
            allocation_refusal.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StartDomain)
        );
        assert_eq!(
            allocation_refusal.receipt.actual,
            ExecutionAccounting::default()
        );
        assert_eq!(allocation_refusal.receipt.actual_allocations, 0);
        assert!(allocation_refusal.closes());
        for (resource, one_below) in [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: exact.max_boundaries - 1,
                    ..exact
                },
            ),
            (
                Resource::RandomAccessBytes,
                OperationLimits {
                    max_random_access_bytes: exact.max_random_access_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ScratchBytes,
                OperationLimits {
                    max_scratch_bytes: exact.max_scratch_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: exact.max_match_events - 1,
                    ..exact
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: exact.max_output_matches - 1,
                    ..exact
                },
            ),
            (
                Resource::PeakBytes,
                OperationLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ExecutionWork,
                OperationLimits {
                    max_work: exact.max_work - 1,
                    ..exact
                },
            ),
        ] {
            let failure = compiled
                .count_value_attempt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    one_below,
                )
                .unwrap_err();
            assert!(
                matches!(
                    failure.source,
                    Error::ResourceLimit {
                        resource: got,
                        ..
                    } if got == resource
                ),
                "one-below {resource:?}: {:?}",
                failure.source
            );
            assert!(failure.closes(), "one-below {resource:?}");
            assert_eq!(
                failure.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::StartDomain)
            );
        }

        let sum = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert!(sum.value > 0);
        let span_failure = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_span_sum: sum.value - 1,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            span_failure.source,
            Error::ResourceLimit {
                resource: Resource::SpanSum,
                required,
                limit,
            } if required == sum.value && limit == sum.value - 1
        ));
        assert!(span_failure.closes());
        assert_eq!(
            span_failure.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StartDomain)
        );
    }

    #[test]
    fn operation_prospective_enforces_every_operation_limit_dimension() {
        let prospective = OperationProspective {
            states: 2,
            boundaries: 3,
            table_cells: 5,
            row_storage: Some(RowStorage::ReachableEndpoints),
            row_record_bytes: 7,
            terminal_frontier: true,
            work_bound: 11,
            random_access_bytes: 13,
            scratch_bytes: 17,
            log_bytes: 19,
            sequential_bytes: 23,
            match_events: 29,
            output_matches: 31,
            output_bytes: 37,
            span_sum: 41,
            allocations: 42,
            peak_bytes: 43,
            accounting: ExecutionAccounting::default(),
        };
        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        };
        prospective.enforce_limits(exact).unwrap();

        macro_rules! assert_one_below {
            ($field:ident, $prospective:ident, $resource:expr) => {{
                let mut one_below = exact;
                one_below.$field = prospective.$prospective - 1;
                assert_eq!(
                    prospective.enforce_limits(one_below),
                    Err(Error::ResourceLimit {
                        resource: $resource,
                        required: prospective.$prospective,
                        limit: prospective.$prospective - 1,
                    })
                );
            }};
        }
        assert_one_below!(max_boundaries, boundaries, Resource::Boundaries);
        assert_one_below!(max_table_cells, table_cells, Resource::TableCells);
        assert_one_below!(
            max_random_access_bytes,
            random_access_bytes,
            Resource::RandomAccessBytes
        );
        assert_one_below!(max_scratch_bytes, scratch_bytes, Resource::ScratchBytes);
        assert_one_below!(max_log_bytes, log_bytes, Resource::LogBytes);
        assert_one_below!(
            max_sequential_bytes,
            sequential_bytes,
            Resource::SequentialBytes
        );
        assert_one_below!(max_match_events, match_events, Resource::MatchEvents);
        assert_one_below!(max_output_matches, output_matches, Resource::OutputMatches);
        assert_one_below!(max_output_bytes, output_bytes, Resource::OutputBytes);
        assert_one_below!(max_span_sum, span_sum, Resource::SpanSum);
        assert_one_below!(max_peak_bytes, peak_bytes, Resource::PeakBytes);
        assert_one_below!(max_work, work_bound, Resource::ExecutionWork);
    }

    #[test]
    fn operation_limits_identity_is_canonical_and_binds_every_field() {
        let ordered = OperationLimits {
            max_boundaries: 11,
            max_table_cells: 22,
            max_random_access_bytes: 33,
            max_scratch_bytes: 44,
            max_log_bytes: 55,
            max_sequential_bytes: 66,
            max_match_events: 77,
            max_output_matches: 88,
            max_output_bytes: 99,
            max_span_sum: 110,
            max_peak_bytes: 121,
            max_work: 132,
        };
        assert_eq!(
            OperationLimitsId::from_limits(ordered).bytes(),
            [
                0x0b, 0xba, 0xcb, 0xe1, 0x86, 0xc3, 0x4c, 0xfe, 0xf9, 0x11, 0x8c, 0xea, 0xf7, 0x42,
                0x5b, 0x5c,
            ]
        );
        assert_eq!(
            OperationLimitsId::from_limits(ordered),
            OperationLimitsId::from_limits(ordered)
        );

        let baseline = OperationLimits::default();
        let identity = OperationLimitsId::from_limits(baseline);
        let mutations = [
            OperationLimits {
                max_boundaries: baseline.max_boundaries - 1,
                ..baseline
            },
            OperationLimits {
                max_table_cells: baseline.max_table_cells - 1,
                ..baseline
            },
            OperationLimits {
                max_random_access_bytes: baseline.max_random_access_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_scratch_bytes: baseline.max_scratch_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_log_bytes: baseline.max_log_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_sequential_bytes: baseline.max_sequential_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_match_events: baseline.max_match_events - 1,
                ..baseline
            },
            OperationLimits {
                max_output_matches: baseline.max_output_matches - 1,
                ..baseline
            },
            OperationLimits {
                max_output_bytes: baseline.max_output_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_span_sum: baseline.max_span_sum - 1,
                ..baseline
            },
            OperationLimits {
                max_peak_bytes: baseline.max_peak_bytes - 1,
                ..baseline
            },
            OperationLimits {
                max_work: baseline.max_work - 1,
                ..baseline
            },
        ];
        for mutation in mutations {
            assert_ne!(OperationLimitsId::from_limits(mutation), identity);
        }
    }

    #[test]
    fn endpoint_count_attempt_invalid_range_has_no_prospective_or_actual_work() {
        let compiled = endpoint_scalar_repeat();
        let failure = compiled
            .admit_count_with_receipt(
                b"short",
                0..6,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap_err();
        assert_eq!(
            failure.source,
            Error::InvalidRange {
                start: 0,
                end: 6,
                haystack_len: 5,
            }
        );
        assert_eq!(failure.receipt.invocation.range, 0..6);
        assert_eq!(failure.receipt.invocation.haystack_len, 5);
        assert_eq!(failure.receipt.identity.regex_plan_id, compiled.plan_id());
        assert!(
            failure
                .receipt
                .identity
                .authenticates_limits(OperationLimits::default())
        );
        assert_eq!(failure.receipt.identity.operation_id(), None);
        assert_eq!(failure.receipt.prospective, None);
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert!(failure.closes());

        let mut mismatched = failure;
        mismatched.source = Error::InvalidRange {
            start: 0,
            end: 7,
            haystack_len: 5,
        };
        assert!(!mismatched.closes());
    }

    #[test]
    fn endpoint_count_attempt_limit_refuses_prepublished_prospective_before_source() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let failure = compiled
            .admit_count_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_output_matches: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        let prospective = failure
            .receipt
            .prospective
            .expect("generic route must publish P before source access");
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::OutputMatches,
                required: prospective.output_matches,
                limit: 0,
            }
        );
        assert!(failure.receipt.identity.operation_id().is_some());
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert!(prospective.contains(failure.receipt.actual));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one route-identity regression keeps incumbent, explicit, and ordinary receipt comparisons together"
    )]
    fn terminal_frontier_count_is_explicit_and_ordinary_receipt_count_is_unchanged() {
        let compiled = terminal_frontier_count();
        let haystack = b"xx cargo/registry/src/name/ yy cargo\\other\\ tail";
        let range = 0..haystack.len();

        let ordinary_before = compiled
            .admit_count_with_receipt(
                haystack,
                range.clone(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert!(!ordinary_before.admitted.certificate().terminal_frontier);
        assert_eq!(
            ordinary_before.receipt.identity.operation_id(),
            Some(operation_identity(
                compiled.plan_id(),
                Strategy::ReverseSequentialRows,
                OperationKind::Count,
                OperationPhysicalRoute::DenseRows,
            ))
        );
        assert!(
            ordinary_before
                .receipt
                .prospective
                .is_some_and(|prospective| !prospective.terminal_frontier)
        );

        let terminal = compiled
            .admit_count_with_terminal_frontier_receipt(
                haystack,
                range.clone(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(terminal.admitted.value(), ordinary_before.admitted.value());
        assert!(terminal.admitted.certificate().terminal_frontier);
        assert_eq!(
            terminal.receipt.identity.operation_id(),
            Some(operation_identity(
                compiled.plan_id(),
                Strategy::ReverseSequentialRows,
                OperationKind::Count,
                OperationPhysicalRoute::TerminalFrontierRows,
            ))
        );
        assert_eq!(
            terminal.receipt.identity.operation_id(),
            Some(terminal.admitted.certificate().operation_id())
        );
        assert_ne!(
            terminal.receipt.identity.operation_id(),
            ordinary_before.receipt.identity.operation_id()
        );
        assert!(
            terminal
                .receipt
                .prospective
                .is_some_and(|prospective| prospective.terminal_frontier)
        );
        assert_eq!(terminal.receipt.actual, terminal.admitted.accounting());

        // The incumbent automatic Count already selects this physical route;
        // the explicit receipt variant must preserve its route identity and
        // result rather than inventing a second executor.
        let incumbent = compiled
            .admit_count(
                haystack,
                range.clone(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(incumbent.value(), terminal.admitted.value());
        assert!(incumbent.certificate().terminal_frontier);
        assert_eq!(
            incumbent.certificate().operation_id(),
            terminal.admitted.certificate().operation_id()
        );
        assert_eq!(
            incumbent.certificate().physical_route,
            terminal.admitted.certificate().physical_route
        );
        assert!(
            terminal
                .admitted
                .certificate()
                .retains_published_prospective(terminal.receipt.prospective.as_ref().unwrap())
        );
        assert_eq!(incumbent.accounting(), terminal.admitted.accounting());

        let ordinary_after = compiled
            .admit_count_with_receipt(
                haystack,
                range,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            ordinary_after.admitted.value(),
            ordinary_before.admitted.value()
        );
        assert_eq!(
            ordinary_after.receipt.identity,
            ordinary_before.receipt.identity
        );
        assert_eq!(
            ordinary_after.receipt.prospective,
            ordinary_before.receipt.prospective
        );
        assert_eq!(
            ordinary_after.receipt.actual,
            ordinary_before.receipt.actual
        );
    }

    #[test]
    fn accounting_v7_terminal_frontier_reaches_nine_p_and_retains_smaller_no_match_a() {
        let compiled = terminal_frontier_count();
        let haystack = b"no terminal prefix here";
        let limits = OperationLimits::default();

        let count = compiled
            .admit_count_with_terminal_frontier_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        let count_p = count.receipt.prospective.unwrap();
        assert_eq!(count.admitted.value(), 0);
        assert_eq!(count_p.allocations, 8);
        assert!(count.receipt.actual_allocations < count_p.allocations);
        assert_eq!(count.admitted.certificate().prospective_allocations, 8);
        assert_eq!(
            usize::from(count.admitted.certificate().actual_allocations),
            count.receipt.actual_allocations
        );

        let spans = compiled
            .admit_spans(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        assert_eq!(
            spans.certificate().physical_route,
            OperationPhysicalRoute::TerminalFrontierRows
        );
        assert!(spans.as_slice().is_empty());
        assert_eq!(
            spans.certificate().prospective_allocations,
            CONTINUATION_OPERATION_MAX_ALLOCATIONS
        );
        assert_eq!(
            usize::from(spans.certificate().actual_allocations),
            count.receipt.actual_allocations
        );
        assert_eq!(
            usize::from(spans.certificate().prospective_allocations),
            count_p.allocations + 1
        );
        assert!(
            spans.certificate().actual_allocations < spans.certificate().prospective_allocations
        );

        let matching = b"cargo/registry/";
        let matching_spans = compiled
            .admit_spans(
                matching,
                0..matching.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        assert_eq!(matching_spans.as_slice().len(), 1);
        assert_eq!(
            matching_spans.certificate().prospective_allocations,
            CONTINUATION_OPERATION_MAX_ALLOCATIONS
        );
        assert_eq!(
            matching_spans.certificate().actual_allocations,
            CONTINUATION_OPERATION_MAX_ALLOCATIONS
        );

        // Intrinsic receipt publication must not turn the caller-independent
        // `usize::MAX` work sentinel into a random-read arithmetic fault. The
        // complete P is published first and the unchanged caller work limit
        // then refuses it without effects.
        let receipt_failure = compiled
            .admit_spans_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap_err();
        assert_eq!(
            receipt_failure.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: usize::MAX,
                limit: limits.max_work,
            }
        );
        let refused = receipt_failure.receipt.prospective.unwrap();
        assert_eq!(refused.work_bound, usize::MAX);
        assert_eq!(refused.accounting.random_access_bytes_read, usize::MAX);
        assert_eq!(
            receipt_failure.receipt.actual,
            ExecutionAccounting::default()
        );
        assert_eq!(receipt_failure.receipt.actual_allocations, 0);
    }

    #[test]
    fn accounting_v7_allocation_encoding_is_checked_at_its_route_maximum() {
        for allocations in 0..=usize::from(CONTINUATION_OPERATION_MAX_ALLOCATIONS) {
            assert_eq!(
                compact_operation_allocation_count(allocations).unwrap(),
                u8::try_from(allocations).unwrap()
            );
        }
        assert_eq!(
            compact_operation_allocation_count(
                usize::from(CONTINUATION_OPERATION_MAX_ALLOCATIONS) + 1
            ),
            Err(Error::InternalInvariant(
                "continuation allocation count exceeds its accounting-version structural maximum"
            ))
        );
    }

    #[test]
    fn url_route_projects_success_allocations_and_terminal_partial_a() {
        let plan = fre_kernels::UrlAggregatePlan::build(
            b"COM",
            &[3],
            fre_kernels::UrlAggregateBuildLimits::default(),
        )
        .unwrap();
        let mut compiled = candidate_count();
        compiled.url_aggregate = Some(plan);
        let haystack = b"a.com";

        let success = compiled
            .admit_span_sum_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            success.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::UrlAggregate)
        );
        assert_eq!(success.receipt.prospective.unwrap().allocations, 1);
        assert_eq!(success.receipt.actual_allocations, 1);
        assert_eq!(success.admitted.certificate().prospective_allocations, 1);
        assert_eq!(success.admitted.certificate().actual_allocations, 1);

        let limits = OperationLimits {
            max_work: haystack.len() + 3,
            ..OperationLimits::default()
        };
        let failure = compiled
            .admit_span_sum_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap_err();
        assert!(matches!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            }
        ));
        let prospective = failure.receipt.prospective.unwrap();
        assert_eq!(prospective.allocations, 1);
        assert_eq!(failure.receipt.actual_allocations, 1);
        assert_eq!(failure.receipt.actual.sequential_bytes_read, haystack.len());
        assert!(failure.receipt.actual.scratch_peak_bytes > 0);
        assert!(prospective.contains(failure.receipt.actual));
    }

    #[test]
    fn certificate_derives_boundaries_and_rejects_malformed_internal_ranges() {
        let compiled = endpoint_scalar_repeat();
        let empty = compiled
            .admit_count(
                b"",
                0..0,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(empty.certificate().boundaries(), 1);

        let haystack = [b'a'; 249];
        let normal = compiled
            .admit_count(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(normal.certificate().boundaries(), haystack.len() + 1);

        let mut reversed = normal.certificate().clone();
        reversed.range = normal.certificate().range.end..normal.certificate().range.start;
        assert!(std::panic::catch_unwind(|| reversed.boundaries()).is_err());

        let mut overflowing = normal.certificate().clone();
        overflowing.range = 0..usize::MAX;
        assert!(std::panic::catch_unwind(|| overflowing.boundaries()).is_err());
    }

    #[test]
    fn nonreceipt_span_sum_certificate_retains_actual_sum_not_range_length() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = b"abbbbb";
        let admitted = compiled
            .admit_span_sum(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(admitted.value(), 1);
        assert_eq!(admitted.certificate().span_sum, admitted.value());
        assert_ne!(admitted.certificate().span_sum, haystack.len());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-and-every-one-below test enumerates every public P dimension in one audit unit"
    )]
    fn terminal_frontier_count_exact_and_every_positive_one_below_refuse_before_source() {
        let compiled = terminal_frontier_count();
        let haystack = b"cargo/registry/src/name/ cargo\\registry\\src\\other\\";
        let baseline = compiled
            .admit_count_with_terminal_frontier_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline
            .receipt
            .prospective
            .expect("terminal-frontier Count must publish P");
        assert!(prospective.terminal_frontier);
        assert!(prospective.allocations > 0);
        assert!(prospective.contains(baseline.receipt.actual));
        assert_eq!(baseline.receipt.actual, baseline.admitted.accounting());
        let identity = baseline.receipt.identity;
        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        };
        let mut observed = None;
        let exact_success = compiled
            .admit_count_with_terminal_frontier_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
                prospective.allocations,
                |published| {
                    observed = Some(published);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(observed, Some(prospective));
        assert_eq!(exact_success.receipt.prospective, Some(prospective));
        let mut exact_identity = identity;
        exact_identity.operation_limits_id = OperationLimitsId::from_limits(exact);
        assert_eq!(exact_success.receipt.identity, exact_identity);
        assert_eq!(exact_success.admitted.value(), baseline.admitted.value());
        assert!(prospective.contains(exact_success.receipt.actual));
        assert_eq!(
            exact_success.receipt.actual,
            exact_success.admitted.accounting()
        );

        macro_rules! assert_one_below {
            ($limit:ident, $field:ident, $resource:expr) => {
                if prospective.$field > 0 {
                    let mut one_below = exact;
                    one_below.$limit = prospective.$field - 1;
                    let allocation = allocation_fault::arm(0);
                    let failure = compiled
                        .admit_count_with_terminal_frontier_receipt(
                            haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            one_below,
                        )
                        .unwrap_err();
                    assert_eq!(
                        failure.source,
                        Error::ResourceLimit {
                            resource: $resource,
                            required: prospective.$field,
                            limit: prospective.$field - 1,
                        }
                    );
                    let mut one_below_identity = identity;
                    one_below_identity.operation_limits_id =
                        OperationLimitsId::from_limits(one_below);
                    assert_eq!(failure.receipt.identity, one_below_identity);
                    assert_eq!(failure.receipt.prospective, Some(prospective));
                    assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
                    assert_eq!(failure.receipt.actual_allocations, 0);
                    assert_eq!(allocation_fault::calls(), 0);
                    drop(allocation);
                }
            };
        }
        assert_one_below!(max_boundaries, boundaries, Resource::Boundaries);
        assert_one_below!(max_table_cells, table_cells, Resource::TableCells);
        assert_one_below!(
            max_random_access_bytes,
            random_access_bytes,
            Resource::RandomAccessBytes
        );
        assert_one_below!(max_scratch_bytes, scratch_bytes, Resource::ScratchBytes);
        assert_one_below!(max_log_bytes, log_bytes, Resource::LogBytes);
        assert_one_below!(
            max_sequential_bytes,
            sequential_bytes,
            Resource::SequentialBytes
        );
        assert_one_below!(max_match_events, match_events, Resource::MatchEvents);
        assert_one_below!(max_output_matches, output_matches, Resource::OutputMatches);
        assert_one_below!(max_output_bytes, output_bytes, Resource::OutputBytes);
        assert_one_below!(max_span_sum, span_sum, Resource::SpanSum);
        assert_one_below!(max_peak_bytes, peak_bytes, Resource::PeakBytes);
        assert_one_below!(max_work, work_bound, Resource::ExecutionWork);

        let allocation = allocation_fault::arm(0);
        let mut allocation_observer = None;
        let failure = compiled
            .admit_count_with_terminal_frontier_receipt_observer(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
                prospective.allocations - 1,
                |published| {
                    allocation_observer = Some(published);
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(allocation_observer, Some(prospective));
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::Allocations,
                required: prospective.allocations,
                limit: prospective.allocations - 1,
            }
        );
        assert_eq!(failure.receipt.identity, exact_identity);
        assert_eq!(failure.receipt.prospective, Some(prospective));
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual_allocations, 0);
        assert_eq!(allocation_fault::calls(), 0);
        drop(allocation);
    }

    #[test]
    fn terminal_frontier_count_requires_compiled_proof_and_route_before_source() {
        let ineligible = endpoint_scalar_repeat();
        let allocation = allocation_fault::arm(0);
        let failure = ineligible
            .admit_count_with_terminal_frontier_receipt(
                b"source",
                0..6,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap_err();
        assert_eq!(
            failure.source,
            Error::InternalInvariant("terminal-frontier Count requires its compiled HIR proof")
        );
        assert_eq!(failure.receipt.identity.operation_id(), None);
        assert_eq!(failure.receipt.prospective, None);
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual_allocations, 0);
        assert_eq!(allocation_fault::calls(), 0);
        drop(allocation);

        let eligible = terminal_frontier_count();
        let allocation = allocation_fault::arm(0);
        let failure = eligible
            .admit_count_with_terminal_frontier_receipt(
                b"cargo/path/",
                0..11,
                Strategy::FullTable,
                OperationLimits::default(),
            )
            .unwrap_err();
        assert_eq!(
            failure.source,
            Error::InternalInvariant("terminal-frontier Count requires reverse sequential rows")
        );
        assert_eq!(failure.receipt.identity.operation_id(), None);
        assert_eq!(failure.receipt.prospective, None);
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual_allocations, 0);
        assert_eq!(allocation_fault::calls(), 0);
        drop(allocation);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-and-every-one-below test enumerates every public P dimension in one audit unit"
    )]
    fn endpoint_count_attempt_exact_and_every_positive_one_below_share_one_p_before_effects() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let baseline = compiled
            .admit_count_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline
            .receipt
            .prospective
            .expect("successful generic count must retain P");
        assert_eq!(prospective.span_sum, 0);
        assert!(
            compiled
                .admit_count_with_receipt(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_span_sum: 0,
                        ..OperationLimits::default()
                    },
                )
                .is_ok()
        );
        let identity = baseline.receipt.identity;
        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        };
        let exact_success = compiled
            .admit_count_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_success.receipt.prospective, Some(prospective));
        let mut exact_identity = identity;
        exact_identity.operation_limits_id = OperationLimitsId::from_limits(exact);
        assert_eq!(exact_success.receipt.identity, exact_identity);

        macro_rules! assert_one_below {
            ($limit:ident, $field:ident, $resource:expr) => {
                if prospective.$field > 0 {
                    let mut one_below = exact;
                    one_below.$limit = prospective.$field - 1;
                    let allocation = allocation_fault::arm(0);
                    let failure = compiled
                        .admit_count_with_receipt(
                            &haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            one_below,
                        )
                        .unwrap_err();
                    assert_eq!(
                        failure.source,
                        Error::ResourceLimit {
                            resource: $resource,
                            required: prospective.$field,
                            limit: prospective.$field - 1,
                        }
                    );
                    let mut one_below_identity = identity;
                    one_below_identity.operation_limits_id =
                        OperationLimitsId::from_limits(one_below);
                    assert_eq!(failure.receipt.identity, one_below_identity);
                    assert_eq!(failure.receipt.prospective, Some(prospective));
                    assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
                    assert_eq!(allocation_fault::calls(), 0);
                    drop(allocation);
                }
            };
        }
        assert_one_below!(max_boundaries, boundaries, Resource::Boundaries);
        assert_one_below!(max_table_cells, table_cells, Resource::TableCells);
        assert_one_below!(
            max_random_access_bytes,
            random_access_bytes,
            Resource::RandomAccessBytes
        );
        assert_one_below!(max_scratch_bytes, scratch_bytes, Resource::ScratchBytes);
        assert_one_below!(max_log_bytes, log_bytes, Resource::LogBytes);
        assert_one_below!(
            max_sequential_bytes,
            sequential_bytes,
            Resource::SequentialBytes
        );
        assert_one_below!(max_match_events, match_events, Resource::MatchEvents);
        assert_one_below!(max_output_matches, output_matches, Resource::OutputMatches);
        assert_one_below!(max_output_bytes, output_bytes, Resource::OutputBytes);
        assert_one_below!(max_span_sum, span_sum, Resource::SpanSum);
        assert_one_below!(max_peak_bytes, peak_bytes, Resource::PeakBytes);
        assert_one_below!(max_work, work_bound, Resource::ExecutionWork);
    }

    #[test]
    fn endpoint_count_attempt_success_retains_release_checked_prospective_and_actual() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let success = compiled
            .admit_count_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(success.admitted.value(), 1);
        assert_eq!(success.receipt.actual, success.admitted.accounting());
        assert!(success.receipt.actual.random_access_bytes_read > 0);
        assert!(
            success
                .receipt
                .prospective
                .is_some_and(|upper| upper.contains(success.receipt.actual))
        );

        let value = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(value.value, 1);
        assert!(
            value
                .receipt
                .prospective
                .is_some_and(|upper| upper.contains(value.receipt.actual))
        );
    }

    #[test]
    fn observed_required_suffix_zero_exact_and_one_below_retain_bounded_receipts() {
        let hir = ParserBuilder::new().build().parse(r"a+").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        let strategy = Strategy::ReverseSequentialRows;
        let dense = Requirements::new::<true>(
            &compiled.program,
            2,
            strategy,
            1,
            super::intrinsic_attempt_limits(),
        )
        .unwrap();
        let routing_limits = OperationLimits {
            max_work: dense.work_bound - 1,
            ..OperationLimits::default()
        };
        let baseline = compiled
            .count_value_attempt(b"a", 0..1, strategy, routing_limits)
            .unwrap();
        assert_eq!(
            baseline.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows)
        );
        let exact_work = baseline.receipt.actual.work;
        assert!(exact_work > 0);

        let exact_limits = OperationLimits {
            max_work: exact_work,
            ..OperationLimits::default()
        };
        let exact = compiled
            .count_value_attempt(b"a", 0..1, strategy, exact_limits)
            .unwrap();
        let exact_p = exact.receipt.prospective.unwrap();
        assert_eq!(
            exact.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows)
        );
        assert_eq!(exact_p.work_bound, exact_work);
        assert_eq!(exact.receipt.actual.work, exact_work);
        assert!(exact_p.contains(exact.receipt.actual));

        let one_below_limits = OperationLimits {
            max_work: exact_work - 1,
            ..OperationLimits::default()
        };
        let one_below = compiled
            .count_value_attempt(b"a", 0..1, strategy, one_below_limits)
            .unwrap_err();
        assert!(matches!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required,
                limit,
            } if required == exact_work && limit == exact_work - 1
        ));
        assert_eq!(
            one_below.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows)
        );
        let one_below_p = one_below
            .receipt
            .prospective
            .expect("published one-below prospective");
        assert_eq!(one_below_p.work_bound, exact_work - 1);
        assert!(one_below_p.contains(one_below.receipt.actual));

        let zero_limits = OperationLimits {
            max_work: 0,
            ..OperationLimits::default()
        };
        let failure = compiled
            .count_value_attempt(b"a", 0..1, strategy, zero_limits)
            .unwrap_err();
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: 2,
                limit: 0,
            },
            "{failure:#?}"
        );
        assert_eq!(
            failure.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows)
        );
        let prospective = failure.receipt.prospective.expect("published prospective");
        assert_eq!(prospective.work_bound, 2);
        assert!(prospective.contains(failure.receipt.actual), "{failure:#?}");
    }

    #[test]
    fn observed_terminal_frontier_zero_exact_and_one_below_retain_bounded_receipts() {
        let compiled = terminal_frontier_count();
        let haystack = b"cargo/registry/";
        let strategy = Strategy::ReverseSequentialRows;
        let baseline = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            baseline.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::TerminalFrontierRows)
        );
        let exact_work = baseline.receipt.actual.work;
        assert!(exact_work > 0);

        let exact_limits = OperationLimits {
            max_work: exact_work,
            ..OperationLimits::default()
        };
        let exact = compiled
            .count_value_attempt(haystack, 0..haystack.len(), strategy, exact_limits)
            .unwrap();
        let exact_p = exact.receipt.prospective.unwrap();
        assert_eq!(
            exact.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::TerminalFrontierRows)
        );
        assert_eq!(exact_p.work_bound, exact_work);
        assert_eq!(exact.receipt.actual.work, exact_work);
        assert!(exact_p.contains(exact.receipt.actual));

        let one_below_limit = exact_work - 1;
        let one_below = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: one_below_limit,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required,
                limit,
            } if required == exact_work && limit == one_below_limit
        ));
        assert_eq!(
            one_below.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::TerminalFrontierRows)
        );
        let one_below_p = one_below.receipt.prospective.unwrap();
        assert_eq!(one_below_p.work_bound, one_below_limit);
        assert!(one_below_p.contains(one_below.receipt.actual));

        let zero = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            zero.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::TerminalFrontierRows)
        );
        let zero_p = zero.receipt.prospective.unwrap();
        assert_eq!(
            zero.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: zero_p.work_bound,
                limit: 0,
            }
        );
        assert!(zero_p.work_bound > 0);
        assert_eq!(zero.receipt.actual, ExecutionAccounting::default());
        assert!(zero_p.contains(zero.receipt.actual));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one receipt regression audits all nonnullable, empty, and nullable exact bounds together"
    )]
    fn nonnullable_spans_publish_structural_cardinality_and_phase_peak_exactly() {
        let hir = ParserBuilder::new().build().parse(r"a{4}").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(compiled.minimum_match_bytes, Some(4));
        let haystack = [b'a'; 64];
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let baseline = compiled
            .admit_spans_with_receipt(
                &haystack,
                range.clone(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline.receipt.prospective.unwrap();
        assert_eq!(prospective.match_events, 16);
        assert_eq!(prospective.output_matches, 16);
        assert_eq!(
            prospective.output_bytes,
            16 * core::mem::size_of::<super::Span>()
        );
        assert_eq!(prospective.accounting.successful_paths, 32);
        assert_eq!(prospective.accounting.suppressed_empty, 0);
        assert_eq!(prospective.accounting.emitted_matches, 16);
        assert_eq!(baseline.admitted.as_slice().len(), 16);
        assert!(prospective.contains(baseline.receipt.actual));

        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        };
        let exact_success = compiled
            .admit_spans_with_receipt(&haystack, range.clone(), strategy, exact)
            .unwrap();
        assert_eq!(exact_success.receipt.prospective, Some(prospective));
        assert_eq!(exact_success.admitted.as_slice().len(), 16);
        assert!(prospective.contains(exact_success.receipt.actual));

        for (limits, resource, required) in [
            (
                OperationLimits {
                    max_match_events: prospective.match_events - 1,
                    ..exact
                },
                Resource::MatchEvents,
                prospective.match_events,
            ),
            (
                OperationLimits {
                    max_output_matches: prospective.output_matches - 1,
                    ..exact
                },
                Resource::OutputMatches,
                prospective.output_matches,
            ),
            (
                OperationLimits {
                    max_output_bytes: prospective.output_bytes - 1,
                    ..exact
                },
                Resource::OutputBytes,
                prospective.output_bytes,
            ),
            (
                OperationLimits {
                    max_peak_bytes: prospective.peak_bytes - 1,
                    ..exact
                },
                Resource::PeakBytes,
                prospective.peak_bytes,
            ),
        ] {
            let allocation = allocation_fault::arm(0);
            let failure = compiled
                .admit_spans_with_receipt(&haystack, range.clone(), strategy, limits)
                .unwrap_err();
            assert_eq!(
                failure.source,
                Error::ResourceLimit {
                    resource,
                    required,
                    limit: required - 1,
                }
            );
            assert_eq!(failure.receipt.prospective, Some(prospective));
            assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
            assert_eq!(failure.receipt.actual_allocations, 0);
            assert_eq!(allocation_fault::calls(), 0);
            drop(allocation);
        }

        let nullable_hir = ParserBuilder::new().build().parse(r"a*").unwrap();
        let nullable = CompiledRegex::from_hir(
            &nullable_hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(nullable.minimum_match_bytes, Some(0));
        let nullable_attempt = nullable
            .admit_spans_with_receipt(
                b"aaaa",
                0..4,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let nullable_prospective = nullable_attempt.receipt.prospective.unwrap();
        assert_eq!(nullable_prospective.match_events, 10);
        assert_eq!(nullable_prospective.output_matches, 5);
        assert_eq!(nullable_prospective.accounting.suppressed_empty, 20);
        assert!(nullable_prospective.contains(nullable_attempt.receipt.actual));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered-root regression audits route identity, exact limits, and one-below closure"
    )]
    fn ordered_root_count_receipt_closes_exact_limits_and_one_below() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"(?P<first>a+)|(?P<second>b+)|(?P<third>c+)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_ordered_root_count(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(compiled.program.root_alternation_arms(), 3);
        assert_eq!(compiled.program.root_split_count(), 2);
        let haystack = b"aa bb ccc";
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let mut published = None;
        let baseline = compiled
            .admit_ordered_root_count_observed_with_receipt_observer(
                haystack,
                range.clone(),
                strategy,
                OperationLimits::default(),
                usize::MAX,
                |prospective| {
                    published = Some(prospective);
                    Ok(())
                },
            )
            .unwrap();
        let prospective = published.unwrap();
        assert_eq!(baseline.receipt.prospective, Some(prospective));
        assert_eq!(baseline.admitted.value(), 3);
        assert_eq!(
            baseline.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedRootRows)
        );
        assert_eq!(
            baseline.admitted.certificate().physical_route,
            OperationPhysicalRoute::OrderedRootRows
        );
        assert_eq!(
            baseline.receipt.identity.operation_id(),
            Some(baseline.admitted.certificate().operation_id())
        );
        assert_eq!(
            baseline.admitted.certificate().row_storage,
            Some(RowStorage::ReachableEndpoints)
        );
        assert_eq!(baseline.admitted.accounting().replay_steps, 0);
        assert!(baseline.admitted.accounting().root_probes > 0);
        assert!(prospective.contains(baseline.receipt.actual));

        let ordinary = compiled
            .count_value_with_receipt(
                haystack,
                range.clone(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(ordinary.value, baseline.admitted.value());
        assert_eq!(
            ordinary.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::DenseRows)
        );
        assert_ne!(
            ordinary.receipt.identity.operation_id(),
            baseline.receipt.identity.operation_id()
        );

        let exact_work = baseline.receipt.actual.work;
        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: exact_work,
        };
        let mut exact_published = None;
        let exact_attempt = compiled
            .admit_ordered_root_count_observed_with_receipt_observer(
                haystack,
                range.clone(),
                strategy,
                exact,
                prospective.allocations,
                |upper| {
                    exact_published = Some(upper);
                    Ok(())
                },
            )
            .unwrap();
        let exact_prospective = exact_published.unwrap();
        assert_eq!(exact_prospective.work_bound, exact_work);
        assert_eq!(exact_attempt.receipt.prospective, Some(exact_prospective));
        assert_eq!(exact_attempt.receipt.actual.work, exact_work);
        assert!(exact_prospective.contains(exact_attempt.receipt.actual));

        for (limits, resource, required) in [
            (
                OperationLimits {
                    max_boundaries: prospective.boundaries - 1,
                    ..exact
                },
                Resource::Boundaries,
                prospective.boundaries,
            ),
            (
                OperationLimits {
                    max_random_access_bytes: prospective.random_access_bytes - 1,
                    ..exact
                },
                Resource::RandomAccessBytes,
                prospective.random_access_bytes,
            ),
            (
                OperationLimits {
                    max_scratch_bytes: prospective.scratch_bytes - 1,
                    ..exact
                },
                Resource::ScratchBytes,
                prospective.scratch_bytes,
            ),
            (
                OperationLimits {
                    max_log_bytes: prospective.log_bytes - 1,
                    ..exact
                },
                Resource::LogBytes,
                prospective.log_bytes,
            ),
            (
                OperationLimits {
                    max_sequential_bytes: prospective.sequential_bytes - 1,
                    ..exact
                },
                Resource::SequentialBytes,
                prospective.sequential_bytes,
            ),
            (
                OperationLimits {
                    max_match_events: prospective.match_events - 1,
                    ..exact
                },
                Resource::MatchEvents,
                prospective.match_events,
            ),
            (
                OperationLimits {
                    max_output_matches: prospective.output_matches - 1,
                    ..exact
                },
                Resource::OutputMatches,
                prospective.output_matches,
            ),
            (
                OperationLimits {
                    max_peak_bytes: prospective.peak_bytes - 1,
                    ..exact
                },
                Resource::PeakBytes,
                prospective.peak_bytes,
            ),
        ] {
            let allocation = allocation_fault::arm(0);
            let failure = compiled
                .admit_ordered_root_count_observed_with_receipt_observer(
                    haystack,
                    range.clone(),
                    strategy,
                    limits,
                    prospective.allocations,
                    |_| Ok(()),
                )
                .unwrap_err();
            assert_eq!(
                failure.source,
                Error::ResourceLimit {
                    resource,
                    required,
                    limit: required - 1,
                }
            );
            assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
            assert_eq!(failure.receipt.actual_allocations, 0);
            assert_eq!(allocation_fault::calls(), 0);
            drop(allocation);
        }

        let allocation = allocation_fault::arm(0);
        let allocation_failure = compiled
            .admit_ordered_root_count_observed_with_receipt_observer(
                haystack,
                range.clone(),
                strategy,
                exact,
                prospective.allocations - 1,
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(
            allocation_failure.source,
            Error::ResourceLimit {
                resource: Resource::Allocations,
                required: prospective.allocations,
                limit: prospective.allocations - 1,
            }
        );
        assert_eq!(allocation_failure.receipt.actual_allocations, 0);
        assert_eq!(allocation_fault::calls(), 0);
        drop(allocation);

        let one_below_work = OperationLimits {
            max_work: exact_work - 1,
            ..exact
        };
        let work_failure = compiled
            .admit_ordered_root_count_observed_with_receipt_observer(
                haystack,
                range,
                strategy,
                one_below_work,
                prospective.allocations,
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(
            work_failure.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: exact_work,
                limit: exact_work - 1,
            }
        );
        let work_prospective = work_failure.receipt.prospective.unwrap();
        assert_eq!(work_prospective.work_bound, exact_work - 1);
        assert_eq!(work_failure.receipt.actual.work, exact_work - 1);
        assert!(work_prospective.contains(work_failure.receipt.actual));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one focused matrix binds all three operation identities, stable P/A, resource refusal, and post-publication failure"
    )]
    fn ordinary_operations_publish_stable_distinct_closed_receipts_and_never_late_fallback() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let limits = OperationLimits::default();

        let spans_first = compiled
            .admit_spans_with_receipt(&haystack, range.clone(), strategy, limits)
            .unwrap();
        let spans_steady = compiled
            .admit_spans_with_receipt(&haystack, range.clone(), strategy, limits)
            .unwrap();
        assert_eq!(
            spans_first.admitted.as_slice(),
            spans_steady.admitted.as_slice()
        );
        assert_eq!(spans_first.receipt.identity, spans_steady.receipt.identity);
        assert_eq!(
            spans_first.receipt.prospective,
            spans_steady.receipt.prospective
        );
        assert_eq!(
            spans_first.receipt.identity.operation,
            OperationAttemptKind::Spans
        );
        assert!(spans_first.receipt.identity.authenticates_limits(limits));
        let spans_upper = spans_first.receipt.prospective.unwrap();
        assert!(spans_upper.output_bytes > 0);
        assert_eq!(spans_upper.span_sum, 0);
        assert!(spans_upper.contains(spans_first.receipt.actual));
        assert_eq!(
            spans_first.receipt.actual,
            spans_first.admitted.accounting()
        );
        assert_eq!(
            spans_first.receipt.identity.operation_id(),
            Some(spans_first.admitted.certificate().operation_id())
        );
        assert_eq!(
            spans_first.receipt.identity.physical_route,
            Some(spans_first.admitted.certificate().physical_route)
        );
        assert_eq!(
            spans_first.receipt.identity.algorithm_version,
            CONTINUATION_OPERATION_ALGORITHM_VERSION
        );
        assert_eq!(
            spans_first.receipt.identity.accounting_version,
            CONTINUATION_OPERATION_ACCOUNTING_VERSION
        );
        assert!(spans_first.receipt.authenticates_success());
        let mut mutated_success = spans_first.receipt.clone();
        mutated_success.identity.accounting_version = 3;
        assert!(!mutated_success.authenticates_canonical());
        assert!(!mutated_success.authenticates_success());
        let mut coherent_actual_mutation = spans_first.receipt.clone();
        assert_ne!(
            coherent_actual_mutation.actual,
            ExecutionAccounting::default()
        );
        coherent_actual_mutation.actual = ExecutionAccounting::default();
        coherent_actual_mutation.actual_allocations = 0;
        assert!(
            coherent_actual_mutation
                .prospective
                .is_some_and(|prospective| prospective.contains(coherent_actual_mutation.actual))
        );
        assert!(!coherent_actual_mutation.authenticates_canonical());
        assert!(!coherent_actual_mutation.authenticates_success());

        let count = compiled
            .admit_count_attempt(&haystack, range.clone(), strategy, limits)
            .unwrap();
        let sum_first = compiled
            .admit_span_sum_with_receipt(&haystack, range.clone(), strategy, limits)
            .unwrap();
        let sum_steady = compiled
            .admit_span_sum_with_receipt(&haystack, range.clone(), strategy, limits)
            .unwrap();
        assert_eq!(sum_first.admitted.value(), 249);
        assert_eq!(sum_first.admitted.value(), sum_steady.admitted.value());
        assert_eq!(sum_first.receipt.identity, sum_steady.receipt.identity);
        assert_eq!(
            sum_first.receipt.prospective,
            sum_steady.receipt.prospective
        );
        assert_eq!(
            sum_first.receipt.identity.operation,
            OperationAttemptKind::SpanSum
        );
        assert_eq!(
            count.receipt.identity.operation,
            OperationAttemptKind::Count
        );
        assert_ne!(
            spans_first.receipt.identity.operation_id(),
            count.receipt.identity.operation_id()
        );
        assert_ne!(
            count.receipt.identity.operation_id(),
            sum_first.receipt.identity.operation_id()
        );
        let sum_upper = sum_first.receipt.prospective.unwrap();
        assert_eq!(sum_upper.output_bytes, 0);
        assert_eq!(sum_upper.span_sum, haystack.len());
        assert!(sum_upper.contains(sum_first.receipt.actual));
        assert_eq!(sum_first.receipt.actual, sum_first.admitted.accounting());

        let mut spans_below = limits;
        spans_below.max_output_bytes = spans_upper.output_bytes - 1;
        let spans_refusal = compiled
            .admit_spans_with_receipt(&haystack, range.clone(), strategy, spans_below)
            .unwrap_err();
        assert_eq!(
            spans_refusal.source,
            Error::ResourceLimit {
                resource: Resource::OutputBytes,
                required: spans_upper.output_bytes,
                limit: spans_upper.output_bytes - 1,
            }
        );
        assert_eq!(spans_refusal.receipt.prospective, Some(spans_upper));
        assert!(
            spans_refusal
                .receipt
                .identity
                .authenticates_limits(spans_below)
        );
        assert!(!spans_refusal.receipt.identity.authenticates_limits(limits));
        assert_eq!(
            spans_refusal.receipt.identity.physical_route,
            spans_first.receipt.identity.physical_route
        );
        assert_eq!(
            spans_refusal.receipt.identity.prepublication_fallback,
            spans_first.receipt.identity.prepublication_fallback
        );
        assert_eq!(spans_refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(spans_refusal.receipt.actual_allocations, 0);
        assert!(spans_refusal.closes());
        let mut invocation_mutation = spans_refusal.clone();
        invocation_mutation.receipt.invocation.range = 0..1;
        invocation_mutation.receipt.invocation.haystack_len = 0;
        assert!(!invocation_mutation.closes());
        let mut source_mutation = spans_refusal.clone();
        source_mutation.source = Error::InternalInvariant("caller-spliced continuation source");
        assert!(!source_mutation.closes());
        let mut receipt_mutation = spans_refusal.clone();
        receipt_mutation.receipt.identity.algorithm_version =
            CONTINUATION_OPERATION_ALGORITHM_VERSION.wrapping_add(1);
        assert!(!receipt_mutation.closes());

        let mut sum_below = limits;
        sum_below.max_span_sum = sum_upper.span_sum - 1;
        let sum_refusal = compiled
            .admit_span_sum_with_receipt(&haystack, range.clone(), strategy, sum_below)
            .unwrap_err();
        assert_eq!(
            sum_refusal.source,
            Error::ResourceLimit {
                resource: Resource::SpanSum,
                required: sum_upper.span_sum,
                limit: sum_upper.span_sum - 1,
            }
        );
        assert_eq!(sum_refusal.receipt.prospective, Some(sum_upper));
        assert!(sum_refusal.receipt.identity.authenticates_limits(sum_below));
        assert_eq!(sum_refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(sum_refusal.receipt.actual_allocations, 0);

        let fault = allocation_fault::arm(0);
        let terminal = compiled
            .admit_spans_with_receipt(&haystack, range, strategy, limits)
            .unwrap_err();
        assert!(matches!(terminal.source, Error::AllocationFailed { .. }));
        assert_eq!(terminal.receipt.identity, spans_first.receipt.identity);
        assert_eq!(terminal.receipt.prospective, Some(spans_upper));
        assert_eq!(terminal.receipt.actual_allocations, 0);
        assert!(spans_upper.contains(terminal.receipt.actual));
        assert_eq!(allocation_fault::calls(), 1);
        drop(fault);
    }

    #[test]
    fn observed_candidate_route_publishes_once_and_closes_success_and_refusal() {
        let compiled = candidate_count();
        let haystack = b"ab xxz q0r 123-x a";
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let limits = OperationLimits::default();
        let first = compiled
            .count_value_attempt(haystack, range.clone(), strategy, limits)
            .unwrap();
        let steady = compiled
            .count_value_attempt(haystack, range.clone(), strategy, limits)
            .unwrap();
        assert_eq!(first.value, steady.value);
        assert_eq!(first.receipt.identity, steady.receipt.identity);
        assert_eq!(first.receipt.prospective, steady.receipt.prospective);
        assert_eq!(
            first.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::Candidate)
        );
        assert_eq!(
            first.receipt.identity.operation,
            OperationAttemptKind::Count
        );
        let prospective = first.receipt.prospective.unwrap();
        assert_eq!(prospective.allocations, 5);
        assert_eq!(first.receipt.actual_allocations, prospective.allocations);
        assert!(prospective.contains(first.receipt.actual));

        let mut one_below = limits;
        one_below.max_scratch_bytes = prospective.scratch_bytes - 1;
        let refusal = compiled
            .count_value_attempt(haystack, range, strategy, one_below)
            .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::ScratchBytes,
                required: prospective.scratch_bytes,
                limit: prospective.scratch_bytes - 1,
            }
        );
        assert_eq!(refusal.receipt.prospective, Some(prospective));
        assert!(refusal.receipt.identity.authenticates_limits(one_below));
        assert_eq!(
            refusal.receipt.identity.physical_route,
            first.receipt.identity.physical_route
        );
        assert_eq!(
            refusal.receipt.identity.prepublication_fallback,
            first.receipt.identity.prepublication_fallback
        );
        assert_eq!(refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(refusal.receipt.actual_allocations, 0);

        let mut terminal_limits = limits;
        terminal_limits.max_work = first.receipt.actual.work - 1;
        let terminal = compiled
            .count_value_attempt(haystack, 0..haystack.len(), strategy, terminal_limits)
            .unwrap_err();
        assert!(matches!(
            terminal.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            }
        ));
        let terminal_p = terminal.receipt.prospective.unwrap();
        assert_eq!(terminal_p.allocations, CANDIDATE_EXECUTION_ALLOCATIONS);
        assert_eq!(
            terminal.receipt.actual_allocations,
            CANDIDATE_EXECUTION_ALLOCATIONS
        );
        assert!(terminal.receipt.actual.work > 0);
        assert!(terminal.receipt.actual.sequential_bytes_read > 0);
        assert!(terminal_p.contains(terminal.receipt.actual));
    }

    #[test]
    fn classified_candidate_publishes_its_exact_one_slot_scratch_envelope() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r"(?i:abx|cdy)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let plan = compiled.candidate.as_ref().unwrap();
        let classified = plan.classified_anchors().unwrap();
        assert_eq!(classified.offset(), 2);
        assert!(!plan.has_shared_fixed());

        let haystack = b"ABX xx cdy";
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let baseline = compiled
            .count_value_attempt(
                haystack,
                range.clone(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            baseline.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::Candidate)
        );
        let prospective = baseline.receipt.prospective.unwrap();
        assert_eq!(
            prospective.scratch_bytes,
            baseline.receipt.actual.scratch_peak_bytes
        );
        assert_eq!(
            prospective.random_access_bytes,
            baseline.receipt.actual.random_access_peak_bytes
        );

        let exact_workspace = OperationLimits {
            max_random_access_bytes: baseline.receipt.actual.random_access_peak_bytes,
            max_scratch_bytes: baseline.receipt.actual.scratch_peak_bytes,
            ..OperationLimits::default()
        };
        let replay = compiled
            .count_value_attempt(haystack, range, strategy, exact_workspace)
            .unwrap();
        assert_eq!(replay.value, baseline.value);
        assert_eq!(replay.receipt.actual, baseline.receipt.actual);
    }

    #[test]
    fn observed_candidate_span_sum_has_typed_receipts_and_exact_prospective_limit() {
        let compiled = candidate_count();
        let haystack = b"ab xxz q0r 123-x a";
        let range = 0..haystack.len();
        let strategy = Strategy::ReverseSequentialRows;
        let limits = OperationLimits::default();
        let count = compiled
            .count_value_attempt(haystack, range.clone(), strategy, limits)
            .unwrap();
        let expected_span_sum = RegexBuilder::new(r"a|ab|x{1,3}z|q.r|[0-9]+-x")
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
            .sum();

        let exact_span_sum_limits = OperationLimits {
            max_span_sum: haystack.len(),
            ..limits
        };
        let span_sum = compiled
            .span_sum_value_with_receipt(haystack, range.clone(), strategy, exact_span_sum_limits)
            .unwrap();
        assert_eq!(span_sum.value, expected_span_sum);
        assert_eq!(
            span_sum.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::Candidate)
        );
        assert_eq!(
            span_sum.receipt.identity.operation,
            OperationAttemptKind::SpanSum
        );
        assert_ne!(
            span_sum.receipt.identity.operation_id(),
            count.receipt.identity.operation_id()
        );
        let prospective = span_sum.receipt.prospective.unwrap();
        assert_eq!(prospective.span_sum, haystack.len());
        assert_eq!(
            span_sum.receipt.actual_allocations,
            CANDIDATE_EXECUTION_ALLOCATIONS
        );
        assert!(prospective.contains(span_sum.receipt.actual));
        assert_eq!(span_sum.receipt.actual, count.receipt.actual);

        let one_below = OperationLimits {
            max_span_sum: haystack.len() - 1,
            ..exact_span_sum_limits
        };
        let refusal = compiled
            .span_sum_value_with_receipt(haystack, range, strategy, one_below)
            .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::SpanSum,
                required: haystack.len(),
                limit: haystack.len() - 1,
            }
        );
        assert_eq!(refusal.receipt.prospective, Some(prospective));
        assert_eq!(refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(refusal.receipt.actual_allocations, 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixed theorem's semantics, route, limits and receipts form one directed matrix"
    )]
    fn fixed_continuation_candidate_preserves_priority_lf_and_exact_receipts() {
        let pattern = r#"(?:(?:alpha|beta|nil|true|\d|["'\\+])+\)*;?((?:\s|-|~|!|\{\}|\|\||\+)*.*(?:.*=.*)))"#;
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let plan = compiled.candidate.as_ref().unwrap();
        assert!(plan.fixed_continuation().is_some());
        let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let cases = [
            b"alpha x=tail".as_slice(),
            b"9nil+alpha))); x==tail".as_slice(),
            b"alpha x".as_slice(),
            b"alpha \n x=y\n".as_slice(),
            b"alpha x\n=y".as_slice(),
            b"alpha q\nbeta x=y".as_slice(),
            b"alpha x=y\r\n".as_slice(),
            b"beta \xff=\0".as_slice(),
            b"alpha a=b\nno match\ntrue c=d".as_slice(),
            b"nil ||=x=last".as_slice(),
        ];
        for haystack in cases {
            let expected = oracle.find_iter(haystack).collect::<Vec<_>>();
            let expected_sum = expected
                .iter()
                .map(|matched| matched.end() - matched.start())
                .sum::<usize>();
            let span_sum = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(span_sum.value, expected_sum, "{haystack:?}");
            assert_eq!(
                span_sum.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::Candidate),
                "{haystack:?}"
            );
            assert_eq!(
                span_sum.receipt.actual_allocations,
                candidate::FIXED_CONTINUATION_EXECUTION_ALLOCATIONS
            );
            assert!(
                span_sum
                    .receipt
                    .prospective
                    .unwrap()
                    .contains(span_sum.receipt.actual)
            );
            let count = compiled
                .count_value_attempt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(count.value, expected.len(), "{haystack:?}");
            let dense = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::FullTable,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(dense.value, expected_sum, "{haystack:?}");
        }

        // Preserve the release residual with a different token language and
        // source: one complete 107-byte match must remain an exact SpanSum
        // 107 on the fixed physical route.
        let mut exact_residual_source = vec![b'x'; 107];
        exact_residual_source[..8].copy_from_slice(b"alpha x=");
        let exact_residual = compiled
            .span_sum_value_with_receipt(
                &exact_residual_source,
                0..exact_residual_source.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(exact_residual.value, 107);
        assert_eq!(
            exact_residual.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::Candidate)
        );

        let haystack = b"alpha x=zz";
        let no_match = b"qqqqqqqqqq";
        assert_eq!(haystack.len(), no_match.len());
        let result = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let absent = compiled
            .span_sum_value_with_receipt(
                no_match,
                0..no_match.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(result.receipt.identity, absent.receipt.identity);
        assert_eq!(result.receipt.prospective, absent.receipt.prospective);
        let no_output_limits = OperationLimits {
            max_output_matches: 0,
            max_span_sum: 0,
            ..OperationLimits::default()
        };
        assert_eq!(
            compiled
                .span_sum_value(
                    no_match,
                    0..no_match.len(),
                    Strategy::ReverseSequentialRows,
                    no_output_limits,
                )
                .unwrap(),
            0
        );
        assert_eq!(
            compiled
                .count_value(
                    no_match,
                    0..no_match.len(),
                    Strategy::ReverseSequentialRows,
                    no_output_limits,
                )
                .unwrap(),
            0
        );

        let exact_sum_work = OperationLimits {
            max_work: result.receipt.actual.work,
            ..OperationLimits::default()
        };
        assert_eq!(
            compiled
                .span_sum_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    exact_sum_work,
                )
                .unwrap(),
            result.value
        );
        let exact_sum_receipt = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact_sum_work,
            )
            .unwrap();
        assert_eq!(exact_sum_receipt.value, result.value);
        assert_eq!(
            exact_sum_receipt.receipt.prospective.unwrap().work_bound,
            result.receipt.actual.work
        );
        let below_sum_work = OperationLimits {
            max_work: result.receipt.actual.work - 1,
            ..OperationLimits::default()
        };
        assert!(matches!(
            compiled.span_sum_value(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                below_sum_work,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            })
        ));
        let below_sum_receipt = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                below_sum_work,
            )
            .unwrap_err();
        assert_eq!(
            below_sum_receipt.receipt.prospective.unwrap().work_bound,
            result.receipt.actual.work - 1
        );
        assert!(below_sum_receipt.receipt.actual.work < result.receipt.actual.work);

        let count = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let exact_count_work = OperationLimits {
            max_work: count.receipt.actual.work,
            ..OperationLimits::default()
        };
        assert_eq!(
            compiled
                .count_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    exact_count_work,
                )
                .unwrap(),
            count.value
        );
        assert_eq!(
            compiled
                .count_value_attempt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    exact_count_work,
                )
                .unwrap()
                .value,
            count.value
        );
        let below_count_work = OperationLimits {
            max_work: count.receipt.actual.work - 1,
            ..OperationLimits::default()
        };
        assert!(matches!(
            compiled.count_value(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                below_count_work,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            })
        ));
        let below_count_receipt = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                below_count_work,
            )
            .unwrap_err();
        assert_eq!(
            below_count_receipt.receipt.prospective.unwrap().work_bound,
            count.receipt.actual.work - 1
        );
        assert!(below_count_receipt.receipt.actual.work < count.receipt.actual.work);

        let prospective = result.receipt.prospective.unwrap();
        let boundaries = haystack.len() + 1;
        let dense_work_floor = dense_reduction_work_floor(&compiled.program, boundaries).unwrap();
        let dense_requirements = Requirements::new::<true>(
            &compiled.program,
            boundaries,
            Strategy::ReverseSequentialRows,
            1,
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(dense_work_floor, dense_requirements.work_bound);
        assert!(prospective.work_bound < dense_work_floor);
        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        };
        let replay = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(replay.value, result.value);
        assert_eq!(replay.receipt.prospective, Some(prospective));

        let refusal = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_scratch_bytes: prospective.scratch_bytes - 1,
                    ..exact
                },
            )
            .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::ScratchBytes,
                required: prospective.scratch_bytes,
                limit: prospective.scratch_bytes - 1,
            }
        );
        assert_eq!(refusal.receipt.prospective, Some(prospective));
        assert_eq!(refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(refusal.receipt.actual_allocations, 0);
    }

    #[test]
    fn fixed_continuation_candidate_is_anchor_generic_on_exhaustive_short_sources() {
        let pattern = r"(?:(?:ab|cd|\d)+\)*;?((?:\s|-)*.*(?:.*:.*)))";
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let fixed = compiled
            .candidate
            .as_ref()
            .and_then(candidate::Plan::fixed_continuation)
            .unwrap();
        assert_eq!(fixed.anchor, b':');
        let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let alphabet = [
            b'a', b'b', b'c', b'd', b'0', b')', b';', b' ', b':', b'\n', b'x', 0xff,
        ];
        for len in 0_u32..=4 {
            let cases = alphabet.len().pow(len);
            for mut ordinal in 0..cases {
                let mut haystack = vec![0_u8; usize::try_from(len).unwrap()];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let expected = oracle.find_iter(&haystack).collect::<Vec<_>>();
                let expected_sum = expected
                    .iter()
                    .map(|matched| matched.end() - matched.start())
                    .sum::<usize>();
                let span_sum = candidate::reduce_fixed_continuation_attempt(
                    candidate::ReductionKind::SpanSum,
                    fixed,
                    &haystack,
                    0..haystack.len(),
                    OperationLimits::default(),
                )
                .unwrap();
                assert_eq!(span_sum.matches, expected.len(), "{haystack:?}");
                assert_eq!(span_sum.span_sum, expected_sum, "{haystack:?}");
                assert!(
                    candidate::fixed_continuation_upper(fixed, haystack.len(), haystack.len() + 1)
                        .unwrap()
                        .work
                        >= span_sum.accounting.work
                );
            }
        }
    }

    #[test]
    fn fixed_continuation_cost_gate_requires_a_strict_proved_win() {
        assert!(fixed_continuation_beats_dense(40, 41));
        assert!(!fixed_continuation_beats_dense(40, 40));
        assert!(!fixed_continuation_beats_dense(41, 40));
    }

    #[test]
    fn fixed_continuation_near_miss_retains_generic_dense_fallback() {
        // Omitting the optional punctuation changes the root topology and
        // deliberately invalidates the complete fixed-continuation theorem.
        let pattern = r"(?:(?:alpha|beta)+\)*((?:\s|-)*.*(?:.*=.*)))";
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(compiled.candidate.is_none());
        let haystack = b"none\nalpha--) x=value";
        let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let expected = oracle
            .find_iter(haystack)
            .map(|matched| matched.end() - matched.start())
            .sum::<usize>();
        let result = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(result.value, expected);
        assert_eq!(
            result.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::DenseRows)
        );
    }

    #[test]
    fn endpoint_forced_dense_allocation_faults_retain_exact_scoped_ordinals() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        for (strategy, ordinals) in [
            (Strategy::FullTable, 0..1),
            (Strategy::ReverseSequentialRows, 0..3),
        ] {
            let prospective = compiled
                .fixed_scalar_dense_count_prospective(haystack.len(), strategy)
                .unwrap();
            assert_eq!(prospective.allocations, ordinals.end);
            for ordinal in ordinals {
                let fault = allocation_fault::arm(ordinal);
                let mut observed = None;
                let failure = compiled
                    .admit_count_with_receipt_observer(
                        &haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                        prospective.allocations,
                        |published| {
                            observed = Some(published);
                            Ok(())
                        },
                    )
                    .unwrap_err();
                assert!(matches!(failure.source, Error::AllocationFailed { .. }));
                assert_eq!(observed, Some(prospective));
                assert_eq!(failure.receipt.prospective, Some(prospective));
                assert_eq!(failure.receipt.identity.strategy, strategy);
                assert_eq!(failure.receipt.actual_allocations, ordinal);
                assert!(prospective.contains(failure.receipt.actual));
                assert!(failure.receipt.actual_allocations <= prospective.allocations);
                assert_eq!(failure.receipt.actual.random_access_bytes_read, 0);
                assert_eq!(failure.receipt.actual.sequential_bytes_read, 0);
                assert_eq!(allocation_fault::calls(), ordinal + 1);
                drop(fault);
            }
        }
    }

    #[test]
    fn endpoint_count_value_attempt_limit_refuses_before_source() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let failure = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_output_matches: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        let prospective = failure
            .receipt
            .prospective
            .expect("generic route must publish P before source access");
        assert_eq!(prospective.output_matches, haystack.len() + 1);
        assert!(prospective.output_matches > 0);
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::OutputMatches,
                required: prospective.output_matches,
                limit: 0,
            }
        );
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual.random_access_bytes_read, 0);
        assert_eq!(failure.receipt.actual.sequential_bytes_read, 0);
        assert!(prospective.contains(failure.receipt.actual));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one cached-policy regression audits exact, one-below, and zero-work closure"
    )]
    fn endpoint_count_value_attempt_preserves_generic_cached_policy() {
        let compiled = endpoint_scalar_repeat();
        let haystack = [b'a'; 249];
        let boundaries = haystack.len() + 1;
        let dense = Requirements::new::<true>(
            &compiled.program,
            boundaries,
            Strategy::ReverseSequentialRows,
            1,
            OperationLimits::default(),
        )
        .unwrap();
        assert!(dense.row_storage.is_some());
        let limits = OperationLimits {
            max_work: dense.work_bound.checked_sub(1).unwrap(),
            ..OperationLimits::default()
        };
        let cached = Requirements::cached(&compiled.program, boundaries, 1, limits)
            .unwrap()
            .expect("one-below-dense observed policy must admit the generic cache");

        let incumbent = compiled
            .count_value(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        let attempt = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        assert_eq!(attempt.value, incumbent);
        let prospective = attempt.receipt.prospective.unwrap();
        assert_eq!(
            attempt.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::CachedFrontier)
        );
        assert_eq!(prospective.table_cells, 0);
        assert_eq!(prospective.row_storage, None);
        assert_eq!(prospective.random_access_bytes, cached.random_access_bound);
        assert!(prospective.contains(attempt.receipt.actual));

        let exact_work = attempt.receipt.actual.work;
        assert!(
            exact_work
                > cached
                    .cached_frontier
                    .unwrap()
                    .initialization_work()
                    .unwrap()
        );
        let exact_limits = OperationLimits {
            max_work: exact_work,
            ..OperationLimits::default()
        };
        let exact = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact_limits,
            )
            .unwrap();
        let exact_p = exact.receipt.prospective.unwrap();
        assert_eq!(
            exact.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::CachedFrontier)
        );
        assert_eq!(exact_p.work_bound, exact_work);
        assert_eq!(exact.receipt.actual.work, exact_work);
        assert!(exact_p.contains(exact.receipt.actual));

        let one_below_limit = exact_work - 1;
        let one_below = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: one_below_limit,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required,
                limit,
            } if required == exact_work && limit == one_below_limit
        ));
        assert_eq!(
            one_below.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::CachedFrontier)
        );
        let one_below_p = one_below.receipt.prospective.unwrap();
        assert_eq!(one_below_p.work_bound, one_below_limit);
        assert!(one_below_p.contains(one_below.receipt.actual));

        // A zero-work caller cannot admit the cache's fixed initialization,
        // so route selection deliberately retains the dense executor and it
        // refuses on its first observed charge without crossing P.
        let zero = compiled
            .count_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            zero.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: 1,
                limit: 0,
            }
        ));
        assert_eq!(
            zero.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::DenseRows)
        );
        let zero_p = zero.receipt.prospective.unwrap();
        assert_eq!(zero_p.work_bound, 0);
        assert!(zero_p.contains(zero.receipt.actual));
    }

    #[test]
    fn cached_symbol_without_assertions_retains_exact_logical_charge() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = b"a";
        let assertions = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let mut accounting = ExecutionAccounting::default();
        let _ = cached_boundary_symbol(
            &compiled.program,
            assertions,
            haystack,
            0,
            0,
            &mut accounting,
            usize::MAX,
            false,
        )
        .unwrap();
        assert_eq!(accounting.frontier_bookkeeping, 19);
        assert_eq!(accounting.work, 19);

        let mut partial = ExecutionAccounting::default();
        assert_eq!(
            cached_boundary_symbol(
                &compiled.program,
                assertions,
                haystack,
                0,
                0,
                &mut partial,
                10,
                false,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: 11,
                limit: 10,
            })
        );
        assert_eq!(partial.frontier_bookkeeping, 10);
        assert_eq!(partial.work, 10);
        assert_eq!(partial.random_access_bytes_read, 0);
    }

    #[test]
    fn endpoint_cached_assertion_source_is_receipt_tracked_without_re_evaluation() {
        let hir = ParserBuilder::new().build().parse(r"\b").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = "éx".as_bytes();
        let assertions = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let admitted = usize::MAX;
        let mut mask_accounting = ExecutionAccounting::default();
        let used_assertions =
            cached_program_assertion_mask(&compiled.program, &mut mask_accounting, admitted)
                .unwrap();

        let mut untracked = ExecutionAccounting::default();
        let untracked_symbol = cached_boundary_symbol(
            &compiled.program,
            assertions,
            haystack,
            "é".len(),
            used_assertions,
            &mut untracked,
            admitted,
            false,
        )
        .unwrap();
        let mut tracked = ExecutionAccounting::default();
        let tracked_symbol = cached_boundary_symbol(
            &compiled.program,
            assertions,
            haystack,
            "é".len(),
            used_assertions,
            &mut tracked,
            admitted,
            true,
        )
        .unwrap();

        assert_eq!(tracked_symbol, untracked_symbol);
        assert_eq!(untracked.random_access_bytes_read, 1);
        assert_eq!(tracked.random_access_bytes_read, 4);
    }

    #[test]
    fn endpoint_incumbent_unicode_word_keeps_malformed_utf8_before_limit_precedence() {
        let hir = ParserBuilder::new().build().parse(r"\b.").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            compiled.admit_count(
                b"\xff",
                0..1,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_boundaries: 0,
                    ..OperationLimits::default()
                },
            ),
            Err(Error::InvalidUtf8ForUnicodeWordBoundary)
        ));
    }

    #[test]
    fn endpoint_receipt_limit_precedes_unicode_word_utf8_validation_and_source() {
        let hir = ParserBuilder::new().build().parse(r"\b.").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        let failure = compiled
            .count_value_with_receipt(
                b"\xff",
                0..1,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_output_matches: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        let prospective = failure.receipt.prospective.unwrap();
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource: Resource::OutputMatches,
                required: prospective.output_matches,
                limit: 0,
            }
        );
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
    }

    #[test]
    fn observed_work_below_utf8_prefix_refuses_before_source_with_closed_receipt() {
        let hir = ParserBuilder::new().build().parse(r"\b.").unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        let haystack = b"\xff\xff";
        for limit in [0, haystack.len() - 1] {
            let failure = compiled
                .count_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_work: limit,
                        ..OperationLimits::default()
                    },
                )
                .unwrap_err();
            assert_eq!(
                failure.source,
                Error::ResourceLimit {
                    resource: Resource::ExecutionWork,
                    required: haystack.len(),
                    limit,
                }
            );
            let prospective = failure.receipt.prospective.unwrap();
            assert_eq!(prospective.work_bound, haystack.len());
            assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
            assert!(prospective.contains(failure.receipt.actual));
        }
    }

    #[test]
    fn endpoint_cached_mid_allocation_failure_retains_exact_partial_ledger() {
        let compiled = endpoint_scalar_repeat();
        let haystack = b"a";
        let boundaries = haystack.len() + 1;
        let limits = OperationLimits::default();
        let cache =
            CachedFrontierRequirements::new(compiled.program.insts.len(), boundaries, 1).unwrap();
        let requirements = Requirements::cached(&compiled.program, boundaries, 1, limits)
            .unwrap()
            .expect("default limits admit the fixed cached frontier");
        let assertions = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let mut accounting = ExecutionAccounting::default();
        let mut actual_allocations = 0;
        let _fault = allocation_fault::arm(2);
        let Err(error) = CachedFrontierStore::build(
            &compiled.program,
            haystack,
            assertions,
            requirements,
            cache,
            limits,
            false,
            &mut accounting,
            &mut actual_allocations,
        ) else {
            panic!("third cached allocation must fail");
        };
        assert_eq!(
            error,
            Error::AllocationFailed {
                resource: Resource::ScratchBytes,
                items: MAX_CACHED_FRONTIERS,
            }
        );
        let state_bytes = cache.state_word_capacity * core::mem::size_of::<u64>();
        let initialized = 2 + cache.boundary_count + cache.state_word_capacity;
        assert_eq!(accounting.log_bytes, cache.log_bytes);
        assert_eq!(accounting.random_access_peak_bytes, state_bytes);
        assert_eq!(accounting.scratch_peak_bytes, state_bytes);
        assert_eq!(accounting.peak_bytes, cache.log_bytes + state_bytes);
        assert_eq!(accounting.frontier_bookkeeping, initialized);
        assert_eq!(accounting.work, initialized);
        assert_eq!(actual_allocations, 2);
    }

    #[test]
    fn endpoint_terminal_mid_allocation_failure_retains_exact_partial_ledger() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a|ab")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let states = compiled.program.insts.len();
        let edges = compiled.program.predecessor_edges();
        let live_words = (states + 1) + edges + states;
        let live_bytes = live_words * core::mem::size_of::<usize>();
        let mut accounting = ExecutionAccounting::default();
        let _fault = allocation_fault::arm(3);
        let error = super::terminal_frontier::test_allocated_composite(
            &compiled.program,
            OperationLimits::default(),
            &mut accounting,
        )
        .unwrap_err();
        assert_eq!(
            error,
            Error::AllocationFailed {
                resource: Resource::ScratchBytes,
                items: states,
            }
        );
        assert_eq!(accounting.random_access_peak_bytes, live_bytes);
        assert_eq!(accounting.scratch_peak_bytes, live_bytes);
        assert_eq!(accounting.frontier_bytes, live_bytes);
        assert_eq!(accounting.peak_bytes, live_bytes);
        assert_eq!(accounting.frontier_bookkeeping, live_words);
        assert_eq!(accounting.work, live_words);
    }

    #[test]
    fn endpoint_terminal_log_allocation_failure_retains_frontier_only_ledger() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a|ab")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let (total_words, frontier_bytes) =
            super::terminal_frontier::test_allocation_shape(&compiled.program).unwrap();
        let log_bytes = 17;
        let mut accounting = ExecutionAccounting::default();
        let _fault = allocation_fault::arm(7);
        let error = super::terminal_frontier::test_allocated_then_log(
            &compiled.program,
            log_bytes,
            OperationLimits::default(),
            &mut accounting,
        )
        .unwrap_err();
        assert_eq!(
            error,
            Error::AllocationFailed {
                resource: Resource::LogBytes,
                items: log_bytes,
            }
        );
        assert_eq!(accounting.log_bytes, 0);
        assert_eq!(accounting.random_access_peak_bytes, frontier_bytes);
        assert_eq!(accounting.scratch_peak_bytes, frontier_bytes);
        assert_eq!(accounting.frontier_bytes, frontier_bytes);
        assert_eq!(accounting.peak_bytes, frontier_bytes);
        assert_eq!(accounting.frontier_bookkeeping, total_words);
        assert_eq!(accounting.work, total_words);
    }

    #[test]
    fn uncached_checkpoint_recomputes_and_preserves_preferred_alternation() {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("a|ab")
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let program = &compiled.program;
        let haystack = b"ab";
        let assertions = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let words = cached_frontier_words(program.insts.len()).unwrap();
        let admitted = usize::MAX;
        let mut accounting = ExecutionAccounting::default();
        let used_assertions =
            cached_program_assertion_mask(program, &mut accounting, admitted).unwrap();

        let zero = vec![0_u64; words];
        let mut terminal = vec![0_u64; words];
        let terminal_symbol = cached_boundary_symbol(
            program,
            assertions,
            haystack,
            haystack.len(),
            used_assertions,
            &mut accounting,
            admitted,
            false,
        )
        .unwrap();
        cached_compute_row(
            program,
            terminal_symbol,
            &zero,
            &mut terminal,
            &mut accounting,
            admitted,
        )
        .unwrap();
        let mut row_one = vec![0_u64; words];
        let row_one_symbol = cached_boundary_symbol(
            program,
            assertions,
            haystack,
            1,
            used_assertions,
            &mut accounting,
            admitted,
            false,
        )
        .unwrap();
        cached_compute_row(
            program,
            row_one_symbol,
            &terminal,
            &mut row_one,
            &mut accounting,
            admitted,
        )
        .unwrap();

        let mut state_bits = exact_filled(words * 3, 0_u64, Resource::ScratchBytes).unwrap();
        state_bits[words..words * 2].copy_from_slice(&terminal);
        state_bits[words * 2..words * 3].copy_from_slice(&row_one);
        let mut boundary_states = exact_filled(3, UNCACHED_FRONTIER, Resource::LogBytes).unwrap();
        boundary_states[1] = 2;
        boundary_states[2] = 1;
        let mut store = CachedFrontierStore {
            boundary_states,
            state_bits,
            state_hashes: fre_exact_alloc::ExactVec::default(),
            transitions: fre_exact_alloc::ExactVec::default(),
            replay_current: exact_filled(words, 0_u64, Resource::ScratchBytes).unwrap(),
            replay_next: exact_filled(words, 0_u64, Resource::ScratchBytes).unwrap(),
            words,
            state_count: 0,
            transition_count: 0,
            saturated: false,
            has_run: true,
            poisoned: false,
            used_assertions,
            checkpoint_log_bytes_read: 0,
            build_peak_bytes: 0,
            replay_bytes: 0,
        };
        let before_random = accounting.random_access_bytes_read;
        assert_eq!(
            store
                .selected(
                    program,
                    haystack,
                    assertions,
                    0,
                    &mut accounting,
                    admitted,
                    false,
                )
                .unwrap(),
            Some(1)
        );
        assert_eq!(accounting.random_access_bytes_read - before_random, 1);
        assert_eq!(store.checkpoint_log_bytes_read, core::mem::size_of::<u16>());
    }

    #[test]
    fn cached_frontier_exact_capacity_and_every_one_below_limit() {
        let requirements = CachedFrontierRequirements::new(65, 11, 1).unwrap();
        assert_eq!(core::mem::size_of::<CachedTransitionSlot>(), 16);
        assert_eq!(requirements.words, 2);
        assert_eq!(requirements.record_bytes, 2);
        assert_eq!(requirements.state_word_capacity, 8_192);
        assert_eq!(requirements.boundary_count, 11);
        assert_eq!(requirements.log_bytes, 22);
        assert_eq!(requirements.random_bytes, 2_195_488);
        assert_eq!(requirements.scratch_bytes, 2_195_488);
        assert_eq!(requirements.peak_bytes, 2_195_510);
        assert_eq!(requirements.sequential_bound, 88);
        assert_eq!(requirements.initialization_work().unwrap(), 143_381);

        let exact = OperationLimits {
            max_random_access_bytes: requirements.random_bytes,
            max_scratch_bytes: requirements.scratch_bytes,
            max_log_bytes: requirements.log_bytes,
            max_sequential_bytes: requirements.sequential_bound,
            max_peak_bytes: requirements.peak_bytes,
            ..OperationLimits::default()
        };
        requirements.enforce(exact).unwrap();
        for (resource, required, one_below) in [
            (
                Resource::RandomAccessBytes,
                requirements.random_bytes,
                OperationLimits {
                    max_random_access_bytes: requirements.random_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ScratchBytes,
                requirements.scratch_bytes,
                OperationLimits {
                    max_scratch_bytes: requirements.scratch_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::LogBytes,
                requirements.log_bytes,
                OperationLimits {
                    max_log_bytes: requirements.log_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::SequentialBytes,
                requirements.sequential_bound,
                OperationLimits {
                    max_sequential_bytes: requirements.sequential_bound - 1,
                    ..exact
                },
            ),
            (
                Resource::PeakBytes,
                requirements.peak_bytes,
                OperationLimits {
                    max_peak_bytes: requirements.peak_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert_eq!(
                requirements.enforce(one_below),
                Err(Error::ResourceLimit {
                    resource,
                    required,
                    limit: required - 1,
                })
            );
        }
    }

    #[test]
    fn cached_frontier_economics_require_clear_fixed_cost_amortization() {
        let pattern = "[ab]".repeat(80);
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(&pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let limits = OperationLimits::default();
        let boundaries = 10_001;
        let dense = Requirements::new::<true>(
            &compiled.program,
            boundaries,
            Strategy::ReverseSequentialRows,
            2,
            limits,
        )
        .unwrap();
        let cached =
            cached_frontier_amortizes_dense(&compiled.program, boundaries, 2, limits, dense)
                .unwrap()
                .expect("large dense continuation must amortize fixed cache construction");
        assert!(cached.cached_frontier.is_some());
        let haystack = vec![b'a'; boundaries - 1];
        let selected = compiled
            .admit_spans_observed_cached_when_amortized(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .expect("amortized cached spans");
        assert_eq!(
            selected.certificate().physical_route,
            OperationPhysicalRoute::CachedFrontier
        );
        let ordinary = compiled
            .admit_spans_observed(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .expect("ordinary observed spans");
        assert_eq!(selected.as_slice(), ordinary.as_slice());

        let short_boundaries = 2;
        let short_dense = Requirements::new::<true>(
            &compiled.program,
            short_boundaries,
            Strategy::ReverseSequentialRows,
            2,
            limits,
        )
        .unwrap();
        assert!(
            cached_frontier_amortizes_dense(
                &compiled.program,
                short_boundaries,
                2,
                limits,
                short_dense,
            )
            .unwrap()
            .is_none(),
            "tiny inputs retain dense rows instead of speculating on cache hits"
        );
    }

    #[test]
    fn cached_count_session_recovers_after_interrupted_population() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"(\bword\b)|(\r\n|\r|\n)|([\t ]+)|(.)")
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let hard: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        let easy = vec![b'a'; hard.len()];
        let defaults = OperationLimits::default();

        let measured_work = |haystack: &[u8]| {
            let mut session = compiled
                .cached_count_session(haystack.len(), defaults)
                .unwrap()
                .expect("assertion-bearing byte session");
            compiled
                .count_value_with_cached_session_and_counters(&mut session, haystack, defaults)
                .unwrap()
                .receipt
                .accounting
                .work
        };
        let hard_work = measured_work(&hard);
        let easy_work = measured_work(&easy);
        let reset_work = cached_frontier_words(compiled.program.insts.len())
            .unwrap()
            .checked_mul(2)
            .unwrap();
        // The interrupted diverse source may retain a small number of
        // source-independent states that the repeated-byte recovery probes
        // before hitting its established transition. Admit that bounded
        // lookup variance while remaining strictly below the diverse scan.
        let admitted_work = easy_work
            .checked_add(reset_work)
            .and_then(|work| work.checked_add(32))
            .unwrap();
        assert!(
            hard_work > admitted_work,
            "fixture must interrupt the diverse population after admitting a repeated-byte scan"
        );

        let limits = OperationLimits {
            max_work: admitted_work,
            ..defaults
        };
        let mut session = compiled
            .cached_count_session(hard.len(), limits)
            .unwrap()
            .expect("bounded cached Count session");
        let interrupted = compiled
            .count_value_with_cached_session_and_counters(&mut session, &hard, limits)
            .unwrap_err();
        assert!(matches!(
            interrupted,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required,
                limit,
            } if required == limit + 1 && limit == admitted_work
        ));

        let recovered = compiled
            .count_value_with_cached_session_and_counters(&mut session, &easy, limits)
            .expect("interrupted population must not poison the next source");
        assert_eq!(recovered.value, easy.len());
        assert!(recovered.receipt.closes());
        assert_eq!(
            recovered.receipt.certificate.physical_route,
            OperationPhysicalRoute::CachedFrontier
        );
        assert_eq!(recovered.receipt.certificate.actual_allocations, 0);
        assert_eq!(recovered.receipt.certificate.prospective_allocations, 0);
    }

    #[test]
    fn cached_count_session_defers_multiword_hit_rows_and_recovers_hit_to_miss() {
        let mut retained = [0_u64; 6];
        retained[5] = 1_u64 << 6;
        let mut direct_accounting = ExecutionAccounting::default();
        assert!(
            cached_retained_candidate_bit(&retained, 2, 2, 70, &mut direct_accounting, 1,).unwrap()
        );
        assert_eq!(direct_accounting.work, 1);

        let pattern = "[ab]".repeat(80);
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(&pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(
            compiled.program.insts.len() > 64,
            "fixture must exercise retained bits beyond the first word"
        );
        let repeated = vec![b'a'; 80 * 8];
        let mut changed = repeated.clone();
        let middle = changed.len() / 2;
        changed[middle] = b'b';
        changed[middle + 1] = b'c';
        let limits = OperationLimits::default();
        let mut session = compiled
            .cached_count_session(repeated.len(), limits)
            .unwrap()
            .expect("multiword byte session");

        let populated = compiled
            .count_value_with_cached_session_and_counters(&mut session, &repeated, limits)
            .unwrap();
        let hit_run = compiled
            .count_value_with_cached_session_and_counters(&mut session, &repeated, limits)
            .unwrap();
        assert_eq!(populated.value, 8);
        assert_eq!(hit_run.value, populated.value);
        assert!(
            hit_run.receipt.accounting.work < populated.receipt.accounting.work,
            "a complete transition-hit run should avoid frontier materialization"
        );

        let hit_then_miss = compiled
            .count_value_with_cached_session_and_counters(&mut session, &changed, limits)
            .unwrap();
        let expected = regex::bytes::RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(&changed)
            .count();
        assert_eq!(hit_then_miss.value, expected);
        assert_eq!(
            compiled
                .count_value_with_cached_session_and_counters(&mut session, &repeated, limits)
                .unwrap()
                .value,
            populated.value,
            "materializing a retained successor after a hit run must not poison later hits"
        );
    }

    #[test]
    fn cached_frontier_capacity_is_input_independent_and_overflow_checked() {
        let short = CachedFrontierRequirements::new(257, 19, 1).unwrap();
        let long = CachedFrontierRequirements::new(257, 19_000, 1).unwrap();
        assert_eq!(short.words, long.words);
        assert_eq!(short.state_word_capacity, long.state_word_capacity);
        assert_eq!(short.random_bytes, long.random_bytes);
        assert_eq!(short.scratch_bytes, long.scratch_bytes);
        assert!(short.log_bytes < long.log_bytes);
        assert!(short.peak_bytes < long.peak_bytes);

        assert_eq!(
            CachedFrontierRequirements::new(usize::MAX, 0, 1),
            Err(Error::ArithmeticOverflow {
                resource: Resource::ScratchBytes,
            })
        );
        assert_eq!(
            CachedFrontierRequirements::new(1, usize::MAX, 1),
            Err(Error::ArithmeticOverflow {
                resource: Resource::LogBytes,
            })
        );
        assert_eq!(
            CachedFrontierRequirements::new(1, 1, usize::MAX),
            Err(Error::ArithmeticOverflow {
                resource: Resource::SequentialBytes,
            })
        );
    }

    #[test]
    fn reachable_endpoint_encoding_covers_arbitrary_word_widths() {
        let cases = [
            (0_usize, 1_usize),
            (1, 1),
            (255, 1),
            (256, 2),
            (65_535, 2),
            (65_536, 3),
        ];
        for (value, width) in cases {
            assert_eq!(width, encoded_width(value));
            let mut record = vec![0_u8; width];
            write_encoded(&mut record, value).unwrap();
            assert_eq!(value, read_encoded(&record).unwrap());
        }
        assert!(write_encoded(&mut [0_u8], 256).is_err());
        assert_eq!(None, decode(read_encoded(&[0]).unwrap()));
        assert_eq!(Some(0), decode(read_encoded(&[1]).unwrap()));
    }

    #[test]
    fn row_reader_advances_from_its_authenticated_offset() {
        let store = [30_u8, 31, 20, 21, 10, 11, 0, 1];
        let mut reader = RowReader {
            store: &store,
            storage: RowStorage::SplitDecisions,
            record_bytes: 2,
            current_record: &[],
            current_position: None,
            current_start: store.len(),
            root_rank: 0,
        };
        let mut accounting = ExecutionAccounting::default();

        reader.ensure(0, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [0, 1]);
        assert_eq!(accounting.sequential_bytes_read, 2);

        reader.ensure(1, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [10, 11]);
        assert_eq!(accounting.sequential_bytes_read, 4);

        reader.ensure(3, &mut accounting).unwrap();
        assert_eq!(reader.current_record, [30, 31]);
        assert_eq!(accounting.sequential_bytes_read, 8);

        reader.ensure(3, &mut accounting).unwrap();
        assert_eq!(accounting.sequential_bytes_read, 8);
        assert!(reader.ensure(2, &mut accounting).is_err());
    }

    #[test]
    fn endpoint_row_reader_preserves_failure_and_empty() {
        let store = [0_u8, 1];
        let mut reader = RowReader {
            store: &store,
            storage: RowStorage::ReachableEndpoints,
            record_bytes: 1,
            current_record: &[],
            current_position: None,
            current_start: store.len(),
            root_rank: 0,
        };
        let mut accounting = ExecutionAccounting::default();

        assert_eq!(Some(0), reader.endpoint(0, &mut accounting).unwrap());
        assert_eq!(None, reader.endpoint(1, &mut accounting).unwrap());
        assert_eq!(2, accounting.sequential_bytes_read);
        assert!(reader.root(1, &mut accounting).is_err());
    }

    #[test]
    #[ignore = "requires authenticated Rebar URL pattern and haystack paths"]
    #[allow(
        clippy::too_many_lines,
        reason = "one authenticated transaction covers compile, every operation route, and all one-below resources"
    )]
    fn authenticated_url_integrates_compile_count_sum_and_generic_spans() {
        let pattern_path = std::env::var_os("FRE_TEST_URL_PATTERN")
            .expect("FRE_TEST_URL_PATTERN must name wild/url.txt");
        let haystack_path = std::env::var_os("FRE_TEST_URL_HAYSTACK")
            .expect("FRE_TEST_URL_HAYSTACK must name the authenticated URL haystack");
        let source = std::fs::read_to_string(pattern_path).unwrap();
        let source = source.trim_end();
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .case_insensitive(true)
            .build()
            .parse(source)
            .unwrap();
        let base_compile = CompileLimits {
            max_hir_nodes: 65_536,
            max_hir_stack_items: 65_536,
            max_repeat_bound: 1_024,
            max_program_bytes: 16 * 1_048_576,
            max_work: 16 * 1_048_576,
            ..CompileLimits::default()
        };
        crate::compile::url_pack_allocation_probe::reset();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            base_compile,
        )
        .unwrap();
        let compile = compiled.compile_accounting();
        assert_eq!(compile.url_aggregate_plans, 1);
        assert_eq!(compile.url_aggregate_tlds, 1_498);
        assert_eq!(compile.url_aggregate_tld_bytes, 8_505);
        assert!(compile.url_aggregate_build_work > 0);
        assert!(compile.url_aggregate_persistent_bytes > 0);
        assert!(compile.work <= base_compile.max_work);
        assert_eq!(crate::compile::url_pack_allocation_probe::calls(), 2);
        assert_eq!(crate::compile::url_pack_allocation_probe::count_calls(), 1);
        assert_eq!(
            crate::compile::url_pack_allocation_probe::copy_calls(),
            compile.url_aggregate_tld_bytes
        );
        let pack_precount_work =
            crate::compile::url_pack_allocation_probe::precount_work().unwrap();
        let pack_precopy_work = crate::compile::url_pack_allocation_probe::precopy_work().unwrap();
        let pack_preallocation_work =
            crate::compile::url_pack_allocation_probe::preallocation_work().unwrap();

        crate::compile::url_pack_allocation_probe::reset();
        let count_accessor_refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_work: pack_precount_work,
                ..base_compile
            },
        );
        assert!(matches!(
            count_accessor_refusal,
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        assert_eq!(crate::compile::url_pack_allocation_probe::count_calls(), 0);

        crate::compile::url_pack_allocation_probe::reset();
        let first_copy_refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_work: pack_precopy_work,
                ..base_compile
            },
        );
        assert!(matches!(
            first_copy_refusal,
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        assert_eq!(crate::compile::url_pack_allocation_probe::copy_calls(), 0);

        crate::compile::url_pack_allocation_probe::reset();
        let pack_preallocation_refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_work: pack_preallocation_work + 3,
                ..base_compile
            },
        );
        assert!(matches!(
            pack_preallocation_refusal,
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        assert_eq!(crate::compile::url_pack_allocation_probe::calls(), 0);

        let exact = CompileLimits {
            max_work: compile.work,
            max_program_bytes: compile.program_bytes,
            ..base_compile
        };
        let exact_compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            exact,
        )
        .unwrap();
        assert_eq!(compiled.plan_id(), exact_compiled.plan_id());
        assert!(matches!(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_work: compile.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        let program_one_below = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_program_bytes: compile.program_bytes - 1,
                ..exact
            },
        );
        assert!(
            matches!(
                program_one_below,
                Err(Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    ..
                })
            ),
            "unexpected program-byte one-below result: {program_one_below:?}"
        );

        let haystack = std::fs::read(haystack_path).unwrap();
        let limits = OperationLimits {
            max_boundaries: haystack.len() + 1,
            ..OperationLimits::default()
        };
        let sum = compiled
            .admit_span_sum(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        assert_eq!(sum.value(), 234_965);
        assert_eq!(sum.certificate().output_matches, 25_957);
        assert_eq!(
            sum.certificate().random_access_bytes,
            sum.accounting().random_access_peak_bytes
        );
        assert!(sum.accounting().random_access_bytes_read > 0);
        assert_eq!(
            sum.certificate().scratch_bytes,
            sum.accounting().scratch_peak_bytes
        );
        assert_eq!(sum.certificate().work_bound, sum.accounting().work);
        let url = sum.accounting();
        assert_eq!(url.url_segments, 742_904);
        assert_eq!(url.url_dot_probes, 76_849);
        assert_eq!(url.url_tld_transitions, 210_680);
        assert_eq!(url.url_tld_candidates, 39_549);
        assert_eq!(url.url_scheme_probes, 205_575);
        assert_eq!(url.url_ipv4_candidates, 0);
        assert_eq!(url.url_prefix_steps, 944_525);
        assert_eq!(url.url_suffix_steps, 14_565);
        assert_eq!(url.url_candidate_insertions, 142_571);
        assert_eq!(url.url_candidate_visits, 25_957);
        assert_eq!(url.state_evaluations, 0);
        assert_eq!(url.transition_checks, 0);
        assert_eq!(url.assertion_checks, 0);
        assert_eq!(url.root_probes, 0);
        assert_eq!(url.frontier_insertions, 0);
        assert_eq!(url.frontier_evaluations, 0);
        let exact_run = OperationLimits {
            max_boundaries: sum.certificate().boundaries(),
            max_table_cells: 0,
            max_random_access_bytes: sum.certificate().random_access_bytes,
            max_scratch_bytes: sum.certificate().scratch_bytes,
            max_log_bytes: 0,
            max_sequential_bytes: sum.certificate().sequential_bytes_bound,
            max_match_events: sum.certificate().match_events,
            max_output_matches: sum.certificate().output_matches,
            max_output_bytes: 0,
            max_span_sum: sum.value(),
            max_peak_bytes: sum.certificate().peak_bytes,
            max_work: sum.certificate().work_bound,
        };
        assert_eq!(
            compiled
                .span_sum_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                )
                .unwrap(),
            234_965
        );
        assert_eq!(
            compiled
                .span_sum_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    exact_run,
                )
                .unwrap(),
            234_965
        );
        let assert_sum_refusal = |limits, resource| {
            assert!(matches!(
                compiled.span_sum_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                ),
                Err(Error::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
        };
        assert_sum_refusal(
            OperationLimits {
                max_boundaries: exact_run.max_boundaries - 1,
                ..exact_run
            },
            Resource::Boundaries,
        );
        assert_sum_refusal(
            OperationLimits {
                max_random_access_bytes: exact_run.max_random_access_bytes - 1,
                ..exact_run
            },
            Resource::RandomAccessBytes,
        );
        assert_sum_refusal(
            OperationLimits {
                max_scratch_bytes: exact_run.max_scratch_bytes - 1,
                ..exact_run
            },
            Resource::ScratchBytes,
        );
        assert_sum_refusal(
            OperationLimits {
                max_peak_bytes: exact_run.max_peak_bytes - 1,
                ..exact_run
            },
            Resource::PeakBytes,
        );
        assert_sum_refusal(
            OperationLimits {
                max_sequential_bytes: exact_run.max_sequential_bytes - 1,
                ..exact_run
            },
            Resource::SequentialBytes,
        );
        assert_sum_refusal(
            OperationLimits {
                max_match_events: exact_run.max_match_events - 1,
                ..exact_run
            },
            Resource::MatchEvents,
        );
        assert_sum_refusal(
            OperationLimits {
                max_output_matches: exact_run.max_output_matches - 1,
                ..exact_run
            },
            Resource::OutputMatches,
        );
        assert_sum_refusal(
            OperationLimits {
                max_span_sum: exact_run.max_span_sum - 1,
                ..exact_run
            },
            Resource::SpanSum,
        );
        assert_sum_refusal(
            OperationLimits {
                max_work: exact_run.max_work - 1,
                ..exact_run
            },
            Resource::ExecutionWork,
        );
        let count = compiled
            .admit_count(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap();
        assert_eq!(count.value(), 25_957);
        assert_eq!(count.certificate().span_sum, 0);
        assert_ne!(
            count.certificate().operation_id(),
            sum.certificate().operation_id()
        );
        assert_eq!(count.certificate().regex_plan_id, compiled.plan_id());
        assert_eq!(sum.certificate().regex_plan_id, compiled.plan_id());
        assert_eq!(
            compiled
                .count_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                )
                .unwrap(),
            25_957
        );
        assert_eq!(
            compiled
                .count_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_boundaries: haystack.len() + 1,
                        max_span_sum: 0,
                        ..OperationLimits::default()
                    },
                )
                .unwrap(),
            25_957
        );

        let sample = b"http://1.2.3.4x.com x.comdef.a.com";
        let expected = RegexBuilder::new(source)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .unwrap()
            .find_iter(sample)
            .map(|found| (found.start(), found.end()))
            .collect::<Vec<_>>();
        let spans = compiled
            .admit_spans(
                sample,
                0..sample.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap()
            .iter()
            .map(|span| (span.start, span.end))
            .collect::<Vec<_>>();
        assert_eq!(spans, expected);
        let reverse_sum = compiled
            .admit_span_sum(
                sample,
                0..sample.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let reverse_count = compiled
            .admit_count(
                sample,
                0..sample.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let full_sum = compiled
            .admit_span_sum(
                sample,
                0..sample.len(),
                Strategy::FullTable,
                OperationLimits::default(),
            )
            .unwrap();
        let full_count = compiled
            .admit_count(
                sample,
                0..sample.len(),
                Strategy::FullTable,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(reverse_sum.value(), full_sum.value());
        assert_eq!(reverse_count.value(), full_count.value());
        assert_eq!(
            full_sum.value(),
            expected.iter().map(|(start, end)| end - start).sum()
        );
        assert_eq!(full_count.value(), expected.len());
        assert!(reverse_sum.accounting().url_segments > 0);
        assert_eq!(full_sum.accounting().url_segments, 0);
        assert_ne!(
            reverse_sum.certificate().operation_id(),
            full_sum.certificate().operation_id()
        );
        assert_ne!(
            reverse_count.certificate().operation_id(),
            full_count.certificate().operation_id()
        );

        let ranged_sum = compiled
            .admit_span_sum(
                b"!!x.com!!",
                2..7,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let ranged_count = compiled
            .admit_count(
                b"!!x.com!!",
                2..7,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_span_sum: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap();
        assert_eq!(ranged_sum.value(), 5);
        assert_eq!(ranged_count.value(), 1);
        assert_eq!(ranged_sum.certificate().range, 2..7);
        assert_eq!(ranged_count.certificate().range, 2..7);

        let conflicting_source = source.replacen("ZIP|AC", "AB|ABC", 1);
        assert_ne!(conflicting_source, source);
        let conflicting_hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .case_insensitive(true)
            .build()
            .parse(&conflicting_source)
            .unwrap();
        let conflicting = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &conflicting_hir,
            RustByteProfile::PINNED_1_12_4,
            base_compile,
        )
        .unwrap();
        let fallback = conflicting.compile_accounting();
        assert_eq!(fallback.url_aggregate_plans, 0);
        assert_eq!(fallback.url_aggregate_tlds, 0);
        assert_eq!(fallback.url_aggregate_tld_bytes, 0);
        assert_eq!(fallback.url_aggregate_build_work, 0);
        assert_eq!(fallback.url_aggregate_persistent_bytes, 0);
        assert_ne!(conflicting.plan_id(), compiled.plan_id());
        let conflict_oracle = RegexBuilder::new(&conflicting_source)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .unwrap();
        let conflict_spans = conflict_oracle.find_iter(b"x.ab").collect::<Vec<_>>();
        assert_eq!(conflict_spans.len(), 1);
        assert_eq!(conflict_spans[0].range(), 0..4);
        assert_eq!(
            conflicting
                .span_sum_value(
                    b"x.ab",
                    0..4,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            4
        );
        assert_eq!(
            conflicting
                .count_value(
                    b"x.ab",
                    0..4,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            1
        );
    }

    fn state_byte_span_sum_fixture(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn unicode_state_byte_fixture(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(true)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn upstream_span_sum(pattern: &str, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
            .sum()
    }

    fn upstream_count(pattern: &str, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count()
    }

    fn exact_state_byte_limits(prospective: &OperationProspective) -> OperationLimits {
        OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one differential test keeps ASCII direct, UTF-8 fallback, malformed fallback, receipt, and target-shape assertions together"
    )]
    fn unicode_bounded_pair_does_not_publish_a_source_dependent_ascii_route() {
        const PATTERN: &str = r"a.{1,2}b|b.{1,2}a";
        let compiled = unicode_state_byte_fixture(PATTERN);
        if compiled.state_byte_span_sum.is_none() {
            assert_eq!(compiled.compile_accounting().state_byte_span_sum_plans, 0);
            return;
        }
        let plan = compiled
            .state_byte_span_sum
            .as_ref()
            .expect("checked as present above");
        assert_ne!(
            plan.topology(),
            StateByteSpanSumTopology::AsciiGuardedBoundedLiteralPair
        );
        assert_eq!(plan.bounded_pair_anchors(), Some((&b"a"[..], &b"b"[..])));
        assert_eq!(plan.bounded_pair_gap_bounds(), Some((1, 2)));
        assert_eq!(compiled.compile_accounting().state_byte_span_sum_plans, 1);

        let oracle = RegexBuilder::new(PATTERN).unicode(true).build().unwrap();
        let alphabet = [b'a', b'b', b'x', b'y', b'\n'];
        let mut haystack = Vec::new();
        for length in 0_u32..=7 {
            for mut ordinal in 0..alphabet.len().pow(length) {
                haystack.clear();
                for _ in 0..length {
                    haystack.push(alphabet[ordinal % alphabet.len()]);
                    ordinal /= alphabet.len();
                }
                let expected = oracle
                    .find_iter(&haystack)
                    .map(|found| found.end() - found.start())
                    .collect::<Vec<_>>();
                let direct = CompiledRegex::state_byte_reducer_value(
                    plan,
                    &haystack,
                    &(0..haystack.len()),
                    OperationKind::Sum,
                    OperationLimits::default(),
                )
                .unwrap();
                assert_eq!(
                    direct,
                    Some((expected.len(), expected.iter().sum())),
                    "{haystack:?}"
                );
                assert_eq!(
                    compiled
                        .count_value(
                            &haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits::default(),
                        )
                        .unwrap(),
                    expected.len(),
                    "{haystack:?}"
                );
                assert_eq!(
                    compiled
                        .span_sum_value(
                            &haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits::default(),
                        )
                        .unwrap(),
                    expected.iter().sum(),
                    "{haystack:?}"
                );
            }
        }

        for haystack in ["aéb axyb béa".as_bytes(), &b"a\xFFxb-bx\xFFa"[..]] {
            assert_eq!(
                CompiledRegex::state_byte_reducer_value(
                    plan,
                    haystack,
                    &(0..haystack.len()),
                    OperationKind::Count,
                    OperationLimits::default(),
                )
                .unwrap(),
                None
            );
            let expected = oracle.find_iter(haystack).collect::<Vec<_>>();
            assert_eq!(
                compiled
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                expected.len()
            );
            assert_eq!(
                compiled
                    .span_sum_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                expected
                    .iter()
                    .map(|found| found.end() - found.start())
                    .sum()
            );
        }

        let byte_compiled = state_byte_span_sum_fixture(PATTERN);
        let byte_plan = byte_compiled
            .state_byte_span_sum
            .as_ref()
            .expect("byte bounded pair should retain its exact class");
        assert_eq!(
            byte_plan.topology(),
            StateByteSpanSumTopology::BoundedLiteralPair
        );
        for haystack in [&b"axyb-bxya"[..], &b"a\xFFb-b\xFFa"[..]] {
            assert_eq!(
                byte_compiled
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                upstream_count(PATTERN, haystack)
            );
        }

        let admitted = compiled
            .admit_count(
                b"axyb",
                0..4,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_ne!(
            admitted.certificate().physical_route,
            OperationPhysicalRoute::StateByteSpanSum
        );

        let benchmark_shape = state_byte_span_sum_fixture(r"Tom.{10,25}river|river.{10,25}Tom");
        let benchmark_plan = benchmark_shape
            .state_byte_span_sum
            .as_ref()
            .expect("target shape should retain the bounded-pair theorem");
        assert_eq!(
            benchmark_plan.topology(),
            StateByteSpanSumTopology::BoundedLiteralPair
        );
        let input_bytes = 16 * 1_048_576;
        let envelope = super::state_byte_reducer_envelope::<true>(
            benchmark_plan,
            input_bytes,
            OperationLimits {
                max_work: 1 << 29,
                ..OperationLimits::default()
            },
        )
        .unwrap();
        assert_eq!(envelope.structural_work_bound, input_bytes * 30);
        assert_eq!(envelope.sequential_bytes_bound, input_bytes * 25);
        assert!(envelope.structural_work_bound <= 1 << 29);
        assert!(envelope.sequential_bytes_bound <= 512 * 1_048_576);
    }

    #[test]
    fn state_byte_span_sum_structural_variants_match_upstream() {
        let cases: [(&str, &[u8]); 9] = [
            (
                r"[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*",
                b"\xffno\npre ABCDEFGHIJKLMNOPQRSTUVWXYZ tail\n\
                  againABCDEFGHIJKLMNOPQRSTUVWXYZ!\nshortABC",
            ),
            (
                r"([ -~]*)(ABCDEFGHIJKLMNOPQRSTUVWXYZ)(.*)",
                b"xxABCDEFGHIJKLMNOPQRSTUVWXYZyy\n---ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ),
            (r"[a-c]*ab[a-z]*", b"ccababzzz\ncabq---abz\xffabab"),
            (
                r"\w+\s+Holmes",
                b"one Holmes two\t \r\nHolmes bad-Holmes x\n\nHolmes \xff z Holmes",
            ),
            (
                r"([0-9A-Za-z_]+)([\t-\r ]+)(Holmes)",
                b"a1\tHolmes -- Z_\r\nHolmes\nHolmes 0 Holmes",
            ),
            (r"[ab]+[ ]+a", b"abba  a b a aba   a\nba a"),
            (
                r"\w+@\w+",
                b"none @bad good@example next@site x@@y left@right_tail",
            ),
            (
                r"[\w.+-]+@[\w.-]+\.[\w.-]+",
                b"a@b.c bad@.x bad@x. bad@.x. fail@x. good@a.b \
                  a+b-c@sub.example.org x@@y.z",
            ),
            (
                r"(.*?,){2}z",
                b"none\n,a,z a,b,z a,b,c,z\nx,y,z\n,,,,z\nx,y,zz",
            ),
        ];
        for (pattern, haystack) in cases {
            let compiled = state_byte_span_sum_fixture(pattern);
            let compile = compiled.compile_accounting();
            assert_eq!(compile.state_byte_span_sum_plans, 1, "{pattern:?}");
            assert!(compile.state_byte_span_sum_build_work > 0);
            assert!(compile.state_byte_span_sum_persistent_bytes > 0);
            let expected = upstream_span_sum(pattern, haystack);
            let attempt = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap_or_else(|error| panic!("{pattern:?}: {error:?}"));
            assert_eq!(attempt.value, expected, "{pattern:?}");
            assert_eq!(
                attempt.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::StateByteSpanSum)
            );
            assert_eq!(attempt.receipt.actual_allocations, 0);
            assert_eq!(attempt.receipt.actual.scratch_peak_bytes, 0);
            assert_eq!(attempt.receipt.actual.random_access_peak_bytes, 0);
            assert!(attempt.receipt.authenticates_success());

            let count = compiled
                .count_value_attempt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_span_sum: 0,
                        ..OperationLimits::default()
                    },
                )
                .unwrap_or_else(|error| panic!("{pattern:?}: {error:?}"));
            assert_eq!(
                count.value,
                upstream_count(pattern, haystack),
                "{pattern:?}"
            );
            assert_eq!(
                count.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::StateByteSpanSum)
            );
            assert_eq!(
                count.receipt.identity.operation,
                OperationAttemptKind::Count
            );
            assert_eq!(count.receipt.prospective.unwrap().span_sum, 0);
            assert_eq!(count.receipt.actual_allocations, 0);
            assert!(count.receipt.authenticates_success());

            // The retained theorem is strategy-specific; full-table
            // operations preserve their established executor.
            assert_eq!(
                compiled
                    .span_sum_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::FullTable,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                expected,
                "{pattern:?}"
            );
        }
    }

    #[test]
    fn state_byte_scalar_value_path_matches_full_counter_path_and_refusals() {
        for (pattern, haystack) in [
            (r"[a-c]*ab[a-z]*", b"ccababzzz\ncabq".as_slice()),
            (r"\w+\s+Holmes", b"alpha Holmes beta".as_slice()),
            (r"\w+@\w+", b"good@example bad@".as_slice()),
            (r"(.*?,){2}z", b"a,b,z\nx,y,no".as_slice()),
        ] {
            let compiled = state_byte_span_sum_fixture(pattern);
            let limits = [
                OperationLimits::default(),
                OperationLimits {
                    max_boundaries: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_sequential_bytes: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_match_events: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_output_matches: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_span_sum: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_work: 0,
                    ..OperationLimits::default()
                },
            ];
            for limits in limits {
                let compact_count = compiled.count_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                );
                let full_count = compiled
                    .count_value_with_counters(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        limits,
                    )
                    .map(|attempt| attempt.value);
                assert_eq!(
                    compact_count, full_count,
                    "count mismatch for {pattern:?}, limits={limits:?}"
                );

                let compact_sum = compiled.span_sum_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                );
                let full_sum = compiled
                    .span_sum_value_with_counters(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        limits,
                    )
                    .map(|attempt| attempt.value);
                assert_eq!(
                    compact_sum, full_sum,
                    "span-sum mismatch for {pattern:?}, limits={limits:?}"
                );
            }
        }
    }

    #[test]
    fn state_byte_redundant_stars_and_large_literal_anchor_match_upstream() {
        for pattern in [r".*.*=.*", r"[ -~]*[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ.*"] {
            let compiled = state_byte_span_sum_fixture(pattern);
            assert_eq!(
                compiled
                    .state_byte_span_sum
                    .as_ref()
                    .map(StateByteSpanSumPlan::topology),
                Some(StateByteSpanSumTopology::GreedyPrefixLiteralSuffix),
                "{pattern:?}"
            );
            for length in [255_usize, 256, 4096] {
                let mut haystack = vec![b'x'; length];
                if pattern == r".*.*=.*" {
                    haystack[length / 3] = b'=';
                    haystack[(length * 2) / 3] = b'\n';
                    haystack[length - 2] = b'=';
                } else {
                    let literal = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let offset = length / 2;
                    haystack[offset..offset + literal.len()].copy_from_slice(literal);
                    haystack[offset - 3] = b'\t';
                    haystack[length - 2] = b'\n';
                }
                let sum = compiled
                    .span_sum_value_with_receipt(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap_or_else(|error| panic!("{pattern:?}, {length}: {error:?}"));
                assert_eq!(
                    sum.value,
                    upstream_span_sum(pattern, &haystack),
                    "{pattern:?}, {length}"
                );
                assert_eq!(
                    sum.receipt.identity.physical_route,
                    Some(OperationPhysicalRoute::StateByteSpanSum)
                );
                assert!(sum.receipt.authenticates_success());
                assert_eq!(
                    compiled
                        .span_sum_value(
                            &haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits::default(),
                        )
                        .unwrap(),
                    sum.value,
                    "compact value mismatch for {pattern:?}, {length}"
                );
                let count = compiled
                    .count_value_attempt(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits {
                            max_span_sum: 0,
                            ..OperationLimits::default()
                        },
                    )
                    .unwrap_or_else(|error| panic!("{pattern:?}, {length}: {error:?}"));
                assert_eq!(
                    count.value,
                    upstream_count(pattern, &haystack),
                    "{pattern:?}, {length}"
                );
                assert!(count.receipt.authenticates_success());
                assert_eq!(
                    compiled
                        .count_value(
                            &haystack,
                            0..haystack.len(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits {
                                max_span_sum: 0,
                                ..OperationLimits::default()
                            },
                        )
                        .unwrap(),
                    count.value,
                    "compact count mismatch for {pattern:?}, {length}"
                );
            }
        }

        let near_miss = state_byte_span_sum_fixture(r"[ab]*[bc]*a[abc]*");
        assert!(near_miss.state_byte_span_sum.is_none());
    }

    #[test]
    fn state_byte_span_sum_exhaustive_small_differential() {
        let cases: [(&str, &[u8]); 11] = [
            (r"[ab]*ab[abc]*", b"abc\n"),
            (r"[ab]*abab[abc]*", b"abc\n"),
            (r"[^\n]*[^\n]*=[^\n]*", b"=\nxy"),
            (r"[^ab]*[^ab]*c[^a]*", b"abcx"),
            (r"[^abc]*[^abc]*d[^ab]*", b"abcd"),
            (r"[^abcd]*[^abcd]*e[^abc]*", b"abde"),
            (r"[ab]+[ ]+a", b"ab \n"),
            (r"[a]+[b]+aba", b"abx\n"),
            (r"[ab]+@[ab]+", b"ab@\n"),
            (r"[a]+@[a.]+\.[a.]+", b"a@.!"),
            (r"(?:.*?,){2}z", b",z\nx"),
        ];
        for (pattern, alphabet) in cases {
            let compiled = state_byte_span_sum_fixture(pattern);
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let mut haystack = Vec::new();
            for encoded in 0_u32..16_384 {
                haystack.clear();
                let mut value = encoded;
                for _ in 0..7 {
                    haystack.push(alphabet[usize::try_from(value & 3).unwrap()]);
                    value >>= 2;
                }
                let expected: usize = oracle
                    .find_iter(&haystack)
                    .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
                    .sum();
                let actual = compiled
                    .span_sum_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(actual, expected, "{pattern:?}, haystack={haystack:?}");
                let expected_count = oracle.find_iter(&haystack).count();
                let actual_count = compiled
                    .count_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits {
                            max_span_sum: 0,
                            ..OperationLimits::default()
                        },
                    )
                    .unwrap();
                assert_eq!(
                    actual_count, expected_count,
                    "{pattern:?}, count haystack={haystack:?}"
                );
                let ranged_expected: usize = oracle
                    .find_iter(&haystack[1..6])
                    .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
                    .sum();
                let ranged_actual = compiled
                    .span_sum_value(
                        &haystack,
                        1..6,
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    ranged_actual, ranged_expected,
                    "{pattern:?}, range haystack={haystack:?}"
                );
                let ranged_expected_count = oracle.find_iter(&haystack[1..6]).count();
                let ranged_actual_count = compiled
                    .count_value(
                        &haystack,
                        1..6,
                        Strategy::ReverseSequentialRows,
                        OperationLimits {
                            max_span_sum: 0,
                            ..OperationLimits::default()
                        },
                    )
                    .unwrap();
                assert_eq!(
                    ranged_actual_count, ranged_expected_count,
                    "{pattern:?}, range count haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn repeated_lazy_delimiter_rejects_an_absent_suffix_with_one_literal_scan() {
        let pattern = r"(?:.*?,){13}z";
        let haystack = vec![b','; 16_384];
        let compiled = state_byte_span_sum_fixture(pattern);
        assert_eq!(
            compiled
                .state_byte_span_sum
                .as_ref()
                .map(StateByteSpanSumPlan::topology),
            Some(StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix)
        );
        let result = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(result.value, 0);
        assert_eq!(result.receipt.actual.work, haystack.len());
        assert_eq!(result.receipt.actual.sequential_bytes_read, haystack.len());
        assert_eq!(result.receipt.actual.random_access_bytes_read, 0);
        assert_eq!(result.receipt.actual.root_probes, haystack.len());
        assert!(result.receipt.authenticates_success());
    }

    #[test]
    fn state_byte_greedy_boundary_classifier_matches_scalar_for_every_byte() {
        let excluded_cases: &[&[u8]] = &[&[], &[0], &[0, 127], &[0, 127, 255], &[0, 64, 128, 255]];
        let source = (u8::MIN..=u8::MAX)
            .rev()
            .chain(u8::MIN..=u8::MAX)
            .collect::<Vec<_>>();
        for &excluded in excluded_cases {
            let mut class = crate::program::ByteSet([u64::MAX; 4]);
            for &byte in excluded {
                let word = usize::from(byte) / 64;
                let bit = usize::from(byte) % 64;
                class.0[word] &= !(1_u64 << bit);
            }
            let classifier = StateByteClassBoundary::new(class);
            assert_eq!(
                matches!(classifier, StateByteClassBoundary::Native { .. }),
                excluded.len() <= 3,
                "excluded={excluded:?}"
            );
            for start in 0..=source.len() {
                let suffix = &source[start..];
                let expected_first = suffix
                    .iter()
                    .position(|&byte| !class.contains(byte))
                    .unwrap_or(suffix.len());
                let expected_last = suffix
                    .iter()
                    .rposition(|&byte| !class.contains(byte))
                    .map_or(0, |index| index + 1);
                assert_eq!(
                    classifier.first_nonmember_or_len(suffix),
                    expected_first,
                    "forward excluded={excluded:?}, start={start}"
                );
                assert_eq!(
                    classifier.start_after_last_nonmember(suffix),
                    expected_last,
                    "reverse excluded={excluded:?}, start={start}"
                );
            }
        }
    }

    #[test]
    fn state_byte_greedy_value_native_boundaries_match_adversarial_runs() {
        let mut haystack = vec![b'x'; 32 * 1024];
        for index in (31..haystack.len()).step_by(251) {
            haystack[index] = b'\n';
        }
        for index in (47..haystack.len()).step_by(379) {
            haystack[index] = if index % 2 == 0 { 0 } else { 0xff };
        }
        for index in (73..haystack.len() - 6).step_by(521) {
            haystack[index..index + 6].copy_from_slice(b"ababab");
        }
        for index in (101..haystack.len()).step_by(613) {
            haystack[index] = b'c';
        }
        for index in (149..haystack.len() - 4).step_by(887) {
            haystack[index..index + 4].copy_from_slice(b"efgh");
        }
        for index in (181..haystack.len()).step_by(997) {
            haystack[index] = b'd';
        }

        for pattern in [
            r".*.*abab.*",
            r"[^ab]*[^ab]*c[^a]*",
            r"[^abcd]*[^abcd]*efgh[^abc]*",
        ] {
            let compiled = state_byte_span_sum_fixture(pattern);
            assert_eq!(
                compiled
                    .state_byte_span_sum
                    .as_ref()
                    .map(StateByteSpanSumPlan::topology),
                Some(StateByteSpanSumTopology::GreedyPrefixLiteralSuffix),
                "{pattern:?}"
            );
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for range in [
                0..haystack.len(),
                13..haystack.len() - 17,
                250..8_193,
                8_191..16_385,
            ] {
                let local = &haystack[range.clone()];
                let expected_sum = oracle
                    .find_iter(local)
                    .map(|matched| matched.end() - matched.start())
                    .sum::<usize>();
                let expected_count = oracle.find_iter(local).count();
                let compact_sum = compiled
                    .span_sum_value(
                        &haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                let diagnostic_sum = compiled
                    .span_sum_value_with_counters(
                        &haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap()
                    .value;
                assert_eq!(
                    (compact_sum, diagnostic_sum),
                    (expected_sum, expected_sum),
                    "{pattern:?}, range={range:?}"
                );
                let count_limits = OperationLimits {
                    max_span_sum: 0,
                    ..OperationLimits::default()
                };
                let compact_count = compiled
                    .count_value(
                        &haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        count_limits,
                    )
                    .unwrap();
                let diagnostic_count = compiled
                    .count_value_with_counters(
                        &haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        count_limits,
                    )
                    .unwrap()
                    .value;
                assert_eq!(
                    (compact_count, diagnostic_count),
                    (expected_count, expected_count),
                    "{pattern:?}, count range={range:?}"
                );
            }
        }
    }

    #[test]
    fn state_byte_repeated_delimiter_dense_and_sparse_differential() {
        for pattern in [
            r"(?:.*?,){2}z",
            r"(?:.*?,){13}z",
            r"(?:.*?;){3}q",
            r"(?:.*?,){2},x",
            r"(?:.*?,){2}\nz",
        ] {
            let compiled = state_byte_span_sum_fixture(pattern);
            assert_eq!(
                compiled
                    .state_byte_span_sum
                    .as_ref()
                    .map(StateByteSpanSumPlan::topology),
                Some(StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix),
                "{pattern:?}"
            );
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let mut seed = 0x243f_6a88_u32;
            let mut haystack = Vec::new();
            for case in 0..384_usize {
                haystack.clear();
                let length = (case * 67 + 31) % 320;
                for index in 0..length {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    let byte = match (seed ^ u32::try_from(index).unwrap()) % 16 {
                        0..=5 => b',',
                        6..=7 => b';',
                        8 => b'\n',
                        9 => b'z',
                        10 => b'x',
                        11 => b'q',
                        _ => b'a' + u8::try_from(seed % 26).unwrap(),
                    };
                    haystack.push(byte);
                }
                let start = if haystack.is_empty() {
                    0
                } else {
                    case % (haystack.len() + 1)
                };
                let available = haystack.len() - start;
                let end = start + (case.wrapping_mul(29) % (available + 1));
                for range in [0..haystack.len(), start..end] {
                    let local = &haystack[range.clone()];
                    let expected_sum: usize = oracle
                        .find_iter(local)
                        .map(|matched| matched.end() - matched.start())
                        .sum();
                    let expected_count = oracle.find_iter(local).count();
                    assert_eq!(
                        compiled
                            .span_sum_value(
                                &haystack,
                                range.clone(),
                                Strategy::ReverseSequentialRows,
                                OperationLimits::default(),
                            )
                            .unwrap(),
                        expected_sum,
                        "{pattern:?}, case={case}, range={range:?}, haystack={haystack:?}"
                    );
                    assert_eq!(
                        compiled
                            .count_value(
                                &haystack,
                                range.clone(),
                                Strategy::ReverseSequentialRows,
                                OperationLimits {
                                    max_span_sum: 0,
                                    ..OperationLimits::default()
                                },
                            )
                            .unwrap(),
                        expected_count,
                        "{pattern:?}, case={case}, range={range:?}, haystack={haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one audit keeps compile and operation exact-limit checks adjacent for every topology"
    )]
    fn state_byte_internal_runs_retain_exact_routes_and_close_one_below() {
        for (pattern, topology, haystack) in [
            (
                r"\w+@\w+",
                StateByteSpanSumTopology::DisjointInternalRuns,
                b"none @bad good@example next@site x@@y".as_slice(),
            ),
            (
                r"[\w.+-]+@[\w.-]+\.[\w.-]+",
                StateByteSpanSumTopology::DisjointInternalRunsCheckpoint,
                b"a@b.c bad@.x bad@x. a+b-c@sub.example.org".as_slice(),
            ),
            (
                r"(?:.*?,){2}z",
                StateByteSpanSumTopology::RepeatedLazyDelimiterSuffix,
                b"none\n,a,z a,b,z a,b,c,z\nx,y,z\n,,,,z\nx,y,zz".as_slice(),
            ),
        ] {
            let compiled = state_byte_span_sum_fixture(pattern);
            assert_eq!(
                compiled.state_byte_span_sum.as_ref().unwrap().topology(),
                topology
            );
            let compile = compiled.compile_accounting();
            let exact_compile_limits = CompileLimits {
                max_program_bytes: compile.program_bytes,
                max_work: compile.work,
                ..CompileLimits::default()
            };
            assert_eq!(
                state_byte_span_sum_fixture_with_limits(pattern, exact_compile_limits)
                    .unwrap()
                    .state_byte_span_sum
                    .as_ref()
                    .unwrap()
                    .topology(),
                topology
            );
            assert!(matches!(
                state_byte_span_sum_fixture_with_limits(
                    pattern,
                    CompileLimits {
                        max_work: compile.work - 1,
                        ..exact_compile_limits
                    },
                ),
                Err(Error::ResourceLimit {
                    resource: Resource::CompileWork,
                    ..
                })
            ));
            let baseline = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(baseline.value, upstream_span_sum(pattern, haystack));
            assert_eq!(baseline.receipt.actual_allocations, 0);
            let prospective = baseline.receipt.prospective.unwrap();
            assert!(prospective.contains(baseline.receipt.actual));
            let exact_limits = OperationLimits {
                max_work: baseline.receipt.actual.work,
                ..exact_state_byte_limits(&prospective)
            };
            let exact = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    exact_limits,
                )
                .unwrap();
            assert_eq!(exact.value, baseline.value);
            assert_eq!(exact.receipt.actual, baseline.receipt.actual);
            assert!(exact.receipt.authenticates_success());

            let one_below = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits {
                        max_work: baseline.receipt.actual.work - 1,
                        ..exact_limits
                    },
                )
                .unwrap_err();
            assert!(matches!(
                one_below.source,
                Error::ResourceLimit {
                    resource: Resource::ExecutionWork,
                    ..
                }
            ));
            assert_eq!(one_below.receipt.actual_allocations, 0);
            assert!(
                one_below
                    .receipt
                    .prospective
                    .unwrap()
                    .contains(one_below.receipt.actual)
            );
            assert!(one_below.closes());
        }
    }

    fn assert_state_byte_exact_case(
        pattern: &str,
        haystack: &[u8],
        expected: &ExecutionAccounting,
        expected_span_sum: usize,
    ) {
        let compiled = state_byte_span_sum_fixture(pattern);
        let baseline = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{pattern:?}, {haystack:?}: {error:?}"));
        assert_eq!(
            baseline.value, expected_span_sum,
            "{pattern:?}, {haystack:?}"
        );
        assert_eq!(
            baseline.receipt.actual, *expected,
            "{pattern:?}, {haystack:?}"
        );
        let structural = baseline.receipt.prospective.unwrap();
        assert!(structural.contains(*expected));

        let exact_limits = OperationLimits {
            max_work: expected.work,
            ..exact_state_byte_limits(&structural)
        };
        let exact = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact_limits,
            )
            .unwrap_or_else(|error| panic!("{pattern:?}, {haystack:?}: {error:?}"));
        let exact_prospective = exact.receipt.prospective.unwrap();
        assert_eq!(exact.value, expected_span_sum);
        assert_eq!(exact.receipt.actual, *expected);
        assert_eq!(exact_prospective.work_bound, expected.work);
        assert_eq!(exact_prospective.accounting.work, expected.work);
        assert!(exact_prospective.contains(*expected));
        assert!(exact.receipt.authenticates_success());

        let one_below_limit = expected.work.checked_sub(1).unwrap();
        let one_below = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: one_below_limit,
                    ..exact_limits
                },
            )
            .unwrap_err();
        assert_eq!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: expected.work,
                limit: one_below_limit,
            },
            "{pattern:?}, {haystack:?}"
        );
        let one_below_prospective = one_below.receipt.prospective.unwrap();
        assert_eq!(one_below_prospective.work_bound, one_below_limit);
        assert_eq!(one_below_prospective.accounting.work, one_below_limit);
        assert!(one_below.receipt.actual.work <= one_below_limit);
        assert!(one_below.receipt.actual.work > 0);
        assert!(one_below_prospective.contains(one_below.receipt.actual));
        assert_eq!(one_below.receipt.actual_allocations, 0);
        assert_eq!(
            one_below.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StateByteSpanSum)
        );
        assert_eq!(
            one_below.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::None
        );
        assert!(one_below.closes());
    }

    #[test]
    fn state_byte_span_sum_exact_kmp_accounting_and_one_below_are_adversarial() {
        assert_eq!(
            state_byte_span_sum_fixture(r"[ab]*abab[a-z]*")
                .state_byte_span_sum
                .as_ref()
                .unwrap()
                .literal_failure(),
            &[0, 0, 1, 2]
        );
        assert_eq!(
            state_byte_span_sum_fixture(r"[ab]*aaaa[a-z]*")
                .state_byte_span_sum
                .as_ref()
                .unwrap()
                .literal_failure(),
            &[0, 1, 2, 3]
        );
        for (pattern, haystack, state, sequential, random, root, events, work, span_sum) in [
            (r"[a-c]*ab[a-z]*", b"c!".as_slice(), 3, 2, 1, 1, 0, 7, 0),
            (r"[a-c]*ab[a-z]*", b"ab!".as_slice(), 5, 3, 2, 2, 1, 13, 2),
            (r"[a-c]*ab[a-z]*", b"ccab!".as_slice(), 9, 5, 4, 4, 1, 23, 4),
            (r"[a-c]*ab[a-z]*", b"cccc!".as_slice(), 9, 5, 4, 4, 0, 22, 0),
            (
                r"[ab]*abab[a-z]*",
                b"aabab!".as_slice(),
                11,
                6,
                5,
                6,
                1,
                29,
                5,
            ),
            (
                r"[a-c]*ab[a-z]*",
                b"cxxabq!".as_slice(),
                12,
                7,
                5,
                3,
                1,
                28,
                3,
            ),
            (
                r"[ab]*aaaa[a-z]*",
                b"aaabaaaa!".as_slice(),
                17,
                9,
                8,
                11,
                1,
                46,
                8,
            ),
        ] {
            assert_state_byte_exact_case(
                pattern,
                haystack,
                &ExecutionAccounting {
                    state_evaluations: state,
                    transition_checks: state,
                    root_probes: root,
                    successful_paths: events,
                    emitted_matches: events,
                    sequential_bytes_read: sequential,
                    random_access_bytes_read: random,
                    work,
                    ..ExecutionAccounting::default()
                },
                span_sum,
            );
        }
    }

    #[test]
    fn state_byte_span_sum_disjoint_accounting_caches_literal_head_and_orders_source() {
        assert_eq!(
            state_byte_span_sum_fixture(r"[ax]+[ ]+aaaaab")
                .state_byte_span_sum
                .as_ref()
                .unwrap()
                .literal_anchor_offset(),
            5
        );
        let overlap = state_byte_span_sum_fixture(r"[a]+[b]+aba");
        assert_eq!(
            overlap
                .state_byte_span_sum
                .as_ref()
                .unwrap()
                .literal_anchor_offset(),
            1
        );
        assert_eq!(
            overlap
                .span_sum_value(
                    b"bababa",
                    0..6,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            5
        );
        assert_eq!(
            overlap
                .count_value(
                    b"bababa",
                    0..6,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            1
        );
        for (haystack, state, sequential, random, root, events, work, span_sum) in [
            (b"ab  a".as_slice(), 6, 3, 3, 1, 1, 14, 5),
            (b"abx".as_slice(), 4, 3, 1, 0, 0, 8, 0),
        ] {
            assert_state_byte_exact_case(
                r"[ab]+[ ]+a",
                haystack,
                &ExecutionAccounting {
                    state_evaluations: state,
                    transition_checks: state,
                    root_probes: root,
                    successful_paths: events,
                    emitted_matches: events,
                    sequential_bytes_read: sequential,
                    random_access_bytes_read: random,
                    work,
                    ..ExecutionAccounting::default()
                },
                span_sum,
            );
        }

        let compiled = state_byte_span_sum_fixture(r"[ab]+[ ]+abc");
        let haystack = b"ab  abc";
        let refusal = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: 13,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: 15,
                limit: 13,
            }
        );
        assert_eq!(refusal.receipt.actual.work, 13);
        assert_eq!(refusal.receipt.actual.root_probes, 11);
        assert_eq!(refusal.receipt.actual.random_access_bytes_read, 5);
        assert_eq!(refusal.receipt.actual.sequential_bytes_read, 5);
        assert!(
            refusal
                .receipt
                .prospective
                .unwrap()
                .contains(refusal.receipt.actual)
        );
        assert!(refusal.closes());
    }

    #[test]
    fn state_byte_span_sum_refuses_inexact_topologies() {
        for pattern in [
            r"[a-c]*ab[a-z]*?",
            r"[a-c]*az[a-z]*",
            r"[a-c]+[b-d]+a",
            r"[a-c]+[ ]*a",
            r"\A[a-c]+[ ]+a",
            r"(?:[a-c]*ab[a-z]*)|x",
            r"[a-c]{1,3}[ ]+a",
            r"[a@]+@[ab]+",
            r"[ab]+@@[ab]+",
            r"[ab]+@[ab]+?",
            r"[ab]+@[ab.]+\.[ac.]+",
            r"[ab]+@[ab]+\.[ab]+",
            r"(?:.*,){2}z",
            r"(?:.*?,){2,3}z",
            r"(?:[^,\n]*?,){2}z",
            r"(?:.*?,){2}",
        ] {
            let compiled = state_byte_span_sum_fixture(pattern);
            assert_eq!(
                compiled.compile_accounting().state_byte_span_sum_plans,
                0,
                "{pattern:?}"
            );
        }
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(r"\w+\s+Holmes")
            .unwrap();
        let unicode = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(unicode.compile_accounting().state_byte_span_sum_plans, 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one receipt audit keeps each selected route's value, counters, refusal, and sealing check together"
    )]
    fn value_only_counter_receipts_are_sealed_after_the_selected_route_finishes() {
        let pattern = r"(?:a+b|a)";
        let haystack = b"aaaabaaaa";
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();

        let hot_value = compiled
            .count_value(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let hot_counters = compiled
            .count_value_with_counters(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(hot_counters.value, hot_value);
        assert!(hot_counters.receipt.closes());
        assert_eq!(
            hot_counters.receipt.certificate.operation,
            OperationAttemptKind::Count
        );
        assert_eq!(
            hot_counters.receipt.counters.output_events,
            hot_counters.receipt.accounting.emitted_matches
        );
        let attempt = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(attempt.value, hot_value);
        assert!(attempt.receipt.authenticates_success());
        assert_eq!(
            hot_counters.receipt.certificate.physical_route,
            attempt.receipt.identity.physical_route.unwrap()
        );

        let receipt = attempt.into_counter_receipt().unwrap();
        assert!(receipt.closes());
        assert_eq!(
            receipt.value,
            super::OperationCounterValue::Count(hot_value)
        );
        assert_eq!(receipt.counters.selector_invocations, 1);
        assert_eq!(
            receipt.counters.state_transitions,
            receipt.attempt.actual.transition_checks
        );
        assert_eq!(
            receipt.counters.output_events,
            receipt.attempt.actual.emitted_matches
        );
        assert_eq!(
            receipt.counters.allocations,
            receipt.attempt.actual_allocations
        );

        let mut forged = receipt.clone();
        forged.counters.output_events = forged.counters.output_events.saturating_add(1);
        assert!(!forged.closes());
        let mut relabeled = receipt;
        relabeled.value = super::OperationCounterValue::SpanSum(hot_value);
        assert!(!relabeled.closes());

        let mut forged_attempt = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        forged_attempt.value = forged_attempt.value.saturating_add(1);
        assert!(forged_attempt.into_counter_receipt().is_err());

        // StateByteSpanSum retains its prospective range-length bound in the
        // ordinary certificate. A no-match value must still be sealed and
        // admitted: the receipt checks the actual result against that bound,
        // rather than incorrectly requiring equality with it.
        let span_compiled = state_byte_span_sum_fixture(r"\w+\s+Holmes");
        let span_haystack = b"no witness here";
        let plain_span_sum = span_compiled
            .span_sum_value(
                span_haystack,
                0..span_haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(plain_span_sum, 0);
        let hot_span_sum = span_compiled
            .span_sum_value_with_counters(
                span_haystack,
                0..span_haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(hot_span_sum.value, plain_span_sum);
        assert!(hot_span_sum.receipt.closes());
        assert!(hot_span_sum.value < hot_span_sum.receipt.certificate.span_sum);

        let span_attempt = span_compiled
            .span_sum_value_with_receipt(
                span_haystack,
                0..span_haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert!(span_attempt.into_counter_receipt().unwrap().closes());
        let mut forged_span_attempt = span_compiled
            .span_sum_value_with_receipt(
                span_haystack,
                0..span_haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        forged_span_attempt.value = forged_span_attempt.value.saturating_add(1);
        assert!(forged_span_attempt.into_counter_receipt().is_err());
    }

    #[test]
    fn counter_projection_preserves_exact_observed_work_admission_and_one_below_refusal() {
        let haystack = b"alpha Holmes beta\r\nHolmes gamma\tHolmes";
        let compiled = state_byte_span_sum_fixture(r"\w+\s+Holmes");
        let baseline = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline.receipt.prospective.unwrap();
        let exact_limits = OperationLimits {
            max_work: baseline.receipt.actual.work,
            ..exact_state_byte_limits(&prospective)
        };
        let projected = compiled
            .span_sum_value_with_counters(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact_limits,
            )
            .unwrap();
        assert_eq!(projected.value, baseline.value);
        assert!(projected.receipt.closes());
        assert_eq!(projected.receipt.accounting, baseline.receipt.actual);

        let one_below = compiled
            .span_sum_value_with_counters(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: baseline.receipt.actual.work - 1,
                    ..exact_limits
                },
            )
            .unwrap_err();
        assert!(matches!(
            one_below,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            }
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the single audit test checks every positive prospective dimension and both compile ceilings"
    )]
    fn state_byte_span_sum_exact_limits_and_one_below_refuse_before_source() {
        let pattern = r"\w+\s+Holmes";
        let haystack = b"alpha Holmes beta\r\nHolmes gamma\tHolmes";
        let compiled = state_byte_span_sum_fixture(pattern);
        let baseline = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline.receipt.prospective.unwrap();
        let exact = exact_state_byte_limits(&prospective);
        let exact_attempt = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_attempt.value, upstream_span_sum(pattern, haystack));
        assert!(exact_attempt.receipt.authenticates_success());
        for (resource, lower) in [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: prospective.boundaries - 1,
                    ..exact
                },
            ),
            (
                Resource::SequentialBytes,
                OperationLimits {
                    max_sequential_bytes: prospective.sequential_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: prospective.match_events - 1,
                    ..exact
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: prospective.output_matches - 1,
                    ..exact
                },
            ),
            (
                Resource::SpanSum,
                OperationLimits {
                    max_span_sum: prospective.span_sum - 1,
                    ..exact
                },
            ),
        ] {
            let failure = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    lower,
                )
                .unwrap_err();
            assert!(matches!(
                &failure.source,
                Error::ResourceLimit {
                    resource: got,
                    ..
                } if *got == resource
            ));
            assert!(failure.closes());
            assert_eq!(
                failure.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::StateByteSpanSum)
            );
            assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
            assert_eq!(failure.receipt.actual_allocations, 0);
            assert!(failure.receipt.prospective.is_some());
        }

        let actual_work = baseline.receipt.actual.work;
        let observed_exact_limits = OperationLimits {
            max_work: actual_work,
            ..exact
        };
        let observed_exact = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                observed_exact_limits,
            )
            .unwrap();
        assert_eq!(
            observed_exact.receipt.prospective.unwrap().work_bound,
            actual_work
        );
        assert_eq!(observed_exact.receipt.actual, baseline.receipt.actual);
        let observed_one_below = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: actual_work - 1,
                    ..observed_exact_limits
                },
            )
            .unwrap_err();
        assert!(matches!(
            observed_one_below.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            }
        ));
        let observed_one_below_prospective = observed_one_below.receipt.prospective.unwrap();
        assert_eq!(observed_one_below_prospective.work_bound, actual_work - 1);
        assert!(observed_one_below.receipt.actual.work > 0);
        assert!(observed_one_below_prospective.contains(observed_one_below.receipt.actual));
        assert!(observed_one_below.closes());

        let conservative = compiled
            .admit_span_sum_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let conservative_prospective = conservative.receipt.prospective.unwrap();
        let conservative_refusal = compiled
            .admit_span_sum_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_work: conservative_prospective.work_bound - 1,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            conservative_refusal.source,
            Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: conservative_prospective.work_bound,
                limit: conservative_prospective.work_bound - 1,
            }
        );
        assert_eq!(
            conservative_refusal.receipt.actual,
            ExecutionAccounting::default()
        );
        assert!(conservative_refusal.closes());

        let compile = compiled.compile_accounting();
        let exact_compile = CompileLimits {
            max_program_bytes: compile.program_bytes,
            max_work: compile.work,
            ..CompileLimits::default()
        };
        state_byte_span_sum_fixture_with_limits(pattern, exact_compile).unwrap();
        assert!(matches!(
            state_byte_span_sum_fixture_with_limits(
                pattern,
                CompileLimits {
                    max_program_bytes: compile.program_bytes - 1,
                    ..exact_compile
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert!(matches!(
            state_byte_span_sum_fixture_with_limits(
                pattern,
                CompileLimits {
                    max_work: compile.work - 1,
                    ..exact_compile
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
    }

    #[test]
    fn state_byte_span_sum_publishes_observed_prospective_before_source() {
        let compiled = state_byte_span_sum_fixture(r"[a-c]*ab[a-z]*");
        let haystack = b"ccab!";
        let limits = OperationLimits {
            max_work: 23,
            ..OperationLimits::default()
        };
        let mut published_prospective = None;
        let refusal = {
            let mut publish_observer = |prospective| {
                published_prospective = Some(prospective);
                Err(Error::InternalInvariant(
                    "state-byte prospective observer sentinel",
                ))
            };
            match compiled.execute_with_receipt::<true>(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationKind::Sum,
                None,
                limits,
                usize::MAX,
                Some(&mut publish_observer),
            ) {
                Err(error) => error,
                Ok(_) => panic!("prospective observer sentinel must terminate the attempt"),
            }
        };
        let prospective = published_prospective.expect("observer receives published prospective");
        assert_eq!(prospective.work_bound, 23);
        assert_eq!(prospective.accounting.work, 23);
        assert_eq!(refusal.receipt.prospective, Some(prospective));
        assert_eq!(
            refusal.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StateByteSpanSum)
        );
        assert_eq!(
            refusal.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::None
        );
        assert_eq!(refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(refusal.receipt.actual_allocations, 0);
        assert!(prospective.contains(refusal.receipt.actual));
        assert!(refusal.closes());
    }

    #[test]
    fn root_assertion_route_matches_dense_rows_for_every_assertion_and_range() {
        let cases = [
            (r"\A", false),
            (r"\z", false),
            (r"(?m:^)", false),
            (r"(?m:$)", false),
            (r"(?Rm:^)", false),
            (r"(?Rm:$)", false),
            (r"\b", false),
            (r"\B", false),
            (r"\b{start}", false),
            (r"\b{end}", false),
            (r"\b{start-half}", false),
            (r"\b{end-half}", false),
            (r"\b", true),
            (r"\B", true),
            (r"\b{start}", true),
            (r"\b{end}", true),
            (r"\b{start-half}", true),
            (r"\b{end-half}", true),
        ];
        for (pattern, unicode) in cases {
            let compiled = root_assertion_fixture(pattern, unicode);
            assert!(
                compiled.program.root_assertion().is_some(),
                "missing retained root assertion for {pattern:?}, unicode={unicode}"
            );
            let haystack: &[u8] = if unicode {
                "aé_ β\r\n".as_bytes()
            } else {
                b"a_ z\r\n"
            };
            let mut ranges = vec![0..haystack.len(), 0..0, haystack.len()..haystack.len()];
            if haystack.len() > 2 {
                ranges.push(1..haystack.len() - 1);
                ranges.push(2..haystack.len());
            }
            for range in ranges {
                let dense_count = compiled
                    .count_value(
                        haystack,
                        range.clone(),
                        Strategy::FullTable,
                        OperationLimits::default(),
                    )
                    .unwrap();
                let direct_count = compiled
                    .count_value(
                        haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    direct_count, dense_count,
                    "count mismatch for {pattern:?}, unicode={unicode}, range={range:?}"
                );
                let dense_sum = compiled
                    .span_sum_value(
                        haystack,
                        range.clone(),
                        Strategy::FullTable,
                        OperationLimits::default(),
                    )
                    .unwrap();
                let direct_sum = compiled
                    .span_sum_value(
                        haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(direct_sum, 0);
                assert_eq!(
                    direct_sum, dense_sum,
                    "span-sum mismatch for {pattern:?}, unicode={unicode}, range={range:?}"
                );
            }

            let reference = RegexBuilder::new(pattern).unicode(unicode).build().unwrap();
            let expected = reference.find_iter(haystack).count();
            assert_eq!(
                compiled
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                expected,
                "regex oracle mismatch for {pattern:?}, unicode={unicode}"
            );
        }
    }

    #[test]
    fn root_assertion_scalar_value_path_matches_full_counter_path_and_refusals() {
        for (pattern, unicode, haystack) in [
            (r"\A", false, b"a_ z\r\n".as_slice()),
            (r"(?Rm:$)", false, b"a_ z\r\n".as_slice()),
            (r"\b", false, b"a_ z\r\n".as_slice()),
            (r"\b", true, "aé_ β\r\n".as_bytes()),
        ] {
            let compiled = root_assertion_fixture(pattern, unicode);
            let range = 1..haystack.len().saturating_sub(1);
            let limits = [
                OperationLimits::default(),
                OperationLimits {
                    max_boundaries: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_random_access_bytes: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_sequential_bytes: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_match_events: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_output_matches: 0,
                    ..OperationLimits::default()
                },
                OperationLimits {
                    max_work: 0,
                    ..OperationLimits::default()
                },
            ];
            for limits in limits {
                let compact_count = compiled.count_value(
                    haystack,
                    range.clone(),
                    Strategy::ReverseSequentialRows,
                    limits,
                );
                let full_count = compiled
                    .count_value_with_counters(
                        haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        limits,
                    )
                    .map(|attempt| attempt.value);
                assert_eq!(
                    compact_count, full_count,
                    "count mismatch for {pattern:?}, unicode={unicode}, limits={limits:?}"
                );

                let compact_sum = compiled.span_sum_value(
                    haystack,
                    range.clone(),
                    Strategy::ReverseSequentialRows,
                    limits,
                );
                let full_sum = compiled
                    .span_sum_value_with_counters(
                        haystack,
                        range.clone(),
                        Strategy::ReverseSequentialRows,
                        limits,
                    )
                    .map(|attempt| attempt.value);
                assert_eq!(
                    compact_sum, full_sum,
                    "span-sum mismatch for {pattern:?}, unicode={unicode}, limits={limits:?}"
                );
            }
        }

        let unicode = root_assertion_fixture(r"\b", true);
        for limits in [
            OperationLimits::default(),
            OperationLimits {
                max_boundaries: 0,
                ..OperationLimits::default()
            },
            OperationLimits {
                max_sequential_bytes: 0,
                ..OperationLimits::default()
            },
        ] {
            let haystack = b"\xFFa";
            let compact =
                unicode.count_value(haystack, 1..2, Strategy::ReverseSequentialRows, limits);
            let full = unicode
                .count_value_with_counters(haystack, 1..2, Strategy::ReverseSequentialRows, limits)
                .map(|attempt| attempt.value);
            assert_eq!(compact, full, "malformed UTF-8 precedence diverged");
        }
    }

    #[test]
    fn root_assertion_route_seals_identity_accounting_and_one_below_limits() {
        let compiled = root_assertion_fixture(r"\b", true);
        let haystack = "aé_ β".as_bytes();
        let count = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert!(count.receipt.authenticates_success());
        assert_eq!(
            count.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RootAssertion)
        );
        assert_eq!(
            count.receipt.identity.algorithm_version,
            CONTINUATION_OPERATION_ALGORITHM_VERSION
        );
        assert_eq!(
            count.receipt.identity.accounting_version,
            CONTINUATION_OPERATION_ACCOUNTING_VERSION
        );
        let mut legacy_algorithm = count.receipt.clone();
        legacy_algorithm.identity.algorithm_version = 3;
        assert_ne!(legacy_algorithm.identity, count.receipt.identity);
        assert!(!legacy_algorithm.authenticates_canonical());
        assert!(!legacy_algorithm.authenticates_success());
        let prospective = count.receipt.prospective.unwrap();
        assert!(prospective.contains(count.receipt.actual));
        assert_eq!(count.receipt.actual_allocations, 0);
        assert_eq!(prospective.allocations, 0);
        assert_eq!(count.value, count.receipt.actual.emitted_matches);
        assert!(count.receipt.actual.assertion_checks > 0);
        assert_eq!(
            count.receipt.actual.assertion_checks,
            count.receipt.actual.root_probes
        );
        assert_eq!(
            count.receipt.actual.work,
            count.receipt.actual.utf8_validation_work
                + count.receipt.actual.transition_checks
                + count.receipt.actual.root_probes
                + count.receipt.actual.successful_paths
        );

        let sum = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(sum.value, 0);
        assert!(sum.receipt.authenticates_success());
        assert_eq!(
            sum.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RootAssertion)
        );
        assert_ne!(
            count.receipt.identity.operation_id(),
            sum.receipt.identity.operation_id()
        );

        let exact = OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: count.receipt.actual.work,
        };
        let exact_success = compiled
            .count_value_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_success.value, count.value);
        assert!(exact_success.receipt.authenticates_success());

        let one_below_cases = [
            OperationLimits {
                max_boundaries: exact.max_boundaries - 1,
                ..exact
            },
            OperationLimits {
                max_random_access_bytes: exact.max_random_access_bytes - 1,
                ..exact
            },
            OperationLimits {
                max_sequential_bytes: exact.max_sequential_bytes - 1,
                ..exact
            },
            OperationLimits {
                max_match_events: exact.max_match_events - 1,
                ..exact
            },
            OperationLimits {
                max_output_matches: exact.max_output_matches - 1,
                ..exact
            },
            OperationLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
        ];
        for limits in one_below_cases {
            let refusal = compiled
                .count_value_attempt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                )
                .unwrap_err();
            assert_eq!(
                refusal.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::RootAssertion)
            );
            assert!(refusal.receipt.prospective.is_some());
            assert!(refusal.closes());
        }
    }

    #[test]
    fn root_assertion_unicode_validation_and_compile_proof_are_exact() {
        let compiled = root_assertion_fixture(r"\b", true);
        let accounting = compiled.compile_accounting();
        assert_eq!(
            accounting.root_assertion_proof_bytes(),
            core::mem::size_of::<Option<crate::program::Assertion>>()
        );
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(r"\b")
            .unwrap();
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            max_work: accounting.work,
            ..CompileLimits::default()
        };
        let replay = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            exact,
        )
        .unwrap();
        assert_eq!(replay.compile_accounting(), accounting);
        assert!(matches!(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CompileLimits {
                    max_program_bytes: accounting.program_bytes - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert!(matches!(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CompileLimits {
                    max_work: accounting.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        assert!(matches!(
            compiled.count_value(
                b"a\xFFz",
                0..3,
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            ),
            Err(Error::InvalidUtf8ForUnicodeWordBoundary)
        ));
        let invalid_outside_range = b"\xFFa";
        assert!(matches!(
            compiled.count_value(
                invalid_outside_range,
                1..2,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_boundaries: 0,
                    ..OperationLimits::default()
                },
            ),
            Err(Error::InvalidUtf8ForUnicodeWordBoundary)
        ));
        assert!(matches!(
            compiled.count_value(
                invalid_outside_range,
                1..2,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_boundaries: 0,
                    max_sequential_bytes: invalid_outside_range.len() - 1,
                    ..OperationLimits::default()
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::SequentialBytes,
                ..
            })
        ));
        let receipt_refusal = compiled
            .count_value_attempt(
                invalid_outside_range,
                1..2,
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_boundaries: 0,
                    ..OperationLimits::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            receipt_refusal.source,
            Error::ResourceLimit {
                resource: Resource::Boundaries,
                ..
            }
        ));
        assert_eq!(
            receipt_refusal.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RootAssertion)
        );
        assert!(receipt_refusal.receipt.prospective.is_some());
        assert_eq!(
            receipt_refusal.receipt.actual,
            ExecutionAccounting::default()
        );
        assert!(receipt_refusal.closes());
        let nearby = root_assertion_fixture(r"a\b", true);
        assert!(nearby.program.root_assertion().is_none());
        let captured = root_assertion_fixture(r"(\b)", true);
        assert!(captured.program.root_assertion().is_some());
    }

    fn root_assertion_fixture(pattern: &str, unicode: bool) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(unicode)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            if unicode {
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
            } else {
                RustByteProfile::PINNED_1_12_4
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn state_byte_span_sum_fixture_with_limits(
        pattern: &str,
        limits: CompileLimits,
    ) -> Result<CompiledRegex, Error> {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            limits,
        )
    }
}
