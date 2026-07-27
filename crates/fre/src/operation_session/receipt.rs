//! Stable authenticated receipts for the four-leaf operation session.

use core::ops::Range;

/// Common operation-session algorithm version.
#[allow(
    unreachable_pub,
    reason = "the sealed blueprint declaration remains public inside its private receipt module"
)]
pub const OPERATION_SESSION_ALGORITHM_VERSION: u32 = 1;
/// Common operation-session accounting version.
#[allow(
    unreachable_pub,
    reason = "the sealed blueprint declaration remains public inside its private receipt module"
)]
pub const OPERATION_SESSION_ACCOUNTING_VERSION: u32 = 1;
/// Common operation-session receipt schema.
#[allow(
    unreachable_pub,
    reason = "the sealed blueprint declaration remains public inside its private receipt module"
)]
pub const OPERATION_SESSION_RECEIPT_SCHEMA_VERSION: u32 = 1;
/// Stable common accounting identity.
#[allow(
    unreachable_pub,
    reason = "the sealed blueprint declaration remains public inside its private receipt module"
)]
pub const OPERATION_SESSION_ACCOUNTING_ID: &str = "fre.operation-session.v1";

/// Fixed construction and counter order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationSessionLeaf {
    /// Candidate streams and prioritized automata.
    Search = 0,
    /// Hot workspace kernels.
    Hot = 1,
    /// Multi-pattern and capture-history operations.
    MultiCapture = 2,
    /// Whole-input line-domain operations.
    Grep = 3,
}

impl OperationSessionLeaf {
    /// Fixed S/H/M/G order.
    pub const ORDERED: [Self; 4] = [Self::Search, Self::Hot, Self::MultiCapture, Self::Grep];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Search => 0,
            Self::Hot => 1,
            Self::MultiCapture => 2,
            Self::Grep => 3,
        }
    }
}

/// Forced reducer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSessionReducer {
    /// Count selected output events.
    Count,
    /// Sum selected half-open span widths.
    SpanSum,
    /// Sum direct capture-participation entries.
    Participation,
}

/// Independently bounded construction, reset, and execution resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSessionResource {
    /// Construction work.
    BuildWork,
    /// Retained persistent bytes.
    PersistentBytes,
    /// Admitted scratch bytes.
    ScratchBytes,
    /// Combined live bytes.
    PeakBytes,
    /// Generation cells.
    GenerationCells,
    /// Fully initialized bytes.
    InitializedBytes,
    /// Fallible exact-layout allocation attempts.
    AllocationAttempts,
    /// Reset work.
    ResetWork,
    /// Rollover generation cells cleared.
    ClearCells,
    /// Rollover generation bytes cleared.
    ClearBytes,
    /// Execution work.
    ExecutionWork,
    /// Source accesses.
    SourceAccesses,
    /// Automaton or pipeline transitions.
    Transitions,
    /// Candidate events.
    Candidates,
    /// Cache misses.
    CacheMisses,
    /// Capture-history nodes.
    HistoryNodes,
    /// Line domains.
    LineDomains,
    /// Output events.
    OutputEvents,
    /// Selected span bytes.
    SelectedSpanBytes,
    /// Direct participation entries.
    ParticipationEntries,
    /// Steady-operation allocations.
    Allocations,
}

/// Stable terminal identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSessionTerminal {
    /// Attempt completed successfully.
    Success,
    /// A componentwise caller limit refused the attempt.
    Refused(OperationSessionResource),
    /// The leaf deliberately does not implement this reducer.
    UnsupportedReducer,
    /// Leaf, reducer, plan, layout, or protocol identity did not match.
    IdentityMismatch,
    /// Invocation range was invalid.
    InvalidInvocation,
    /// Checked arithmetic failed.
    ArithmeticOverflow,
    /// A selected engine or its authenticated observer failed after begin.
    ExecutionFailed,
    /// A fallible exact-layout allocation failed.
    AllocationFailed,
}

/// Typed direct reducer value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSessionValue {
    /// Count value.
    Count(u64),
    /// Span-sum value.
    SpanSum(u64),
    /// Participation value.
    Participation(u64),
}

/// Componentwise construction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionConstructionLimits {
    /// Maximum construction work.
    pub max_build_work: u64,
    /// Maximum retained persistent bytes.
    pub max_persistent_bytes: usize,
    /// Maximum admitted scratch bytes.
    pub max_scratch_bytes: usize,
    /// Maximum combined peak bytes.
    pub max_peak_bytes: usize,
    /// Maximum generation cells.
    pub max_generation_cells: usize,
    /// Maximum initialized bytes.
    pub max_initialized_bytes: usize,
    /// Maximum allocation attempts.
    pub max_allocation_attempts: usize,
}

impl OperationSessionConstructionLimits {
    /// Exact limits for a construction prospective.
    #[must_use]
    pub const fn exact(prospective: &OperationSessionConstructionProspective) -> Self {
        Self {
            max_build_work: prospective.aggregate.build_work,
            max_persistent_bytes: prospective.aggregate.persistent_bytes,
            max_scratch_bytes: prospective.aggregate.scratch_bytes,
            max_peak_bytes: prospective.aggregate.peak_bytes,
            max_generation_cells: prospective.aggregate.generation_cells,
            max_initialized_bytes: prospective.aggregate.initialized_bytes,
            max_allocation_attempts: prospective.aggregate.allocation_attempts,
        }
    }

    pub(crate) const fn first_refusal(
        self,
        prospective: OperationSessionStorageProspective,
    ) -> Option<OperationSessionResource> {
        if prospective.build_work > self.max_build_work {
            Some(OperationSessionResource::BuildWork)
        } else if prospective.persistent_bytes > self.max_persistent_bytes {
            Some(OperationSessionResource::PersistentBytes)
        } else if prospective.scratch_bytes > self.max_scratch_bytes {
            Some(OperationSessionResource::ScratchBytes)
        } else if prospective.peak_bytes > self.max_peak_bytes {
            Some(OperationSessionResource::PeakBytes)
        } else if prospective.generation_cells > self.max_generation_cells {
            Some(OperationSessionResource::GenerationCells)
        } else if prospective.initialized_bytes > self.max_initialized_bytes {
            Some(OperationSessionResource::InitializedBytes)
        } else if prospective.allocation_attempts > self.max_allocation_attempts {
            Some(OperationSessionResource::AllocationAttempts)
        } else {
            None
        }
    }
}

/// Componentwise reset policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionResetLimits {
    /// Maximum reset work.
    pub max_work: u64,
    /// Maximum rollover cells cleared.
    pub max_clear_cells: usize,
    /// Maximum rollover bytes cleared.
    pub max_clear_bytes: usize,
}

impl OperationSessionResetLimits {
    /// Exact limits for a reset prospective.
    #[must_use]
    pub fn exact(prospective: &OperationSessionResetProspective) -> Option<Self> {
        Some(Self {
            max_work: prospective.work,
            max_clear_cells: usize::try_from(
                prospective
                    .counters_after
                    .clear_cells
                    .checked_sub(prospective.counters_before.clear_cells)?,
            )
            .ok()?,
            max_clear_bytes: usize::try_from(
                prospective
                    .counters_after
                    .clear_bytes
                    .checked_sub(prospective.counters_before.clear_bytes)?,
            )
            .ok()?,
        })
    }
}

/// Componentwise run policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionRunLimits {
    /// Maximum execution work.
    pub max_work: u64,
    /// Maximum source accesses.
    pub max_source_accesses: u64,
    /// Maximum transitions.
    pub max_transitions: u64,
    /// Maximum candidates.
    pub max_candidates: u64,
    /// Maximum cache misses.
    pub max_cache_misses: u64,
    /// Maximum history nodes.
    pub max_history_nodes: u64,
    /// Maximum line domains.
    pub max_line_domains: u64,
    /// Maximum output events.
    pub max_output_events: u64,
    /// Maximum selected span bytes.
    pub max_selected_span_bytes: u64,
    /// Maximum participation entries.
    pub max_participation_entries: u64,
    /// Maximum allocations.
    pub max_allocations: u64,
}

impl OperationSessionRunLimits {
    /// Exact limits for an execution prospective.
    #[must_use]
    pub const fn exact(prospective: OperationSessionExecutionProspective) -> Self {
        Self {
            max_work: prospective.work,
            max_source_accesses: prospective.source_accesses,
            max_transitions: prospective.transitions,
            max_candidates: prospective.candidates,
            max_cache_misses: prospective.cache_misses,
            max_history_nodes: prospective.history_nodes,
            max_line_domains: prospective.line_domains,
            max_output_events: prospective.output_events,
            max_selected_span_bytes: prospective.selected_span_bytes,
            max_participation_entries: prospective.participation_entries,
            max_allocations: prospective.allocations,
        }
    }

    pub(crate) const fn first_refusal(
        self,
        value: OperationSessionExecutionProspective,
    ) -> Option<OperationSessionResource> {
        if value.work > self.max_work {
            Some(OperationSessionResource::ExecutionWork)
        } else if value.source_accesses > self.max_source_accesses {
            Some(OperationSessionResource::SourceAccesses)
        } else if value.transitions > self.max_transitions {
            Some(OperationSessionResource::Transitions)
        } else if value.candidates > self.max_candidates {
            Some(OperationSessionResource::Candidates)
        } else if value.cache_misses > self.max_cache_misses {
            Some(OperationSessionResource::CacheMisses)
        } else if value.history_nodes > self.max_history_nodes {
            Some(OperationSessionResource::HistoryNodes)
        } else if value.line_domains > self.max_line_domains {
            Some(OperationSessionResource::LineDomains)
        } else if value.output_events > self.max_output_events {
            Some(OperationSessionResource::OutputEvents)
        } else if value.selected_span_bytes > self.max_selected_span_bytes {
            Some(OperationSessionResource::SelectedSpanBytes)
        } else if value.participation_entries > self.max_participation_entries {
            Some(OperationSessionResource::ParticipationEntries)
        } else if value.allocations > self.max_allocations {
            Some(OperationSessionResource::Allocations)
        } else {
            None
        }
    }
}

/// Exact source invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSessionInvocation {
    /// Complete haystack length.
    pub haystack_len: usize,
    /// Half-open selected source range.
    pub range: Range<usize>,
    /// Generation advance required by this invocation.
    pub required_generations: u64,
}

impl OperationSessionInvocation {
    pub(crate) fn is_valid(&self) -> bool {
        self.range.start <= self.range.end && self.range.end <= self.haystack_len
    }
}

/// Complete immutable route identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionRouteIdentity {
    /// Stable common accounting identity.
    pub session_accounting_id: &'static str,
    /// Common algorithm version.
    pub session_algorithm_version: u32,
    /// Common accounting version.
    pub session_accounting_version: u32,
    /// Exact selected leaf.
    pub leaf: OperationSessionLeaf,
    /// Exact forced reducer.
    pub reducer: OperationSessionReducer,
    /// Immutable compiled-plan identity.
    pub compiled_plan_id: [u8; 16],
    /// Exact whole-byte/range/line/multi-pattern source contract.
    pub source_identity: &'static str,
    /// Exact source, pattern, and line order contract.
    pub order_identity: &'static str,
    /// Construction-derived fallback edge already exhausted pre-source.
    pub fallback_identity: &'static str,
    /// Leaf algorithm version.
    pub leaf_algorithm_version: u32,
    /// Leaf accounting version.
    pub leaf_accounting_version: u32,
    /// Stable leaf accounting identity.
    pub leaf_accounting_id: &'static str,
}

impl OperationSessionRouteIdentity {
    pub(crate) fn has_current_common_protocol(&self) -> bool {
        self.session_accounting_id == OPERATION_SESSION_ACCOUNTING_ID
            && self.session_algorithm_version == OPERATION_SESSION_ALGORITHM_VERSION
            && self.session_accounting_version == OPERATION_SESSION_ACCOUNTING_VERSION
            && self.compiled_plan_id != [0; 16]
            && !self.source_identity.is_empty()
            && !self.order_identity.is_empty()
            && !self.fallback_identity.is_empty()
            && !self.leaf_accounting_id.is_empty()
    }
}

/// Complete request consumed by a forced leaf entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    unreachable_pub,
    reason = "the sealed blueprint declaration remains public inside its private receipt module"
)]
pub struct OperationSessionAttemptRequest {
    /// Immutable route identity.
    pub identity: OperationSessionRouteIdentity,
    /// Exact source invocation.
    pub invocation: OperationSessionInvocation,
    /// Complete pre-source execution prospective.
    pub prospective: OperationSessionExecutionProspective,
    /// Reset limits.
    pub reset_limits: OperationSessionResetLimits,
    /// Execution limits.
    pub run_limits: OperationSessionRunLimits,
    /// Immutable-plan identity supplied by the crate-private artifact owner.
    ///
    /// Keeping this distinct from the attempted public route identity makes
    /// a zero or substituted caller identity detectable rather than merely
    /// self-authenticating it.
    trusted_compiled_plan_id: [u8; 16],
    trusted_reducer: OperationSessionReducer,
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
impl OperationSessionAttemptRequest {
    pub(crate) fn new_trusted(
        identity: OperationSessionRouteIdentity,
        invocation: OperationSessionInvocation,
        prospective: OperationSessionExecutionProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
        trusted_compiled_plan_id: [u8; 16],
    ) -> Result<Self, OperationSessionTerminal> {
        if trusted_compiled_plan_id == [0; 16] {
            return Err(OperationSessionTerminal::IdentityMismatch);
        }
        Ok(Self {
            identity,
            invocation,
            prospective,
            reset_limits,
            run_limits,
            trusted_compiled_plan_id,
            trusted_reducer: identity.reducer,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked_for_test(
        identity: OperationSessionRouteIdentity,
        invocation: OperationSessionInvocation,
        prospective: OperationSessionExecutionProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
        trusted_compiled_plan_id: [u8; 16],
    ) -> Self {
        Self {
            identity,
            invocation,
            prospective,
            reset_limits,
            run_limits,
            trusted_compiled_plan_id,
            trusted_reducer: identity.reducer,
        }
    }

    pub(crate) const fn trusted_compiled_plan_id(&self) -> [u8; 16] {
        self.trusted_compiled_plan_id
    }

    pub(crate) fn bind_reducer(&mut self, reducer: OperationSessionReducer) {
        self.trusted_reducer = reducer;
    }

    pub(crate) const fn trusted_reducer(&self) -> OperationSessionReducer {
        self.trusted_reducer
    }
}

/// Leaf or aggregate construction prospective.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionStorageProspective {
    /// Construction work.
    pub build_work: u64,
    /// Retained persistent bytes.
    pub persistent_bytes: usize,
    /// Admitted scratch bytes.
    pub scratch_bytes: usize,
    /// Combined live bytes.
    pub peak_bytes: usize,
    /// Generation cells.
    pub generation_cells: usize,
    /// Fully initialized bytes.
    pub initialized_bytes: usize,
    /// Fallible exact-layout allocation attempts.
    pub allocation_attempts: usize,
}

/// Leaf or aggregate construction actual.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionStorageActual {
    /// Construction work.
    pub build_work: u64,
    /// Retained persistent bytes.
    pub persistent_bytes: usize,
    /// Admitted scratch bytes.
    pub scratch_bytes: usize,
    /// Combined live bytes.
    pub peak_bytes: usize,
    /// Generation cells.
    pub generation_cells: usize,
    /// Fully initialized bytes.
    pub initialized_bytes: usize,
    /// Fallible exact-layout allocation attempts.
    pub allocation_attempts: usize,
}

impl From<OperationSessionStorageProspective> for OperationSessionStorageActual {
    fn from(value: OperationSessionStorageProspective) -> Self {
        Self {
            build_work: value.build_work,
            persistent_bytes: value.persistent_bytes,
            scratch_bytes: value.scratch_bytes,
            peak_bytes: value.peak_bytes,
            generation_cells: value.generation_cells,
            initialized_bytes: value.initialized_bytes,
            allocation_attempts: value.allocation_attempts,
        }
    }
}

impl OperationSessionStorageProspective {
    pub(crate) const fn contains_actual(self, actual: OperationSessionStorageActual) -> bool {
        actual.build_work <= self.build_work
            && actual.persistent_bytes <= self.persistent_bytes
            && actual.scratch_bytes <= self.scratch_bytes
            && actual.peak_bytes <= self.peak_bytes
            && actual.generation_cells <= self.generation_cells
            && actual.initialized_bytes <= self.initialized_bytes
            && actual.allocation_attempts <= self.allocation_attempts
    }
}

/// Four-leaf construction prospective.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionConstructionProspective {
    /// Checked fixed-order aggregate.
    pub aggregate: OperationSessionStorageProspective,
    /// Fixed S/H/M/G leaf prospectives.
    pub leaves: [OperationSessionStorageProspective; 4],
}

/// Four-leaf construction actual.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionConstructionActual {
    /// Checked fixed-order aggregate.
    pub aggregate: OperationSessionStorageActual,
    /// Fixed S/H/M/G leaf actuals.
    pub leaves: [OperationSessionStorageActual; 4],
}

/// Pre-source execution prospective.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionExecutionProspective {
    /// Execution work.
    pub work: u64,
    /// Source accesses.
    pub source_accesses: u64,
    /// Transitions.
    pub transitions: u64,
    /// Candidate events.
    pub candidates: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Capture-history nodes.
    pub history_nodes: u64,
    /// Line domains.
    pub line_domains: u64,
    /// Output events.
    pub output_events: u64,
    /// Selected span bytes.
    pub selected_span_bytes: u64,
    /// Participation entries.
    pub participation_entries: u64,
    /// Steady allocations.
    pub allocations: u64,
}

/// Exact execution actual.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionExecutionActual {
    /// Execution work.
    pub work: u64,
    /// Source accesses.
    pub source_accesses: u64,
    /// Transitions.
    pub transitions: u64,
    /// Candidate events.
    pub candidates: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Capture-history nodes.
    pub history_nodes: u64,
    /// Line domains.
    pub line_domains: u64,
    /// Output events.
    pub output_events: u64,
    /// Selected span bytes.
    pub selected_span_bytes: u64,
    /// Participation entries.
    pub participation_entries: u64,
    /// Steady allocations.
    pub allocations: u64,
}

impl OperationSessionExecutionProspective {
    pub(crate) const fn contains_actual(self, actual: OperationSessionExecutionActual) -> bool {
        actual.work <= self.work
            && actual.source_accesses <= self.source_accesses
            && actual.transitions <= self.transitions
            && actual.candidates <= self.candidates
            && actual.cache_misses <= self.cache_misses
            && actual.history_nodes <= self.history_nodes
            && actual.line_domains <= self.line_domains
            && actual.output_events <= self.output_events
            && actual.selected_span_bytes <= self.selected_span_bytes
            && actual.participation_entries <= self.participation_entries
            && actual.allocations <= self.allocations
    }
}

/// One fixed leaf construction closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionLeafConstructionReceipt {
    /// Fixed leaf.
    pub leaf: OperationSessionLeaf,
    /// Exact capacity-derived layout identity.
    pub layout_id: [u8; 16],
    /// Leaf algorithm version.
    pub leaf_algorithm_version: u32,
    /// Leaf accounting version.
    pub leaf_accounting_version: u32,
    /// Stable leaf accounting identity.
    pub leaf_accounting_id: &'static str,
    /// Leaf prospective.
    pub prospective: OperationSessionStorageProspective,
    /// Leaf actual.
    pub actual: OperationSessionStorageActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationSessionConstructionAuthentication {
    schema_version: u32,
    accounting_id: &'static str,
    limits: OperationSessionConstructionLimits,
    prospective: OperationSessionConstructionProspective,
    actual: OperationSessionConstructionActual,
    leaves: [OperationSessionLeafConstructionReceipt; 4],
    expected_layouts: [[u8; 16]; 4],
}

/// Closed four-leaf construction receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSessionConstructionReceipt {
    /// Stable schema.
    pub schema_version: u32,
    /// Stable accounting identity.
    pub accounting_id: &'static str,
    /// Caller limits.
    pub limits: OperationSessionConstructionLimits,
    /// Aggregate and per-leaf P.
    pub prospective: OperationSessionConstructionProspective,
    /// Aggregate and per-leaf A.
    pub actual: OperationSessionConstructionActual,
    /// Fixed S/H/M/G leaf receipts.
    pub leaves: [OperationSessionLeafConstructionReceipt; 4],
    authentication: OperationSessionConstructionAuthentication,
}

impl OperationSessionConstructionReceipt {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the authenticated constructor deliberately consumes complete fixed four-leaf records"
    )]
    pub(crate) fn new(
        limits: OperationSessionConstructionLimits,
        prospective: OperationSessionConstructionProspective,
        actual: OperationSessionConstructionActual,
        leaves: [OperationSessionLeafConstructionReceipt; 4],
        expected_layouts: [[u8; 16]; 4],
    ) -> Self {
        let authentication = OperationSessionConstructionAuthentication {
            schema_version: OPERATION_SESSION_RECEIPT_SCHEMA_VERSION,
            accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            limits,
            prospective,
            actual,
            leaves,
            expected_layouts,
        };
        Self {
            schema_version: authentication.schema_version,
            accounting_id: authentication.accounting_id,
            limits,
            prospective,
            actual,
            leaves,
            authentication,
        }
    }

    /// Authenticate every public identity, limit, P/A, and leaf field.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.authentication
            == OperationSessionConstructionAuthentication {
                schema_version: self.schema_version,
                accounting_id: self.accounting_id,
                limits: self.limits,
                prospective: self.prospective,
                actual: self.actual,
                leaves: self.leaves,
                expected_layouts: self.authentication.expected_layouts,
            }
            && self.schema_version == OPERATION_SESSION_RECEIPT_SCHEMA_VERSION
            && self.accounting_id == OPERATION_SESSION_ACCOUNTING_ID
            && self
                .limits
                .first_refusal(self.prospective.aggregate)
                .is_none()
            && construction_actual_within(&self.prospective, &self.actual)
            && storage_exactly_matches_actual(self.prospective.aggregate, self.actual.aggregate)
            && construction_aggregate_closes(&self.prospective, &self.actual)
            && OperationSessionLeaf::ORDERED
                .iter()
                .zip(self.leaves.iter())
                .enumerate()
                .all(|(index, (leaf, receipt))| {
                    receipt.leaf == *leaf
                        && receipt.layout_id == self.authentication.expected_layouts[index]
                        && receipt.layout_id[15] == super::tag_layout_id(*leaf, [0; 16])[15]
                        && receipt.layout_id != [0; 16]
                        && leaf_protocol_closes(
                            receipt.leaf,
                            receipt.leaf_algorithm_version,
                            receipt.leaf_accounting_version,
                            receipt.leaf_accounting_id,
                        )
                        && receipt.prospective == self.prospective.leaves[index]
                        && receipt.actual == self.actual.leaves[index]
                        && receipt.prospective.contains_actual(receipt.actual)
                        && storage_exactly_matches_actual(receipt.prospective, receipt.actual)
                })
            && self.leaves.iter().enumerate().all(|(left, receipt)| {
                self.leaves
                    .iter()
                    .skip(left.checked_add(1).expect("bounded leaf index"))
                    .all(|other| receipt.layout_id != other.layout_id)
            })
    }
}

/// Cumulative counters owned by one leaf slot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationSessionLeafCounters {
    /// Current generation.
    pub generation: u64,
    /// Successful reset invocations.
    pub reset_invocations: u64,
    /// Generation rollovers.
    pub rollovers: u64,
    /// Generation-mark clears.
    pub clears: u64,
    /// Generation cells cleared.
    pub clear_cells: u64,
    /// Generation bytes cleared.
    pub clear_bytes: u64,
}

/// Selected-leaf reset prospective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionResetProspective {
    /// Selected leaf.
    pub leaf: OperationSessionLeaf,
    /// Cumulative counters before reset.
    pub counters_before: OperationSessionLeafCounters,
    /// Cumulative counters after success.
    pub counters_after: OperationSessionLeafCounters,
    /// Requested generation advance.
    pub required_generations: u64,
    /// Exact reset work.
    pub work: u64,
}

/// Selected-leaf reset actual.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionResetActual {
    /// Selected leaf.
    pub leaf: OperationSessionLeaf,
    /// Cumulative counters before reset.
    pub counters_before: OperationSessionLeafCounters,
    /// Cumulative counters after terminal.
    pub counters_after: OperationSessionLeafCounters,
    /// Requested generation advance.
    pub required_generations: u64,
    /// Actual reset work.
    pub work: u64,
}

impl From<OperationSessionResetProspective> for OperationSessionResetActual {
    fn from(value: OperationSessionResetProspective) -> Self {
        Self {
            leaf: value.leaf,
            counters_before: value.counters_before,
            counters_after: value.counters_after,
            required_generations: value.required_generations,
            work: value.work,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationSessionResetAuthentication {
    schema_version: u32,
    layout_id: [u8; 16],
    generation_cells: usize,
    limits: OperationSessionResetLimits,
    prospective: Option<OperationSessionResetProspective>,
    actual: OperationSessionResetActual,
    all_leaves_before: [OperationSessionLeafCounters; 4],
    all_leaves_after: [OperationSessionLeafCounters; 4],
    terminal: OperationSessionTerminal,
}

/// Closed selected-leaf reset attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSessionResetAttemptReceipt {
    /// Stable schema.
    pub schema_version: u32,
    /// Exact selected-leaf construction layout.
    pub layout_id: [u8; 16],
    /// Caller reset limits.
    pub limits: OperationSessionResetLimits,
    /// Source-free P, absent only on pre-P failure.
    pub prospective: Option<OperationSessionResetProspective>,
    /// Exact A through terminal.
    pub actual: OperationSessionResetActual,
    /// Fixed S/H/M/G counters before.
    pub all_leaves_before: [OperationSessionLeafCounters; 4],
    /// Fixed S/H/M/G counters after.
    pub all_leaves_after: [OperationSessionLeafCounters; 4],
    /// Exact terminal.
    pub terminal: OperationSessionTerminal,
    authentication: OperationSessionResetAuthentication,
}

impl OperationSessionResetAttemptReceipt {
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated constructor deliberately receives every reset receipt field"
    )]
    pub(crate) fn new(
        layout_id: [u8; 16],
        generation_cells: usize,
        limits: OperationSessionResetLimits,
        prospective: Option<OperationSessionResetProspective>,
        actual: OperationSessionResetActual,
        all_leaves_before: [OperationSessionLeafCounters; 4],
        all_leaves_after: [OperationSessionLeafCounters; 4],
        terminal: OperationSessionTerminal,
    ) -> Self {
        let authentication = OperationSessionResetAuthentication {
            schema_version: OPERATION_SESSION_RECEIPT_SCHEMA_VERSION,
            layout_id,
            generation_cells,
            limits,
            prospective,
            actual,
            all_leaves_before,
            all_leaves_after,
            terminal,
        };
        Self {
            schema_version: authentication.schema_version,
            layout_id,
            limits,
            prospective,
            actual,
            all_leaves_before,
            all_leaves_after,
            terminal,
            authentication,
        }
    }

    /// Authenticate every reset field and selected-leaf isolation.
    #[must_use]
    pub fn closes(&self) -> bool {
        if self.authentication
            != (OperationSessionResetAuthentication {
                schema_version: self.schema_version,
                layout_id: self.layout_id,
                generation_cells: self.authentication.generation_cells,
                limits: self.limits,
                prospective: self.prospective,
                actual: self.actual,
                all_leaves_before: self.all_leaves_before,
                all_leaves_after: self.all_leaves_after,
                terminal: self.terminal,
            })
            || self.schema_version != OPERATION_SESSION_RECEIPT_SCHEMA_VERSION
            || self.layout_id == [0; 16]
            || self.layout_id[15] != super::tag_layout_id(self.actual.leaf, [0; 16])[15]
        {
            return false;
        }
        let leaf = self.actual.leaf;
        let index = leaf.index();
        if self.actual.counters_before != self.all_leaves_before[index]
            || self.actual.counters_after != self.all_leaves_after[index]
            || !reset_leaf_isolated(leaf, self.all_leaves_before, self.all_leaves_after)
        {
            return false;
        }
        match (self.terminal, self.prospective) {
            (OperationSessionTerminal::Success, Some(prospective)) => {
                reset_prospective_closes(prospective, self.authentication.generation_cells)
                    && self.actual == OperationSessionResetActual::from(prospective)
                    && reset_limits_contain(self.limits, prospective)
                    && leaf == prospective.leaf
            }
            (OperationSessionTerminal::Refused(resource), Some(prospective)) => {
                reset_prospective_closes(prospective, self.authentication.generation_cells)
                    && leaf == prospective.leaf
                    && self.actual.required_generations == prospective.required_generations
                    && self.actual.counters_before == prospective.counters_before
                    && self.actual.counters_after == prospective.counters_before
                    && self.actual.work == 0
                    && self.all_leaves_before == self.all_leaves_after
                    && reset_limits_first_refusal(self.limits, prospective) == Some(resource)
            }
            (
                OperationSessionTerminal::Refused(_)
                | OperationSessionTerminal::UnsupportedReducer
                | OperationSessionTerminal::IdentityMismatch
                | OperationSessionTerminal::InvalidInvocation,
                None,
            ) => {
                self.actual.counters_before == self.actual.counters_after
                    && self.actual.work == 0
                    && self.all_leaves_before == self.all_leaves_after
            }
            (OperationSessionTerminal::ArithmeticOverflow, None) => {
                self.actual.counters_before == self.actual.counters_after
                    && self.actual.work == 0
                    && self.all_leaves_before == self.all_leaves_after
                    && reset_arithmetic_overflow_proven(
                        self.actual.counters_before,
                        self.authentication.generation_cells,
                        self.actual.required_generations,
                    )
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationSessionFailureEvidence {
    None,
    RouteMismatch,
    RefusedActual,
    InvalidOrder,
    ArithmeticOverflow,
    ReducerMismatch,
    ExecutionFailed(OperationSessionExecutionFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationSessionExecutionFailure {
    Engine,
    Observer,
    Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationSessionAttemptedOperation {
    None,
    Meter {
        resource: OperationSessionResource,
        amount: u64,
    },
    Span {
        start: usize,
        end: usize,
        pattern_ordinal: Option<usize>,
    },
    ObserveParticipation {
        start: usize,
        end: usize,
        pattern_ordinal: usize,
    },
    EmitParticipation {
        entries: u64,
    },
    LineDomain {
        line_ordinal: usize,
    },
    Finish {
        reducer: OperationSessionReducer,
    },
    ExecutionFailure {
        failure: OperationSessionExecutionFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationSessionAttemptEvidence {
    pub(crate) first_span: Option<(usize, usize, Option<usize>)>,
    pub(crate) last_span: Option<(usize, usize, Option<usize>)>,
    pub(crate) span_events: u64,
    pub(crate) first_participation: Option<(usize, usize, Option<usize>)>,
    pub(crate) last_participation: Option<(usize, usize, Option<usize>)>,
    pub(crate) pending_participation: Option<(usize, usize, usize)>,
    pub(crate) participation_events: u64,
    pub(crate) first_line_ordinal: Option<usize>,
    pub(crate) last_line_ordinal: Option<usize>,
    pub(crate) line_events: u64,
    pub(crate) refused_actual: Option<OperationSessionExecutionActual>,
    pub(crate) attempted_identity: Option<OperationSessionRouteIdentity>,
    pub(crate) attempted_operation: OperationSessionAttemptedOperation,
    pub(crate) failure: OperationSessionFailureEvidence,
    pub(crate) order_valid: bool,
}

impl OperationSessionAttemptEvidence {
    pub(crate) const fn empty() -> Self {
        Self {
            first_span: None,
            last_span: None,
            span_events: 0,
            first_participation: None,
            last_participation: None,
            pending_participation: None,
            participation_events: 0,
            first_line_ordinal: None,
            last_line_ordinal: None,
            line_events: 0,
            refused_actual: None,
            attempted_identity: None,
            attempted_operation: OperationSessionAttemptedOperation::None,
            failure: OperationSessionFailureEvidence::None,
            order_valid: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationSessionAttemptAuthentication {
    schema_version: u32,
    identity: OperationSessionRouteIdentity,
    expected_identity: OperationSessionRouteIdentity,
    invocation: OperationSessionInvocation,
    limits: OperationSessionRunLimits,
    construction_layout_id: [u8; 16],
    reset: OperationSessionResetAttemptReceipt,
    prospective: Option<OperationSessionExecutionProspective>,
    actual: OperationSessionExecutionActual,
    value: Option<OperationSessionValue>,
    terminal: OperationSessionTerminal,
    evidence: OperationSessionAttemptEvidence,
}

/// Closed forced-operation attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSessionAttemptReceipt {
    /// Stable schema.
    pub schema_version: u32,
    /// Complete route identity.
    pub identity: OperationSessionRouteIdentity,
    /// Exact source invocation.
    pub invocation: OperationSessionInvocation,
    /// Caller execution limits.
    pub limits: OperationSessionRunLimits,
    /// Exact selected-leaf construction layout.
    pub construction_layout_id: [u8; 16],
    /// Nested reset attempt.
    pub reset: OperationSessionResetAttemptReceipt,
    /// Pre-source execution P.
    pub prospective: Option<OperationSessionExecutionProspective>,
    /// Exact execution A.
    pub actual: OperationSessionExecutionActual,
    /// Typed value only on success.
    pub value: Option<OperationSessionValue>,
    /// Exact terminal.
    pub terminal: OperationSessionTerminal,
    authentication: OperationSessionAttemptAuthentication,
}

impl OperationSessionAttemptReceipt {
    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated constructor deliberately receives every public receipt field"
    )]
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the authenticated constructor deliberately consumes the complete failure witness"
    )]
    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    pub(crate) fn new(
        identity: OperationSessionRouteIdentity,
        expected_identity: OperationSessionRouteIdentity,
        invocation: OperationSessionInvocation,
        limits: OperationSessionRunLimits,
        construction_layout_id: [u8; 16],
        reset: OperationSessionResetAttemptReceipt,
        prospective: Option<OperationSessionExecutionProspective>,
        actual: OperationSessionExecutionActual,
        value: Option<OperationSessionValue>,
        terminal: OperationSessionTerminal,
        evidence: OperationSessionAttemptEvidence,
    ) -> Self {
        let authentication = OperationSessionAttemptAuthentication {
            schema_version: OPERATION_SESSION_RECEIPT_SCHEMA_VERSION,
            identity,
            expected_identity,
            invocation: invocation.clone(),
            limits,
            construction_layout_id,
            reset: reset.clone(),
            prospective,
            actual,
            value,
            terminal,
            evidence,
        };
        Self {
            schema_version: authentication.schema_version,
            identity,
            invocation,
            limits,
            construction_layout_id,
            reset,
            prospective,
            actual,
            value,
            terminal,
            authentication,
        }
    }

    /// Authenticate all public fields plus semantic P/A/value closure.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "one closure audit enumerates every authenticated terminal shape in a single match"
    )]
    pub fn closes(&self) -> bool {
        let expected_identity = self.authentication.expected_identity;
        let evidence = self.authentication.evidence;
        if self.authentication
            != (OperationSessionAttemptAuthentication {
                schema_version: self.schema_version,
                identity: self.identity,
                expected_identity,
                invocation: self.invocation.clone(),
                limits: self.limits,
                construction_layout_id: self.construction_layout_id,
                reset: self.reset.clone(),
                prospective: self.prospective,
                actual: self.actual,
                value: self.value,
                terminal: self.terminal,
                evidence,
            })
            || self.schema_version != OPERATION_SESSION_RECEIPT_SCHEMA_VERSION
            || self.construction_layout_id == [0; 16]
            || !self.reset.closes()
            || !route_identity_closes(expected_identity)
            || expected_identity.leaf != self.reset.actual.leaf
            || self.identity.leaf != self.reset.actual.leaf
            || self.construction_layout_id != self.reset.layout_id
            || self.invocation.required_generations != self.reset.actual.required_generations
            || self.reset.prospective.is_some_and(|prospective| {
                prospective.leaf != self.identity.leaf
                    || prospective.required_generations != self.invocation.required_generations
            })
        {
            return false;
        }
        match (self.terminal, self.prospective, self.value) {
            (OperationSessionTerminal::Success, Some(prospective), Some(value)) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && prospective.allocations == 0
                    && self.actual.allocations == 0
                    && prospective.contains_actual(self.actual)
                    && self.limits.first_refusal(prospective).is_none()
                    && value_closes(self.identity.reducer, value, self.actual)
                    && execution_evidence_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            (OperationSessionTerminal::IdentityMismatch, None, None) => {
                self.identity == expected_identity
                    && evidence.failure == OperationSessionFailureEvidence::RouteMismatch
                    && evidence
                        .attempted_identity
                        .is_some_and(|attempted| attempted != expected_identity)
                    && evidence.attempted_operation == OperationSessionAttemptedOperation::None
                    && evidence.refused_actual.is_none()
                    && evidence.first_span.is_none()
                    && evidence.last_span.is_none()
                    && evidence.span_events == 0
                    && evidence.first_participation.is_none()
                    && evidence.last_participation.is_none()
                    && evidence.pending_participation.is_none()
                    && evidence.participation_events == 0
                    && evidence.first_line_ordinal.is_none()
                    && evidence.last_line_ordinal.is_none()
                    && evidence.line_events == 0
                    && evidence.order_valid
                    && reset_is_matching_noop(&self.reset, self.terminal)
                    && self.actual == OperationSessionExecutionActual::default()
            }
            (OperationSessionTerminal::InvalidInvocation, None, None) => {
                self.identity == expected_identity
                    && !super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && reset_is_matching_noop(&self.reset, self.terminal)
                    && self.actual == OperationSessionExecutionActual::default()
                    && evidence == OperationSessionAttemptEvidence::empty()
            }
            (OperationSessionTerminal::UnsupportedReducer, None, None) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && !super::route_supported(self.identity.leaf, self.identity.reducer)
                    && reset_is_matching_noop(&self.reset, self.terminal)
                    && self.actual == OperationSessionExecutionActual::default()
                    && evidence == OperationSessionAttemptEvidence::empty()
            }
            (OperationSessionTerminal::Refused(resource), Some(prospective), None)
                if self.reset.prospective.is_none() =>
            {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && reset_is_matching_noop(&self.reset, self.terminal)
                    && execution_preflight_first_refusal(self.limits, prospective) == Some(resource)
                    && self.actual == OperationSessionExecutionActual::default()
                    && evidence == OperationSessionAttemptEvidence::empty()
            }
            (OperationSessionTerminal::Refused(resource), Some(prospective), None)
                if self.reset.prospective.is_some() && self.reset.terminal == self.terminal =>
            {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.actual == OperationSessionExecutionActual::default()
                    && self.reset.terminal == OperationSessionTerminal::Refused(resource)
                    && evidence == OperationSessionAttemptEvidence::empty()
                    && prospective.allocations == 0
                    && self.limits.first_refusal(prospective).is_none()
            }
            (OperationSessionTerminal::ArithmeticOverflow, Some(prospective), None)
                if self.reset.prospective.is_none() && self.reset.terminal == self.terminal =>
            {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && prospective.allocations == 0
                    && self.limits.first_refusal(prospective).is_none()
                    && reset_is_matching_noop(&self.reset, self.terminal)
                    && self.actual == OperationSessionExecutionActual::default()
                    && evidence == OperationSessionAttemptEvidence::empty()
            }
            (OperationSessionTerminal::Refused(resource), Some(prospective), None) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && prospective.allocations == 0
                    && execution_actual_admitted(self.limits, prospective, self.actual)
                    && evidence.refused_actual.is_some_and(|refused| {
                        execution_actual_first_refusal(self.limits, prospective, refused)
                            == Some(resource)
                    })
                    && evidence.failure == OperationSessionFailureEvidence::RefusedActual
                    && evidence.refused_actual
                        == attempted_operation_actual(
                            self.identity.leaf,
                            self.identity.reducer,
                            &self.invocation,
                            self.actual,
                            &evidence,
                        )
                    && execution_failure_evidence_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            (OperationSessionTerminal::InvalidInvocation, Some(prospective), None) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && prospective.allocations == 0
                    && execution_actual_admitted(self.limits, prospective, self.actual)
                    && evidence.refused_actual.is_none()
                    && evidence.failure == OperationSessionFailureEvidence::InvalidOrder
                    && attempted_operation_proves_invalid_order(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        &evidence,
                    )
                    && execution_failure_evidence_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            (OperationSessionTerminal::ArithmeticOverflow, Some(prospective), None) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && prospective.allocations == 0
                    && execution_actual_admitted(self.limits, prospective, self.actual)
                    && evidence.refused_actual.is_none()
                    && evidence.failure == OperationSessionFailureEvidence::ArithmeticOverflow
                    && attempted_operation_proves_arithmetic_overflow(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
                    && execution_failure_evidence_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            (OperationSessionTerminal::IdentityMismatch, Some(prospective), None) => {
                self.identity == expected_identity
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && prospective.allocations == 0
                    && execution_actual_admitted(self.limits, prospective, self.actual)
                    && evidence.refused_actual.is_none()
                    && evidence.failure == OperationSessionFailureEvidence::ReducerMismatch
                    && attempted_operation_proves_reducer_mismatch(
                        self.identity.leaf,
                        self.identity.reducer,
                        &evidence,
                    )
                    && execution_failure_evidence_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            (OperationSessionTerminal::ExecutionFailed, Some(prospective), None) => {
                let OperationSessionFailureEvidence::ExecutionFailed(failure) = evidence.failure
                else {
                    return false;
                };
                self.identity == expected_identity
                    && self.identity.leaf == OperationSessionLeaf::Grep
                    && self.identity.reducer == OperationSessionReducer::Count
                    && super::invocation_closes(
                        self.identity.leaf,
                        self.identity.reducer,
                        &self.invocation,
                    )
                    && super::route_supported(self.identity.leaf, self.identity.reducer)
                    && self.reset.terminal == OperationSessionTerminal::Success
                    && prospective.allocations == 0
                    && execution_actual_admitted(self.limits, prospective, self.actual)
                    && evidence.refused_actual.is_none()
                    && evidence.attempted_operation
                        == OperationSessionAttemptedOperation::ExecutionFailure { failure }
                    && grep_execution_failure_evidence_closes(
                        failure,
                        &self.invocation,
                        self.actual,
                        &evidence,
                    )
            }
            _ => false,
        }
    }
}

fn storage_exactly_matches_actual(
    prospective: OperationSessionStorageProspective,
    actual: OperationSessionStorageActual,
) -> bool {
    prospective.build_work == actual.build_work
        && prospective.persistent_bytes == actual.persistent_bytes
        && prospective.scratch_bytes == actual.scratch_bytes
        && prospective.peak_bytes == actual.peak_bytes
        && prospective.generation_cells == actual.generation_cells
        && prospective.initialized_bytes == actual.initialized_bytes
        && prospective.allocation_attempts == actual.allocation_attempts
        && prospective
            .persistent_bytes
            .checked_add(prospective.scratch_bytes)
            == Some(prospective.peak_bytes)
        && actual.persistent_bytes.checked_add(actual.scratch_bytes) == Some(actual.peak_bytes)
}

fn leaf_protocol_closes(
    leaf: OperationSessionLeaf,
    algorithm_version: u32,
    accounting_version: u32,
    accounting_id: &str,
) -> bool {
    let (expected_algorithm, expected_accounting, expected_id) = match leaf {
        OperationSessionLeaf::Search => (
            super::search::ALGORITHM_VERSION,
            super::search::ACCOUNTING_VERSION,
            super::search::ACCOUNTING_ID,
        ),
        OperationSessionLeaf::Hot => (
            super::hot::ALGORITHM_VERSION,
            super::hot::ACCOUNTING_VERSION,
            super::hot::ACCOUNTING_ID,
        ),
        OperationSessionLeaf::MultiCapture => (
            super::multi_capture::ALGORITHM_VERSION,
            super::multi_capture::ACCOUNTING_VERSION,
            super::multi_capture::ACCOUNTING_ID,
        ),
        OperationSessionLeaf::Grep => (
            super::grep::ALGORITHM_VERSION,
            super::grep::ACCOUNTING_VERSION,
            super::grep::ACCOUNTING_ID,
        ),
    };
    algorithm_version == expected_algorithm
        && accounting_version == expected_accounting
        && accounting_id == expected_id
}

fn route_identity_closes(identity: OperationSessionRouteIdentity) -> bool {
    let (source_identity, order_identity, fallback_identity) =
        super::route_contract(identity.leaf, identity.reducer);
    identity.has_current_common_protocol()
        && leaf_protocol_closes(
            identity.leaf,
            identity.leaf_algorithm_version,
            identity.leaf_accounting_version,
            identity.leaf_accounting_id,
        )
        && identity.source_identity == source_identity
        && identity.order_identity == order_identity
        && identity.fallback_identity == fallback_identity
}

fn reset_prospective_closes(
    prospective: OperationSessionResetProspective,
    generation_cells: usize,
) -> bool {
    let before = prospective.counters_before;
    let after = prospective.counters_after;
    let Some(reset_invocations) = before.reset_invocations.checked_add(1) else {
        return false;
    };
    if after.reset_invocations != reset_invocations {
        return false;
    }
    if let Some(generation) = before
        .generation
        .checked_add(prospective.required_generations)
    {
        prospective.work == 1
            && after.generation == generation
            && after.rollovers == before.rollovers
            && after.clears == before.clears
            && after.clear_cells == before.clear_cells
            && after.clear_bytes == before.clear_bytes
    } else {
        let Ok(cells) = u64::try_from(generation_cells) else {
            return false;
        };
        let Ok(cell_bytes) = u64::try_from(core::mem::size_of::<u64>()) else {
            return false;
        };
        let Some(bytes) = cells.checked_mul(cell_bytes) else {
            return false;
        };
        let Some(work) = 1_u64.checked_add(cells) else {
            return false;
        };
        let (Some(rollovers), Some(clears), Some(clear_cells), Some(clear_bytes)) = (
            before.rollovers.checked_add(1),
            before.clears.checked_add(1),
            before.clear_cells.checked_add(cells),
            before.clear_bytes.checked_add(bytes),
        ) else {
            return false;
        };
        prospective.work == work
            && after.generation == prospective.required_generations
            && after.rollovers == rollovers
            && after.clears == clears
            && after.clear_cells == clear_cells
            && after.clear_bytes == clear_bytes
    }
}

fn reset_arithmetic_overflow_proven(
    before: OperationSessionLeafCounters,
    generation_cells: usize,
    required_generations: u64,
) -> bool {
    if before.reset_invocations.checked_add(1).is_none() {
        return true;
    }
    if before
        .generation
        .checked_add(required_generations)
        .is_some()
    {
        return false;
    }
    let Ok(cells) = u64::try_from(generation_cells) else {
        return true;
    };
    let Ok(cell_bytes) = u64::try_from(core::mem::size_of::<u64>()) else {
        return true;
    };
    cells.checked_mul(cell_bytes).is_none()
        || 1_u64.checked_add(cells).is_none()
        || before.rollovers.checked_add(1).is_none()
        || before.clears.checked_add(1).is_none()
        || before.clear_cells.checked_add(cells).is_none()
        || cells
            .checked_mul(cell_bytes)
            .is_some_and(|bytes| before.clear_bytes.checked_add(bytes).is_none())
}

fn reset_is_matching_noop(
    reset: &OperationSessionResetAttemptReceipt,
    terminal: OperationSessionTerminal,
) -> bool {
    reset.prospective.is_none()
        && reset.terminal == terminal
        && reset.actual.work == 0
        && reset.actual.counters_before == reset.actual.counters_after
        && reset.all_leaves_before == reset.all_leaves_after
}

fn execution_preflight_first_refusal(
    limits: OperationSessionRunLimits,
    prospective: OperationSessionExecutionProspective,
) -> Option<OperationSessionResource> {
    limits
        .first_refusal(prospective)
        .or_else(|| (prospective.allocations != 0).then_some(OperationSessionResource::Allocations))
}

fn execution_actual_admitted(
    limits: OperationSessionRunLimits,
    prospective: OperationSessionExecutionProspective,
    actual: OperationSessionExecutionActual,
) -> bool {
    prospective.contains_actual(actual)
        && actual.allocations == 0
        && limits
            .first_refusal(execution_actual_as_prospective(actual))
            .is_none()
}

fn execution_actual_as_prospective(
    actual: OperationSessionExecutionActual,
) -> OperationSessionExecutionProspective {
    OperationSessionExecutionProspective {
        work: actual.work,
        source_accesses: actual.source_accesses,
        transitions: actual.transitions,
        candidates: actual.candidates,
        cache_misses: actual.cache_misses,
        history_nodes: actual.history_nodes,
        line_domains: actual.line_domains,
        output_events: actual.output_events,
        selected_span_bytes: actual.selected_span_bytes,
        participation_entries: actual.participation_entries,
        allocations: actual.allocations,
    }
}

fn execution_actual_first_refusal(
    limits: OperationSessionRunLimits,
    prospective: OperationSessionExecutionProspective,
    actual: OperationSessionExecutionActual,
) -> Option<OperationSessionResource> {
    let upper = OperationSessionRunLimits::exact(prospective);
    upper
        .first_refusal(execution_actual_as_prospective(actual))
        .or_else(|| limits.first_refusal(execution_actual_as_prospective(actual)))
        .or_else(|| (actual.allocations != 0).then_some(OperationSessionResource::Allocations))
}

fn attempted_operation_actual(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
    actual: OperationSessionExecutionActual,
    evidence: &OperationSessionAttemptEvidence,
) -> Option<OperationSessionExecutionActual> {
    if attempted_operation_proves_reducer_mismatch(leaf, reducer, evidence)
        || attempted_operation_proves_invalid_order(leaf, reducer, invocation, evidence)
    {
        return None;
    }
    let mut next = actual;
    match evidence.attempted_operation {
        OperationSessionAttemptedOperation::Meter { resource, amount } => {
            let dimension = execution_dimension_mut(&mut next, resource)?;
            *dimension = dimension.checked_add(amount)?;
        }
        OperationSessionAttemptedOperation::Span { start, end, .. } => {
            let width = u64::try_from(end.checked_sub(start)?).ok()?;
            next.output_events = next.output_events.checked_add(1)?;
            next.selected_span_bytes = next.selected_span_bytes.checked_add(width)?;
        }
        OperationSessionAttemptedOperation::EmitParticipation { entries } => {
            next.output_events = next.output_events.checked_add(1)?;
            next.participation_entries = next.participation_entries.checked_add(entries)?;
        }
        OperationSessionAttemptedOperation::LineDomain { .. } => {
            next.line_domains = next.line_domains.checked_add(1)?;
            next.output_events = next.output_events.checked_add(1)?;
        }
        OperationSessionAttemptedOperation::None
        | OperationSessionAttemptedOperation::ObserveParticipation { .. }
        | OperationSessionAttemptedOperation::Finish { .. }
        | OperationSessionAttemptedOperation::ExecutionFailure { .. } => return None,
    }
    Some(next)
}

fn attempted_operation_proves_invalid_order(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    match evidence.attempted_operation {
        OperationSessionAttemptedOperation::Span {
            start,
            end,
            pattern_ordinal,
        } if span_method_matches(leaf, reducer) => {
            (leaf == OperationSessionLeaf::MultiCapture && pattern_ordinal.is_none())
                || start > end
                || start < invocation.range.start
                || end > invocation.range.end
                || evidence
                    .last_span
                    .is_some_and(|(last_start, last_end, last_pattern)| {
                        start < last_end
                            || start < last_start
                            || (start == last_start && pattern_ordinal <= last_pattern)
                    })
        }
        OperationSessionAttemptedOperation::ObserveParticipation {
            start,
            end,
            pattern_ordinal,
        } if participation_method_matches(leaf, reducer) => {
            evidence.pending_participation.is_some()
                || start > end
                || start < invocation.range.start
                || end > invocation.range.end
                || evidence.last_participation.is_some_and(
                    |(last_start, last_end, last_pattern)| {
                        start < last_end
                            || start < last_start
                            || (start == last_start && Some(pattern_ordinal) <= last_pattern)
                    },
                )
        }
        OperationSessionAttemptedOperation::EmitParticipation { .. }
            if participation_method_matches(leaf, reducer) =>
        {
            evidence.pending_participation.is_none()
        }
        OperationSessionAttemptedOperation::LineDomain { line_ordinal }
            if line_method_matches(leaf, reducer) =>
        {
            evidence
                .last_line_ordinal
                .is_some_and(|last| line_ordinal <= last)
        }
        OperationSessionAttemptedOperation::Finish { .. } => {
            evidence.pending_participation.is_some()
        }
        _ => false,
    }
}

fn attempted_operation_proves_arithmetic_overflow(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
    actual: OperationSessionExecutionActual,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    if attempted_operation_proves_reducer_mismatch(leaf, reducer, evidence)
        || attempted_operation_proves_invalid_order(leaf, reducer, invocation, evidence)
    {
        return false;
    }
    match evidence.attempted_operation {
        OperationSessionAttemptedOperation::Meter { resource, amount } => {
            execution_dimension(actual, resource)
                .is_some_and(|value| value.checked_add(amount).is_none())
        }
        OperationSessionAttemptedOperation::Span { start, end, .. } => {
            let Some(width) = end
                .checked_sub(start)
                .and_then(|width| u64::try_from(width).ok())
            else {
                return true;
            };
            actual.output_events.checked_add(1).is_none()
                || actual.selected_span_bytes.checked_add(width).is_none()
        }
        OperationSessionAttemptedOperation::EmitParticipation { entries } => {
            actual.output_events.checked_add(1).is_none()
                || actual.participation_entries.checked_add(entries).is_none()
        }
        OperationSessionAttemptedOperation::LineDomain { .. } => {
            actual.line_domains.checked_add(1).is_none()
                || actual.output_events.checked_add(1).is_none()
        }
        OperationSessionAttemptedOperation::None
        | OperationSessionAttemptedOperation::ObserveParticipation { .. }
        | OperationSessionAttemptedOperation::Finish { .. }
        | OperationSessionAttemptedOperation::ExecutionFailure { .. } => false,
    }
}

fn attempted_operation_proves_reducer_mismatch(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    match evidence.attempted_operation {
        OperationSessionAttemptedOperation::Span { .. } => !span_method_matches(leaf, reducer),
        OperationSessionAttemptedOperation::ObserveParticipation { .. }
        | OperationSessionAttemptedOperation::EmitParticipation { .. } => {
            !participation_method_matches(leaf, reducer)
        }
        OperationSessionAttemptedOperation::LineDomain { .. } => {
            !line_method_matches(leaf, reducer)
        }
        OperationSessionAttemptedOperation::Finish { reducer: attempted } => {
            evidence.pending_participation.is_none() && attempted != reducer
        }
        OperationSessionAttemptedOperation::None
        | OperationSessionAttemptedOperation::Meter { .. }
        | OperationSessionAttemptedOperation::ExecutionFailure { .. } => false,
    }
}

fn span_method_matches(leaf: OperationSessionLeaf, reducer: OperationSessionReducer) -> bool {
    leaf != OperationSessionLeaf::Grep
        && matches!(
            reducer,
            OperationSessionReducer::Count | OperationSessionReducer::SpanSum
        )
}

fn participation_method_matches(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
) -> bool {
    leaf == OperationSessionLeaf::MultiCapture && reducer == OperationSessionReducer::Participation
}

fn line_method_matches(leaf: OperationSessionLeaf, reducer: OperationSessionReducer) -> bool {
    leaf == OperationSessionLeaf::Grep && reducer == OperationSessionReducer::Count
}

fn execution_dimension(
    actual: OperationSessionExecutionActual,
    resource: OperationSessionResource,
) -> Option<u64> {
    match resource {
        OperationSessionResource::ExecutionWork => Some(actual.work),
        OperationSessionResource::SourceAccesses => Some(actual.source_accesses),
        OperationSessionResource::Transitions => Some(actual.transitions),
        OperationSessionResource::Candidates => Some(actual.candidates),
        OperationSessionResource::CacheMisses => Some(actual.cache_misses),
        OperationSessionResource::HistoryNodes => Some(actual.history_nodes),
        _ => None,
    }
}

fn execution_dimension_mut(
    actual: &mut OperationSessionExecutionActual,
    resource: OperationSessionResource,
) -> Option<&mut u64> {
    match resource {
        OperationSessionResource::ExecutionWork => Some(&mut actual.work),
        OperationSessionResource::SourceAccesses => Some(&mut actual.source_accesses),
        OperationSessionResource::Transitions => Some(&mut actual.transitions),
        OperationSessionResource::Candidates => Some(&mut actual.candidates),
        OperationSessionResource::CacheMisses => Some(&mut actual.cache_misses),
        OperationSessionResource::HistoryNodes => Some(&mut actual.history_nodes),
        _ => None,
    }
}

fn execution_evidence_closes(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
    actual: OperationSessionExecutionActual,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    evidence.refused_actual.is_none()
        && evidence.pending_participation.is_none()
        && evidence.attempted_operation == OperationSessionAttemptedOperation::None
        && evidence.failure == OperationSessionFailureEvidence::None
        && execution_failure_evidence_closes(leaf, reducer, invocation, actual, evidence)
}

fn execution_failure_evidence_closes(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
    actual: OperationSessionExecutionActual,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    if (evidence.failure == OperationSessionFailureEvidence::InvalidOrder) == evidence.order_valid
        || evidence.attempted_identity.is_some()
        || evidence.first_span.is_some() != (evidence.span_events != 0)
        || evidence.last_span.is_some() != (evidence.span_events != 0)
        || evidence.first_participation.is_some() != (evidence.participation_events != 0)
        || evidence.last_participation.is_some() != (evidence.participation_events != 0)
        || evidence.first_line_ordinal.is_some() != (evidence.line_events != 0)
        || evidence.last_line_ordinal.is_some() != (evidence.line_events != 0)
        || evidence
            .first_span
            .zip(evidence.last_span)
            .is_some_and(|(first, last)| {
                first.0 < invocation.range.start
                    || first.1 > invocation.range.end
                    || last.0 < invocation.range.start
                    || last.1 > invocation.range.end
                    || first.0 > last.0
                    || first.1 < first.0
                    || last.1 < last.0
                    || (evidence.span_events > 1 && first.1 > last.0)
                    || (evidence.span_events > 1 && first.0 == last.0 && first.2 >= last.2)
            })
        || evidence
            .first_line_ordinal
            .zip(evidence.last_line_ordinal)
            .is_some_and(|(first, last)| {
                first > last || (evidence.line_events > 1 && first == last)
            })
        || !ordered_observations_close(
            evidence.first_participation,
            evidence.last_participation,
            evidence.participation_events,
            invocation,
        )
        || !pending_participation_closes(
            leaf,
            reducer,
            evidence.last_participation,
            evidence.pending_participation,
            invocation,
        )
        || evidence.line_events != actual.line_domains
    {
        return false;
    }
    match (leaf, reducer) {
        (OperationSessionLeaf::Grep, OperationSessionReducer::Count) => {
            evidence.line_events == actual.output_events
                && evidence.span_events == 0
                && evidence.participation_events == 0
                && actual.selected_span_bytes == 0
                && actual.participation_entries == 0
        }
        (
            OperationSessionLeaf::MultiCapture,
            OperationSessionReducer::Count | OperationSessionReducer::SpanSum,
        ) => {
            evidence.span_events == actual.output_events
                && evidence
                    .first_span
                    .is_none_or(|observation| observation.2.is_some())
                && evidence
                    .last_span
                    .is_none_or(|observation| observation.2.is_some())
                && evidence.line_events == 0
                && evidence.participation_events == 0
                && actual.participation_entries == 0
        }
        (_, OperationSessionReducer::Count | OperationSessionReducer::SpanSum) => {
            evidence.span_events == actual.output_events
                && evidence.line_events == 0
                && evidence.participation_events == 0
                && actual.participation_entries == 0
        }
        (_, OperationSessionReducer::Participation) => {
            evidence.participation_events == actual.output_events
                && evidence
                    .first_participation
                    .is_none_or(|observation| observation.2.is_some())
                && evidence
                    .last_participation
                    .is_none_or(|observation| observation.2.is_some())
                && evidence.span_events == 0
                && evidence.line_events == 0
                && actual.selected_span_bytes == 0
        }
    }
}

fn grep_execution_failure_evidence_closes(
    failure: OperationSessionExecutionFailure,
    invocation: &OperationSessionInvocation,
    actual: OperationSessionExecutionActual,
    evidence: &OperationSessionAttemptEvidence,
) -> bool {
    let line_count_closes = match failure {
        OperationSessionExecutionFailure::Engine => {
            evidence.line_events == actual.line_domains
                && evidence.line_events == actual.output_events
        }
        OperationSessionExecutionFailure::Observer => evidence
            .line_events
            .checked_add(1)
            .is_some_and(|events| events == actual.line_domains && events == actual.output_events),
        OperationSessionExecutionFailure::Protocol => {
            evidence.line_events <= actual.line_domains
                && evidence.line_events <= actual.output_events
        }
    };
    line_count_closes
        && evidence.attempted_identity.is_none()
        && evidence.pending_participation.is_none()
        && evidence.first_span.is_none()
        && evidence.last_span.is_none()
        && evidence.span_events == 0
        && evidence.first_participation.is_none()
        && evidence.last_participation.is_none()
        && evidence.participation_events == 0
        && evidence.first_line_ordinal.is_some() == (evidence.line_events != 0)
        && evidence.last_line_ordinal.is_some() == (evidence.line_events != 0)
        && evidence
            .first_line_ordinal
            .zip(evidence.last_line_ordinal)
            .is_none_or(|(first, last)| {
                first <= last
                    && (evidence.line_events <= 1 || first < last)
                    && last < invocation.haystack_len
            })
        && evidence.order_valid
        && actual.selected_span_bytes == 0
        && actual.participation_entries == 0
        && actual.allocations == 0
}

fn pending_participation_closes(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    last: Option<(usize, usize, Option<usize>)>,
    pending: Option<(usize, usize, usize)>,
    invocation: &OperationSessionInvocation,
) -> bool {
    let Some((start, end, pattern)) = pending else {
        return true;
    };
    if leaf != OperationSessionLeaf::MultiCapture
        || reducer != OperationSessionReducer::Participation
        || start > end
        || start < invocation.range.start
        || end > invocation.range.end
    {
        return false;
    }
    last.is_none_or(|(last_start, last_end, last_pattern)| {
        start >= last_end
            && start >= last_start
            && (start != last_start || Some(pattern) > last_pattern)
    })
}

fn ordered_observations_close(
    first: Option<(usize, usize, Option<usize>)>,
    last: Option<(usize, usize, Option<usize>)>,
    events: u64,
    invocation: &OperationSessionInvocation,
) -> bool {
    match (first, last, events) {
        (None, None, 0) => true,
        (Some(first), Some(last), 1) => {
            first == last
                && first.0 <= first.1
                && first.0 >= invocation.range.start
                && first.1 <= invocation.range.end
        }
        (Some(first), Some(last), events) if events > 1 => {
            first.0 <= first.1
                && last.0 <= last.1
                && first.0 >= invocation.range.start
                && first.1 <= invocation.range.end
                && last.0 >= invocation.range.start
                && last.1 <= invocation.range.end
                && first.1 <= last.0
                && (first.0 != last.0 || first.2 < last.2)
        }
        _ => false,
    }
}

fn construction_actual_within(
    prospective: &OperationSessionConstructionProspective,
    actual: &OperationSessionConstructionActual,
) -> bool {
    prospective.aggregate.contains_actual(actual.aggregate)
        && prospective
            .leaves
            .iter()
            .zip(actual.leaves.iter())
            .all(|(prospective, actual)| prospective.contains_actual(*actual))
}

fn construction_aggregate_closes(
    prospective: &OperationSessionConstructionProspective,
    actual: &OperationSessionConstructionActual,
) -> bool {
    aggregate_prospective(prospective.leaves) == Some(prospective.aggregate)
        && aggregate_actual(actual.leaves) == Some(actual.aggregate)
}

pub(crate) fn aggregate_prospective(
    leaves: [OperationSessionStorageProspective; 4],
) -> Option<OperationSessionStorageProspective> {
    let mut aggregate = OperationSessionStorageProspective::default();
    for leaf in leaves {
        aggregate.build_work = aggregate.build_work.checked_add(leaf.build_work)?;
        aggregate.persistent_bytes = aggregate
            .persistent_bytes
            .checked_add(leaf.persistent_bytes)?;
        aggregate.scratch_bytes = aggregate.scratch_bytes.checked_add(leaf.scratch_bytes)?;
        aggregate.generation_cells = aggregate
            .generation_cells
            .checked_add(leaf.generation_cells)?;
        aggregate.initialized_bytes = aggregate
            .initialized_bytes
            .checked_add(leaf.initialized_bytes)?;
        aggregate.allocation_attempts = aggregate
            .allocation_attempts
            .checked_add(leaf.allocation_attempts)?;
    }
    aggregate.peak_bytes = aggregate
        .persistent_bytes
        .checked_add(aggregate.scratch_bytes)?;
    Some(aggregate)
}

fn aggregate_actual(
    leaves: [OperationSessionStorageActual; 4],
) -> Option<OperationSessionStorageActual> {
    let prospective = leaves.map(|leaf| OperationSessionStorageProspective {
        build_work: leaf.build_work,
        persistent_bytes: leaf.persistent_bytes,
        scratch_bytes: leaf.scratch_bytes,
        peak_bytes: leaf.peak_bytes,
        generation_cells: leaf.generation_cells,
        initialized_bytes: leaf.initialized_bytes,
        allocation_attempts: leaf.allocation_attempts,
    });
    let value = aggregate_prospective(prospective)?;
    Some(value.into())
}

pub(crate) fn reset_limits_first_refusal(
    limits: OperationSessionResetLimits,
    prospective: OperationSessionResetProspective,
) -> Option<OperationSessionResource> {
    let Some(clear_cells_u64) = prospective
        .counters_after
        .clear_cells
        .checked_sub(prospective.counters_before.clear_cells)
    else {
        return Some(OperationSessionResource::ClearCells);
    };
    let Ok(clear_cells) = usize::try_from(clear_cells_u64) else {
        return Some(OperationSessionResource::ClearCells);
    };
    let Some(clear_bytes_u64) = prospective
        .counters_after
        .clear_bytes
        .checked_sub(prospective.counters_before.clear_bytes)
    else {
        return Some(OperationSessionResource::ClearBytes);
    };
    let Ok(clear_bytes) = usize::try_from(clear_bytes_u64) else {
        return Some(OperationSessionResource::ClearBytes);
    };
    if prospective.work > limits.max_work {
        Some(OperationSessionResource::ResetWork)
    } else if clear_cells > limits.max_clear_cells {
        Some(OperationSessionResource::ClearCells)
    } else if clear_bytes > limits.max_clear_bytes {
        Some(OperationSessionResource::ClearBytes)
    } else {
        None
    }
}

fn reset_limits_contain(
    limits: OperationSessionResetLimits,
    prospective: OperationSessionResetProspective,
) -> bool {
    reset_limits_first_refusal(limits, prospective).is_none()
}

fn reset_leaf_isolated(
    leaf: OperationSessionLeaf,
    before: [OperationSessionLeafCounters; 4],
    after: [OperationSessionLeafCounters; 4],
) -> bool {
    OperationSessionLeaf::ORDERED.iter().all(|candidate| {
        *candidate == leaf || before[candidate.index()] == after[candidate.index()]
    })
}

fn value_closes(
    reducer: OperationSessionReducer,
    value: OperationSessionValue,
    actual: OperationSessionExecutionActual,
) -> bool {
    match (reducer, value) {
        (OperationSessionReducer::Count, OperationSessionValue::Count(value)) => {
            value == actual.output_events
        }
        (OperationSessionReducer::SpanSum, OperationSessionValue::SpanSum(value)) => {
            value == actual.selected_span_bytes
        }
        (OperationSessionReducer::Participation, OperationSessionValue::Participation(value)) => {
            value == actual.participation_entries
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "adversarial receipt copies mutate one small test-record field at a time"
)]
mod tests {
    use super::*;

    fn storage(value: usize) -> OperationSessionStorageProspective {
        let bytes = value * core::mem::size_of::<u64>();
        OperationSessionStorageProspective {
            build_work: u64::try_from(value + usize::from(value != 0)).unwrap(),
            persistent_bytes: bytes,
            scratch_bytes: 0,
            peak_bytes: bytes,
            generation_cells: value,
            initialized_bytes: bytes,
            allocation_attempts: usize::from(value != 0),
        }
    }

    fn construction() -> OperationSessionConstructionReceipt {
        let leaves_p = [storage(1), storage(2), storage(3), storage(4)];
        let prospective = OperationSessionConstructionProspective {
            aggregate: aggregate_prospective(leaves_p).unwrap(),
            leaves: leaves_p,
        };
        let leaves_a = leaves_p.map(Into::into);
        let actual = OperationSessionConstructionActual {
            aggregate: aggregate_actual(leaves_a).unwrap(),
            leaves: leaves_a,
        };
        let identities = [
            (
                OperationSessionLeaf::Search,
                super::super::search::ALGORITHM_VERSION,
                super::super::search::ACCOUNTING_VERSION,
                super::super::search::ACCOUNTING_ID,
            ),
            (
                OperationSessionLeaf::Hot,
                super::super::hot::ALGORITHM_VERSION,
                super::super::hot::ACCOUNTING_VERSION,
                super::super::hot::ACCOUNTING_ID,
            ),
            (
                OperationSessionLeaf::MultiCapture,
                super::super::multi_capture::ALGORITHM_VERSION,
                super::super::multi_capture::ACCOUNTING_VERSION,
                super::super::multi_capture::ACCOUNTING_ID,
            ),
            (
                OperationSessionLeaf::Grep,
                super::super::grep::ALGORITHM_VERSION,
                super::super::grep::ACCOUNTING_VERSION,
                super::super::grep::ACCOUNTING_ID,
            ),
        ];
        let leaves = core::array::from_fn(|index| {
            let (leaf, algorithm, accounting, id) = identities[index];
            OperationSessionLeafConstructionReceipt {
                leaf,
                layout_id: [u8::try_from(index + 1).unwrap(); 16],
                leaf_algorithm_version: algorithm,
                leaf_accounting_version: accounting,
                leaf_accounting_id: id,
                prospective: leaves_p[index],
                actual: leaves_a[index],
            }
        });
        let expected_layouts = leaves.map(|leaf| leaf.layout_id);
        OperationSessionConstructionReceipt::new(
            OperationSessionConstructionLimits::exact(&prospective),
            prospective,
            actual,
            leaves,
            expected_layouts,
        )
    }

    fn reset() -> OperationSessionResetAttemptReceipt {
        let before = OperationSessionLeafCounters::default();
        let after = OperationSessionLeafCounters {
            generation: 1,
            reset_invocations: 1,
            ..before
        };
        let prospective = OperationSessionResetProspective {
            leaf: OperationSessionLeaf::Search,
            counters_before: before,
            counters_after: after,
            required_generations: 1,
            work: 1,
        };
        let mut all_after = [before; 4];
        all_after[OperationSessionLeaf::Search.index()] = after;
        OperationSessionResetAttemptReceipt::new(
            [1; 16],
            3,
            OperationSessionResetLimits::exact(&prospective).unwrap(),
            Some(prospective),
            prospective.into(),
            [before; 4],
            all_after,
            OperationSessionTerminal::Success,
        )
    }

    fn identity(
        leaf: OperationSessionLeaf,
        reducer: OperationSessionReducer,
    ) -> OperationSessionRouteIdentity {
        let (source_identity, order_identity, fallback_identity) =
            super::super::route_contract(leaf, reducer);
        let (algorithm, accounting, id) = match leaf {
            OperationSessionLeaf::Search => (
                super::super::search::ALGORITHM_VERSION,
                super::super::search::ACCOUNTING_VERSION,
                super::super::search::ACCOUNTING_ID,
            ),
            OperationSessionLeaf::Hot => (
                super::super::hot::ALGORITHM_VERSION,
                super::super::hot::ACCOUNTING_VERSION,
                super::super::hot::ACCOUNTING_ID,
            ),
            OperationSessionLeaf::MultiCapture => (
                super::super::multi_capture::ALGORITHM_VERSION,
                super::super::multi_capture::ACCOUNTING_VERSION,
                super::super::multi_capture::ACCOUNTING_ID,
            ),
            OperationSessionLeaf::Grep => (
                super::super::grep::ALGORITHM_VERSION,
                super::super::grep::ACCOUNTING_VERSION,
                super::super::grep::ACCOUNTING_ID,
            ),
        };
        OperationSessionRouteIdentity {
            session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
            session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
            leaf,
            reducer,
            compiled_plan_id: [9; 16],
            source_identity,
            order_identity,
            fallback_identity,
            leaf_algorithm_version: algorithm,
            leaf_accounting_version: accounting,
            leaf_accounting_id: id,
        }
    }

    fn attempt() -> OperationSessionAttemptReceipt {
        let identity = identity(OperationSessionLeaf::Search, OperationSessionReducer::Count);
        let invocation = OperationSessionInvocation {
            haystack_len: 4,
            range: 0..4,
            required_generations: 1,
        };
        let prospective = OperationSessionExecutionProspective {
            output_events: 1,
            selected_span_bytes: 2,
            ..OperationSessionExecutionProspective::default()
        };
        let actual = OperationSessionExecutionActual {
            output_events: 1,
            selected_span_bytes: 2,
            ..OperationSessionExecutionActual::default()
        };
        let mut evidence = OperationSessionAttemptEvidence::empty();
        evidence.first_span = Some((0, 2, None));
        evidence.last_span = evidence.first_span;
        evidence.span_events = 1;
        OperationSessionAttemptReceipt::new(
            identity,
            identity,
            invocation,
            OperationSessionRunLimits::exact(prospective),
            [1; 16],
            reset(),
            Some(prospective),
            actual,
            Some(OperationSessionValue::Count(1)),
            OperationSessionTerminal::Success,
            evidence,
        )
    }

    fn multi_capture_attempt(reducer: OperationSessionReducer) -> OperationSessionAttemptReceipt {
        let identity = identity(OperationSessionLeaf::MultiCapture, reducer);
        let invocation = OperationSessionInvocation {
            haystack_len: 4,
            range: 0..4,
            required_generations: 1,
        };
        let prospective = OperationSessionExecutionProspective {
            output_events: 1,
            selected_span_bytes: 2,
            ..OperationSessionExecutionProspective::default()
        };
        let actual = OperationSessionExecutionActual {
            output_events: 1,
            selected_span_bytes: 2,
            ..OperationSessionExecutionActual::default()
        };
        let before = OperationSessionLeafCounters::default();
        let after = OperationSessionLeafCounters {
            generation: 1,
            reset_invocations: 1,
            ..before
        };
        let reset_prospective = OperationSessionResetProspective {
            leaf: OperationSessionLeaf::MultiCapture,
            counters_before: before,
            counters_after: after,
            required_generations: 1,
            work: 1,
        };
        let mut all_after = [before; 4];
        all_after[OperationSessionLeaf::MultiCapture.index()] = after;
        let reset = OperationSessionResetAttemptReceipt::new(
            [3; 16],
            3,
            OperationSessionResetLimits::exact(&reset_prospective).unwrap(),
            Some(reset_prospective),
            reset_prospective.into(),
            [before; 4],
            all_after,
            OperationSessionTerminal::Success,
        );
        let mut evidence = OperationSessionAttemptEvidence::empty();
        evidence.first_span = Some((0, 2, Some(0)));
        evidence.last_span = evidence.first_span;
        evidence.span_events = 1;
        let value = match reducer {
            OperationSessionReducer::Count => OperationSessionValue::Count(1),
            OperationSessionReducer::SpanSum => OperationSessionValue::SpanSum(2),
            OperationSessionReducer::Participation => unreachable!(),
        };
        OperationSessionAttemptReceipt::new(
            identity,
            identity,
            invocation,
            OperationSessionRunLimits::exact(prospective),
            [3; 16],
            reset,
            Some(prospective),
            actual,
            Some(value),
            OperationSessionTerminal::Success,
            evidence,
        )
    }

    fn mutate_storage_p(value: &mut OperationSessionStorageProspective, field: usize) {
        match field {
            0 => value.build_work += 1,
            1 => value.persistent_bytes += 1,
            2 => value.scratch_bytes += 1,
            3 => value.peak_bytes += 1,
            4 => value.generation_cells += 1,
            5 => value.initialized_bytes += 1,
            6 => value.allocation_attempts += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_storage_a(value: &mut OperationSessionStorageActual, field: usize) {
        match field {
            0 => value.build_work += 1,
            1 => value.persistent_bytes += 1,
            2 => value.scratch_bytes += 1,
            3 => value.peak_bytes += 1,
            4 => value.generation_cells += 1,
            5 => value.initialized_bytes += 1,
            6 => value.allocation_attempts += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_construction_limit(value: &mut OperationSessionConstructionLimits, field: usize) {
        match field {
            0 => value.max_build_work += 1,
            1 => value.max_persistent_bytes += 1,
            2 => value.max_scratch_bytes += 1,
            3 => value.max_peak_bytes += 1,
            4 => value.max_generation_cells += 1,
            5 => value.max_initialized_bytes += 1,
            6 => value.max_allocation_attempts += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_counters(value: &mut OperationSessionLeafCounters, field: usize) {
        match field {
            0 => value.generation += 1,
            1 => value.reset_invocations += 1,
            2 => value.rollovers += 1,
            3 => value.clears += 1,
            4 => value.clear_cells += 1,
            5 => value.clear_bytes += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_execution_p(value: &mut OperationSessionExecutionProspective, field: usize) {
        match field {
            0 => value.work += 1,
            1 => value.source_accesses += 1,
            2 => value.transitions += 1,
            3 => value.candidates += 1,
            4 => value.cache_misses += 1,
            5 => value.history_nodes += 1,
            6 => value.line_domains += 1,
            7 => value.output_events += 1,
            8 => value.selected_span_bytes += 1,
            9 => value.participation_entries += 1,
            10 => value.allocations += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_execution_a(value: &mut OperationSessionExecutionActual, field: usize) {
        match field {
            0 => value.work += 1,
            1 => value.source_accesses += 1,
            2 => value.transitions += 1,
            3 => value.candidates += 1,
            4 => value.cache_misses += 1,
            5 => value.history_nodes += 1,
            6 => value.line_domains += 1,
            7 => value.output_events += 1,
            8 => value.selected_span_bytes += 1,
            9 => value.participation_entries += 1,
            10 => value.allocations += 1,
            _ => unreachable!(),
        }
    }

    fn mutate_run_limit(value: &mut OperationSessionRunLimits, field: usize) {
        match field {
            0 => value.max_work += 1,
            1 => value.max_source_accesses += 1,
            2 => value.max_transitions += 1,
            3 => value.max_candidates += 1,
            4 => value.max_cache_misses += 1,
            5 => value.max_history_nodes += 1,
            6 => value.max_line_domains += 1,
            7 => value.max_output_events += 1,
            8 => value.max_selected_span_bytes += 1,
            9 => value.max_participation_entries += 1,
            10 => value.max_allocations += 1,
            _ => unreachable!(),
        }
    }

    #[test]
    fn construction_public_field_mutations_swaps_and_duplicate_layouts_reject() {
        let receipt = construction();
        assert!(receipt.closes());
        let mut mutations = Vec::new();

        let mut changed = receipt.clone();
        changed.schema_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.accounting_id = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.limits.max_build_work += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.prospective.aggregate.build_work += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.actual.aggregate.build_work -= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].layout_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].leaf_algorithm_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].leaf_accounting_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].leaf_accounting_id = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].prospective.build_work += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].actual.build_work -= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.leaves[0].leaf = OperationSessionLeaf::Hot;
        mutations.push(changed);
        for field in 0..7 {
            let mut changed = receipt.clone();
            mutate_construction_limit(&mut changed.limits, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_p(&mut changed.prospective.aggregate, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_a(&mut changed.actual.aggregate, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_p(&mut changed.prospective.leaves[0], field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_a(&mut changed.actual.leaves[0], field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_p(&mut changed.leaves[0].prospective, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_storage_a(&mut changed.leaves[0].actual, field);
            mutations.push(changed);
        }
        assert!(mutations.iter().all(|changed| !changed.closes()));

        let mut swapped = receipt.leaves;
        swapped.swap(0, 1);
        let forged = OperationSessionConstructionReceipt::new(
            receipt.limits,
            receipt.prospective,
            receipt.actual,
            swapped,
            receipt.authentication.expected_layouts,
        );
        assert!(!forged.closes());
        let mut layout_swapped = receipt.leaves;
        let search_layout = layout_swapped[0].layout_id;
        layout_swapped[0].layout_id = layout_swapped[1].layout_id;
        layout_swapped[1].layout_id = search_layout;
        let forged = OperationSessionConstructionReceipt::new(
            receipt.limits,
            receipt.prospective,
            receipt.actual,
            layout_swapped,
            layout_swapped.map(|leaf| leaf.layout_id),
        );
        assert!(!forged.closes());
        let mut duplicate = receipt.leaves;
        duplicate[1].layout_id = duplicate[0].layout_id;
        let forged = OperationSessionConstructionReceipt::new(
            receipt.limits,
            receipt.prospective,
            receipt.actual,
            duplicate,
            receipt.authentication.expected_layouts,
        );
        assert!(!forged.closes());
    }

    #[test]
    fn reset_public_mutations_and_coherent_wrong_resource_reject() {
        let receipt = reset();
        assert!(receipt.closes());
        let mut mutations = Vec::new();
        let mut changed = receipt.clone();
        changed.schema_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.layout_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.limits.max_work += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.prospective.as_mut().unwrap().work += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.actual.work = 0;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.all_leaves_before[0].generation += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.all_leaves_after[0].generation += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.terminal = OperationSessionTerminal::ArithmeticOverflow;
        mutations.push(changed);
        for field in 0..3 {
            let mut changed = receipt.clone();
            match field {
                0 => changed.limits.max_work += 1,
                1 => changed.limits.max_clear_cells += 1,
                2 => changed.limits.max_clear_bytes += 1,
                _ => unreachable!(),
            }
            mutations.push(changed);
        }
        let mut changed = receipt.clone();
        changed.prospective.as_mut().unwrap().leaf = OperationSessionLeaf::Hot;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.prospective.as_mut().unwrap().required_generations += 1;
        mutations.push(changed);
        for field in 0..6 {
            let mut changed = receipt.clone();
            mutate_counters(
                &mut changed.prospective.as_mut().unwrap().counters_before,
                field,
            );
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_counters(
                &mut changed.prospective.as_mut().unwrap().counters_after,
                field,
            );
            mutations.push(changed);
        }
        let mut changed = receipt.clone();
        changed.actual.leaf = OperationSessionLeaf::Hot;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.actual.required_generations += 1;
        mutations.push(changed);
        for field in 0..6 {
            let mut changed = receipt.clone();
            mutate_counters(&mut changed.actual.counters_before, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_counters(&mut changed.actual.counters_after, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_counters(&mut changed.all_leaves_before[0], field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_counters(&mut changed.all_leaves_after[0], field);
            mutations.push(changed);
        }
        assert!(mutations.iter().all(|changed| !changed.closes()));

        let prospective = receipt.prospective.unwrap();
        let limits = OperationSessionResetLimits {
            max_work: 0,
            max_clear_cells: 0,
            max_clear_bytes: 0,
        };
        let before = receipt.all_leaves_before;
        let forged = OperationSessionResetAttemptReceipt::new(
            receipt.layout_id,
            3,
            limits,
            Some(prospective),
            OperationSessionResetActual {
                leaf: prospective.leaf,
                counters_before: prospective.counters_before,
                counters_after: prospective.counters_before,
                required_generations: prospective.required_generations,
                work: 0,
            },
            before,
            before,
            OperationSessionTerminal::Refused(OperationSessionResource::ClearCells),
        );
        assert!(!forged.closes());
        let mut hot_layout = receipt.layout_id;
        hot_layout[15] = 2;
        let forged = OperationSessionResetAttemptReceipt::new(
            hot_layout,
            3,
            receipt.limits,
            receipt.prospective,
            receipt.actual,
            receipt.all_leaves_before,
            receipt.all_leaves_after,
            receipt.terminal,
        );
        assert!(!forged.closes());
    }

    #[test]
    fn attempt_public_mutations_cross_bindings_and_allocation_counter_reject() {
        let receipt = attempt();
        assert!(receipt.closes());
        let mut mutations = Vec::new();
        let mut changed = receipt.clone();
        changed.schema_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.source_identity = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.order_identity = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.fallback_identity = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.compiled_plan_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.session_accounting_id = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.session_algorithm_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.session_accounting_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.leaf = OperationSessionLeaf::Hot;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.reducer = OperationSessionReducer::SpanSum;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.leaf_algorithm_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.leaf_accounting_version += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.identity.leaf_accounting_id = "wrong";
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.invocation.haystack_len += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.invocation.range.start += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.invocation.range.end -= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.invocation.required_generations += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.limits.max_output_events += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.construction_layout_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.reset.layout_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.prospective.as_mut().unwrap().output_events += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.actual.output_events += 1;
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.value = Some(OperationSessionValue::SpanSum(1));
        mutations.push(changed);
        let mut changed = receipt.clone();
        changed.terminal = OperationSessionTerminal::ArithmeticOverflow;
        mutations.push(changed);
        for field in 0..11 {
            let mut changed = receipt.clone();
            mutate_run_limit(&mut changed.limits, field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_execution_p(changed.prospective.as_mut().unwrap(), field);
            mutations.push(changed);
            let mut changed = receipt.clone();
            mutate_execution_a(&mut changed.actual, field);
            mutations.push(changed);
        }
        assert!(mutations.iter().all(|changed| !changed.closes()));

        let selected_identity = receipt.identity;
        let mut prospective = receipt.prospective.unwrap();
        prospective.allocations = 1;
        let mut actual = receipt.actual;
        actual.allocations = 1;
        let forged = OperationSessionAttemptReceipt::new(
            selected_identity,
            selected_identity,
            receipt.invocation.clone(),
            OperationSessionRunLimits::exact(prospective),
            receipt.construction_layout_id,
            receipt.reset.clone(),
            Some(prospective),
            actual,
            receipt.value,
            OperationSessionTerminal::Success,
            receipt.authentication.evidence,
        );
        assert!(!forged.closes());

        let mut wrong_tag_reset = receipt.reset.clone();
        let mut hot_layout = wrong_tag_reset.layout_id;
        hot_layout[15] = 2;
        wrong_tag_reset = OperationSessionResetAttemptReceipt::new(
            hot_layout,
            3,
            wrong_tag_reset.limits,
            wrong_tag_reset.prospective,
            wrong_tag_reset.actual,
            wrong_tag_reset.all_leaves_before,
            wrong_tag_reset.all_leaves_after,
            wrong_tag_reset.terminal,
        );
        let forged = OperationSessionAttemptReceipt::new(
            selected_identity,
            selected_identity,
            receipt.invocation.clone(),
            receipt.limits,
            hot_layout,
            wrong_tag_reset,
            receipt.prospective,
            receipt.actual,
            receipt.value,
            receipt.terminal,
            receipt.authentication.evidence,
        );
        assert!(!forged.closes());

        let hot = identity(OperationSessionLeaf::Hot, OperationSessionReducer::Count);
        let forged = OperationSessionAttemptReceipt::new(
            hot,
            selected_identity,
            receipt.invocation,
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset,
            receipt.prospective,
            receipt.actual,
            receipt.value,
            receipt.terminal,
            receipt.authentication.evidence,
        );
        assert!(!forged.closes());
    }

    #[test]
    fn coherent_multi_capture_success_requires_pattern_ordinals() {
        for reducer in [
            OperationSessionReducer::Count,
            OperationSessionReducer::SpanSum,
        ] {
            let receipt = multi_capture_attempt(reducer);
            assert!(receipt.closes(), "{reducer:?}");
            let forge = |evidence| {
                OperationSessionAttemptReceipt::new(
                    receipt.identity,
                    receipt.identity,
                    receipt.invocation.clone(),
                    receipt.limits,
                    receipt.construction_layout_id,
                    receipt.reset.clone(),
                    receipt.prospective,
                    receipt.actual,
                    receipt.value,
                    receipt.terminal,
                    evidence,
                )
            };

            let mut first_missing = receipt.authentication.evidence;
            first_missing
                .first_span
                .as_mut()
                .expect("one emitted span")
                .2 = None;
            assert!(!forge(first_missing).closes(), "{reducer:?}");

            let mut last_missing = receipt.authentication.evidence;
            last_missing.last_span.as_mut().expect("one emitted span").2 = None;
            assert!(!forge(last_missing).closes(), "{reducer:?}");

            let mut both_missing = receipt.authentication.evidence;
            both_missing
                .first_span
                .as_mut()
                .expect("one emitted span")
                .2 = None;
            both_missing.last_span.as_mut().expect("one emitted span").2 = None;
            assert!(!forge(both_missing).closes(), "{reducer:?}");
        }
    }

    #[test]
    fn coherent_private_terminal_relabels_reject() {
        let receipt = attempt();
        assert!(receipt.closes());

        let mut stale_success_evidence = receipt.authentication.evidence;
        stale_success_evidence.attempted_operation = OperationSessionAttemptedOperation::Meter {
            resource: OperationSessionResource::ExecutionWork,
            amount: 0,
        };
        let forged = OperationSessionAttemptReceipt::new(
            receipt.identity,
            receipt.identity,
            receipt.invocation.clone(),
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset.clone(),
            receipt.prospective,
            receipt.actual,
            receipt.value,
            OperationSessionTerminal::Success,
            stale_success_evidence,
        );
        assert!(!forged.closes());

        let mut invalid_evidence = receipt.authentication.evidence;
        invalid_evidence.failure = OperationSessionFailureEvidence::InvalidOrder;
        invalid_evidence.order_valid = false;
        invalid_evidence.attempted_operation = OperationSessionAttemptedOperation::Span {
            start: 2,
            end: 3,
            pattern_ordinal: None,
        };
        let forged = OperationSessionAttemptReceipt::new(
            receipt.identity,
            receipt.identity,
            receipt.invocation.clone(),
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset.clone(),
            receipt.prospective,
            receipt.actual,
            None,
            OperationSessionTerminal::InvalidInvocation,
            invalid_evidence,
        );
        assert!(!forged.closes());

        let mut arithmetic_evidence = receipt.authentication.evidence;
        arithmetic_evidence.failure = OperationSessionFailureEvidence::ArithmeticOverflow;
        arithmetic_evidence.attempted_operation = OperationSessionAttemptedOperation::Meter {
            resource: OperationSessionResource::ExecutionWork,
            amount: 1,
        };
        let forged = OperationSessionAttemptReceipt::new(
            receipt.identity,
            receipt.identity,
            receipt.invocation.clone(),
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset.clone(),
            receipt.prospective,
            receipt.actual,
            None,
            OperationSessionTerminal::ArithmeticOverflow,
            arithmetic_evidence,
        );
        assert!(!forged.closes());

        let mut reducer_evidence = receipt.authentication.evidence;
        reducer_evidence.failure = OperationSessionFailureEvidence::ReducerMismatch;
        reducer_evidence.attempted_operation = OperationSessionAttemptedOperation::Span {
            start: 2,
            end: 3,
            pattern_ordinal: None,
        };
        let forged = OperationSessionAttemptReceipt::new(
            receipt.identity,
            receipt.identity,
            receipt.invocation.clone(),
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset.clone(),
            receipt.prospective,
            receipt.actual,
            None,
            OperationSessionTerminal::IdentityMismatch,
            reducer_evidence,
        );
        assert!(!forged.closes());

        let mut refused = receipt.actual;
        refused.output_events += 1;
        let mut refusal_evidence = receipt.authentication.evidence;
        refusal_evidence.failure = OperationSessionFailureEvidence::RefusedActual;
        refusal_evidence.refused_actual = Some(refused);
        refusal_evidence.attempted_operation = OperationSessionAttemptedOperation::Meter {
            resource: OperationSessionResource::ExecutionWork,
            amount: 1,
        };
        let forged = OperationSessionAttemptReceipt::new(
            receipt.identity,
            receipt.identity,
            receipt.invocation,
            receipt.limits,
            receipt.construction_layout_id,
            receipt.reset,
            receipt.prospective,
            receipt.actual,
            None,
            OperationSessionTerminal::Refused(OperationSessionResource::OutputEvents),
            refusal_evidence,
        );
        assert!(!forged.closes());
    }
}
