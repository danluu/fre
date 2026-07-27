//! Grep-stream-lane-owned fixed storage and forced entry stubs.

use fre_exact_alloc::ExactVec;

use super::{
    OPERATION_SESSION_ACCOUNTING_ID, OPERATION_SESSION_ACCOUNTING_VERSION,
    OPERATION_SESSION_ALGORITHM_VERSION, OperationSession, OperationSessionAttempt,
    OperationSessionAttemptError, OperationSessionAttemptRequest, OperationSessionError,
    OperationSessionExecutionActual, OperationSessionExecutionProspective,
    OperationSessionInvocation, OperationSessionLeaf, OperationSessionLeafCounters,
    OperationSessionReducer, OperationSessionResetActual, OperationSessionResetLimits,
    OperationSessionResetProspective, OperationSessionRouteIdentity, OperationSessionRunLimits,
    OperationSessionStorageActual, OperationSessionStorageProspective, SessionLeafSlot,
    allocate_zeroed_cells, apply_leaf_reset, begin_forced_slot, derive_layout_id,
    leaf_reset_prospective, measured_storage_actual, storage_prospective, tag_layout_id,
};
use super::{
    OperationSessionAttemptedOperation, OperationSessionFailureEvidence, OperationSessionTerminal,
    receipt::OperationSessionExecutionFailure,
};

/// Grep slot algorithm version.
pub const ALGORITHM_VERSION: u32 = 1;
/// Grep slot accounting version.
pub const ACCOUNTING_VERSION: u32 = 1;
/// Stable grep slot accounting identity.
pub const ACCOUNTING_ID: &str = "fre.operation-session.grep.v1";
pub(crate) const COUNT_SOURCE_IDENTITY: &str =
    "fre.operation-session.grep.count.whole-input-line-domains.v1";
pub(crate) const COUNT_ORDER_IDENTITY: &str =
    "fre.operation-session.grep.count.strict-ascending-line-order.v1";
pub(crate) const COUNT_FALLBACK_IDENTITY: &str =
    "fre.operation-session.grep.count.no-post-source-fallback.v1";
pub(crate) const SPAN_SUM_SOURCE_IDENTITY: &str =
    "fre.operation-session.grep.span-sum.whole-input-line-domains.v1";
pub(crate) const SPAN_SUM_ORDER_IDENTITY: &str =
    "fre.operation-session.grep.span-sum.strict-ascending-line-order.v1";
pub(crate) const SPAN_SUM_FALLBACK_IDENTITY: &str =
    "fre.operation-session.grep.span-sum.unsupported-pre-source.v1";
pub(crate) const PARTICIPATION_SOURCE_IDENTITY: &str =
    "fre.operation-session.grep.participation.whole-input-line-domains.v1";
pub(crate) const PARTICIPATION_ORDER_IDENTITY: &str =
    "fre.operation-session.grep.participation.strict-ascending-line-order.v1";
pub(crate) const PARTICIPATION_FALLBACK_IDENTITY: &str =
    "fre.operation-session.grep.participation.unsupported-pre-source.v1";
const LAYOUT_SEED: [u8; 16] = *b"fre.grep.v1\0\0\0\0\0";

/// Explicit fixed capacities for the grep-stream leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotAdmission {
    /// Line-state cells.
    pub line_state_cells: usize,
    /// Generation-mark cells.
    pub generation_cells: usize,
    /// Candidate cells.
    pub candidate_cells: usize,
    /// Persistent cache cells.
    pub cache_cells: usize,
    /// Persistent history cells.
    pub history_cells: usize,
}

/// Checked fixed-storage dimensions for one capture-free line-state automaton.
///
/// Thread records use two cells: one state ordinal and one absolute start
/// offset. The current frontier and closure stack share `line_state`, while
/// next-boundary roots use `candidates`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomatonSlotLayout {
    /// Validated automaton states.
    states: usize,
    /// Validated automaton edges.
    edges: usize,
    /// Validated zero-width edges.
    zero_width_edges: usize,
    /// Closure records, including the injected root.
    closure_records: usize,
    /// Two-cell current-frontier plus closure-stack storage.
    line_state_cells: usize,
    /// One generation mark per state.
    generation_cells: usize,
    /// Two cells per next-boundary root.
    candidate_cells: usize,
}

/// Failure to derive an exact grep-stream slot shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomatonSlotLayoutError {
    /// A validated automaton cannot have zero states.
    EmptyAutomaton,
    /// The claimed zero-width edge count exceeds the total edge count.
    ImpossibleEdgeFacts {
        /// Claimed total edge count.
        edges: usize,
        /// Claimed zero-width edge count.
        zero_width_edges: usize,
    },
    /// One checked fixed-storage dimension was not representable.
    ArithmeticOverflow {
        /// Stable name of the failed dimension.
        dimension: &'static str,
    },
}

impl core::fmt::Display for AutomatonSlotLayoutError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "grep-stream slot layout error: {self:?}")
    }
}

impl std::error::Error for AutomatonSlotLayoutError {}

impl AutomatonSlotLayout {
    /// Derive the complete exact slot shape from already validated graph facts.
    ///
    /// # Errors
    ///
    /// Refuses an empty graph and every checked size overflow.
    pub fn for_automaton(
        states: usize,
        edges: usize,
        zero_width_edges: usize,
    ) -> Result<Self, AutomatonSlotLayoutError> {
        if states == 0 {
            return Err(AutomatonSlotLayoutError::EmptyAutomaton);
        }
        if zero_width_edges > edges {
            return Err(AutomatonSlotLayoutError::ImpossibleEdgeFacts {
                edges,
                zero_width_edges,
            });
        }
        let closure_records = zero_width_edges.checked_add(1).ok_or(
            AutomatonSlotLayoutError::ArithmeticOverflow {
                dimension: "closure records",
            },
        )?;
        let line_state_records = states.checked_add(closure_records).ok_or(
            AutomatonSlotLayoutError::ArithmeticOverflow {
                dimension: "line-state records",
            },
        )?;
        let line_state_cells = line_state_records.checked_mul(2).ok_or(
            AutomatonSlotLayoutError::ArithmeticOverflow {
                dimension: "line-state cells",
            },
        )?;
        let candidate_cells =
            edges
                .checked_mul(2)
                .ok_or(AutomatonSlotLayoutError::ArithmeticOverflow {
                    dimension: "candidate cells",
                })?;
        Ok(Self {
            states,
            edges,
            zero_width_edges,
            closure_records,
            line_state_cells,
            generation_cells: states,
            candidate_cells,
        })
    }

    /// Exact common-session admission for this graph.
    #[must_use]
    pub const fn admission(self) -> SlotAdmission {
        SlotAdmission {
            line_state_cells: self.line_state_cells,
            generation_cells: self.generation_cells,
            candidate_cells: self.candidate_cells,
            cache_cells: 0,
            history_cells: 0,
        }
    }

    /// Validated automaton state count.
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    /// Validated automaton edge count.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    /// Validated zero-width edge count.
    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    /// Closure records including the injected root.
    #[must_use]
    pub const fn closure_records(self) -> usize {
        self.closure_records
    }

    /// Exact line-state cell count.
    #[must_use]
    pub const fn line_state_cells(self) -> usize {
        self.line_state_cells
    }

    /// Exact generation cell count.
    #[must_use]
    pub const fn generation_cells(self) -> usize {
        self.generation_cells
    }

    /// Exact candidate cell count.
    #[must_use]
    pub const fn candidate_cells(self) -> usize {
        self.candidate_cells
    }
}

/// One selected matching line with absolute source coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) struct GrepStreamMatch {
    pub(crate) line_ordinal: usize,
    pub(crate) line_start: usize,
    pub(crate) line_content_end: usize,
    pub(crate) line_source_end: usize,
    pub(crate) match_start: usize,
    pub(crate) match_end: usize,
}

/// Failure while authenticating the complete selected-line sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) enum GrepStreamOrderError {
    /// A selected line or match had impossible half-open coordinates.
    InvalidCoordinates,
    /// The next selected line did not strictly follow the previous one.
    InvalidOrder,
    /// The selected-line count was not representable.
    ArithmeticOverflow,
}

/// Private constant-space validator for the full engine-emitted line sequence.
///
/// Its fields are inaccessible outside this leaf module. The adapter can only
/// obtain a proof by feeding every selected line through [`Self::observe`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) struct GrepStreamOrderVerifier {
    count: u64,
    first: Option<GrepStreamMatch>,
    last: Option<GrepStreamMatch>,
}

/// Sealed proof that every selected line was observed in strict source order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) struct GrepStreamOrderProof {
    count: u64,
    first: Option<GrepStreamMatch>,
    last: Option<GrepStreamMatch>,
}

#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
impl GrepStreamOrderVerifier {
    /// Validate and retain one event from the engine's complete observer trace.
    pub(crate) fn observe(
        &mut self,
        selected: GrepStreamMatch,
    ) -> Result<(), GrepStreamOrderError> {
        if !match_coordinates_intrinsically_close(selected) {
            return Err(GrepStreamOrderError::InvalidCoordinates);
        }
        if self.last.is_some_and(|last| {
            selected.line_ordinal <= last.line_ordinal || selected.line_start < last.line_source_end
        }) {
            return Err(GrepStreamOrderError::InvalidOrder);
        }
        let count = self
            .count
            .checked_add(1)
            .ok_or(GrepStreamOrderError::ArithmeticOverflow)?;
        self.first.get_or_insert(selected);
        self.last = Some(selected);
        self.count = count;
        Ok(())
    }

    /// Consume the validator into an unforgeable leaf-private proof.
    #[must_use]
    pub(crate) const fn finish(self) -> GrepStreamOrderProof {
        GrepStreamOrderProof {
            count: self.count,
            first: self.first,
            last: self.last,
        }
    }
}

/// Exact report returned by one preflighted whole-input line-state engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) struct GrepStreamExecutionReport {
    /// Number of ByteSlice-compatible source domains scanned.
    pub(crate) source_line_domains: usize,
    /// Common-session execution dimensions.
    pub(crate) actual: OperationSessionExecutionActual,
    /// First selected line/match, if any.
    pub(crate) first_match: Option<GrepStreamMatch>,
    /// Last selected line/match, if any.
    pub(crate) last_match: Option<GrepStreamMatch>,
}

/// Failure while committing a trusted engine report to the common receipt.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
#[allow(
    clippy::large_enum_variant,
    reason = "typed common-session failures retain their closed allocation-free receipt by value"
)]
pub(crate) enum GrepStreamCommitError {
    /// The common reset did not reserve a nonempty generation interval.
    GenerationReservationInvariant,
    /// The engine returned internally inconsistent count/endpoint evidence.
    ReportInvariant(GrepStreamExecutionReport),
    /// The common attempt refused or failed to close the admitted actual.
    Attempt(OperationSessionAttemptError),
}

/// Trusted post-begin engine terminal class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrepStreamFailure {
    Engine,
    Observer,
    Protocol,
}

impl From<GrepStreamFailure> for OperationSessionExecutionFailure {
    fn from(value: GrepStreamFailure) -> Self {
        match value {
            GrepStreamFailure::Engine => Self::Engine,
            GrepStreamFailure::Observer => Self::Observer,
            GrepStreamFailure::Protocol => Self::Protocol,
        }
    }
}

/// Failure before or while selecting the common G attempt.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
#[allow(
    clippy::large_enum_variant,
    reason = "typed common-session failures retain their closed allocation-free receipt by value"
)]
pub(crate) enum GrepStreamBeginError {
    /// The immutable compiled-plan owner supplied the reserved zero identity.
    InvalidCompiledPlanIdentity,
    /// The common operation-session preflight or reset refused.
    Attempt(OperationSessionAttemptError),
}

impl From<OperationSessionAttemptError> for GrepStreamBeginError {
    fn from(error: OperationSessionAttemptError) -> Self {
        Self::Attempt(error)
    }
}

impl From<OperationSessionAttemptError> for GrepStreamCommitError {
    fn from(error: OperationSessionAttemptError) -> Self {
        Self::Attempt(error)
    }
}

impl GrepStreamExecutionReport {
    #[allow(
        dead_code,
        reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
    )]
    fn closes(&self, proof: GrepStreamOrderProof, invocation: &OperationSessionInvocation) -> bool {
        let matched = self.actual.line_domains;
        let endpoints_present = self.first_match.is_some() == (matched != 0)
            && self.last_match.is_some() == (matched != 0)
            && proof.first.is_some() == (matched != 0)
            && proof.last.is_some() == (matched != 0);
        let source_line_domains = u64::try_from(self.source_line_domains).ok();
        endpoints_present
            && proof.count == matched
            && proof.first == self.first_match
            && proof.last == self.last_match
            && self.actual.output_events == matched
            && self.actual.selected_span_bytes == 0
            && self.actual.participation_entries == 0
            && self.actual.allocations == 0
            && (self.source_line_domains == 0) == (invocation.haystack_len == 0)
            && self.source_line_domains <= invocation.haystack_len
            && source_line_domains.is_some_and(|domains| matched <= domains)
            && self
                .first_match
                .zip(self.last_match)
                .is_none_or(|(first, last)| {
                    let ordinal_width = last
                        .line_ordinal
                        .checked_sub(first.line_ordinal)
                        .and_then(|width| width.checked_add(1))
                        .and_then(|width| u64::try_from(width).ok());
                    (matched != 1 || first == last)
                        && first.line_ordinal <= last.line_ordinal
                        && (matched <= 1 || first.line_ordinal < last.line_ordinal)
                        && ordinal_width.is_some_and(|width| matched <= width)
                        && last.line_ordinal < self.source_line_domains
                        && match_coordinates_close(first, invocation)
                        && match_coordinates_close(last, invocation)
                })
    }
}

#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
fn match_coordinates_close(
    selected: GrepStreamMatch,
    invocation: &OperationSessionInvocation,
) -> bool {
    match_coordinates_intrinsically_close(selected)
        && selected.line_source_end <= invocation.haystack_len
}

fn match_coordinates_intrinsically_close(selected: GrepStreamMatch) -> bool {
    selected.line_start < selected.line_source_end
        && selected.line_start <= selected.line_content_end
        && selected.line_content_end <= selected.line_source_end
        && selected
            .line_source_end
            .checked_sub(selected.line_content_end)
            .is_some_and(|tail| tail <= 2)
        && selected.match_start >= selected.line_start
        && selected.match_start <= selected.match_end
        && selected.match_end <= selected.line_content_end
}

/// Disjoint mutable fixed storage lent to one selected grep engine.
///
/// The engine may change cell contents but cannot grow any buffer or borrow a
/// different operation-session leaf.
#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
pub(crate) struct GrepStreamStorage<'a> {
    pub(crate) line_state: &'a mut [u64],
    pub(crate) generation: &'a mut [u64],
    pub(crate) candidates: &'a mut [u64],
    pub(crate) cache: &'a mut [u64],
    pub(crate) history: &'a mut [u64],
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the common seal owns exact buffers before the G lane installs stream semantics"
)]
pub(crate) struct Slot {
    line_state: ExactVec<u64>,
    generation: ExactVec<u64>,
    candidates: ExactVec<u64>,
    cache: ExactVec<u64>,
    history: ExactVec<u64>,
    counters: OperationSessionLeafCounters,
    layout_id: [u8; 16],
}

impl super::private::Sealed for Slot {}

impl SessionLeafSlot for Slot {
    const LEAF: OperationSessionLeaf = OperationSessionLeaf::Grep;
    type Admission = SlotAdmission;

    fn prospective(
        admission: &Self::Admission,
    ) -> Result<OperationSessionStorageProspective, OperationSessionError> {
        storage_prospective(
            &[
                admission.generation_cells,
                admission.cache_cells,
                admission.history_cells,
            ],
            &[admission.line_state_cells, admission.candidate_cells],
            admission.generation_cells,
        )
    }

    fn try_new(
        admission: Self::Admission,
        prospective: &OperationSessionStorageProspective,
    ) -> Result<(Self, OperationSessionStorageActual), OperationSessionError> {
        let line_state = allocate_zeroed_cells(admission.line_state_cells)?;
        let generation = allocate_zeroed_cells(admission.generation_cells)?;
        let candidates = allocate_zeroed_cells(admission.candidate_cells)?;
        let cache = allocate_zeroed_cells(admission.cache_cells)?;
        let history = allocate_zeroed_cells(admission.history_cells)?;
        let layout_id = tag_layout_id(
            Self::LEAF,
            derive_layout_id(
                LAYOUT_SEED,
                &[
                    admission.line_state_cells,
                    admission.generation_cells,
                    admission.candidate_cells,
                    admission.cache_cells,
                    admission.history_cells,
                ],
            )?,
        );
        let actual = measured_storage_actual(
            &[&generation, &cache, &history],
            &[&line_state, &candidates],
            &generation,
        )?;
        debug_assert_eq!(actual.build_work, prospective.build_work);
        Ok((
            Self {
                line_state,
                generation,
                candidates,
                cache,
                history,
                counters: OperationSessionLeafCounters::default(),
                layout_id,
            },
            actual,
        ))
    }

    fn layout_id(&self) -> [u8; 16] {
        self.layout_id
    }

    fn generation_capacity(&self) -> usize {
        self.generation.capacity()
    }

    fn counters(&self) -> OperationSessionLeafCounters {
        self.counters
    }

    fn reset_prospective(
        &self,
        required_generations: u64,
    ) -> Result<OperationSessionResetProspective, OperationSessionError> {
        leaf_reset_prospective(
            Self::LEAF,
            self.counters,
            self.generation.capacity(),
            required_generations,
        )
    }

    fn apply_reset(
        &mut self,
        prospective: &OperationSessionResetProspective,
    ) -> OperationSessionResetActual {
        apply_leaf_reset(&mut self.generation, &mut self.counters, prospective)
    }
}

pub(crate) const fn route_contract(
    reducer: OperationSessionReducer,
) -> (&'static str, &'static str, &'static str) {
    match reducer {
        OperationSessionReducer::Count => (
            COUNT_SOURCE_IDENTITY,
            COUNT_ORDER_IDENTITY,
            COUNT_FALLBACK_IDENTITY,
        ),
        OperationSessionReducer::SpanSum => (
            SPAN_SUM_SOURCE_IDENTITY,
            SPAN_SUM_ORDER_IDENTITY,
            SPAN_SUM_FALLBACK_IDENTITY,
        ),
        OperationSessionReducer::Participation => (
            PARTICIPATION_SOURCE_IDENTITY,
            PARTICIPATION_ORDER_IDENTITY,
            PARTICIPATION_FALLBACK_IDENTITY,
        ),
    }
}

pub(crate) const fn supports(reducer: OperationSessionReducer) -> bool {
    matches!(reducer, OperationSessionReducer::Count)
}

pub(crate) fn invocation_closes(
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
) -> bool {
    invocation.is_valid()
        && (reducer != OperationSessionReducer::Count
            || (invocation.range.start == 0 && invocation.range.end == invocation.haystack_len))
}

impl OperationSession {
    /// Grep-stream forced entry view.
    pub fn forced_grep(&mut self) -> ForcedGrep<'_> {
        ForcedGrep { session: self }
    }

    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn begin_grep(
        &mut self,
        mut request: OperationSessionAttemptRequest,
        reducer: OperationSessionReducer,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        request.bind_reducer(reducer);
        let all_before = self.all_counters();
        begin_forced_slot(&self.construction, all_before, &mut self.grep, request)
    }
}

/// Grep-stream forced entry view.
#[derive(Debug)]
pub struct ForcedGrep<'a> {
    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    pub(crate) session: &'a mut OperationSession,
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
impl ForcedGrep<'_> {
    /// Authenticate and begin one whole-input Count route from engine facts.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_stream_count(
        &mut self,
        compiled_plan_id: [u8; 16],
        invocation: OperationSessionInvocation,
        prospective: OperationSessionExecutionProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
    ) -> Result<OperationSessionAttempt<'_, Slot>, GrepStreamBeginError> {
        let identity = OperationSessionRouteIdentity {
            session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
            session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
            leaf: OperationSessionLeaf::Grep,
            reducer: OperationSessionReducer::Count,
            compiled_plan_id,
            source_identity: COUNT_SOURCE_IDENTITY,
            order_identity: COUNT_ORDER_IDENTITY,
            fallback_identity: COUNT_FALLBACK_IDENTITY,
            leaf_algorithm_version: ALGORITHM_VERSION,
            leaf_accounting_version: ACCOUNTING_VERSION,
            leaf_accounting_id: ACCOUNTING_ID,
        };
        let request = OperationSessionAttemptRequest::new_trusted(
            identity,
            invocation,
            prospective,
            reset_limits,
            run_limits,
            compiled_plan_id,
        )
        .map_err(|_| GrepStreamBeginError::InvalidCompiledPlanIdentity)?;
        self.begin_count(request)
            .map_err(GrepStreamBeginError::Attempt)
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_count(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_grep(request, OperationSessionReducer::Count)
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_span_sum(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_grep(request, OperationSessionReducer::SpanSum)
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_participation(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_grep(request, OperationSessionReducer::Participation)
    }
}

#[allow(
    dead_code,
    reason = "the G-owned adapter consumes this seam after integration-owner module wiring"
)]
impl OperationSessionAttempt<'_, Slot> {
    /// First generation in the interval reserved by the authenticated reset.
    #[allow(
        clippy::result_large_err,
        reason = "typed common-session failures retain their closed allocation-free receipt by value"
    )]
    pub(crate) fn reserved_first_generation(&self) -> Result<u64, GrepStreamCommitError> {
        let required = self.reset.actual.required_generations;
        if required == 0 {
            return Err(GrepStreamCommitError::GenerationReservationInvariant);
        }
        self.reset
            .actual
            .counters_after
            .generation
            .checked_sub(required)
            .and_then(|generation| generation.checked_add(1))
            .ok_or(GrepStreamCommitError::GenerationReservationInvariant)
    }

    /// Lend the selected G slot's exact initialized cells to one engine call.
    pub(crate) fn stream_storage(&mut self) -> GrepStreamStorage<'_> {
        let slot = self.selected_slot();
        GrepStreamStorage {
            line_state: slot.line_state.as_mut_slice(),
            generation: slot.generation.as_mut_slice(),
            candidates: slot.candidates.as_mut_slice(),
            cache: slot.cache.as_mut_slice(),
            history: slot.history.as_mut_slice(),
        }
    }

    /// Create the only G-owned validator that can seal an ordered-event proof.
    ///
    /// The returned value is independent of the attempt borrow, so the engine
    /// can call it while holding the attempt's disjoint fixed storage.
    #[allow(
        clippy::unused_self,
        reason = "the method receiver proves a live authenticated attempt owns this verifier"
    )]
    pub(crate) const fn stream_order_verifier(&self) -> GrepStreamOrderVerifier {
        GrepStreamOrderVerifier {
            count: 0,
            first: None,
            last: None,
        }
    }

    /// Publish a completed whole-input engine report as one closed Count
    /// receipt without retaining every matched ordinal.
    ///
    /// `order` proves that a G-private observer validated every selected event,
    /// while the receipt retains only its count and endpoints.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn finish_stream_count(
        mut self,
        report: GrepStreamExecutionReport,
        order: GrepStreamOrderProof,
    ) -> Result<super::OperationSessionAttemptReceipt, GrepStreamCommitError> {
        let fresh = self.actual == OperationSessionExecutionActual::default()
            && self.terminal.is_none()
            && self.evidence == super::OperationSessionAttemptEvidence::empty();
        let actual_admitted = self.request.prospective.contains_actual(report.actual)
            && self
                .request
                .run_limits
                .first_refusal(super::execution_actual_as_prospective(report.actual))
                .is_none();
        if !fresh {
            let failure = OperationSessionExecutionFailure::Protocol;
            return Err(GrepStreamCommitError::Attempt(self.fail_with(
                OperationSessionTerminal::ExecutionFailed,
                OperationSessionFailureEvidence::ExecutionFailed(failure),
                None,
                OperationSessionAttemptedOperation::ExecutionFailure { failure },
            )));
        }
        if !actual_admitted || !report.closes(order, &self.request.invocation) {
            return Err(GrepStreamCommitError::Attempt(self.fail_stream_count(
                report.actual,
                order,
                GrepStreamFailure::Protocol,
            )));
        }
        self.actual = report.actual;
        self.evidence.first_line_ordinal = order.first.map(|selected| selected.line_ordinal);
        self.evidence.last_line_ordinal = order.last.map(|selected| selected.line_ordinal);
        self.evidence.line_events = order.count;
        self.finish_count().map_err(GrepStreamCommitError::Attempt)
    }

    /// Close an authenticated post-begin engine, observer, or protocol fault.
    ///
    /// `actual` is the engine's exact partial accounting and `order` is the
    /// exact successfully observed prefix. The private receipt schema checks
    /// the distinct engine/observer prefix relationship.
    pub(crate) fn fail_stream_count(
        mut self,
        actual: OperationSessionExecutionActual,
        order: GrepStreamOrderProof,
        failure: GrepStreamFailure,
    ) -> OperationSessionAttemptError {
        let execution_failure = failure.into();
        if !self.request.prospective.contains_actual(actual)
            || self
                .request
                .run_limits
                .first_refusal(super::execution_actual_as_prospective(actual))
                .is_some()
        {
            return self.fail_with(
                OperationSessionTerminal::ExecutionFailed,
                OperationSessionFailureEvidence::ExecutionFailed(
                    OperationSessionExecutionFailure::Protocol,
                ),
                None,
                OperationSessionAttemptedOperation::ExecutionFailure {
                    failure: OperationSessionExecutionFailure::Protocol,
                },
            );
        }
        self.actual = actual;
        self.evidence.first_line_ordinal = order.first.map(|selected| selected.line_ordinal);
        self.evidence.last_line_ordinal = order.last.map(|selected| selected.line_ordinal);
        self.evidence.line_events = order.count;
        self.fail_with(
            OperationSessionTerminal::ExecutionFailed,
            OperationSessionFailureEvidence::ExecutionFailed(execution_failure),
            None,
            OperationSessionAttemptedOperation::ExecutionFailure {
                failure: execution_failure,
            },
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "the test-only slot canary API remains private and adjacent to the owning type"
)]
mod stream_tests {
    use super::*;
    use crate::operation_session::{
        OperationSessionAdmission, OperationSessionConstructionLimits, OperationSessionValue, hot,
        multi_capture, search,
    };

    const PLAN_ID: [u8; 16] = [0x47; 16];

    fn session(grep: SlotAdmission) -> OperationSession {
        let admission = OperationSessionAdmission {
            search: search::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            hot: hot::SlotAdmission {
                state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            multi_capture: multi_capture::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                tagged_candidate_cells: 0,
                tagged_cache_cells: 0,
                history_cells: 0,
                participation_cells: 0,
            },
            grep,
        };
        let prospective = OperationSession::prospective(&admission).expect("prospective");
        OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
        .expect("session")
    }

    fn request(
        haystack_len: usize,
        required_generations: u64,
        prospective: OperationSessionExecutionProspective,
        run_limits: OperationSessionRunLimits,
    ) -> OperationSessionAttemptRequest {
        let identity = OperationSessionRouteIdentity {
            session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
            session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
            leaf: OperationSessionLeaf::Grep,
            reducer: OperationSessionReducer::Count,
            compiled_plan_id: PLAN_ID,
            source_identity: COUNT_SOURCE_IDENTITY,
            order_identity: COUNT_ORDER_IDENTITY,
            fallback_identity: COUNT_FALLBACK_IDENTITY,
            leaf_algorithm_version: ALGORITHM_VERSION,
            leaf_accounting_version: ACCOUNTING_VERSION,
            leaf_accounting_id: ACCOUNTING_ID,
        };
        OperationSessionAttemptRequest::new_trusted(
            identity,
            OperationSessionInvocation {
                haystack_len,
                range: 0..haystack_len,
                required_generations,
            },
            prospective,
            OperationSessionResetLimits {
                max_work: u64::MAX,
                max_clear_cells: usize::MAX,
                max_clear_bytes: usize::MAX,
            },
            run_limits,
            PLAN_ID,
        )
        .expect("trusted request")
    }

    fn exact_report() -> GrepStreamExecutionReport {
        GrepStreamExecutionReport {
            source_line_domains: 3,
            actual: OperationSessionExecutionActual {
                work: 19,
                source_accesses: 8,
                transitions: 7,
                candidates: 3,
                line_domains: 2,
                output_events: 2,
                ..OperationSessionExecutionActual::default()
            },
            first_match: Some(GrepStreamMatch {
                line_ordinal: 0,
                line_start: 0,
                line_content_end: 1,
                line_source_end: 2,
                match_start: 0,
                match_end: 1,
            }),
            last_match: Some(GrepStreamMatch {
                line_ordinal: 2,
                line_start: 4,
                line_content_end: 8,
                line_source_end: 8,
                match_start: 5,
                match_end: 7,
            }),
        }
    }

    fn empty_report(source_line_domains: usize) -> GrepStreamExecutionReport {
        GrepStreamExecutionReport {
            source_line_domains,
            actual: OperationSessionExecutionActual::default(),
            first_match: None,
            last_match: None,
        }
    }

    #[test]
    fn automaton_shape_derives_exact_fixed_cells_and_refuses_overflow() {
        let layout = AutomatonSlotLayout::for_automaton(3, 5, 2).expect("layout");
        assert_eq!(
            layout,
            AutomatonSlotLayout {
                states: 3,
                edges: 5,
                zero_width_edges: 2,
                closure_records: 3,
                line_state_cells: 12,
                generation_cells: 3,
                candidate_cells: 10,
            }
        );
        assert_eq!(
            layout.admission(),
            SlotAdmission {
                line_state_cells: 12,
                generation_cells: 3,
                candidate_cells: 10,
                cache_cells: 0,
                history_cells: 0,
            }
        );
        assert_eq!(
            AutomatonSlotLayout::for_automaton(0, 0, 0),
            Err(AutomatonSlotLayoutError::EmptyAutomaton)
        );
        assert_eq!(
            AutomatonSlotLayout::for_automaton(1, 0, 1),
            Err(AutomatonSlotLayoutError::ImpossibleEdgeFacts {
                edges: 0,
                zero_width_edges: 1,
            })
        );
        assert!(matches!(
            AutomatonSlotLayout::for_automaton(1, usize::MAX, usize::MAX),
            Err(AutomatonSlotLayoutError::ArithmeticOverflow {
                dimension: "closure records"
            })
        ));
        assert!(matches!(
            AutomatonSlotLayout::for_automaton(1, usize::MAX, 0),
            Err(AutomatonSlotLayoutError::ArithmeticOverflow {
                dimension: "candidate cells"
            })
        ));
    }

    #[test]
    fn exact_storage_is_lent_without_growth_and_batch_report_closes() {
        let layout = AutomatonSlotLayout::for_automaton(3, 5, 2).expect("layout");
        let mut session = session(layout.admission());
        let report = exact_report();
        let prospective = OperationSessionExecutionProspective {
            work: report.actual.work,
            source_accesses: report.actual.source_accesses,
            transitions: report.actual.transitions,
            candidates: report.actual.candidates,
            line_domains: report.actual.line_domains,
            output_events: report.actual.output_events,
            ..OperationSessionExecutionProspective::default()
        };
        let request = request(
            8,
            9,
            prospective,
            OperationSessionRunLimits::exact(prospective),
        );
        let mut forced = session.forced_grep();
        let mut attempt = forced.begin_count(request).expect("attempt");
        assert_eq!(
            attempt
                .reserved_first_generation()
                .expect("reserved generation"),
            1
        );
        {
            let storage = attempt.stream_storage();
            assert_eq!(storage.line_state.len(), 12);
            assert_eq!(storage.generation.len(), 3);
            assert_eq!(storage.candidates.len(), 10);
            assert!(storage.cache.is_empty());
            assert!(storage.history.is_empty());
            storage.line_state[0] = 0x47;
        }
        let mut order = attempt.stream_order_verifier();
        order
            .observe(report.first_match.expect("first match"))
            .expect("first event");
        order
            .observe(report.last_match.expect("last match"))
            .expect("last event");
        let receipt = attempt
            .finish_stream_count(report, order.finish())
            .expect("closed stream receipt");
        assert!(receipt.closes());
        assert_eq!(receipt.value, Some(OperationSessionValue::Count(2)));
        assert_eq!(receipt.actual, report.actual);
    }

    #[test]
    fn malformed_engine_summary_is_rejected_as_an_internal_invariant() {
        let layout = AutomatonSlotLayout::for_automaton(1, 0, 0).expect("layout");
        let mut session = session(layout.admission());
        let exact = exact_report();
        let mut report = exact_report();
        report.first_match = report.last_match;
        let prospective = OperationSessionExecutionProspective {
            work: report.actual.work,
            source_accesses: report.actual.source_accesses,
            transitions: report.actual.transitions,
            candidates: report.actual.candidates,
            line_domains: report.actual.line_domains,
            output_events: report.actual.output_events,
            ..OperationSessionExecutionProspective::default()
        };
        let mut forced = session.forced_grep();
        let attempt = forced
            .begin_count(request(
                8,
                9,
                prospective,
                OperationSessionRunLimits::exact(prospective),
            ))
            .expect("attempt");
        let mut order = attempt.stream_order_verifier();
        order
            .observe(exact.first_match.expect("first match"))
            .expect("first event");
        order
            .observe(exact.last_match.expect("last match"))
            .expect("last event");
        let error = attempt
            .finish_stream_count(report, order.finish())
            .expect_err("duplicate endpoints must fail");
        let GrepStreamCommitError::Attempt(error) = error else {
            panic!("post-begin protocol failure must retain its attempt")
        };
        let receipt = match &error {
            OperationSessionAttemptError::Refused(receipt)
            | OperationSessionAttemptError::ReceiptNotClosed(receipt) => receipt,
        };
        assert!(receipt.closes());
        assert_eq!(receipt.terminal, OperationSessionTerminal::ExecutionFailed);
        assert_eq!(receipt.actual, report.actual);
    }

    #[test]
    fn engine_and_observer_failures_close_their_exact_observed_prefixes() {
        for (failure, observed_events, actual_events) in [
            (GrepStreamFailure::Engine, 1_u64, 1_u64),
            (GrepStreamFailure::Observer, 1_u64, 2_u64),
        ] {
            let layout = AutomatonSlotLayout::for_automaton(1, 0, 0).expect("layout");
            let mut session = session(layout.admission());
            let report = exact_report();
            let prospective = OperationSessionExecutionProspective {
                work: report.actual.work,
                source_accesses: report.actual.source_accesses,
                transitions: report.actual.transitions,
                candidates: report.actual.candidates,
                line_domains: report.actual.line_domains,
                output_events: report.actual.output_events,
                ..OperationSessionExecutionProspective::default()
            };
            let mut forced = session.forced_grep();
            let attempt = forced
                .begin_count(request(
                    8,
                    9,
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ))
                .expect("attempt");
            let mut order = attempt.stream_order_verifier();
            order
                .observe(report.first_match.expect("first match"))
                .expect("first observed event");
            assert_eq!(order.count, observed_events);
            let mut actual = report.actual;
            actual.line_domains = actual_events;
            actual.output_events = actual_events;
            let error = attempt.fail_stream_count(actual, order.finish(), failure);
            let receipt = match &error {
                OperationSessionAttemptError::Refused(receipt)
                | OperationSessionAttemptError::ReceiptNotClosed(receipt) => receipt,
            };
            assert!(receipt.closes());
            assert_eq!(receipt.terminal, OperationSessionTerminal::ExecutionFailed);
            assert_eq!(receipt.actual, actual);
        }
    }

    #[test]
    fn complete_order_verifier_rejects_a_reversed_middle_event() {
        let mut order = GrepStreamOrderVerifier {
            count: 0,
            first: None,
            last: None,
        };
        let report = exact_report();
        let first = report.first_match.expect("first match");
        let last = report.last_match.expect("last match");
        order.observe(first).expect("first event");
        order.observe(last).expect("last event");
        let reversed = GrepStreamMatch {
            line_ordinal: 1,
            line_start: 2,
            line_content_end: 3,
            line_source_end: 4,
            match_start: 2,
            match_end: 3,
        };
        assert_eq!(
            order.observe(reversed),
            Err(GrepStreamOrderError::InvalidOrder)
        );
    }

    #[test]
    fn zero_generation_empty_source_and_rollover_intervals_close() {
        let layout = AutomatonSlotLayout::for_automaton(1, 0, 0).expect("layout");
        let mut session = session(layout.admission());
        {
            let mut forced = session.forced_grep();
            let attempt = forced
                .begin_count(request(
                    0,
                    0,
                    OperationSessionExecutionProspective::default(),
                    OperationSessionRunLimits::exact(
                        OperationSessionExecutionProspective::default(),
                    ),
                ))
                .expect("empty attempt");
            assert!(matches!(
                attempt.reserved_first_generation(),
                Err(GrepStreamCommitError::GenerationReservationInvariant)
            ));
            let order = attempt.stream_order_verifier().finish();
            let receipt = attempt
                .finish_stream_count(empty_report(0), order)
                .expect("empty receipt");
            assert!(receipt.closes());
            assert_eq!(receipt.value, Some(OperationSessionValue::Count(0)));
        }

        session
            .grep
            .test_set_counters(OperationSessionLeafCounters {
                generation: u64::MAX,
                ..OperationSessionLeafCounters::default()
            });
        let mut forced = session.forced_grep();
        let attempt = forced
            .begin_count(request(
                1,
                2,
                OperationSessionExecutionProspective::default(),
                OperationSessionRunLimits::exact(OperationSessionExecutionProspective::default()),
            ))
            .expect("rollover attempt");
        assert_eq!(
            attempt
                .reserved_first_generation()
                .expect("rollover first generation"),
            1
        );
        let order = attempt.stream_order_verifier().finish();
        let receipt = attempt
            .finish_stream_count(empty_report(1), order)
            .expect("rollover receipt");
        assert!(receipt.closes());
        assert_eq!(receipt.reset.actual.counters_after.generation, 2);
        assert_eq!(receipt.reset.actual.counters_after.rollovers, 1);
        assert_eq!(receipt.reset.actual.counters_after.clears, 1);
    }

    #[test]
    fn batch_commit_rejects_a_nonfresh_attempt_without_erasing_actual() {
        let layout = AutomatonSlotLayout::for_automaton(1, 0, 0).expect("layout");
        let mut session = session(layout.admission());
        let prospective = OperationSessionExecutionProspective {
            work: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let mut forced = session.forced_grep();
        let mut attempt = forced
            .begin_count(request(
                1,
                1,
                prospective,
                OperationSessionRunLimits::exact(prospective),
            ))
            .expect("attempt");
        attempt.meter_work(1).expect("prior meter");
        let mut report = empty_report(1);
        report.actual.work = 1;
        let order = attempt.stream_order_verifier().finish();
        let error = attempt
            .finish_stream_count(report, order)
            .expect_err("nonfresh attempt must fail closed");
        let GrepStreamCommitError::Attempt(error) = error else {
            panic!("nonfresh failure must retain its attempt")
        };
        let receipt = match &error {
            OperationSessionAttemptError::Refused(receipt)
            | OperationSessionAttemptError::ReceiptNotClosed(receipt) => receipt,
        };
        assert!(receipt.closes());
        assert_eq!(receipt.terminal, OperationSessionTerminal::ExecutionFailed);
        assert_eq!(receipt.actual.work, 1);
    }

    #[test]
    fn one_below_execution_limit_refuses_before_storage_is_lent() {
        let layout = AutomatonSlotLayout::for_automaton(1, 0, 0).expect("layout");
        let mut session = session(layout.admission());
        let prospective = OperationSessionExecutionProspective {
            source_accesses: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let run_limits =
            OperationSessionRunLimits::exact(OperationSessionExecutionProspective::default());
        let mut forced = session.forced_grep();
        let Err(error) = forced.begin_count(request(1, 2, prospective, run_limits)) else {
            panic!("one-below request unexpectedly reached the slot");
        };
        let receipt = match error {
            OperationSessionAttemptError::Refused(receipt)
            | OperationSessionAttemptError::ReceiptNotClosed(receipt) => receipt,
        };
        assert!(receipt.closes());
        assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
    }
}

#[cfg(test)]
impl Slot {
    pub(super) fn test_set_counters(&mut self, counters: OperationSessionLeafCounters) {
        self.counters = counters;
    }

    pub(super) fn test_fill_canary(&mut self, seed: u64) {
        for (ordinal, values) in [
            &mut self.line_state,
            &mut self.generation,
            &mut self.candidates,
            &mut self.cache,
            &mut self.history,
        ]
        .into_iter()
        .enumerate()
        {
            for (index, value) in values.as_mut_slice().iter_mut().enumerate() {
                *value = seed
                    .wrapping_add(u64::try_from(ordinal).expect("small ordinal") << 32)
                    .wrapping_add(u64::try_from(index).expect("test capacity"));
            }
        }
    }

    pub(super) fn test_snapshot(&self) -> super::TestSlotSnapshot {
        super::TestSlotSnapshot {
            capacities: vec![
                self.line_state.capacity(),
                self.generation.capacity(),
                self.candidates.capacity(),
                self.cache.capacity(),
                self.history.capacity(),
            ],
            contents: vec![
                self.line_state.as_slice().to_vec(),
                self.generation.as_slice().to_vec(),
                self.candidates.as_slice().to_vec(),
                self.cache.as_slice().to_vec(),
                self.history.as_slice().to_vec(),
            ],
        }
    }
}
