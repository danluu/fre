//! Multi-capture-lane-owned fixed storage and forced entry stubs.

use fre_exact_alloc::ExactVec;

use super::{
    OperationSession, OperationSessionAttempt, OperationSessionAttemptError,
    OperationSessionAttemptRequest, OperationSessionError, OperationSessionInvocation,
    OperationSessionLeaf, OperationSessionLeafCounters, OperationSessionReducer,
    OperationSessionResetActual, OperationSessionResetProspective, OperationSessionStorageActual,
    OperationSessionStorageProspective, SessionLeafSlot, allocate_zeroed_cells, apply_leaf_reset,
    begin_forced_slot, derive_layout_id, leaf_reset_prospective, measured_storage_actual,
    storage_prospective, tag_layout_id,
};

/// Multi-capture slot algorithm version.
pub const ALGORITHM_VERSION: u32 = 1;
/// Multi-capture slot accounting version.
pub const ACCOUNTING_VERSION: u32 = 1;
/// Stable multi-capture slot accounting identity.
pub const ACCOUNTING_ID: &str = "fre.operation-session.multi-capture.v1";
pub(crate) const COUNT_SOURCE_IDENTITY: &str =
    "fre.operation-session.multi-capture.count.multi-pattern-range.v1";
pub(crate) const COUNT_ORDER_IDENTITY: &str =
    "fre.operation-session.multi-capture.count.source-pattern-order.v1";
pub(crate) const COUNT_FALLBACK_IDENTITY: &str =
    "fre.operation-session.multi-capture.count.no-post-source-fallback.v1";
pub(crate) const SPAN_SUM_SOURCE_IDENTITY: &str =
    "fre.operation-session.multi-capture.span-sum.multi-pattern-range.v1";
pub(crate) const SPAN_SUM_ORDER_IDENTITY: &str =
    "fre.operation-session.multi-capture.span-sum.source-pattern-order.v1";
pub(crate) const SPAN_SUM_FALLBACK_IDENTITY: &str =
    "fre.operation-session.multi-capture.span-sum.no-post-source-fallback.v1";
pub(crate) const PARTICIPATION_SOURCE_IDENTITY: &str =
    "fre.operation-session.multi-capture.participation.capture-history.v1";
pub(crate) const PARTICIPATION_ORDER_IDENTITY: &str =
    "fre.operation-session.multi-capture.participation.source-pattern-order.v1";
pub(crate) const PARTICIPATION_FALLBACK_IDENTITY: &str =
    "fre.operation-session.multi-capture.participation.no-post-source-fallback.v1";
const LAYOUT_SEED: [u8; 16] = *b"fre.multi.v1\0\0\0\0";

/// Explicit fixed capacities for the multi-capture leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotAdmission {
    /// Current frontier cells.
    pub frontier_cells: usize,
    /// Next frontier cells.
    pub next_frontier_cells: usize,
    /// Generation-mark cells.
    pub generation_cells: usize,
    /// Tagged candidate cells.
    pub tagged_candidate_cells: usize,
    /// Tagged persistent cache cells.
    pub tagged_cache_cells: usize,
    /// Persistent capture-history cells.
    pub history_cells: usize,
    /// Persistent participation cells.
    pub participation_cells: usize,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the common seal owns exact buffers before the M lane installs capture semantics"
)]
pub(crate) struct Slot {
    frontier: ExactVec<u64>,
    next_frontier: ExactVec<u64>,
    generation: ExactVec<u64>,
    tagged_candidates: ExactVec<u64>,
    tagged_cache: ExactVec<u64>,
    history: ExactVec<u64>,
    participation: ExactVec<u64>,
    counters: OperationSessionLeafCounters,
    layout_id: [u8; 16],
}

impl super::private::Sealed for Slot {}

impl SessionLeafSlot for Slot {
    const LEAF: OperationSessionLeaf = OperationSessionLeaf::MultiCapture;
    type Admission = SlotAdmission;

    fn prospective(
        admission: &Self::Admission,
    ) -> Result<OperationSessionStorageProspective, OperationSessionError> {
        storage_prospective(
            &[
                admission.generation_cells,
                admission.tagged_cache_cells,
                admission.history_cells,
                admission.participation_cells,
            ],
            &[
                admission.frontier_cells,
                admission.next_frontier_cells,
                admission.tagged_candidate_cells,
            ],
            admission.generation_cells,
        )
    }

    fn try_new(
        admission: Self::Admission,
        prospective: &OperationSessionStorageProspective,
    ) -> Result<(Self, OperationSessionStorageActual), OperationSessionError> {
        let frontier = allocate_zeroed_cells(admission.frontier_cells)?;
        let next_frontier = allocate_zeroed_cells(admission.next_frontier_cells)?;
        let generation = allocate_zeroed_cells(admission.generation_cells)?;
        let tagged_candidates = allocate_zeroed_cells(admission.tagged_candidate_cells)?;
        let tagged_cache = allocate_zeroed_cells(admission.tagged_cache_cells)?;
        let history = allocate_zeroed_cells(admission.history_cells)?;
        let participation = allocate_zeroed_cells(admission.participation_cells)?;
        let layout_id = tag_layout_id(
            Self::LEAF,
            derive_layout_id(
                LAYOUT_SEED,
                &[
                    admission.frontier_cells,
                    admission.next_frontier_cells,
                    admission.generation_cells,
                    admission.tagged_candidate_cells,
                    admission.tagged_cache_cells,
                    admission.history_cells,
                    admission.participation_cells,
                ],
            )?,
        );
        let actual = measured_storage_actual(
            &[&generation, &tagged_cache, &history, &participation],
            &[&frontier, &next_frontier, &tagged_candidates],
            &generation,
        )?;
        debug_assert_eq!(actual.build_work, prospective.build_work);
        Ok((
            Self {
                frontier,
                next_frontier,
                generation,
                tagged_candidates,
                tagged_cache,
                history,
                participation,
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

pub(crate) const fn supports(_reducer: OperationSessionReducer) -> bool {
    true
}

pub(crate) fn invocation_closes(
    _reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
) -> bool {
    invocation.is_valid()
}

impl OperationSession {
    /// Multi-capture forced entry view.
    pub fn forced_multi_capture(&mut self) -> ForcedMultiCapture<'_> {
        ForcedMultiCapture { session: self }
    }

    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn begin_multi_capture(
        &mut self,
        mut request: OperationSessionAttemptRequest,
        reducer: OperationSessionReducer,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        request.bind_reducer(reducer);
        let all_before = self.all_counters();
        begin_forced_slot(
            &self.construction,
            all_before,
            &mut self.multi_capture,
            request,
        )
    }
}

/// Multi-capture forced entry view.
#[derive(Debug)]
pub struct ForcedMultiCapture<'a> {
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
impl ForcedMultiCapture<'_> {
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_count(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_multi_capture(request, OperationSessionReducer::Count)
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
            .begin_multi_capture(request, OperationSessionReducer::SpanSum)
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
            .begin_multi_capture(request, OperationSessionReducer::Participation)
    }
}

#[cfg(test)]
impl Slot {
    pub(super) fn test_set_counters(&mut self, counters: OperationSessionLeafCounters) {
        self.counters = counters;
    }

    pub(super) fn test_fill_canary(&mut self, seed: u64) {
        for (ordinal, values) in [
            &mut self.frontier,
            &mut self.next_frontier,
            &mut self.generation,
            &mut self.tagged_candidates,
            &mut self.tagged_cache,
            &mut self.history,
            &mut self.participation,
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
                self.frontier.capacity(),
                self.next_frontier.capacity(),
                self.generation.capacity(),
                self.tagged_candidates.capacity(),
                self.tagged_cache.capacity(),
                self.history.capacity(),
                self.participation.capacity(),
            ],
            contents: vec![
                self.frontier.as_slice().to_vec(),
                self.next_frontier.as_slice().to_vec(),
                self.generation.as_slice().to_vec(),
                self.tagged_candidates.as_slice().to_vec(),
                self.tagged_cache.as_slice().to_vec(),
                self.history.as_slice().to_vec(),
                self.participation.as_slice().to_vec(),
            ],
        }
    }
}
