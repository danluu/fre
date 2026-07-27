//! Grep-stream-lane-owned fixed storage and forced entry stubs.

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
