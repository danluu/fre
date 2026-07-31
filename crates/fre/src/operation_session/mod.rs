//! Four disjoint, caller-owned operation slots for forced FRE routes.
//!
//! Immutable compiled matchers remain shareable. A caller owns one mutable
//! session per worker thread; the session contains no lock or global cache.

use core::{cell::Cell, marker::PhantomData, mem::size_of};

use fre_exact_alloc::ExactVec;

#[cfg(test)]
#[global_allocator]
static OPERATION_SESSION_TEST_ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> =
    &stats_alloc::INSTRUMENTED_SYSTEM;

pub mod grep;
pub mod hot;
pub mod multi_capture;
mod receipt;
pub mod search;

pub use receipt::{
    OperationSessionAttemptReceipt, OperationSessionConstructionActual,
    OperationSessionConstructionLimits, OperationSessionConstructionProspective,
    OperationSessionConstructionReceipt, OperationSessionExecutionActual,
    OperationSessionExecutionProspective, OperationSessionInvocation, OperationSessionLeaf,
    OperationSessionLeafConstructionReceipt, OperationSessionLeafCounters, OperationSessionReducer,
    OperationSessionResetActual, OperationSessionResetAttemptReceipt, OperationSessionResetLimits,
    OperationSessionResetProspective, OperationSessionResource, OperationSessionRouteIdentity,
    OperationSessionRunLimits, OperationSessionStorageActual, OperationSessionStorageProspective,
    OperationSessionTerminal, OperationSessionValue,
};

use receipt::{
    OPERATION_SESSION_ACCOUNTING_ID, OPERATION_SESSION_ACCOUNTING_VERSION,
    OPERATION_SESSION_ALGORITHM_VERSION, OperationSessionAttemptEvidence,
    OperationSessionAttemptRequest, OperationSessionAttemptedOperation,
    OperationSessionFailureEvidence, aggregate_prospective, reset_limits_first_refusal,
};

/// Four namespaced, source-independent leaf admissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSessionAdmission {
    /// Search-lane fixed capacities.
    pub search: search::SlotAdmission,
    /// Hot-kernel-lane fixed capacities.
    pub hot: hot::SlotAdmission,
    /// Multi-capture-lane fixed capacities.
    pub multi_capture: multi_capture::SlotAdmission,
    /// Grep-stream-lane fixed capacities.
    pub grep: grep::SlotAdmission,
}

/// Construction error before session publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSessionError {
    /// A componentwise construction limit refused.
    Refused(OperationSessionResource),
    /// Checked arithmetic failed.
    ArithmeticOverflow,
    /// Fallible exact-layout allocation failed.
    AllocationFailed,
    /// A freshly built receipt failed its private closure.
    ReceiptNotClosed,
}

/// Reset failure with a closed terminal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSessionResetError {
    /// A reset was refused atomically.
    Refused(OperationSessionResetAttemptReceipt),
    /// A generated reset receipt did not close.
    ReceiptNotClosed(OperationSessionResetAttemptReceipt),
}

/// Forced operation failure with a closed terminal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationSessionAttemptError {
    /// A pre-source or in-operation refusal.
    Refused(OperationSessionAttemptReceipt),
    /// A generated attempt receipt did not close.
    ReceiptNotClosed(OperationSessionAttemptReceipt),
}

pub(crate) mod private {
    pub(crate) trait Sealed {}
}

/// Private protocol implemented by each disjoint leaf slot.
pub(crate) trait SessionLeafSlot: private::Sealed {
    const LEAF: OperationSessionLeaf;
    type Admission;

    fn prospective(
        admission: &Self::Admission,
    ) -> Result<OperationSessionStorageProspective, OperationSessionError>;

    fn try_new(
        admission: Self::Admission,
        prospective: &OperationSessionStorageProspective,
    ) -> Result<(Self, OperationSessionStorageActual), OperationSessionError>
    where
        Self: Sized;

    fn layout_id(&self) -> [u8; 16];
    fn generation_capacity(&self) -> usize;
    fn counters(&self) -> OperationSessionLeafCounters;
    fn reset_prospective(
        &self,
        required_generations: u64,
    ) -> Result<OperationSessionResetProspective, OperationSessionError>;
    fn apply_reset(
        &mut self,
        prospective: &OperationSessionResetProspective,
    ) -> OperationSessionResetActual;
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TestSlotSnapshot {
    capacities: Vec<usize>,
    contents: Vec<Vec<u64>>,
}

/// Root owner of four independently admitted mutable slots.
#[derive(Debug)]
pub struct OperationSession {
    construction: OperationSessionConstructionReceipt,
    search: search::Slot,
    hot: hot::Slot,
    multi_capture: multi_capture::Slot,
    grep: grep::Slot,
    _thread_owned: PhantomData<Cell<()>>,
}

impl OperationSession {
    /// Derive aggregate and fixed S/H/M/G construction prospectives.
    ///
    /// # Errors
    ///
    /// Refuses checked sum, byte, or work overflow.
    pub fn prospective(
        admission: &OperationSessionAdmission,
    ) -> Result<OperationSessionConstructionProspective, OperationSessionError> {
        let leaves = [
            search::Slot::prospective(&admission.search)?,
            hot::Slot::prospective(&admission.hot)?,
            multi_capture::Slot::prospective(&admission.multi_capture)?,
            grep::Slot::prospective(&admission.grep)?,
        ];
        let aggregate =
            aggregate_prospective(leaves).ok_or(OperationSessionError::ArithmeticOverflow)?;
        Ok(OperationSessionConstructionProspective { aggregate, leaves })
    }

    /// Allocate and fully initialize all four exact fixed-capacity slots.
    ///
    /// Every prospective and caller limit is checked before the first
    /// allocation. A failure publishes no partially usable session.
    ///
    /// # Errors
    ///
    /// Returns a typed construction refusal, arithmetic failure, allocation
    /// failure, or receipt-closure failure.
    pub fn try_new(
        admission: OperationSessionAdmission,
        limits: OperationSessionConstructionLimits,
    ) -> Result<Self, OperationSessionError> {
        let prospective = Self::prospective(&admission)?;
        if let Some(resource) = limits.first_refusal(prospective.aggregate) {
            return Err(OperationSessionError::Refused(resource));
        }

        let (search, search_actual) =
            search::Slot::try_new(admission.search, &prospective.leaves[0])?;
        let (hot, hot_actual) = hot::Slot::try_new(admission.hot, &prospective.leaves[1])?;
        let (multi_capture, multi_actual) =
            multi_capture::Slot::try_new(admission.multi_capture, &prospective.leaves[2])?;
        let (grep, grep_actual) = grep::Slot::try_new(admission.grep, &prospective.leaves[3])?;
        let leaf_actuals = [search_actual, hot_actual, multi_actual, grep_actual];
        let aggregate_actual = aggregate_storage_actual(leaf_actuals)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        let actual = OperationSessionConstructionActual {
            aggregate: aggregate_actual,
            leaves: leaf_actuals,
        };
        let leaves = [
            leaf_construction_receipt::<search::Slot>(
                &search,
                prospective.leaves[0],
                search_actual,
                search::ALGORITHM_VERSION,
                search::ACCOUNTING_VERSION,
                search::ACCOUNTING_ID,
            ),
            leaf_construction_receipt::<hot::Slot>(
                &hot,
                prospective.leaves[1],
                hot_actual,
                hot::ALGORITHM_VERSION,
                hot::ACCOUNTING_VERSION,
                hot::ACCOUNTING_ID,
            ),
            leaf_construction_receipt::<multi_capture::Slot>(
                &multi_capture,
                prospective.leaves[2],
                multi_actual,
                multi_capture::ALGORITHM_VERSION,
                multi_capture::ACCOUNTING_VERSION,
                multi_capture::ACCOUNTING_ID,
            ),
            leaf_construction_receipt::<grep::Slot>(
                &grep,
                prospective.leaves[3],
                grep_actual,
                grep::ALGORITHM_VERSION,
                grep::ACCOUNTING_VERSION,
                grep::ACCOUNTING_ID,
            ),
        ];
        let expected_layouts = leaves.map(|leaf| leaf.layout_id);
        let construction = OperationSessionConstructionReceipt::new(
            limits,
            prospective,
            actual,
            leaves,
            expected_layouts,
        );
        validate_construction_receipt(&construction)?;
        Ok(Self {
            construction,
            search,
            hot,
            multi_capture,
            grep,
            _thread_owned: PhantomData,
        })
    }

    /// Closed construction receipt.
    #[must_use]
    pub const fn construction_receipt(&self) -> &OperationSessionConstructionReceipt {
        &self.construction
    }

    /// Cumulative counters for one leaf.
    #[must_use]
    pub fn counters(&self, leaf: OperationSessionLeaf) -> OperationSessionLeafCounters {
        match leaf {
            OperationSessionLeaf::Search => self.search.counters(),
            OperationSessionLeaf::Hot => self.hot.counters(),
            OperationSessionLeaf::MultiCapture => self.multi_capture.counters(),
            OperationSessionLeaf::Grep => self.grep.counters(),
        }
    }

    /// Source-free selected-leaf reset prospective.
    ///
    /// Zero required generations is legal and still increments the reset
    /// invocation counter.
    ///
    /// # Errors
    ///
    /// Refuses checked counter, generation, cell, byte, or work overflow.
    pub fn reset_prospective(
        &self,
        leaf: OperationSessionLeaf,
        required_generations: u64,
    ) -> Result<OperationSessionResetProspective, OperationSessionError> {
        match leaf {
            OperationSessionLeaf::Search => self.search.reset_prospective(required_generations),
            OperationSessionLeaf::Hot => self.hot.reset_prospective(required_generations),
            OperationSessionLeaf::MultiCapture => {
                self.multi_capture.reset_prospective(required_generations)
            }
            OperationSessionLeaf::Grep => self.grep.reset_prospective(required_generations),
        }
    }

    /// Atomically reset one selected leaf.
    ///
    /// # Errors
    ///
    /// Every refusal contains a closed receipt and leaves all four slots
    /// unchanged.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub fn reset_forced(
        &mut self,
        leaf: OperationSessionLeaf,
        required_generations: u64,
        limits: OperationSessionResetLimits,
    ) -> Result<OperationSessionResetAttemptReceipt, OperationSessionResetError> {
        let all_before = self.all_counters();
        match leaf {
            OperationSessionLeaf::Search => {
                reset_forced_slot(all_before, &mut self.search, required_generations, limits)
            }
            OperationSessionLeaf::Hot => {
                reset_forced_slot(all_before, &mut self.hot, required_generations, limits)
            }
            OperationSessionLeaf::MultiCapture => reset_forced_slot(
                all_before,
                &mut self.multi_capture,
                required_generations,
                limits,
            ),
            OperationSessionLeaf::Grep => {
                reset_forced_slot(all_before, &mut self.grep, required_generations, limits)
            }
        }
    }

    fn all_counters(&self) -> [OperationSessionLeafCounters; 4] {
        [
            self.search.counters(),
            self.hot.counters(),
            self.multi_capture.counters(),
            self.grep.counters(),
        ]
    }
}

fn validate_construction_receipt(
    construction: &OperationSessionConstructionReceipt,
) -> Result<(), OperationSessionError> {
    if construction.closes() {
        Ok(())
    } else {
        Err(OperationSessionError::ReceiptNotClosed)
    }
}

/// One authenticated, selected-leaf forced attempt token.
#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
pub(crate) struct OperationSessionAttempt<'a, S: SessionLeafSlot> {
    slot: &'a mut S,
    request: OperationSessionAttemptRequest,
    expected_identity: OperationSessionRouteIdentity,
    reset: OperationSessionResetAttemptReceipt,
    construction_layout_id: [u8; 16],
    actual: OperationSessionExecutionActual,
    terminal: Option<OperationSessionTerminal>,
    evidence: OperationSessionAttemptEvidence,
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
impl<S: SessionLeafSlot> OperationSessionAttempt<'_, S> {
    /// Borrow the already selected leaf's private fixed storage.
    ///
    /// The concrete leaf module can access its own fields; this generic
    /// token cannot select or borrow any other session leaf.
    pub(crate) fn selected_slot(&mut self) -> &mut S {
        self.slot
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_work(&mut self, amount: u64) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::ExecutionWork, amount, |actual| {
            &mut actual.work
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_source_accesses(
        &mut self,
        amount: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::SourceAccesses, amount, |actual| {
            &mut actual.source_accesses
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_transitions(
        &mut self,
        amount: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::Transitions, amount, |actual| {
            &mut actual.transitions
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_candidates(
        &mut self,
        amount: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::Candidates, amount, |actual| {
            &mut actual.candidates
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_cache_misses(
        &mut self,
        amount: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::CacheMisses, amount, |actual| {
            &mut actual.cache_misses
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn meter_history_nodes(
        &mut self,
        amount: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        self.meter_dimension(OperationSessionResource::HistoryNodes, amount, |actual| {
            &mut actual.history_nodes
        })
    }

    /// Emit one ordered, nonoverlapping half-open span.
    ///
    /// Multi-capture `Count` and `SpanSum` operations require a concrete source
    /// pattern ordinal for every emitted span.
    ///
    /// # Errors
    ///
    /// Refuses invalid range/order, checked overflow, P, or run-limit excess
    /// with a closed terminal receipt and no value.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn emit_span(
        &mut self,
        start: usize,
        end: usize,
        pattern_ordinal: Option<usize>,
    ) -> Result<(), OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::Span {
            start,
            end,
            pattern_ordinal,
        };
        if S::LEAF == OperationSessionLeaf::Grep
            || !matches!(
                self.request.identity.reducer,
                OperationSessionReducer::Count | OperationSessionReducer::SpanSum
            )
        {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        let invalid_order = self.terminal.is_some()
            || (S::LEAF == OperationSessionLeaf::MultiCapture && pattern_ordinal.is_none())
            || start > end
            || start < self.request.invocation.range.start
            || end > self.request.invocation.range.end
            || self
                .evidence
                .last_span
                .is_some_and(|(last_start, last_end, last_pattern)| {
                    start < last_end
                        || start < last_start
                        || (start == last_start && pattern_ordinal <= last_pattern)
                });
        if invalid_order {
            return Err(self.fail_with(
                OperationSessionTerminal::InvalidInvocation,
                OperationSessionFailureEvidence::InvalidOrder,
                None,
                operation,
            ));
        }
        let Some(width_usize) = end.checked_sub(start) else {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        };
        let Ok(width) = u64::try_from(width_usize) else {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        };
        let mut next = self.actual;
        if checked_add_to(&mut next.output_events, 1).is_err()
            || checked_add_to(&mut next.selected_span_bytes, width).is_err()
        {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        }
        self.admit_actual(next, operation)?;
        let event = (start, end, pattern_ordinal);
        self.evidence.first_span.get_or_insert(event);
        self.evidence.last_span = Some(event);
        self.evidence.span_events = self
            .evidence
            .span_events
            .checked_add(1)
            .expect("admitted output count proves evidence count representable");
        Ok(())
    }

    /// Stage one checked participation source/pattern observation.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn observe_participation(
        &mut self,
        start: usize,
        end: usize,
        pattern_ordinal: usize,
    ) -> Result<(), OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::ObserveParticipation {
            start,
            end,
            pattern_ordinal,
        };
        if S::LEAF != OperationSessionLeaf::MultiCapture
            || self.request.identity.reducer != OperationSessionReducer::Participation
        {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        let invalid_order = self.terminal.is_some()
            || self.evidence.pending_participation.is_some()
            || start > end
            || start < self.request.invocation.range.start
            || end > self.request.invocation.range.end
            || self.evidence.last_participation.is_some_and(
                |(last_start, last_end, last_pattern)| {
                    start < last_end
                        || start < last_start
                        || (start == last_start && Some(pattern_ordinal) <= last_pattern)
                },
            );
        if invalid_order {
            return Err(self.fail_with(
                OperationSessionTerminal::InvalidInvocation,
                OperationSessionFailureEvidence::InvalidOrder,
                None,
                operation,
            ));
        }
        self.evidence.pending_participation = Some((start, end, pattern_ordinal));
        Ok(())
    }

    /// Emit direct capture-participation entries for the pending observation.
    ///
    /// # Errors
    ///
    /// Refuses checked overflow, P, or run-limit excess with a closed
    /// terminal receipt and no value.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn emit_participation(
        &mut self,
        entries: u64,
    ) -> Result<(), OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::EmitParticipation { entries };
        if S::LEAF != OperationSessionLeaf::MultiCapture
            || self.request.identity.reducer != OperationSessionReducer::Participation
        {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        if self.terminal.is_some() || self.evidence.pending_participation.is_none() {
            return Err(self.fail_with(
                OperationSessionTerminal::InvalidInvocation,
                OperationSessionFailureEvidence::InvalidOrder,
                None,
                operation,
            ));
        }
        let mut next = self.actual;
        if checked_add_to(&mut next.output_events, 1).is_err()
            || checked_add_to(&mut next.participation_entries, entries).is_err()
        {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        }
        self.admit_actual(next, operation)?;
        let (start, end, pattern_ordinal) = self
            .evidence
            .pending_participation
            .take()
            .expect("pending observation checked before admitted update");
        let observation = (start, end, Some(pattern_ordinal));
        self.evidence.first_participation.get_or_insert(observation);
        self.evidence.last_participation = Some(observation);
        self.evidence.participation_events = self
            .evidence
            .participation_events
            .checked_add(1)
            .expect("admitted output count proves evidence count representable");
        Ok(())
    }

    /// Emit one selected line domain in strict source-line order.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn emit_line_domain(
        &mut self,
        line_ordinal: usize,
    ) -> Result<(), OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::LineDomain { line_ordinal };
        if S::LEAF != OperationSessionLeaf::Grep
            || self.request.identity.reducer != OperationSessionReducer::Count
        {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        if self.terminal.is_some()
            || self
                .evidence
                .last_line_ordinal
                .is_some_and(|last| line_ordinal <= last)
        {
            return Err(self.fail_with(
                OperationSessionTerminal::InvalidInvocation,
                OperationSessionFailureEvidence::InvalidOrder,
                None,
                operation,
            ));
        }
        let mut next = self.actual;
        if checked_add_to(&mut next.line_domains, 1).is_err()
            || checked_add_to(&mut next.output_events, 1).is_err()
        {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        }
        self.admit_actual(next, operation)?;
        self.evidence.first_line_ordinal.get_or_insert(line_ordinal);
        self.evidence.last_line_ordinal = Some(line_ordinal);
        self.evidence.line_events = self
            .evidence
            .line_events
            .checked_add(1)
            .expect("admitted line-domain count proves evidence count representable");
        Ok(())
    }

    /// Finish a Count attempt.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn finish_count(
        self,
    ) -> Result<OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        let value = OperationSessionValue::Count(self.actual.output_events);
        self.finish(OperationSessionReducer::Count, value)
    }

    /// Finish a `SpanSum` attempt.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn finish_span_sum(
        self,
    ) -> Result<OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        let value = OperationSessionValue::SpanSum(self.actual.selected_span_bytes);
        self.finish(OperationSessionReducer::SpanSum, value)
    }

    /// Finish a Participation attempt.
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn finish_participation(
        self,
    ) -> Result<OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        let value = OperationSessionValue::Participation(self.actual.participation_entries);
        self.finish(OperationSessionReducer::Participation, value)
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn admit_actual(
        &mut self,
        next: OperationSessionExecutionActual,
        operation: OperationSessionAttemptedOperation,
    ) -> Result<(), OperationSessionAttemptError> {
        let prospective = self.request.prospective;
        if !prospective.contains_actual(next) {
            let resource = actual_first_excess(prospective, next);
            return Err(self.fail_with(
                OperationSessionTerminal::Refused(resource),
                OperationSessionFailureEvidence::RefusedActual,
                Some(next),
                operation,
            ));
        }
        let as_prospective = execution_actual_as_prospective(next);
        if let Some(resource) = self.request.run_limits.first_refusal(as_prospective) {
            return Err(self.fail_with(
                OperationSessionTerminal::Refused(resource),
                OperationSessionFailureEvidence::RefusedActual,
                Some(next),
                operation,
            ));
        }
        self.actual = next;
        Ok(())
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn finish(
        mut self,
        reducer: OperationSessionReducer,
        value: OperationSessionValue,
    ) -> Result<OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::Finish { reducer };
        if self.terminal.is_some() {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        if self.evidence.pending_participation.is_some() {
            return Err(self.fail_with(
                OperationSessionTerminal::InvalidInvocation,
                OperationSessionFailureEvidence::InvalidOrder,
                None,
                operation,
            ));
        }
        if self.request.identity.reducer != reducer {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        let receipt = self.receipt(Some(value), OperationSessionTerminal::Success);
        if receipt.closes() {
            Ok(receipt)
        } else {
            Err(OperationSessionAttemptError::ReceiptNotClosed(receipt))
        }
    }

    fn fail_with(
        &mut self,
        terminal: OperationSessionTerminal,
        failure: OperationSessionFailureEvidence,
        refused_actual: Option<OperationSessionExecutionActual>,
        attempted_operation: OperationSessionAttemptedOperation,
    ) -> OperationSessionAttemptError {
        if let Some(latched) = self.terminal {
            let receipt = self.receipt(None, latched);
            return if receipt.closes() {
                OperationSessionAttemptError::Refused(receipt)
            } else {
                OperationSessionAttemptError::ReceiptNotClosed(receipt)
            };
        }
        self.terminal = Some(terminal);
        self.evidence.failure = failure;
        self.evidence.refused_actual = refused_actual;
        self.evidence.attempted_operation = attempted_operation;
        if failure == OperationSessionFailureEvidence::InvalidOrder {
            self.evidence.order_valid = false;
        }
        let receipt = self.receipt(None, terminal);
        if receipt.closes() {
            OperationSessionAttemptError::Refused(receipt)
        } else {
            OperationSessionAttemptError::ReceiptNotClosed(receipt)
        }
    }

    fn receipt(
        &self,
        value: Option<OperationSessionValue>,
        terminal: OperationSessionTerminal,
    ) -> OperationSessionAttemptReceipt {
        OperationSessionAttemptReceipt::new(
            self.request.identity,
            self.expected_identity,
            self.request.invocation.clone(),
            self.request.run_limits,
            self.construction_layout_id,
            self.reset.clone(),
            Some(self.request.prospective),
            self.actual,
            value,
            terminal,
            self.evidence,
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn meter_dimension(
        &mut self,
        resource: OperationSessionResource,
        amount: u64,
        select: impl FnOnce(&mut OperationSessionExecutionActual) -> &mut u64,
    ) -> Result<(), OperationSessionAttemptError> {
        let operation = OperationSessionAttemptedOperation::Meter { resource, amount };
        if self.terminal.is_some() {
            return Err(self.fail_with(
                OperationSessionTerminal::IdentityMismatch,
                OperationSessionFailureEvidence::ReducerMismatch,
                None,
                operation,
            ));
        }
        let mut next = self.actual;
        if checked_add_to(select(&mut next), amount).is_err() {
            return Err(self.fail_with(
                OperationSessionTerminal::ArithmeticOverflow,
                OperationSessionFailureEvidence::ArithmeticOverflow,
                None,
                operation,
            ));
        }
        self.admit_actual(next, operation)
    }
}

/// Authenticate and begin one supported forced slot.
#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
#[allow(
    clippy::result_large_err,
    reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
)]
pub(crate) fn begin_forced_slot<'a, S: SessionLeafSlot>(
    construction: &OperationSessionConstructionReceipt,
    all_leaves_before: [OperationSessionLeafCounters; 4],
    slot: &'a mut S,
    request: OperationSessionAttemptRequest,
) -> Result<OperationSessionAttempt<'a, S>, OperationSessionAttemptError> {
    let expected_identity = expected_route_identity::<S>(&request);
    if let Some(failure) = preflight_attempt::<S>(construction, slot, &request, expected_identity) {
        let (terminal, prospective) = match failure {
            AttemptPreflightFailure::WithoutProspective(terminal) => (terminal, None),
            AttemptPreflightFailure::WithProspective(resource) => (
                OperationSessionTerminal::Refused(resource),
                Some(request.prospective),
            ),
        };
        return Err(pre_reset_attempt_error(
            all_leaves_before,
            slot,
            request,
            expected_identity,
            terminal,
            prospective,
        ));
    }
    let reset = match reset_forced_slot(
        all_leaves_before,
        slot,
        request.invocation.required_generations,
        request.reset_limits,
    ) {
        Ok(receipt) => receipt,
        Err(
            OperationSessionResetError::Refused(receipt)
            | OperationSessionResetError::ReceiptNotClosed(receipt),
        ) => {
            let terminal = receipt.terminal;
            let attempt = OperationSessionAttemptReceipt::new(
                expected_identity,
                expected_identity,
                request.invocation,
                request.run_limits,
                slot.layout_id(),
                receipt,
                Some(request.prospective),
                OperationSessionExecutionActual::default(),
                None,
                terminal,
                OperationSessionAttemptEvidence::empty(),
            );
            return if attempt.closes() {
                Err(OperationSessionAttemptError::Refused(attempt))
            } else {
                Err(OperationSessionAttemptError::ReceiptNotClosed(attempt))
            };
        }
    };
    Ok(OperationSessionAttempt {
        slot,
        request,
        expected_identity,
        construction_layout_id: reset.layout_id,
        reset,
        actual: OperationSessionExecutionActual::default(),
        terminal: None,
        evidence: OperationSessionAttemptEvidence::empty(),
    })
}

#[allow(
    clippy::result_large_err,
    reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
)]
fn reset_forced_slot<S: SessionLeafSlot>(
    all_leaves_before: [OperationSessionLeafCounters; 4],
    slot: &mut S,
    required_generations: u64,
    limits: OperationSessionResetLimits,
) -> Result<OperationSessionResetAttemptReceipt, OperationSessionResetError> {
    let layout_id = slot.layout_id();
    let Ok(prospective) = slot.reset_prospective(required_generations) else {
        let before = slot.counters();
        let actual = OperationSessionResetActual {
            leaf: S::LEAF,
            counters_before: before,
            counters_after: before,
            required_generations,
            work: 0,
        };
        let receipt = OperationSessionResetAttemptReceipt::new(
            layout_id,
            slot.generation_capacity(),
            limits,
            None,
            actual,
            all_leaves_before,
            all_leaves_before,
            OperationSessionTerminal::ArithmeticOverflow,
        );
        return Err(closed_reset_error(receipt));
    };
    if let Some(resource) = reset_limits_first_refusal(limits, prospective) {
        let actual = OperationSessionResetActual {
            leaf: S::LEAF,
            counters_before: prospective.counters_before,
            counters_after: prospective.counters_before,
            required_generations,
            work: 0,
        };
        let receipt = OperationSessionResetAttemptReceipt::new(
            layout_id,
            slot.generation_capacity(),
            limits,
            Some(prospective),
            actual,
            all_leaves_before,
            all_leaves_before,
            OperationSessionTerminal::Refused(resource),
        );
        return Err(closed_reset_error(receipt));
    }
    let actual = slot.apply_reset(&prospective);
    let mut all_leaves_after = all_leaves_before;
    all_leaves_after[S::LEAF.index()] = actual.counters_after;
    let receipt = OperationSessionResetAttemptReceipt::new(
        layout_id,
        slot.generation_capacity(),
        limits,
        Some(prospective),
        actual,
        all_leaves_before,
        all_leaves_after,
        OperationSessionTerminal::Success,
    );
    if receipt.closes() {
        Ok(receipt)
    } else {
        Err(OperationSessionResetError::ReceiptNotClosed(receipt))
    }
}

fn closed_reset_error(receipt: OperationSessionResetAttemptReceipt) -> OperationSessionResetError {
    if receipt.closes() {
        OperationSessionResetError::Refused(receipt)
    } else {
        OperationSessionResetError::ReceiptNotClosed(receipt)
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
enum AttemptPreflightFailure {
    WithoutProspective(OperationSessionTerminal),
    WithProspective(OperationSessionResource),
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn preflight_attempt<S: SessionLeafSlot>(
    construction: &OperationSessionConstructionReceipt,
    slot: &S,
    request: &OperationSessionAttemptRequest,
    expected_identity: OperationSessionRouteIdentity,
) -> Option<AttemptPreflightFailure> {
    debug_assert!(
        construction.closes(),
        "published operation sessions retain their closed construction receipt"
    );
    if request.trusted_compiled_plan_id() == [0; 16]
        || construction.leaves[S::LEAF.index()].layout_id != slot.layout_id()
        || request.identity != expected_identity
    {
        Some(AttemptPreflightFailure::WithoutProspective(
            OperationSessionTerminal::IdentityMismatch,
        ))
    } else if !invocation_closes(S::LEAF, request.trusted_reducer(), &request.invocation) {
        Some(AttemptPreflightFailure::WithoutProspective(
            OperationSessionTerminal::InvalidInvocation,
        ))
    } else if !route_supported(S::LEAF, request.trusted_reducer()) {
        Some(AttemptPreflightFailure::WithoutProspective(
            OperationSessionTerminal::UnsupportedReducer,
        ))
    } else if let Some(resource) = request.run_limits.first_refusal(request.prospective) {
        Some(AttemptPreflightFailure::WithProspective(resource))
    } else if request.prospective.allocations != 0 {
        Some(AttemptPreflightFailure::WithProspective(
            OperationSessionResource::Allocations,
        ))
    } else {
        None
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn pre_reset_attempt_error<S: SessionLeafSlot>(
    all_leaves_before: [OperationSessionLeafCounters; 4],
    slot: &S,
    request: OperationSessionAttemptRequest,
    expected_identity: OperationSessionRouteIdentity,
    terminal: OperationSessionTerminal,
    prospective: Option<OperationSessionExecutionProspective>,
) -> OperationSessionAttemptError {
    let before = slot.counters();
    let reset_actual = OperationSessionResetActual {
        leaf: S::LEAF,
        counters_before: before,
        counters_after: before,
        required_generations: request.invocation.required_generations,
        work: 0,
    };
    let reset = OperationSessionResetAttemptReceipt::new(
        slot.layout_id(),
        slot.generation_capacity(),
        request.reset_limits,
        None,
        reset_actual,
        all_leaves_before,
        all_leaves_before,
        terminal,
    );
    let mut evidence = OperationSessionAttemptEvidence::empty();
    if terminal == OperationSessionTerminal::IdentityMismatch {
        evidence.failure = OperationSessionFailureEvidence::RouteMismatch;
        evidence.attempted_identity = Some(request.identity);
    }
    let receipt = OperationSessionAttemptReceipt::new(
        expected_identity,
        expected_identity,
        request.invocation,
        request.run_limits,
        slot.layout_id(),
        reset,
        prospective,
        OperationSessionExecutionActual::default(),
        None,
        terminal,
        evidence,
    );
    if receipt.closes() {
        OperationSessionAttemptError::Refused(receipt)
    } else {
        OperationSessionAttemptError::ReceiptNotClosed(receipt)
    }
}

pub(crate) fn storage_prospective(
    persistent_cells: &[usize],
    scratch_cells: &[usize],
    generation_cells: usize,
) -> Result<OperationSessionStorageProspective, OperationSessionError> {
    let persistent = checked_sum(persistent_cells)?;
    let scratch = checked_sum(scratch_cells)?;
    let all_cells = persistent
        .checked_add(scratch)
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let persistent_bytes = persistent
        .checked_mul(size_of::<u64>())
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let scratch_bytes = scratch
        .checked_mul(size_of::<u64>())
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let peak_bytes = persistent_bytes
        .checked_add(scratch_bytes)
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let allocation_attempts = persistent_cells
        .iter()
        .chain(scratch_cells.iter())
        .filter(|cells| **cells != 0)
        .count();
    let build_work = u64::try_from(all_cells)
        .map_err(|_| OperationSessionError::ArithmeticOverflow)?
        .checked_add(
            u64::try_from(allocation_attempts)
                .map_err(|_| OperationSessionError::ArithmeticOverflow)?,
        )
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    Ok(OperationSessionStorageProspective {
        build_work,
        persistent_bytes,
        scratch_bytes,
        peak_bytes,
        generation_cells,
        initialized_bytes: peak_bytes,
        allocation_attempts,
    })
}

pub(crate) fn measured_storage_actual(
    persistent: &[&ExactVec<u64>],
    scratch: &[&ExactVec<u64>],
    generation: &ExactVec<u64>,
) -> Result<OperationSessionStorageActual, OperationSessionError> {
    let persistent_cells = persistent.iter().try_fold(0_usize, |total, values| {
        total
            .checked_add(values.capacity())
            .ok_or(OperationSessionError::ArithmeticOverflow)
    })?;
    let scratch_cells = scratch.iter().try_fold(0_usize, |total, values| {
        total
            .checked_add(values.capacity())
            .ok_or(OperationSessionError::ArithmeticOverflow)
    })?;
    let initialized_cells =
        persistent
            .iter()
            .chain(scratch.iter())
            .try_fold(0_usize, |total, values| {
                total
                    .checked_add(values.len())
                    .ok_or(OperationSessionError::ArithmeticOverflow)
            })?;
    let allocation_attempts = persistent
        .iter()
        .chain(scratch.iter())
        .filter(|values| values.capacity() != 0)
        .count();
    let persistent_bytes = persistent_cells
        .checked_mul(size_of::<u64>())
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let scratch_bytes = scratch_cells
        .checked_mul(size_of::<u64>())
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let peak_bytes = persistent_bytes
        .checked_add(scratch_bytes)
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let initialized_bytes = initialized_cells
        .checked_mul(size_of::<u64>())
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let build_work = u64::try_from(initialized_cells)
        .map_err(|_| OperationSessionError::ArithmeticOverflow)?
        .checked_add(
            u64::try_from(allocation_attempts)
                .map_err(|_| OperationSessionError::ArithmeticOverflow)?,
        )
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    Ok(OperationSessionStorageActual {
        build_work,
        persistent_bytes,
        scratch_bytes,
        peak_bytes,
        generation_cells: generation.capacity(),
        initialized_bytes,
        allocation_attempts,
    })
}

pub(crate) fn allocate_zeroed_cells(cells: usize) -> Result<ExactVec<u64>, OperationSessionError> {
    #[cfg(test)]
    if cells != 0 {
        exact_allocation_probe::record();
        if exact_allocation_probe::take_failure() {
            return Err(OperationSessionError::AllocationFailed);
        }
    }
    let mut values =
        ExactVec::try_with_capacity(cells).map_err(|_| OperationSessionError::AllocationFailed)?;
    for _ in 0..cells {
        values
            .try_push(0)
            .map_err(|_| OperationSessionError::ArithmeticOverflow)?;
    }
    Ok(values)
}

#[cfg(test)]
mod exact_allocation_probe {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static FAIL_CALL: Cell<Option<usize>> = const { Cell::new(None) };
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Scope;

    impl Drop for Scope {
        fn drop(&mut self) {
            reset();
            ACTIVE.set(false);
        }
    }

    pub(super) fn scope() -> Scope {
        assert!(!ACTIVE.replace(true), "allocation probe scopes cannot nest");
        reset();
        Scope
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
        FAIL_CALL.set(None);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn fail_call(call: usize) {
        FAIL_CALL.set(Some(call));
    }

    pub(super) fn take_failure() -> bool {
        let call = CALLS.get();
        if FAIL_CALL.get() == Some(call) {
            FAIL_CALL.set(None);
            true
        } else {
            false
        }
    }
}

pub(crate) fn derive_layout_id(
    mut seed: [u8; 16],
    capacities: &[usize],
) -> Result<[u8; 16], OperationSessionError> {
    for (ordinal, capacity) in capacities.iter().enumerate() {
        let value =
            u64::try_from(*capacity).map_err(|_| OperationSessionError::ArithmeticOverflow)?;
        let mixed = value.rotate_left(
            u32::try_from(ordinal % 64).map_err(|_| OperationSessionError::ArithmeticOverflow)?,
        ) ^ u64::try_from(ordinal)
            .map_err(|_| OperationSessionError::ArithmeticOverflow)?
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for (index, byte) in mixed.to_le_bytes().iter().enumerate() {
            let target = ordinal
                .checked_add(index)
                .ok_or(OperationSessionError::ArithmeticOverflow)?
                .checked_rem(seed.len())
                .ok_or(OperationSessionError::ArithmeticOverflow)?;
            seed[target] = seed[target].wrapping_add(*byte).rotate_left(1);
        }
    }
    Ok(seed)
}

pub(crate) const fn tag_layout_id(leaf: OperationSessionLeaf, mut layout_id: [u8; 16]) -> [u8; 16] {
    layout_id[15] = match leaf {
        OperationSessionLeaf::Search => 1,
        OperationSessionLeaf::Hot => 2,
        OperationSessionLeaf::MultiCapture => 3,
        OperationSessionLeaf::Grep => 4,
    };
    layout_id
}

pub(crate) fn leaf_reset_prospective(
    leaf: OperationSessionLeaf,
    before: OperationSessionLeafCounters,
    generation_cells: usize,
    required_generations: u64,
) -> Result<OperationSessionResetProspective, OperationSessionError> {
    let mut after = before;
    after.reset_invocations = after
        .reset_invocations
        .checked_add(1)
        .ok_or(OperationSessionError::ArithmeticOverflow)?;
    let mut work = 1_u64;
    if let Some(generation) = before.generation.checked_add(required_generations) {
        after.generation = generation;
    } else {
        let cells = u64::try_from(generation_cells)
            .map_err(|_| OperationSessionError::ArithmeticOverflow)?;
        let bytes = cells
            .checked_mul(
                u64::try_from(size_of::<u64>())
                    .map_err(|_| OperationSessionError::ArithmeticOverflow)?,
            )
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        after.generation = required_generations;
        after.rollovers = after
            .rollovers
            .checked_add(1)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        after.clears = after
            .clears
            .checked_add(1)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        after.clear_cells = after
            .clear_cells
            .checked_add(cells)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        after.clear_bytes = after
            .clear_bytes
            .checked_add(bytes)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
        work = work
            .checked_add(cells)
            .ok_or(OperationSessionError::ArithmeticOverflow)?;
    }
    Ok(OperationSessionResetProspective {
        leaf,
        counters_before: before,
        counters_after: after,
        required_generations,
        work,
    })
}

pub(crate) fn apply_leaf_reset(
    generation: &mut ExactVec<u64>,
    counters: &mut OperationSessionLeafCounters,
    prospective: &OperationSessionResetProspective,
) -> OperationSessionResetActual {
    if prospective.counters_after.rollovers != prospective.counters_before.rollovers {
        generation.as_mut_slice().fill(0);
    }
    *counters = prospective.counters_after;
    OperationSessionResetActual::from(*prospective)
}

fn checked_sum(values: &[usize]) -> Result<usize, OperationSessionError> {
    values.iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(*value)
            .ok_or(OperationSessionError::ArithmeticOverflow)
    })
}

fn aggregate_storage_actual(
    leaves: [OperationSessionStorageActual; 4],
) -> Option<OperationSessionStorageActual> {
    let prospectives = leaves.map(|leaf| OperationSessionStorageProspective {
        build_work: leaf.build_work,
        persistent_bytes: leaf.persistent_bytes,
        scratch_bytes: leaf.scratch_bytes,
        peak_bytes: leaf.peak_bytes,
        generation_cells: leaf.generation_cells,
        initialized_bytes: leaf.initialized_bytes,
        allocation_attempts: leaf.allocation_attempts,
    });
    aggregate_prospective(prospectives).map(Into::into)
}

fn leaf_construction_receipt<S: SessionLeafSlot>(
    slot: &S,
    prospective: OperationSessionStorageProspective,
    actual: OperationSessionStorageActual,
    algorithm_version: u32,
    accounting_version: u32,
    accounting_id: &'static str,
) -> OperationSessionLeafConstructionReceipt {
    OperationSessionLeafConstructionReceipt {
        leaf: S::LEAF,
        layout_id: slot.layout_id(),
        leaf_algorithm_version: algorithm_version,
        leaf_accounting_version: accounting_version,
        leaf_accounting_id: accounting_id,
        prospective,
        actual,
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn leaf_algorithm_version(leaf: OperationSessionLeaf) -> u32 {
    match leaf {
        OperationSessionLeaf::Search => search::ALGORITHM_VERSION,
        OperationSessionLeaf::Hot => hot::ALGORITHM_VERSION,
        OperationSessionLeaf::MultiCapture => multi_capture::ALGORITHM_VERSION,
        OperationSessionLeaf::Grep => grep::ALGORITHM_VERSION,
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn leaf_accounting_version(leaf: OperationSessionLeaf) -> u32 {
    match leaf {
        OperationSessionLeaf::Search => search::ACCOUNTING_VERSION,
        OperationSessionLeaf::Hot => hot::ACCOUNTING_VERSION,
        OperationSessionLeaf::MultiCapture => multi_capture::ACCOUNTING_VERSION,
        OperationSessionLeaf::Grep => grep::ACCOUNTING_VERSION,
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn leaf_accounting_id(leaf: OperationSessionLeaf) -> &'static str {
    match leaf {
        OperationSessionLeaf::Search => search::ACCOUNTING_ID,
        OperationSessionLeaf::Hot => hot::ACCOUNTING_ID,
        OperationSessionLeaf::MultiCapture => multi_capture::ACCOUNTING_ID,
        OperationSessionLeaf::Grep => grep::ACCOUNTING_ID,
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn expected_route_identity<S: SessionLeafSlot>(
    request: &OperationSessionAttemptRequest,
) -> OperationSessionRouteIdentity {
    let reducer = request.trusted_reducer();
    let (source_identity, order_identity, fallback_identity) = route_contract(S::LEAF, reducer);
    OperationSessionRouteIdentity {
        session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
        session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
        session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
        leaf: S::LEAF,
        reducer,
        compiled_plan_id: request.trusted_compiled_plan_id(),
        source_identity,
        order_identity,
        fallback_identity,
        leaf_algorithm_version: leaf_algorithm_version(S::LEAF),
        leaf_accounting_version: leaf_accounting_version(S::LEAF),
        leaf_accounting_id: leaf_accounting_id(S::LEAF),
    }
}

pub(crate) fn route_contract(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
) -> (&'static str, &'static str, &'static str) {
    match leaf {
        OperationSessionLeaf::Search => search::route_contract(reducer),
        OperationSessionLeaf::Hot => hot::route_contract(reducer),
        OperationSessionLeaf::MultiCapture => multi_capture::route_contract(reducer),
        OperationSessionLeaf::Grep => grep::route_contract(reducer),
    }
}

pub(crate) fn route_supported(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
) -> bool {
    match leaf {
        OperationSessionLeaf::Search => search::supports(reducer),
        OperationSessionLeaf::Hot => hot::supports(reducer),
        OperationSessionLeaf::MultiCapture => multi_capture::supports(reducer),
        OperationSessionLeaf::Grep => grep::supports(reducer),
    }
}

pub(crate) fn invocation_closes(
    leaf: OperationSessionLeaf,
    reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
) -> bool {
    match leaf {
        OperationSessionLeaf::Search => search::invocation_closes(reducer, invocation),
        OperationSessionLeaf::Hot => hot::invocation_closes(reducer, invocation),
        OperationSessionLeaf::MultiCapture => multi_capture::invocation_closes(reducer, invocation),
        OperationSessionLeaf::Grep => grep::invocation_closes(reducer, invocation),
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
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

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn actual_first_excess(
    prospective: OperationSessionExecutionProspective,
    actual: OperationSessionExecutionActual,
) -> OperationSessionResource {
    let limits = OperationSessionRunLimits::exact(prospective);
    limits
        .first_refusal(execution_actual_as_prospective(actual))
        .unwrap_or(OperationSessionResource::ExecutionWork)
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
fn checked_add_to(value: &mut u64, amount: u64) -> Result<(), ()> {
    *value = value.checked_add(amount).ok_or(())?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the exhaustive contract matrix uses guarded one-below and compact test arithmetic"
)]
mod tests {
    use super::*;

    const PLAN_ID: [u8; 16] = [0x51; 16];

    fn admission() -> OperationSessionAdmission {
        OperationSessionAdmission {
            search: search::SlotAdmission {
                frontier_cells: 3,
                next_frontier_cells: 4,
                generation_cells: 5,
                candidate_cells: 6,
                cache_cells: 7,
                history_cells: 8,
            },
            hot: hot::SlotAdmission {
                state_cells: 9,
                generation_cells: 10,
                candidate_cells: 11,
                cache_cells: 12,
                history_cells: 13,
            },
            multi_capture: multi_capture::SlotAdmission {
                frontier_cells: 14,
                next_frontier_cells: 15,
                generation_cells: 16,
                tagged_candidate_cells: 17,
                tagged_cache_cells: 18,
                history_cells: 19,
                participation_cells: 20,
            },
            grep: grep::SlotAdmission {
                line_state_cells: 21,
                generation_cells: 22,
                candidate_cells: 23,
                cache_cells: 24,
                history_cells: 25,
            },
        }
    }

    fn session() -> OperationSession {
        let admission = admission();
        let prospective = OperationSession::prospective(&admission).unwrap();
        OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
        .unwrap()
    }

    fn identity(
        leaf: OperationSessionLeaf,
        reducer: OperationSessionReducer,
        plan_id: [u8; 16],
    ) -> OperationSessionRouteIdentity {
        let (source_identity, order_identity, fallback_identity) = route_contract(leaf, reducer);
        OperationSessionRouteIdentity {
            session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
            session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
            leaf,
            reducer,
            compiled_plan_id: plan_id,
            source_identity,
            order_identity,
            fallback_identity,
            leaf_algorithm_version: leaf_algorithm_version(leaf),
            leaf_accounting_version: leaf_accounting_version(leaf),
            leaf_accounting_id: leaf_accounting_id(leaf),
        }
    }

    fn request_with(
        leaf: OperationSessionLeaf,
        reducer: OperationSessionReducer,
        invocation: OperationSessionInvocation,
        prospective: OperationSessionExecutionProspective,
    ) -> OperationSessionAttemptRequest {
        let identity = identity(leaf, reducer, PLAN_ID);
        OperationSessionAttemptRequest::new_trusted(
            identity,
            invocation,
            prospective,
            OperationSessionResetLimits {
                max_work: u64::MAX,
                max_clear_cells: usize::MAX,
                max_clear_bytes: usize::MAX,
            },
            OperationSessionRunLimits::exact(prospective),
            PLAN_ID,
        )
        .unwrap()
    }

    fn request(
        leaf: OperationSessionLeaf,
        reducer: OperationSessionReducer,
        prospective: OperationSessionExecutionProspective,
    ) -> OperationSessionAttemptRequest {
        request_with(
            leaf,
            reducer,
            OperationSessionInvocation {
                haystack_len: 100,
                range: 0..100,
                required_generations: 0,
            },
            prospective,
        )
    }

    fn attempt_error_receipt(
        error: OperationSessionAttemptError,
    ) -> OperationSessionAttemptReceipt {
        match error {
            OperationSessionAttemptError::Refused(receipt)
            | OperationSessionAttemptError::ReceiptNotClosed(receipt) => receipt,
        }
    }

    fn begin_error<S: SessionLeafSlot>(
        result: Result<OperationSessionAttempt<'_, S>, OperationSessionAttemptError>,
    ) -> OperationSessionAttemptError {
        match result {
            Ok(_) => panic!("attempt unexpectedly admitted"),
            Err(error) => error,
        }
    }

    fn run_one_count(
        session: &mut OperationSession,
        leaf: OperationSessionLeaf,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        match leaf {
            OperationSessionLeaf::Search => {
                let mut forced = session.forced_search();
                let mut attempt = forced.begin_count(request)?;
                attempt.emit_span(0, 1, None)?;
                attempt.finish_count()
            }
            OperationSessionLeaf::Hot => {
                let mut forced = session.forced_hot();
                let mut attempt = forced.begin_count(request)?;
                attempt.emit_span(0, 1, None)?;
                attempt.finish_count()
            }
            OperationSessionLeaf::MultiCapture => {
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced.begin_count(request)?;
                attempt.emit_span(0, 1, Some(0))?;
                attempt.finish_count()
            }
            OperationSessionLeaf::Grep => {
                let mut forced = session.forced_grep();
                let mut attempt = forced.begin_count(request)?;
                attempt.emit_line_domain(0)?;
                attempt.finish_count()
            }
        }
    }

    fn snapshots(session: &OperationSession) -> [TestSlotSnapshot; 4] {
        [
            session.search.test_snapshot(),
            session.hot.test_snapshot(),
            session.multi_capture.test_snapshot(),
            session.grep.test_snapshot(),
        ]
    }

    fn generation_contents(
        snapshots: &[TestSlotSnapshot; 4],
        leaf: OperationSessionLeaf,
    ) -> &[u64] {
        let generation_ordinal = match leaf {
            OperationSessionLeaf::Search | OperationSessionLeaf::MultiCapture => 2,
            OperationSessionLeaf::Hot | OperationSessionLeaf::Grep => 1,
        };
        &snapshots[leaf.index()].contents[generation_ordinal]
    }

    #[test]
    fn attempt_first_terminal_latches_and_replays_exact_receipt() {
        let mut session = session();
        let request = request(
            OperationSessionLeaf::Search,
            OperationSessionReducer::Count,
            OperationSessionExecutionProspective::default(),
        );
        let mut forced = session.forced_search();
        let mut attempt = forced.begin_count(request).unwrap();
        let first = attempt_error_receipt(attempt.emit_span(0, 1, None).unwrap_err());
        assert!(first.closes());
        let replay = attempt_error_receipt(attempt.meter_source_accesses(1).unwrap_err());
        assert_eq!(replay, first);
        let replay = attempt_error_receipt(attempt.observe_participation(1, 1, 0).unwrap_err());
        assert_eq!(replay, first);
        let replay = attempt_error_receipt(attempt.emit_participation(1).unwrap_err());
        assert_eq!(replay, first);
        let replay = attempt_error_receipt(attempt.emit_line_domain(1).unwrap_err());
        assert_eq!(replay, first);
        let replay = attempt_error_receipt(attempt.finish_span_sum().unwrap_err());
        assert_eq!(replay, first);
        assert!(replay.closes());
    }

    #[test]
    fn token_route_methods_fail_closed_before_execution_mutation_and_replay() {
        {
            let mut session = session();
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::Count,
                    OperationSessionExecutionProspective::default(),
                ))
                .unwrap();
            let first = attempt_error_receipt(attempt.emit_line_domain(0).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::IdentityMismatch);
            assert_eq!(first.actual, OperationSessionExecutionActual::default());
            assert_eq!(first.value, None);
            assert!(first.closes());
            let replay = attempt_error_receipt(attempt.meter_work(1).unwrap_err());
            assert_eq!(replay, first);
        }
        {
            let mut session = session();
            let mut forced = session.forced_multi_capture();
            let mut attempt = forced
                .begin_participation(request(
                    OperationSessionLeaf::MultiCapture,
                    OperationSessionReducer::Participation,
                    OperationSessionExecutionProspective::default(),
                ))
                .unwrap();
            let first = attempt_error_receipt(attempt.emit_span(0, 0, Some(0)).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::IdentityMismatch);
            assert_eq!(first.actual, OperationSessionExecutionActual::default());
            assert_eq!(first.value, None);
            assert!(first.closes());
            let replay = attempt_error_receipt(attempt.emit_participation(0).unwrap_err());
            assert_eq!(replay, first);
        }
        {
            let mut session = session();
            let mut forced = session.forced_grep();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Grep,
                    OperationSessionReducer::Count,
                    OperationSessionExecutionProspective::default(),
                ))
                .unwrap();
            let first = attempt_error_receipt(attempt.emit_span(0, 0, None).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::IdentityMismatch);
            assert_eq!(first.actual, OperationSessionExecutionActual::default());
            assert_eq!(first.value, None);
            assert!(first.closes());
            let replay = attempt_error_receipt(attempt.emit_line_domain(0).unwrap_err());
            assert_eq!(replay, first);
        }
    }

    #[test]
    fn runtime_refusal_and_meter_overflow_witnesses_close_and_replay() {
        {
            let mut session = session();
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::Count,
                    OperationSessionExecutionProspective::default(),
                ))
                .unwrap();
            let first = attempt_error_receipt(attempt.emit_span(0, 1, None).unwrap_err());
            assert_eq!(
                first.terminal,
                OperationSessionTerminal::Refused(OperationSessionResource::OutputEvents)
            );
            assert_eq!(first.actual, OperationSessionExecutionActual::default());
            assert!(first.closes());
            let replay = attempt_error_receipt(attempt.finish_count().unwrap_err());
            assert_eq!(replay, first);
        }
        {
            let p = OperationSessionExecutionProspective {
                work: u64::MAX,
                ..OperationSessionExecutionProspective::default()
            };
            let mut session = session();
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::Count,
                    p,
                ))
                .unwrap();
            attempt.meter_work(u64::MAX).unwrap();
            let first = attempt_error_receipt(attempt.meter_work(1).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::ArithmeticOverflow);
            assert_eq!(first.actual.work, u64::MAX);
            assert!(first.closes());
            let replay = attempt_error_receipt(attempt.finish_count().unwrap_err());
            assert_eq!(replay, first);
        }
    }

    #[test]
    fn grep_count_partial_range_refuses_before_reset_and_source() {
        let mut session = session();
        let before = session.all_counters();
        let before_storage = snapshots(&session);
        let request = request_with(
            OperationSessionLeaf::Grep,
            OperationSessionReducer::Count,
            OperationSessionInvocation {
                haystack_len: 100,
                range: 1..2,
                required_generations: 1,
            },
            OperationSessionExecutionProspective::default(),
        );
        let receipt =
            attempt_error_receipt(begin_error(session.forced_grep().begin_count(request)));
        assert_eq!(
            receipt.terminal,
            OperationSessionTerminal::InvalidInvocation
        );
        assert!(receipt.closes());
        assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
        assert_eq!(
            receipt.reset.all_leaves_before,
            receipt.reset.all_leaves_after
        );
        assert_eq!(session.all_counters(), before);
        assert_eq!(snapshots(&session), before_storage);
    }

    #[test]
    fn malformed_ranges_refuse_before_reset_and_source() {
        for range in [core::ops::Range { start: 5, end: 4 }, 0..11] {
            let mut session = session();
            let before = session.all_counters();
            let before_storage = snapshots(&session);
            let request = request_with(
                OperationSessionLeaf::Search,
                OperationSessionReducer::Count,
                OperationSessionInvocation {
                    haystack_len: 10,
                    range,
                    required_generations: 1,
                },
                OperationSessionExecutionProspective::default(),
            );
            let receipt = {
                let mut forced = session.forced_search();
                attempt_error_receipt(begin_error(forced.begin_count(request)))
            };
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::InvalidInvocation
            );
            assert!(receipt.closes());
            assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            assert_eq!(session.all_counters(), before);
            assert_eq!(snapshots(&session), before_storage);
        }
    }

    #[test]
    fn zero_trusted_plan_never_returns_a_source_capable_token() {
        let mut session = session();
        let before_counters = session.all_counters();
        let before_storage = snapshots(&session);
        let attempted = identity(
            OperationSessionLeaf::Search,
            OperationSessionReducer::Count,
            [0; 16],
        );
        assert!(matches!(
            OperationSessionAttemptRequest::new_trusted(
                attempted,
                OperationSessionInvocation {
                    haystack_len: 1,
                    range: 0..1,
                    required_generations: 1,
                },
                OperationSessionExecutionProspective::default(),
                OperationSessionResetLimits {
                    max_work: u64::MAX,
                    max_clear_cells: usize::MAX,
                    max_clear_bytes: usize::MAX,
                },
                OperationSessionRunLimits::exact(OperationSessionExecutionProspective::default(),),
                [0; 16],
            ),
            Err(OperationSessionTerminal::IdentityMismatch)
        ));
        let request = OperationSessionAttemptRequest::new_unchecked_for_test(
            attempted,
            OperationSessionInvocation {
                haystack_len: 1,
                range: 0..1,
                required_generations: 1,
            },
            OperationSessionExecutionProspective::default(),
            OperationSessionResetLimits {
                max_work: u64::MAX,
                max_clear_cells: usize::MAX,
                max_clear_bytes: usize::MAX,
            },
            OperationSessionRunLimits::exact(OperationSessionExecutionProspective::default()),
            [0; 16],
        );
        let error = begin_error(session.forced_search().begin_count(request));
        assert!(matches!(
            &error,
            OperationSessionAttemptError::ReceiptNotClosed(_)
        ));
        let receipt = attempt_error_receipt(error);
        assert!(!receipt.closes());
        assert_eq!(session.all_counters(), before_counters);
        assert_eq!(snapshots(&session), before_storage);
    }

    fn zero_admission() -> OperationSessionAdmission {
        OperationSessionAdmission {
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
            grep: grep::SlotAdmission {
                line_state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
        }
    }

    fn isolated_admission(leaf: OperationSessionLeaf) -> OperationSessionAdmission {
        let mut value = zero_admission();
        match leaf {
            OperationSessionLeaf::Search => {
                value.search = search::SlotAdmission {
                    frontier_cells: 1,
                    next_frontier_cells: 1,
                    generation_cells: 1,
                    candidate_cells: 1,
                    cache_cells: 1,
                    history_cells: 1,
                };
            }
            OperationSessionLeaf::Hot => {
                value.hot = hot::SlotAdmission {
                    state_cells: 1,
                    generation_cells: 1,
                    candidate_cells: 1,
                    cache_cells: 1,
                    history_cells: 1,
                };
            }
            OperationSessionLeaf::MultiCapture => {
                value.multi_capture = multi_capture::SlotAdmission {
                    frontier_cells: 1,
                    next_frontier_cells: 1,
                    generation_cells: 1,
                    tagged_candidate_cells: 1,
                    tagged_cache_cells: 1,
                    history_cells: 1,
                    participation_cells: 1,
                };
            }
            OperationSessionLeaf::Grep => {
                value.grep = grep::SlotAdmission {
                    line_state_cells: 1,
                    generation_cells: 1,
                    candidate_cells: 1,
                    cache_cells: 1,
                    history_cells: 1,
                };
            }
        }
        value
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "every one-below subtraction is guarded by a positive prospective"
    )]
    fn assert_construction_fences(admission: OperationSessionAdmission) {
        let prospective = OperationSession::prospective(&admission).unwrap();
        let exact = OperationSessionConstructionLimits::exact(&prospective);
        let mut cases = Vec::new();
        if prospective.aggregate.build_work > 0 {
            cases.push((
                OperationSessionResource::BuildWork,
                OperationSessionConstructionLimits {
                    max_build_work: prospective.aggregate.build_work - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.persistent_bytes > 0 {
            cases.push((
                OperationSessionResource::PersistentBytes,
                OperationSessionConstructionLimits {
                    max_persistent_bytes: prospective.aggregate.persistent_bytes - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.scratch_bytes > 0 {
            cases.push((
                OperationSessionResource::ScratchBytes,
                OperationSessionConstructionLimits {
                    max_scratch_bytes: prospective.aggregate.scratch_bytes - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.peak_bytes > 0 {
            cases.push((
                OperationSessionResource::PeakBytes,
                OperationSessionConstructionLimits {
                    max_peak_bytes: prospective.aggregate.peak_bytes - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.generation_cells > 0 {
            cases.push((
                OperationSessionResource::GenerationCells,
                OperationSessionConstructionLimits {
                    max_generation_cells: prospective.aggregate.generation_cells - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.initialized_bytes > 0 {
            cases.push((
                OperationSessionResource::InitializedBytes,
                OperationSessionConstructionLimits {
                    max_initialized_bytes: prospective.aggregate.initialized_bytes - 1,
                    ..exact
                },
            ));
        }
        if prospective.aggregate.allocation_attempts > 0 {
            cases.push((
                OperationSessionResource::AllocationAttempts,
                OperationSessionConstructionLimits {
                    max_allocation_attempts: prospective.aggregate.allocation_attempts - 1,
                    ..exact
                },
            ));
        }
        for (resource, limits) in cases {
            let _probe = exact_allocation_probe::scope();
            exact_allocation_probe::fail_call(1);
            let error = OperationSession::try_new(admission, limits).unwrap_err();
            assert_eq!(error, OperationSessionError::Refused(resource));
            assert_eq!(exact_allocation_probe::calls(), 0, "{resource:?}");
        }
    }

    #[test]
    fn construction_exact_aggregate_and_leaf_actuals_close() {
        let admission = admission();
        let prospective = OperationSession::prospective(&admission).unwrap();
        let session = OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
        .unwrap();
        let receipt = session.construction_receipt();
        assert!(receipt.closes());
        assert_eq!(receipt.prospective, prospective);
        for index in 0..4 {
            let p = receipt.prospective.leaves[index];
            let a = receipt.actual.leaves[index];
            assert_eq!(p.build_work, a.build_work);
            assert_eq!(p.persistent_bytes, a.persistent_bytes);
            assert_eq!(p.scratch_bytes, a.scratch_bytes);
            assert_eq!(p.peak_bytes, a.peak_bytes);
            assert_eq!(p.generation_cells, a.generation_cells);
            assert_eq!(p.initialized_bytes, a.initialized_bytes);
            assert_eq!(p.allocation_attempts, a.allocation_attempts);
        }
    }

    #[test]
    fn construction_validation_rejects_tampered_receipts_before_publication() {
        let receipt = session().construction_receipt().clone();
        assert_eq!(validate_construction_receipt(&receipt), Ok(()));

        let mut wrong_schema = receipt.clone();
        wrong_schema.schema_version ^= 1;
        assert_eq!(
            validate_construction_receipt(&wrong_schema),
            Err(OperationSessionError::ReceiptNotClosed)
        );

        let mut wrong_layout = receipt;
        wrong_layout.leaves[OperationSessionLeaf::Hot.index()].layout_id[0] ^= 1;
        assert_eq!(
            validate_construction_receipt(&wrong_layout),
            Err(OperationSessionError::ReceiptNotClosed)
        );
    }

    #[test]
    fn construction_each_positive_root_limit_one_below_precedes_allocation() {
        assert_construction_fences(admission());
    }

    #[test]
    fn construction_each_isolated_leaf_limit_one_below_precedes_allocation() {
        for leaf in OperationSessionLeaf::ORDERED {
            assert_construction_fences(isolated_admission(leaf));
        }
    }

    #[test]
    fn construction_checked_sum_overflow_precedes_allocation() {
        let mut admission = zero_admission();
        admission.search.frontier_cells = usize::MAX;
        admission.search.next_frontier_cells = 1;
        let _probe = exact_allocation_probe::scope();
        exact_allocation_probe::fail_call(1);
        assert_eq!(
            OperationSession::prospective(&admission),
            Err(OperationSessionError::ArithmeticOverflow)
        );
        assert_eq!(exact_allocation_probe::calls(), 0);
        let mut leaves = [OperationSessionStorageProspective::default(); 4];
        leaves[0].build_work = u64::MAX;
        leaves[1].build_work = 1;
        assert_eq!(aggregate_prospective(leaves), None);
        assert_eq!(
            storage_prospective(&[usize::MAX / 8], &[1], 0),
            Err(OperationSessionError::ArithmeticOverflow)
        );
    }

    #[test]
    fn construction_exact_allocator_failure_has_no_session_publication() {
        let admission = admission();
        let prospective = OperationSession::prospective(&admission).unwrap();
        let _probe = exact_allocation_probe::scope();
        exact_allocation_probe::fail_call(2);
        let error = OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
        .unwrap_err();
        assert_eq!(error, OperationSessionError::AllocationFailed);
        assert_eq!(exact_allocation_probe::calls(), 2);
    }

    #[test]
    fn construction_zero_capacity_leaves_allocate_zero_and_have_unique_layouts() {
        let admission = zero_admission();
        let prospective = OperationSession::prospective(&admission).unwrap();
        assert_eq!(prospective.aggregate.allocation_attempts, 0);
        let _probe = exact_allocation_probe::scope();
        let session = OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
        .unwrap();
        assert_eq!(exact_allocation_probe::calls(), 0);
        let receipt = session.construction_receipt();
        assert!(receipt.closes());
        for left in 0..4 {
            assert_ne!(receipt.leaves[left].layout_id, [0; 16]);
            for right in (left + 1)..4 {
                assert_ne!(
                    receipt.leaves[left].layout_id,
                    receipt.leaves[right].layout_id
                );
            }
        }
    }

    fn reset_error_receipt(
        error: OperationSessionResetError,
    ) -> OperationSessionResetAttemptReceipt {
        match error {
            OperationSessionResetError::Refused(receipt)
            | OperationSessionResetError::ReceiptNotClosed(receipt) => receipt,
        }
    }

    fn exact_reset_limits(
        session: &OperationSession,
        leaf: OperationSessionLeaf,
        required_generations: u64,
    ) -> OperationSessionResetLimits {
        let prospective = session
            .reset_prospective(leaf, required_generations)
            .unwrap();
        OperationSessionResetLimits::exact(&prospective).unwrap()
    }

    fn set_counters(
        session: &mut OperationSession,
        leaf: OperationSessionLeaf,
        counters: OperationSessionLeafCounters,
    ) {
        match leaf {
            OperationSessionLeaf::Search => session.search.test_set_counters(counters),
            OperationSessionLeaf::Hot => session.hot.test_set_counters(counters),
            OperationSessionLeaf::MultiCapture => {
                session.multi_capture.test_set_counters(counters);
            }
            OperationSessionLeaf::Grep => session.grep.test_set_counters(counters),
        }
    }

    fn fill_canaries(session: &mut OperationSession) {
        session.search.test_fill_canary(0x1000);
        session.hot.test_fill_canary(0x2000);
        session.multi_capture.test_fill_canary(0x3000);
        session.grep.test_fill_canary(0x4000);
    }

    #[test]
    fn reset_ordinary_exact_and_zero_generation_semantics() {
        let mut session = session();
        let leaf = OperationSessionLeaf::Search;
        let receipt = session
            .reset_forced(leaf, 7, exact_reset_limits(&session, leaf, 7))
            .unwrap();
        assert!(receipt.closes());
        assert_eq!(receipt.actual.counters_after.generation, 7);
        assert_eq!(receipt.prospective.unwrap().work, 1);
        assert_eq!(receipt.actual.work, 1);
        assert_eq!(receipt.actual.counters_after.reset_invocations, 1);
        assert_eq!(receipt.actual.counters_after.rollovers, 0);
        assert_eq!(receipt.actual.counters_after.clears, 0);
        assert_eq!(receipt.actual.counters_after.clear_cells, 0);
        assert_eq!(receipt.actual.counters_after.clear_bytes, 0);

        let before = session.counters(leaf);
        let zero = session
            .reset_forced(leaf, 0, exact_reset_limits(&session, leaf, 0))
            .unwrap();
        assert!(zero.closes());
        assert_eq!(zero.actual.counters_after.generation, before.generation);
        assert_eq!(
            zero.actual.counters_after.reset_invocations,
            before.reset_invocations + 1
        );
        assert_eq!(zero.actual.counters_after.rollovers, before.rollovers);
        assert_eq!(zero.actual.counters_after.clears, before.clears);
        assert_eq!(zero.actual.counters_after.clear_cells, before.clear_cells);
        assert_eq!(zero.actual.counters_after.clear_bytes, before.clear_bytes);
    }

    #[test]
    fn reset_ordinary_work_one_below_is_atomic() {
        let mut session = session();
        let before_counters = session.all_counters();
        let before_storage = snapshots(&session);
        let receipt = reset_error_receipt(
            session
                .reset_forced(
                    OperationSessionLeaf::Hot,
                    1,
                    OperationSessionResetLimits {
                        max_work: 0,
                        max_clear_cells: 0,
                        max_clear_bytes: 0,
                    },
                )
                .unwrap_err(),
        );
        assert_eq!(
            receipt.terminal,
            OperationSessionTerminal::Refused(OperationSessionResource::ResetWork)
        );
        assert!(receipt.closes());
        assert_eq!(session.all_counters(), before_counters);
        assert_eq!(snapshots(&session), before_storage);
    }

    #[test]
    fn rollover_exact_generation_overflow_clears_only_selected_marks() {
        let mut session = session();
        let leaf = OperationSessionLeaf::MultiCapture;
        fill_canaries(&mut session);
        let first = session
            .reset_forced(leaf, u64::MAX, exact_reset_limits(&session, leaf, u64::MAX))
            .unwrap();
        assert_eq!(first.actual.counters_after.generation, u64::MAX);
        assert_eq!(first.actual.counters_after.rollovers, 0);
        let prospective = session.reset_prospective(leaf, 1).unwrap();
        let receipt = session
            .reset_forced(
                leaf,
                1,
                OperationSessionResetLimits::exact(&prospective).unwrap(),
            )
            .unwrap();
        assert!(receipt.closes());
        assert_eq!(receipt.actual.counters_after.generation, 1);
        assert_eq!(receipt.actual.counters_after.rollovers, 1);
        assert_eq!(receipt.actual.counters_after.clears, 1);
        assert_eq!(
            receipt.actual.counters_after.clear_cells,
            u64::try_from(
                session.construction_receipt().actual.leaves[leaf.index()].generation_cells
            )
            .unwrap()
        );
        assert_eq!(
            receipt.actual.counters_after.clear_bytes,
            receipt.actual.counters_after.clear_cells * 8
        );
        assert_eq!(
            receipt.actual.work,
            1_u64
                .checked_add(receipt.actual.counters_after.clear_cells)
                .unwrap()
        );
        assert!(
            generation_contents(&snapshots(&session), leaf)
                .iter()
                .all(|value| *value == 0)
        );
    }

    #[test]
    fn rollover_each_positive_limit_one_below_is_atomic() {
        let leaf = OperationSessionLeaf::Search;
        for resource in [
            OperationSessionResource::ResetWork,
            OperationSessionResource::ClearCells,
            OperationSessionResource::ClearBytes,
        ] {
            let mut session = session();
            session
                .reset_forced(leaf, u64::MAX, exact_reset_limits(&session, leaf, u64::MAX))
                .unwrap();
            fill_canaries(&mut session);
            let prospective = session.reset_prospective(leaf, 1).unwrap();
            let mut limits = OperationSessionResetLimits::exact(&prospective).unwrap();
            match resource {
                OperationSessionResource::ResetWork => limits.max_work -= 1,
                OperationSessionResource::ClearCells => limits.max_clear_cells -= 1,
                OperationSessionResource::ClearBytes => limits.max_clear_bytes -= 1,
                _ => unreachable!(),
            }
            let before_counters = session.all_counters();
            let before_storage = snapshots(&session);
            let receipt = reset_error_receipt(session.reset_forced(leaf, 1, limits).unwrap_err());
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::Refused(resource)
            );
            assert!(receipt.closes());
            assert_eq!(session.all_counters(), before_counters);
            assert_eq!(snapshots(&session), before_storage);
        }
    }

    #[test]
    fn rollover_counter_and_clear_arithmetic_overflow_refuse_before_clear() {
        let leaf = OperationSessionLeaf::Grep;
        let cases = [
            OperationSessionLeafCounters {
                reset_invocations: u64::MAX,
                ..OperationSessionLeafCounters::default()
            },
            OperationSessionLeafCounters {
                generation: u64::MAX,
                rollovers: u64::MAX,
                ..OperationSessionLeafCounters::default()
            },
            OperationSessionLeafCounters {
                generation: u64::MAX,
                clears: u64::MAX,
                ..OperationSessionLeafCounters::default()
            },
            OperationSessionLeafCounters {
                generation: u64::MAX,
                clear_cells: u64::MAX,
                ..OperationSessionLeafCounters::default()
            },
            OperationSessionLeafCounters {
                generation: u64::MAX,
                clear_bytes: u64::MAX,
                ..OperationSessionLeafCounters::default()
            },
        ];
        for counters in cases {
            let mut session = session();
            set_counters(&mut session, leaf, counters);
            fill_canaries(&mut session);
            let before_storage = snapshots(&session);
            let before_counters = session.all_counters();
            let receipt = reset_error_receipt(
                session
                    .reset_forced(
                        leaf,
                        1,
                        OperationSessionResetLimits {
                            max_work: u64::MAX,
                            max_clear_cells: usize::MAX,
                            max_clear_bytes: usize::MAX,
                        },
                    )
                    .unwrap_err(),
            );
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::ArithmeticOverflow
            );
            assert!(receipt.closes(), "{counters:?}");
            assert_eq!(session.all_counters(), before_counters);
            assert_eq!(snapshots(&session), before_storage);
        }
        assert_eq!(
            leaf_reset_prospective(
                leaf,
                OperationSessionLeafCounters {
                    generation: u64::MAX,
                    ..OperationSessionLeafCounters::default()
                },
                usize::MAX,
                1,
            ),
            Err(OperationSessionError::ArithmeticOverflow)
        );
    }

    #[test]
    fn cross_leaf_reset_canaries_and_exact_capacity_are_isolated() {
        let mut session = session();
        for leaf in OperationSessionLeaf::ORDERED {
            fill_canaries(&mut session);
            set_counters(
                &mut session,
                leaf,
                OperationSessionLeafCounters {
                    generation: u64::MAX,
                    ..OperationSessionLeafCounters::default()
                },
            );
            let before = snapshots(&session);
            let prospective = session.reset_prospective(leaf, 1).unwrap();
            let receipt = session
                .reset_forced(
                    leaf,
                    1,
                    OperationSessionResetLimits::exact(&prospective).unwrap(),
                )
                .unwrap();
            assert!(receipt.closes());
            let after = snapshots(&session);
            for other in OperationSessionLeaf::ORDERED {
                if other != leaf {
                    assert_eq!(after[other.index()], before[other.index()]);
                }
            }
            assert_eq!(
                after[leaf.index()].capacities,
                before[leaf.index()].capacities
            );
            let generation_ordinal = match leaf {
                OperationSessionLeaf::Search | OperationSessionLeaf::MultiCapture => 2,
                OperationSessionLeaf::Hot | OperationSessionLeaf::Grep => 1,
            };
            for index in 0..after[leaf.index()].contents.len() {
                if index != generation_ordinal {
                    assert_eq!(
                        after[leaf.index()].contents[index],
                        before[leaf.index()].contents[index]
                    );
                }
            }
            assert!(
                generation_contents(&after, leaf)
                    .iter()
                    .all(|value| *value == 0)
            );
        }
    }

    #[test]
    fn all_twelve_leaf_reducer_entries_are_supported_or_typed_unsupported() {
        let p = OperationSessionExecutionProspective::default();
        let mut session = session();

        {
            let mut forced = session.forced_search();
            assert!(
                forced
                    .begin_count(request(
                        OperationSessionLeaf::Search,
                        OperationSessionReducer::Count,
                        p,
                    ))
                    .unwrap()
                    .finish_count()
                    .unwrap()
                    .closes()
            );
        }
        {
            let mut forced = session.forced_search();
            assert!(
                forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::Search,
                        OperationSessionReducer::SpanSum,
                        p,
                    ))
                    .unwrap()
                    .finish_span_sum()
                    .unwrap()
                    .closes()
            );
        }
        {
            let before = session.all_counters();
            let before_storage = snapshots(&session);
            let mut forced = session.forced_search();
            let receipt = attempt_error_receipt(begin_error(forced.begin_participation(request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::Participation,
                p,
            ))));
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::UnsupportedReducer
            );
            assert!(receipt.closes());
            assert_eq!(receipt.reset.all_leaves_before, before);
            assert_eq!(receipt.reset.all_leaves_after, before);
            assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            assert_eq!(receipt.prospective, None);
            assert_eq!(session.all_counters(), before);
            assert_eq!(snapshots(&session), before_storage);
        }

        {
            let mut forced = session.forced_hot();
            assert!(
                forced
                    .begin_count(request(
                        OperationSessionLeaf::Hot,
                        OperationSessionReducer::Count,
                        p,
                    ))
                    .unwrap()
                    .finish_count()
                    .unwrap()
                    .closes()
            );
        }
        {
            let mut forced = session.forced_hot();
            assert!(
                forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::Hot,
                        OperationSessionReducer::SpanSum,
                        p,
                    ))
                    .unwrap()
                    .finish_span_sum()
                    .unwrap()
                    .closes()
            );
        }
        {
            let before = session.all_counters();
            let before_storage = snapshots(&session);
            let mut forced = session.forced_hot();
            let receipt = attempt_error_receipt(begin_error(forced.begin_participation(request(
                OperationSessionLeaf::Hot,
                OperationSessionReducer::Participation,
                p,
            ))));
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::UnsupportedReducer
            );
            assert!(receipt.closes());
            assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            assert_eq!(receipt.prospective, None);
            assert_eq!(receipt.reset.all_leaves_before, before);
            assert_eq!(receipt.reset.all_leaves_after, before);
            assert_eq!(session.all_counters(), before);
            assert_eq!(snapshots(&session), before_storage);
        }

        {
            let mut forced = session.forced_multi_capture();
            assert!(
                forced
                    .begin_count(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::Count,
                        p,
                    ))
                    .unwrap()
                    .finish_count()
                    .unwrap()
                    .closes()
            );
        }
        {
            let mut forced = session.forced_multi_capture();
            assert!(
                forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::SpanSum,
                        p,
                    ))
                    .unwrap()
                    .finish_span_sum()
                    .unwrap()
                    .closes()
            );
        }
        {
            let mut forced = session.forced_multi_capture();
            assert!(
                forced
                    .begin_participation(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::Participation,
                        p,
                    ))
                    .unwrap()
                    .finish_participation()
                    .unwrap()
                    .closes()
            );
        }

        {
            let mut forced = session.forced_grep();
            assert!(
                forced
                    .begin_count(request(
                        OperationSessionLeaf::Grep,
                        OperationSessionReducer::Count,
                        p,
                    ))
                    .unwrap()
                    .finish_count()
                    .unwrap()
                    .closes()
            );
        }
        for reducer in [
            OperationSessionReducer::SpanSum,
            OperationSessionReducer::Participation,
        ] {
            let before = session.all_counters();
            let before_storage = snapshots(&session);
            let mut forced = session.forced_grep();
            let result = match reducer {
                OperationSessionReducer::SpanSum => {
                    forced.begin_span_sum(request(OperationSessionLeaf::Grep, reducer, p))
                }
                OperationSessionReducer::Participation => {
                    forced.begin_participation(request(OperationSessionLeaf::Grep, reducer, p))
                }
                OperationSessionReducer::Count => unreachable!(),
            };
            let receipt = attempt_error_receipt(begin_error(result));
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::UnsupportedReducer
            );
            assert!(receipt.closes());
            assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            assert_eq!(receipt.prospective, None);
            assert_eq!(receipt.reset.all_leaves_before, before);
            assert_eq!(receipt.reset.all_leaves_after, before);
            assert_eq!(session.all_counters(), before);
            assert_eq!(snapshots(&session), before_storage);
        }
    }

    #[test]
    fn repeated_counts_preserve_outputs_accounting_and_limit_errors_for_every_leaf() {
        let prospective = OperationSessionExecutionProspective {
            line_domains: 1,
            output_events: 1,
            selected_span_bytes: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let mut session = session();

        for _ in 0..3 {
            for leaf in OperationSessionLeaf::ORDERED {
                let before = session.all_counters();
                let receipt = run_one_count(
                    &mut session,
                    leaf,
                    request(leaf, OperationSessionReducer::Count, prospective),
                )
                .unwrap();
                let expected_actual = match leaf {
                    OperationSessionLeaf::Grep => OperationSessionExecutionActual {
                        line_domains: 1,
                        output_events: 1,
                        ..OperationSessionExecutionActual::default()
                    },
                    OperationSessionLeaf::Search
                    | OperationSessionLeaf::Hot
                    | OperationSessionLeaf::MultiCapture => OperationSessionExecutionActual {
                        output_events: 1,
                        selected_span_bytes: 1,
                        ..OperationSessionExecutionActual::default()
                    },
                };
                assert_eq!(receipt.value, Some(OperationSessionValue::Count(1)));
                assert_eq!(receipt.prospective, Some(prospective));
                assert_eq!(receipt.actual, expected_actual);
                assert_eq!(receipt.reset.all_leaves_before, before);
                assert_eq!(receipt.reset.all_leaves_after, session.all_counters());
                assert!(receipt.closes());

                let after_success = session.all_counters();
                let mut refused = request(leaf, OperationSessionReducer::Count, prospective);
                refused.run_limits.max_output_events = 0;
                let receipt =
                    attempt_error_receipt(run_one_count(&mut session, leaf, refused).unwrap_err());
                assert_eq!(
                    receipt.terminal,
                    OperationSessionTerminal::Refused(OperationSessionResource::OutputEvents)
                );
                assert_eq!(receipt.prospective, Some(prospective));
                assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
                assert_eq!(receipt.value, None);
                assert_eq!(receipt.reset.prospective, None);
                assert_eq!(receipt.reset.all_leaves_before, after_success);
                assert_eq!(receipt.reset.all_leaves_after, after_success);
                assert_eq!(session.all_counters(), after_success);
                assert!(receipt.closes());
            }
        }
    }

    #[test]
    fn cross_leaf_and_cross_reducer_identity_mismatches_close_without_reset() {
        let mut session = session();
        let before = session.all_counters();
        let p = OperationSessionExecutionProspective::default();
        let hot_identity = identity(
            OperationSessionLeaf::Hot,
            OperationSessionReducer::Count,
            PLAN_ID,
        );
        let hot_request = OperationSessionAttemptRequest::new_trusted(
            hot_identity,
            OperationSessionInvocation {
                haystack_len: 10,
                range: 0..10,
                required_generations: 1,
            },
            p,
            OperationSessionResetLimits {
                max_work: u64::MAX,
                max_clear_cells: usize::MAX,
                max_clear_bytes: usize::MAX,
            },
            OperationSessionRunLimits::exact(p),
            PLAN_ID,
        )
        .unwrap();
        let receipt = {
            let mut forced = session.forced_search();
            attempt_error_receipt(begin_error(forced.begin_count(hot_request)))
        };
        assert_eq!(receipt.identity.leaf, OperationSessionLeaf::Search);
        assert_eq!(receipt.reset.actual.leaf, OperationSessionLeaf::Search);
        assert_eq!(receipt.terminal, OperationSessionTerminal::IdentityMismatch);
        assert!(receipt.closes());
        assert_eq!(session.all_counters(), before);

        let receipt = {
            let mut forced = session.forced_search();
            attempt_error_receipt(begin_error(forced.begin_count(request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::SpanSum,
                p,
            ))))
        };
        assert_eq!(receipt.terminal, OperationSessionTerminal::IdentityMismatch);
        assert!(receipt.closes());
        assert_eq!(session.all_counters(), before);
    }

    #[test]
    fn route_source_order_and_fallback_mutations_are_pre_reset_mismatches() {
        for field in 0..10 {
            let mut session = session();
            let before = session.all_counters();
            let mut request = request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::Count,
                OperationSessionExecutionProspective::default(),
            );
            match field {
                0 => request.identity.source_identity = "wrong-source",
                1 => request.identity.order_identity = "wrong-order",
                2 => request.identity.fallback_identity = "wrong-fallback",
                3 => request.identity.session_accounting_id = "wrong-session",
                4 => request.identity.session_algorithm_version += 1,
                5 => request.identity.session_accounting_version += 1,
                6 => request.identity.leaf_algorithm_version += 1,
                7 => request.identity.leaf_accounting_version += 1,
                8 => request.identity.leaf_accounting_id = "wrong-leaf",
                9 => request.identity.compiled_plan_id[0] ^= 1,
                _ => unreachable!(),
            }
            let receipt = {
                let mut forced = session.forced_search();
                attempt_error_receipt(begin_error(forced.begin_count(request)))
            };
            assert_eq!(receipt.terminal, OperationSessionTerminal::IdentityMismatch);
            assert!(receipt.closes());
            assert_eq!(session.all_counters(), before);
        }
    }

    #[test]
    fn ordered_count_span_and_participation_values_close() {
        let mut session = session();
        let count_p = OperationSessionExecutionProspective {
            output_events: 2,
            selected_span_bytes: 5,
            ..OperationSessionExecutionProspective::default()
        };
        let count = {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::Count,
                    count_p,
                ))
                .unwrap();
            attempt.emit_span(0, 2, None).unwrap();
            attempt.emit_span(3, 6, None).unwrap();
            attempt.finish_count().unwrap()
        };
        assert_eq!(count.value, Some(OperationSessionValue::Count(2)));
        assert!(count.closes());

        let span = {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_span_sum(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::SpanSum,
                    count_p,
                ))
                .unwrap();
            attempt.emit_span(0, 2, None).unwrap();
            attempt.emit_span(3, 6, None).unwrap();
            attempt.finish_span_sum().unwrap()
        };
        assert_eq!(span.value, Some(OperationSessionValue::SpanSum(5)));
        assert!(span.closes());

        let participation_p = OperationSessionExecutionProspective {
            output_events: 2,
            participation_entries: 7,
            ..OperationSessionExecutionProspective::default()
        };
        let participation = {
            let mut forced = session.forced_multi_capture();
            let mut attempt = forced
                .begin_participation(request(
                    OperationSessionLeaf::MultiCapture,
                    OperationSessionReducer::Participation,
                    participation_p,
                ))
                .unwrap();
            attempt.observe_participation(1, 2, 0).unwrap();
            attempt.emit_participation(3).unwrap();
            attempt.observe_participation(2, 4, 1).unwrap();
            attempt.emit_participation(4).unwrap();
            attempt.finish_participation().unwrap()
        };
        assert_eq!(
            participation.value,
            Some(OperationSessionValue::Participation(7))
        );
        assert!(participation.closes());
    }

    #[test]
    fn multi_capture_count_and_span_require_pattern_ordinals_and_latch() {
        let prospective = OperationSessionExecutionProspective {
            output_events: 1,
            selected_span_bytes: 1,
            ..OperationSessionExecutionProspective::default()
        };
        for reducer in [
            OperationSessionReducer::Count,
            OperationSessionReducer::SpanSum,
        ] {
            let mut refusal_session = session();
            let mut forced = refusal_session.forced_multi_capture();
            let mut attempt = match reducer {
                OperationSessionReducer::Count => forced.begin_count(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    prospective,
                )),
                OperationSessionReducer::SpanSum => forced.begin_span_sum(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    prospective,
                )),
                OperationSessionReducer::Participation => unreachable!(),
            }
            .unwrap();
            let selected_before = attempt.selected_slot().test_snapshot();
            let first = attempt_error_receipt(attempt.emit_span(0, 1, None).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::InvalidInvocation);
            assert_eq!(first.prospective, Some(prospective));
            assert_eq!(first.actual, OperationSessionExecutionActual::default());
            assert_eq!(first.value, None);
            assert!(first.closes(), "{reducer:?}");
            assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);

            let emit_replay = attempt_error_receipt(attempt.emit_span(0, 1, Some(0)).unwrap_err());
            assert_eq!(emit_replay, first);
            assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
            let finish_replay = attempt_error_receipt(match reducer {
                OperationSessionReducer::Count => attempt.finish_count().unwrap_err(),
                OperationSessionReducer::SpanSum => attempt.finish_span_sum().unwrap_err(),
                OperationSessionReducer::Participation => unreachable!(),
            });
            assert_eq!(finish_replay, first);

            let event_prospective = OperationSessionExecutionProspective {
                output_events: 2,
                selected_span_bytes: 2,
                ..OperationSessionExecutionProspective::default()
            };
            let mut event_session = session();
            let mut forced = event_session.forced_multi_capture();
            let mut attempt = match reducer {
                OperationSessionReducer::Count => forced.begin_count(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    event_prospective,
                )),
                OperationSessionReducer::SpanSum => forced.begin_span_sum(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    event_prospective,
                )),
                OperationSessionReducer::Participation => unreachable!(),
            }
            .unwrap();
            attempt.emit_span(0, 1, Some(0)).unwrap();
            let actual_before_refusal = attempt.actual;
            let slot_before_refusal = attempt.selected_slot().test_snapshot();
            let counters_before_refusal = attempt.selected_slot().counters();
            let evidence_before_refusal = (
                attempt.evidence.first_span,
                attempt.evidence.last_span,
                attempt.evidence.span_events,
            );
            let first = attempt_error_receipt(attempt.emit_span(1, 2, None).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::InvalidInvocation);
            assert_eq!(first.prospective, Some(event_prospective));
            assert_eq!(first.actual, actual_before_refusal);
            assert_eq!(first.value, None);
            assert!(first.closes(), "{reducer:?}");
            assert_eq!(attempt.actual, actual_before_refusal);
            assert_eq!(attempt.selected_slot().test_snapshot(), slot_before_refusal);
            assert_eq!(attempt.selected_slot().counters(), counters_before_refusal);
            assert_eq!(
                (
                    attempt.evidence.first_span,
                    attempt.evidence.last_span,
                    attempt.evidence.span_events,
                ),
                evidence_before_refusal
            );
            let emit_replay = attempt_error_receipt(attempt.emit_span(1, 2, Some(1)).unwrap_err());
            assert_eq!(emit_replay, first);
            let meter_replay = attempt_error_receipt(attempt.meter_work(1).unwrap_err());
            assert_eq!(meter_replay, first);
            let finish_replay = attempt_error_receipt(match reducer {
                OperationSessionReducer::Count => attempt.finish_count().unwrap_err(),
                OperationSessionReducer::SpanSum => attempt.finish_span_sum().unwrap_err(),
                OperationSessionReducer::Participation => unreachable!(),
            });
            assert_eq!(finish_replay, first);

            let mut success_session = session();
            let mut forced = success_session.forced_multi_capture();
            let mut attempt = match reducer {
                OperationSessionReducer::Count => forced.begin_count(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    prospective,
                )),
                OperationSessionReducer::SpanSum => forced.begin_span_sum(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    prospective,
                )),
                OperationSessionReducer::Participation => unreachable!(),
            }
            .unwrap();
            attempt.emit_span(0, 1, Some(0)).unwrap();
            let receipt = match reducer {
                OperationSessionReducer::Count => attempt.finish_count().unwrap(),
                OperationSessionReducer::SpanSum => attempt.finish_span_sum().unwrap(),
                OperationSessionReducer::Participation => unreachable!(),
            };
            let expected_value = match reducer {
                OperationSessionReducer::Count => OperationSessionValue::Count(1),
                OperationSessionReducer::SpanSum => OperationSessionValue::SpanSum(1),
                OperationSessionReducer::Participation => unreachable!(),
            };
            assert_eq!(receipt.value, Some(expected_value));
            assert_eq!(receipt.actual.output_events, 1);
            assert_eq!(receipt.actual.selected_span_bytes, 1);
            assert!(receipt.closes(), "{reducer:?}");

            let tie_prospective = OperationSessionExecutionProspective {
                output_events: 2,
                selected_span_bytes: 0,
                ..OperationSessionExecutionProspective::default()
            };
            let mut tie_success_session = session();
            let mut forced = tie_success_session.forced_multi_capture();
            let mut attempt = match reducer {
                OperationSessionReducer::Count => forced.begin_count(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    tie_prospective,
                )),
                OperationSessionReducer::SpanSum => forced.begin_span_sum(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    tie_prospective,
                )),
                OperationSessionReducer::Participation => unreachable!(),
            }
            .unwrap();
            attempt.emit_span(2, 2, Some(0)).unwrap();
            attempt.emit_span(2, 2, Some(1)).unwrap();
            let receipt = match reducer {
                OperationSessionReducer::Count => attempt.finish_count().unwrap(),
                OperationSessionReducer::SpanSum => attempt.finish_span_sum().unwrap(),
                OperationSessionReducer::Participation => unreachable!(),
            };
            let expected_value = match reducer {
                OperationSessionReducer::Count => OperationSessionValue::Count(2),
                OperationSessionReducer::SpanSum => OperationSessionValue::SpanSum(0),
                OperationSessionReducer::Participation => unreachable!(),
            };
            assert_eq!(receipt.value, Some(expected_value));
            assert_eq!(
                receipt.actual,
                OperationSessionExecutionActual {
                    output_events: 2,
                    ..OperationSessionExecutionActual::default()
                }
            );
            assert!(receipt.closes(), "{reducer:?}");

            let mut tie_refusal_session = session();
            let mut forced = tie_refusal_session.forced_multi_capture();
            let mut attempt = match reducer {
                OperationSessionReducer::Count => forced.begin_count(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    tie_prospective,
                )),
                OperationSessionReducer::SpanSum => forced.begin_span_sum(request(
                    OperationSessionLeaf::MultiCapture,
                    reducer,
                    tie_prospective,
                )),
                OperationSessionReducer::Participation => unreachable!(),
            }
            .unwrap();
            attempt.emit_span(2, 2, Some(0)).unwrap();
            let actual_before_refusal = attempt.actual;
            let slot_before_refusal = attempt.selected_slot().test_snapshot();
            let counters_before_refusal = attempt.selected_slot().counters();
            let evidence_before_refusal = (
                attempt.evidence.first_span,
                attempt.evidence.last_span,
                attempt.evidence.span_events,
            );
            let first = attempt_error_receipt(attempt.emit_span(2, 2, Some(0)).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::InvalidInvocation);
            assert_eq!(first.prospective, Some(tie_prospective));
            assert_eq!(first.actual, actual_before_refusal);
            assert_eq!(first.value, None);
            assert!(first.closes(), "{reducer:?}");
            assert_eq!(attempt.actual, actual_before_refusal);
            assert_eq!(attempt.selected_slot().test_snapshot(), slot_before_refusal);
            assert_eq!(attempt.selected_slot().counters(), counters_before_refusal);
            assert_eq!(
                (
                    attempt.evidence.first_span,
                    attempt.evidence.last_span,
                    attempt.evidence.span_events,
                ),
                evidence_before_refusal
            );
            let emit_replay = attempt_error_receipt(attempt.emit_span(2, 2, Some(1)).unwrap_err());
            assert_eq!(emit_replay, first);
            let finish_replay = attempt_error_receipt(match reducer {
                OperationSessionReducer::Count => attempt.finish_count().unwrap_err(),
                OperationSessionReducer::SpanSum => attempt.finish_span_sum().unwrap_err(),
                OperationSessionReducer::Participation => unreachable!(),
            });
            assert_eq!(finish_replay, first);
        }
    }

    #[test]
    fn ordered_span_overlap_pattern_ties_and_line_ordinals_are_checked() {
        let mut session = session();
        let tie_p = OperationSessionExecutionProspective {
            output_events: 2,
            ..OperationSessionExecutionProspective::default()
        };
        {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_span_sum(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::SpanSum,
                    tie_p,
                ))
                .unwrap();
            attempt.emit_span(2, 2, Some(0)).unwrap();
            attempt.emit_span(2, 2, Some(1)).unwrap();
            let receipt = attempt.finish_span_sum().unwrap();
            assert_eq!(receipt.value, Some(OperationSessionValue::SpanSum(0)));
            assert!(receipt.closes());
        }
        {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_span_sum(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::SpanSum,
                    tie_p,
                ))
                .unwrap();
            attempt.emit_span(2, 2, Some(1)).unwrap();
            let first = attempt_error_receipt(attempt.emit_span(2, 2, Some(1)).unwrap_err());
            assert!(first.closes());
            assert_eq!(
                attempt_error_receipt(attempt.finish_span_sum().unwrap_err()),
                first
            );
        }
        {
            let overlap_p = OperationSessionExecutionProspective {
                output_events: 2,
                selected_span_bytes: 4,
                ..OperationSessionExecutionProspective::default()
            };
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_span_sum(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::SpanSum,
                    overlap_p,
                ))
                .unwrap();
            attempt.emit_span(0, 2, None).unwrap();
            let first = attempt_error_receipt(attempt.emit_span(1, 3, None).unwrap_err());
            assert_eq!(first.terminal, OperationSessionTerminal::InvalidInvocation);
            assert!(first.closes());
        }

        let grep_p = OperationSessionExecutionProspective {
            line_domains: 2,
            output_events: 2,
            ..OperationSessionExecutionProspective::default()
        };
        {
            let mut forced = session.forced_grep();
            let mut grep = forced
                .begin_count(request(
                    OperationSessionLeaf::Grep,
                    OperationSessionReducer::Count,
                    grep_p,
                ))
                .unwrap();
            grep.emit_line_domain(1).unwrap();
            grep.emit_line_domain(3).unwrap();
            let receipt = grep.finish_count().unwrap();
            assert_eq!(receipt.value, Some(OperationSessionValue::Count(2)));
            assert!(receipt.closes());
        }
        {
            let mut forced = session.forced_grep();
            let mut grep = forced
                .begin_count(request(
                    OperationSessionLeaf::Grep,
                    OperationSessionReducer::Count,
                    grep_p,
                ))
                .unwrap();
            grep.emit_line_domain(3).unwrap();
            let first = attempt_error_receipt(grep.emit_line_domain(3).unwrap_err());
            assert!(first.closes());
            assert_eq!(
                attempt_error_receipt(grep.finish_count().unwrap_err()),
                first
            );
        }
    }

    #[test]
    fn participation_pending_observation_order_and_latch_are_exact() {
        let p = OperationSessionExecutionProspective {
            output_events: 2,
            participation_entries: 2,
            ..OperationSessionExecutionProspective::default()
        };

        let mut session = session();
        {
            let mut forced = session.forced_multi_capture();
            let mut tied = forced
                .begin_participation(request(
                    OperationSessionLeaf::MultiCapture,
                    OperationSessionReducer::Participation,
                    p,
                ))
                .unwrap();
            tied.observe_participation(5, 5, 0).unwrap();
            tied.emit_participation(1).unwrap();
            tied.observe_participation(5, 5, 1).unwrap();
            tied.emit_participation(1).unwrap();
            let receipt = tied.finish_participation().unwrap();
            assert_eq!(receipt.value, Some(OperationSessionValue::Participation(2)));
            assert!(receipt.closes());
        }
        {
            let mut forced = session.forced_multi_capture();
            let mut descending = forced
                .begin_participation(request(
                    OperationSessionLeaf::MultiCapture,
                    OperationSessionReducer::Participation,
                    p,
                ))
                .unwrap();
            descending.observe_participation(5, 5, 1).unwrap();
            descending.emit_participation(1).unwrap();
            let first =
                attempt_error_receipt(descending.observe_participation(5, 5, 0).unwrap_err());
            assert!(first.closes());
            assert_eq!(
                attempt_error_receipt(descending.finish_participation().unwrap_err()),
                first
            );
        }
        let mut forced = session.forced_multi_capture();
        let mut missing = forced
            .begin_participation(request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Participation,
                p,
            ))
            .unwrap();
        let receipt = attempt_error_receipt(missing.emit_participation(1).unwrap_err());
        assert!(receipt.closes());
        assert_eq!(
            receipt.terminal,
            OperationSessionTerminal::InvalidInvocation
        );
        assert_eq!(
            attempt_error_receipt(missing.finish_participation().unwrap_err()),
            receipt
        );

        let mut forced = session.forced_multi_capture();
        let mut pending = forced
            .begin_participation(request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Participation,
                p,
            ))
            .unwrap();
        pending.observe_participation(5, 5, 0).unwrap();
        let first = attempt_error_receipt(pending.observe_participation(5, 6, 1).unwrap_err());
        let replay = attempt_error_receipt(pending.emit_participation(1).unwrap_err());
        assert_eq!(replay, first);
        let replay = attempt_error_receipt(pending.finish_participation().unwrap_err());
        assert_eq!(replay, first);
        assert!(replay.closes());

        let mut forced = session.forced_multi_capture();
        let mut unconsumed = forced
            .begin_participation(request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Participation,
                p,
            ))
            .unwrap();
        unconsumed.observe_participation(5, 5, 0).unwrap();
        let receipt = attempt_error_receipt(unconsumed.finish_participation().unwrap_err());
        assert_eq!(
            receipt.terminal,
            OperationSessionTerminal::InvalidInvocation
        );
        assert!(receipt.closes());
    }

    #[test]
    fn value_overflow_has_no_partial_value_and_latches() {
        let p = OperationSessionExecutionProspective {
            output_events: 2,
            participation_entries: u64::MAX,
            ..OperationSessionExecutionProspective::default()
        };
        let mut session = session();
        let mut forced = session.forced_multi_capture();
        let mut attempt = forced
            .begin_participation(request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Participation,
                p,
            ))
            .unwrap();
        attempt.observe_participation(0, 0, 0).unwrap();
        attempt.emit_participation(u64::MAX).unwrap();
        attempt.observe_participation(0, 0, 1).unwrap();
        let first = attempt_error_receipt(attempt.emit_participation(1).unwrap_err());
        assert_eq!(first.terminal, OperationSessionTerminal::ArithmeticOverflow);
        assert_eq!(first.value, None);
        assert_eq!(first.actual.participation_entries, u64::MAX);
        assert_eq!(first.actual.output_events, 1);
        assert!(first.closes());
        assert_eq!(
            attempt_error_receipt(attempt.finish_participation().unwrap_err()),
            first
        );
    }

    #[test]
    fn accounting_projection_copies_every_execution_dimension_without_second_scan() {
        let search_p = OperationSessionExecutionProspective {
            work: 3,
            source_accesses: 1,
            transitions: 2,
            candidates: 4,
            cache_misses: 5,
            history_nodes: 6,
            output_events: 2,
            selected_span_bytes: 3,
            ..OperationSessionExecutionProspective::default()
        };
        let mut session = session();
        let receipt = {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_span_sum(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::SpanSum,
                    search_p,
                ))
                .unwrap();
            attempt.meter_work(3).unwrap();
            attempt.meter_source_accesses(1).unwrap();
            attempt.meter_transitions(2).unwrap();
            attempt.meter_candidates(4).unwrap();
            attempt.meter_cache_misses(5).unwrap();
            attempt.meter_history_nodes(6).unwrap();
            attempt.emit_span(0, 1, None).unwrap();
            attempt.emit_span(2, 4, None).unwrap();
            attempt.finish_span_sum().unwrap()
        };
        assert_eq!(receipt.actual.work, 3);
        assert_eq!(receipt.actual.source_accesses, 1);
        assert_eq!(receipt.actual.transitions, 2);
        assert_eq!(receipt.actual.candidates, 4);
        assert_eq!(receipt.actual.cache_misses, 5);
        assert_eq!(receipt.actual.history_nodes, 6);
        assert_eq!(receipt.actual.output_events, 2);
        assert_eq!(receipt.actual.selected_span_bytes, 3);
        assert_eq!(receipt.actual.allocations, 0);
        assert!(receipt.closes());

        let zero_match_p = OperationSessionExecutionProspective {
            source_accesses: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let receipt = {
            let mut forced = session.forced_search();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Search,
                    OperationSessionReducer::Count,
                    zero_match_p,
                ))
                .unwrap();
            attempt.meter_source_accesses(1).unwrap();
            attempt.finish_count().unwrap()
        };
        assert_eq!(receipt.actual.source_accesses, 1);
        assert_eq!(receipt.actual.output_events, 0);
        assert!(receipt.closes());

        let grep_p = OperationSessionExecutionProspective {
            line_domains: 2,
            output_events: 2,
            ..OperationSessionExecutionProspective::default()
        };
        let receipt = {
            let mut forced = session.forced_grep();
            let mut attempt = forced
                .begin_count(request(
                    OperationSessionLeaf::Grep,
                    OperationSessionReducer::Count,
                    grep_p,
                ))
                .unwrap();
            attempt.emit_line_domain(1).unwrap();
            attempt.emit_line_domain(2).unwrap();
            attempt.finish_count().unwrap()
        };
        assert_eq!(receipt.actual.line_domains, 2);
        assert_eq!(receipt.actual.output_events, 2);
        assert!(receipt.closes());

        let participation_p = OperationSessionExecutionProspective {
            output_events: 1,
            participation_entries: 7,
            ..OperationSessionExecutionProspective::default()
        };
        let receipt = {
            let mut forced = session.forced_multi_capture();
            let mut attempt = forced
                .begin_participation(request(
                    OperationSessionLeaf::MultiCapture,
                    OperationSessionReducer::Participation,
                    participation_p,
                ))
                .unwrap();
            attempt.observe_participation(1, 1, 0).unwrap();
            attempt.emit_participation(7).unwrap();
            attempt.finish_participation().unwrap()
        };
        assert_eq!(receipt.actual.participation_entries, 7);
        assert_eq!(receipt.actual.output_events, 1);
        assert!(receipt.closes());
    }

    #[test]
    fn accounting_each_positive_run_limit_one_below_refuses_pre_source() {
        let resources = [
            OperationSessionResource::ExecutionWork,
            OperationSessionResource::SourceAccesses,
            OperationSessionResource::Transitions,
            OperationSessionResource::Candidates,
            OperationSessionResource::CacheMisses,
            OperationSessionResource::HistoryNodes,
            OperationSessionResource::LineDomains,
            OperationSessionResource::OutputEvents,
            OperationSessionResource::SelectedSpanBytes,
            OperationSessionResource::ParticipationEntries,
            OperationSessionResource::Allocations,
        ];
        for (field, resource) in resources.into_iter().enumerate() {
            let mut p = OperationSessionExecutionProspective {
                work: 1,
                source_accesses: 1,
                transitions: 1,
                candidates: 1,
                cache_misses: 1,
                history_nodes: 1,
                line_domains: 1,
                output_events: 1,
                selected_span_bytes: 1,
                participation_entries: 1,
                allocations: 0,
            };
            if field == 10 {
                p.allocations = 1;
            }
            let mut request = request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::Count,
                p,
            );
            if field != 10 {
                match field {
                    0 => request.run_limits.max_work = 0,
                    1 => request.run_limits.max_source_accesses = 0,
                    2 => request.run_limits.max_transitions = 0,
                    3 => request.run_limits.max_candidates = 0,
                    4 => request.run_limits.max_cache_misses = 0,
                    5 => request.run_limits.max_history_nodes = 0,
                    6 => request.run_limits.max_line_domains = 0,
                    7 => request.run_limits.max_output_events = 0,
                    8 => request.run_limits.max_selected_span_bytes = 0,
                    9 => request.run_limits.max_participation_entries = 0,
                    _ => unreachable!(),
                }
            }
            let mut session = session();
            let before_counters = session.all_counters();
            let before_storage = snapshots(&session);
            let receipt = {
                let mut forced = session.forced_search();
                attempt_error_receipt(begin_error(forced.begin_count(request)))
            };
            assert_eq!(
                receipt.terminal,
                OperationSessionTerminal::Refused(resource),
                "{resource:?}"
            );
            assert!(receipt.closes(), "{resource:?}");
            assert_eq!(receipt.value, None);
            assert_eq!(receipt.prospective, Some(p));
            assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            assert_eq!(receipt.reset.prospective, None);
            assert_eq!(session.all_counters(), before_counters);
            assert_eq!(snapshots(&session), before_storage);
        }
    }

    #[test]
    fn accounting_repeated_supported_operations_keep_layout_capacity_and_zero_allocations() {
        macro_rules! assert_receipt {
            ($receipt:expr) => {{
                let receipt = $receipt;
                assert_eq!(receipt.actual.allocations, 0);
                assert!(receipt.closes());
            }};
        }

        let mut session = session();
        let construction = session.construction_receipt().clone();
        let before = snapshots(&session);
        let span_p = OperationSessionExecutionProspective {
            output_events: 1,
            selected_span_bytes: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let participation_p = OperationSessionExecutionProspective {
            output_events: 1,
            participation_entries: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let grep_p = OperationSessionExecutionProspective {
            line_domains: 1,
            output_events: 1,
            ..OperationSessionExecutionProspective::default()
        };

        for _ in 0..8 {
            assert_receipt!({
                let mut forced = session.forced_search();
                let mut attempt = forced
                    .begin_count(request(
                        OperationSessionLeaf::Search,
                        OperationSessionReducer::Count,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, None).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_count().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_search();
                let mut attempt = forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::Search,
                        OperationSessionReducer::SpanSum,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, None).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_span_sum().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_hot();
                let mut attempt = forced
                    .begin_count(request(
                        OperationSessionLeaf::Hot,
                        OperationSessionReducer::Count,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, None).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_count().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_hot();
                let mut attempt = forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::Hot,
                        OperationSessionReducer::SpanSum,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, None).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_span_sum().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced
                    .begin_count(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::Count,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, Some(0)).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_count().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced
                    .begin_span_sum(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::SpanSum,
                        span_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_span(0, 1, Some(0)).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_span_sum().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced
                    .begin_participation(request(
                        OperationSessionLeaf::MultiCapture,
                        OperationSessionReducer::Participation,
                        participation_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.observe_participation(0, 0, 0).unwrap();
                attempt.emit_participation(1).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_participation().unwrap()
            });
            assert_receipt!({
                let mut forced = session.forced_grep();
                let mut attempt = forced
                    .begin_count(request(
                        OperationSessionLeaf::Grep,
                        OperationSessionReducer::Count,
                        grep_p,
                    ))
                    .unwrap();
                let selected_before = attempt.selected_slot().test_snapshot();
                attempt.emit_line_domain(0).unwrap();
                assert_eq!(attempt.selected_slot().test_snapshot(), selected_before);
                attempt.finish_count().unwrap()
            });
        }
        assert_eq!(session.construction_receipt(), &construction);
        assert_eq!(snapshots(&session), before);
    }

    #[test]
    #[ignore = "run alone with the exact coordinator gate and one test thread"]
    fn accounting_all_supported_routes_have_zero_observed_allocations() {
        const REPEATS: usize = 8;
        let span_p = OperationSessionExecutionProspective {
            work: 1,
            output_events: 1,
            selected_span_bytes: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let participation_p = OperationSessionExecutionProspective {
            work: 1,
            output_events: 1,
            participation_entries: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let grep_p = OperationSessionExecutionProspective {
            work: 1,
            line_domains: 1,
            output_events: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let search_count_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::Count,
                span_p,
            )
        });
        let search_span_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::Search,
                OperationSessionReducer::SpanSum,
                span_p,
            )
        });
        let hot_count_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::Hot,
                OperationSessionReducer::Count,
                span_p,
            )
        });
        let hot_span_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::Hot,
                OperationSessionReducer::SpanSum,
                span_p,
            )
        });
        let multi_count_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Count,
                span_p,
            )
        });
        let multi_span_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::SpanSum,
                span_p,
            )
        });
        let participation_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::MultiCapture,
                OperationSessionReducer::Participation,
                participation_p,
            )
        });
        let grep_count_requests = core::array::from_fn::<_, REPEATS, _>(|_| {
            request(
                OperationSessionLeaf::Grep,
                OperationSessionReducer::Count,
                grep_p,
            )
        });
        let mut session = session();
        let construction_before = session.construction_receipt().clone();
        let layouts_before = construction_before.leaves.map(|leaf| leaf.layout_id);
        let slots_before = snapshots(&session);

        let (
            search_count_receipts,
            search_span_receipts,
            hot_count_receipts,
            hot_span_receipts,
            multi_count_receipts,
            multi_span_receipts,
            participation_receipts,
            grep_count_receipts,
            allocation_change,
        ) = {
            let region = stats_alloc::Region::new(OPERATION_SESSION_TEST_ALLOCATOR);
            let search_count_receipts = search_count_requests.map(|request| {
                let mut forced = session.forced_search();
                let mut attempt = forced.begin_count(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, None).unwrap();
                attempt.finish_count().unwrap()
            });
            let search_span_receipts = search_span_requests.map(|request| {
                let mut forced = session.forced_search();
                let mut attempt = forced.begin_span_sum(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, None).unwrap();
                attempt.finish_span_sum().unwrap()
            });
            let hot_count_receipts = hot_count_requests.map(|request| {
                let mut forced = session.forced_hot();
                let mut attempt = forced.begin_count(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, None).unwrap();
                attempt.finish_count().unwrap()
            });
            let hot_span_receipts = hot_span_requests.map(|request| {
                let mut forced = session.forced_hot();
                let mut attempt = forced.begin_span_sum(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, None).unwrap();
                attempt.finish_span_sum().unwrap()
            });
            let multi_count_receipts = multi_count_requests.map(|request| {
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced.begin_count(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, Some(0)).unwrap();
                attempt.finish_count().unwrap()
            });
            let multi_span_receipts = multi_span_requests.map(|request| {
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced.begin_span_sum(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_span(0, 1, Some(0)).unwrap();
                attempt.finish_span_sum().unwrap()
            });
            let participation_receipts = participation_requests.map(|request| {
                let mut forced = session.forced_multi_capture();
                let mut attempt = forced.begin_participation(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.observe_participation(0, 0, 0).unwrap();
                attempt.emit_participation(1).unwrap();
                attempt.finish_participation().unwrap()
            });
            let grep_count_receipts = grep_count_requests.map(|request| {
                let mut forced = session.forced_grep();
                let mut attempt = forced.begin_count(request).unwrap();
                attempt.meter_work(1).unwrap();
                attempt.emit_line_domain(0).unwrap();
                attempt.finish_count().unwrap()
            });
            let allocation_change = region.change();
            (
                search_count_receipts,
                search_span_receipts,
                hot_count_receipts,
                hot_span_receipts,
                multi_count_receipts,
                multi_span_receipts,
                participation_receipts,
                grep_count_receipts,
                allocation_change,
            )
        };

        assert_eq!(allocation_change, stats_alloc::Stats::default());
        for receipts in [
            &search_count_receipts,
            &search_span_receipts,
            &hot_count_receipts,
            &hot_span_receipts,
            &multi_count_receipts,
            &multi_span_receipts,
            &participation_receipts,
            &grep_count_receipts,
        ] {
            for receipt in receipts {
                assert_eq!(receipt.actual.allocations, 0);
                assert!(receipt.closes());
            }
        }
        assert_eq!(session.construction_receipt(), &construction_before);
        assert_eq!(
            session
                .construction_receipt()
                .leaves
                .map(|leaf| leaf.layout_id),
            layouts_before
        );
        assert_eq!(snapshots(&session), slots_before);
    }

    fn one_count_receipt(
        session: &mut OperationSession,
        plan_id: [u8; 16],
    ) -> OperationSessionAttemptReceipt {
        let p = OperationSessionExecutionProspective {
            output_events: 1,
            selected_span_bytes: 1,
            ..OperationSessionExecutionProspective::default()
        };
        let route = identity(
            OperationSessionLeaf::Search,
            OperationSessionReducer::Count,
            plan_id,
        );
        let request = OperationSessionAttemptRequest::new_trusted(
            route,
            OperationSessionInvocation {
                haystack_len: 1,
                range: 0..1,
                required_generations: 0,
            },
            p,
            OperationSessionResetLimits {
                max_work: 1,
                max_clear_cells: 0,
                max_clear_bytes: 0,
            },
            OperationSessionRunLimits::exact(p),
            plan_id,
        )
        .unwrap();
        let mut forced = session.forced_search();
        let mut attempt = forced.begin_count(request).unwrap();
        attempt.emit_span(0, 1, None).unwrap();
        attempt.finish_count().unwrap()
    }

    fn one_count_receipt_for_external_label(
        session: &mut OperationSession,
        plan_id: [u8; 16],
        _external_label: &str,
    ) -> OperationSessionAttemptReceipt {
        one_count_receipt(session, plan_id)
    }

    #[test]
    fn two_independent_sessions_have_disjoint_state_and_identical_outputs() {
        let mut left = session();
        let mut right = session();
        let right_before = right.all_counters();
        let left_receipt = one_count_receipt(&mut left, PLAN_ID);
        assert_eq!(right.all_counters(), right_before);
        let right_receipt = one_count_receipt(&mut right, PLAN_ID);
        assert_eq!(left_receipt, right_receipt);
        assert_eq!(left_receipt.value, Some(OperationSessionValue::Count(1)));
        assert!(left_receipt.closes());
    }

    #[test]
    fn concurrent_per_thread_sessions_are_deterministic_without_shared_cache() {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut session = session();
                    one_count_receipt(&mut session, PLAN_ID)
                })
            })
            .collect();
        let receipts: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(receipts.iter().all(OperationSessionAttemptReceipt::closes));
        assert!(receipts.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn arbitrary_plan_id_changes_only_authenticated_plan_binding() {
        let mut same_left = session();
        let mut same_right = session();
        let same_left = one_count_receipt_for_external_label(&mut same_left, PLAN_ID, "external-a");
        let same_right =
            one_count_receipt_for_external_label(&mut same_right, PLAN_ID, "external-b");
        assert_eq!(same_left, same_right);

        let mut left = session();
        let mut right = session();
        let left = one_count_receipt_for_external_label(&mut left, [0x11; 16], "external-a");
        let right = one_count_receipt_for_external_label(&mut right, [0x22; 16], "external-b");
        assert_eq!(left.schema_version, right.schema_version);
        assert_eq!(
            left.identity.session_accounting_id,
            right.identity.session_accounting_id
        );
        assert_eq!(
            left.identity.session_algorithm_version,
            right.identity.session_algorithm_version
        );
        assert_eq!(
            left.identity.session_accounting_version,
            right.identity.session_accounting_version
        );
        assert_eq!(left.identity.leaf, right.identity.leaf);
        assert_eq!(left.identity.reducer, right.identity.reducer);
        assert_ne!(
            left.identity.compiled_plan_id,
            right.identity.compiled_plan_id
        );
        assert_eq!(
            left.identity.source_identity,
            right.identity.source_identity
        );
        assert_eq!(left.identity.order_identity, right.identity.order_identity);
        assert_eq!(
            left.identity.fallback_identity,
            right.identity.fallback_identity
        );
        assert_eq!(
            left.identity.leaf_algorithm_version,
            right.identity.leaf_algorithm_version
        );
        assert_eq!(
            left.identity.leaf_accounting_version,
            right.identity.leaf_accounting_version
        );
        assert_eq!(
            left.identity.leaf_accounting_id,
            right.identity.leaf_accounting_id
        );
        assert_eq!(left.invocation, right.invocation);
        assert_eq!(left.limits, right.limits);
        assert_eq!(left.construction_layout_id, right.construction_layout_id);
        assert_eq!(left.reset, right.reset);
        assert_eq!(left.prospective, right.prospective);
        assert_eq!(left.actual, right.actual);
        assert_eq!(left.value, right.value);
        assert_eq!(left.terminal, right.terminal);
        assert!(left.closes());
        assert!(right.closes());
    }

    #[test]
    fn forced_path_sources_exclude_external_routing_vocabulary() {
        let sources = [
            include_str!("mod.rs"),
            include_str!("receipt.rs"),
            include_str!("search.rs"),
            include_str!("hot.rs"),
            include_str!("multi_capture.rs"),
            include_str!("grep.rs"),
        ];
        let forbidden = [
            "benchmark",
            "fixture",
            "point-id",
            "result",
            "timing",
            "metadata",
            "planner",
            "threshold",
        ];
        for source in sources {
            let final_test_marker = source
                .rfind(concat!("#[cfg", "(test)]"))
                .expect("operation-session source has a final test boundary");
            let production_source = &source[..final_test_marker];
            // This mandatory error-shape lint name is the sole scrubbed lexeme.
            let production_source = production_source.replace("clippy::result_large_err", "");
            for token in forbidden {
                assert!(
                    !production_source.contains(token),
                    "forbidden production token: {token}"
                );
            }
        }
    }
}
