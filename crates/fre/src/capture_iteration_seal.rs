//! Owner-local seal and terminal session receipt for materialized captures.
//!
//! Capture-array iteration is deliberately distinct from capture Count. Its
//! immutable owner binds the restarted persistent-history backend and its
//! capture schema; one invocation publishes a complete source-independent
//! session envelope before any byte is inspected.

use std::sync::Arc;

use fre_capture_lab::{
    AggregateLimits, CaptureProfile, HistoryProgramShape, HistorySearchProspective,
    MaskedInclusiveRange, ResourceKind, RestartedHistoryProspective, SearchConfig, SearchError,
    Window,
};
use fre_syntax::CacheKey;

use crate::captures::{CaptureBuildLimits, CaptureIterationPlanKind};

/// Version of materialized restarted persistent-history iteration.
pub const CAPTURE_ITERATION_ALGORITHM_VERSION: u32 = 4;

/// Version of the capture-array session prospective/actual ledger.
pub const CAPTURE_ITERATION_ACCOUNTING_VERSION: u32 = 2;

/// Fixed work charged by the optional construction-time start classifier.
pub const CAPTURE_ITERATION_START_CLASSIFIER_WORK: usize = 5;

pub(crate) const CAPTURE_ITERATION_ASCII_FOLD_RANGE: MaskedInclusiveRange =
    match MaskedInclusiveRange::new(0x20, b'a', b'z') {
        Some(classifier) => classifier,
        None => panic!("the ASCII alphabetic classifier is ordered"),
    };

/// Terminal of the last optional HIR-budget transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationStartClassifierOutcome {
    /// Fewer than five HIR work units remained, so no comparison ran.
    NotAttempted,
    /// All five fixed units were charged, but the exact first-byte set did not
    /// equal the predetermined classifier image.
    AttemptedIneligible,
    /// The exact non-nullable first-byte set equals this classifier image.
    Selected(MaskedInclusiveRange),
}

/// Closed construction receipt for the optional new-root classifier proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureIterationStartClassifierReceipt {
    work_before: usize,
    charged_work: usize,
    work_after: usize,
    outcome: CaptureIterationStartClassifierOutcome,
}

impl CaptureIterationStartClassifierReceipt {
    pub(crate) const fn new(
        work_before: usize,
        charged_work: usize,
        work_after: usize,
        outcome: CaptureIterationStartClassifierOutcome,
    ) -> Self {
        Self {
            work_before,
            charged_work,
            work_after,
            outcome,
        }
    }

    /// HIR work already charged before the optional transaction.
    #[must_use]
    pub const fn work_before(self) -> usize {
        self.work_before
    }

    /// Work charged by this transaction: exactly zero or five.
    #[must_use]
    pub const fn charged_work(self) -> usize {
        self.charged_work
    }

    /// Final HIR work after the optional transaction.
    #[must_use]
    pub const fn work_after(self) -> usize {
        self.work_after
    }

    /// Source-independent classifier selection terminal.
    #[must_use]
    pub const fn outcome(self) -> CaptureIterationStartClassifierOutcome {
        self.outcome
    }

    /// Selected classifier, absent for either incumbent terminal.
    #[must_use]
    pub const fn classifier(self) -> Option<MaskedInclusiveRange> {
        match self.outcome {
            CaptureIterationStartClassifierOutcome::Selected(classifier) => Some(classifier),
            CaptureIterationStartClassifierOutcome::NotAttempted
            | CaptureIterationStartClassifierOutcome::AttemptedIneligible => None,
        }
    }

    /// Authenticate arithmetic, ceiling admission and the only selected
    /// classifier implemented by this algorithm version.
    #[must_use]
    pub fn closes(self, max_hir_work: usize) -> bool {
        if self.work_before > max_hir_work {
            return false;
        }
        let admitted_after = self
            .work_before
            .checked_add(CAPTURE_ITERATION_START_CLASSIFIER_WORK);
        match self.outcome {
            CaptureIterationStartClassifierOutcome::NotAttempted => {
                self.charged_work == 0
                    && self.work_after == self.work_before
                    && admitted_after.is_none_or(|after| after > max_hir_work)
            }
            CaptureIterationStartClassifierOutcome::AttemptedIneligible => {
                self.charged_work == CAPTURE_ITERATION_START_CLASSIFIER_WORK
                    && admitted_after == Some(self.work_after)
                    && self.work_after <= max_hir_work
            }
            CaptureIterationStartClassifierOutcome::Selected(classifier) => {
                self.charged_work == CAPTURE_ITERATION_START_CLASSIFIER_WORK
                    && admitted_after == Some(self.work_after)
                    && self.work_after <= max_hir_work
                    && classifier == CAPTURE_ITERATION_ASCII_FOLD_RANGE
                    && classifier.lower() <= classifier.upper()
            }
        }
    }
}

/// Capture-valued operation authenticated by the construction owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationOperation {
    /// Materialize every capture schema entry for every selected match.
    MaterializeCaptureArray,
}

/// Physical backend selected before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationBackend {
    /// Independently bounded searches with persistent tagged histories.
    PersistentHistory,
}

/// Permitted behavior after the capture-array route is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationDeclaredFallback {
    /// Any refusal or fault is terminal for this invocation.
    None,
}

/// Complete construction-owned capture-array route identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationRouteIdentity {
    /// Canonical syntax/profile/admission identity.
    pub syntax: Arc<CacheKey>,
    /// Versioned capture semantics.
    pub capture_profile: CaptureProfile,
    /// Capture-valued operation, distinct from capture Count.
    pub operation: CaptureIterationOperation,
    /// Exact materializing iterator formulation.
    pub plan: CaptureIterationPlanKind,
    /// Physical tagged executor.
    pub backend: CaptureIterationBackend,
    /// Immutable program shape sufficient to reproduce every prospective.
    pub engine_shape: HistoryProgramShape,
    /// Construction-proved whole-match lower bound. Zero retains nullable
    /// empty-progress accounting.
    pub minimum_match_bytes: usize,
    /// Exact construction limits used to publish the tagged program.
    pub build_limits: CaptureBuildLimits,
    /// Algorithm version.
    pub algorithm_version: u32,
    /// Prospective/actual accounting version.
    pub accounting_version: u32,
    /// Only permitted post-publication behavior.
    pub declared_fallback: CaptureIterationDeclaredFallback,
}

/// Opaque construction provenance for materialized capture arrays.
///
/// Equality is pointer identity. Clones of one published capture regex retain
/// the same owner; a separately built equivalent regex does not.
#[derive(Clone, Debug)]
pub struct CaptureIterationOwnerSeal(Arc<CaptureIterationOwner>);

#[derive(Debug)]
struct CaptureIterationOwner {
    route: CaptureIterationRouteIdentity,
    start_classifier: CaptureIterationStartClassifierReceipt,
}

impl PartialEq for CaptureIterationOwnerSeal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CaptureIterationOwnerSeal {}

impl CaptureIterationOwnerSeal {
    pub(crate) fn new(
        identity: CaptureIterationRouteIdentity,
        start_classifier: CaptureIterationStartClassifierReceipt,
    ) -> Self {
        debug_assert_eq!(
            identity.operation,
            CaptureIterationOperation::MaterializeCaptureArray
        );
        debug_assert_eq!(
            identity.plan,
            CaptureIterationPlanKind::RestartedPersistentHistory
        );
        debug_assert_eq!(identity.backend, CaptureIterationBackend::PersistentHistory);
        debug_assert!(start_classifier.closes(identity.build_limits.max_hir_work));
        Self(Arc::new(CaptureIterationOwner {
            route: identity,
            start_classifier,
        }))
    }

    /// Exact immutable route identity owned by this construction.
    #[must_use]
    pub fn identity(&self) -> &CaptureIterationRouteIdentity {
        &self.0.route
    }

    /// Last optional HIR-budget transaction bound to this construction.
    #[must_use]
    pub fn start_classifier_receipt(&self) -> &CaptureIterationStartClassifierReceipt {
        &self.0.start_classifier
    }

    pub(crate) fn for_invocation(
        &self,
        search: SearchConfig,
        run_limits: AggregateLimits,
    ) -> CaptureIterationSeal {
        CaptureIterationSeal {
            owner: self.clone(),
            search,
            run_limits,
        }
    }
}

/// Construction provenance plus exact policy and limits for one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationSeal {
    owner: CaptureIterationOwnerSeal,
    search: SearchConfig,
    run_limits: AggregateLimits,
}

impl CaptureIterationSeal {
    /// Construction-owned physical route identity.
    #[must_use]
    pub fn route_identity(&self) -> &CaptureIterationRouteIdentity {
        self.owner.identity()
    }

    /// Start-classifier construction receipt sealed by this owner.
    #[must_use]
    pub fn start_classifier_receipt(&self) -> &CaptureIterationStartClassifierReceipt {
        self.owner.start_classifier_receipt()
    }

    /// Exact match-end, priority, and start-injection policy.
    #[must_use]
    pub const fn search(&self) -> SearchConfig {
        self.search
    }

    /// Exact aggregate limits for this invocation.
    #[must_use]
    pub const fn run_limits(&self) -> AggregateLimits {
        self.run_limits
    }

    pub(crate) fn prospective(
        &self,
        haystack_len: usize,
        window: Window,
    ) -> Result<CaptureIterationProspective, SearchError> {
        if window.start > window.end || window.end > haystack_len {
            return Err(SearchError::InvalidWindow);
        }
        let engine = self
            .route_identity()
            .engine_shape
            .restarted_prospective_with_minimum(
                window,
                self.route_identity().minimum_match_bytes,
            )?;
        Ok(CaptureIterationProspective {
            haystack_len,
            engine,
        })
    }
}

/// Complete pre-source capture-array session envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureIterationProspective {
    /// Original haystack length. Assertions retain this surrounding context.
    pub haystack_len: usize,
    /// Restarted persistent-history work, result, and scratch envelope.
    pub engine: RestartedHistoryProspective,
}

impl CaptureIterationProspective {
    /// Componentwise upper-bound check for one cumulative terminal charge.
    #[must_use]
    pub fn contains(self, actual: CaptureIterationActual) -> bool {
        actual.searches <= self.engine.searches
            && actual.materialized_records <= self.engine.materialized_records
            && actual.results <= self.engine.results
            && actual.total_state_visits <= self.engine.total_state_visits
            && actual.total_slot_copies <= self.engine.total_slot_copies
            && actual.total_history_nodes <= self.engine.total_history_nodes
            && actual.total_history_walk <= self.engine.total_history_walk
            && actual.capture_events <= self.engine.capture_events
            && actual.bytes_examined <= self.engine.bytes_examined
            && actual.starts_injected <= self.engine.starts_injected
            && actual.peak_threads <= self.engine.peak_threads
            && actual.scratch_bytes <= self.engine.scratch_bytes
            && actual.retained_output_bytes <= self.engine.retained_output_bytes
            && actual.combined_peak_bytes <= self.engine.combined_peak_bytes
    }

    pub(crate) fn first_limit_error(self, limits: AggregateLimits) -> Option<SearchError> {
        let largest_search = self.engine.largest_search;
        first_resource_failure(
            ResourceKind::StateVisits,
            largest_search.state_visits,
            limits.per_search.max_state_visits,
        )
        .or_else(|| {
            first_resource_failure(
                ResourceKind::HistoryNodes,
                largest_search.history_nodes,
                limits.per_search.max_history_nodes,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::HistoryWalk,
                largest_search.history_walk,
                limits.per_search.max_history_walk,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::ScratchBytes,
                largest_search.scratch_bytes,
                limits.per_search.max_scratch_bytes,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::Searches,
                self.engine.searches,
                limits.max_searches,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::Results,
                self.engine.results,
                limits.max_results,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::AggregateStateVisits,
                self.engine.total_state_visits,
                limits.max_total_state_visits,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::AggregateSlotCopies,
                self.engine.total_slot_copies,
                limits.max_total_slot_copies,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::AggregateHistoryNodes,
                self.engine.total_history_nodes,
                limits.max_total_history_nodes,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::AggregateHistoryWalk,
                self.engine.total_history_walk,
                limits.max_total_history_walk,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::CaptureEvents,
                self.engine.capture_events,
                limits.max_capture_events,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::RetainedOutputBytes,
                self.engine.retained_output_bytes,
                limits.max_retained_output_bytes,
            )
        })
        .or_else(|| {
            first_resource_failure(
                ResourceKind::CombinedPeakBytes,
                self.engine.combined_peak_bytes,
                limits.max_combined_peak_bytes,
            )
        })
    }
}

/// Complete cumulative charged ledger through a success or terminal failure.
///
/// Search work is charged at its published per-search prospective immediately
/// before that search can read source. This remains lossless even if a nested
/// executor faults before it can return physical counters. Result and capture
/// event counters are exact completed materializations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureIterationActual {
    /// Searches whose individual prospectives were committed.
    pub searches: usize,
    /// Winners materialized by nested searches, including an empty winner
    /// subsequently suppressed by iterator progress.
    pub materialized_records: usize,
    /// Materialized capture records retained by the returned output.
    pub results: usize,
    /// Cumulative charged Thompson state visits.
    pub total_state_visits: usize,
    /// Cumulative charged inline slot copies (always zero for this backend).
    pub total_slot_copies: usize,
    /// Cumulative charged persistent-history nodes.
    pub total_history_nodes: usize,
    /// Cumulative charged history reconstruction steps.
    pub total_history_walk: usize,
    /// Exact complete-schema capture entries materialized.
    pub capture_events: usize,
    /// Cumulative charged input bytes advanced over.
    pub bytes_examined: usize,
    /// Cumulative charged candidate starts.
    pub starts_injected: usize,
    /// Maximum charged live-thread count.
    pub peak_threads: usize,
    /// Maximum charged dynamic scratch bytes.
    pub scratch_bytes: usize,
    /// Exact versioned logical bytes retained by completed output records.
    pub retained_output_bytes: usize,
    /// Maximum charged current-search scratch plus logical retained/current
    /// materialization bytes observed at session accounting boundaries.
    pub combined_peak_bytes: usize,
}

impl CaptureIterationActual {
    pub(crate) fn charge_search(
        &mut self,
        prospective: HistorySearchProspective,
    ) -> Result<(), SearchError> {
        self.searches = checked_add(self.searches, 1, ResourceKind::Searches)?;
        self.total_state_visits = checked_add(
            self.total_state_visits,
            prospective.state_visits,
            ResourceKind::AggregateStateVisits,
        )?;
        self.total_history_nodes = checked_add(
            self.total_history_nodes,
            prospective.history_nodes,
            ResourceKind::AggregateHistoryNodes,
        )?;
        self.total_history_walk = checked_add(
            self.total_history_walk,
            prospective.history_walk,
            ResourceKind::AggregateHistoryWalk,
        )?;
        self.bytes_examined = checked_add(
            self.bytes_examined,
            prospective.bytes_examined,
            ResourceKind::AggregateStateVisits,
        )?;
        self.starts_injected = checked_add(
            self.starts_injected,
            prospective.starts_injected,
            ResourceKind::AggregateStateVisits,
        )?;
        self.peak_threads = self.peak_threads.max(prospective.peak_threads);
        self.scratch_bytes = self.scratch_bytes.max(prospective.scratch_bytes);
        self.combined_peak_bytes = self.combined_peak_bytes.max(
            self.retained_output_bytes
                .checked_add(prospective.scratch_bytes)
                .ok_or(SearchError::BoundOverflow(ResourceKind::CombinedPeakBytes))?,
        );
        Ok(())
    }

    pub(crate) fn record_materialized(
        &mut self,
        groups: usize,
        materialized_record_bytes: usize,
        current_scratch_bytes: usize,
    ) -> Result<(), SearchError> {
        self.materialized_records =
            checked_add(self.materialized_records, 1, ResourceKind::Results)?;
        self.capture_events =
            checked_add(self.capture_events, groups, ResourceKind::CaptureEvents)?;
        let materialization_peak = self
            .retained_output_bytes
            .checked_add(materialized_record_bytes)
            .and_then(|bytes| bytes.checked_add(current_scratch_bytes))
            .ok_or(SearchError::BoundOverflow(ResourceKind::CombinedPeakBytes))?;
        self.combined_peak_bytes = self.combined_peak_bytes.max(materialization_peak);
        Ok(())
    }

    pub(crate) fn record_result(
        &mut self,
        retained_record_bytes: usize,
    ) -> Result<(), SearchError> {
        self.results = checked_add(self.results, 1, ResourceKind::Results)?;
        self.retained_output_bytes = checked_add(
            self.retained_output_bytes,
            retained_record_bytes,
            ResourceKind::RetainedOutputBytes,
        )?;
        // The outer capture-vector cell is allocated only after the nested
        // search and its scratch have returned. Its non-overlapping logical
        // contribution is therefore the new retained total alone.
        self.combined_peak_bytes = self.combined_peak_bytes.max(self.retained_output_bytes);
        Ok(())
    }
}

/// Terminal state authenticated by a capture-array session receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationTerminal {
    /// Every selected capture record was materialized.
    Success,
    /// The published route refused or faulted without fallback.
    Failure,
}

/// One lossless terminal receipt for a materialized capture-array invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationAttemptReceipt {
    /// Published session envelope, absent only when invocation validation or
    /// checked derivation failed before any complete prospective existed.
    pub prospective: Option<CaptureIterationProspective>,
    /// Cumulative charged work and exact completed result counters.
    pub actual: CaptureIterationActual,
    /// Terminal state.
    pub terminal: CaptureIterationTerminal,
}

impl CaptureIterationAttemptReceipt {
    pub(crate) fn failure(
        prospective: Option<CaptureIterationProspective>,
        actual: CaptureIterationActual,
    ) -> Self {
        Self {
            prospective,
            actual,
            terminal: CaptureIterationTerminal::Failure,
        }
    }

    pub(crate) fn success(
        prospective: CaptureIterationProspective,
        actual: CaptureIterationActual,
    ) -> Self {
        Self {
            prospective: Some(prospective),
            actual,
            terminal: CaptureIterationTerminal::Success,
        }
    }

    /// Validate owner route, exact input-derived prospective, limits, and
    /// cumulative A≤P for this invocation.
    #[must_use]
    pub fn closes(&self, seal: &CaptureIterationSeal) -> bool {
        let route = seal.route_identity();
        if route.operation != CaptureIterationOperation::MaterializeCaptureArray
            || route.plan != CaptureIterationPlanKind::RestartedPersistentHistory
            || route.backend != CaptureIterationBackend::PersistentHistory
            || route.algorithm_version != CAPTURE_ITERATION_ALGORITHM_VERSION
            || route.accounting_version != CAPTURE_ITERATION_ACCOUNTING_VERSION
            || route.declared_fallback != CaptureIterationDeclaredFallback::None
            || route.engine_shape.groups == 0
        {
            return false;
        }
        let Some(prospective) = self.prospective else {
            return self.terminal == CaptureIterationTerminal::Failure
                && self.actual == CaptureIterationActual::default();
        };
        if prospective.engine.window.end > prospective.haystack_len
            || route.engine_shape.restarted_prospective_with_minimum(
                prospective.engine.window,
                route.minimum_match_bytes,
            ) != Ok(prospective.engine)
            || !prospective.contains(self.actual)
            || self
                .actual
                .materialized_records
                .checked_mul(route.engine_shape.groups)
                != Some(self.actual.capture_events)
            || self.actual.results > self.actual.materialized_records
            || route
                .engine_shape
                .retained_record_bytes()
                .ok()
                .and_then(|bytes| self.actual.results.checked_mul(bytes))
                != Some(self.actual.retained_output_bytes)
            || self.actual.combined_peak_bytes < self.actual.retained_output_bytes
        {
            return false;
        }
        self.terminal != CaptureIterationTerminal::Success
            || prospective.first_limit_error(seal.run_limits).is_none()
    }
}

fn first_resource_failure(
    kind: ResourceKind,
    required: usize,
    limit: usize,
) -> Option<SearchError> {
    (required > limit).then_some(SearchError::Resource {
        kind,
        required,
        limit,
    })
}

fn checked_add(left: usize, right: usize, kind: ResourceKind) -> Result<usize, SearchError> {
    left.checked_add(right)
        .ok_or(SearchError::BoundOverflow(kind))
}
