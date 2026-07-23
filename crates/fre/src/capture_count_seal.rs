//! Construction-owner seal and whole-operation receipt for admitted capture Count.

use std::sync::Arc;

use fre_aggregate::{
    CONTINUATION_OPERATION_ACCOUNTING_VERSION, CONTINUATION_OPERATION_ALGORITHM_VERSION,
    ExecutionAccounting as SelectorExecutionAccounting,
    OperationAttemptKind as SelectorOperationAttemptKind,
    OperationAttemptReceipt as SelectorOperationAttemptReceipt,
    OperationLimits as SelectorOperationLimits,
    OperationPhysicalRoute as SelectorOperationPhysicalRoute,
    OperationPrepublicationFallback as SelectorOperationPrepublicationFallback,
    OperationProspective as SelectorOperationProspective,
    OperationWorkMode as SelectorOperationWorkMode, Strategy as SelectorStrategy,
};
use fre_kernels::{
    PREFIX_CLASS_UNIFORM_PARTICIPATION_ACCOUNTING_VERSION,
    PREFIX_CLASS_UNIFORM_PARTICIPATION_ALGORITHM_VERSION,
    PrefixClassUniformParticipationActual as DirectExecutionActual,
    PrefixClassUniformParticipationAttemptReceipt as DirectAttemptReceipt,
    PrefixClassUniformParticipationLimits as DirectOperationLimits,
    PrefixClassUniformParticipationProspective as DirectOperationProspective,
};

use crate::captures::{
    CaptureBuildLimits, CaptureOperation, CapturePlanIdentity, CapturePlanKind, CaptureRunLimits,
};

/// Version of the positive-width uniform-participation Count algorithm.
pub const CAPTURE_COUNT_ALGORITHM_VERSION: u32 = 2;

/// Version of the owner-local capture Count prospective/actual ledger.
pub const CAPTURE_COUNT_ACCOUNTING_VERSION: u32 = 1;

/// Capture-side physical branch selected before an admitted Count invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureCountBranch {
    /// Receipt-bearing U3 selector Count followed by checked schema arithmetic.
    SelectorUniformParticipation,
    /// Allocation-free U4 prefix/class capture-participation reducer.
    DirectPrefixClassParticipation,
}

/// Complete U0-A identity fields for the retained U3 selector route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureCountSelectorRoute {
    /// Exact physical executor selected before source access.
    pub physical_route: SelectorOperationPhysicalRoute,
    /// Nested continuation algorithm version.
    pub algorithm_version: u8,
    /// Nested continuation accounting version.
    pub accounting_version: u8,
    /// Route-selection edge exhausted before nested P publication.
    pub prepublication_fallback: SelectorOperationPrepublicationFallback,
}

/// Permitted action after the sealed route is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureCountDeclaredFallback {
    /// A refusal or fault is terminal; no other route may inspect the source.
    None,
}

/// Permitted construction-time action before the sealed route is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureCountPrepublicationFallback {
    /// No alternate capture Count route is permitted.
    None,
    /// U4 direct construction may refuse into the already-built U3 selector.
    SelectorUniformParticipation,
}

/// Complete structural identity retained by one construction-owned Count seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCountRouteIdentity {
    /// Canonical syntax, capture policy, profile, selector plan, and operation.
    pub plan: CapturePlanIdentity,
    /// Exact construction limits used to publish the capture artifact.
    pub build_limits: CaptureBuildLimits,
    /// Capture-side physical branch selected before source access.
    pub branch: CaptureCountBranch,
    /// Exact U0-A selector or retained U3 fallback-control route.
    pub selector_route: CaptureCountSelectorRoute,
    /// Selector traversal strategy.
    pub selector_strategy: SelectorStrategy,
    /// Receipt-bearing selector operation.
    pub selector_operation: SelectorOperationAttemptKind,
    /// Selector admission policy.
    pub selector_work_mode: SelectorOperationWorkMode,
    /// Positive whole-match lower bound used for the match envelope.
    pub minimum_match_bytes: usize,
    /// Participating capture entries per match, including group zero.
    pub participating_captures_per_match: usize,
    /// Complete capture schema entries charged per match, including group zero.
    pub capture_schema_entries_per_match: usize,
    /// Generic selector and tagged-program bytes retained beside a direct plan.
    pub retained_fallback_bytes: usize,
    /// Capture Count algorithm version.
    pub algorithm_version: u32,
    /// Capture Count prospective/actual ledger version.
    pub accounting_version: u32,
    /// Only permitted construction-time fallback.
    pub declared_prepublication_fallback: CaptureCountPrepublicationFallback,
    /// Only permitted action after route publication.
    pub declared_fallback: CaptureCountDeclaredFallback,
}

/// Opaque construction provenance for one capture Count route.
///
/// Equality is exact owner provenance, not structural equality. Clones of one
/// published [`crate::CaptureRegex`] retain the same owner.
#[derive(Clone, Debug)]
pub struct CaptureCountOwnerSeal(Arc<CaptureCountRouteIdentity>);

impl PartialEq for CaptureCountOwnerSeal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CaptureCountOwnerSeal {}

impl CaptureCountOwnerSeal {
    pub(crate) fn new(identity: CaptureCountRouteIdentity) -> Self {
        debug_assert!(matches!(
            (identity.branch, identity.plan.plan),
            (
                CaptureCountBranch::SelectorUniformParticipation,
                CapturePlanKind::LinearSelectorUniformParticipation
                    | CapturePlanKind::OrderedRootCaptureManyCount
            ) | (
                CaptureCountBranch::DirectPrefixClassParticipation,
                CapturePlanKind::UniformPrefixClassParticipation
            )
        ));
        Self(Arc::new(identity))
    }

    /// Exact immutable structural identity owned by this construction.
    #[must_use]
    pub fn identity(&self) -> &CaptureCountRouteIdentity {
        &self.0
    }

    pub(crate) fn for_limits(&self, run_limits: &CaptureRunLimits) -> CaptureCountSeal {
        CaptureCountSeal {
            owner: self.clone(),
            run_limits: *run_limits,
        }
    }
}

/// Immutable owner provenance plus the exact limits for one Count invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCountSeal {
    owner: CaptureCountOwnerSeal,
    run_limits: CaptureRunLimits,
}

impl CaptureCountSeal {
    /// Construction-owned physical route identity.
    #[must_use]
    pub fn route_identity(&self) -> &CaptureCountRouteIdentity {
        self.owner.identity()
    }

    /// Exact invocation limits bound by this seal.
    #[must_use]
    pub const fn run_limits(&self) -> CaptureRunLimits {
        self.run_limits
    }

    fn effective_selector_limits(&self) -> SelectorOperationLimits {
        let mut limits = self.run_limits.selector;
        limits.max_peak_bytes = limits
            .max_peak_bytes
            .min(self.run_limits.max_combined_peak_bytes);
        limits
    }
}

/// Complete input-only envelope published before the sealed route reads source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureCountProspective {
    /// U3 selector P, executed by the selector branch and retained as direct
    /// fallback/control evidence by the U4 branch.
    pub selector: SelectorOperationProspective,
    /// U4 direct P. This is absent for a selected U3 selector route.
    pub direct: Option<DirectOperationProspective>,
    /// Maximum selected non-empty matches.
    pub matches: usize,
    /// Maximum participating-capture result.
    pub capture_count: usize,
    /// Maximum complete-schema entries inspected by the reducer.
    pub capture_events: usize,
    /// Maximum allocations committed by the selected physical operation.
    pub allocations: usize,
    /// Maximum logical co-live peak for the complete selected route.
    pub combined_peak_bytes: usize,
}

impl CaptureCountProspective {
    fn fits_limits(self, route: &CaptureCountRouteIdentity, seal: &CaptureCountSeal) -> bool {
        let selector_fits = match route.branch {
            CaptureCountBranch::SelectorUniformParticipation => {
                selector_fits_limits(&self.selector, seal.effective_selector_limits())
            }
            CaptureCountBranch::DirectPrefixClassParticipation => {
                retained_selector_control_fits_limits(
                    &self.selector,
                    seal.effective_selector_limits(),
                )
            }
        };
        selector_fits
            && self.matches <= seal.run_limits.aggregate.max_results
            && self.capture_count <= seal.run_limits.aggregate.max_capture_count
            && self.capture_events <= seal.run_limits.aggregate.max_capture_events
            && self.combined_peak_bytes <= seal.run_limits.max_combined_peak_bytes
            && match (route.branch, self.direct) {
                (CaptureCountBranch::SelectorUniformParticipation, None) => {
                    self.allocations == self.selector.allocations
                }
                (CaptureCountBranch::DirectPrefixClassParticipation, Some(direct)) => {
                    self.allocations == direct.operation_allocations
                        && direct_fits_limits(&direct, seal.run_limits.prefix_class_participation)
                }
                _ => false,
            }
    }

    /// Componentwise upper-bound check for one cumulative terminal actual.
    #[must_use]
    pub fn contains(self, actual: CaptureCountActual) -> bool {
        let direct_is_bounded = match (self.direct, actual.direct) {
            (None, None) => true,
            (Some(prospective), Some(actual)) => prospective.contains(&actual),
            _ => false,
        };
        self.selector.contains(actual.selector)
            && direct_is_bounded
            && actual.selector_allocations <= self.selector.allocations
            && actual.direct_allocations <= self.allocations
            && actual.matches <= self.matches
            && actual.capture_count <= self.capture_count
            && actual.capture_events <= self.capture_events
            && actual.combined_peak_bytes <= self.combined_peak_bytes
    }
}

/// Exact cumulative Count counters through one success or terminal failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureCountActual {
    /// Nested selector counters, including partial counters on failure.
    pub selector: SelectorExecutionAccounting,
    /// Nested direct counters, including partial counters on failure.
    pub direct: Option<DirectExecutionActual>,
    /// Selector allocations committed before the terminal outcome.
    pub selector_allocations: usize,
    /// Direct allocations committed before the terminal outcome.
    pub direct_allocations: usize,
    /// Selected matches admitted to capture arithmetic.
    pub matches: usize,
    /// Participating-capture result completed by the reducer.
    pub capture_count: usize,
    /// Complete-schema entries charged by the reducer.
    pub capture_events: usize,
    /// Logical co-live peak reached before the terminal outcome.
    pub combined_peak_bytes: usize,
}

impl CaptureCountActual {
    pub(crate) fn from_selector(receipt: &SelectorOperationAttemptReceipt) -> Self {
        Self {
            selector: receipt.actual,
            selector_allocations: receipt.actual_allocations,
            combined_peak_bytes: receipt.actual.peak_bytes,
            ..Self::default()
        }
    }

    pub(crate) fn from_direct(
        receipt: &DirectAttemptReceipt,
        retained_fallback_bytes: usize,
    ) -> Option<Self> {
        Some(Self {
            direct: Some(receipt.actual),
            direct_allocations: receipt.actual_allocations,
            matches: receipt.actual.results,
            capture_count: receipt.actual.capture_count,
            capture_events: receipt.actual.capture_events,
            combined_peak_bytes: retained_fallback_bytes.checked_add(receipt.actual.peak_bytes)?,
            ..Self::default()
        })
    }
}

/// Terminal state authenticated by a whole-operation Count receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureCountTerminal {
    /// Selected route and capture arithmetic completed successfully.
    Success,
    /// The selected route refused or faulted without a runtime fallback.
    Failure,
}

/// Authenticated publication frontier reached by one terminal attempt.
///
/// This remains crate-private so callers can inspect the public P/A payload
/// but cannot relabel a cloned receipt after deleting a published envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureCountPublicationPhase {
    /// Neither the nested route nor the whole-operation owner published P.
    BeforeNested,
    /// The nested route published P, but checked outer arithmetic did not
    /// produce the complete whole-operation envelope.
    Nested,
    /// The complete whole-operation P was published.
    Whole,
}

/// One whole-operation receipt retaining nested route P/A and capture P/A.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCountAttemptReceipt {
    /// Exact construction provenance and invocation limits. Keeping this
    /// private prevents callers from splicing a structurally equal receipt
    /// onto a separately built owner or a different run-limit identity.
    seal: CaptureCountSeal,
    /// Private publication frontier prevents deletion or insertion of public P
    /// fields from preserving closure.
    publication_phase: CaptureCountPublicationPhase,
    /// Private terminal disposition prevents a completed success receipt from
    /// being relabeled as a failure, or vice versa.
    authenticated_terminal: CaptureCountTerminal,
    /// Complete receipt from the U3 selector route, when selected.
    pub selector: Option<SelectorOperationAttemptReceipt>,
    /// Complete receipt from the U4 direct route, when selected.
    pub direct: Option<DirectAttemptReceipt>,
    /// Capture-owner envelope, absent only if route publication or checked
    /// source-free arithmetic could not produce the complete P.
    pub prospective: Option<CaptureCountProspective>,
    /// Cumulative selected-route and capture actual counters.
    pub actual: CaptureCountActual,
    /// Terminal outcome of the sealed attempt.
    pub terminal: CaptureCountTerminal,
}

impl CaptureCountAttemptReceipt {
    pub(crate) fn selector_failure(
        seal: &CaptureCountSeal,
        selector: SelectorOperationAttemptReceipt,
        prospective: Option<&CaptureCountProspective>,
        actual: &CaptureCountActual,
    ) -> Self {
        let publication_phase = if prospective.is_some() {
            CaptureCountPublicationPhase::Whole
        } else if selector.prospective.is_some() {
            CaptureCountPublicationPhase::Nested
        } else {
            CaptureCountPublicationPhase::BeforeNested
        };
        Self {
            seal: seal.clone(),
            publication_phase,
            authenticated_terminal: CaptureCountTerminal::Failure,
            selector: Some(selector),
            direct: None,
            prospective: prospective.copied(),
            actual: *actual,
            terminal: CaptureCountTerminal::Failure,
        }
    }

    pub(crate) fn selector_success(
        seal: &CaptureCountSeal,
        selector: SelectorOperationAttemptReceipt,
        prospective: &CaptureCountProspective,
        actual: &CaptureCountActual,
    ) -> Self {
        Self {
            seal: seal.clone(),
            publication_phase: CaptureCountPublicationPhase::Whole,
            authenticated_terminal: CaptureCountTerminal::Success,
            selector: Some(selector),
            direct: None,
            prospective: Some(*prospective),
            actual: *actual,
            terminal: CaptureCountTerminal::Success,
        }
    }

    pub(crate) fn direct_failure(
        seal: &CaptureCountSeal,
        direct: &DirectAttemptReceipt,
        prospective: Option<&CaptureCountProspective>,
        actual: &CaptureCountActual,
    ) -> Self {
        let publication_phase = if prospective.is_some() {
            CaptureCountPublicationPhase::Whole
        } else if direct.prospective.is_some() {
            CaptureCountPublicationPhase::Nested
        } else {
            CaptureCountPublicationPhase::BeforeNested
        };
        Self {
            seal: seal.clone(),
            publication_phase,
            authenticated_terminal: CaptureCountTerminal::Failure,
            selector: None,
            direct: Some(*direct),
            prospective: prospective.copied(),
            actual: *actual,
            terminal: CaptureCountTerminal::Failure,
        }
    }

    pub(crate) fn direct_success(
        seal: &CaptureCountSeal,
        direct: &DirectAttemptReceipt,
        prospective: &CaptureCountProspective,
        actual: &CaptureCountActual,
    ) -> Self {
        Self {
            seal: seal.clone(),
            publication_phase: CaptureCountPublicationPhase::Whole,
            authenticated_terminal: CaptureCountTerminal::Success,
            selector: None,
            direct: Some(*direct),
            prospective: Some(*prospective),
            actual: *actual,
            terminal: CaptureCountTerminal::Success,
        }
    }

    pub(crate) const fn publication_phase(&self) -> CaptureCountPublicationPhase {
        self.publication_phase
    }

    /// Validate route identity, exact input-derived P, nested P/A, limits, and
    /// cumulative A≤P against the construction-owned seal.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the branch-aware closure intentionally authenticates every selector, direct, capture, limit, version, fallback, and P/A field in one audit boundary"
    )]
    pub fn closes(&self, seal: &CaptureCountSeal) -> bool {
        let route = seal.route_identity();
        let nested_prospective_is_some = match route.branch {
            CaptureCountBranch::SelectorUniformParticipation => self
                .selector
                .as_ref()
                .is_some_and(|selector| selector.prospective.is_some()),
            CaptureCountBranch::DirectPrefixClassParticipation => self
                .direct
                .as_ref()
                .is_some_and(|direct| direct.prospective.is_some()),
        };
        let observed_publication_phase =
            match (nested_prospective_is_some, self.prospective.is_some()) {
                (false, false) => Some(CaptureCountPublicationPhase::BeforeNested),
                (true, false) => Some(CaptureCountPublicationPhase::Nested),
                (true, true) => Some(CaptureCountPublicationPhase::Whole),
                (false, true) => None,
            };
        if self.seal != *seal
            || observed_publication_phase != Some(self.publication_phase)
            || self.authenticated_terminal != self.terminal
            || route.plan.operation != CaptureOperation::CountParticipatingNonempty
            || route.selector_strategy != SelectorStrategy::ReverseSequentialRows
            || route.selector_operation != SelectorOperationAttemptKind::Count
            || route.selector_work_mode
                != match route.branch {
                    CaptureCountBranch::SelectorUniformParticipation => {
                        SelectorOperationWorkMode::Observed
                    }
                    CaptureCountBranch::DirectPrefixClassParticipation => {
                        SelectorOperationWorkMode::ConservativeAdmission
                    }
                }
            || route.selector_route.algorithm_version != CONTINUATION_OPERATION_ALGORITHM_VERSION
            || route.selector_route.accounting_version != CONTINUATION_OPERATION_ACCOUNTING_VERSION
            || route.selector_route.prepublication_fallback
                != SelectorOperationPrepublicationFallback::None
            || route.algorithm_version != CAPTURE_COUNT_ALGORITHM_VERSION
            || route.accounting_version != CAPTURE_COUNT_ACCOUNTING_VERSION
            || route.minimum_match_bytes == 0
            || !matches!(
                (route.plan.plan, route.selector_route.physical_route),
                (
                    CapturePlanKind::OrderedRootCaptureManyCount,
                    SelectorOperationPhysicalRoute::OrderedRootRows,
                ) | (
                    CapturePlanKind::LinearSelectorUniformParticipation,
                    SelectorOperationPhysicalRoute::DenseRows
                        | SelectorOperationPhysicalRoute::TerminalFrontierRows,
                ) | (
                    CapturePlanKind::UniformPrefixClassParticipation,
                    SelectorOperationPhysicalRoute::DenseRows,
                )
            )
            || match (route.plan.plan, route.plan.ordered_root_capture_many) {
                (CapturePlanKind::OrderedRootCaptureManyCount, Some(proof)) => {
                    proof.root_arms.checked_add(1) != Some(route.capture_schema_entries_per_match)
                        || proof.participating_captures.checked_add(1)
                            != Some(route.participating_captures_per_match)
                        || proof.groups_per_match != route.participating_captures_per_match
                }
                (CapturePlanKind::OrderedRootCaptureManyCount, None) | (_, Some(_)) => true,
                (_, None) => false,
            }
        {
            return false;
        }

        let haystack_len = match route.branch {
            CaptureCountBranch::SelectorUniformParticipation => {
                if !matches!(
                    route.plan.plan,
                    CapturePlanKind::LinearSelectorUniformParticipation
                        | CapturePlanKind::OrderedRootCaptureManyCount
                ) || route.plan.prefix_class_participation.is_some()
                    || route.retained_fallback_bytes != 0
                    || route.declared_prepublication_fallback
                        != CaptureCountPrepublicationFallback::None
                    || route.declared_fallback != CaptureCountDeclaredFallback::None
                    || self.direct.is_some()
                {
                    return false;
                }
                let Some(selector) = self.selector.as_ref() else {
                    return false;
                };
                if !selector_closes(selector, route, seal, self.prospective.is_some())
                    || self.actual.selector != selector.actual
                    || self.actual.selector_allocations != selector.actual_allocations
                    || self.actual.direct.is_some()
                    || self.actual.direct_allocations != 0
                {
                    return false;
                }
                selector.invocation.haystack_len
            }
            CaptureCountBranch::DirectPrefixClassParticipation => {
                if route.plan.plan != CapturePlanKind::UniformPrefixClassParticipation
                    || route.declared_prepublication_fallback
                        != CaptureCountPrepublicationFallback::SelectorUniformParticipation
                    || route.declared_fallback != CaptureCountDeclaredFallback::None
                    || self.selector.is_some()
                    || self.actual.selector != SelectorExecutionAccounting::default()
                    || self.actual.selector_allocations != 0
                {
                    return false;
                }
                let (Some(plan), Some(direct), Some(actual)) = (
                    route.plan.prefix_class_participation,
                    self.direct.as_ref(),
                    self.actual.direct,
                ) else {
                    return false;
                };
                if plan.declared_prepublication_fallback
                    != CapturePlanKind::LinearSelectorUniformParticipation
                    || route.selector_route.physical_route
                        != SelectorOperationPhysicalRoute::DenseRows
                    || plan.kernel.algorithm_version
                        != PREFIX_CLASS_UNIFORM_PARTICIPATION_ALGORITHM_VERSION
                    || plan.kernel.accounting_version
                        != PREFIX_CLASS_UNIFORM_PARTICIPATION_ACCOUNTING_VERSION
                    || !direct.authenticates(plan.kernel, direct.invocation)
                    || direct.invocation.schema.participating_with_overall
                        != route.participating_captures_per_match
                    || direct.invocation.schema.capture_schema_slots
                        != route.capture_schema_entries_per_match
                    || direct.invocation.limits != seal.run_limits.prefix_class_participation
                    || direct.actual != actual
                    || direct.actual_allocations != self.actual.direct_allocations
                    || !direct.retains_bounded_actual()
                    || self.actual.matches != direct.actual.results
                    || self.actual.capture_count != direct.actual.capture_count
                    || self.actual.capture_events != direct.actual.capture_events
                    || route
                        .retained_fallback_bytes
                        .checked_add(direct.actual.peak_bytes)
                        != Some(self.actual.combined_peak_bytes)
                {
                    return false;
                }
                direct.invocation.haystack_bytes
            }
        };

        let Some(prospective) = self.prospective else {
            return self.terminal == CaptureCountTerminal::Failure
                && match route.branch {
                    CaptureCountBranch::SelectorUniformParticipation => {
                        self.actual == CaptureCountActual::default()
                    }
                    CaptureCountBranch::DirectPrefixClassParticipation => {
                        self.actual
                            == CaptureCountActual {
                                direct: Some(DirectExecutionActual::default()),
                                combined_peak_bytes: route.retained_fallback_bytes,
                                ..CaptureCountActual::default()
                            }
                    }
                };
        };
        let Some(matches) = haystack_len.checked_div(route.minimum_match_bytes) else {
            return false;
        };
        let Some(capture_count) = matches.checked_mul(route.participating_captures_per_match)
        else {
            return false;
        };
        let Some(capture_events) = matches.checked_mul(route.capture_schema_entries_per_match)
        else {
            return false;
        };
        if prospective.matches != matches
            || prospective.capture_count != capture_count
            || prospective.capture_events != capture_events
            || prospective.selector.output_bytes != 0
            || prospective.selector.output_matches < matches
            || !prospective.contains(self.actual)
        {
            return false;
        }

        match route.branch {
            CaptureCountBranch::SelectorUniformParticipation => {
                let Some(selector) = self.selector.as_ref() else {
                    return false;
                };
                let expected_terminal_frontier = route.selector_route.physical_route
                    == SelectorOperationPhysicalRoute::TerminalFrontierRows;
                if prospective.direct.is_some()
                    || selector.prospective != Some(prospective.selector)
                    || prospective.selector.terminal_frontier != expected_terminal_frontier
                    || prospective.allocations != prospective.selector.allocations
                    || prospective.combined_peak_bytes != prospective.selector.peak_bytes
                    || self.actual.combined_peak_bytes != selector.actual.peak_bytes
                {
                    return false;
                }
            }
            CaptureCountBranch::DirectPrefixClassParticipation => {
                let Some(direct) = self.direct.as_ref() else {
                    return false;
                };
                let Some(direct_prospective) = prospective.direct else {
                    return false;
                };
                let Some(boundaries) = haystack_len.checked_add(1) else {
                    return false;
                };
                let Some(direct_peak) = route
                    .retained_fallback_bytes
                    .checked_add(direct_prospective.peak_bytes)
                else {
                    return false;
                };
                if direct.prospective != Some(direct_prospective)
                    || direct_prospective.haystack_bytes != haystack_len
                    || direct_prospective.minimum_match_bytes != route.minimum_match_bytes
                    || direct_prospective.results != matches
                    || direct_prospective.capture_count != capture_count
                    || direct_prospective.capture_events != capture_events
                    || prospective.allocations != direct_prospective.operation_allocations
                    || prospective.selector.boundaries != boundaries
                    || prospective.selector.terminal_frontier
                    || prospective.combined_peak_bytes
                        != direct_peak.max(prospective.selector.peak_bytes)
                {
                    return false;
                }
            }
        }

        if self.terminal == CaptureCountTerminal::Success {
            prospective.fits_limits(route, seal)
                && match route.branch {
                    CaptureCountBranch::SelectorUniformParticipation => {
                        self.selector.as_ref().is_some_and(|selector| {
                            self.actual.matches == selector.actual.emitted_matches
                                && capture_count_for_actual(route, self)
                                    == Some(self.actual.capture_count)
                                && capture_events_for_actual(route, self)
                                    == Some(self.actual.capture_events)
                        })
                    }
                    CaptureCountBranch::DirectPrefixClassParticipation => {
                        self.direct.as_ref().is_some_and(|direct| {
                            self.actual.matches == direct.actual.results
                                && self.actual.capture_count == direct.actual.capture_count
                                && self.actual.capture_events == direct.actual.capture_events
                        })
                    }
                }
        } else {
            true
        }
    }
}

fn selector_closes(
    selector: &SelectorOperationAttemptReceipt,
    route: &CaptureCountRouteIdentity,
    seal: &CaptureCountSeal,
    outer_prospective_is_some: bool,
) -> bool {
    let expected_physical_route = route.selector_route.physical_route;
    let physical_route_closes = selector.identity.physical_route == Some(expected_physical_route)
        || (!outer_prospective_is_some
            && selector.prospective.is_none()
            && selector.identity.physical_route.is_none());
    selector.identity.regex_plan_id == route.plan.selector_plan_id
        && selector.identity.strategy == route.selector_strategy
        && selector.identity.operation == route.selector_operation
        && selector.identity.work_mode == route.selector_work_mode
        && physical_route_closes
        && selector.identity.algorithm_version == route.selector_route.algorithm_version
        && selector.identity.accounting_version == route.selector_route.accounting_version
        && selector.identity.prepublication_fallback == route.selector_route.prepublication_fallback
        && selector
            .identity
            .authenticates_limits(seal.effective_selector_limits())
        && selector.invocation.range == (0..selector.invocation.haystack_len)
        && selector.allocation_limit == usize::MAX
        && selector.actual_allocations
            <= selector
                .prospective
                .map_or(0, |prospective| prospective.allocations)
        && selector
            .prospective
            .is_none_or(|prospective| prospective.contains(selector.actual))
}

fn capture_count_for_actual(
    route: &CaptureCountRouteIdentity,
    receipt: &CaptureCountAttemptReceipt,
) -> Option<usize> {
    receipt
        .actual
        .matches
        .checked_mul(route.participating_captures_per_match)
}

fn capture_events_for_actual(
    route: &CaptureCountRouteIdentity,
    receipt: &CaptureCountAttemptReceipt,
) -> Option<usize> {
    receipt
        .actual
        .matches
        .checked_mul(route.capture_schema_entries_per_match)
}

fn selector_fits_limits(
    prospective: &SelectorOperationProspective,
    limits: SelectorOperationLimits,
) -> bool {
    prospective.boundaries <= limits.max_boundaries
        && prospective.table_cells <= limits.max_table_cells
        && prospective.random_access_bytes <= limits.max_random_access_bytes
        && prospective.scratch_bytes <= limits.max_scratch_bytes
        && prospective.log_bytes <= limits.max_log_bytes
        && prospective.sequential_bytes <= limits.max_sequential_bytes
        && prospective.match_events <= limits.max_match_events
        && prospective.output_matches <= limits.max_output_matches
        && prospective.output_bytes <= limits.max_output_bytes
        && prospective.span_sum <= limits.max_span_sum
        && prospective.peak_bytes <= limits.max_peak_bytes
        && prospective.work_bound <= limits.max_work
}

fn retained_selector_control_fits_limits(
    prospective: &SelectorOperationProspective,
    limits: SelectorOperationLimits,
) -> bool {
    prospective.boundaries <= limits.max_boundaries
        && prospective.table_cells <= limits.max_table_cells
        && prospective.random_access_bytes <= limits.max_random_access_bytes
        && prospective.scratch_bytes <= limits.max_scratch_bytes
        && prospective.log_bytes <= limits.max_log_bytes
        && prospective.sequential_bytes <= limits.max_sequential_bytes
        && prospective.match_events <= limits.max_match_events
        && prospective.output_matches <= limits.max_output_matches
        && prospective.output_bytes <= limits.max_output_bytes
        && prospective.span_sum <= limits.max_span_sum
        && prospective.peak_bytes <= limits.max_peak_bytes
}

fn direct_fits_limits(
    prospective: &DirectOperationProspective,
    limits: DirectOperationLimits,
) -> bool {
    prospective.work <= limits.max_work
        && prospective.first_finder_bytes <= limits.max_first_finder_bytes
        && prospective.second_finder_bytes <= limits.max_second_finder_bytes
        && prospective.prefix_candidates <= limits.max_prefix_candidates
        && prospective.start_arbitrations <= limits.max_start_arbitrations
        && prospective.first_class_probes <= limits.max_first_class_probes
        && prospective.greedy_extension_reads <= limits.max_greedy_extension_reads
        && prospective.results <= limits.max_results
        && prospective.capture_count <= limits.max_capture_count
        && prospective.capture_events <= limits.max_capture_events
        && prospective.operation_allocations <= limits.max_operation_allocations
        && prospective.operation_bytes <= limits.max_operation_bytes
        && prospective.scratch_bytes <= limits.max_scratch_bytes
        && prospective.peak_bytes <= limits.max_peak_bytes
}
