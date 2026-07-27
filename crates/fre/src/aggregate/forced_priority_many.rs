//! Explicit, forced ordered Build-Many bridge for the priority substrate.
//!
//! This module is deliberately additive. It does not participate in
//! `AggregateManyBuilder` selection: planner work remains disabled until the
//! forced route has its own semantic and resource qualification. Every input
//! pattern is parsed and lowered independently, then projected into one
//! bounded owner-tagged quotient. The quotient shares structurally identical
//! continuation states without erasing source ordinals or edge priority.

#![allow(
    clippy::result_large_err,
    reason = "typed construction failures retain the exact failed stage without an unaccounted heap envelope"
)]

use core::{fmt, mem::size_of};
use std::{alloc::Layout, sync::Arc};

use fre_capture_lab::{
    CaptureStreamAccounting, CaptureStreamError, CaptureStreamLimits, CaptureStreamResource,
    SearchLimits as CaptureSearchLimits, Span as CaptureSpan,
};

use fre_automata::{
    ActionCapabilities, CompileError, CompileLimits, DirectCount, DirectReduceLimits,
    DirectReduceReport, DirectSpanSum, EdgeKind, EmptyMatchProgress, ExecutionActual,
    ExecutionProspective, ForcedExecution, MatchLengthProof, PreparationAccounting,
    PreparationError, PreparationLimits, PreparationProspective, PreparationResource,
    PriorityMatch, PriorityTarget, RawPlan, ReduceError, StateRole, TAGGED_MANY_ACCOUNTING_ID,
    TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS, TaggedManyBuildAccounting, TaggedManyBuildError,
    TaggedManyBuildLimits, TaggedManyExecutionClass, TaggedManyPlan, TaggedManyStats,
    TaggedManyTraceSession, TaggedManyTraceSessionSetupProspective,
};
use fre_lower::{
    CheckedWidth, FactError, FactLimits, FactOperation, FactOutput, FactStats, LowerError,
    LowerLimits, LowerStats, OperationSemantics, analyze_facts, lower_raw,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseAttemptError, ParseAttemptReceipt, ParseAttemptTerminal, ParseRequest, ParseSummary,
    RustConstructor, RustMatchKind, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::Hir;

use crate::capture_required_literal::{
    self, CaptureRequiredLiteralBuildError, CaptureRequiredLiteralBuildLimits,
    CaptureRequiredLiteralBuildReport, CaptureRequiredLiteralCacheIdentity,
    CaptureRequiredLiteralPlan, CaptureRequiredLiteralRunLimits, CaptureRequiredLiteralSearchError,
    CaptureRequiredLiteralSearchOperation, CaptureRequiredLiteralSearchReport,
};
use crate::captures::{
    CaptureBuildError, CaptureBuildLimits, CaptureBuildReport, CaptureBuilder,
    CaptureExactProjectionSession, CaptureRegex, ExactCaptureParticipation,
};

/// Schema for the forced ordered Build-Many receipt.
pub const PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION: u32 = 3;
/// Stable accounting identity for this forced-only bridge.
pub const PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID: &str = "fre.priority-aggregate-many.facade.v3";

// Three source/report vectors are admitted before the first bridge-owned
// allocation. The tagged substrate separately seals every construction
// allocation; lowering owns each per-pattern raw-plan allocation.
const FACADE_ALLOCATION_ATTEMPTS: usize = 3;
const WHOLE_LITERAL_IDENTITY_HEX: &[u8; 16] = b"0123456789abcdef";
// The ordered-union proof holds one exact root table and one `Arc<CacheKey>`
// after first moving the encoded identity source into that key. Every
// nonempty ordinal additionally makes one exact temporary parser-source
// copy. Parser internals and the nested literal builder are intentionally
// sealed by their own receipts rather than double-counted here.
const WHOLE_LITERAL_FIXED_DIRECT_BRIDGE_ALLOCATIONS: usize = 3;
const WHOLE_LITERAL_MAX_DIRECT_BRIDGE_ALLOCATIONS: usize =
    WHOLE_LITERAL_FIXED_DIRECT_BRIDGE_ALLOCATIONS + 128;
/// Whole-operation value fixed before parsing any pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorityAggregateManyOperation {
    /// Count selected non-overlapping whole matches.
    Count,
    /// Sum selected non-overlapping whole-match byte lengths.
    SpanSum,
}

impl PriorityAggregateManyOperation {
    const fn fact_operation(self) -> FactOperation {
        FactOperation::new(match self {
            Self::Count => FactOutput::Count,
            Self::SpanSum => FactOutput::SpanSum,
        })
    }
}

/// Complete checked construction limits for the forced bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    /// Per-pattern bounds for the allocation-backed parse-attempt owner.
    pub source_owner: PriorityAggregateManySourceOwnerLimits,
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    /// Exact source-identity copies made while building independently owned
    /// parse requests from the borrowed input slice.
    pub max_source_identity_allocation_attempts: usize,
    pub max_parser_work: u64,
    pub max_lowered_states: usize,
    pub max_lowered_edges: usize,
    pub max_composition_work: u64,
    /// Peak temporary ownership: retained lowered source plans plus the
    /// composed raw tables and action sidecar while they are simultaneously
    /// live.
    pub max_composition_scratch_bytes: usize,
    pub max_composition_allocation_attempts: usize,
    pub max_persistent_bytes: usize,
    pub facts: FactLimits,
    pub lowering: LowerLimits,
    pub composition_automata: CompileLimits,
    /// Exact owner-tagged quotient construction limits.
    pub tagged: TaggedManyBuildLimits,
    /// Retained for source compatibility. These bounds are intersected with
    /// the corresponding tagged construction dimensions; no legacy prepared
    /// sparse plan is constructed.
    pub preparation: PreparationLimits,
    /// Capture-sidecar and one whole-operation literal-proof construction
    /// envelope. This is consulted only by [`Self::build_capture_count`]; the
    /// ordinary Count and `SpanSum` artifacts retain their established receipt.
    pub capture_build: PriorityAggregateManyCaptureBuildLimits,
}

impl Default for PriorityAggregateManyBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            source_owner: PriorityAggregateManySourceOwnerLimits::default(),
            max_patterns: 4_096,
            max_pattern_bytes: 4 * 1_048_576,
            max_source_identity_allocation_attempts: 4_096,
            max_parser_work: 32 * 1_048_576,
            max_lowered_states: 1_048_576,
            max_lowered_edges: 4_194_304,
            max_composition_work: 4_000_000_000,
            max_composition_scratch_bytes: 256 * 1_048_576,
            max_composition_allocation_attempts: 19,
            max_persistent_bytes: 256 * 1_048_576,
            facts: FactLimits::default(),
            lowering: LowerLimits::default(),
            composition_automata: CompileLimits::default(),
            tagged: TaggedManyBuildLimits::default(),
            preparation: PreparationLimits::default(),
            capture_build: PriorityAggregateManyCaptureBuildLimits::default(),
        }
    }
}

/// Checked pre-source construction envelope for the forced multi-pattern
/// capture-count artifact.
///
/// Sidecars inherit the enclosing builder's admission policy and syntax
/// safety envelope. Their `required_literal` option is deliberately ignored:
/// the sole permitted literal proof is the separately bounded, ordered-union
/// pass in [`Self::whole_required_literal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureBuildLimits {
    /// Per-ordinal capture compiler limits, except syntax policy/safety and
    /// per-sidecar literal filtering as documented above.
    pub sidecar: CaptureBuildLimits,
    /// Limits for the one ordered-union required-literal proof.
    pub whole_required_literal: CaptureRequiredLiteralBuildLimits,
    /// Aggregate retained sidecar-envelope bytes admitted before any capture
    /// sidecar is allocated.
    pub max_sidecar_persistent_bytes: usize,
    /// Aggregate sidecar compiler-work envelope admitted before construction.
    pub max_sidecar_build_work: usize,
    /// Aggregate sidecar peak-envelope bytes admitted before construction.
    pub max_sidecar_peak_bytes: usize,
    /// Maximum capture-sidecar table allocations performed by this facade.
    /// Individual nested compilers retain and check their own allocation
    /// ledgers; this dimension covers the bridge-owned ordinal table.
    pub max_sidecar_table_allocations: usize,
    /// Aggregate parser work for the identity plus independently parsed
    /// ordered-union literal proof.
    pub max_whole_literal_parser_work: u64,
    /// Retained union-identity plus nested literal-plan payload admitted
    /// before any sidecar is constructed.
    pub max_whole_literal_persistent_bytes: usize,
    /// Conservative union-HIR bridge plus nested literal-plan construction
    /// peak admitted before any sidecar is constructed.
    pub max_whole_literal_peak_bytes: usize,
    /// Exact wrapper-owned allocations outside the syntax parser and nested
    /// literal builder: encoded identity source, identity `Arc<CacheKey>`,
    /// exact root-HIR table, and one exact source copy for each nonempty
    /// ordinal. The parser and nested literal builder authenticate their
    /// separate allocations in their own published receipts.
    pub max_whole_literal_bridge_allocations: usize,
}

impl Default for PriorityAggregateManyCaptureBuildLimits {
    fn default() -> Self {
        Self {
            sidecar: CaptureBuildLimits::default(),
            whole_required_literal: CaptureRequiredLiteralBuildLimits::default(),
            // These are construction ceilings, not eager reservations. They
            // leave room for the 16+ pattern qualified tail while preventing
            // an unbounded aggregate envelope.
            max_sidecar_persistent_bytes: 16 * 1_024 * 1_024 * 1_024,
            max_sidecar_build_work: 16 * 1_024 * 1_024 * 1_024,
            max_sidecar_peak_bytes: 16 * 1_024 * 1_024 * 1_024,
            max_sidecar_table_allocations: 1,
            max_whole_literal_parser_work: 128 * 1_024 * 1_024,
            max_whole_literal_persistent_bytes: 64 * 1_024 * 1_024,
            // The HIR bridge is admitted from the parser's hard node
            // envelope and the outer pattern ceiling; this is a checked
            // logical peak, not an eager allocation.
            max_whole_literal_peak_bytes: 128 * 1_024 * 1_024 * 1_024,
            max_whole_literal_bridge_allocations: WHOLE_LITERAL_MAX_DIRECT_BRIDGE_ALLOCATIONS,
        }
    }
}

/// One independently bounded construction resource owned by the forced
/// multi-pattern capture artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorityAggregateManyCaptureBuildResource {
    SidecarPersistentBytes,
    SidecarBuildWork,
    SidecarPeakBytes,
    SidecarTableAllocations,
    WholeLiteralParserWork,
    WholeLiteralPersistentBytes,
    WholeLiteralPeakBytes,
    WholeLiteralBridgeAllocations,
}

/// Authenticated aggregate construction ledger for capture sidecars and the
/// one optional ordered-union literal proof. Retained table/source bytes are
/// exact; peak fields are deliberately named conservative envelopes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureConstructionAccounting {
    /// One capture sidecar is retained for every ordered selector terminal.
    pub patterns: usize,
    /// Sum of the retained engine/selector/direct-plan payloads reported by
    /// all sidecars.
    pub sidecar_persistent_bytes: usize,
    /// Sum of the HIR, capture-engine, selector, and direct-plan construction
    /// work reported by all sidecars.
    pub sidecar_build_work: usize,
    /// Sum of independently reported sidecar construction peaks. This is an
    /// envelope, not a claim that every sidecar peak is simultaneously live.
    pub sidecar_peak_bytes: usize,
    /// Bridge-owned exact-capacity sidecar-table allocations.
    pub sidecar_table_allocations: usize,
    /// Parse work spent making the ordered-union literal identity and HIR.
    pub whole_literal_parser_work: u64,
    /// Required-literal planner work; zero means no universal literal proof
    /// was available for the ordered union.
    pub whole_literal_planner_work: usize,
    /// Retained identity plus the nested literal plan's authenticated
    /// published source envelope. This is zero only before the sole
    /// whole-operation proof has been constructed.
    pub whole_literal_persistent_bytes: usize,
    /// Conservative peak covering the identity, the bounded HIR bridge, and
    /// the nested literal builder's own authenticated peak envelope.
    pub whole_literal_peak_bytes: usize,
    /// Exact wrapper-owned allocation attempts outside the syntax parser and
    /// nested literal builder: encoded identity source, its `Arc<CacheKey>`,
    /// exact root-HIR table, and one exact source copy for each nonempty
    /// ordinal. Nested parser/literal-builder allocations remain sealed in
    /// their respective receipts.
    pub whole_literal_bridge_allocations: usize,
}

impl PriorityAggregateManyCaptureConstructionAccounting {
    fn closes(self, limits: &PriorityAggregateManyCaptureBuildLimits) -> bool {
        self.sidecar_persistent_bytes <= limits.max_sidecar_persistent_bytes
            && self.sidecar_build_work <= limits.max_sidecar_build_work
            && self.sidecar_peak_bytes <= limits.max_sidecar_peak_bytes
            && self.sidecar_table_allocations <= limits.max_sidecar_table_allocations
            && self.whole_literal_parser_work <= limits.max_whole_literal_parser_work
            && self.whole_literal_persistent_bytes <= limits.max_whole_literal_persistent_bytes
            && self.whole_literal_peak_bytes <= limits.max_whole_literal_peak_bytes
            && self.whole_literal_bridge_allocations <= limits.max_whole_literal_bridge_allocations
    }
}

/// Authenticated disposition of the sole whole-operation literal proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PriorityAggregateManyWholeRequiredLiteralBuildReceipt {
    /// A bounded universal-literal proof was retained and can gate the shared
    /// selector exactly once per operation.
    Built {
        report: CaptureRequiredLiteralBuildReport,
        parser_work: u64,
    },
    /// The bounded analysis completed but the ordered union has no universal
    /// literal suitable for a sound filter. The selector remains mandatory.
    NoProof {
        parser_work: u64,
        planner_work: usize,
    },
}

impl PriorityAggregateManyWholeRequiredLiteralBuildReceipt {
    #[must_use]
    pub const fn parser_work(&self) -> u64 {
        match self {
            Self::Built { parser_work, .. } | Self::NoProof { parser_work, .. } => *parser_work,
        }
    }

    #[must_use]
    pub const fn planner_work(&self) -> usize {
        match self {
            Self::Built { report, .. } => report.accounting.planner_work,
            Self::NoProof { planner_work, .. } => *planner_work,
        }
    }

    fn closes(
        &self,
        plan: Option<&CaptureRequiredLiteralPlan>,
        identity: &Arc<CacheKey>,
        selector: &PriorityAggregateManyBuildReport,
    ) -> bool {
        let identity_closes = whole_required_literal_identity_closes(identity, selector);
        match (self, plan) {
            (Self::Built { report, .. }, Some(plan)) => {
                plan.build_report() == report
                    && Arc::ptr_eq(&report.identity.syntax, identity)
                    && capture_required_literal_build_report_closes(
                        report,
                        selector.limits.capture_build.whole_required_literal,
                    )
                    && identity_closes
            }
            (Self::NoProof { planner_work, .. }, None) => {
                *planner_work
                    <= selector
                        .limits
                        .capture_build
                        .whole_required_literal
                        .max_planner_work
                    && identity_closes
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
struct WholeRequiredLiteralBuild {
    plan: Option<CaptureRequiredLiteralPlan>,
    identity: Arc<CacheKey>,
    receipt: PriorityAggregateManyWholeRequiredLiteralBuildReceipt,
    persistent_bytes: usize,
    peak_bytes: usize,
    bridge_allocations: usize,
}

/// Bounds checked before binding each retained parse-attempt source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManySourceOwnerLimits {
    pub max_allocation_bytes: usize,
    pub max_handle_bytes: usize,
    pub max_allocation_attempts: usize,
}

impl Default for PriorityAggregateManySourceOwnerLimits {
    fn default() -> Self {
        Self {
            max_allocation_bytes: ParseRequest::attempt_source_owner_allocation_bytes(),
            max_handle_bytes: ParseRequest::attempt_source_owner_handle_bytes().saturating_mul(2),
            max_allocation_attempts: 1,
        }
    }
}

/// Exact stable-owner allocation and inline-handle accounting for one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManySourceOwnerAccounting {
    allocation_bytes: usize,
    handle_bytes: usize,
    allocation_attempts: usize,
}

/// Stable source-owner dimension admitted before its allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateManySourceOwnerResource {
    AllocationBytes,
    HandleBytes,
    AllocationAttempts,
}

impl PriorityAggregateManySourceOwnerAccounting {
    #[must_use]
    pub const fn allocation_bytes(self) -> usize {
        self.allocation_bytes
    }

    #[must_use]
    pub const fn handle_bytes(self) -> usize {
        self.handle_bytes
    }

    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    fn closes_against(self, limits: PriorityAggregateManySourceOwnerLimits) -> bool {
        self.allocation_bytes == ParseRequest::attempt_source_owner_allocation_bytes()
            && ParseRequest::attempt_source_owner_handle_bytes().checked_mul(2)
                == Some(self.handle_bytes)
            && self.allocation_attempts == 1
            && self.allocation_bytes <= limits.max_allocation_bytes
            && self.handle_bytes <= limits.max_handle_bytes
            && self.allocation_attempts <= limits.max_allocation_attempts
    }
}

/// Exact syntax and lowering evidence retained for one source pattern.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyPatternReport {
    pub ordinal: usize,
    pub syntax_key: CacheKey,
    pub admission: AdmissionStatus,
    pub syntax: ParseSummary,
    pub syntax_receipt: ParseAttemptReceipt,
    pub source_owner: PriorityAggregateManySourceOwnerAccounting,
    pub width: CheckedWidth,
    pub facts: FactStats,
    pub lowering: LowerStats,
    pub raw_capacity_bytes: usize,
}

/// Exact bridge-owned composition accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCompositionAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub parser_work: u64,
    pub parser_work_reservation: u64,
    pub fact_work: u64,
    pub lowering_work: u64,
    pub source_states: usize,
    pub source_edges: usize,
    /// Shared quotient states (legacy field name retained for callers).
    pub composed_states: usize,
    /// Shared quotient edge shards (legacy field name retained for callers).
    pub composed_edges: usize,
    /// Exact tagged construction work consumed.
    pub composition_work: u64,
    pub source_raw_capacity_bytes: usize,
    /// Exact immutable tagged-plan payload bytes.
    pub composed_raw_capacity_bytes: usize,
    /// The tagged representation has no per-state action sidecar.
    pub action_capacity_bytes: usize,
    pub metadata_persistent_bytes: usize,
    /// Conservative aggregate peak admitted before any source parser or
    /// lowerer is invoked.
    pub preflight_scratch_bytes: usize,
    /// Conservative aggregate retained ownership admitted before any source
    /// parser or lowerer is invoked.
    pub preflight_persistent_bytes: usize,
    /// Conservative bridge plus one-time receipt-authentication work admitted
    /// before any source parser or lowerer is invoked.
    pub preflight_composition_work: u64,
    pub source_owner_allocation_bytes: usize,
    pub source_owner_handle_bytes: usize,
    pub source_owner_allocation_attempts: usize,
    pub source_identity_allocation_attempts: usize,
    pub scratch_bytes: usize,
    pub allocation_attempts: usize,
    /// Exact immutable quotient dimensions.
    pub tagged_stats: TaggedManyStats,
    /// Exact construction ledger closed by the tagged substrate.
    pub tagged_build: TaggedManyBuildAccounting,
}

/// Immutable forced Build-Many construction receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyBuildReport {
    schema_version: u32,
    accounting_id: &'static str,
    operation: PriorityAggregateManyOperation,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PriorityAggregateManyBuildLimits,
    profile: RustProfile,
    patterns: Vec<PriorityAggregateManyPatternReport>,
    composition: PriorityAggregateManyCompositionAccounting,
    automaton: TaggedManyStats,
    declared_match_length: MatchLengthProof,
    empty_progress: EmptyMatchProgress,
    preparation: PreparationAccounting,
    tagged_limits: TaggedManyBuildLimits,
    tagged_build: TaggedManyBuildAccounting,
    retained_capacity_bytes: usize,
    validated: bool,
}

impl PriorityAggregateManyBuildReport {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn accounting_id(&self) -> &'static str {
        self.accounting_id
    }

    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateManyOperation {
        self.operation
    }

    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        self.execution
    }

    #[must_use]
    pub const fn target(&self) -> PriorityTarget {
        self.target
    }

    #[must_use]
    pub const fn limits(&self) -> PriorityAggregateManyBuildLimits {
        self.limits
    }

    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    #[must_use]
    pub fn patterns(&self) -> &[PriorityAggregateManyPatternReport] {
        &self.patterns
    }

    #[must_use]
    pub const fn composition(&self) -> PriorityAggregateManyCompositionAccounting {
        self.composition
    }

    #[must_use]
    pub const fn automaton(&self) -> TaggedManyStats {
        self.automaton
    }

    #[must_use]
    pub const fn tagged_limits(&self) -> TaggedManyBuildLimits {
        self.tagged_limits
    }

    #[must_use]
    pub const fn tagged_build(&self) -> TaggedManyBuildAccounting {
        self.tagged_build
    }

    #[must_use]
    pub const fn declared_match_length(&self) -> MatchLengthProof {
        self.declared_match_length
    }

    #[must_use]
    pub const fn empty_progress(&self) -> EmptyMatchProgress {
        self.empty_progress
    }

    #[must_use]
    pub const fn preparation(&self) -> PreparationAccounting {
        self.preparation
    }

    #[must_use]
    pub const fn retained_capacity_bytes(&self) -> usize {
        self.retained_capacity_bytes
    }

    /// Verify the independently meaningful receipt boundaries without
    /// reconstructing or reselecting a plan.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the immutable receipt closes every independently admitted parser, lowering, tagged graph, and resource dimension"
    )]
    pub fn closes(&self) -> bool {
        let required = build_many_action_capabilities();
        let pattern_order = self
            .patterns
            .iter()
            .enumerate()
            .all(|(ordinal, report)| report.ordinal == ordinal);
        let expected_profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let profile_identity = self
            .patterns
            .iter()
            .all(|report| report.syntax_key.profile == expected_profile);
        let syntax_receipts_close = self
            .patterns
            .iter()
            .all(|report| pattern_syntax_closes(report, self.limits.source_owner));
        let component_limits = self.patterns.iter().all(|report| {
            report.facts.work() <= self.limits.facts.max_work
                && report.facts.peak_stack_items() <= self.limits.facts.max_stack_items
                && report.facts.hir_nodes() <= self.limits.facts.max_hir_nodes
                && report.facts.peak_bytes() <= self.limits.facts.max_peak_bytes
                && report.facts.allocation_attempts() <= self.limits.facts.max_allocation_attempts
                && report.lowering.work() <= self.limits.lowering.max_work
                && report.lowering.peak_stack_items() <= self.limits.lowering.max_stack_items
                && report.lowering.states() <= self.limits.lowering.automata.max_states
                && report.lowering.edges() <= self.limits.lowering.automata.max_edges
                && report.lowering.normalized_nullable_repetitions() == 0
                && raw_plan_bytes(report.lowering.states(), report.lowering.edges())
                    .is_ok_and(|exact| report.raw_capacity_bytes == exact)
        });
        let report_parser_work = self.patterns.iter().try_fold(0_u64, |total, report| {
            total.checked_add(report.syntax.parse_work)
        });
        let report_parser_reservation = self.patterns.iter().try_fold(0_u64, |total, report| {
            report
                .syntax_receipt
                .prospective
                .and_then(|prospective| {
                    prospective
                        .source_bytes
                        .checked_add(prospective.max_observed_work)
                })
                .and_then(|work| total.checked_add(work))
        });
        let report_fact_work = self.patterns.iter().try_fold(0_u64, |total, report| {
            total.checked_add(report.facts.work())
        });
        let report_lowering_work = self.patterns.iter().try_fold(0_u64, |total, report| {
            total.checked_add(report.lowering.work())
        });
        let report_states = self.patterns.iter().try_fold(0_usize, |total, report| {
            total.checked_add(report.lowering.states())
        });
        let report_edges = self.patterns.iter().try_fold(0_usize, |total, report| {
            total.checked_add(report.lowering.edges())
        });
        let report_pattern_bytes = self.patterns.iter().try_fold(0_usize, |total, report| {
            total.checked_add(report.syntax_key.pattern.as_bytes().len())
        });
        let report_raw_capacity_bytes = self.patterns.iter().try_fold(0_usize, |total, report| {
            total.checked_add(report.raw_capacity_bytes)
        });
        let report_source_owner_allocation_bytes =
            self.patterns.iter().try_fold(0_usize, |total, report| {
                total.checked_add(report.source_owner.allocation_bytes())
            });
        let report_source_owner_handle_bytes =
            self.patterns.iter().try_fold(0_usize, |total, report| {
                total.checked_add(report.source_owner.handle_bytes())
            });
        let report_source_owner_allocation_attempts =
            self.patterns.iter().try_fold(0_usize, |total, report| {
                total.checked_add(report.source_owner.allocation_attempts())
            });
        let source_identity_allocation_attempts = self
            .patterns
            .iter()
            .filter(|report| !report.syntax_key.pattern.as_bytes().is_empty())
            .count();
        let syntax_identity_bytes = self.patterns.iter().try_fold(0_usize, |total, report| {
            total.checked_add(report.syntax_key.pattern.capacity_bytes())
        });
        let report_capacity_bytes = self
            .patterns
            .capacity()
            .checked_mul(size_of::<PriorityAggregateManyPatternReport>());
        let parts_capacity_bytes = self.patterns.len().checked_mul(size_of::<RawPlan>());
        let width_capacity_bytes = self.patterns.len().checked_mul(size_of::<CheckedWidth>());
        let expected_metadata = report_capacity_bytes
            .zip(syntax_identity_bytes)
            .zip(report_source_owner_allocation_bytes)
            .and_then(|((reports, syntax), owners)| {
                reports
                    .checked_add(syntax)
                    .and_then(|bytes| bytes.checked_add(owners))
            });
        let expected_tagged_limits = expected_metadata
            .and_then(|metadata| effective_tagged_limits(&self.limits, metadata).ok());
        let expected_preflight = parts_capacity_bytes
            .zip(width_capacity_bytes)
            .zip(expected_metadata)
            .and_then(|((parts, widths), metadata)| {
                aggregate_capacity_preflight(
                    self.patterns.len(),
                    &self.limits,
                    self.limits.tagged,
                    parts,
                    widths,
                    metadata,
                )
                .ok()
            });
        let expected_source_peak = parts_capacity_bytes
            .zip(width_capacity_bytes)
            .zip(report_raw_capacity_bytes)
            .zip(expected_metadata)
            .and_then(|(((parts, widths), raw), metadata)| {
                parts
                    .checked_add(widths)
                    .and_then(|bytes| bytes.checked_add(raw))
                    .and_then(|bytes| bytes.checked_add(metadata))
            });
        let expected_tagged_peak = expected_metadata
            .and_then(|metadata| metadata.checked_add(self.tagged_build.peak_bytes));
        let expected_scratch = expected_source_peak
            .zip(expected_tagged_peak)
            .map(|(source, tagged)| source.max(tagged));
        let expected_retained = expected_metadata
            .and_then(|metadata| metadata.checked_add(self.tagged_build.persistent_bytes));
        let expected_allocations = self
            .tagged_build
            .allocation_attempts
            .checked_add(FACADE_ALLOCATION_ATTEMPTS);
        let expected_preparation =
            tagged_preparation_compatibility(self.automaton, self.tagged_build).ok();
        let stats_close = self.automaton == self.composition.tagged_stats
            && self.automaton.patterns() == self.patterns.len()
            && self.automaton.source_states() == self.composition.source_states
            && self.automaton.source_edges() == self.composition.source_edges
            && self.automaton.states() == self.composition.composed_states
            && self.automaton.edges() == self.composition.composed_edges
            && self.automaton.owner_state_memberships() == self.composition.source_states
            && self.automaton.owner_edge_memberships() == self.composition.source_edges
            && self
                .automaton
                .zero_width_edges()
                .checked_add(self.automaton.consuming_edges())
                == Some(self.automaton.edges())
            && self.automaton.persistent_bytes() == self.tagged_build.persistent_bytes;
        let tagged_close = self.tagged_build == self.composition.tagged_build
            && self.tagged_build.accounting_id == TAGGED_MANY_ACCOUNTING_ID
            && self.tagged_build.closes(self.tagged_limits)
            && tagged_classification_closes(self.automaton, self.tagged_build)
            && self.tagged_build.actual_work == self.composition.composition_work
            && self.tagged_build.persistent_bytes == self.composition.composed_raw_capacity_bytes
            && self.composition.action_capacity_bytes == 0
            && self.tagged_build.actual_work <= self.tagged_build.prospective_work
            && self.tagged_build.prospective_work <= self.composition.preflight_composition_work;
        self.schema_version == PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION
            && self.accounting_id == PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID
            && self.execution == ForcedExecution::Sparse
            && self.target.sparse
            && self.target.actions.contains(required)
            && self.empty_progress == EmptyMatchProgress::Byte
            && self.composition.patterns == self.patterns.len()
            && self.patterns.capacity() == self.patterns.len()
            && !self.patterns.is_empty()
            && self.patterns.len() <= 128
            && pattern_order
            && profile_identity
            && syntax_receipts_close
            && component_limits
            && report_parser_work == Some(self.composition.parser_work)
            && report_parser_reservation == Some(self.composition.parser_work_reservation)
            && self.composition.parser_work <= self.composition.parser_work_reservation
            && report_fact_work == Some(self.composition.fact_work)
            && report_lowering_work == Some(self.composition.lowering_work)
            && report_states == Some(self.composition.source_states)
            && report_edges == Some(self.composition.source_edges)
            && report_pattern_bytes == Some(self.composition.pattern_bytes)
            && report_raw_capacity_bytes == Some(self.composition.source_raw_capacity_bytes)
            && report_source_owner_allocation_bytes
                == Some(self.composition.source_owner_allocation_bytes)
            && report_source_owner_handle_bytes == Some(self.composition.source_owner_handle_bytes)
            && report_source_owner_allocation_attempts
                == Some(self.composition.source_owner_allocation_attempts)
            && source_identity_allocation_attempts
                == self.composition.source_identity_allocation_attempts
            && combine_widths(self.patterns.iter().map(|report| report.width))
                == self.declared_match_length
            && expected_metadata == Some(self.composition.metadata_persistent_bytes)
            && expected_tagged_limits == Some(self.tagged_limits)
            && expected_preflight.is_some_and(|preflight| {
                preflight.scratch_bytes == self.composition.preflight_scratch_bytes
                    && preflight.persistent_bytes == self.composition.preflight_persistent_bytes
                    && preflight.composition_work == self.composition.preflight_composition_work
            })
            && expected_scratch == Some(self.composition.scratch_bytes)
            && expected_retained == Some(self.retained_capacity_bytes)
            && expected_allocations == Some(self.composition.allocation_attempts)
            && expected_preparation == Some(self.preparation)
            && tagged_preparation_closes_against(self.preparation, self.limits.preparation)
            && self.retained_capacity_bytes <= self.limits.max_persistent_bytes
            && self.composition.scratch_bytes <= self.limits.max_composition_scratch_bytes
            && self.composition.allocation_attempts
                <= self.limits.max_composition_allocation_attempts
            && self.composition.pattern_bytes <= self.limits.max_pattern_bytes
            && self.composition.parser_work_reservation <= self.limits.max_parser_work
            && self.composition.source_states <= self.limits.max_lowered_states
            && self.composition.source_edges <= self.limits.max_lowered_edges
            && stats_close
            && tagged_close
    }
}

/// Exact build failure; no executable route is returned on any error.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "receipt-bearing parse failures retain their exact request and terminal receipt without an unaccounted heap envelope"
)]
#[non_exhaustive]
pub enum PriorityAggregateManyBuildError {
    EmptyPatternSet,
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    ParserWorkLimit {
        needed: u64,
        limit: u64,
    },
    LoweredStatesLimit {
        needed: usize,
        limit: usize,
    },
    LoweredEdgesLimit {
        needed: usize,
        limit: usize,
    },
    CompositionWorkLimit {
        needed: u64,
        limit: u64,
    },
    CompositionScratchLimit {
        needed: usize,
        limit: usize,
    },
    CompositionAllocationAttemptsLimit {
        needed: usize,
        limit: usize,
    },
    PreparationSubsetItemsLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    SourceIdentityAllocationAttemptsLimit {
        needed: usize,
        limit: usize,
    },
    SourceIdentityCapacityMismatch {
        pattern: usize,
        expected: usize,
        actual: usize,
    },
    SourceOwnerResourceLimit {
        resource: PriorityAggregateManySourceOwnerResource,
        needed: usize,
        limit: usize,
    },
    SourceOwnerAlreadyBound,
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    Syntax {
        pattern: usize,
        source: ParseAttemptError,
    },
    NonRustCanonicalPattern {
        pattern: usize,
    },
    UnsupportedBuildManyProfile,
    UnsupportedUnicodeProfile,
    UnsupportedBytesEmptyProgress,
    UnsupportedExecution {
        execution: ForcedExecution,
    },
    UnsupportedTarget,
    Facts {
        pattern: usize,
        source: FactError,
    },
    CaptureErasureNotProven {
        pattern: usize,
    },
    /// The capture-preserving sidecar for one ordinal could not be compiled.
    /// The shared tagged selector is never published without every source
    /// sidecar needed to preserve its selected captures.
    CaptureSidecar {
        pattern: usize,
        source: CaptureBuildError,
    },
    /// The aggregate sidecar/literal construction envelope was exhausted
    /// before publishing a capture artifact.
    CaptureConstructionLimit {
        resource: PriorityAggregateManyCaptureBuildResource,
        needed: usize,
        limit: usize,
    },
    WholeRequiredLiteralParserWorkLimit {
        needed: u64,
        limit: u64,
    },
    /// The whole-operation literal identity or one of its ordered source HIRs
    /// could not be parsed under the same policy/safety envelope as selector
    /// construction.
    WholeRequiredLiteralSyntax {
        pattern: Option<usize>,
        source: fre_syntax::ParseError,
    },
    /// The bounded whole-operation literal proof reached a terminal
    /// construction failure. A successful capture artifact never silently
    /// collapses this failure into an opaque missing filter.
    WholeRequiredLiteral {
        source: CaptureRequiredLiteralBuildError,
    },
    Lower {
        pattern: usize,
        source: LowerError,
    },
    NormalizedLoweringRequiresIntrinsicLength {
        pattern: usize,
        repetitions: usize,
    },
    CompositionArithmeticOverflow {
        computation: &'static str,
    },
    InvalidAcceptTerminalCount {
        pattern: usize,
        terminals: usize,
    },
    Automaton(CompileError),
    Preparation(PreparationError),
    Tagged(TaggedManyBuildError),
    InternalInvariant {
        detail: &'static str,
    },
    BuildReportNotClosed,
}

impl fmt::Display for PriorityAggregateManyBuildError {
    #[allow(
        clippy::too_many_lines,
        reason = "each typed construction failure retains a dedicated stable diagnostic"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => formatter.write_str("forced Build-Many requires a pattern"),
            Self::PatternLimit { needed, limit } => {
                write!(formatter, "forced Build-Many needs {needed} patterns, limit is {limit}")
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} pattern bytes, limit is {limit}"
            ),
            Self::ParserWorkLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} parser work, limit is {limit}"
            ),
            Self::LoweredStatesLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} lowered states, limit is {limit}"
            ),
            Self::LoweredEdgesLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} lowered edges, limit is {limit}"
            ),
            Self::CompositionWorkLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} composition work, limit is {limit}"
            ),
            Self::CompositionScratchLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} composition scratch bytes, limit is {limit}"
            ),
            Self::CompositionAllocationAttemptsLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} composition allocations, limit is {limit}"
            ),
            Self::PreparationSubsetItemsLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} tagged owner memberships, preparation limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many retains {needed} bytes, limit is {limit}"
            ),
            Self::SourceIdentityAllocationAttemptsLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many needs {needed} source-identity allocations, limit is {limit}"
            ),
            Self::SourceIdentityCapacityMismatch {
                pattern,
                expected,
                actual,
            } => write!(
                formatter,
                "forced Build-Many pattern {pattern} source identity reserved {actual} bytes, expected {expected}"
            ),
            Self::SourceOwnerResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "forced Build-Many source owner needs {needed} {resource:?}, limit is {limit}"
            ),
            Self::SourceOwnerAlreadyBound => {
                formatter.write_str("forced Build-Many source owner was already bound")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "forced Build-Many could not reserve {additional} entries for {structure}"
            ),
            Self::Syntax { pattern, source } => {
                write!(formatter, "forced Build-Many pattern {pattern} syntax: {source}")
            }
            Self::NonRustCanonicalPattern { pattern } => write!(
                formatter,
                "forced Build-Many pattern {pattern} did not produce Rust HIR"
            ),
            Self::UnsupportedBuildManyProfile => formatter.write_str(
                "forced Build-Many requires Rebar's ordered Rust meta-regex profile",
            ),
            Self::UnsupportedUnicodeProfile => formatter.write_str(
                "forced Build-Many raw priority composition refuses Unicode profile until valid-UTF-8 input admission is bound",
            ),
            Self::UnsupportedBytesEmptyProgress => formatter.write_str(
                "forced Build-Many requires byte-progress empty-match semantics",
            ),
            Self::UnsupportedExecution { execution } => write!(
                formatter,
                "forced Build-Many currently supports sparse execution, not {execution:?}"
            ),
            Self::UnsupportedTarget => formatter.write_str(
                "forced Build-Many target lacks sparse ordinal-reduction capability",
            ),
            Self::Facts { pattern, source } => write!(
                formatter,
                "forced Build-Many pattern {pattern} facts: {source}"
            ),
            Self::CaptureErasureNotProven { pattern } => write!(
                formatter,
                "forced Build-Many pattern {pattern} lacks capture-erasure proof"
            ),
            Self::CaptureSidecar { pattern, source } => write!(
                formatter,
                "forced Build-Many pattern {pattern} capture sidecar: {source}"
            ),
            Self::CaptureConstructionLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "forced Build-Many capture construction {resource:?} needs {needed}, limit is {limit}"
            ),
            Self::WholeRequiredLiteralParserWorkLimit { needed, limit } => write!(
                formatter,
                "forced Build-Many whole required-literal parser work needs {needed}, limit is {limit}"
            ),
            Self::WholeRequiredLiteralSyntax { pattern, source } => match pattern {
                Some(pattern) => write!(
                    formatter,
                    "forced Build-Many whole required-literal pattern {pattern} syntax: {source}"
                ),
                None => write!(
                    formatter,
                    "forced Build-Many whole required-literal identity syntax: {source}"
                ),
            },
            Self::WholeRequiredLiteral { source } => {
                write!(formatter, "forced Build-Many whole required-literal: {source}")
            }
            Self::Lower { pattern, source } => write!(
                formatter,
                "forced Build-Many pattern {pattern} lowering: {source}"
            ),
            Self::NormalizedLoweringRequiresIntrinsicLength {
                pattern,
                repetitions,
            } => write!(
                formatter,
                "forced Build-Many pattern {pattern} normalized {repetitions} nullable repetitions"
            ),
            Self::CompositionArithmeticOverflow { computation } => write!(
                formatter,
                "forced Build-Many overflow computing {computation}"
            ),
            Self::InvalidAcceptTerminalCount { pattern, terminals } => write!(
                formatter,
                "forced Build-Many pattern {pattern} lowered to {terminals} accept terminals"
            ),
            Self::Automaton(source) => write!(formatter, "forced Build-Many automaton: {source}"),
            Self::Preparation(source) => write!(formatter, "forced Build-Many preparation: {source}"),
            Self::Tagged(source) => write!(formatter, "forced Build-Many tagged quotient: {source}"),
            Self::InternalInvariant { detail } => {
                write!(formatter, "forced Build-Many invariant failed: {detail}")
            }
            Self::BuildReportNotClosed => formatter.write_str("forced Build-Many receipt did not close"),
        }
    }
}

impl std::error::Error for PriorityAggregateManyBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax { source, .. } => Some(source),
            Self::Facts { source, .. } => Some(source),
            Self::CaptureSidecar { source, .. } => Some(source),
            Self::WholeRequiredLiteralSyntax { source, .. } => Some(source),
            Self::WholeRequiredLiteral { source } => Some(source),
            Self::Lower { source, .. } => Some(source),
            Self::Automaton(source) => Some(source),
            Self::Preparation(source) => Some(source),
            Self::Tagged(source) => Some(source),
            _ => None,
        }
    }
}

/// Builder for the forced-only shared priority Build-Many route.
#[derive(Clone, Debug)]
pub struct PriorityAggregateManyBuilder<'a> {
    patterns: &'a [String],
    profile: RustProfile,
    limits: PriorityAggregateManyBuildLimits,
}

impl<'a> PriorityAggregateManyBuilder<'a> {
    #[must_use]
    pub fn new(patterns: &'a [String]) -> Self {
        Self {
            patterns,
            profile: RustProfile::rebar_1_12_4(),
            limits: PriorityAggregateManyBuildLimits::default(),
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: PriorityAggregateManyBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Build exactly the requested sparse Count route.
    pub fn build_count(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<PriorityAggregateManyCountRegex, PriorityAggregateManyBuildError> {
        let common = self.build_common::<DirectCount>(
            PriorityAggregateManyOperation::Count,
            execution,
            target,
        )?;
        let (plan, mut report) = common.finish()?;
        if !report.closes() {
            return Err(PriorityAggregateManyBuildError::BuildReportNotClosed);
        }
        report.validated = true;
        Ok(PriorityAggregateManyCountRegex { plan, report })
    }

    /// Build exactly the requested sparse `SpanSum` route.
    pub fn build_span_sum(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<PriorityAggregateManySpanSumRegex, PriorityAggregateManyBuildError> {
        let common = self.build_common::<DirectSpanSum>(
            PriorityAggregateManyOperation::SpanSum,
            execution,
            target,
        )?;
        let (plan, mut report) = common.finish()?;
        if !report.closes() {
            return Err(PriorityAggregateManyBuildError::BuildReportNotClosed);
        }
        report.validated = true;
        Ok(PriorityAggregateManySpanSumRegex { plan, report })
    }

    /// Build one shared priority selector plus one capture-preserving sidecar
    /// for each source ordinal.
    ///
    /// The selector is still the sole whole-haystack matcher: sidecars only
    /// project spans already selected by that one ordered automaton. Each
    /// sidecar starts with the capture lab's no-required-literal default, so
    /// it cannot accidentally rescan a selected span with a second literal
    /// filter. A future whole-operation prefilter is therefore one explicit
    /// outer pass rather than an implicit per-pattern or per-replay pass.
    pub fn build_capture_count(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<PriorityAggregateManyCaptureCountRegex, PriorityAggregateManyBuildError> {
        let selector = self.clone().build_count(execution, target)?;
        let count = self.patterns.len();
        let sidecar_limits =
            capture_sidecar_limits(self.limits.capture_build.sidecar, &self.limits);
        preflight_whole_required_literal_parser(
            self.patterns,
            self.limits.capture_build.max_whole_literal_parser_work,
        )?;
        let mut accounting = capture_construction_preflight(
            self.patterns,
            selector.build_report(),
            &self.limits.capture_build,
        )?;
        let mut captures = reserve_exact::<CaptureRegex>(count, "capture sidecars")?;
        for (ordinal, pattern) in self.patterns.iter().enumerate() {
            let mut per_ordinal_sidecar_limits = sidecar_limits;
            per_ordinal_sidecar_limits.syntax_safety = selector
                .build_report()
                .patterns()
                .get(ordinal)
                .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "capture sidecar ordinal exceeded its shared selector receipt",
                })?
                .syntax_key
                .safety;
            let sidecar = CaptureBuilder::new(pattern.as_str())
                .profile(self.profile.clone())
                .limits(per_ordinal_sidecar_limits)
                .build()
                .map_err(|source| PriorityAggregateManyBuildError::CaptureSidecar {
                    pattern: ordinal,
                    source,
                })?;
            if sidecar
                .build_report()
                .plan_identity
                .syntax
                .pattern
                .capacity_bytes()
                != pattern.len()
            {
                return Err(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "capture sidecar syntax source did not retain the admitted exact capacity",
                });
            }
            accumulate_capture_sidecar_accounting(&mut accounting, sidecar.build_report())?;
            captures.push(sidecar);
        }
        if captures.len() != count || captures.capacity() != count {
            return Err(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "capture sidecar collection lost its exact source ordinal shape",
            });
        }
        // This optional proof is deliberately built over the alternation of
        // all independently parsed source HIRs. It is never run per ordinal
        // or per selected span: a negative whole-input decision is the only
        // route on which it suppresses the shared selector.
        let whole_required_literal = build_whole_operation_required_literal(
            self.patterns,
            &self.profile,
            self.limits.admission,
            self.limits.syntax_safety,
            self.limits.capture_build.whole_required_literal,
            self.limits.capture_build.max_whole_literal_parser_work,
        )?;
        accounting.whole_literal_parser_work = whole_required_literal.receipt.parser_work();
        accounting.whole_literal_planner_work = whole_required_literal.receipt.planner_work();
        accounting.whole_literal_persistent_bytes = whole_required_literal.persistent_bytes;
        accounting.whole_literal_peak_bytes = whole_required_literal.peak_bytes;
        accounting.whole_literal_bridge_allocations = whole_required_literal.bridge_allocations;
        enforce_capture_construction_limits(accounting, &self.limits.capture_build)?;
        let artifact = PriorityAggregateManyCaptureCountRegex {
            selector,
            captures: captures.into_boxed_slice(),
            whole_required_literal: whole_required_literal.plan,
            whole_required_literal_identity: whole_required_literal.identity,
            whole_required_literal_receipt: whole_required_literal.receipt,
            construction: accounting,
        };
        if !artifact.build_report().closes() {
            return Err(PriorityAggregateManyBuildError::BuildReportNotClosed);
        }
        Ok(artifact)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the construction transaction keeps all preflight, independent parsing, and composition gates adjacent"
    )]
    fn build_common<O: fre_automata::DirectReduceValue>(
        self,
        operation: PriorityAggregateManyOperation,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<CommonBuild<O>, PriorityAggregateManyBuildError> {
        validate_route(execution, target)?;
        if !is_ordered_build_many_profile(&self.profile) {
            return Err(PriorityAggregateManyBuildError::UnsupportedBuildManyProfile);
        }
        if !bytes_empty_progress_is_byte(&self.profile) {
            return Err(PriorityAggregateManyBuildError::UnsupportedBytesEmptyProgress);
        }
        let count = self.patterns.len();
        if count == 0 {
            return Err(PriorityAggregateManyBuildError::EmptyPatternSet);
        }
        let pattern_limit = self
            .limits
            .max_patterns
            .min(self.limits.tagged.max_patterns)
            .min(128);
        enforce_usize(count, pattern_limit, |needed, limit| {
            PriorityAggregateManyBuildError::PatternLimit { needed, limit }
        })?;
        if count > self.limits.preparation.max_pattern_terminals {
            return Err(PriorityAggregateManyBuildError::Preparation(
                PreparationError::ResourceLimit {
                    resource: PreparationResource::PatternTerminals,
                    needed: count,
                    limit: self.limits.preparation.max_pattern_terminals,
                },
            ));
        }
        if u32::try_from(count).is_err() {
            return Err(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "pattern ordinal index space",
                },
            );
        }
        let pattern_bytes = self.patterns.iter().try_fold(0usize, |total, pattern| {
            total.checked_add(pattern.len()).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "pattern byte sum",
                },
            )
        })?;
        enforce_usize(
            pattern_bytes,
            self.limits.max_pattern_bytes,
            |needed, limit| PriorityAggregateManyBuildError::PatternBytesLimit { needed, limit },
        )?;
        let source_bytes = u64::try_from(pattern_bytes).map_err(|_| {
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "aggregate source byte conversion",
            }
        })?;
        // Every parse spends at least its source length. Admit that aggregate
        // minimum before allocating the bridge vectors or entering any parser.
        enforce_u64(
            source_bytes,
            self.limits.max_parser_work,
            |needed, limit| PriorityAggregateManyBuildError::ParserWorkLimit { needed, limit },
        )?;
        let parser_observed_budget = self
            .limits
            .max_parser_work
            .checked_sub(source_bytes)
            .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "parser source minimum exceeded its admitted aggregate budget",
            })?;
        let source_identity_allocation_attempts = self
            .patterns
            .iter()
            .filter(|pattern| !pattern.is_empty())
            .count();
        enforce_usize(
            source_identity_allocation_attempts,
            self.limits.max_source_identity_allocation_attempts,
            |needed, limit| {
                PriorityAggregateManyBuildError::SourceIdentityAllocationAttemptsLimit {
                    needed,
                    limit,
                }
            },
        )?;
        let source_owner_allocation_bytes = ParseRequest::attempt_source_owner_allocation_bytes()
            .checked_mul(count)
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "aggregate source-owner allocation bytes",
                },
            )?;
        let source_owner_handle_bytes = ParseRequest::attempt_source_owner_handle_bytes()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_mul(count))
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "aggregate source-owner handle bytes",
                },
            )?;
        let source_owner_allocation_attempts = count;
        for (resource, needed, limit) in [
            (
                PriorityAggregateManySourceOwnerResource::AllocationBytes,
                ParseRequest::attempt_source_owner_allocation_bytes(),
                self.limits.source_owner.max_allocation_bytes,
            ),
            (
                PriorityAggregateManySourceOwnerResource::HandleBytes,
                ParseRequest::attempt_source_owner_handle_bytes()
                    .checked_mul(2)
                    .ok_or(
                        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                            computation: "source-owner handle bytes",
                        },
                    )?,
                self.limits.source_owner.max_handle_bytes,
            ),
            (
                PriorityAggregateManySourceOwnerResource::AllocationAttempts,
                1,
                self.limits.source_owner.max_allocation_attempts,
            ),
        ] {
            enforce_usize(needed, limit, |needed, limit| {
                PriorityAggregateManyBuildError::SourceOwnerResourceLimit {
                    resource,
                    needed,
                    limit,
                }
            })?;
        }

        // This charge is made from the requested exact capacities before any
        // bridge-owned allocation. `reserve_exact` below refuses a platform
        // that cannot honor the already-admitted exact capacity.
        let parts_capacity_bytes = capacity_bytes::<RawPlan>(count, "part vector bytes")?;
        let report_capacity_bytes =
            capacity_bytes::<PriorityAggregateManyPatternReport>(count, "report vector bytes")?;
        let width_capacity_bytes = capacity_bytes::<CheckedWidth>(count, "width vector bytes")?;
        // The reports retain both source identities and source-owner Arc
        // blocks. Reserve their exact logical ownership before the bridge
        // vectors, owner bindings, or parser traversals begin.
        let metadata_persistent_preflight = report_capacity_bytes
            .checked_add(pattern_bytes)
            .and_then(|bytes| bytes.checked_add(source_owner_allocation_bytes))
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "metadata persistent preflight",
                },
            )?;
        enforce_usize(
            metadata_persistent_preflight,
            self.limits.max_persistent_bytes,
            |needed, limit| PriorityAggregateManyBuildError::PersistentLimit { needed, limit },
        )?;
        let initial_peak_scratch = parts_capacity_bytes
            .checked_add(width_capacity_bytes)
            .and_then(|bytes| bytes.checked_add(metadata_persistent_preflight))
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "initial aggregate scratch",
                },
            )?;
        enforce_usize(
            initial_peak_scratch,
            self.limits.max_composition_scratch_bytes,
            |needed, limit| PriorityAggregateManyBuildError::CompositionScratchLimit {
                needed,
                limit,
            },
        )?;
        let aggregate_preflight = aggregate_capacity_preflight(
            count,
            &self.limits,
            self.limits.tagged,
            parts_capacity_bytes,
            width_capacity_bytes,
            metadata_persistent_preflight,
        )?;
        enforce_usize(
            aggregate_preflight.scratch_bytes,
            self.limits.max_composition_scratch_bytes,
            |needed, limit| PriorityAggregateManyBuildError::CompositionScratchLimit {
                needed,
                limit,
            },
        )?;
        enforce_usize(
            aggregate_preflight.persistent_bytes,
            self.limits.max_persistent_bytes,
            |needed, limit| PriorityAggregateManyBuildError::PersistentLimit { needed, limit },
        )?;
        enforce_u64(
            aggregate_preflight.composition_work,
            self.limits.max_composition_work,
            |needed, limit| PriorityAggregateManyBuildError::CompositionWorkLimit { needed, limit },
        )?;
        if self.limits.tagged.max_allocation_attempts < TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS {
            return Err(PriorityAggregateManyBuildError::Tagged(
                TaggedManyBuildError::AllocationAttemptsLimit {
                    needed: TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS,
                    limit: self.limits.tagged.max_allocation_attempts,
                },
            ));
        }
        enforce_usize(
            FACADE_ALLOCATION_ATTEMPTS
                .checked_add(TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS)
                .ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "aggregate construction allocation attempts",
                    },
                )?,
            self.limits.max_composition_allocation_attempts,
            |needed, limit| PriorityAggregateManyBuildError::CompositionAllocationAttemptsLimit {
                needed,
                limit,
            },
        )?;
        let tagged_limits = effective_tagged_limits(&self.limits, metadata_persistent_preflight)?;

        let mut parts = reserve_exact::<RawPlan>(count, "lowered pattern parts")?;
        let mut reports =
            reserve_exact::<PriorityAggregateManyPatternReport>(count, "per-pattern reports")?;
        let mut widths = reserve_exact::<CheckedWidth>(count, "pattern widths")?;

        let compatibility = CompatibilityProfile::RustBytes(self.profile.clone());
        let mut parser_work = 0u64;
        let mut fact_work = 0u64;
        let mut lowering_work = 0u64;
        let mut source_states = 0usize;
        let mut source_edges = 0usize;
        let mut syntax_identity_bytes = 0usize;
        let mut source_raw_capacity_bytes = 0usize;
        let mut parser_work_reservation = 0u64;
        let mut remaining_parser_observed_budget = parser_observed_budget;
        let mut remaining_parser_slots = count;

        for (ordinal, pattern) in self.patterns.iter().enumerate() {
            let slots = u64::try_from(remaining_parser_slots).map_err(|_| {
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "remaining parser reservation slots",
                }
            })?;
            let observed_share = remaining_parser_observed_budget.checked_div(slots).ok_or(
                PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "parser reservation had no remaining slot",
                },
            )?;
            remaining_parser_observed_budget = remaining_parser_observed_budget
                .checked_sub(observed_share)
                .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "parser reservation share exceeded its remaining budget",
                })?;
            remaining_parser_slots = remaining_parser_slots.checked_sub(1).ok_or(
                PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "parser reservation slots underflowed",
                },
            )?;
            let source_bytes = u64::try_from(pattern.len()).map_err(|_| {
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "pattern source byte conversion",
                }
            })?;
            let parser_cap = source_bytes.checked_add(observed_share).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "per-pattern parser reservation",
                },
            )?;
            let mut syntax_safety = self.limits.syntax_safety;
            syntax_safety.max_parse_work = syntax_safety.max_parse_work.min(parser_cap);
            let mut request = ParseRequest::rust(pattern.as_str(), compatibility.clone())
                .with_admission(self.limits.admission)
                .with_safety_envelope(syntax_safety);
            let source_capacity = request.attempt_identity().source_capacity_bytes();
            if source_capacity != pattern.len() {
                return Err(
                    PriorityAggregateManyBuildError::SourceIdentityCapacityMismatch {
                        pattern: ordinal,
                        expected: pattern.len(),
                        actual: source_capacity,
                    },
                );
            }
            let prospective = request.attempt_prospective();
            let reservation = prospective
                .source_bytes
                .checked_add(prospective.max_observed_work)
                .ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "parser prospective reservation",
                    },
                )?;
            enforce_u64(reservation, parser_cap, |needed, limit| {
                PriorityAggregateManyBuildError::ParserWorkLimit { needed, limit }
            })?;
            parser_work_reservation = parser_work_reservation.checked_add(reservation).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "aggregate parser reservation",
                },
            )?;
            enforce_u64(
                parser_work_reservation,
                self.limits.max_parser_work,
                |needed, limit| PriorityAggregateManyBuildError::ParserWorkLimit { needed, limit },
            )?;
            let source_owner = bind_source_owner(&mut request, self.limits.source_owner)?;
            let attempt = fre_syntax::parse_attempt(request).map_err(|source| {
                PriorityAggregateManyBuildError::Syntax {
                    pattern: ordinal,
                    source,
                }
            })?;
            if !attempt.closes() {
                return Err(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "successful syntax attempt did not close",
                });
            }
            let (parsed, syntax_receipt) = attempt.into_parts();
            parser_work = parser_work.checked_add(parsed.summary.parse_work).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "parser work sum",
                },
            )?;
            enforce_u64(parser_work, parser_work_reservation, |needed, limit| {
                PriorityAggregateManyBuildError::ParserWorkLimit { needed, limit }
            })?;
            syntax_identity_bytes = syntax_identity_bytes
                .checked_add(parsed.key.pattern.capacity_bytes())
                .ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "syntax identity capacity sum",
                    },
                )?;
            let fre_syntax::ParseRecord {
                key,
                admission_status,
                summary,
                pattern,
            } = parsed;
            let CanonicalPattern::Rust(rust) = pattern else {
                return Err(PriorityAggregateManyBuildError::NonRustCanonicalPattern {
                    pattern: ordinal,
                });
            };
            let facts = analyze_facts(&rust, operation.fact_operation(), self.limits.facts)
                .map_err(|source| PriorityAggregateManyBuildError::Facts {
                    pattern: ordinal,
                    source,
                })?;
            if !facts.captures().erasure_permitted() {
                return Err(PriorityAggregateManyBuildError::CaptureErasureNotProven {
                    pattern: ordinal,
                });
            }
            fact_work = fact_work.checked_add(facts.stats().work()).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "fact work sum",
                },
            )?;
            let width = facts.width();
            let remaining_states = aggregate_preflight
                .source_states_limit
                .checked_sub(source_states)
                .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "source states exceeded their aggregate admission",
                })?;
            let remaining_edges = aggregate_preflight
                .source_edges_limit
                .checked_sub(source_edges)
                .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "source edges exceeded their aggregate admission",
                })?;
            let mut lowering_limits = self.limits.lowering;
            lowering_limits.automata.max_states =
                lowering_limits.automata.max_states.min(remaining_states);
            lowering_limits.automata.max_edges =
                lowering_limits.automata.max_edges.min(remaining_edges);
            let raw = lower_raw(&rust, OperationSemantics::CaptureFree, lowering_limits).map_err(
                |source| PriorityAggregateManyBuildError::Lower {
                    pattern: ordinal,
                    source,
                },
            )?;
            let lowering = raw.stats();
            if lowering.normalized_nullable_repetitions() != 0 {
                return Err(
                    PriorityAggregateManyBuildError::NormalizedLoweringRequiresIntrinsicLength {
                        pattern: ordinal,
                        repetitions: lowering.normalized_nullable_repetitions(),
                    },
                );
            }
            lowering_work = lowering_work.checked_add(lowering.work()).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "lowering work sum",
                },
            )?;
            source_states = source_states.checked_add(lowering.states()).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "lowered state sum",
                },
            )?;
            source_edges = source_edges.checked_add(lowering.edges()).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "lowered edge sum",
                },
            )?;
            enforce_usize(
                source_states,
                self.limits.max_lowered_states,
                |needed, limit| PriorityAggregateManyBuildError::LoweredStatesLimit {
                    needed,
                    limit,
                },
            )?;
            enforce_usize(
                source_edges,
                self.limits.max_lowered_edges,
                |needed, limit| PriorityAggregateManyBuildError::LoweredEdgesLimit {
                    needed,
                    limit,
                },
            )?;
            let raw = raw.into_plan();
            let raw_capacity_bytes = raw_plan_capacity_bytes(&raw)?;
            source_raw_capacity_bytes = source_raw_capacity_bytes
                .checked_add(raw_capacity_bytes)
                .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "source raw capacity sum",
                },
            )?;
            widths.push(width);
            reports.push(PriorityAggregateManyPatternReport {
                ordinal,
                syntax_key: key,
                admission: admission_status,
                syntax: summary,
                syntax_receipt,
                source_owner,
                width,
                facts: facts.stats(),
                lowering,
                raw_capacity_bytes,
            });
            parts.push(raw);
        }

        if remaining_parser_slots != 0 || remaining_parser_observed_budget != 0 {
            return Err(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "aggregate parser reservation did not close",
            });
        }
        let declared_match_length = combine_widths(widths.iter().copied());
        drop(widths);
        let metadata_persistent_bytes = report_capacity_bytes
            .checked_add(syntax_identity_bytes)
            .and_then(|bytes| bytes.checked_add(source_owner_allocation_bytes))
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "metadata persistent bytes",
                },
            )?;
        let (plan, composition) = compose_tagged_parts::<O>(
            parts,
            count,
            pattern_bytes,
            parser_work,
            parser_work_reservation,
            fact_work,
            lowering_work,
            source_states,
            source_edges,
            parts_capacity_bytes,
            width_capacity_bytes,
            source_raw_capacity_bytes,
            metadata_persistent_bytes,
            aggregate_preflight.scratch_bytes,
            aggregate_preflight.persistent_bytes,
            aggregate_preflight.composition_work,
            source_owner_allocation_bytes,
            source_owner_handle_bytes,
            source_owner_allocation_attempts,
            source_identity_allocation_attempts,
            tagged_limits,
            self.profile.options.line_terminator,
            &self.limits,
        )?;
        let automaton = plan.stats();
        let tagged_build = plan.build_accounting();
        Ok(CommonBuild {
            operation,
            execution,
            target,
            limits: self.limits,
            profile: self.profile,
            reports,
            composition,
            automaton,
            declared_match_length,
            tagged_limits,
            tagged_build,
            plan: Some(plan),
        })
    }
}

struct CommonBuild<O: fre_automata::DirectReduceValue> {
    operation: PriorityAggregateManyOperation,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PriorityAggregateManyBuildLimits,
    profile: RustProfile,
    reports: Vec<PriorityAggregateManyPatternReport>,
    composition: PriorityAggregateManyCompositionAccounting,
    automaton: TaggedManyStats,
    declared_match_length: MatchLengthProof,
    tagged_limits: TaggedManyBuildLimits,
    tagged_build: TaggedManyBuildAccounting,
    plan: Option<TaggedManyPlan<O>>,
}

fn shared_frontier_stats_close(
    stats: TaggedManyStats,
    depth: usize,
    byte_start: u8,
    byte_end: u8,
) -> bool {
    let shared_states = depth.checked_add(1);
    let source_states =
        shared_states.and_then(|state_count| stats.patterns().checked_mul(state_count));
    let source_edges = stats.patterns().checked_mul(depth);
    stats.patterns() > 0
        && stats.patterns() <= 128
        && depth > 0
        && byte_start < byte_end
        && shared_states == Some(stats.states())
        && stats.edges() == depth
        && source_states == Some(stats.source_states())
        && source_edges == Some(stats.source_edges())
        && stats.owner_state_memberships() == stats.source_states()
        && stats.owner_edge_memberships() == stats.source_edges()
        && stats.zero_width_edges() == 0
        && stats.consuming_edges() == depth
        && stats.maximum_zero_width_rank() == 0
}

fn tagged_classification_closes(stats: TaggedManyStats, build: TaggedManyBuildAccounting) -> bool {
    let prospective = u64::try_from(stats.patterns())
        .ok()
        .and_then(|owners| {
            u64::try_from(stats.source_states())
                .ok()
                .and_then(|states| owners.checked_add(states))
        })
        .and_then(|checks| {
            u64::try_from(stats.source_edges())
                .ok()
                .and_then(|edges| checks.checked_add(edges))
        })
        .and_then(|checks| checks.checked_add(2));
    let within_physical_graph = build.classification_owner_checks <= stats.patterns()
        && build.classification_state_checks <= stats.states()
        && build.classification_edge_checks <= stats.edges();
    let shape_passes = stats.edges() > 0
        && stats.edges().checked_add(1) == Some(stats.states())
        && stats.patterns() > 0;
    let class_scan_closes = match stats.execution_class() {
        TaggedManyExecutionClass::Generic => {
            if build.classification_state_checks == 0 {
                build.classification_edge_checks == 0
                    && if shape_passes {
                        build.classification_owner_checks > 0
                    } else {
                        build.classification_owner_checks == 0
                    }
            } else {
                build.classification_owner_checks == stats.patterns()
                    && shape_passes
                    && build.classification_edge_checks <= build.classification_state_checks
                    && build
                        .classification_edge_checks
                        .checked_add(1)
                        .is_some_and(|next| build.classification_state_checks <= next)
            }
        }
        TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
            depth,
            byte_start,
            byte_end,
        } => {
            shared_frontier_stats_close(stats, depth, byte_start, byte_end)
                && build.classification_owner_checks == stats.patterns()
                && build.classification_state_checks == stats.states()
                && build.classification_edge_checks == stats.edges()
        }
        _ => false,
    };
    prospective == Some(build.classification_work_upper_bound)
        && within_physical_graph
        && class_scan_closes
}

fn tagged_preparation_compatibility(
    stats: TaggedManyStats,
    build: TaggedManyBuildAccounting,
) -> Result<PreparationAccounting, PriorityAggregateManyBuildError> {
    let subset_items = stats
        .owner_state_memberships()
        .checked_add(stats.owner_edge_memberships())
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "tagged compatibility membership count",
            },
        )?;
    Ok(PreparationAccounting {
        prospective: PreparationProspective {
            pattern_terminals: stats.patterns(),
            dfa_states: stats.states(),
            transition_cells: stats.edges(),
            subset_items,
            tagged_dispatch_states: 0,
            tagged_dispatch_cells: 0,
            tagged_candidate_items: 0,
            work: build.prospective_work,
            persistent_bytes: build.persistent_bytes,
            peak_bytes: build.peak_bytes,
            allocation_attempts: build.allocation_attempts,
        },
        pattern_terminals: stats.patterns(),
        dfa_states: stats.states(),
        transition_cells: stats.edges(),
        subset_items,
        tagged_dispatch_states: 0,
        tagged_dispatch_cells: 0,
        tagged_candidate_items: 0,
        work: build.actual_work,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build.peak_bytes,
        allocation_attempts: build.allocation_attempts,
    })
}

fn tagged_preparation_closes_against(
    accounting: PreparationAccounting,
    limits: PreparationLimits,
) -> bool {
    let prospective = accounting.prospective;
    prospective.pattern_terminals == accounting.pattern_terminals
        && prospective.dfa_states == accounting.dfa_states
        && prospective.transition_cells == accounting.transition_cells
        && prospective.subset_items == accounting.subset_items
        && prospective.tagged_dispatch_states == 0
        && prospective.tagged_dispatch_cells == 0
        && prospective.tagged_candidate_items == 0
        && accounting.tagged_dispatch_states == 0
        && accounting.tagged_dispatch_cells == 0
        && accounting.tagged_candidate_items == 0
        && accounting.work <= prospective.work
        && prospective.persistent_bytes == accounting.persistent_bytes
        && prospective.peak_bytes == accounting.peak_bytes
        && prospective.allocation_attempts == accounting.allocation_attempts
        && prospective.pattern_terminals <= limits.max_pattern_terminals
        && prospective.dfa_states <= limits.max_dfa_states
        && prospective.transition_cells <= limits.max_transition_cells
        && prospective.subset_items <= limits.max_subset_items
        && prospective.work <= limits.max_work
        && prospective.persistent_bytes <= limits.max_persistent_bytes
        && prospective.peak_bytes <= limits.max_peak_bytes
        && prospective.allocation_attempts <= limits.max_allocation_attempts
}

impl<O: fre_automata::DirectReduceValue> CommonBuild<O> {
    fn finish(
        mut self,
    ) -> Result<
        (TaggedManyPlan<O>, PriorityAggregateManyBuildReport),
        PriorityAggregateManyBuildError,
    > {
        let retained_capacity_bytes = self
            .tagged_build
            .persistent_bytes
            .checked_add(self.composition.metadata_persistent_bytes)
            .ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "retained forced Build-Many capacity bytes",
                },
            )?;
        let preparation = tagged_preparation_compatibility(self.automaton, self.tagged_build)?;
        let report = PriorityAggregateManyBuildReport {
            schema_version: PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
            accounting_id: PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID,
            operation: self.operation,
            execution: self.execution,
            target: self.target,
            limits: self.limits,
            profile: self.profile,
            patterns: self.reports,
            composition: self.composition,
            automaton: self.automaton,
            declared_match_length: self.declared_match_length,
            empty_progress: EmptyMatchProgress::Byte,
            preparation,
            tagged_limits: self.tagged_limits,
            tagged_build: self.tagged_build,
            retained_capacity_bytes,
            validated: false,
        };
        let plan = self
            .plan
            .take()
            .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "forced Build-Many tagged plan was already consumed",
            })?;
        Ok((plan, report))
    }
}

fn validate_route(
    execution: ForcedExecution,
    target: PriorityTarget,
) -> Result<(), PriorityAggregateManyBuildError> {
    if execution != ForcedExecution::Sparse {
        return Err(PriorityAggregateManyBuildError::UnsupportedExecution { execution });
    }
    if !target.sparse || !target.actions.contains(build_many_action_capabilities()) {
        return Err(PriorityAggregateManyBuildError::UnsupportedTarget);
    }
    Ok(())
}

fn bind_source_owner(
    request: &mut ParseRequest,
    limits: PriorityAggregateManySourceOwnerLimits,
) -> Result<PriorityAggregateManySourceOwnerAccounting, PriorityAggregateManyBuildError> {
    let allocation_bytes = ParseRequest::attempt_source_owner_allocation_bytes();
    let handle_bytes = ParseRequest::attempt_source_owner_handle_bytes()
        .checked_mul(2)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "source-owner handle bytes",
            },
        )?;
    for (resource, needed, limit) in [
        (
            PriorityAggregateManySourceOwnerResource::AllocationBytes,
            allocation_bytes,
            limits.max_allocation_bytes,
        ),
        (
            PriorityAggregateManySourceOwnerResource::HandleBytes,
            handle_bytes,
            limits.max_handle_bytes,
        ),
        (
            PriorityAggregateManySourceOwnerResource::AllocationAttempts,
            1,
            limits.max_allocation_attempts,
        ),
    ] {
        enforce_usize(needed, limit, |needed, limit| {
            PriorityAggregateManyBuildError::SourceOwnerResourceLimit {
                resource,
                needed,
                limit,
            }
        })?;
    }
    let bound = request
        .bind_attempt_source_owner()
        .ok_or(PriorityAggregateManyBuildError::SourceOwnerAlreadyBound)?;
    if bound != allocation_bytes {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "source-owner allocation identity changed",
        });
    }
    Ok(PriorityAggregateManySourceOwnerAccounting {
        allocation_bytes,
        handle_bytes,
        allocation_attempts: 1,
    })
}

const fn build_many_action_capabilities() -> ActionCapabilities {
    ActionCapabilities::MATCH
        .union(ActionCapabilities::DIRECT_REDUCE)
        .union(ActionCapabilities::BUILD_MANY)
}

fn bytes_empty_progress_is_byte(profile: &RustProfile) -> bool {
    match &profile.constructor {
        RustConstructor::RegexBuilder {
            bytes_utf8_empty, ..
        } => !bytes_utf8_empty,
        RustConstructor::RebarMeta { utf8_empty, .. } => !utf8_empty,
        RustConstructor::RegexSetBuilder { .. } => false,
    }
}

fn is_ordered_build_many_profile(profile: &RustProfile) -> bool {
    matches!(
        profile.constructor,
        RustConstructor::RebarMeta {
            syntax_utf8: false,
            utf8_empty: false,
            match_kind: RustMatchKind::LeftmostFirst,
            build_many_ordered: true,
            ..
        }
    )
}

#[derive(Clone, Copy, Debug)]
struct CaptureSidecarBuildEnvelope {
    persistent_bytes: usize,
    build_work: usize,
    peak_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct WholeRequiredLiteralConstructionEnvelope {
    persistent_bytes: usize,
    peak_bytes: usize,
    bridge_allocations: usize,
}

fn arc_block_bytes<T>() -> Result<usize, PriorityAggregateManyBuildError> {
    Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size())
        .map_err(
            |_| PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "Arc block bytes",
            },
        )
}

fn cache_key_arc_storage_bytes(
    pattern_capacity: usize,
    computation: &'static str,
) -> Result<usize, PriorityAggregateManyBuildError> {
    arc_block_bytes::<CacheKey>()?
        .checked_add(pattern_capacity)
        .ok_or(PriorityAggregateManyBuildError::CompositionArithmeticOverflow { computation })
}

fn capture_sidecar_limits(
    mut sidecar: CaptureBuildLimits,
    outer: &PriorityAggregateManyBuildLimits,
) -> CaptureBuildLimits {
    // One literal proof is deliberately owned by the multi-pattern artifact.
    // Keeping this `None` prevents a sidecar from introducing a second
    // per-pattern/per-span literal pass behind the forced interface.
    sidecar.required_literal = None;
    sidecar.admission = outer.admission;
    sidecar.syntax_safety = outer.syntax_safety;
    sidecar
}

fn capture_sidecar_build_envelope(
    limits: &CaptureBuildLimits,
    source_capacity: usize,
) -> Result<CaptureSidecarBuildEnvelope, PriorityAggregateManyBuildError> {
    let syntax_storage = cache_key_arc_storage_bytes(
        source_capacity,
        "capture sidecar syntax persistent envelope",
    )?;
    let persistent_bytes = syntax_storage
        .checked_add(limits.engine.max_program_bytes)
        .and_then(|value| value.checked_add(limits.selector.max_program_bytes))
        .and_then(|value| value.checked_add(limits.prefix_class_participation.max_persistent_bytes))
        .and_then(|value| {
            value.checked_add(
                limits
                    .prefix_class_participation
                    .max_retained_capacity_bytes,
            )
        })
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar persistent envelope",
            },
        )?;
    let parser_work = usize::try_from(limits.syntax_safety.max_parse_work).map_err(|_| {
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "capture sidecar parser-work envelope",
        }
    })?;
    let build_work = parser_work
        .checked_add(limits.max_hir_work)
        .and_then(|value| value.checked_add(limits.engine.max_compile_work))
        .and_then(|value| value.checked_add(limits.selector.max_work))
        .and_then(|value| value.checked_add(limits.max_prefix_class_participation_planner_work))
        .and_then(|value| value.checked_add(limits.prefix_class_participation.max_build_work))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar work envelope",
            },
        )?;
    // The nested builders are sequential, but the envelope is intentionally
    // conservative: all independently retained payloads plus their checked
    // construction peaks are admitted before a sidecar table is allocated.
    let peak_bytes = persistent_bytes
        .checked_add(limits.selector.max_program_bytes)
        .and_then(|value| value.checked_add(limits.prefix_class_participation.max_peak_bytes))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar peak envelope",
            },
        )?;
    Ok(CaptureSidecarBuildEnvelope {
        persistent_bytes,
        build_work,
        peak_bytes,
    })
}

fn enforce_capture_construction_limits(
    accounting: PriorityAggregateManyCaptureConstructionAccounting,
    limits: &PriorityAggregateManyCaptureBuildLimits,
) -> Result<(), PriorityAggregateManyBuildError> {
    for (resource, needed, limit) in [
        (
            PriorityAggregateManyCaptureBuildResource::SidecarPersistentBytes,
            accounting.sidecar_persistent_bytes,
            limits.max_sidecar_persistent_bytes,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::SidecarBuildWork,
            accounting.sidecar_build_work,
            limits.max_sidecar_build_work,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::SidecarPeakBytes,
            accounting.sidecar_peak_bytes,
            limits.max_sidecar_peak_bytes,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::SidecarTableAllocations,
            accounting.sidecar_table_allocations,
            limits.max_sidecar_table_allocations,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::WholeLiteralPersistentBytes,
            accounting.whole_literal_persistent_bytes,
            limits.max_whole_literal_persistent_bytes,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::WholeLiteralPeakBytes,
            accounting.whole_literal_peak_bytes,
            limits.max_whole_literal_peak_bytes,
        ),
        (
            PriorityAggregateManyCaptureBuildResource::WholeLiteralBridgeAllocations,
            accounting.whole_literal_bridge_allocations,
            limits.max_whole_literal_bridge_allocations,
        ),
    ] {
        if needed > limit {
            return Err(PriorityAggregateManyBuildError::CaptureConstructionLimit {
                resource,
                needed,
                limit,
            });
        }
    }
    if accounting.whole_literal_parser_work > limits.max_whole_literal_parser_work {
        return Err(
            PriorityAggregateManyBuildError::WholeRequiredLiteralParserWorkLimit {
                needed: accounting.whole_literal_parser_work,
                limit: limits.max_whole_literal_parser_work,
            },
        );
    }
    Ok(())
}

fn capture_construction_preflight(
    patterns: &[String],
    selector: &PriorityAggregateManyBuildReport,
    limits: &PriorityAggregateManyCaptureBuildLimits,
) -> Result<PriorityAggregateManyCaptureConstructionAccounting, PriorityAggregateManyBuildError> {
    let count = patterns.len();
    if count != selector.patterns().len() {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "capture-sidecar preflight source count diverged from selector receipt",
        });
    }
    let table_bytes = capacity_bytes::<CaptureRegex>(count, "capture sidecar table bytes")?;
    let base_sidecar_limits = capture_sidecar_limits(limits.sidecar, &selector.limits);
    let (aggregate_persistent, aggregate_work, aggregate_peak) =
        patterns.iter().zip(selector.patterns()).try_fold(
            (table_bytes, 0_usize, 0_usize),
            |(persistent, work, peak), (pattern, selector_pattern)| {
                let mut sidecar_limits = base_sidecar_limits;
                sidecar_limits.syntax_safety = selector_pattern.syntax_key.safety;
                let envelope = capture_sidecar_build_envelope(&sidecar_limits, pattern.len())?;
                let persistent = persistent.checked_add(envelope.persistent_bytes).ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "aggregate capture-sidecar persistent envelope",
                    },
                )?;
                let work = work.checked_add(envelope.build_work).ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "aggregate capture-sidecar work envelope",
                    },
                )?;
                let peak = peak.checked_add(envelope.peak_bytes).ok_or(
                    PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                        computation: "aggregate capture-sidecar peak envelope",
                    },
                )?;
                Ok::<_, PriorityAggregateManyBuildError>((persistent, work, peak))
            },
        )?;
    let whole = whole_required_literal_construction_envelope(
        patterns,
        selector.limits.syntax_safety,
        limits.whole_required_literal,
    )?;
    let preflight = PriorityAggregateManyCaptureConstructionAccounting {
        patterns: count,
        sidecar_persistent_bytes: aggregate_persistent,
        sidecar_build_work: aggregate_work,
        sidecar_peak_bytes: aggregate_peak,
        sidecar_table_allocations: usize::from(count != 0),
        whole_literal_parser_work: 0,
        whole_literal_planner_work: 0,
        whole_literal_persistent_bytes: whole.persistent_bytes,
        whole_literal_peak_bytes: whole.peak_bytes,
        whole_literal_bridge_allocations: whole.bridge_allocations,
    };
    enforce_capture_construction_limits(preflight, limits)?;
    Ok(PriorityAggregateManyCaptureConstructionAccounting {
        patterns: count,
        sidecar_persistent_bytes: table_bytes,
        sidecar_build_work: 0,
        sidecar_peak_bytes: 0,
        sidecar_table_allocations: usize::from(count != 0),
        whole_literal_parser_work: 0,
        whole_literal_planner_work: 0,
        whole_literal_persistent_bytes: 0,
        whole_literal_peak_bytes: 0,
        whole_literal_bridge_allocations: 0,
    })
}

fn accumulate_capture_sidecar_accounting(
    total: &mut PriorityAggregateManyCaptureConstructionAccounting,
    report: &CaptureBuildReport,
) -> Result<(), PriorityAggregateManyBuildError> {
    if report.required_literal.is_some() || report.plan_identity.required_literal.is_some() {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "capture sidecar retained a forbidden per-ordinal literal proof",
        });
    }
    let prefix = report.prefix_class_participation;
    let syntax_storage = cache_key_arc_storage_bytes(
        report.plan_identity.syntax.pattern.capacity_bytes(),
        "capture sidecar syntax persistent accounting",
    )?;
    let persistent_bytes = syntax_storage
        .checked_add(report.engine.program_bytes)
        .and_then(|value| value.checked_add(report.selector.program_bytes))
        .and_then(|value| value.checked_add(prefix.map_or(0, |receipt| receipt.persistent_bytes)))
        .and_then(|value| {
            value.checked_add(prefix.map_or(0, |receipt| receipt.retained_capacity_bytes))
        })
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar persistent accounting",
            },
        )?;
    let parser_work = usize::try_from(report.syntax.parse_work).map_err(|_| {
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "capture sidecar parser work accounting",
        }
    })?;
    let build_work = parser_work
        .checked_add(report.hir.work)
        .and_then(|value| value.checked_add(report.engine.compile_work))
        .and_then(|value| value.checked_add(report.selector.work))
        .and_then(|value| value.checked_add(prefix.map_or(0, |receipt| receipt.work_upper_bound)))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar work accounting",
            },
        )?;
    let peak_bytes = syntax_storage
        .checked_add(report.engine.program_bytes)
        .and_then(|value| value.checked_add(report.selector.construction_peak_bytes))
        .and_then(|value| value.checked_add(prefix.map_or(0, |receipt| receipt.peak_bytes)))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "capture sidecar peak accounting",
            },
        )?;
    total.sidecar_persistent_bytes = total
        .sidecar_persistent_bytes
        .checked_add(persistent_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "aggregate capture-sidecar persistent accounting",
            },
        )?;
    total.sidecar_build_work = total.sidecar_build_work.checked_add(build_work).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "aggregate capture-sidecar work accounting",
        },
    )?;
    total.sidecar_peak_bytes = total.sidecar_peak_bytes.checked_add(peak_bytes).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "aggregate capture-sidecar peak accounting",
        },
    )?;
    Ok(())
}

fn whole_operation_literal_identity_len(
    patterns: &[String],
) -> Result<usize, PriorityAggregateManyBuildError> {
    let byte_count = patterns
        .iter()
        .try_fold(0_usize, |total, pattern| total.checked_add(pattern.len()))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal identity byte sum",
            },
        )?;
    byte_count
        .checked_mul(2)
        .and_then(|value| value.checked_add(patterns.len()))
        .and_then(|value| value.checked_add("frewholeliteralq".len()))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal identity capacity",
            },
        )
}

/// Maximum simultaneously live capacity of the exact temporary source copy
/// made for an ordinal parse. The copies are parsed and dropped serially.
fn whole_required_literal_source_copy_peak_bytes(lengths: impl Iterator<Item = usize>) -> usize {
    lengths.filter(|length| *length != 0).max().unwrap_or(0)
}

/// Exact wrapper-owned allocation attempts outside the syntax parser and
/// nested literal builder. The encoded identity source and its `Arc` always
/// allocate; the exact HIR root table is allocated only for a nonempty union,
/// and each nonempty ordinal gets one separately reserved transient source.
fn whole_required_literal_direct_bridge_allocations(
    patterns: usize,
    lengths: impl Iterator<Item = usize>,
) -> Result<usize, PriorityAggregateManyBuildError> {
    let fixed = if patterns == 0 {
        2
    } else {
        WHOLE_LITERAL_FIXED_DIRECT_BRIDGE_ALLOCATIONS
    };
    lengths
        .filter(|length| *length != 0)
        .try_fold(fixed, |total, _| {
            total.checked_add(1).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "whole required-literal bridge allocations",
                },
            )
        })
}

/// Make one parser-owned ordinal source with the exact capacity used by the
/// bridge receipt. Empty sources deliberately retain no allocation.
fn copy_whole_required_literal_source(
    pattern: &str,
) -> Result<String, PriorityAggregateManyBuildError> {
    let mut source = String::new();
    if !pattern.is_empty() {
        source.try_reserve_exact(pattern.len()).map_err(|_| {
            PriorityAggregateManyBuildError::AllocationFailed {
                structure: "whole required-literal ordinal source",
                additional: pattern.len(),
            }
        })?;
    }
    source.push_str(pattern);
    if source.capacity() != pattern.len() {
        return Err(PriorityAggregateManyBuildError::AllocationFailed {
            structure: "whole required-literal ordinal source capacity",
            additional: source.capacity(),
        });
    }
    Ok(source)
}

fn whole_required_literal_hir_bridge_peak_bytes(
    patterns: usize,
    syntax_safety: SafetyEnvelope,
) -> Result<usize, PriorityAggregateManyBuildError> {
    // The parser's admitted HIR-node ceiling bounds material held through the
    // logical ordered-union proof. Two root-sized logical envelopes per node
    // conservatively cover parsed HIR material plus the wrapper's exact root
    // table; this is a byte envelope, not a count of opaque parser
    // allocations. `build_from_hirs` deliberately avoids upstream HIR
    // normalization and its variable allocation paths.
    let nodes_per_pattern = usize::try_from(syntax_safety.max_hir_nodes).map_err(|_| {
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal HIR node envelope",
        }
    })?;
    let flattened = patterns.checked_mul(nodes_per_pattern).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal flattened HIR roots",
        },
    )?;
    capacity_bytes::<Hir>(flattened, "whole required-literal HIR bridge")?
        .checked_mul(2)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal HIR bridge peak",
            },
        )
}

fn whole_required_literal_construction_envelope(
    patterns: &[String],
    syntax_safety: SafetyEnvelope,
    limits: CaptureRequiredLiteralBuildLimits,
) -> Result<WholeRequiredLiteralConstructionEnvelope, PriorityAggregateManyBuildError> {
    let identity_capacity = whole_operation_literal_identity_len(patterns)?;
    let identity_persistent = cache_key_arc_storage_bytes(
        identity_capacity,
        "whole required-literal identity persistent envelope",
    )?;
    let bridge_peak = whole_required_literal_hir_bridge_peak_bytes(patterns.len(), syntax_safety)?;
    let source_copy_peak =
        whole_required_literal_source_copy_peak_bytes(patterns.iter().map(String::len));
    let persistent_bytes = identity_persistent
        .checked_add(limits.max_source_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal persistent envelope",
            },
        )?;
    let peak_bytes = identity_persistent
        .checked_add(bridge_peak)
        .and_then(|value| value.checked_add(source_copy_peak))
        .and_then(|value| value.checked_add(limits.max_peak_bytes))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal peak envelope",
            },
        )?;
    Ok(WholeRequiredLiteralConstructionEnvelope {
        persistent_bytes,
        peak_bytes,
        bridge_allocations: whole_required_literal_direct_bridge_allocations(
            patterns.len(),
            patterns.iter().map(String::len),
        )?,
    })
}

fn whole_required_literal_actual_persistent_bytes(
    identity: &Arc<CacheKey>,
    plan: Option<&CaptureRequiredLiteralPlan>,
) -> Result<usize, PriorityAggregateManyBuildError> {
    let identity_bytes = cache_key_arc_storage_bytes(
        identity.pattern.capacity_bytes(),
        "whole required-literal identity persistent accounting",
    )?;
    identity_bytes
        .checked_add(plan.map_or(0, |plan| plan.build_report().accounting.source_bytes))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal persistent accounting",
            },
        )
}

fn whole_required_literal_actual_peak_bytes(
    identity: &Arc<CacheKey>,
    plan: Option<&CaptureRequiredLiteralPlan>,
    patterns: usize,
    source_copy_peak: usize,
    syntax_safety: SafetyEnvelope,
) -> Result<usize, PriorityAggregateManyBuildError> {
    let identity_bytes = cache_key_arc_storage_bytes(
        identity.pattern.capacity_bytes(),
        "whole required-literal identity peak accounting",
    )?;
    let bridge_peak = whole_required_literal_hir_bridge_peak_bytes(patterns, syntax_safety)?;
    identity_bytes
        .checked_add(bridge_peak)
        .and_then(|value| value.checked_add(source_copy_peak))
        .and_then(|value| {
            value.checked_add(plan.map_or(0, |plan| {
                plan.build_report().accounting.peak_bytes_upper_bound
            }))
        })
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal peak accounting",
            },
        )
}

/// Build a conservative required-any-literal proof over the ordered union of
/// all source HIRs. The proof uses the enclosing forced builder's exact
/// admission and safety policy. Every terminal parse/allocation/proof failure
/// remains typed; only a completed proof with no universal literal publishes
/// the explicit `NoProof` selector fallback receipt.
#[allow(
    clippy::too_many_lines,
    reason = "the parser reservation, ordered HIR union, proof disposition, and receipt publication form one audited construction transaction"
)]
fn build_whole_operation_required_literal(
    patterns: &[String],
    profile: &RustProfile,
    admission: AdmissionPolicy,
    syntax_safety: SafetyEnvelope,
    limits: CaptureRequiredLiteralBuildLimits,
    max_parser_work: u64,
) -> Result<WholeRequiredLiteralBuild, PriorityAggregateManyBuildError> {
    let identity_source = whole_operation_literal_identity_source(patterns)?;
    let source_floor = patterns
        .iter()
        .try_fold(identity_source.len(), |total, pattern| {
            total.checked_add(pattern.len())
        })
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal parser source floor",
            },
        )?;
    let source_floor = u64::try_from(source_floor).map_err(|_| {
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal parser source conversion",
        }
    })?;
    if source_floor > max_parser_work {
        return Err(
            PriorityAggregateManyBuildError::WholeRequiredLiteralParserWorkLimit {
                needed: source_floor,
                limit: max_parser_work,
            },
        );
    }
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    let mut remaining_observed = max_parser_work.checked_sub(source_floor).ok_or(
        PriorityAggregateManyBuildError::InternalInvariant {
            detail: "whole required-literal parser floor exceeded its admitted budget",
        },
    )?;
    let mut remaining_slots = patterns.len().checked_add(1).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal parser slots",
        },
    )?;
    let mut parse_source =
        |source: String,
         pattern: Option<usize>|
         -> Result<fre_syntax::ParseRecord, PriorityAggregateManyBuildError> {
            let slots = u64::try_from(remaining_slots).map_err(|_| {
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "whole required-literal remaining parser slots",
                }
            })?;
            let observed_share = remaining_observed.checked_div(slots).ok_or(
                PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "whole required-literal parser slots reached zero",
                },
            )?;
            remaining_observed = remaining_observed.checked_sub(observed_share).ok_or(
                PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "whole required-literal parser share exceeded its budget",
                },
            )?;
            remaining_slots = remaining_slots.checked_sub(1).ok_or(
                PriorityAggregateManyBuildError::InternalInvariant {
                    detail: "whole required-literal parser slots underflowed",
                },
            )?;
            let source_bytes = u64::try_from(source.len()).map_err(|_| {
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "whole required-literal source byte conversion",
                }
            })?;
            let parser_cap = source_bytes.checked_add(observed_share).ok_or(
                PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                    computation: "whole required-literal parser reservation",
                },
            )?;
            let mut safety = syntax_safety;
            safety.max_parse_work = safety.max_parse_work.min(parser_cap);
            fre_syntax::parse(
                ParseRequest::rust(source, compatibility.clone())
                    .with_admission(admission)
                    .with_safety_envelope(safety),
            )
            .map_err(|source| {
                PriorityAggregateManyBuildError::WholeRequiredLiteralSyntax { pattern, source }
            })
        };
    let fre_syntax::ParseRecord {
        key: identity_key,
        summary: identity_summary,
        pattern: identity_pattern,
        ..
    } = parse_source(identity_source, None)?;
    let mut parser_work = identity_summary.parse_work;
    // The encoded identity is only a receipt key. Drop its parsed HIR before
    // retaining any ordinal HIR so the bridge peak has one explicit owner.
    drop(identity_pattern);
    let mut hirs = reserve_exact(patterns.len(), "whole required-literal HIRs")?;
    for (ordinal, pattern) in patterns.iter().enumerate() {
        let fre_syntax::ParseRecord {
            key,
            summary,
            pattern,
            ..
        } = parse_source(
            copy_whole_required_literal_source(pattern.as_str())?,
            Some(ordinal),
        )?;
        parser_work = parser_work.checked_add(summary.parse_work).ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal parser work",
            },
        )?;
        // Each ordinal parser key owns only its temporary source copy. The
        // HIR is retained in the exact root table; release the source before
        // moving to the next ordinal so `source_copy_peak` is a true maximum.
        drop(key);
        let CanonicalPattern::Rust(rust) = pattern else {
            return Err(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "whole required-literal Rust request produced non-Rust syntax",
            });
        };
        hirs.push(rust.hir);
    }
    if remaining_slots != 0 || remaining_observed != 0 {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "whole required-literal parser reservation did not close",
        });
    }
    if parser_work > max_parser_work {
        return Err(
            PriorityAggregateManyBuildError::WholeRequiredLiteralParserWorkLimit {
                needed: parser_work,
                limit: max_parser_work,
            },
        );
    }
    if hirs.len() != patterns.len() || hirs.capacity() != patterns.len() {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "whole required-literal HIR collection lost its source ordinal shape",
        });
    }
    let identity = Arc::new(identity_key);
    if identity.pattern.capacity_bytes() != whole_operation_literal_identity_len(patterns)? {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "whole required-literal identity lost its admitted exact capacity",
        });
    }
    let outcome = capture_required_literal::build_from_hirs(&hirs, Arc::clone(&identity), limits)
        .map_err(
        |failure| PriorityAggregateManyBuildError::WholeRequiredLiteral {
            source: failure.source,
        },
    )?;
    let receipt = match outcome.plan.as_ref() {
        Some(plan) => PriorityAggregateManyWholeRequiredLiteralBuildReceipt::Built {
            report: plan.build_report().clone(),
            parser_work,
        },
        None => PriorityAggregateManyWholeRequiredLiteralBuildReceipt::NoProof {
            parser_work,
            planner_work: outcome.planner_work,
        },
    };
    let persistent_bytes =
        whole_required_literal_actual_persistent_bytes(&identity, outcome.plan.as_ref())?;
    let source_copy_peak =
        whole_required_literal_source_copy_peak_bytes(patterns.iter().map(String::len));
    let bridge_allocations = whole_required_literal_direct_bridge_allocations(
        patterns.len(),
        patterns.iter().map(String::len),
    )?;
    let peak_bytes = whole_required_literal_actual_peak_bytes(
        &identity,
        outcome.plan.as_ref(),
        patterns.len(),
        source_copy_peak,
        syntax_safety,
    )?;
    let envelope = whole_required_literal_construction_envelope(patterns, syntax_safety, limits)?;
    if persistent_bytes > envelope.persistent_bytes
        || peak_bytes > envelope.peak_bytes
        || bridge_allocations > envelope.bridge_allocations
    {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "whole required-literal construction exceeded its admitted envelope",
        });
    }
    Ok(WholeRequiredLiteralBuild {
        plan: outcome.plan,
        identity,
        receipt,
        persistent_bytes,
        peak_bytes,
        bridge_allocations,
    })
}

fn preflight_whole_required_literal_parser(
    patterns: &[String],
    max_parser_work: u64,
) -> Result<(), PriorityAggregateManyBuildError> {
    let pattern_bytes = patterns
        .iter()
        .try_fold(0_usize, |total, pattern| total.checked_add(pattern.len()))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "whole required-literal parser preflight pattern bytes",
            },
        )?;
    let identity_bytes = whole_operation_literal_identity_len(patterns)?;
    let floor = pattern_bytes.checked_add(identity_bytes).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal parser preflight source floor",
        },
    )?;
    let floor = u64::try_from(floor).map_err(|_| {
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "whole required-literal parser preflight source conversion",
        }
    })?;
    if floor > max_parser_work {
        return Err(
            PriorityAggregateManyBuildError::WholeRequiredLiteralParserWorkLimit {
                needed: floor,
                limit: max_parser_work,
            },
        );
    }
    Ok(())
}

/// Encode sources as a literal-only, collision-free parser key. The string is
/// not used as the literal proof's semantic input; it only carries exact
/// ordered multi-source identity because `CacheKey` is intentionally private
/// to the syntax parser.
fn whole_operation_literal_identity_source(
    patterns: &[String],
) -> Result<String, PriorityAggregateManyBuildError> {
    let capacity = whole_operation_literal_identity_len(patterns)?;
    let mut source = String::new();
    source.try_reserve_exact(capacity).map_err(|_| {
        PriorityAggregateManyBuildError::AllocationFailed {
            structure: "whole required-literal identity",
            additional: capacity,
        }
    })?;
    source.push_str("frewholeliteralq");
    for pattern in patterns {
        source.push('z');
        for byte in pattern.as_bytes() {
            source.push(char::from(
                WHOLE_LITERAL_IDENTITY_HEX[usize::from(byte >> 4)],
            ));
            source.push(char::from(
                WHOLE_LITERAL_IDENTITY_HEX[usize::from(byte & 0x0F)],
            ));
        }
    }
    if source.capacity() != capacity {
        return Err(PriorityAggregateManyBuildError::AllocationFailed {
            structure: "whole required-literal identity capacity",
            additional: source.capacity(),
        });
    }
    Ok(source)
}

fn capture_required_literal_build_report_closes(
    report: &CaptureRequiredLiteralBuildReport,
    limits: CaptureRequiredLiteralBuildLimits,
) -> bool {
    let accounting = report.accounting;
    let literal = accounting.literal_set;
    report.identity.plan_id == capture_required_literal::CAPTURE_REQUIRED_LITERAL_PLAN_ID
        && report.identity.needles.len() == accounting.needles
        && report.identity.needles.byte_len() == accounting.needle_bytes
        && accounting.planner_work <= limits.max_planner_work
        && accounting.hir_depth <= limits.max_hir_depth
        && accounting.needles >= 2
        && accounting.needles <= limits.max_needles
        && accounting.needle_bytes <= limits.max_needle_bytes
        && accounting.minimum_needle_bytes > 0
        && accounting.minimum_needle_bytes <= accounting.needle_bytes
        && accounting.source_bytes <= limits.max_source_bytes
        && accounting.scratch_bytes <= limits.max_scratch_bytes
        && accounting.peak_bytes_upper_bound <= limits.max_peak_bytes
        && literal.match_semantics == fre_kernels::LiteralSetMatchSemantics::StreamingAny
        && literal.patterns == accounting.needles
        && literal.pattern_bytes == accounting.needle_bytes
        && literal.minimum_pattern_bytes == accounting.minimum_needle_bytes
        && literal.patterns <= limits.literal_set.max_patterns
        && literal.pattern_bytes <= limits.literal_set.max_pattern_bytes
        && literal.build_work_upper_bound <= limits.literal_set.max_build_work
        && literal.build_bytes_upper_bound <= limits.literal_set.max_build_bytes
        && literal.persistent_bytes <= limits.literal_set.max_persistent_bytes
}

fn whole_required_literal_identity_closes(
    identity: &Arc<CacheKey>,
    selector: &PriorityAggregateManyBuildReport,
) -> bool {
    let patterns = selector.patterns();
    let Some(pattern_bytes) = patterns.iter().try_fold(0_usize, |total, report| {
        total.checked_add(report.syntax_key.pattern.as_bytes().len())
    }) else {
        return false;
    };
    let Some(identity_len) = pattern_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(patterns.len()))
        .and_then(|value| value.checked_add("frewholeliteralq".len()))
    else {
        return false;
    };
    let Some(source_floor) = identity_len.checked_add(pattern_bytes) else {
        return false;
    };
    let Ok(source_floor) = u64::try_from(source_floor) else {
        return false;
    };
    let slots = match u64::try_from(patterns.len().saturating_add(1)) {
        Ok(slots) if slots != 0 => slots,
        _ => return false,
    };
    let parser_budget = selector.limits.capture_build.max_whole_literal_parser_work;
    let Some(remaining) = parser_budget.checked_sub(source_floor) else {
        return false;
    };
    let Ok(identity_bytes) = u64::try_from(identity_len) else {
        return false;
    };
    let Some(share) = remaining.checked_div(slots) else {
        return false;
    };
    let Some(parser_cap) = identity_bytes.checked_add(share) else {
        return false;
    };
    let mut expected_safety = selector.limits.syntax_safety;
    expected_safety.max_parse_work = expected_safety.max_parse_work.min(parser_cap);
    let expected_profile = CompatibilityProfile::RustBytes(selector.profile.clone());
    let Some(first) = patterns.first() else {
        return false;
    };
    if identity.pattern.capacity_bytes() != identity_len
        || identity.schema_version != first.syntax_key.schema_version
        || identity.profile != expected_profile
        || identity.admission != selector.limits.admission
        || identity.safety != expected_safety
    {
        return false;
    }
    let mut remaining_source = identity.pattern.as_bytes();
    let Some(after_prefix) = remaining_source.strip_prefix(b"frewholeliteralq") else {
        return false;
    };
    remaining_source = after_prefix;
    for report in patterns {
        let Some((b'z', rest)) = remaining_source.split_first() else {
            return false;
        };
        remaining_source = rest;
        for &byte in report.syntax_key.pattern.as_bytes() {
            let Some((&high, rest)) = remaining_source.split_first() else {
                return false;
            };
            let Some((&low, rest)) = rest.split_first() else {
                return false;
            };
            if high != WHOLE_LITERAL_IDENTITY_HEX[usize::from(byte >> 4)]
                || low != WHOLE_LITERAL_IDENTITY_HEX[usize::from(byte & 0x0F)]
            {
                return false;
            }
            remaining_source = rest;
        }
    }
    remaining_source.is_empty()
}

#[derive(Clone, Copy, Debug)]
struct AggregateCapacityPreflight {
    source_states_limit: usize,
    source_edges_limit: usize,
    scratch_bytes: usize,
    persistent_bytes: usize,
    composition_work: u64,
}

fn effective_tagged_limits(
    limits: &PriorityAggregateManyBuildLimits,
    metadata_persistent_bytes: usize,
) -> Result<TaggedManyBuildLimits, PriorityAggregateManyBuildError> {
    let peak_outer_bytes = metadata_persistent_bytes;
    let peak_allowance = limits
        .max_composition_scratch_bytes
        .checked_sub(peak_outer_bytes)
        .ok_or(PriorityAggregateManyBuildError::CompositionScratchLimit {
            needed: peak_outer_bytes,
            limit: limits.max_composition_scratch_bytes,
        })?;
    let persistent_allowance = limits
        .max_persistent_bytes
        .checked_sub(metadata_persistent_bytes)
        .ok_or(PriorityAggregateManyBuildError::PersistentLimit {
            needed: metadata_persistent_bytes,
            limit: limits.max_persistent_bytes,
        })?;
    let allocation_allowance = limits
        .max_composition_allocation_attempts
        .checked_sub(FACADE_ALLOCATION_ATTEMPTS)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionAllocationAttemptsLimit {
                needed: FACADE_ALLOCATION_ATTEMPTS,
                limit: limits.max_composition_allocation_attempts,
            },
        )?;
    let mut tagged = limits.tagged;
    tagged.max_patterns = tagged
        .max_patterns
        .min(limits.max_patterns)
        .min(limits.preparation.max_pattern_terminals)
        .min(128);
    tagged.max_source_states = tagged.max_source_states.min(limits.max_lowered_states);
    tagged.max_source_edges = tagged.max_source_edges.min(limits.max_lowered_edges);
    tagged.max_shared_states = tagged
        .max_shared_states
        .min(limits.composition_automata.max_states)
        .min(limits.preparation.max_dfa_states);
    tagged.max_shared_edges = tagged
        .max_shared_edges
        .min(limits.composition_automata.max_edges)
        .min(limits.preparation.max_transition_cells);
    tagged.max_owner_state_memberships = tagged
        .max_owner_state_memberships
        .min(limits.preparation.max_subset_items);
    tagged.max_owner_edge_memberships = tagged
        .max_owner_edge_memberships
        .min(limits.preparation.max_subset_items);
    tagged.max_work = tagged
        .max_work
        .min(limits.max_composition_work)
        .min(limits.preparation.max_work);
    tagged.max_persistent_bytes = tagged
        .max_persistent_bytes
        .min(persistent_allowance)
        .min(limits.preparation.max_persistent_bytes);
    tagged.max_peak_bytes = tagged
        .max_peak_bytes
        .min(peak_allowance)
        .min(limits.preparation.max_peak_bytes);
    tagged.max_allocation_attempts = tagged
        .max_allocation_attempts
        .min(allocation_allowance)
        .min(limits.preparation.max_allocation_attempts);
    Ok(tagged)
}

fn repeated_source_bound(
    global: usize,
    per_pattern: usize,
    count: usize,
) -> Result<usize, PriorityAggregateManyBuildError> {
    let count_minus_one =
        count
            .checked_sub(1)
            .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "source bound needs a nonempty pattern set",
            })?;
    let ceiling = global
        .checked_add(count_minus_one)
        .and_then(|value| value.checked_div(count))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "repeated source ceiling",
            },
        )?;
    if per_pattern >= ceiling {
        Ok(global)
    } else {
        per_pattern.checked_mul(count).ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "repeated source bound",
            },
        )
    }
}

fn source_raw_capacity_upper(
    states: usize,
    edges: usize,
    patterns: usize,
) -> Result<usize, PriorityAggregateManyBuildError> {
    let base = raw_plan_bytes(states, edges)?;
    let extra_offsets =
        patterns
            .checked_sub(1)
            .ok_or(PriorityAggregateManyBuildError::InternalInvariant {
                detail: "source raw capacity needs a nonempty pattern set",
            })?;
    let extra_offset_bytes = capacity_bytes::<u32>(extra_offsets, "source raw offset bytes")?;
    base.checked_add(extra_offset_bytes).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "source raw capacity upper bound",
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the aggregate reservation intentionally keeps every source and composed ownership dimension together before source work begins"
)]
fn aggregate_capacity_preflight(
    count: usize,
    limits: &PriorityAggregateManyBuildLimits,
    tagged: TaggedManyBuildLimits,
    parts_capacity_bytes: usize,
    width_capacity_bytes: usize,
    metadata_persistent_bytes: usize,
) -> Result<AggregateCapacityPreflight, PriorityAggregateManyBuildError> {
    let source_states_limit = repeated_source_bound(
        limits.max_lowered_states,
        limits.lowering.automata.max_states,
        count,
    )?
    .min(tagged.max_source_states);
    let source_edges_limit = repeated_source_bound(
        limits.max_lowered_edges,
        limits.lowering.automata.max_edges,
        count,
    )?
    .min(tagged.max_source_edges);
    let source_raw_capacity_bytes =
        source_raw_capacity_upper(source_states_limit, source_edges_limit, count)?;
    let source_phase_scratch = parts_capacity_bytes
        .checked_add(width_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(source_raw_capacity_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_persistent_bytes))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "preflight source scratch",
            },
        )?;
    let composition_phase_scratch = metadata_persistent_bytes
        .checked_add(tagged.max_peak_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "preflight composition scratch",
            },
        )?;
    let scratch_bytes = source_phase_scratch.max(composition_phase_scratch);
    let persistent_bytes = metadata_persistent_bytes
        .checked_add(tagged.max_persistent_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "preflight persistent bytes",
            },
        )?;
    Ok(AggregateCapacityPreflight {
        source_states_limit,
        source_edges_limit,
        scratch_bytes,
        persistent_bytes,
        composition_work: tagged.max_work,
    })
}

fn pattern_syntax_closes(
    report: &PriorityAggregateManyPatternReport,
    source_owner_limits: PriorityAggregateManySourceOwnerLimits,
) -> bool {
    let actual = report.syntax_receipt.actual;
    let summary_work = report
        .syntax_receipt
        .prospective
        .and_then(|prospective| prospective.source_bytes.checked_add(actual.observed_work));
    let expected_admission = match report.syntax_key.admission {
        AdmissionPolicy::Strict(_) => AdmissionStatus::UpstreamOraclePending,
        AdmissionPolicy::Quota(_) => AdmissionStatus::QuotaChecked,
    };
    report.syntax_receipt.terminal == ParseAttemptTerminal::Success
        && report
            .syntax_receipt
            .identity
            .authenticates_key(&report.syntax_key)
        && report.syntax_receipt.identity.has_stable_source_owner()
        && report.syntax_receipt.authenticates_canonical()
        && report.admission == expected_admission
        && actual.source_admission_checks == 1
        && actual.configuration_checks == 1
        && actual.opaque_parser_invocations >= 1
        && actual.hir_nodes == report.syntax.hir_nodes
        && actual.literal_bytes == report.syntax.literal_bytes
        && actual.class_ranges == report.syntax.class_ranges
        && actual.captures == report.syntax.captures
        && actual.repetitions == report.syntax.repetitions
        && actual.max_depth == report.syntax.max_depth
        && summary_work == Some(report.syntax.parse_work)
        && report.source_owner.closes_against(source_owner_limits)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the facade records every independently admitted source and tagged-construction dimension in one receipt"
)]
fn compose_tagged_parts<O: fre_automata::DirectReduceValue>(
    parts: Vec<RawPlan>,
    count: usize,
    pattern_bytes: usize,
    parser_work: u64,
    parser_work_reservation: u64,
    fact_work: u64,
    lowering_work: u64,
    source_states: usize,
    source_edges: usize,
    parts_capacity_bytes: usize,
    width_capacity_bytes: usize,
    source_raw_capacity_bytes: usize,
    metadata_persistent_bytes: usize,
    preflight_scratch_bytes: usize,
    preflight_persistent_bytes: usize,
    preflight_composition_work: u64,
    source_owner_allocation_bytes: usize,
    source_owner_handle_bytes: usize,
    source_owner_allocation_attempts: usize,
    source_identity_allocation_attempts: usize,
    tagged_limits: TaggedManyBuildLimits,
    line_terminator: u8,
    limits: &PriorityAggregateManyBuildLimits,
) -> Result<
    (
        TaggedManyPlan<O>,
        PriorityAggregateManyCompositionAccounting,
    ),
    PriorityAggregateManyBuildError,
> {
    if parts.len() != count || parts.capacity() != count {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "tagged source-plan vector did not retain its exact admitted capacity",
        });
    }
    let owner_memberships = source_states.checked_add(source_edges).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "tagged owner membership preparation sum",
        },
    )?;
    enforce_usize(
        owner_memberships,
        limits.preparation.max_subset_items,
        |needed, limit| PriorityAggregateManyBuildError::PreparationSubsetItemsLimit {
            needed,
            limit,
        },
    )?;
    let source_phase_scratch = parts_capacity_bytes
        .checked_add(width_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(source_raw_capacity_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_persistent_bytes))
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "tagged source lowering peak scratch",
            },
        )?;
    let plan = TaggedManyPlan::<O>::from_raw(
        parts,
        line_terminator,
        limits.composition_automata,
        tagged_limits,
    )
    .map_err(PriorityAggregateManyBuildError::Tagged)?;
    let tagged_stats = plan.stats();
    let tagged_build = plan.build_accounting();
    if tagged_stats.patterns() != count
        || tagged_stats.source_states() != source_states
        || tagged_stats.source_edges() != source_edges
        || tagged_stats.persistent_bytes() != tagged_build.persistent_bytes
        || !tagged_build.closes(tagged_limits)
    {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "tagged construction dimensions did not authenticate facade sources",
        });
    }
    let construction_phase_scratch = metadata_persistent_bytes
        .checked_add(tagged_build.peak_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "tagged construction peak scratch",
            },
        )?;
    let scratch_bytes = source_phase_scratch.max(construction_phase_scratch);
    if scratch_bytes > preflight_scratch_bytes {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "tagged construction exceeded facade scratch preflight",
        });
    }
    enforce_usize(
        scratch_bytes,
        limits.max_composition_scratch_bytes,
        |needed, limit| PriorityAggregateManyBuildError::CompositionScratchLimit { needed, limit },
    )?;
    let retained = metadata_persistent_bytes
        .checked_add(tagged_build.persistent_bytes)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "tagged aggregate persistent bytes",
            },
        )?;
    if retained > preflight_persistent_bytes {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "tagged construction exceeded facade persistent preflight",
        });
    }
    enforce_usize(retained, limits.max_persistent_bytes, |needed, limit| {
        PriorityAggregateManyBuildError::PersistentLimit { needed, limit }
    })?;
    if tagged_build.prospective_work > preflight_composition_work {
        return Err(PriorityAggregateManyBuildError::InternalInvariant {
            detail: "tagged prospective work exceeded facade preflight",
        });
    }
    enforce_u64(
        tagged_build.prospective_work,
        limits.max_composition_work,
        |needed, limit| PriorityAggregateManyBuildError::CompositionWorkLimit { needed, limit },
    )?;
    let allocation_attempts = FACADE_ALLOCATION_ATTEMPTS
        .checked_add(tagged_build.allocation_attempts)
        .ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "tagged aggregate allocation attempts",
            },
        )?;
    enforce_usize(
        allocation_attempts,
        limits.max_composition_allocation_attempts,
        |needed, limit| PriorityAggregateManyBuildError::CompositionAllocationAttemptsLimit {
            needed,
            limit,
        },
    )?;
    let composition = PriorityAggregateManyCompositionAccounting {
        patterns: count,
        pattern_bytes,
        parser_work,
        parser_work_reservation,
        fact_work,
        lowering_work,
        source_states,
        source_edges,
        composed_states: tagged_stats.states(),
        composed_edges: tagged_stats.edges(),
        composition_work: tagged_build.actual_work,
        source_raw_capacity_bytes,
        composed_raw_capacity_bytes: tagged_build.persistent_bytes,
        action_capacity_bytes: 0,
        metadata_persistent_bytes,
        preflight_scratch_bytes,
        preflight_persistent_bytes,
        preflight_composition_work,
        source_owner_allocation_bytes,
        source_owner_handle_bytes,
        source_owner_allocation_attempts,
        source_identity_allocation_attempts,
        scratch_bytes,
        allocation_attempts,
        tagged_stats,
        tagged_build,
    };
    Ok((plan, composition))
}

fn combine_widths(widths: impl IntoIterator<Item = CheckedWidth>) -> MatchLengthProof {
    let mut minimum = None::<usize>;
    let mut maximum = Some(0usize);
    for width in widths {
        let CheckedWidth::NonEmpty {
            minimum: current_minimum,
            maximum: current_maximum,
        } = width
        else {
            continue;
        };
        minimum = Some(minimum.map_or(current_minimum, |value| value.min(current_minimum)));
        maximum = match (maximum, current_maximum) {
            (None, _) | (_, None) => None,
            (Some(left), Some(right)) => Some(left.max(right)),
        };
    }
    let Some(minimum) = minimum else {
        return MatchLengthProof::Empty;
    };
    match maximum {
        None => MatchLengthProof::Unbounded,
        Some(maximum) if minimum == maximum => MatchLengthProof::Exact(minimum),
        Some(maximum) => MatchLengthProof::Finite {
            minimum_bytes: minimum,
            maximum_bytes: maximum,
        },
    }
}

fn raw_plan_capacity_bytes(raw: &RawPlan) -> Result<usize, PriorityAggregateManyBuildError> {
    let mut bytes = capacity_bytes::<StateRole>(raw.roles.capacity(), "raw role capacity")?;
    for (additional, computation) in [
        (
            capacity_bytes::<u32>(raw.edge_offsets.capacity(), "raw offset capacity")?,
            "raw plan capacity bytes",
        ),
        (
            capacity_bytes::<u32>(raw.edge_targets.capacity(), "raw target capacity")?,
            "raw plan capacity bytes",
        ),
        (
            capacity_bytes::<EdgeKind>(raw.edge_kinds.capacity(), "raw kind capacity")?,
            "raw plan capacity bytes",
        ),
        (
            capacity_bytes::<u8>(raw.byte_starts.capacity(), "raw byte-start capacity")?,
            "raw plan capacity bytes",
        ),
        (
            capacity_bytes::<u8>(raw.byte_ends.capacity(), "raw byte-end capacity")?,
            "raw plan capacity bytes",
        ),
    ] {
        bytes = bytes.checked_add(additional).ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow { computation },
        )?;
    }
    Ok(bytes)
}

fn raw_plan_bytes(states: usize, edges: usize) -> Result<usize, PriorityAggregateManyBuildError> {
    let offset_entries = states.checked_add(1).ok_or(
        PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
            computation: "composed offset bytes",
        },
    )?;
    let mut bytes = capacity_bytes::<StateRole>(states, "composed role bytes")?;
    for additional in [
        capacity_bytes::<u32>(offset_entries, "composed offset bytes")?,
        capacity_bytes::<u32>(edges, "composed target bytes")?,
        capacity_bytes::<EdgeKind>(edges, "composed kind bytes")?,
        capacity_bytes::<u8>(edges, "composed byte-start bytes")?,
        capacity_bytes::<u8>(edges, "composed byte-end bytes")?,
    ] {
        bytes = bytes.checked_add(additional).ok_or(
            PriorityAggregateManyBuildError::CompositionArithmeticOverflow {
                computation: "composed raw bytes",
            },
        )?;
    }
    Ok(bytes)
}

fn reserve_exact<T>(
    length: usize,
    structure: &'static str,
) -> Result<Vec<T>, PriorityAggregateManyBuildError> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| {
        PriorityAggregateManyBuildError::AllocationFailed {
            structure,
            additional: length,
        }
    })?;
    if values.capacity() != length {
        return Err(PriorityAggregateManyBuildError::AllocationFailed {
            structure,
            additional: values.capacity(),
        });
    }
    Ok(values)
}

fn capacity_bytes<T>(
    capacity: usize,
    computation: &'static str,
) -> Result<usize, PriorityAggregateManyBuildError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(PriorityAggregateManyBuildError::CompositionArithmeticOverflow { computation })
}

fn enforce_usize(
    needed: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> PriorityAggregateManyBuildError,
) -> Result<(), PriorityAggregateManyBuildError> {
    if needed > limit {
        Err(error(needed, limit))
    } else {
        Ok(())
    }
}

fn enforce_u64(
    needed: u64,
    limit: u64,
    error: impl FnOnce(u64, u64) -> PriorityAggregateManyBuildError,
) -> Result<(), PriorityAggregateManyBuildError> {
    if needed > limit {
        Err(error(needed, limit))
    } else {
        Ok(())
    }
}

/// Direct run limits for one forced Build-Many value reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyRunLimits {
    pub execution: DirectReduceLimits,
    pub max_output: u64,
}

impl PriorityAggregateManyRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            execution: DirectReduceLimits::unlimited(),
            max_output: u64::MAX,
        }
    }
}

impl Default for PriorityAggregateManyRunLimits {
    fn default() -> Self {
        Self {
            execution: DirectReduceLimits::default(),
            max_output: u64::MAX,
        }
    }
}

/// Whole-operation ceilings for exact capture projection work.
///
/// `resources` uses the same named resource fields as one prepared
/// [`CaptureStreamLimits`]. For a per-match limit, construction and replay
/// fields are both enforced. For an aggregate limit, replay fields,
/// `max_matches`, and `max_capture_count` apply to the sum over selected
/// spans. Whole-session construction storage is independently bounded by
/// [`PriorityAggregateManyCaptureSessionLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureProjectionLimits {
    /// Named capture-stream construction and replay ceilings.
    pub resources: CaptureStreamLimits,
    /// Maximum live capture-frontier threads over the operation.
    pub max_peak_threads: usize,
    /// Maximum dynamic allocations after session preparation.
    pub max_dynamic_allocations: usize,
}

impl PriorityAggregateManyCaptureProjectionLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            resources: CaptureStreamLimits {
                max_source_bytes: usize::MAX,
                max_states: usize::MAX,
                max_build_work: usize::MAX,
                max_persistent_bytes: usize::MAX,
                max_combined_peak_bytes: usize::MAX,
                max_allocations: usize::MAX,
                max_line_domains: usize::MAX,
                max_searches: usize::MAX,
                max_matches: usize::MAX,
                max_bytes_examined: usize::MAX,
                max_starts_injected: usize::MAX,
                max_state_visits: usize::MAX,
                max_tag_actions: usize::MAX,
                max_history_nodes: usize::MAX,
                max_history_walk: usize::MAX,
                max_history_reads: usize::MAX,
                max_materialization_reads: usize::MAX,
                max_materialization_writes: usize::MAX,
                max_materialization_preview_writes: usize::MAX,
                max_mask_states: usize::MAX,
                max_mask_word_copies: usize::MAX,
                max_mask_word_reads: usize::MAX,
                max_reset_cells: usize::MAX,
                max_capture_events: usize::MAX,
                max_capture_count: usize::MAX,
                max_line_source_reads: usize::MAX,
                max_work: usize::MAX,
            },
            max_peak_threads: usize::MAX,
            max_dynamic_allocations: 0,
        }
    }
}

impl Default for PriorityAggregateManyCaptureProjectionLimits {
    fn default() -> Self {
        Self {
            resources: CaptureStreamLimits::default(),
            max_peak_threads: usize::MAX,
            max_dynamic_allocations: 0,
        }
    }
}

/// One independently limited pre-source capture-session resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorityAggregateManyCaptureSessionResource {
    /// Retained selector-trace, projection-table, and reusable-stream bytes.
    PersistentBytes,
    /// Exact selector-session and projection initialization work.
    BuildWork,
    /// Setup allocations completed before source access.
    Allocations,
}

/// Independently bounded setup envelope for a caller-owned capture session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "each field deliberately mirrors one named pre-source resource ceiling"
)]
pub struct PriorityAggregateManyCaptureSessionLimits {
    /// Maximum retained selector-trace, projection-table, and reusable-stream
    /// bytes.
    pub max_persistent_bytes: usize,
    /// Maximum exact selector-session and projection initialization work.
    pub max_build_work: usize,
    /// Maximum setup allocations, all completed before haystack access.
    pub max_allocations: usize,
}

impl PriorityAggregateManyCaptureSessionLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_persistent_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_allocations: usize::MAX,
        }
    }
}

impl Default for PriorityAggregateManyCaptureSessionLimits {
    fn default() -> Self {
        Self {
            max_persistent_bytes: 512 << 20,
            max_build_work: 1 << 30,
            max_allocations: 1 << 20,
        }
    }
}

/// Exact setup accounting for one prepared multi-pattern capture session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureSessionAccounting {
    /// Fixed complete-source length bound into every reusable stream.
    pub source_bytes: usize,
    /// Number of source ordinals in the shared selector.
    pub patterns: usize,
    /// Sidecars that reduce every selected span by fixed cardinality.
    pub cardinality_sidecars: usize,
    /// Sidecars retaining an exact frontier and tag workspace.
    pub replay_workspaces: usize,
    /// Retained shared-selector trace workspace bytes.
    pub selector_trace_persistent_bytes: usize,
    /// Exact shared-selector trace initialization work performed before
    /// source access. This deliberately excludes any future source scan.
    pub selector_trace_build_work: usize,
    /// Shared-selector trace workspace allocations completed at setup.
    pub selector_trace_allocations: usize,
    /// Total retained selector-trace, projection-table, and stream storage.
    pub persistent_bytes: usize,
    /// Exact selector-session and projection construction work.
    pub build_work: usize,
    /// Exact setup allocation count.
    pub allocations: usize,
}

impl PriorityAggregateManyCaptureSessionAccounting {
    #[must_use]
    pub fn closes(self, limits: PriorityAggregateManyCaptureSessionLimits) -> bool {
        self.cardinality_sidecars
            .checked_add(self.replay_workspaces)
            == Some(self.patterns)
            && self.selector_trace_persistent_bytes <= self.persistent_bytes
            && self.selector_trace_build_work <= self.build_work
            && self.selector_trace_allocations <= self.allocations
            && self.persistent_bytes <= limits.max_persistent_bytes
            && self.build_work <= limits.max_build_work
            && self.allocations <= limits.max_allocations
    }
}

/// Limits for one capture-participation reduction driven by the shared
/// priority selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureRunLimits {
    /// Limits for the sole whole-haystack shared tagged-automaton pass.
    pub selector: PriorityAggregateManyRunLimits,
    /// Per-selected-span bounds for the exact capture projection.
    pub capture: CaptureSearchLimits,
    /// Bound for all session preparation before haystack access.
    pub session: PriorityAggregateManyCaptureSessionLimits,
    /// Complete construction and replay ceiling for every selected span.
    pub per_match_capture: PriorityAggregateManyCaptureProjectionLimits,
    /// Aggregate capture-sidecar ceiling across the entire operation.
    pub total_capture: PriorityAggregateManyCaptureProjectionLimits,
    /// Bound for the one permitted whole-input required-literal pass.
    pub required_literal: CaptureRequiredLiteralRunLimits,
    /// Maximum participating groups, including group zero, in the final
    /// count-only result.
    pub max_capture_count: u64,
}

impl PriorityAggregateManyCaptureRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            selector: PriorityAggregateManyRunLimits::unlimited(),
            capture: CaptureSearchLimits {
                max_state_visits: usize::MAX,
                max_slot_copies: usize::MAX,
                max_history_nodes: usize::MAX,
                max_history_walk: usize::MAX,
                max_scratch_bytes: usize::MAX,
            },
            session: PriorityAggregateManyCaptureSessionLimits::unlimited(),
            per_match_capture: PriorityAggregateManyCaptureProjectionLimits::unlimited(),
            total_capture: PriorityAggregateManyCaptureProjectionLimits::unlimited(),
            required_literal: CaptureRequiredLiteralRunLimits {
                max_transitions: usize::MAX,
            },
            max_capture_count: u64::MAX,
        }
    }
}

impl Default for PriorityAggregateManyCaptureRunLimits {
    fn default() -> Self {
        Self {
            selector: PriorityAggregateManyRunLimits::default(),
            capture: CaptureSearchLimits::default(),
            session: PriorityAggregateManyCaptureSessionLimits::default(),
            per_match_capture: PriorityAggregateManyCaptureProjectionLimits::default(),
            total_capture: PriorityAggregateManyCaptureProjectionLimits::default(),
            required_literal: CaptureRequiredLiteralRunLimits::default(),
            max_capture_count: u64::MAX,
        }
    }
}

/// Terminal source of a shared-selector capture-count failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum PriorityAggregateManyCaptureRunFailure {
    /// The sole shared selector did not complete.
    Selector(PriorityAggregateManyRunError),
    /// The selected ordinal was outside the immutable source-sidecar table.
    PatternOrdinal { ordinal: u32, patterns: usize },
    /// Exact-capacity caller-owned projection sessions could not be reserved.
    SessionAllocation { patterns: usize },
    /// Session setup exceeded one immutable pre-source resource ceiling.
    SessionLimit {
        resource: PriorityAggregateManyCaptureSessionResource,
        required: usize,
        limit: usize,
    },
    /// The one permitted whole-operation required-literal pass refused.
    RequiredLiteral(CaptureRequiredLiteralSearchError),
    /// A capture sidecar disagreed with a span selected from the same source
    /// profile, or exceeded its independently admitted exact replay bounds.
    Capture {
        pattern: usize,
        source: CaptureStreamError,
    },
    /// The checked participation sum exceeded the public output limit.
    CaptureCountLimit { needed: u64, limit: u64 },
    /// Aggregate exact-projection accounting exceeded a named stream resource.
    CaptureProjectionLimit {
        resource: CaptureStreamResource,
        required: usize,
        limit: usize,
    },
    /// Aggregate exact-projection frontier occupancy exceeded its independent cap.
    CaptureProjectionPeakThreads { required: usize, limit: usize },
    /// Prepared projection work unexpectedly allocated after session setup.
    CaptureProjectionAllocations { required: usize, limit: usize },
    /// Checked accumulation of capture participation overflowed.
    ArithmeticOverflow,
    /// An internally assembled result failed its immutable trace closure.
    InternalInvariant { detail: &'static str },
}

impl fmt::Display for PriorityAggregateManyCaptureRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector(source) => write!(formatter, "shared selector: {source}"),
            Self::PatternOrdinal { ordinal, patterns } => write!(
                formatter,
                "shared selector emitted ordinal {ordinal} outside {patterns} capture sidecars"
            ),
            Self::SessionAllocation { patterns } => write!(
                formatter,
                "could not reserve {patterns} shared capture projection sessions"
            ),
            Self::SessionLimit {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "capture session {resource:?} {required} exceeds limit {limit}"
            ),
            Self::RequiredLiteral(source) => write!(formatter, "whole required literal: {source}"),
            Self::Capture { pattern, source } => {
                write!(formatter, "capture sidecar {pattern}: {source}")
            }
            Self::CaptureCountLimit { needed, limit } => write!(
                formatter,
                "capture participation count {needed} exceeds limit {limit}"
            ),
            Self::CaptureProjectionLimit {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "aggregate capture projection {resource:?} {required} exceeds limit {limit}"
            ),
            Self::CaptureProjectionPeakThreads { required, limit } => write!(
                formatter,
                "aggregate capture projection peak threads {required} exceeds limit {limit}"
            ),
            Self::CaptureProjectionAllocations { required, limit } => write!(
                formatter,
                "aggregate capture projection allocations {required} exceed limit {limit}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("capture participation arithmetic overflow")
            }
            Self::InternalInvariant { detail } => {
                write!(
                    formatter,
                    "shared capture reducer invariant failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for PriorityAggregateManyCaptureRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selector(source) => Some(source),
            Self::Capture { source, .. } => Some(source),
            Self::RequiredLiteral(source) => Some(source),
            Self::PatternOrdinal { .. }
            | Self::SessionAllocation { .. }
            | Self::SessionLimit { .. }
            | Self::CaptureCountLimit { .. }
            | Self::CaptureProjectionLimit { .. }
            | Self::CaptureProjectionPeakThreads { .. }
            | Self::CaptureProjectionAllocations { .. }
            | Self::ArithmeticOverflow
            | Self::InternalInvariant { .. } => None,
        }
    }
}

fn enforce_capture_session_limits(
    accounting: PriorityAggregateManyCaptureSessionAccounting,
    limits: PriorityAggregateManyCaptureSessionLimits,
) -> Result<(), PriorityAggregateManyCaptureRunFailure> {
    for (resource, required, limit) in [
        (
            PriorityAggregateManyCaptureSessionResource::PersistentBytes,
            accounting.persistent_bytes,
            limits.max_persistent_bytes,
        ),
        (
            PriorityAggregateManyCaptureSessionResource::BuildWork,
            accounting.build_work,
            limits.max_build_work,
        ),
        (
            PriorityAggregateManyCaptureSessionResource::Allocations,
            accounting.allocations,
            limits.max_allocations,
        ),
    ] {
        if required > limit {
            return Err(PriorityAggregateManyCaptureRunFailure::SessionLimit {
                resource,
                required,
                limit,
            });
        }
    }
    if accounting.closes(limits) {
        Ok(())
    } else {
        Err(PriorityAggregateManyCaptureRunFailure::InternalInvariant {
            detail: "capture session setup accounting did not close",
        })
    }
}

/// A typed shared-selector capture-count failure with its full immutable
/// source/limit identity.
#[derive(Debug)]
pub struct PriorityAggregateManyCaptureRunError {
    pub limits: PriorityAggregateManyCaptureRunLimits,
    pub source: PriorityAggregateManyCaptureRunFailure,
}

impl fmt::Display for PriorityAggregateManyCaptureRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "forced Build-Many capture count: {}",
            self.source
        )
    }
}

impl std::error::Error for PriorityAggregateManyCaptureRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// One terminal forced-run failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyRunError {
    pub operation: PriorityAggregateManyOperation,
    pub execution: ForcedExecution,
    pub limits: PriorityAggregateManyRunLimits,
    pub source: PriorityAggregateManyRunFailure,
}

impl fmt::Display for PriorityAggregateManyRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "forced Build-Many {:?}/{:?}: {}",
            self.operation, self.execution, self.source
        )
    }
}

impl std::error::Error for PriorityAggregateManyRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Terminal source of a forced-run failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateManyRunFailure {
    BuildReportNotClosed,
    OutputLimit { needed: u64, limit: u64 },
    Execution(ReduceError),
}

impl fmt::Display for PriorityAggregateManyRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildReportNotClosed => formatter.write_str("build receipt no longer closes"),
            Self::OutputLimit { needed, limit } => {
                write!(
                    formatter,
                    "output upper bound {needed} exceeds limit {limit}"
                )
            }
            Self::Execution(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for PriorityAggregateManyRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Execution(source) => Some(source),
            Self::BuildReportNotClosed | Self::OutputLimit { .. } => None,
        }
    }
}

/// Immutable direct value plus its exact construction and execution ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyExecutionReceipt {
    schema_version: u32,
    accounting_id: &'static str,
    operation: PriorityAggregateManyOperation,
    execution: ForcedExecution,
    preparation: PreparationAccounting,
    tagged_stats: TaggedManyStats,
    prospective: ExecutionProspective,
    actual: ExecutionActual,
    value: u64,
    /// True only for a caller-owned reusable trace workspace whose setup owns
    /// the trace allocation while its steady execution reports zero new
    /// allocations.
    reused_trace_session: bool,
}

fn generic_tagged_execution_closes(
    stats: TaggedManyStats,
    prospective: ExecutionProspective,
    actual: &ExecutionActual,
) -> bool {
    let tagged_map_capacity = stats.states().checked_add(1);
    let tagged_state_evaluations = prospective.boundary_rows.checked_mul(stats.states());
    let tagged_edge_visits = prospective.boundary_rows.checked_mul(stats.edges());
    let tagged_group_publications = prospective
        .boundary_rows
        .checked_mul(stats.owner_state_memberships());
    tagged_map_capacity == Some(prospective.tagged_map_capacity)
        && prospective.tagged_group_capacity == stats.owner_state_memberships()
        && tagged_state_evaluations == Some(prospective.tagged_state_evaluations_upper_bound)
        && actual.tagged_state_evaluations == prospective.tagged_state_evaluations_upper_bound
        && tagged_edge_visits == Some(prospective.tagged_edge_visits_upper_bound)
        && tagged_group_publications == Some(prospective.tagged_group_publications_upper_bound)
        && actual.tagged_map_publications <= prospective.tagged_state_evaluations_upper_bound
        && actual.tagged_group_publications <= prospective.tagged_group_publications_upper_bound
}

fn shared_frontier_tagged_execution_closes(
    stats: TaggedManyStats,
    prospective: ExecutionProspective,
    actual: &ExecutionActual,
    reused_trace_session: bool,
    depth: usize,
    byte_start: u8,
    byte_end: u8,
) -> bool {
    let boundaries = actual.source_bytes.checked_add(1);
    let matches = u64::try_from(actual.match_events).ok();
    let source_bytes = u64::try_from(actual.source_bytes).ok();
    let boundaries_work = boundaries.and_then(|value| u64::try_from(value).ok());
    let traced = if reused_trace_session {
        Some(true)
    } else {
        match prospective.allocation_attempts {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    };
    let expected_scratch = traced.and_then(|trace| {
        if trace {
            boundaries.and_then(|rows| rows.checked_mul(size_of::<PriorityMatch>()))
        } else {
            Some(0)
        }
    });
    let expected_prospective_work =
        source_bytes
            .zip(boundaries_work)
            .zip(traced)
            .and_then(|((bytes, rows), trace)| {
                bytes.checked_add(rows).and_then(|base| {
                    if trace {
                        rows.checked_add(1)
                            .and_then(|trace_work| base.checked_add(trace_work))
                    } else {
                        Some(base)
                    }
                })
            });
    let expected_actual_work =
        source_bytes
            .zip(matches)
            .zip(traced)
            .and_then(|((bytes, events), trace)| {
                events
                    .checked_mul(if trace { 2 } else { 1 })
                    .and_then(|event_work| bytes.checked_add(event_work))
                    .and_then(|work| work.checked_add(u64::from(trace)))
            });
    let expected_span = matches.and_then(|events| {
        u64::try_from(depth)
            .ok()
            .and_then(|width| events.checked_mul(width))
    });
    shared_frontier_stats_close(stats, depth, byte_start, byte_end)
        && prospective.match_events_upper_bound == prospective.boundary_rows
        && prospective.tagged_state_evaluations_upper_bound == actual.source_bytes
        && prospective.tagged_edge_visits_upper_bound == actual.source_bytes
        && actual.tagged_state_evaluations == actual.source_bytes
        && actual.tagged_edge_visits == actual.source_bytes
        && prospective.tagged_map_capacity == 0
        && prospective.tagged_group_capacity == 0
        && prospective.tagged_group_publications_upper_bound == 0
        && actual.tagged_map_publications == 0
        && actual.tagged_group_publications == 0
        && actual.tagged_peak_maps == 0
        && actual.tagged_peak_groups == 0
        && expected_scratch == Some(prospective.scratch_bytes)
        && expected_prospective_work == Some(prospective.work_upper_bound)
        && expected_actual_work == Some(actual.work)
        && actual.empty_match_events == 0
        && actual.selected_ordinal_sum == 0
        && expected_span == Some(actual.selected_span_bytes)
        && expected_span
            .zip(source_bytes)
            .is_some_and(|(span, bytes)| span <= bytes)
}

impl PriorityAggregateManyExecutionReceipt {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub const fn accounting_id(&self) -> &'static str {
        self.accounting_id
    }

    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateManyOperation {
        self.operation
    }

    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        self.execution
    }

    #[must_use]
    pub const fn preparation(&self) -> PreparationAccounting {
        self.preparation
    }

    #[must_use]
    pub const fn tagged_stats(&self) -> TaggedManyStats {
        self.tagged_stats
    }

    #[must_use]
    pub const fn prospective(&self) -> ExecutionProspective {
        self.prospective
    }

    #[must_use]
    pub const fn actual(&self) -> ExecutionActual {
        self.actual
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Whether this receipt ran against caller-owned trace workspace whose
    /// allocation was admitted during session setup.
    #[must_use]
    pub const fn reuses_trace_session(&self) -> bool {
        self.reused_trace_session
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        let source_boundaries = self.actual.source_bytes.checked_add(1);
        let output_matches = u64::try_from(self.actual.match_events);
        let output_closes = match self.operation {
            PriorityAggregateManyOperation::Count => output_matches == Ok(self.value),
            PriorityAggregateManyOperation::SpanSum => {
                self.value == self.actual.selected_span_bytes
            }
        };
        let class_closes = match self.tagged_stats.execution_class() {
            TaggedManyExecutionClass::Generic => {
                generic_tagged_execution_closes(self.tagged_stats, self.prospective, &self.actual)
            }
            TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
                depth,
                byte_start,
                byte_end,
            } => shared_frontier_tagged_execution_closes(
                self.tagged_stats,
                self.prospective,
                &self.actual,
                self.reused_trace_session,
                depth,
                byte_start,
                byte_end,
            ),
            _ => false,
        };
        let tagged_memberships = self
            .tagged_stats
            .owner_state_memberships()
            .checked_add(self.tagged_stats.owner_edge_memberships());
        self.schema_version == PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION
            && self.accounting_id == PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID
            && self.execution == ForcedExecution::Sparse
            && self.prospective.tagged_execution_class == Some(self.tagged_stats.execution_class())
            && self.actual.boundary_rows == self.prospective.boundary_rows
            && source_boundaries == Some(self.prospective.boundary_rows)
            && self.actual.work <= self.prospective.work_upper_bound
            && self.actual.scratch_bytes == self.prospective.scratch_bytes
            && self.actual.match_events <= self.prospective.match_events_upper_bound
            && self.actual.dfa_states == 0
            && self.actual.dfa_cells == 0
            && self.actual.subset_items == 0
            && self.actual.dfa_transitions == 0
            && self.actual.lazy_cache_hits == 0
            && self.actual.lazy_cache_misses == 0
            && self.actual.lazy_cache_inserts == 0
            && self.actual.lazy_cache_evictions == 0
            && self.actual.generation_resets == 0
            && self.actual.sparse_root_evaluations == 0
            && self.actual.sparse_closure_visits == 0
            && self.actual.sparse_edge_visits == 0
            && self.actual.suffix_reducer_steps == 0
            && self.prospective.tagged_dispatch_states_capacity == 0
            && self.prospective.tagged_dispatch_cells_capacity == 0
            && self.prospective.tagged_candidate_items_capacity == 0
            && self.prospective.tagged_cache_cells_capacity == 0
            && self.actual.tagged_dispatch_states == 0
            && self.actual.tagged_dispatch_cells == 0
            && self.actual.tagged_candidate_items == 0
            && self.actual.tagged_cache_cells == 0
            && self.actual.tagged_cache_hits == 0
            && self.actual.tagged_cache_misses == 0
            && self.actual.tagged_cache_inserts == 0
            && self.actual.tagged_cache_evictions == 0
            && self.actual.tagged_state_evaluations
                <= self.prospective.tagged_state_evaluations_upper_bound
            && self.actual.tagged_edge_visits <= self.prospective.tagged_edge_visits_upper_bound
            && self.actual.tagged_peak_maps <= self.prospective.tagged_map_capacity
            && self.actual.tagged_peak_groups <= self.prospective.tagged_group_capacity
            && self.prospective.dfa_states_capacity == 0
            && self.prospective.dfa_cells_capacity == 0
            && self.prospective.subset_items_capacity == 0
            && self.tagged_stats.patterns() > 0
            && self.tagged_stats.patterns() <= 128
            && self.prospective.tagged_owner_capacity == self.tagged_stats.patterns()
            && class_closes
            && self.preparation.pattern_terminals == self.tagged_stats.patterns()
            && self.preparation.dfa_states == self.tagged_stats.states()
            && self.preparation.transition_cells == self.tagged_stats.edges()
            && tagged_memberships == Some(self.preparation.subset_items)
            && self.preparation.persistent_bytes == self.tagged_stats.persistent_bytes()
            && self.preparation.prospective.persistent_bytes == self.tagged_stats.persistent_bytes()
            && tagged_preparation_closes_against(self.preparation, PreparationLimits::unlimited())
            && self.actual.allocation_attempts == self.prospective.allocation_attempts
            && (!self.reused_trace_session || self.prospective.allocation_attempts == 0)
            && output_closes
    }
}

/// A forced Build-Many execution receipt with its preflighted ordinal trace.
///
/// Unlike a callback, this type owns exactly the trace capacity admitted by
/// the underlying sparse executor. It is intended for semantic differentials;
/// count and span-sum callers can continue using the no-trace methods.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyTraceReceipt {
    execution: PriorityAggregateManyExecutionReceipt,
    untraced_prospective: ExecutionProspective,
    matches: Vec<PriorityMatch>,
}

impl PriorityAggregateManyTraceReceipt {
    /// The direct value and execution ledger.
    #[must_use]
    pub const fn execution(&self) -> &PriorityAggregateManyExecutionReceipt {
        &self.execution
    }

    /// Pattern ordinals and selected spans in source order.
    #[must_use]
    pub fn matches(&self) -> &[PriorityMatch] {
        &self.matches
    }

    /// Exact pre-reserved number of ordinal trace entries.
    #[must_use]
    pub const fn trace_capacity(&self) -> usize {
        self.untraced_prospective.match_events_upper_bound
    }

    /// Consume the admitted trace receipt.
    #[must_use]
    pub fn into_parts(self) -> (PriorityAggregateManyExecutionReceipt, Vec<PriorityMatch>) {
        (self.execution, self.matches)
    }

    /// Verify that the trace closes against the direct-reducer ledger.
    ///
    /// This deliberately avoids rescanning the trace after the exact-work
    /// execution completes. The sparse executor records span and ordinal
    /// totals while it performs each prepaid push, and this receipt verifies
    /// the sealed vector's capacity and reservation delta in constant time.
    #[must_use]
    pub fn closes(&self) -> bool {
        let trace_capacity = self.untraced_prospective.match_events_upper_bound;
        let trace_bytes = trace_capacity.checked_mul(size_of::<PriorityMatch>());
        let trace_work = u64::try_from(trace_capacity)
            .ok()
            .and_then(|work| work.checked_add(1));
        let traced = self.execution.prospective();
        let actual = self.execution.actual();
        self.execution.closes()
            && traced.tagged_execution_class == self.untraced_prospective.tagged_execution_class
            && traced.boundary_rows == self.untraced_prospective.boundary_rows
            && traced.match_events_upper_bound == trace_capacity
            && traced.dfa_states_capacity == self.untraced_prospective.dfa_states_capacity
            && traced.dfa_cells_capacity == self.untraced_prospective.dfa_cells_capacity
            && traced.subset_items_capacity == self.untraced_prospective.subset_items_capacity
            && traced.tagged_dispatch_states_capacity
                == self.untraced_prospective.tagged_dispatch_states_capacity
            && traced.tagged_dispatch_cells_capacity
                == self.untraced_prospective.tagged_dispatch_cells_capacity
            && traced.tagged_candidate_items_capacity
                == self.untraced_prospective.tagged_candidate_items_capacity
            && traced.tagged_cache_cells_capacity
                == self.untraced_prospective.tagged_cache_cells_capacity
            && traced.tagged_state_evaluations_upper_bound
                == self
                    .untraced_prospective
                    .tagged_state_evaluations_upper_bound
            && traced.tagged_edge_visits_upper_bound
                == self.untraced_prospective.tagged_edge_visits_upper_bound
            && traced.tagged_map_capacity == self.untraced_prospective.tagged_map_capacity
            && traced.tagged_group_capacity == self.untraced_prospective.tagged_group_capacity
            && traced.tagged_group_publications_upper_bound
                == self
                    .untraced_prospective
                    .tagged_group_publications_upper_bound
            && traced.tagged_owner_capacity == self.untraced_prospective.tagged_owner_capacity
            && trace_bytes
                .and_then(|bytes| self.untraced_prospective.scratch_bytes.checked_add(bytes))
                == Some(traced.scratch_bytes)
            && self.untraced_prospective.allocation_attempts.checked_add(1)
                == Some(traced.allocation_attempts)
            && trace_work
                .and_then(|work| self.untraced_prospective.work_upper_bound.checked_add(work))
                == Some(traced.work_upper_bound)
            && self.matches.capacity() == trace_capacity
            && self.matches.len() == actual.match_events
            && actual.match_events <= trace_capacity
    }
}

/// Explicit forced Count artifact.
#[derive(Debug)]
pub struct PriorityAggregateManyCountRegex {
    plan: TaggedManyPlan<DirectCount>,
    report: PriorityAggregateManyBuildReport,
}

impl PriorityAggregateManyCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &PriorityAggregateManyBuildReport {
        &self.report
    }

    pub fn count(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyRunLimits,
    ) -> Result<PriorityAggregateManyExecutionReceipt, PriorityAggregateManyRunError> {
        run(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }

    /// Execute the same forced route with an admitted ordinal trace for a
    /// semantic oracle.
    pub fn count_trace(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyRunLimits,
    ) -> Result<PriorityAggregateManyTraceReceipt, PriorityAggregateManyRunError> {
        run_trace(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }
}

/// Immutable multi-pattern capture-count artifact.
///
/// Its `selector` is the same one-owner-tagged automaton used by ordinary
/// Count. Capture sidecars never search for another start, choose another
/// pattern, or apply a literal filter: they only project a span/ordinal that
/// the shared selector has already made irrevocable.
#[derive(Debug)]
pub struct PriorityAggregateManyCaptureCountRegex {
    selector: PriorityAggregateManyCountRegex,
    captures: Box<[CaptureRegex]>,
    whole_required_literal: Option<CaptureRequiredLiteralPlan>,
    whole_required_literal_identity: Arc<CacheKey>,
    whole_required_literal_receipt: PriorityAggregateManyWholeRequiredLiteralBuildReceipt,
    construction: PriorityAggregateManyCaptureConstructionAccounting,
}

/// Complete immutable build receipt for the forced multi-pattern
/// capture-count artifact.
///
/// This is a borrowing view rather than a duplicated graph of reports: the
/// selector and every capture sidecar retain their original authenticated
/// receipts, and `closes` cross-checks their exact common ordinal/policy
/// boundary.
#[derive(Debug)]
pub struct PriorityAggregateManyCaptureBuildReport<'a> {
    selector: &'a PriorityAggregateManyBuildReport,
    captures: &'a [CaptureRegex],
    whole_required_literal: Option<&'a CaptureRequiredLiteralPlan>,
    whole_required_literal_identity: &'a Arc<CacheKey>,
    whole_required_literal_receipt: &'a PriorityAggregateManyWholeRequiredLiteralBuildReceipt,
    construction: PriorityAggregateManyCaptureConstructionAccounting,
}

impl PriorityAggregateManyCaptureBuildReport<'_> {
    /// The shared ordered-selector receipt.
    #[must_use]
    pub const fn selector(&self) -> &PriorityAggregateManyBuildReport {
        self.selector
    }

    /// Per-ordinal capture sidecar receipts in source-pattern order.
    #[must_use]
    pub fn sidecars(&self) -> impl ExactSizeIterator<Item = &CaptureBuildReport> {
        self.captures.iter().map(CaptureRegex::build_report)
    }

    /// The one permitted whole-operation literal-proof disposition.
    #[must_use]
    pub const fn whole_required_literal(
        &self,
    ) -> &PriorityAggregateManyWholeRequiredLiteralBuildReceipt {
        self.whole_required_literal_receipt
    }

    /// Stable parser identity for the one ordered-union proof, retained even
    /// when the completed analysis publishes the explicit `NoProof` fallback.
    #[must_use]
    pub fn whole_required_literal_identity(&self) -> &CacheKey {
        self.whole_required_literal_identity
    }

    /// Aggregate sidecar/literal construction accounting.
    #[must_use]
    pub const fn construction(&self) -> PriorityAggregateManyCaptureConstructionAccounting {
        self.construction
    }

    /// Re-authenticate the selector, all ordinal sidecars, the literal
    /// disposition, and their common checked construction envelope.
    #[must_use]
    pub fn closes(&self) -> bool {
        let selector_limits = self.selector.limits();
        let limits = selector_limits.capture_build;
        let base_sidecar_limits = capture_sidecar_limits(limits.sidecar, &selector_limits);
        let table_bytes = self.captures.len().checked_mul(size_of::<CaptureRegex>());
        let whole_persistent = whole_required_literal_actual_persistent_bytes(
            self.whole_required_literal_identity,
            self.whole_required_literal,
        );
        let source_copy_peak = whole_required_literal_source_copy_peak_bytes(
            self.selector
                .patterns()
                .iter()
                .map(|pattern| pattern.syntax_key.pattern.as_bytes().len()),
        );
        let whole_peak = whole_required_literal_actual_peak_bytes(
            self.whole_required_literal_identity,
            self.whole_required_literal,
            self.selector.patterns().len(),
            source_copy_peak,
            selector_limits.syntax_safety,
        );
        let whole_bridge_allocations = whole_required_literal_direct_bridge_allocations(
            self.selector.patterns().len(),
            self.selector
                .patterns()
                .iter()
                .map(|pattern| pattern.syntax_key.pattern.as_bytes().len()),
        );
        let mut expected = PriorityAggregateManyCaptureConstructionAccounting {
            patterns: self.captures.len(),
            sidecar_persistent_bytes: table_bytes.unwrap_or(usize::MAX),
            sidecar_build_work: 0,
            sidecar_peak_bytes: 0,
            sidecar_table_allocations: usize::from(!self.captures.is_empty()),
            whole_literal_parser_work: self.whole_required_literal_receipt.parser_work(),
            whole_literal_planner_work: self.whole_required_literal_receipt.planner_work(),
            whole_literal_persistent_bytes: whole_persistent.unwrap_or(usize::MAX),
            whole_literal_peak_bytes: whole_peak.unwrap_or(usize::MAX),
            whole_literal_bridge_allocations: whole_bridge_allocations.unwrap_or(usize::MAX),
        };
        let sidecars_close =
            self.captures
                .iter()
                .zip(self.selector.patterns())
                .all(|(capture, selector)| {
                    let report = capture.build_report();
                    let mut expected_sidecar_limits = base_sidecar_limits;
                    expected_sidecar_limits.syntax_safety = selector.syntax_key.safety;
                    let limits_close = capture.build_limits() == expected_sidecar_limits;
                    let admission_close = report.admission == selector.admission;
                    let syntax_close = report.syntax == selector.syntax;
                    let key_close = report.plan_identity.syntax.as_ref() == &selector.syntax_key;
                    let capacity_close = report.plan_identity.syntax.pattern.capacity_bytes()
                        == selector.syntax_key.pattern.as_bytes().len();
                    let literal_close = report.required_literal.is_none()
                        && report.plan_identity.required_literal.is_none();
                    limits_close
                        && admission_close
                        && syntax_close
                        && key_close
                        && capacity_close
                        && literal_close
                        && accumulate_capture_sidecar_accounting(&mut expected, report).is_ok()
                });
        let selector_closes = self.selector.operation() == PriorityAggregateManyOperation::Count
            && self.selector.closes()
            && self.captures.len() == self.selector.patterns().len();
        let literal_closes = self.whole_required_literal_receipt.closes(
            self.whole_required_literal,
            self.whole_required_literal_identity,
            self.selector,
        );
        let construction_closes =
            expected == self.construction && self.construction.closes(&limits);
        selector_closes && sidecars_close && literal_closes && construction_closes
    }
}

impl PriorityAggregateManyCaptureCountRegex {
    /// Complete immutable capture artifact receipt, including the shared
    /// selector, every sidecar, and the one literal-proof disposition.
    #[must_use]
    pub fn build_report(&self) -> PriorityAggregateManyCaptureBuildReport<'_> {
        PriorityAggregateManyCaptureBuildReport {
            selector: self.selector.build_report(),
            captures: &self.captures,
            whole_required_literal: self.whole_required_literal.as_ref(),
            whole_required_literal_identity: &self.whole_required_literal_identity,
            whole_required_literal_receipt: &self.whole_required_literal_receipt,
            construction: self.construction,
        }
    }

    /// Shared-selector receipt retained for callers that need only the
    /// capture-erased tagged automaton construction boundary.
    #[must_use]
    pub const fn selector_build_report(&self) -> &PriorityAggregateManyBuildReport {
        self.selector.build_report()
    }

    /// Execute an owning selector trace for semantic diagnostics.
    ///
    /// This deliberately remains separate from [`Self::count_captures`]: the
    /// latter consumes a caller-owned reusable trace workspace and performs
    /// no steady-operation allocation, whereas this diagnostic API returns an
    /// owned trace vector.
    pub fn selector_trace(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyRunLimits,
    ) -> Result<PriorityAggregateManyTraceReceipt, PriorityAggregateManyRunError> {
        self.selector.count_trace(haystack, limits)
    }

    /// Number of independently compiled capture sidecars, one for every
    /// source ordinal retained by the tagged selector.
    #[must_use]
    pub const fn patterns(&self) -> usize {
        self.captures.len()
    }

    /// Capture-sidecar construction report for one source ordinal.
    #[must_use]
    pub fn capture_build_report(&self, ordinal: usize) -> Option<&CaptureBuildReport> {
        self.captures.get(ordinal).map(CaptureRegex::build_report)
    }

    /// Optional union-HIR proof used once per whole capture operation. `None`
    /// is a declared conservative fallback (for example, no universal
    /// required literal or the fixed proof envelope refusing a wide union).
    #[must_use]
    pub fn whole_required_literal_build_report(
        &self,
    ) -> Option<&CaptureRequiredLiteralBuildReport> {
        self.whole_required_literal
            .as_ref()
            .map(CaptureRequiredLiteralPlan::build_report)
    }

    /// Authenticated disposition of the one whole-operation literal proof.
    #[must_use]
    pub const fn whole_required_literal_build_receipt(
        &self,
    ) -> &PriorityAggregateManyWholeRequiredLiteralBuildReceipt {
        &self.whole_required_literal_receipt
    }

    /// Aggregate pre-source sidecar/literal construction accounting.
    #[must_use]
    pub const fn construction_accounting(
        &self,
    ) -> PriorityAggregateManyCaptureConstructionAccounting {
        self.construction
    }

    /// Prepare reusable exact-span capture workspaces for one fixed haystack
    /// size. Construction occurs before source access; repeated calls on the
    /// returned session reuse each ordinal's frontiers and tag workspace.
    #[allow(
        clippy::too_many_lines,
        clippy::large_types_passed_by_value,
        reason = "the atomic preflight and construction boundary retains the complete immutable run-limit identity in its returned session"
    )]
    pub fn prepare_capture_session(
        &self,
        source_bytes: usize,
        limits: PriorityAggregateManyCaptureRunLimits,
    ) -> Result<PriorityAggregateManyCaptureSession<'_>, PriorityAggregateManyCaptureRunError> {
        preflight_run_len(self.selector.build_report(), source_bytes, limits.selector).map_err(
            |source| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::Selector(source),
            },
        )?;
        let selector_setup = self
            .selector
            .plan
            .trace_session_setup_prospective(source_bytes, limits.selector.execution)
            .map_err(|source| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::Selector(run_error(
                    self.selector.build_report(),
                    limits.selector,
                    PriorityAggregateManyRunFailure::Execution(source),
                )),
            })?;
        let selector_setup_work =
            usize::try_from(selector_setup.initialization_work).map_err(|_| {
                PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                }
            })?;
        let table_bytes = self
            .captures
            .len()
            .checked_mul(size_of::<CaptureExactProjectionSession>())
            .ok_or(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
            })?;
        let mut accounting = PriorityAggregateManyCaptureSessionAccounting {
            source_bytes,
            patterns: self.captures.len(),
            cardinality_sidecars: 0,
            replay_workspaces: 0,
            selector_trace_persistent_bytes: selector_setup.persistent_bytes,
            selector_trace_build_work: selector_setup_work,
            selector_trace_allocations: selector_setup.allocation_attempts,
            persistent_bytes: table_bytes
                .checked_add(selector_setup.persistent_bytes)
                .ok_or(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                })?,
            build_work: self.captures.len().checked_add(selector_setup_work).ok_or(
                PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                },
            )?,
            allocations: usize::from(!self.captures.is_empty())
                .checked_add(selector_setup.allocation_attempts)
                .ok_or(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                })?,
        };
        for (pattern, sidecar) in self.captures.iter().enumerate() {
            match sidecar
                .exact_projection_stream_prospective(
                    source_bytes,
                    limits.capture,
                    limits.per_match_capture.resources,
                )
                .map_err(|source| PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::Capture { pattern, source },
                })? {
                Some(prospective) => {
                    accounting.replay_workspaces = accounting
                        .replay_workspaces
                        .checked_add(1)
                        .ok_or(PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        })?;
                    accounting.persistent_bytes = accounting
                        .persistent_bytes
                        .checked_add(prospective.allocator_bytes)
                        .ok_or(PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        })?;
                    accounting.build_work = accounting
                        .build_work
                        .checked_add(prospective.build_work)
                        .ok_or(PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        })?;
                    accounting.allocations = accounting
                        .allocations
                        .checked_add(prospective.allocations)
                        .ok_or(PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        })?;
                }
                None => {
                    accounting.cardinality_sidecars = accounting
                        .cardinality_sidecars
                        .checked_add(1)
                        .ok_or(PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        })?;
                }
            }
        }
        enforce_capture_session_limits(accounting, limits.session)
            .map_err(|source| PriorityAggregateManyCaptureRunError { limits, source })?;
        let selector_trace = self
            .selector
            .plan
            .prepare_trace_session(source_bytes, limits.selector.execution)
            .map_err(|source| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::Selector(run_error(
                    self.selector.build_report(),
                    limits.selector,
                    PriorityAggregateManyRunFailure::Execution(source),
                )),
            })?;
        if !selector_setup.closes() || selector_trace.setup_prospective_receipt() != selector_setup
        {
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "capture selector session diverged from preflight envelope",
                },
            });
        }
        let mut projections = Vec::new();
        projections
            .try_reserve_exact(self.captures.len())
            .map_err(|_| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::SessionAllocation {
                    patterns: self.captures.len(),
                },
            })?;
        for (pattern, sidecar) in self.captures.iter().enumerate() {
            let projection = sidecar
                .prepare_exact_projection_session(
                    source_bytes,
                    limits.capture,
                    limits.per_match_capture.resources,
                )
                .map_err(|source| PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::Capture { pattern, source },
                })?;
            let expected = sidecar
                .exact_projection_stream_prospective(
                    source_bytes,
                    limits.capture,
                    limits.per_match_capture.resources,
                )
                .map_err(|source| PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::Capture { pattern, source },
                })?;
            if projection.stream_prospective() != expected {
                return Err(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                        detail: "capture projection session diverged from preflight envelope",
                    },
                });
            }
            projections.push(projection);
        }
        if projections.len() != self.captures.len() || projections.capacity() != self.captures.len()
        {
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "capture projection session table lost its source ordinal shape",
                },
            });
        }
        let required_literal_identity = self
            .whole_required_literal
            .as_ref()
            .map(|plan| plan.candidate_cache_identity(limits.required_literal));
        Ok(PriorityAggregateManyCaptureSession {
            artifact: self,
            selector_trace,
            selector_setup,
            projections: projections.into_boxed_slice(),
            source_bytes,
            limits,
            accounting,
            required_literal_identity,
        })
    }

    /// Count participating groups, including group zero, for every selected
    /// non-overlapping match.
    ///
    /// The method executes exactly one whole-haystack shared tagged automaton
    /// pass. Its trace fixes the source ordinal and prioritized span before a
    /// sidecar projects capture participation as a fixed cardinality, a
    /// quotient mask, or exact persistent history.
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the returned reusable session retains the complete immutable run-limit identity"
    )]
    pub fn count_captures(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyCaptureRunLimits,
    ) -> Result<PriorityAggregateManyCaptureCountResult, PriorityAggregateManyCaptureRunError> {
        self.prepare_capture_session(haystack.len(), limits)?
            .count_captures(haystack)
    }
}

/// Caller-owned reusable capture projection session for one immutable shared
/// selector and fixed haystack length. The selector remains the sole
/// whole-input priority pass; this session only projects spans it selected.
#[derive(Debug)]
pub struct PriorityAggregateManyCaptureSession<'a> {
    artifact: &'a PriorityAggregateManyCaptureCountRegex,
    selector_trace: TaggedManyTraceSession<'a, DirectCount>,
    selector_setup: TaggedManyTraceSessionSetupProspective,
    projections: Box<[CaptureExactProjectionSession]>,
    source_bytes: usize,
    limits: PriorityAggregateManyCaptureRunLimits,
    accounting: PriorityAggregateManyCaptureSessionAccounting,
    required_literal_identity: Option<CaptureRequiredLiteralCacheIdentity>,
}

impl PriorityAggregateManyCaptureSession<'_> {
    /// Immutable pre-source setup receipt for the reusable workspace table.
    #[must_use]
    pub const fn accounting(&self) -> PriorityAggregateManyCaptureSessionAccounting {
        self.accounting
    }

    /// Run the shared selector and project every selected span through the
    /// already-admitted ordinal workspace table.
    #[allow(
        clippy::too_many_lines,
        reason = "one operation retains the whole-input literal gate, selector, per-ordinal projection, and closed aggregate receipt together"
    )]
    pub fn count_captures(
        &mut self,
        haystack: &[u8],
    ) -> Result<PriorityAggregateManyCaptureCountResult, PriorityAggregateManyCaptureRunError> {
        let limits = self.limits;
        if haystack.len() != self.source_bytes {
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "capture session haystack length differs from its admitted workspace",
                },
            });
        }
        let required_literal = self
            .artifact
            .whole_required_literal
            .as_ref()
            .map(|plan| plan.is_candidate(haystack, limits.required_literal))
            .transpose()
            .map_err(|source| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::RequiredLiteral(source),
            })?;
        if required_literal
            .as_ref()
            .is_some_and(|report| !report.candidate)
        {
            let result = PriorityAggregateManyCaptureCountResult {
                value: 0,
                matches: 0,
                cardinality_matches: 0,
                mask_matches: 0,
                persistent_history_matches: 0,
                capture_accounting: CaptureStreamAccounting::default(),
                capture_projection_limits: limits.total_capture,
                required_literal_limits: limits.required_literal,
                limits,
                session_accounting: self.accounting,
                selector_setup: self.selector_setup,
                per_match_projection: PriorityAggregateManyCaptureProjectionReceipt::default(),
                required_literal_identity: self.required_literal_identity.clone(),
                required_literal,
                selector_skipped_by_required_literal: true,
                selector_receipt: None,
                trace: None,
            };
            if result.closes() {
                return Ok(result);
            }
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "negative whole-operation literal gate did not close",
                },
            });
        }
        let trace = self
            .selector_trace
            .execute_trace(haystack)
            .map_err(|source| PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::Selector(run_error(
                    self.artifact.selector.build_report(),
                    limits.selector,
                    PriorityAggregateManyRunFailure::Execution(source),
                )),
            })?;
        let selector_execution = finish_trace_session_run(
            self.artifact.selector.build_report(),
            limits.selector,
            trace.report(),
            |report| *report.output(),
        )
        .map_err(|source| PriorityAggregateManyCaptureRunError {
            limits,
            source: PriorityAggregateManyCaptureRunFailure::Selector(source),
        })?;
        let selector_receipt = PriorityAggregateManyCaptureSelectorReceipt {
            execution: selector_execution,
            setup: trace.setup_prospective_receipt(),
            trace_capacity: trace.trace_capacity(),
        };
        if !trace.closes() || !selector_receipt.closes() {
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "capture selector session receipt did not close",
                },
            });
        }
        let mut value = 0_u64;
        let mut cardinality_matches = 0_u64;
        let mut mask_matches = 0_u64;
        let mut persistent_history_matches = 0_u64;
        let mut capture_accounting = CaptureStreamAccounting::default();
        let mut projection_matches = 0_u64;
        let mut per_match_projection = PriorityAggregateManyCaptureProjectionReceipt::default();

        for selected in trace.matches() {
            let ordinal = selected.ordinal().get();
            let pattern =
                usize::try_from(ordinal).map_err(|_| PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::PatternOrdinal {
                        ordinal,
                        patterns: self.projections.len(),
                    },
                })?;
            let Some(projection_session) = self.projections.get_mut(pattern) else {
                return Err(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::PatternOrdinal {
                        ordinal,
                        patterns: self.projections.len(),
                    },
                });
            };
            let (projection, accounting) = projection_session
                .project(
                    haystack,
                    CaptureSpan {
                        start: selected.start(),
                        end: selected.end(),
                    },
                )
                .map_err(|source| PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::Capture { pattern, source },
                })?;
            let entries = projection.entries();
            enforce_capture_projection_limits(accounting, 1, entries, limits.per_match_capture)
                .map_err(|source| PriorityAggregateManyCaptureRunError { limits, source })?;
            per_match_projection
                .record(accounting, entries)
                .map_err(|source| PriorityAggregateManyCaptureRunError { limits, source })?;
            accumulate_capture_projection_accounting(&mut capture_accounting, accounting)
                .map_err(|source| PriorityAggregateManyCaptureRunError { limits, source })?;
            projection_matches =
                projection_matches
                    .checked_add(1)
                    .ok_or(PriorityAggregateManyCaptureRunError {
                        limits,
                        source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                    })?;
            enforce_capture_projection_limits(
                capture_accounting,
                projection_matches,
                value
                    .checked_add(entries)
                    .ok_or(PriorityAggregateManyCaptureRunError {
                        limits,
                        source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                    })?,
                limits.total_capture,
            )
            .map_err(|source| PriorityAggregateManyCaptureRunError { limits, source })?;
            value = value
                .checked_add(entries)
                .ok_or(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                })?;
            if value > limits.max_capture_count {
                return Err(PriorityAggregateManyCaptureRunError {
                    limits,
                    source: PriorityAggregateManyCaptureRunFailure::CaptureCountLimit {
                        needed: value,
                        limit: limits.max_capture_count,
                    },
                });
            }
            match projection {
                ExactCaptureParticipation::Cardinality(_) => {
                    cardinality_matches = cardinality_matches.checked_add(1).ok_or(
                        PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        },
                    )?;
                }
                ExactCaptureParticipation::MaskCount(_) => {
                    mask_matches = mask_matches.checked_add(1).ok_or(
                        PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        },
                    )?;
                }
                ExactCaptureParticipation::PersistentHistory(_) => {
                    persistent_history_matches = persistent_history_matches.checked_add(1).ok_or(
                        PriorityAggregateManyCaptureRunError {
                            limits,
                            source: PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow,
                        },
                    )?;
                }
            }
        }
        let result = PriorityAggregateManyCaptureCountResult {
            value,
            matches: selector_receipt.execution().value(),
            cardinality_matches,
            mask_matches,
            persistent_history_matches,
            capture_accounting,
            capture_projection_limits: limits.total_capture,
            required_literal_limits: limits.required_literal,
            limits,
            session_accounting: self.accounting,
            selector_setup: self.selector_setup,
            per_match_projection,
            required_literal_identity: self.required_literal_identity.clone(),
            required_literal,
            selector_skipped_by_required_literal: false,
            selector_receipt: Some(selector_receipt),
            trace: None,
        };
        if !result.closes() {
            return Err(PriorityAggregateManyCaptureRunError {
                limits,
                source: PriorityAggregateManyCaptureRunFailure::InternalInvariant {
                    detail: "capture participation result did not close its shared trace",
                },
            });
        }
        Ok(result)
    }
}

fn accumulate_capture_projection_accounting(
    total: &mut CaptureStreamAccounting,
    delta: CaptureStreamAccounting,
) -> Result<(), PriorityAggregateManyCaptureRunFailure> {
    macro_rules! add {
        ($field:ident) => {
            total.$field = total
                .$field
                .checked_add(delta.$field)
                .ok_or(PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow)?;
        };
    }
    add!(line_domains);
    add!(searches);
    add!(state_visits);
    add!(tag_actions);
    add!(history_nodes);
    add!(history_walk);
    add!(history_reads);
    add!(materialization_reads);
    add!(materialization_writes);
    add!(materialization_preview_writes);
    add!(mask_states);
    add!(mask_word_copies);
    add!(mask_word_reads);
    add!(reset_cells);
    add!(capture_events);
    add!(line_source_reads);
    add!(bytes_examined);
    add!(starts_injected);
    add!(work);
    add!(allocations);
    total.peak_threads = total.peak_threads.max(delta.peak_threads);
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "every independently named projection resource is checked together at the one closed enforcement boundary"
)]
fn enforce_capture_projection_limits(
    accounting: CaptureStreamAccounting,
    matches: u64,
    capture_count: u64,
    limits: PriorityAggregateManyCaptureProjectionLimits,
) -> Result<(), PriorityAggregateManyCaptureRunFailure> {
    let matches = usize::try_from(matches)
        .map_err(|_| PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow)?;
    let capture_count = usize::try_from(capture_count)
        .map_err(|_| PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow)?;
    macro_rules! check {
        ($resource:expr, $actual:expr, $limit:expr) => {
            if $actual > $limit {
                return Err(
                    PriorityAggregateManyCaptureRunFailure::CaptureProjectionLimit {
                        resource: $resource,
                        required: $actual,
                        limit: $limit,
                    },
                );
            }
        };
    }
    let resources = limits.resources;
    check!(
        CaptureStreamResource::LineDomains,
        accounting.line_domains,
        resources.max_line_domains
    );
    check!(
        CaptureStreamResource::Searches,
        accounting.searches,
        resources.max_searches
    );
    check!(
        CaptureStreamResource::Matches,
        matches,
        resources.max_matches
    );
    check!(
        CaptureStreamResource::CaptureCount,
        capture_count,
        resources.max_capture_count
    );
    check!(
        CaptureStreamResource::BytesExamined,
        accounting.bytes_examined,
        resources.max_bytes_examined
    );
    check!(
        CaptureStreamResource::StartsInjected,
        accounting.starts_injected,
        resources.max_starts_injected
    );
    check!(
        CaptureStreamResource::StateVisits,
        accounting.state_visits,
        resources.max_state_visits
    );
    check!(
        CaptureStreamResource::TagActions,
        accounting.tag_actions,
        resources.max_tag_actions
    );
    check!(
        CaptureStreamResource::HistoryNodes,
        accounting.history_nodes,
        resources.max_history_nodes
    );
    check!(
        CaptureStreamResource::HistoryWalk,
        accounting.history_walk,
        resources.max_history_walk
    );
    check!(
        CaptureStreamResource::HistoryReads,
        accounting.history_reads,
        resources.max_history_reads
    );
    check!(
        CaptureStreamResource::MaterializationReads,
        accounting.materialization_reads,
        resources.max_materialization_reads
    );
    check!(
        CaptureStreamResource::MaterializationWrites,
        accounting.materialization_writes,
        resources.max_materialization_writes
    );
    check!(
        CaptureStreamResource::MaterializationPreviewWrites,
        accounting.materialization_preview_writes,
        resources.max_materialization_preview_writes
    );
    check!(
        CaptureStreamResource::MaskStates,
        accounting.mask_states,
        resources.max_mask_states
    );
    check!(
        CaptureStreamResource::MaskWordCopies,
        accounting.mask_word_copies,
        resources.max_mask_word_copies
    );
    check!(
        CaptureStreamResource::MaskWordReads,
        accounting.mask_word_reads,
        resources.max_mask_word_reads
    );
    check!(
        CaptureStreamResource::ResetCells,
        accounting.reset_cells,
        resources.max_reset_cells
    );
    check!(
        CaptureStreamResource::CaptureEvents,
        accounting.capture_events,
        resources.max_capture_events
    );
    check!(
        CaptureStreamResource::LineSourceReads,
        accounting.line_source_reads,
        resources.max_line_source_reads
    );
    check!(
        CaptureStreamResource::Work,
        accounting.work,
        resources.max_work
    );
    if accounting.peak_threads > limits.max_peak_threads {
        return Err(
            PriorityAggregateManyCaptureRunFailure::CaptureProjectionPeakThreads {
                required: accounting.peak_threads,
                limit: limits.max_peak_threads,
            },
        );
    }
    if accounting.allocations > limits.max_dynamic_allocations {
        return Err(
            PriorityAggregateManyCaptureRunFailure::CaptureProjectionAllocations {
                required: accounting.allocations,
                limit: limits.max_dynamic_allocations,
            },
        );
    }
    Ok(())
}

/// Compact allocation-free steady selector receipt retained by a capture
/// result. The ordinal/span trace itself remains in the caller-owned session
/// workspace and is consumed before this value is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureSelectorReceipt {
    execution: PriorityAggregateManyExecutionReceipt,
    setup: TaggedManyTraceSessionSetupProspective,
    trace_capacity: usize,
}

impl PriorityAggregateManyCaptureSelectorReceipt {
    /// Shared selector execution receipt for this steady operation.
    #[must_use]
    pub const fn execution(&self) -> &PriorityAggregateManyExecutionReceipt {
        &self.execution
    }

    /// One-time trace-workspace envelope admitted during session preparation.
    #[must_use]
    pub const fn setup_prospective(&self) -> ExecutionProspective {
        self.setup.steady_traced_prospective
    }

    /// Exact preparation receipt for the caller-owned trace workspace.
    #[must_use]
    pub const fn setup(&self) -> TaggedManyTraceSessionSetupProspective {
        self.setup
    }

    /// Exact ordinal trace capacity retained by the caller-owned session.
    #[must_use]
    pub const fn trace_capacity(&self) -> usize {
        self.trace_capacity
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.setup.closes()
            && self.execution.closes()
            && self.execution.reuses_trace_session()
            && self.execution.prospective() == self.setup.steady_traced_prospective
            && self.execution.actual().allocation_attempts == 0
            && self.trace_capacity == self.setup.trace_capacity
            && self.execution.actual().match_events <= self.trace_capacity
    }
}

fn selector_setup_accounting_closes(
    accounting: PriorityAggregateManyCaptureSessionAccounting,
    setup: &TaggedManyTraceSessionSetupProspective,
) -> bool {
    setup.closes()
        && accounting.selector_trace_persistent_bytes == setup.persistent_bytes
        && usize::try_from(setup.initialization_work).ok()
            == Some(accounting.selector_trace_build_work)
        && accounting.selector_trace_allocations == setup.allocation_attempts
        && accounting.source_bytes == setup.source_bytes
        && accounting.source_bytes.checked_add(1)
            == Some(setup.steady_traced_prospective.boundary_rows)
}

fn selector_session_accounting_closes(
    accounting: PriorityAggregateManyCaptureSessionAccounting,
    selector: &PriorityAggregateManyCaptureSelectorReceipt,
) -> bool {
    selector_setup_accounting_closes(accounting, &selector.setup())
}

fn required_literal_search_closes(
    expected: Option<&CaptureRequiredLiteralCacheIdentity>,
    report: Option<&CaptureRequiredLiteralSearchReport>,
    source_bytes: usize,
    limits: CaptureRequiredLiteralRunLimits,
) -> bool {
    match (expected, report) {
        (None, None) => true,
        (Some(expected), Some(report)) => {
            expected.operation == CaptureRequiredLiteralSearchOperation::CandidateV1
                && expected.run_limits == limits
                && report.identity == *expected
                && report.identity.operation == CaptureRequiredLiteralSearchOperation::CandidateV1
                && report.identity.run_limits == limits
                && report.accounting.searched_bytes == source_bytes
                && source_bytes.checked_add(1) == Some(report.accounting.transitions_upper_bound)
                && report.accounting.transitions_upper_bound <= limits.max_transitions
                && report.accounting.scratch_bytes == 0
        }
        _ => false,
    }
}

/// Exact sealed maxima for the individual ordinal projections contributing to
/// one capture-count operation.
///
/// The aggregate capture accounting is not sufficient to prove a caller's
/// per-match limit identity. This compact receipt retains a componentwise
/// maximum and the largest participation contribution without storing an
/// allocation-backed record for every selected span.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureProjectionReceipt {
    /// Number of spans projected by the already-selected shared trace.
    pub matches: u64,
    /// Sum of participation entries; it must equal the public result value.
    pub entries: u64,
    /// Componentwise maximum capture-stream accounting for one projection.
    pub maximum_accounting: CaptureStreamAccounting,
    /// Largest participating-group contribution from one selected span.
    pub maximum_entries: u64,
}

impl PriorityAggregateManyCaptureProjectionReceipt {
    fn record(
        &mut self,
        accounting: CaptureStreamAccounting,
        entries: u64,
    ) -> Result<(), PriorityAggregateManyCaptureRunFailure> {
        self.matches = self
            .matches
            .checked_add(1)
            .ok_or(PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow)?;
        self.entries = self
            .entries
            .checked_add(entries)
            .ok_or(PriorityAggregateManyCaptureRunFailure::ArithmeticOverflow)?;
        self.maximum_entries = self.maximum_entries.max(entries);
        macro_rules! max {
            ($field:ident) => {
                self.maximum_accounting.$field =
                    self.maximum_accounting.$field.max(accounting.$field);
            };
        }
        max!(line_domains);
        max!(searches);
        max!(state_visits);
        max!(tag_actions);
        max!(history_nodes);
        max!(history_walk);
        max!(history_reads);
        max!(materialization_reads);
        max!(materialization_writes);
        max!(materialization_preview_writes);
        max!(mask_states);
        max!(mask_word_copies);
        max!(mask_word_reads);
        max!(reset_cells);
        max!(capture_events);
        max!(line_source_reads);
        max!(bytes_examined);
        max!(starts_injected);
        max!(work);
        max!(allocations);
        max!(peak_threads);
        Ok(())
    }

    fn closes(
        self,
        aggregate: CaptureStreamAccounting,
        limits: PriorityAggregateManyCaptureProjectionLimits,
    ) -> bool {
        let matches = u64::from(self.matches != 0);
        let empty_closes = self.matches != 0
            || (self.entries == 0
                && self.maximum_entries == 0
                && self.maximum_accounting == CaptureStreamAccounting::default());
        let maximum_within_aggregate = {
            let maximum = self.maximum_accounting;
            maximum.line_domains <= aggregate.line_domains
                && maximum.searches <= aggregate.searches
                && maximum.state_visits <= aggregate.state_visits
                && maximum.tag_actions <= aggregate.tag_actions
                && maximum.history_nodes <= aggregate.history_nodes
                && maximum.history_walk <= aggregate.history_walk
                && maximum.history_reads <= aggregate.history_reads
                && maximum.materialization_reads <= aggregate.materialization_reads
                && maximum.materialization_writes <= aggregate.materialization_writes
                && maximum.materialization_preview_writes
                    <= aggregate.materialization_preview_writes
                && maximum.mask_states <= aggregate.mask_states
                && maximum.mask_word_copies <= aggregate.mask_word_copies
                && maximum.mask_word_reads <= aggregate.mask_word_reads
                && maximum.reset_cells <= aggregate.reset_cells
                && maximum.capture_events <= aggregate.capture_events
                && maximum.line_source_reads <= aggregate.line_source_reads
                && maximum.bytes_examined <= aggregate.bytes_examined
                && maximum.starts_injected <= aggregate.starts_injected
                && maximum.work <= aggregate.work
                && maximum.allocations <= aggregate.allocations
                && maximum.peak_threads == aggregate.peak_threads
        };
        empty_closes
            && self.maximum_entries <= self.entries
            && maximum_within_aggregate
            && enforce_capture_projection_limits(
                self.maximum_accounting,
                matches,
                self.maximum_entries,
                limits,
            )
            .is_ok()
    }
}

/// Capture-count result and the single shared selection trace that drove it.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateManyCaptureCountResult {
    value: u64,
    matches: u64,
    cardinality_matches: u64,
    mask_matches: u64,
    persistent_history_matches: u64,
    capture_accounting: CaptureStreamAccounting,
    capture_projection_limits: PriorityAggregateManyCaptureProjectionLimits,
    required_literal_limits: CaptureRequiredLiteralRunLimits,
    limits: PriorityAggregateManyCaptureRunLimits,
    session_accounting: PriorityAggregateManyCaptureSessionAccounting,
    selector_setup: TaggedManyTraceSessionSetupProspective,
    per_match_projection: PriorityAggregateManyCaptureProjectionReceipt,
    required_literal_identity: Option<CaptureRequiredLiteralCacheIdentity>,
    required_literal: Option<CaptureRequiredLiteralSearchReport>,
    selector_skipped_by_required_literal: bool,
    selector_receipt: Option<PriorityAggregateManyCaptureSelectorReceipt>,
    /// Legacy one-shot diagnostic trace. Steady capture sessions deliberately
    /// leave this empty because their ordinal buffer remains caller-owned.
    trace: Option<PriorityAggregateManyTraceReceipt>,
}

impl PriorityAggregateManyCaptureCountResult {
    /// Participating groups, including group zero, over all selected matches.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Number of matches selected by the shared tagged automaton.
    #[must_use]
    pub const fn matches(&self) -> u64 {
        self.matches
    }

    /// Matches reduced directly by a proved fixed cardinality.
    #[must_use]
    pub const fn cardinality_matches(&self) -> u64 {
        self.cardinality_matches
    }

    /// Matches reduced by the fixed participation mask quotient.
    #[must_use]
    pub const fn mask_matches(&self) -> u64 {
        self.mask_matches
    }

    /// Matches whose genuine ambiguity required persistent history.
    #[must_use]
    pub const fn persistent_history_matches(&self) -> u64 {
        self.persistent_history_matches
    }

    /// Exact aggregate of all reusable sidecar replay counters. The selector
    /// has a separate immutable execution receipt; this value contains only
    /// capture projection work and must report zero dynamic allocations.
    #[must_use]
    pub const fn capture_accounting(&self) -> CaptureStreamAccounting {
        self.capture_accounting
    }

    /// Complete immutable run-limit identity used by this result.
    #[must_use]
    pub const fn limits(&self) -> PriorityAggregateManyCaptureRunLimits {
        self.limits
    }

    /// The pre-source reusable selector/capture workspace envelope that
    /// admitted this operation.
    #[must_use]
    pub const fn session_accounting(&self) -> PriorityAggregateManyCaptureSessionAccounting {
        self.session_accounting
    }

    /// One-time selector trace-workspace envelope retained by the session,
    /// including the allocations deliberately absent from steady runs.
    #[must_use]
    pub const fn selector_setup_prospective(&self) -> ExecutionProspective {
        self.selector_setup.steady_traced_prospective
    }

    /// Exact one-time selector-session accounting, distinct from the
    /// allocation-free steady operation prospective.
    #[must_use]
    pub const fn selector_setup(&self) -> TaggedManyTraceSessionSetupProspective {
        self.selector_setup
    }

    /// Sealed per-projection maxima used to re-authenticate the independent
    /// per-match capture limit identity.
    #[must_use]
    pub const fn per_match_projection(&self) -> PriorityAggregateManyCaptureProjectionReceipt {
        self.per_match_projection
    }

    /// Whether the optional whole-operation required-literal proof ran and
    /// found any candidate byte sequence.
    #[must_use]
    pub const fn required_literal_candidate(&self) -> Option<bool> {
        match self.required_literal.as_ref() {
            Some(report) => Some(report.candidate),
            None => None,
        }
    }

    /// A negative union literal proof is the only case that skips the shared
    /// selector. All other runs retain a complete selector trace.
    #[must_use]
    pub const fn selector_skipped_by_required_literal(&self) -> bool {
        self.selector_skipped_by_required_literal
    }

    /// The sole shared ordinal/span selection pass.
    #[must_use]
    pub const fn trace(&self) -> Option<&PriorityAggregateManyTraceReceipt> {
        self.trace.as_ref()
    }

    /// Allocation-free steady selector receipt. Its trace was consumed while
    /// projecting captures and remains in the reusable session workspace.
    #[must_use]
    pub const fn selector_receipt(&self) -> Option<&PriorityAggregateManyCaptureSelectorReceipt> {
        self.selector_receipt.as_ref()
    }

    /// Check that the branch partition and output agree with the immutable
    /// shared trace. Individual capture projections are checked before they
    /// contribute to this result, so this closure remains O(1).
    #[must_use]
    pub fn closes(&self) -> bool {
        let branches = self
            .cardinality_matches
            .checked_add(self.mask_matches)
            .and_then(|count| count.checked_add(self.persistent_history_matches));
        let selector_closes = match (
            &self.selector_receipt,
            &self.required_literal,
            self.selector_skipped_by_required_literal,
        ) {
            (Some(selector), Some(literal), false) => {
                required_literal_search_closes(
                    self.required_literal_identity.as_ref(),
                    Some(literal),
                    self.session_accounting.source_bytes,
                    self.required_literal_limits,
                ) && literal.candidate
                    && selector.closes()
                    && selector_session_accounting_closes(self.session_accounting, selector)
                    && self.selector_setup == selector.setup()
                    && self.matches == selector.execution().value()
            }
            (Some(selector), None, false) => {
                required_literal_search_closes(
                    self.required_literal_identity.as_ref(),
                    None,
                    self.session_accounting.source_bytes,
                    self.required_literal_limits,
                ) && selector.closes()
                    && selector_session_accounting_closes(self.session_accounting, selector)
                    && self.selector_setup == selector.setup()
                    && self.matches == selector.execution().value()
            }
            (None, Some(literal), true) => {
                required_literal_search_closes(
                    self.required_literal_identity.as_ref(),
                    Some(literal),
                    self.session_accounting.source_bytes,
                    self.required_literal_limits,
                ) && !literal.candidate
                    && self.matches == 0
                    && self.value == 0
            }
            _ => false,
        };
        selector_closes
            && self.trace.is_none()
            && branches == Some(self.matches)
            && self.value >= self.matches
            && self.capture_projection_limits == self.limits.total_capture
            && self.required_literal_limits == self.limits.required_literal
            && self.session_accounting.closes(self.limits.session)
            && selector_setup_accounting_closes(self.session_accounting, &self.selector_setup)
            && self.per_match_projection.matches == self.matches
            && self.per_match_projection.entries == self.value
            && self
                .per_match_projection
                .closes(self.capture_accounting, self.limits.per_match_capture)
            && enforce_capture_projection_limits(
                self.capture_accounting,
                self.matches,
                self.value,
                self.capture_projection_limits,
            )
            .is_ok()
    }
}

/// Explicit forced `SpanSum` artifact.
#[derive(Debug)]
pub struct PriorityAggregateManySpanSumRegex {
    plan: TaggedManyPlan<DirectSpanSum>,
    report: PriorityAggregateManyBuildReport,
}

impl PriorityAggregateManySpanSumRegex {
    #[must_use]
    pub const fn build_report(&self) -> &PriorityAggregateManyBuildReport {
        &self.report
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyRunLimits,
    ) -> Result<PriorityAggregateManyExecutionReceipt, PriorityAggregateManyRunError> {
        run(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }

    /// Execute the same forced route with an admitted ordinal trace for a
    /// semantic oracle.
    pub fn span_sum_trace(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateManyRunLimits,
    ) -> Result<PriorityAggregateManyTraceReceipt, PriorityAggregateManyRunError> {
        run_trace(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }
}

fn run<O, F>(
    plan: &TaggedManyPlan<O>,
    build: &PriorityAggregateManyBuildReport,
    haystack: &[u8],
    limits: PriorityAggregateManyRunLimits,
    value: F,
) -> Result<PriorityAggregateManyExecutionReceipt, PriorityAggregateManyRunError>
where
    O: fre_automata::DirectReduceValue<Output = u64>,
    F: FnOnce(&DirectReduceReport<u64>) -> u64,
{
    preflight_run(build, haystack, limits)?;
    let report = plan.execute(haystack, limits.execution).map_err(|source| {
        run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(source),
        )
    })?;
    finish_run(build, limits, &report, value)
}

fn run_trace<O, F>(
    plan: &TaggedManyPlan<O>,
    build: &PriorityAggregateManyBuildReport,
    haystack: &[u8],
    limits: PriorityAggregateManyRunLimits,
    value: F,
) -> Result<PriorityAggregateManyTraceReceipt, PriorityAggregateManyRunError>
where
    O: fre_automata::DirectReduceValue<Output = u64>,
    F: FnOnce(&DirectReduceReport<u64>) -> u64,
{
    preflight_run(build, haystack, limits)?;
    let trace = plan
        .execute_trace(haystack, limits.execution)
        .map_err(|source| {
            run_error(
                build,
                limits,
                PriorityAggregateManyRunFailure::Execution(source),
            )
        })?;
    if !trace.closes() {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(ReduceError::InternalInvariant {
                detail: "forced Build-Many trace report did not close",
            }),
        ));
    }
    let untraced_prospective = trace.untraced_prospective();
    let execution = finish_run(build, limits, trace.report(), value)?;
    let (_, matches) = trace.into_parts();
    let receipt = PriorityAggregateManyTraceReceipt {
        execution,
        untraced_prospective,
        matches,
    };
    if !receipt.closes() {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(ReduceError::InternalInvariant {
                detail: "forced Build-Many trace receipt did not close",
            }),
        ));
    }
    Ok(receipt)
}

fn preflight_run(
    build: &PriorityAggregateManyBuildReport,
    haystack: &[u8],
    limits: PriorityAggregateManyRunLimits,
) -> Result<(), PriorityAggregateManyRunError> {
    preflight_run_len(build, haystack.len(), limits)
}

fn preflight_run_len(
    build: &PriorityAggregateManyBuildReport,
    source_bytes: usize,
    limits: PriorityAggregateManyRunLimits,
) -> Result<(), PriorityAggregateManyRunError> {
    // Publication performed the full, prepaid receipt closure exactly once.
    // The owned artifact is immutable thereafter, so execution needs only the
    // sealed O(1) bit rather than a fresh O(patterns) metadata traversal.
    if !build.validated {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::BuildReportNotClosed,
        ));
    }
    let needed = match build.operation {
        PriorityAggregateManyOperation::Count => source_bytes
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok()),
        PriorityAggregateManyOperation::SpanSum => u64::try_from(source_bytes).ok(),
    }
    .ok_or_else(|| {
        run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(ReduceError::ArithmeticOverflow {
                computation: "forced Build-Many output upper bound",
            }),
        )
    })?;
    if needed > limits.max_output {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::OutputLimit {
                needed,
                limit: limits.max_output,
            },
        ));
    }
    Ok(())
}

fn finish_run<F>(
    build: &PriorityAggregateManyBuildReport,
    limits: PriorityAggregateManyRunLimits,
    report: &DirectReduceReport<u64>,
    value: F,
) -> Result<PriorityAggregateManyExecutionReceipt, PriorityAggregateManyRunError>
where
    F: FnOnce(&DirectReduceReport<u64>) -> u64,
{
    let receipt = PriorityAggregateManyExecutionReceipt {
        schema_version: PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
        accounting_id: PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID,
        operation: build.operation,
        execution: build.execution,
        preparation: build.preparation,
        tagged_stats: build.automaton,
        prospective: report.prospective(),
        actual: report.actual(),
        value: value(report),
        reused_trace_session: false,
    };
    if !receipt.closes() {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(ReduceError::InternalInvariant {
                detail: "forced Build-Many execution receipt did not close",
            }),
        ));
    }
    Ok(receipt)
}

fn finish_trace_session_run<F>(
    build: &PriorityAggregateManyBuildReport,
    limits: PriorityAggregateManyRunLimits,
    report: &DirectReduceReport<u64>,
    value: F,
) -> Result<PriorityAggregateManyExecutionReceipt, PriorityAggregateManyRunError>
where
    F: FnOnce(&DirectReduceReport<u64>) -> u64,
{
    let receipt = PriorityAggregateManyExecutionReceipt {
        schema_version: PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION,
        accounting_id: PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID,
        operation: build.operation,
        execution: build.execution,
        preparation: build.preparation,
        tagged_stats: build.automaton,
        prospective: report.prospective(),
        actual: report.actual(),
        value: value(report),
        reused_trace_session: true,
    };
    if !receipt.closes() {
        return Err(run_error(
            build,
            limits,
            PriorityAggregateManyRunFailure::Execution(ReduceError::InternalInvariant {
                detail: "forced Build-Many reusable trace execution receipt did not close",
            }),
        ));
    }
    Ok(receipt)
}

fn run_error(
    build: &PriorityAggregateManyBuildReport,
    limits: PriorityAggregateManyRunLimits,
    source: PriorityAggregateManyRunFailure,
) -> PriorityAggregateManyRunError {
    PriorityAggregateManyRunError {
        operation: build.operation,
        execution: build.execution,
        limits,
        source,
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    fn frontier(depth: usize) -> PriorityAggregateManyCountRegex {
        let source = format!("[a-z]{{{depth}}}");
        PriorityAggregateManyBuilder::new(&vec![source; 8])
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
    }

    fn single_owner_frontier() -> PriorityAggregateManyCountRegex {
        PriorityAggregateManyBuilder::new(&["[a-z]".to_owned()])
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
    }

    fn alternate_range_frontier() -> PriorityAggregateManyCountRegex {
        PriorityAggregateManyBuilder::new(&vec!["[b-z]".to_owned(); 8])
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
    }

    fn generic() -> PriorityAggregateManyCountRegex {
        PriorityAggregateManyBuilder::new(&["[a-z]".to_owned(), "[b-z]".to_owned()])
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap()
    }

    #[test]
    fn public_execution_receipt_rejects_stale_identity_and_cross_class_dimensions() {
        let haystack = vec![b'a'; 32];
        let shared = frontier(1);
        let generic = generic();
        let receipt = shared
            .count(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        let generic_receipt = generic
            .count(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        assert!(receipt.closes());
        assert!(generic_receipt.closes());

        let mut malformed = receipt.clone();
        malformed.schema_version -= 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.accounting_id = "fre.priority-aggregate-many.facade.v2";
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.prospective.tagged_execution_class = Some(TaggedManyExecutionClass::Generic);
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.prospective.tagged_map_capacity = 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.prospective.tagged_dispatch_states_capacity = 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.actual.tagged_cache_hits = 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.actual.tagged_state_evaluations -= 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.preparation.persistent_bytes += 1;
        malformed.preparation.prospective.persistent_bytes += 1;
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.actual.match_events = haystack.len() + 1;
        malformed.actual.selected_span_bytes = u64::try_from(haystack.len() + 1).unwrap();
        malformed.actual.work = u64::try_from(haystack.len() * 2 + 1).unwrap();
        malformed.value = u64::try_from(haystack.len() + 1).unwrap();
        assert!(!malformed.closes());

        let mut malformed = receipt.clone();
        malformed.prospective = generic_receipt.prospective;
        assert!(!malformed.closes());

        let mut malformed = generic_receipt.clone();
        malformed.prospective = receipt.prospective;
        assert!(!malformed.closes());

        let mut malformed = generic_receipt.clone();
        malformed.actual.tagged_state_evaluations -= 1;
        assert!(!malformed.closes());

        let alternate_range = alternate_range_frontier()
            .count(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        let mut malformed = receipt.clone();
        malformed.tagged_stats = alternate_range.tagged_stats;
        assert!(!malformed.closes());

        let single_owner = single_owner_frontier()
            .count(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        let mut malformed = receipt;
        malformed.tagged_stats = single_owner.tagged_stats;
        malformed.prospective.tagged_execution_class =
            Some(single_owner.tagged_stats.execution_class());
        assert!(!malformed.closes());
    }

    #[test]
    fn trace_and_build_receipts_reject_classification_and_identity_corruption() {
        let haystack = vec![b'a'; 32];
        let mut trace = frontier(1)
            .count_trace(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        assert!(trace.closes());
        trace.untraced_prospective.tagged_execution_class = Some(TaggedManyExecutionClass::Generic);
        assert!(!trace.closes());

        let mut trace = frontier(1)
            .count_trace(&haystack, PriorityAggregateManyRunLimits::unlimited())
            .unwrap();
        trace.untraced_prospective.tagged_cache_cells_capacity = 1;
        assert!(!trace.closes());

        let mut stale = frontier(1);
        assert!(stale.report.closes());
        stale.report.schema_version -= 1;
        assert!(!stale.report.closes());

        let mut preparation_seam = frontier(1);
        preparation_seam
            .report
            .preparation
            .prospective
            .tagged_dispatch_states = 1;
        assert!(!preparation_seam.report.closes());

        let mut malformed = frontier(1);
        let owner_checks = malformed.report.tagged_build.classification_owner_checks;
        malformed.report.tagged_build.classification_owner_checks = owner_checks - 1;
        malformed
            .report
            .composition
            .tagged_build
            .classification_owner_checks = owner_checks - 1;
        assert!(!malformed.report.closes());

        let mut stale_tagged = frontier(1);
        stale_tagged.report.tagged_build.accounting_id = "fre.automata.tagged-many.v1";
        stale_tagged.report.composition.tagged_build.accounting_id = "fre.automata.tagged-many.v1";
        assert!(!stale_tagged.report.closes());
    }

    #[test]
    fn generic_classification_receipt_rejects_impossible_phase_prefixes() {
        let shape_pass = generic();
        let shape_pass_stats = shape_pass.report.automaton;
        let shape_pass_build = shape_pass.report.tagged_build;
        assert_eq!(
            shape_pass_stats.edges().checked_add(1),
            Some(shape_pass_stats.states())
        );
        assert!(tagged_classification_closes(
            shape_pass_stats,
            shape_pass_build
        ));
        let mut omitted_owner_phase = shape_pass_build;
        omitted_owner_phase.classification_owner_checks = 0;
        omitted_owner_phase.classification_state_checks = 0;
        omitted_owner_phase.classification_edge_checks = 0;
        omitted_owner_phase.classification_work = 2;
        assert!(!tagged_classification_closes(
            shape_pass_stats,
            omitted_owner_phase
        ));

        let shape_fail = PriorityAggregateManyBuilder::new(&["a+".to_owned(), "b+".to_owned()])
            .unicode(false)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let shape_fail_stats = shape_fail.report.automaton;
        let shape_fail_build = shape_fail.report.tagged_build;
        assert_ne!(
            shape_fail_stats.edges().checked_add(1),
            Some(shape_fail_stats.states())
        );
        assert!(tagged_classification_closes(
            shape_fail_stats,
            shape_fail_build
        ));
        let mut invented_owner_phase = shape_fail_build;
        invented_owner_phase.classification_owner_checks = 1;
        invented_owner_phase.classification_state_checks = 0;
        invented_owner_phase.classification_edge_checks = 0;
        invented_owner_phase.classification_work = 3;
        assert!(!tagged_classification_closes(
            shape_fail_stats,
            invented_owner_phase
        ));
    }

    #[test]
    fn positive_width_uniform_sidecars_need_no_exact_workspace() {
        let values = vec!["(a)".repeat(65), "z".to_owned()];
        let regex = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let mut limits = PriorityAggregateManyCaptureRunLimits::default();
        let resources = &mut limits.per_match_capture.resources;
        resources.max_source_bytes = 0;
        resources.max_states = 0;
        resources.max_build_work = 0;
        resources.max_persistent_bytes = 0;
        resources.max_combined_peak_bytes = 0;
        resources.max_allocations = 0;
        resources.max_matches = 1;
        resources.max_capture_count = 66;
        let haystack = vec![b'a'; 65];
        let mut session = regex
            .prepare_capture_session(haystack.len(), limits)
            .unwrap();
        assert_eq!(2, session.accounting().cardinality_sidecars);
        assert_eq!(0, session.accounting().replay_workspaces);
        assert!(session.accounting().closes(limits.session));
        let result = session.count_captures(&haystack).unwrap();
        assert_eq!(1, result.matches());
        assert_eq!(66, result.value());
        assert_eq!(1, result.cardinality_matches());
        assert_eq!(0, result.capture_accounting().work);
        assert!(result.closes());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test keeps exact-cap and one-below identities adjacent to their shared baseline"
    )]
    fn capture_session_and_projection_limits_admit_exact_and_refuse_one_below() {
        let values = vec!["(?:a|(ab))c".to_owned()];
        let regex = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let haystack = b"abcabc";
        let baseline = regex
            .count_captures(haystack, PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        assert_eq!(2, baseline.matches());
        assert!(baseline.capture_accounting().reset_cells > 0);

        let baseline_session = regex
            .prepare_capture_session(
                haystack.len(),
                PriorityAggregateManyCaptureRunLimits::default(),
            )
            .unwrap()
            .accounting();
        assert_eq!(
            u64::try_from(baseline_session.selector_trace_build_work).unwrap(),
            baseline.selector_setup().initialization_work
        );
        assert!(
            baseline.selector_setup().initialization_work
                < baseline.selector_setup_prospective().work_upper_bound
        );
        let mut session_exact = PriorityAggregateManyCaptureRunLimits::default();
        session_exact.session.max_persistent_bytes = baseline_session.persistent_bytes;
        session_exact.session.max_build_work = baseline_session.build_work;
        session_exact.session.max_allocations = baseline_session.allocations;
        assert!(
            regex
                .prepare_capture_session(haystack.len(), session_exact)
                .is_ok()
        );
        let mut session_one_below = session_exact;
        session_one_below.session.max_persistent_bytes = baseline_session
            .persistent_bytes
            .checked_sub(1)
            .expect("session retains storage");
        let session_error = regex
            .prepare_capture_session(haystack.len(), session_one_below)
            .expect_err("one below session storage must refuse before allocation");
        assert!(matches!(
            session_error.source,
            PriorityAggregateManyCaptureRunFailure::SessionLimit {
                resource: PriorityAggregateManyCaptureSessionResource::PersistentBytes,
                required,
                limit,
            } if required == baseline_session.persistent_bytes
                && limit == session_one_below.session.max_persistent_bytes
        ));

        let mut work_one_below = session_exact;
        work_one_below.session.max_build_work = baseline_session
            .build_work
            .checked_sub(1)
            .expect("session initialization performs work");
        let work_error = regex
            .prepare_capture_session(haystack.len(), work_one_below)
            .expect_err("one below session initialization work must refuse before allocation");
        assert!(matches!(
            work_error.source,
            PriorityAggregateManyCaptureRunFailure::SessionLimit {
                resource: PriorityAggregateManyCaptureSessionResource::BuildWork,
                required,
                limit,
            } if required == baseline_session.build_work
                && limit == work_one_below.session.max_build_work
        ));

        let mut allocations_one_below = session_exact;
        allocations_one_below.session.max_allocations = baseline_session
            .allocations
            .checked_sub(1)
            .expect("session owns allocations");
        let allocations_error = regex
            .prepare_capture_session(haystack.len(), allocations_one_below)
            .expect_err("one below session allocation cap must refuse before allocation");
        assert!(matches!(
            allocations_error.source,
            PriorityAggregateManyCaptureRunFailure::SessionLimit {
                resource: PriorityAggregateManyCaptureSessionResource::Allocations,
                required,
                limit,
            } if required == baseline_session.allocations
                && limit == allocations_one_below.session.max_allocations
        ));

        let mut total_exact = PriorityAggregateManyCaptureRunLimits::default();
        total_exact.total_capture.resources.max_reset_cells =
            baseline.capture_accounting().reset_cells;
        let exact = regex.count_captures(haystack, total_exact).unwrap();
        assert_eq!(baseline.capture_accounting(), exact.capture_accounting());
        assert!(exact.closes());
        let mut total_one_below = total_exact;
        total_one_below.total_capture.resources.max_reset_cells = baseline
            .capture_accounting()
            .reset_cells
            .checked_sub(1)
            .expect("two replay epochs reset cells");
        let total_error = regex
            .count_captures(haystack, total_one_below)
            .expect_err("one below aggregate reset cap must refuse");
        assert!(matches!(
            total_error.source,
            PriorityAggregateManyCaptureRunFailure::CaptureProjectionLimit {
                resource: CaptureStreamResource::ResetCells,
                required,
                limit,
            } if required == baseline.capture_accounting().reset_cells
                && limit == total_one_below.total_capture.resources.max_reset_cells
        ));

        let single = regex
            .count_captures(b"abc", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        let mut per_match_one_below = PriorityAggregateManyCaptureRunLimits::default();
        per_match_one_below
            .per_match_capture
            .resources
            .max_reset_cells = single
            .capture_accounting()
            .reset_cells
            .checked_sub(1)
            .expect("one replay resets cells");
        let per_match_error = regex
            .count_captures(b"abc", per_match_one_below)
            .expect_err("one below exact replay reset cap must retain its resource identity");
        assert!(matches!(
            per_match_error.source,
            PriorityAggregateManyCaptureRunFailure::Capture {
                pattern: 0,
                source: CaptureStreamError::Resource {
                    resource: CaptureStreamResource::ResetCells,
                    required,
                    limit,
                },
            } if required == single.capture_accounting().reset_cells
                && limit == per_match_one_below.per_match_capture.resources.max_reset_cells
        ));
    }

    #[test]
    fn capture_build_receipt_closes_across_sidecar_and_union_literal_owners() {
        let values = vec!["([a-z])".to_owned(), "([0-9])".to_owned()];
        let regex = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        assert!(regex.build_report().closes());
    }

    #[test]
    fn whole_literal_bridge_ledger_seals_exact_source_copies() {
        let patterns = vec![String::new(), "AB".to_owned(), "WXYZ".to_owned()];
        assert_eq!(
            whole_operation_literal_identity_len(&patterns).unwrap(),
            "frewholeliteralq".len() + patterns.len() + 2 * (2 + 4)
        );
        assert_eq!(
            whole_required_literal_source_copy_peak_bytes(patterns.iter().map(String::len)),
            4
        );
        assert_eq!(
            whole_required_literal_direct_bridge_allocations(
                patterns.len(),
                patterns.iter().map(String::len),
            )
            .unwrap(),
            5,
            "identity, Arc, exact root table, and two nonempty source copies"
        );
        assert_eq!(
            capacity_bytes::<Hir>(patterns.len(), "test exact root table").unwrap(),
            patterns.len() * size_of::<Hir>()
        );
        let source = copy_whole_required_literal_source("WXYZ").unwrap();
        assert_eq!(source.len(), 4);
        assert_eq!(source.capacity(), 4);
        assert_eq!(
            copy_whole_required_literal_source("").unwrap().capacity(),
            0
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "cross-owner, exact-capacity, planner, and run-receipt mutations share one construction fixture"
    )]
    fn capture_receipts_reject_cross_owner_and_run_receipt_mutations() {
        let values = vec!["([a-z])".to_owned(), "([0-9])".to_owned()];
        let mut sidecars = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        assert!(sidecars.build_report().closes());
        sidecars.captures.swap(0, 1);
        assert!(!sidecars.build_report().closes());

        let mut bridge = PriorityAggregateManyBuilder::new(&values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        assert!(bridge.build_report().closes());
        bridge.construction.whole_literal_bridge_allocations -= 1;
        assert!(!bridge.build_report().closes());

        let no_proof_values = vec!["(a)".to_owned()];
        let mut no_proof = PriorityAggregateManyBuilder::new(&no_proof_values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        assert!(matches!(
            no_proof.whole_required_literal_receipt,
            PriorityAggregateManyWholeRequiredLiteralBuildReceipt::NoProof { .. }
        ));
        let mut oversized_source = whole_operation_literal_identity_source(&no_proof_values)
            .expect("encoded NoProof identity source");
        oversized_source
            .try_reserve_exact(1)
            .expect("oversized forged identity source");
        let original_identity = &no_proof.whole_required_literal_identity;
        let parsed = fre_syntax::parse(
            ParseRequest::rust(oversized_source, original_identity.profile.clone())
                .with_admission(original_identity.admission)
                .with_safety_envelope(original_identity.safety),
        )
        .expect("same bytes remain a valid literal-only parser key");
        assert_eq!(
            parsed.key.pattern.as_bytes(),
            original_identity.pattern.as_bytes()
        );
        assert!(
            parsed.key.pattern.capacity_bytes() > original_identity.pattern.capacity_bytes(),
            "the forged key retains the same bytes with excess source capacity"
        );
        no_proof.whole_required_literal_identity = Arc::new(parsed.key);
        let source_copy_peak = whole_required_literal_source_copy_peak_bytes(
            no_proof
                .selector
                .build_report()
                .patterns()
                .iter()
                .map(|pattern| pattern.syntax_key.pattern.as_bytes().len()),
        );
        no_proof.construction.whole_literal_persistent_bytes =
            whole_required_literal_actual_persistent_bytes(
                &no_proof.whole_required_literal_identity,
                no_proof.whole_required_literal.as_ref(),
            )
            .unwrap();
        no_proof.construction.whole_literal_peak_bytes = whole_required_literal_actual_peak_bytes(
            &no_proof.whole_required_literal_identity,
            no_proof.whole_required_literal.as_ref(),
            no_proof.selector.build_report().patterns().len(),
            source_copy_peak,
            no_proof.selector.build_report().limits().syntax_safety,
        )
        .unwrap();
        assert!(
            !no_proof.build_report().closes(),
            "same bytes with excess identity capacity must not close"
        );
        no_proof.whole_required_literal_identity = Arc::new(
            no_proof.selector.build_report().patterns()[0]
                .syntax_key
                .clone(),
        );
        assert!(!no_proof.build_report().closes());

        let mut malformed_planner = PriorityAggregateManyBuilder::new(&no_proof_values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let planner_limit = malformed_planner
            .selector
            .build_report()
            .limits()
            .capture_build
            .whole_required_literal
            .max_planner_work;
        let malformed_planner_work = planner_limit.checked_add(1).unwrap();
        let PriorityAggregateManyWholeRequiredLiteralBuildReceipt::NoProof { planner_work, .. } =
            &mut malformed_planner.whole_required_literal_receipt
        else {
            panic!("single literal fixture must use the explicit NoProof receipt");
        };
        *planner_work = malformed_planner_work;
        malformed_planner.construction.whole_literal_planner_work = malformed_planner_work;
        assert!(
            !malformed_planner.build_report().closes(),
            "NoProof planner work must remain within its published proof limit"
        );

        let run_values = vec![
            r"(?:a|(ab))c".to_owned(),
            r"(?:(d)|(e))f".to_owned(),
            r"(?P<g>g)".to_owned(),
        ];
        let regex = PriorityAggregateManyBuilder::new(&run_values)
            .unicode(false)
            .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .unwrap();
        let baseline = regex
            .count_captures(b"abcdfg", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        assert!(baseline.closes());
        assert!(baseline.required_literal.is_some());
        assert!(baseline.capture_accounting.work > 0);

        let mut malformed = regex
            .count_captures(b"abcdfg", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        malformed.per_match_projection.maximum_accounting.work =
            malformed.capture_accounting.work.checked_add(1).unwrap();
        assert!(!malformed.closes());

        let mut malformed = regex
            .count_captures(b"abcdfg", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        malformed
            .required_literal
            .as_mut()
            .unwrap()
            .identity
            .operation = CaptureRequiredLiteralSearchOperation::LinePartitionMatchesV1;
        assert!(!malformed.closes());

        let mut malformed = regex
            .count_captures(b"abcdfg", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        malformed
            .required_literal
            .as_mut()
            .unwrap()
            .accounting
            .searched_bytes += 1;
        assert!(!malformed.closes());

        let mut malformed = regex
            .count_captures(b"abcdfg", PriorityAggregateManyCaptureRunLimits::default())
            .unwrap();
        malformed.selector_setup.initialization_work += 1;
        assert!(!malformed.closes());
    }
}
