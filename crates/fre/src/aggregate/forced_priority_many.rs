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

use fre_automata::{
    ActionCapabilities, CompileError, CompileLimits, DirectCount, DirectReduceLimits,
    DirectReduceReport, DirectSpanSum, EdgeKind, EmptyMatchProgress, ExecutionActual,
    ExecutionProspective, ForcedExecution, MatchLengthProof, PreparationAccounting,
    PreparationError, PreparationLimits, PreparationProspective, PreparationResource,
    PriorityMatch, PriorityTarget, RawPlan, ReduceError, StateRole, TAGGED_MANY_ACCOUNTING_ID,
    TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS, TaggedManyBuildAccounting, TaggedManyBuildError,
    TaggedManyBuildLimits, TaggedManyExecutionClass, TaggedManyPlan, TaggedManyStats,
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

/// Schema for the forced ordered Build-Many receipt.
pub const PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION: u32 = 3;
/// Stable accounting identity for this forced-only bridge.
pub const PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID: &str = "fre.priority-aggregate-many.facade.v3";

// Three source/report vectors are admitted before the first bridge-owned
// allocation. The tagged substrate separately seals every construction
// allocation; lowering owns each per-pattern raw-plan allocation.
const FACADE_ALLOCATION_ATTEMPTS: usize = 3;
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
        }
    }
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
        if self.profile.options.unicode {
            return Err(PriorityAggregateManyBuildError::UnsupportedUnicodeProfile);
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
    depth: usize,
    byte_start: u8,
    byte_end: u8,
) -> bool {
    let boundaries = actual.source_bytes.checked_add(1);
    let matches = u64::try_from(actual.match_events).ok();
    let source_bytes = u64::try_from(actual.source_bytes).ok();
    let boundaries_work = boundaries.and_then(|value| u64::try_from(value).ok());
    let traced = match prospective.allocation_attempts {
        0 => Some(false),
        1 => Some(true),
        _ => None,
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
        PriorityAggregateManyOperation::Count => haystack
            .len()
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok()),
        PriorityAggregateManyOperation::SpanSum => u64::try_from(haystack.len()).ok(),
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
}
