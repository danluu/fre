//! Honest operation-specific facade for the currently certified FRE subsets.
//!
//! [`PortableRegex`] provides bounded single-search operations for the HIR
//! subset that `fre-lower` can prove exact. [`AggregateBuilder`] constructs
//! separate complete-span, count, or matched-byte-sum plans for the bounded
//! `fre-aggregate` Rust-byte subset. [`AggregateManyBuilder`] retains each
//! pattern's syntax identity and composes ordered whole-match count/span-sum
//! plans without source concatenation. Whole-match aggregate plans may erase
//! capture annotations, but no capture group API is exposed. None of these
//! types is named `Regex`: unsupported syntax/profile/operation combinations
//! are typed build errors, and there is no full Rust-regex/RE2 or JIT claim.

#![forbid(unsafe_code)]

use core::fmt;

mod aggregate;
mod aggregate_many;
mod finite;
mod forward_anchored;
mod required_literal;
mod unicode_compile;

pub use aggregate::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuildLimits, AggregateBuildReport, AggregateBuilder, AggregateCacheIdentity,
    AggregateCaptureSemantics, AggregateCompileRegex, AggregateContinuationIdentity,
    AggregateContinuationSemantics, AggregateCountRegex, AggregateCountResult,
    AggregateExactLiteralIdentity, AggregateExactLiteralSemantics, AggregateExecutionDetails,
    AggregateExecutionError, AggregateExecutionReport, AggregateExecutionSource,
    AggregateFiniteLiteralBuildAccounting, AggregateFiniteLiteralIdentity,
    AggregateLiteralIneligibility, AggregateOperation, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateRunLimits, AggregateSpanIter, AggregateSpanSumRegex,
    AggregateSpanSumResult, AggregateSpans, AggregateSpansRegex, AggregateStrategy,
};
pub use aggregate_many::{
    AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION, AggregateManyBuildAccounting, AggregateManyBuildError,
    AggregateManyBuildLimits, AggregateManyBuildReport, AggregateManyBuilder,
    AggregateManyCompositionAccounting, AggregateManyCountRegex, AggregateManyCountResult,
    AggregateManyExecutionDetails, AggregateManyExecutionError, AggregateManyExecutionSource,
    AggregateManyLiteralSemantics, AggregateManyOperation, AggregateManyOutput,
    AggregateManyPatternReport, AggregateManyPlanIdentity, AggregateManyPlanKind,
    AggregateManyRegex, AggregateManyRunLimits, AggregateManySpanSumRegex,
    AggregateManySpanSumResult,
};
pub use fre_aggregate::{
    CompileAccounting as AggregateCompileAccounting, CompileLimits as AggregateCompileLimits,
    Error as AggregateEngineError, ExecutionAccounting as AggregateExecutionAccounting,
    OperationCertificate as AggregateOperationCertificate, OperationId as AggregateOperationId,
    OperationLimits as AggregateOperationLimits, PlanId as AggregatePlanId,
    Resource as AggregateResource, Unsupported as AggregateUnsupported,
};
pub use fre_kernels::{
    LiteralAggregateActualCounters, LiteralAggregateBuildAccounting, LiteralAggregateBuildError,
    LiteralAggregateBuildLimits, LiteralAggregateOperation, LiteralAggregateOperationIdentity,
    LiteralAggregateReduceAccounting, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    LiteralAggregateUpperBounds, OrderedLiteralAggregateActualCounters,
    OrderedLiteralAggregateBuildAccounting, OrderedLiteralAggregateBuildError,
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, OrderedLiteralAggregateUpperBounds,
};

use fre_automata::{Automaton, Exists, SelectedEnd, Span};
use fre_kernels::{
    AbsoluteEndFixedPlan, ForwardAnchoredBuildAccounting, ForwardAnchoredBuildError,
    ForwardAnchoredBuildLimits, ForwardAnchoredPlan, ForwardAnchoredSearchAccounting,
    ForwardAnchoredSearchError, ForwardAnchoredSearchLimits, LiteralAccounting, LiteralBuildLimits,
    LiteralError, LiteralPlan, LiteralSearchLimits, LiteralSetAccounting, LiteralSetBuildLimits,
    LiteralSetError, LiteralSetPlan, LiteralSetSearchLimits, PackedLiteralSetAccounting,
    PackedLiteralSetBuildLimits, PackedLiteralSetError, PackedLiteralSetPlan,
    PackedLiteralSetSearchLimits, RequiredLiteralBuildAccounting, RequiredLiteralBuildError,
    RequiredLiteralBuildLimits, RequiredLiteralPlan, RequiredLiteralSearchAccounting,
    RequiredLiteralSearchError, RequiredLiteralSearchLimits, Window as LiteralWindow,
};
use fre_lower::{LowerLimits, LowerStats, OperationSemantics};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CanonicalPattern, ParseSummary, SafetyEnvelope,
};
use regex_syntax::hir::Look;

pub use fre_syntax::{CompatibilityProfile, RustProfile};
pub use unicode_compile::{
    UnicodeCompileArtifact, UnicodeCompileArtifactBuilder, UnicodeCompileArtifactId,
    UnicodeCompileBuildError, UnicodeCompileBuildLimits, UnicodeCompileBuildReport,
    UnicodeCompileResource, UnicodeScalarEncoding, UnicodeScalarIter,
};

pub use fre_automata::{SearchError as K0SearchError, SearchLimits, SearchWindow};

/// Stable schema for facade-level explanation records.
pub const EXPLAIN_SCHEMA_VERSION: u32 = 1;

/// Construction limits whose identities affect admission or lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Exact-upstream-pending strict mode or an explicitly FRE-quota mode.
    pub admission: AdmissionPolicy,
    /// Non-configurable-in-production hard syntax safety envelope.
    pub syntax_safety: SafetyEnvelope,
    /// Checked graph construction limits.
    pub lowering: LowerLimits,
    /// Persistent exact-literal kernel limit.
    pub literal: LiteralBuildLimits,
    /// Bounded DFA fallback for an exactly enumerated finite language.
    pub literal_set: LiteralSetBuildLimits,
    /// SIMD packed plan limits for an exactly enumerated finite language.
    pub packed_literal_set: PackedLiteralSetBuildLimits,
    /// Proof-restricted `CLASS+ SUFFIX` construction limits.
    pub required_literal: RequiredLiteralBuildLimits,
    /// Unique-boundary `\A CLASS+ SUFFIX (?:\z)?` construction limits.
    pub forward_anchored: ForwardAnchoredBuildLimits,
    /// Maximum checked planner traversal/copy work.
    pub max_planner_work: u64,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            lowering: LowerLimits::default(),
            literal: LiteralBuildLimits::default(),
            literal_set: LiteralSetBuildLimits::default(),
            packed_literal_set: PackedLiteralSetBuildLimits::default(),
            required_literal: RequiredLiteralBuildLimits::default(),
            forward_anchored: ForwardAnchoredBuildLimits::default(),
            max_planner_work: 8_000_000,
        }
    }
}

/// A half-open byte match in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Match {
    start: usize,
    end: usize,
}

impl Match {
    /// Inclusive byte start.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive byte end.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Whether the selected match consumed no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Auditable construction facts for one portable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildReport {
    /// Complete compatibility profile selected before parsing.
    pub profile: CompatibilityProfile,
    /// What has and has not established constructor admission.
    pub admission: AdmissionStatus,
    /// Bounded syntax traversal facts.
    pub syntax: ParseSummary,
    /// Selected execution-plan family.
    pub plan: PlanKind,
    /// Checked planner traversal/copy work.
    pub planner_work: u64,
    /// Checked K0 lowering facts, absent for direct native finite-language plans.
    pub lowering: Option<LowerStats>,
    /// Immutable state count after independent automata validation.
    pub states: usize,
    /// Immutable edge count after independent automata validation.
    pub edges: usize,
    /// Immutable logical table payload bytes.
    pub plan_storage_bytes: usize,
    /// Exact minimum bytes consumed by any match, or `None` if the HIR's
    /// language is empty. This is preserved for future aggregate routing.
    pub minimum_match_bytes: Option<usize>,
    /// Complete construction certificate for the proof-restricted plan.
    pub required_literal: Option<RequiredLiteralBuildAccounting>,
    /// Complete construction certificate for the forward-boundary plan.
    pub forward_anchored: Option<ForwardAnchoredBuildAccounting>,
}

/// An honestly labelled selected plan family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanKind {
    /// SIMD-aware shared native exact-substring primitive. This is not JIT.
    ExactLiteral,
    /// Shared SIMD packed ordered finite-literal primitive. This is not JIT.
    PackedLiteralSet,
    /// Bounded ordered finite-literal DFA used when packed search is ineligible.
    LiteralSetDfa,
    /// Proof-restricted SIMD-aware `CLASS+ SUFFIX` kernel. This is not JIT.
    RequiredLiteral,
    /// Absolute-start unique-boundary forward scan. This is not JIT.
    ForwardAnchored,
    /// Generic bounded portable prioritized automaton.
    K0,
}

/// Construction failure without semantic fallback.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// Syntax/profile/admission failure.
    Syntax(fre_syntax::ParseError),
    /// The syntax was valid but is outside the certified portable lowering.
    Lower(fre_lower::LowerError),
    /// K0 line assertions currently carry the pinned LF terminator only.
    UnsupportedLineTerminator { line_terminator: u8 },
    /// Operation-specific kernel construction failure.
    Literal(LiteralError),
    /// Ordered finite-literal DFA construction failure.
    LiteralSet(LiteralSetError),
    /// Required-literal proof or construction failure.
    RequiredLiteral(RequiredLiteralBuildError),
    /// A forced required-literal request did not have the exact HIR shape.
    RequiredLiteralShape,
    /// Forward-anchored proof or construction failure.
    ForwardAnchored(ForwardAnchoredBuildError),
    /// A forced forward-anchored request did not have the exact HIR shape.
    ForwardAnchoredShape,
    /// Checked planner work was exhausted before plan selection.
    PlannerWorkLimit { needed: u64, limit: u64 },
    /// A planner buffer could not be reserved.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// Internal facade/profile mismatch.
    InternalInvariant(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "syntax construction failed: {error}"),
            Self::Lower(error) => write!(f, "portable lowering failed: {error}"),
            Self::UnsupportedLineTerminator { line_terminator } => write!(
                f,
                "portable line assertions require LF, but the profile uses byte 0x{line_terminator:02X}"
            ),
            Self::Literal(error) => write!(f, "literal-plan construction failed: {error}"),
            Self::LiteralSet(error) => {
                write!(f, "literal-set DFA construction failed: {error}")
            }
            Self::RequiredLiteral(error) => {
                write!(f, "required-literal construction failed: {error}")
            }
            Self::RequiredLiteralShape => {
                f.write_str("pattern is outside the forced required-literal HIR shape")
            }
            Self::ForwardAnchored(error) => {
                write!(f, "forward-anchored construction failed: {error}")
            }
            Self::ForwardAnchoredShape => {
                f.write_str("pattern is outside the forced forward-anchored HIR shape")
            }
            Self::PlannerWorkLimit { needed, limit } => {
                write!(f, "planner needs {needed} work units, exceeding {limit}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} additional items for planner {structure}"
            ),
            Self::InternalInvariant(detail) => {
                write!(f, "facade internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Lower(error) => Some(error),
            Self::Literal(error) => Some(error),
            Self::LiteralSet(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            Self::ForwardAnchored(error) => Some(error),
            Self::RequiredLiteralShape
            | Self::UnsupportedLineTerminator { .. }
            | Self::ForwardAnchoredShape
            | Self::PlannerWorkLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl From<fre_syntax::ParseError> for BuildError {
    fn from(value: fre_syntax::ParseError) -> Self {
        Self::Syntax(value)
    }
}

impl From<fre_lower::LowerError> for BuildError {
    fn from(value: fre_lower::LowerError) -> Self {
        Self::Lower(value)
    }
}

impl From<LiteralError> for BuildError {
    fn from(value: LiteralError) -> Self {
        Self::Literal(value)
    }
}

impl From<LiteralSetError> for BuildError {
    fn from(value: LiteralSetError) -> Self {
        Self::LiteralSet(value)
    }
}

impl From<RequiredLiteralBuildError> for BuildError {
    fn from(value: RequiredLiteralBuildError) -> Self {
        Self::RequiredLiteral(value)
    }
}

impl From<ForwardAnchoredBuildError> for BuildError {
    fn from(value: ForwardAnchoredBuildError) -> Self {
        Self::ForwardAnchored(value)
    }
}

/// Per-search accounting with the selected plan kept explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchAccounting {
    /// Exact K0 counters.
    K0(fre_automata::SearchAccounting),
    /// Inputs to the native literal plan's documented linear bound.
    ExactLiteral(LiteralAccounting),
    /// Conservative SIMD packed filter-plus-verification bound.
    PackedLiteralSet(PackedLiteralSetAccounting),
    /// Conservative ordered finite-literal DFA bound.
    LiteralSetDfa(LiteralSetAccounting),
    /// Complete required-literal proof-bound and actual counters.
    RequiredLiteral(RequiredLiteralSearchAccounting),
    /// Complete forward-boundary proof-bound and structural counters.
    ForwardAnchored(ForwardAnchoredSearchAccounting),
}

impl SearchAccounting {
    /// Selected plan family.
    #[must_use]
    pub const fn plan(&self) -> PlanKind {
        match self {
            Self::K0(_) => PlanKind::K0,
            Self::ExactLiteral(_) => PlanKind::ExactLiteral,
            Self::PackedLiteralSet(_) => PlanKind::PackedLiteralSet,
            Self::LiteralSetDfa(_) => PlanKind::LiteralSetDfa,
            Self::RequiredLiteral(_) => PlanKind::RequiredLiteral,
            Self::ForwardAnchored(_) => PlanKind::ForwardAnchored,
        }
    }

    /// Actual charged K0 work or checked literal linear-bound terms.
    #[must_use]
    pub fn work_or_linear_terms(&self) -> u64 {
        match self {
            Self::K0(accounting) => accounting.work(),
            Self::ExactLiteral(accounting) => {
                u64::try_from(accounting.linear_terms).unwrap_or(u64::MAX)
            }
            Self::PackedLiteralSet(accounting) => {
                u64::try_from(accounting.work_upper_bound).unwrap_or(u64::MAX)
            }
            Self::LiteralSetDfa(accounting) => {
                u64::try_from(accounting.transitions_upper_bound).unwrap_or(u64::MAX)
            }
            Self::RequiredLiteral(accounting) => accounting.work_upper_bound,
            Self::ForwardAnchored(accounting) => accounting.work_upper_bound,
        }
    }
}

/// Search failure from the selected forced plan; no fallback is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    K0(K0SearchError),
    ExactLiteral(LiteralError),
    PackedLiteralSet(PackedLiteralSetError),
    LiteralSetDfa(LiteralSetError),
    RequiredLiteral(RequiredLiteralSearchError),
    ForwardAnchored(ForwardAnchoredSearchError),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::K0(error) => write!(f, "K0 search failed: {error}"),
            Self::ExactLiteral(error) => write!(f, "literal search failed: {error}"),
            Self::PackedLiteralSet(error) => {
                write!(f, "packed literal-set search failed: {error}")
            }
            Self::LiteralSetDfa(error) => write!(f, "literal-set DFA search failed: {error}"),
            Self::RequiredLiteral(error) => write!(f, "required-literal search failed: {error}"),
            Self::ForwardAnchored(error) => {
                write!(f, "forward-anchored search failed: {error}")
            }
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::K0(error) => Some(error),
            Self::ExactLiteral(error) => Some(error),
            Self::PackedLiteralSet(error) => Some(error),
            Self::LiteralSetDfa(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            Self::ForwardAnchored(error) => Some(error),
        }
    }
}

impl From<K0SearchError> for SearchError {
    fn from(value: K0SearchError) -> Self {
        Self::K0(value)
    }
}

impl From<LiteralError> for SearchError {
    fn from(value: LiteralError) -> Self {
        Self::ExactLiteral(value)
    }
}

impl From<PackedLiteralSetError> for SearchError {
    fn from(value: PackedLiteralSetError) -> Self {
        Self::PackedLiteralSet(value)
    }
}

impl From<LiteralSetError> for SearchError {
    fn from(value: LiteralSetError) -> Self {
        Self::LiteralSetDfa(value)
    }
}

impl From<RequiredLiteralSearchError> for SearchError {
    fn from(value: RequiredLiteralSearchError) -> Self {
        Self::RequiredLiteral(value)
    }
}

impl From<ForwardAnchoredSearchError> for SearchError {
    fn from(value: ForwardAnchoredSearchError) -> Self {
        Self::ForwardAnchored(value)
    }
}

/// Planner selection control used by forced-plan differential tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlanSelection {
    /// Use evidence-backed production routing.
    #[default]
    Auto,
    /// Require the v1 required-literal plan and propagate every refusal.
    ForceRequiredLiteral,
    /// Require the distinct forward-boundary plan and propagate every refusal.
    ForceForwardAnchored,
    /// Require the generic bounded K0 plan for qualification comparisons.
    ForceK0,
}

/// Capture-free operation stamped into a required-literal cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFreeOperation {
    Exists,
    SelectedEnd,
    Span,
}

/// Complete equality key for one required-literal compiled/search contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredLiteralCacheIdentity {
    pub schema_version: u32,
    pub plan_id: &'static str,
    pub profile: CompatibilityProfile,
    pub operation: CaptureFreeOperation,
    pub anchors: fre_kernels::RequiredLiteralAnchors,
    pub class_words: [u64; 4],
    pub suffix: Vec<u8>,
    pub build_limits: BuildLimits,
    pub search_limits: SearchLimits,
}

/// Complete equality key for one forward-anchored compiled/search contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardAnchoredCacheIdentity {
    pub schema_version: u32,
    pub plan_id: &'static str,
    pub profile: CompatibilityProfile,
    pub operation: CaptureFreeOperation,
    pub anchors: fre_kernels::ForwardAnchoredAnchors,
    pub class_words: [u64; 4],
    pub suffix: Vec<u8>,
    pub implementation: fre_kernels::ForwardClassImplementation,
    pub build_limits: BuildLimits,
    pub search_limits: SearchLimits,
}

/// Builder for the exact currently certified Rust-bytes subset.
#[derive(Clone, Debug)]
pub struct PortableBuilder {
    pattern: String,
    profile: RustProfile,
    limits: BuildLimits,
    selection: PlanSelection,
}

impl PortableBuilder {
    /// Start from pinned Rust-regex defaults. Because the current lowerer has
    /// no Unicode-class compiler, callers commonly select [`Self::unicode`]
    /// `false` for byte classes; unsupported HIR is rejected either way.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: BuildLimits::default(),
            selection: PlanSelection::Auto,
        }
    }

    /// Select the complete Rust release-stack and constructor identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the Rust bytes facade's Unicode mode before parsing.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Replace every checked construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: BuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Force one plan so tests and qualification cannot accidentally exercise
    /// an alternative implementation.
    #[must_use]
    pub const fn plan_selection(mut self, selection: PlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Parse, plan, and independently validate an immutable portable plan.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] for syntax/admission failure, a resource cap, or
    /// any feature outside the certified subset. No alternate engine silently
    /// accepts an unsupported pattern.
    #[allow(
        clippy::too_many_lines,
        reason = "plan selection keeps each no-fallback construction branch and report explicit"
    )]
    pub fn build(self) -> Result<PortableRegex, BuildError> {
        let profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let request = fre_syntax::ParseRequest::rust(self.pattern, profile.clone())
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let parsed = fre_syntax::parse(request)?;
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(BuildError::InternalInvariant(
                "Rust bytes request produced a non-Rust canonical pattern",
            ));
        };
        let looks = rust.hir.properties().look_set();
        if self.profile.options.line_terminator != b'\n'
            && (looks.contains(Look::StartLF) || looks.contains(Look::EndLF))
        {
            return Err(BuildError::UnsupportedLineTerminator {
                line_terminator: self.profile.options.line_terminator,
            });
        }
        let minimum_match_bytes = rust.hir.properties().minimum_len();
        if self.selection == PlanSelection::ForceK0 {
            let lowered =
                fre_lower::lower(&rust, OperationSemantics::CaptureFree, self.limits.lowering)?;
            let lowering = lowered.stats();
            let automaton = lowered.into_automaton();
            let plan = automaton.stats();
            return Ok(PortableRegex {
                plan: PortablePlan::K0(automaton),
                profile: profile.clone(),
                limits: self.limits,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::K0,
                    planner_work: 0,
                    lowering: Some(lowering),
                    states: plan.states(),
                    edges: plan.edges(),
                    plan_storage_bytes: plan.storage_bytes(),
                    minimum_match_bytes,
                    required_literal: None,
                    forward_anchored: None,
                },
            });
        }
        let mut planner_work = 0_u64;
        if matches!(
            self.selection,
            PlanSelection::Auto | PlanSelection::ForceForwardAnchored
        ) {
            let forward = forward_anchored::extract(&rust.hir, 0, self.limits.max_planner_work)?;
            planner_work = forward.work;
            if let Some(shape) = forward.shape {
                if self.selection == PlanSelection::ForceForwardAnchored && shape.anchors.end {
                    let plan = AbsoluteEndFixedPlan::build(
                        shape.class,
                        shape.suffix,
                        shape.anchors,
                        self.limits.forward_anchored,
                    )
                    .map_err(BuildError::ForwardAnchored)?;
                    let build = plan.build_accounting();
                    return Ok(PortableRegex {
                        plan: PortablePlan::ForwardEndFixed(plan),
                        profile: profile.clone(),
                        limits: self.limits,
                        report: BuildReport {
                            profile: profile.clone(),
                            admission,
                            syntax,
                            plan: PlanKind::ForwardAnchored,
                            planner_work,
                            lowering: None,
                            states: 0,
                            edges: 0,
                            plan_storage_bytes: build.persistent_bytes,
                            minimum_match_bytes,
                            required_literal: None,
                            forward_anchored: Some(build),
                        },
                    });
                }
                match ForwardAnchoredPlan::build(
                    shape.class,
                    shape.suffix,
                    shape.anchors,
                    self.limits.forward_anchored,
                ) {
                    Ok(plan) => {
                        let build = plan.build_accounting();
                        return Ok(PortableRegex {
                            plan: PortablePlan::ForwardAnchored(plan),
                            profile: profile.clone(),
                            limits: self.limits,
                            report: BuildReport {
                                profile: profile.clone(),
                                admission,
                                syntax,
                                plan: PlanKind::ForwardAnchored,
                                planner_work,
                                lowering: None,
                                states: 0,
                                edges: 0,
                                plan_storage_bytes: build.persistent_bytes,
                                minimum_match_bytes,
                                required_literal: None,
                                forward_anchored: Some(build),
                            },
                        });
                    }
                    Err(error)
                        if self.selection == PlanSelection::Auto && error.is_semantic_refusal() => {
                    }
                    Err(error) => return Err(BuildError::ForwardAnchored(error)),
                }
            } else if self.selection == PlanSelection::ForceForwardAnchored {
                return Err(BuildError::ForwardAnchoredShape);
            }
        }
        let required =
            required_literal::extract(&rust.hir, planner_work, self.limits.max_planner_work)?;
        let required_work = required.work;
        if let Some(shape) = required.shape {
            let default_allowed = !(shape.anchors.start && shape.anchors.end);
            if self.selection == PlanSelection::ForceRequiredLiteral || default_allowed {
                match RequiredLiteralPlan::build(
                    shape.class,
                    &shape.suffix,
                    shape.anchors,
                    self.limits.required_literal,
                ) {
                    Ok(plan) => {
                        let build = plan.build_accounting();
                        return Ok(PortableRegex {
                            plan: PortablePlan::RequiredLiteral(plan),
                            profile: profile.clone(),
                            limits: self.limits,
                            report: BuildReport {
                                profile: profile.clone(),
                                admission,
                                syntax,
                                plan: PlanKind::RequiredLiteral,
                                planner_work: required_work,
                                lowering: None,
                                states: 0,
                                edges: 0,
                                plan_storage_bytes: build.persistent_bytes,
                                minimum_match_bytes,
                                required_literal: Some(build),
                                forward_anchored: None,
                            },
                        });
                    }
                    Err(error)
                        if self.selection == PlanSelection::Auto && error.is_semantic_refusal() => {
                    }
                    Err(error) => return Err(BuildError::RequiredLiteral(error)),
                }
            }
        } else if self.selection == PlanSelection::ForceRequiredLiteral {
            return Err(BuildError::RequiredLiteralShape);
        }
        let extraction = finite::extract(
            &rust.hir,
            self.limits.literal_set.max_patterns,
            self.limits.literal_set.max_pattern_bytes,
            required_work,
            self.limits.max_planner_work,
        )?;
        if let Some(words) = extraction.words {
            if words.len() == 1 {
                let literal = LiteralPlan::new(&words[0], self.limits.literal)?;
                let storage = literal.storage_bytes();
                return Ok(PortableRegex {
                    plan: PortablePlan::ExactLiteral(literal),
                    profile: profile.clone(),
                    limits: self.limits,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::ExactLiteral,
                        planner_work: extraction.work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes: storage,
                        minimum_match_bytes,
                        required_literal: None,
                        forward_anchored: None,
                    },
                });
            }
            if words.len() > 1 {
                if let Ok(packed) =
                    PackedLiteralSetPlan::new(&words, self.limits.packed_literal_set)
                {
                    let storage = packed.build_accounting().persistent_bytes;
                    return Ok(PortableRegex {
                        plan: PortablePlan::PackedLiteralSet(packed),
                        profile: profile.clone(),
                        limits: self.limits,
                        report: BuildReport {
                            profile: profile.clone(),
                            admission,
                            syntax,
                            plan: PlanKind::PackedLiteralSet,
                            planner_work: extraction.work,
                            lowering: None,
                            states: 0,
                            edges: 0,
                            plan_storage_bytes: storage,
                            minimum_match_bytes,
                            required_literal: None,
                            forward_anchored: None,
                        },
                    });
                }
                let literal_set = LiteralSetPlan::new(&words, self.limits.literal_set)?;
                let storage = literal_set.build_accounting().persistent_bytes;
                return Ok(PortableRegex {
                    plan: PortablePlan::LiteralSetDfa(literal_set),
                    profile: profile.clone(),
                    limits: self.limits,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::LiteralSetDfa,
                        planner_work: extraction.work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes: storage,
                        minimum_match_bytes,
                        required_literal: None,
                        forward_anchored: None,
                    },
                });
            }
        }
        let lowered =
            fre_lower::lower(&rust, OperationSemantics::CaptureFree, self.limits.lowering)?;
        let lowering = lowered.stats();
        let automaton = lowered.into_automaton();
        let plan = automaton.stats();
        Ok(PortableRegex {
            plan: PortablePlan::K0(automaton),
            profile: profile.clone(),
            limits: self.limits,
            report: BuildReport {
                profile: profile.clone(),
                admission,
                syntax,
                plan: PlanKind::K0,
                planner_work: extraction.work,
                lowering: Some(lowering),
                states: plan.states(),
                edges: plan.edges(),
                plan_storage_bytes: plan.storage_bytes(),
                minimum_match_bytes,
                required_literal: None,
                forward_anchored: None,
            },
        })
    }
}

/// Immutable, shareable matcher for the certified capture-free byte subset.
#[derive(Debug)]
pub struct PortableRegex {
    plan: PortablePlan,
    profile: CompatibilityProfile,
    limits: BuildLimits,
    report: BuildReport,
}

#[derive(Debug)]
enum PortablePlan {
    ExactLiteral(LiteralPlan),
    PackedLiteralSet(PackedLiteralSetPlan),
    LiteralSetDfa(LiteralSetPlan),
    RequiredLiteral(RequiredLiteralPlan),
    ForwardAnchored(ForwardAnchoredPlan),
    ForwardEndFixed(AbsoluteEndFixedPlan),
    K0(Automaton),
}

impl PortablePlan {
    const fn runtime_implementation_id(&self) -> &'static str {
        match self {
            Self::ExactLiteral(_) => "exact-literal",
            Self::PackedLiteralSet(_) => "packed-literal-set",
            Self::LiteralSetDfa(_) => "literal-set-dfa",
            Self::RequiredLiteral(required) => required.plan_id(),
            Self::ForwardAnchored(forward) => forward.plan_id(),
            Self::ForwardEndFixed(fixed) => fixed.plan_id(),
            Self::K0(_) => "k0",
        }
    }
}

impl PortableRegex {
    /// Construct with pinned Rust-bytes defaults and default resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] under the same conditions as
    /// [`PortableBuilder::build`].
    pub fn new(pattern: impl Into<String>) -> Result<Self, BuildError> {
        PortableBuilder::new(pattern).build()
    }

    /// The immutable compatibility profile used during parsing.
    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    /// Construction accounting and admission status.
    #[must_use]
    pub const fn build_report(&self) -> &BuildReport {
        &self.report
    }

    /// Stable identity of the selected runtime implementation.
    ///
    /// This is intentionally obtained from the stored plan rather than
    /// reconstructed from [`PlanKind`]. For the required-literal and
    /// forward-anchored plans, it is the same strategy identity stored in
    /// their operation cache keys.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        self.plan.runtime_implementation_id()
    }

    /// Whether a selected match exists.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let (matched, accounting) = literal.find(haystack, literal_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, packed_literal_set_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, literal_set_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let (matched, accounting) =
                    fixed.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::K0(automaton) => {
                let report = automaton.prepare::<Exists>().search(haystack, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the selected match end without materializing its start.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn selected_end(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let (matched, accounting) = literal.find(haystack, literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, packed_literal_set_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, literal_set_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let (matched, accounting) =
                    fixed.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::K0(automaton) => {
                let report = automaton
                    .prepare::<SelectedEnd>()
                    .search(haystack, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the profile-selected leftmost-first match.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Search a range while assertions retain original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    packed_literal_set_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    literal_set_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::K0(automaton) => {
                let report = automaton
                    .prepare::<Span>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                let matched = report.into_output().map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                });
                Ok((matched, SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Produce the complete equality key for a required-literal operation.
    ///
    /// `None` means this matcher selected another plan family. Search limits
    /// are included deliberately so cached qualification records cannot mix
    /// distinct refusal contracts.
    #[must_use]
    pub fn required_literal_cache_identity(
        &self,
        operation: CaptureFreeOperation,
        search_limits: SearchLimits,
    ) -> Option<RequiredLiteralCacheIdentity> {
        let PortablePlan::RequiredLiteral(required) = &self.plan else {
            return None;
        };
        Some(RequiredLiteralCacheIdentity {
            schema_version: EXPLAIN_SCHEMA_VERSION,
            plan_id: required.plan_id(),
            profile: self.profile.clone(),
            operation,
            anchors: required.anchors(),
            class_words: required.class().words(),
            suffix: required.suffix().to_vec(),
            build_limits: self.limits,
            search_limits,
        })
    }

    /// Produce the complete equality key for a forward-anchored operation.
    ///
    /// `None` means this matcher selected another plan family. The key is
    /// deliberately distinct from the required-literal candidate.
    #[must_use]
    pub fn forward_anchored_cache_identity(
        &self,
        operation: CaptureFreeOperation,
        search_limits: SearchLimits,
    ) -> Option<ForwardAnchoredCacheIdentity> {
        match &self.plan {
            PortablePlan::ForwardAnchored(forward) => Some(ForwardAnchoredCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: forward.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: forward.anchors(),
                class_words: forward.class().words(),
                suffix: forward.suffix().to_vec(),
                implementation: forward.implementation(),
                build_limits: self.limits,
                search_limits,
            }),
            PortablePlan::ForwardEndFixed(fixed) => Some(ForwardAnchoredCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: fixed.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: fixed.anchors(),
                class_words: fixed.class().words(),
                suffix: fixed.suffix().to_vec(),
                implementation: fixed.implementation(),
                build_limits: self.limits,
                search_limits,
            }),
            _ => None,
        }
    }
}

pub(crate) fn reserve_planner<T>(
    values: &mut Vec<T>,
    additional: usize,
    work: &mut u64,
    limit: u64,
    structure: &'static str,
) -> Result<(), BuildError> {
    let needed = values
        .len()
        .checked_add(additional)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit,
        })?;
    if needed > values.capacity() {
        charge_planner(work, u64::try_from(values.len()).unwrap_or(u64::MAX), limit)?;
    }
    charge_planner(work, u64::try_from(additional).unwrap_or(u64::MAX), limit)?;
    values
        .try_reserve(additional)
        .map_err(|_| BuildError::AllocationFailed {
            structure,
            additional,
        })
}

pub(crate) fn charge_planner(work: &mut u64, amount: u64, limit: u64) -> Result<(), BuildError> {
    let needed = work
        .checked_add(amount)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit,
        })?;
    if needed > limit {
        return Err(BuildError::PlannerWorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn literal_limits(limits: SearchLimits) -> LiteralSearchLimits {
    LiteralSearchLimits {
        max_linear_terms: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn packed_literal_set_limits(limits: SearchLimits) -> PackedLiteralSetSearchLimits {
    PackedLiteralSetSearchLimits {
        max_work: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn literal_set_limits(limits: SearchLimits) -> LiteralSetSearchLimits {
    LiteralSetSearchLimits {
        max_transitions: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn required_literal_limits(limits: SearchLimits) -> RequiredLiteralSearchLimits {
    RequiredLiteralSearchLimits {
        max_work_upper_bound: limits.max_work,
        max_candidate_visits: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

fn forward_anchored_limits(limits: SearchLimits) -> ForwardAnchoredSearchLimits {
    ForwardAnchoredSearchLimits {
        max_work_upper_bound: limits.max_work,
        max_examined_bytes_upper_bound: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuildError, BuildLimits, CaptureFreeOperation, PlanKind, PlanSelection, PortableBuilder,
        PortableRegex, SearchAccounting, SearchError, SearchLimits, SearchWindow,
    };
    use fre_lower::UnsupportedFeature;
    use std::fmt::Write as _;

    #[test]
    fn facade_exposes_only_the_certified_byte_path() {
        let regex = PortableBuilder::new("ab[0-3]+")
            .unicode(false)
            .build()
            .unwrap();
        let (matched, accounting) = regex.find(b"zzab123x", SearchLimits::unlimited()).unwrap();
        let matched = matched.unwrap();
        assert_eq!((matched.start(), matched.end()), (2, 7));
        assert!(accounting.work_or_linear_terms() > 0);
        assert!(regex.build_report().states > 0);
    }

    #[test]
    fn exact_literals_select_the_labelled_native_kernel() {
        let regex = PortableRegex::new("Sherlock").unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);
        assert_eq!(regex.build_report().lowering, None);
        let (matched, accounting) = regex
            .find(b"zzSherlock", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 10))
        );
        assert!(matches!(accounting, SearchAccounting::ExactLiteral(_)));

        let captured = PortableRegex::new("(Sherlock)").unwrap();
        assert_eq!(captured.build_report().plan, PlanKind::ExactLiteral);
    }

    #[test]
    fn exact_literal_plan_exhaustively_matches_the_rebar_baseline() {
        let patterns = words(3);
        let haystacks = words(5);
        for pattern in &patterns {
            let pattern = core::str::from_utf8(pattern).unwrap();
            let fre = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert_eq!(fre.build_report().plan, PlanKind::ExactLiteral);
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in &haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, _) = fre.find(haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                let (exists, _) = fre.is_match(haystack, SearchLimits::unlimited()).unwrap();
                let (end, _) = fre
                    .selected_end(haystack, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(exists, expected.is_some());
                assert_eq!(end, expected.map(|(_, end)| end));
            }
        }
    }

    #[test]
    fn finite_languages_select_a_forced_literal_set_and_match_upstream() {
        let patterns = [
            "a|ab",
            "ab|a",
            "(?:a|b)(?:c|)",
            "[ab]c|d",
            "foobar|foobaz|fooquux",
            "(?:|a)",
        ];
        let mut haystacks = words(4);
        haystacks.push(b"foo-no-match/foobaz".to_vec());
        for pattern in patterns {
            let fre = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(
                fre.build_report().plan,
                PlanKind::PackedLiteralSet | PlanKind::LiteralSetDfa
            ));
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in &haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = fre.find(haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                assert_eq!(accounting.plan(), fre.build_report().plan);
            }
        }
    }

    #[test]
    fn packed_ineligibility_is_resolved_before_selecting_the_dfa() {
        let limits = BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        };
        let fre = PortableBuilder::new("foobar|foobaz|fooquux")
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::LiteralSetDfa);
        let (matched, accounting) = fre.find(b"xxfoobaz", SearchLimits::unlimited()).unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 8))
        );
        assert!(matches!(accounting, SearchAccounting::LiteralSetDfa(_)));
    }

    #[test]
    fn finite_enumeration_cap_falls_back_before_cross_product_growth() {
        let limits = BuildLimits {
            literal_set: fre_kernels::LiteralSetBuildLimits {
                max_patterns: 4,
                ..fre_kernels::LiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        };
        let fre = PortableBuilder::new("[ab][cd][ef]")
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        let (matched, _) = fre.find(b"xxbcf", SearchLimits::unlimited()).unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 5))
        );
    }

    #[test]
    fn finite_planner_work_limit_is_an_exact_preselection_boundary() {
        let pattern = "(?:ab|cd)(?:e|f)";
        let baseline = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let required = baseline.build_report().planner_work;
        assert!(required > 0);
        let exact = BuildLimits {
            max_planner_work: required,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(exact)
                .build()
                .is_ok()
        );
        let refused = BuildLimits {
            max_planner_work: required - 1,
            ..BuildLimits::default()
        };
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(refused)
                .build(),
            Err(BuildError::PlannerWorkLimit { .. })
        ));
    }

    #[test]
    fn uncertified_nullable_loop_is_a_build_error() {
        let error = PortableBuilder::new("(?:|a)*")
            .unicode(false)
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            BuildError::Lower(fre_lower::LowerError::Unsupported(
                UnsupportedFeature::UncertifiedUnboundedRepetition
            ))
        ));
    }

    #[test]
    fn ranged_search_keeps_original_anchor_context() {
        let regex = PortableRegex::new("^a").unwrap();
        let (matched, _) = regex
            .find_window(b"za", SearchWindow::new(1, 2), SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None);
    }

    #[test]
    fn production_routing_selects_only_the_evidence_backed_anchor_slice() {
        let selected = PortableBuilder::new("[a-z]+Z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(selected.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(selected.build_report().minimum_match_bytes, Some(2));
        assert!(selected.build_report().required_literal.is_some());

        let anchored_start = PortableBuilder::new(r"\A[a-z]+Z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            anchored_start.build_report().plan,
            PlanKind::ForwardAnchored
        );

        let both_anchors = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(both_anchors.build_report().plan, PlanKind::ForwardAnchored);

        let forced = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::RequiredLiteral);

        let captured = PortableBuilder::new("([a-z]+Z)")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(captured.build_report().plan, PlanKind::RequiredLiteral);
    }

    #[test]
    fn forced_shape_and_theorem_refusals_are_typed() {
        assert!(matches!(
            PortableBuilder::new("[ab]*Z")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteralShape)
        ));
        assert!(matches!(
            PortableBuilder::new("a+a")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::FirstSuffixByteInClass { .. }
            ))
        ));
        assert!(matches!(
            PortableBuilder::new("b+aba")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::OverlappingSuffix { .. }
            ))
        ));

        // Auto mode declines those theorem shapes before selecting K0.
        let safe_fallback = PortableBuilder::new("b+aba")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(safe_fallback.build_report().plan, PlanKind::K0);
        assert_eq!(
            safe_fallback
                .find(b"ababa", SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5))
        );
    }

    #[test]
    fn facade_propagates_exact_required_literal_resource_boundaries() {
        let baseline = PortableBuilder::new("a+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        let accounting = baseline.build_report().required_literal.unwrap();
        let exact_kernel = fre_kernels::RequiredLiteralBuildLimits {
            max_suffix_bytes: accounting.suffix_bytes,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        let exact = BuildLimits {
            required_literal: exact_kernel,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new("a+Z")
                .unicode(false)
                .limits(exact)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build()
                .is_ok()
        );

        for limited in [
            fre_kernels::RequiredLiteralBuildLimits {
                max_suffix_bytes: accounting.suffix_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_build_work: accounting.work_upper_bound - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_scratch_bytes: accounting.scratch_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_persistent_bytes: accounting.persistent_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_peak_bytes: accounting.peak_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
        ] {
            let limits = BuildLimits {
                required_literal: limited,
                ..BuildLimits::default()
            };
            assert!(matches!(
                PortableBuilder::new("a+Z")
                    .unicode(false)
                    .limits(limits)
                    .plan_selection(PlanSelection::ForceRequiredLiteral)
                    .build(),
                Err(BuildError::RequiredLiteral(_))
            ));
        }

        let (_, search) = baseline.find(b"aaaaZ", SearchLimits::unlimited()).unwrap();
        let SearchAccounting::RequiredLiteral(search) = search else {
            panic!("forced required-literal search changed plans")
        };
        assert!(
            baseline
                .find(
                    b"aaaaZ",
                    SearchLimits {
                        max_work: search.work_upper_bound,
                        max_scratch_bytes: search.scratch_bytes,
                    }
                )
                .is_ok()
        );
        assert!(matches!(
            baseline.find(
                b"aaaaZ",
                SearchLimits {
                    max_work: search.work_upper_bound - 1,
                    max_scratch_bytes: search.scratch_bytes,
                }
            ),
            Err(SearchError::RequiredLiteral(
                fre_kernels::RequiredLiteralSearchError::WorkLimit { .. }
            ))
        ));
        assert_eq!(baseline.build_report().plan, PlanKind::RequiredLiteral);
    }

    #[test]
    fn cache_identity_stamps_profile_operation_anchors_and_every_limit() {
        let regex = PortableBuilder::new("[ab]+Z")
            .unicode(false)
            .build()
            .unwrap();
        let limits = SearchLimits::default();
        let span = regex
            .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_eq!(span.plan_id, fre_kernels::REQUIRED_LITERAL_PLAN_ID);
        assert_eq!(span.build_limits, BuildLimits::default());
        assert_eq!(span.search_limits, limits);
        assert_eq!(
            span,
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Exists, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .required_literal_cache_identity(
                    CaptureFreeOperation::Span,
                    SearchLimits::unlimited()
                )
                .unwrap()
        );
    }

    #[test]
    fn arbitrary_bytes_and_absolute_windows_reach_the_forced_facade_plan() {
        let regex = PortableBuilder::new(r"(?-u:[\x00\x80\xFF]+\x7F\xFE)")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(
            regex
                .find(&[9, 0x80, 0xFF, 0x7F, 0xFE], SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5))
        );

        let anchored = PortableBuilder::new(r"\Aa+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(
            anchored
                .find_window(b"aaaZ", SearchWindow::new(1, 4), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
    }

    #[test]
    fn forced_facade_plan_matches_regex_1_12_4_exhaustively() {
        let alphabet = [b'a', b'b', b'Z'];
        let haystacks = byte_words(&alphabet, 6);
        let suffixes = non_empty_byte_words(&alphabet, 3);
        let mut span_comparisons = 0_usize;
        let mut operation_comparisons = 0_usize;
        for mask in 1_u8..4 {
            let class_bytes: Vec<u8> = [b'a', b'b']
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            for suffix in &suffixes {
                for start in [false, true] {
                    for end in [false, true] {
                        let pattern = required_pattern(&class_bytes, suffix, start, end);
                        let fre = match PortableBuilder::new(&pattern)
                            .unicode(false)
                            .plan_selection(PlanSelection::ForceRequiredLiteral)
                            .build()
                        {
                            Ok(fre) => fre,
                            Err(BuildError::RequiredLiteral(error))
                                if error.is_semantic_refusal() =>
                            {
                                continue;
                            }
                            Err(error) => panic!("pattern={pattern:?}: {error:?}"),
                        };
                        let upstream = regex::bytes::RegexBuilder::new(&pattern)
                            .unicode(false)
                            .build()
                            .unwrap();
                        for haystack in &haystacks {
                            let expected = upstream
                                .find(haystack)
                                .map(|matched| (matched.start(), matched.end()));
                            let (actual, accounting) =
                                fre.find(haystack, SearchLimits::unlimited()).unwrap();
                            assert_eq!(accounting.plan(), PlanKind::RequiredLiteral);
                            assert_eq!(
                                actual.map(|matched| (matched.start(), matched.end())),
                                expected,
                                "pattern={pattern:?}, haystack={haystack:?}"
                            );
                            assert_eq!(
                                fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                                expected.is_some()
                            );
                            assert_eq!(
                                fre.selected_end(haystack, SearchLimits::unlimited())
                                    .unwrap()
                                    .0,
                                expected.map(|(_, end)| end)
                            );
                            span_comparisons = span_comparisons.saturating_add(1);
                            operation_comparisons = operation_comparisons.saturating_add(3);
                        }
                    }
                }
            }
        }
        assert_eq!(span_comparisons, 196_740);
        assert_eq!(operation_comparisons, 590_220);
    }

    #[test]
    fn forced_facade_windows_match_find_at_exhaustively() {
        let alphabet = [b'a', b'Z'];
        let haystacks = byte_words(&alphabet, 4);
        let suffixes = non_empty_byte_words(&alphabet, 2);
        let mut comparisons = 0_usize;
        for suffix in &suffixes {
            for start in [false, true] {
                for end in [false, true] {
                    let pattern = required_pattern(b"a", suffix, start, end);
                    let fre = match PortableBuilder::new(&pattern)
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceRequiredLiteral)
                        .build()
                    {
                        Ok(fre) => fre,
                        Err(BuildError::RequiredLiteral(error)) if error.is_semantic_refusal() => {
                            continue;
                        }
                        Err(error) => panic!("pattern={pattern:?}: {error:?}"),
                    };
                    let upstream = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        for window_start in 0..=haystack.len() {
                            for window_end in window_start..=haystack.len() {
                                let actual = fre
                                    .find_window(
                                        haystack,
                                        SearchWindow::new(window_start, window_end),
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0
                                    .map(|matched| (matched.start(), matched.end()));
                                let expected = upstream
                                    .find_at(haystack, window_start)
                                    .filter(|matched| matched.end() <= window_end)
                                    .map(|matched| (matched.start(), matched.end()));
                                assert_eq!(
                                    actual, expected,
                                    "pattern={pattern:?} haystack={haystack:?} window={window_start}..{window_end}"
                                );
                                comparisons = comparisons.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 2_808);
    }

    #[test]
    fn forward_candidate_keeps_distinct_identity_after_evidence_backed_promotion() {
        let pattern = r"\Ab+aba";
        let forced = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::ForwardAnchored);
        assert!(forced.build_report().forward_anchored.is_some());
        assert!(forced.build_report().required_literal.is_none());
        assert_eq!(
            forced
                .find(b"bbbaba", SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 6))
        );
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::OverlappingSuffix { .. }
            ))
        ));

        assert_eq!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap()
                .build_report()
                .plan,
            PlanKind::ForwardAnchored
        );
        assert_eq!(
            PortableBuilder::new(r"\A[ab]+?Z")
                .unicode(false)
                .build()
                .unwrap()
                .build_report()
                .plan,
            PlanKind::ForwardAnchored
        );
    }

    #[test]
    fn forward_forced_shape_theorem_and_absolute_windows_are_typed() {
        for pattern in [r"[ab]+Z", r"\A[ab]*Z", r"\A[ab]+[ZQ]"] {
            assert!(matches!(
                PortableBuilder::new(pattern)
                    .unicode(false)
                    .plan_selection(PlanSelection::ForceForwardAnchored)
                    .build(),
                Err(BuildError::ForwardAnchoredShape)
            ));
        }
        assert!(matches!(
            PortableBuilder::new(r"\Aa+a")
                .unicode(false)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build(),
            Err(BuildError::ForwardAnchored(
                fre_kernels::ForwardAnchoredBuildError::FirstSuffixByteInClass { .. }
            ))
        ));

        let forced = PortableBuilder::new(r"\A([ab]+Z)\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(
            forced
                .find_window(b"abZ", SearchWindow::new(1, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert_eq!(
            forced
                .find_window(b"abZx", SearchWindow::new(0, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert!(matches!(
            forced.find_window(b"abZ", SearchWindow::new(2, 1), SearchLimits::unlimited()),
            Err(SearchError::ForwardAnchored(
                fre_kernels::ForwardAnchoredSearchError::InvalidWindow { .. }
            ))
        ));
    }

    #[test]
    fn forward_facade_propagates_exact_resource_boundaries() {
        let baseline = PortableBuilder::new(r"\A[a-z]+Zborderedaba")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let accounting = baseline.build_report().forward_anchored.unwrap();
        let exact_kernel = fre_kernels::ForwardAnchoredBuildLimits {
            max_suffix_bytes: accounting.suffix_bytes,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        let exact = BuildLimits {
            forward_anchored: exact_kernel,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new(r"\A[a-z]+Zborderedaba")
                .unicode(false)
                .limits(exact)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build()
                .is_ok()
        );
        for limited in [
            fre_kernels::ForwardAnchoredBuildLimits {
                max_suffix_bytes: accounting.suffix_bytes - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_build_work: accounting.work_upper_bound - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_persistent_bytes: accounting.persistent_bytes - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_peak_bytes: accounting.peak_bytes - 1,
                ..exact_kernel
            },
        ] {
            let limits = BuildLimits {
                forward_anchored: limited,
                ..BuildLimits::default()
            };
            assert!(matches!(
                PortableBuilder::new(r"\A[a-z]+Zborderedaba")
                    .unicode(false)
                    .limits(limits)
                    .plan_selection(PlanSelection::ForceForwardAnchored)
                    .build(),
                Err(BuildError::ForwardAnchored(_))
            ));
        }
        assert_eq!(accounting.scratch_bytes, 0);

        let (_, search) = baseline
            .find(b"alphabetZborderedaba", SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::ForwardAnchored(search) = search else {
            panic!("forced forward plan changed identities")
        };
        assert!(
            baseline
                .find(
                    b"alphabetZborderedaba",
                    SearchLimits {
                        max_work: search.work_upper_bound,
                        max_scratch_bytes: search.scratch_bytes,
                    }
                )
                .is_ok()
        );
        assert!(matches!(
            baseline.find(
                b"alphabetZborderedaba",
                SearchLimits {
                    max_work: search.work_upper_bound - 1,
                    max_scratch_bytes: search.scratch_bytes,
                }
            ),
            Err(SearchError::ForwardAnchored(
                fre_kernels::ForwardAnchoredSearchError::ExaminedBytesLimit { .. }
                    | fre_kernels::ForwardAnchoredSearchError::WorkLimit { .. }
            ))
        ));
    }

    #[test]
    fn forward_cache_identity_is_complete_and_not_required_literal_identity() {
        let regex = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let limits = SearchLimits::default();
        let span = regex
            .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_eq!(span.plan_id, fre_kernels::ABSOLUTE_END_FIXED_PLAN_ID);
        assert_eq!(span.build_limits, BuildLimits::default());
        assert_eq!(span.search_limits, limits);
        assert_eq!(
            span,
            regex
                .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .forward_anchored_cache_identity(CaptureFreeOperation::Exists, limits)
                .unwrap()
        );
        assert!(
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .is_none()
        );
    }

    #[test]
    fn runtime_implementation_identity_tracks_cache_bound_strategy_variants() {
        let pattern = r"\A[a-z]+Z";
        let limits = SearchLimits::default();
        let forward = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let required = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();

        let forward_id = forward.runtime_implementation_id();
        let required_id = required.runtime_implementation_id();
        assert_eq!(forward.build_report().plan, PlanKind::ForwardAnchored);
        assert_eq!(required.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(
            forward_id,
            forward
                .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
                .plan_id
        );
        assert_eq!(
            required_id,
            required
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
                .plan_id
        );
        assert_ne!(forward_id, required_id);
    }

    #[test]
    fn equality5_short_middle_runtime_identity_rejects_stale_forward_family_labels() {
        const EQUALITY5_ID: &str = "anchored-class-suffix.single-candidate32-65536-equality32-pair-candidate16-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar1-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v22";
        const STALE_ES8I_ID: &str = "anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1";
        const STALE_FORWARD_ID: &str = "anchored-class-suffix.forward.v1";

        assert_eq!(fre_kernels::FORWARD_ANCHORED_PLAN_ID, EQUALITY5_ID);
        let forward = PortableBuilder::new(r"\A[a-z]+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(forward.runtime_implementation_id(), EQUALITY5_ID);
        assert_ne!(forward.runtime_implementation_id(), STALE_ES8I_ID);
        assert_ne!(forward.runtime_implementation_id(), STALE_FORWARD_ID);
    }

    #[test]
    fn forward_forced_facade_matches_regex_1_12_4_exhaustively() {
        let alphabet = [0_u8, 1, 2];
        let haystacks = byte_words(&alphabet, 6);
        let suffixes = non_empty_byte_words(&alphabet, 3);
        let mut span_comparisons = 0_usize;
        let mut operation_comparisons = 0_usize;
        for mask in 1_u8..8 {
            let class_bytes: Vec<u8> = alphabet
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            for suffix in &suffixes {
                if class_bytes.contains(&suffix[0]) {
                    continue;
                }
                for lazy in [false, true] {
                    for end in [false, true] {
                        let pattern = forward_pattern(&class_bytes, suffix, lazy, end);
                        let fre = PortableBuilder::new(&pattern)
                            .unicode(false)
                            .plan_selection(PlanSelection::ForceForwardAnchored)
                            .build()
                            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
                        let upstream = regex::bytes::RegexBuilder::new(&pattern)
                            .unicode(false)
                            .build()
                            .unwrap();
                        for haystack in &haystacks {
                            let expected = upstream
                                .find(haystack)
                                .map(|matched| (matched.start(), matched.end()));
                            let (actual, accounting) =
                                fre.find(haystack, SearchLimits::unlimited()).unwrap();
                            assert_eq!(accounting.plan(), PlanKind::ForwardAnchored);
                            assert_eq!(
                                actual.map(|matched| (matched.start(), matched.end())),
                                expected,
                                "pattern={pattern:?}, haystack={haystack:?}"
                            );
                            assert_eq!(
                                fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                                expected.is_some()
                            );
                            assert_eq!(
                                fre.selected_end(haystack, SearchLimits::unlimited())
                                    .unwrap()
                                    .0,
                                expected.map(|(_, end)| end)
                            );
                            span_comparisons += 1;
                            operation_comparisons += 3;
                        }
                    }
                }
            }
        }
        assert_eq!(span_comparisons, 511_524);
        assert_eq!(operation_comparisons, 1_534_572);
    }

    #[test]
    fn forward_forced_windows_match_find_at_exhaustively() {
        let alphabet = [b'a', b'b', b'Z'];
        let haystacks = byte_words(&alphabet, 4);
        let suffixes = non_empty_byte_words(&alphabet, 2);
        let mut comparisons = 0_usize;
        for suffix in &suffixes {
            if suffix[0] == b'a' {
                continue;
            }
            for lazy in [false, true] {
                for end in [false, true] {
                    let pattern = forward_pattern(b"a", suffix, lazy, end);
                    let fre = PortableBuilder::new(&pattern)
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceForwardAnchored)
                        .build()
                        .unwrap();
                    let upstream = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        for window_start in 0..=haystack.len() {
                            for window_end in window_start..=haystack.len() {
                                let actual = fre
                                    .find_window(
                                        haystack,
                                        SearchWindow::new(window_start, window_end),
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0
                                    .map(|matched| (matched.start(), matched.end()));
                                let expected = upstream
                                    .find_at(haystack, window_start)
                                    .filter(|matched| matched.end() <= window_end)
                                    .map(|matched| (matched.start(), matched.end()));
                                assert_eq!(
                                    actual, expected,
                                    "pattern={pattern:?} haystack={haystack:?} window={window_start}..{window_end}"
                                );
                                comparisons += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 49_568);
    }

    #[test]
    fn forward_arbitrary_bytes_captures_and_existing_plan_overlap_are_exact() {
        let pattern = r"(?-u:\A([\x00\x80\xFF]+)\x7F\xFE\z)";
        let forward = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let haystack = [0, 0x80, 0xFF, 0x7F, 0xFE];
        assert_eq!(
            forward
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 5))
        );

        let unbordered = r"\A[a-z]+Z";
        let forward = PortableBuilder::new(unbordered)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let required = PortableBuilder::new(unbordered)
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        for haystack in [
            b"".as_slice(),
            b"a".as_slice(),
            b"Z".as_slice(),
            b"abcZ".as_slice(),
            b"abcQ".as_slice(),
            b"abcZZ".as_slice(),
        ] {
            let forward_match = forward.find(haystack, SearchLimits::unlimited()).unwrap().0;
            let required_match = required
                .find(haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(forward_match, required_match, "haystack={haystack:?}");
        }
    }

    fn forward_pattern(class: &[u8], suffix: &[u8], lazy: bool, end: bool) -> String {
        let mut pattern = String::from(r"(?-u:\A[");
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        if lazy {
            pattern.push('?');
        }
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn required_pattern(class: &[u8], suffix: &[u8], start: bool, end: bool) -> String {
        let mut pattern = String::from("(?-u:");
        if start {
            pattern.push_str(r"\A");
        }
        pattern.push('[');
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn byte_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    fn non_empty_byte_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        byte_words(alphabet, max_len)
            .into_iter()
            .filter(|word| !word.is_empty())
            .collect()
    }

    fn words(max_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in [b'a', b'b', b'c'] {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            words.extend(next.iter().cloned());
            frontier = next;
        }
        words
    }
}
