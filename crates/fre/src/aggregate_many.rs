use core::{fmt, mem::size_of};

use fre_aggregate::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, CompileAccounting, CompileLimits, CompiledRegex,
    Error as AggregateEngineError, ExecutionAccounting, OperationCertificate, OperationLimits,
    PlanId, RustByteProfile, SpanIter, Strategy,
};
use fre_kernels::{
    ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, ORDERED_LITERAL_COUNT_PLAN_ID,
    ORDERED_LITERAL_SPAN_SUM_PLAN_ID, OrderedLiteralAggregateActualCounters,
    OrderedLiteralAggregateBuildAccounting, OrderedLiteralAggregateBuildError,
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, OrderedLiteralAggregateUpperBounds,
    OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile, ParseError,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Hir, HirKind};

/// Stable report schema for one ordered multi-pattern aggregate plan.
pub const AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION: u32 = 3;

/// Requested output boundary for ordered multi-pattern construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyOutput {
    Count,
    SpanSum,
    /// Complete non-overlapping whole-match spans.
    Spans,
    /// Participating groups when every pattern has the uniform root-capture proof.
    CaptureCount,
}

/// Operation fixed before an admitted plan is built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyOperation {
    Compile,
    Count,
    CaptureCount,
    SpanSum,
    Spans,
}

/// Structural proof used by ordered multi-pattern capture reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyCaptureSemantics {
    /// Every independently parsed pattern is non-nullable and has exactly one
    /// capture at its HIR root. Therefore every selected match contributes
    /// exactly the implicit whole-match group and one participating capture.
    UniformSingleWholeMatchCaptureNonempty,
}

/// Why one pattern cannot join the capture-erased ordered selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyCaptureIneligibility {
    CaptureCountNotOne,
    CaptureNotAtRoot,
    EmptyMatchPossible,
}

/// Construction-selected implementation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyPlanKind {
    /// Ordered finite literals reduced by one reverse DFA and DP ring.
    OrderedLiteral,
    /// Independently parsed HIRs joined by one ordered alternation program.
    ContinuationProgram,
}

/// Profile proof attached to an ordered-literal multi-pattern plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyLiteralSemantics {
    UnicodeOffByteBoundaries,
    UnicodeOnNonemptyUtf8Literals,
}

/// Stable identity of the selected implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyPlanIdentity {
    OrderedLiteral {
        algorithm: &'static str,
        operation: &'static str,
        semantics: AggregateManyLiteralSemantics,
    },
    Continuation(PlanId),
}

/// Complete caller-selected limits for multi-pattern construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    /// Source-byte preflight, parser-reported work and composition visits.
    pub max_composition_work: u64,
    /// Exact observed capacities of temporary HIR and literal-view vectors.
    pub max_composition_scratch_bytes: usize,
    /// Exact observed capacity of the retained per-pattern report vector.
    pub max_report_capacity_bytes: usize,
    /// Selected engine plus retained report-vector capacity.
    pub max_persistent_bytes: usize,
    pub ordered_literal: OrderedLiteralAggregateBuildLimits,
    pub continuation: CompileLimits,
}

impl Default for AggregateManyBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_patterns: 4_096,
            max_pattern_bytes: 4 * 1_048_576,
            max_composition_work: 32 * 1_048_576,
            max_composition_scratch_bytes: 32 * 1_048_576,
            max_report_capacity_bytes: 4 * 1_048_576,
            max_persistent_bytes: 256 * 1_048_576,
            ordered_literal: OrderedLiteralAggregateBuildLimits::default(),
            continuation: CompileLimits::default(),
        }
    }
}

/// Exact syntax identity and parser accounting for one input pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManyPatternReport {
    pub ordinal: usize,
    pub syntax_key: CacheKey,
    pub admission: AdmissionStatus,
    pub syntax: ParseSummary,
}

/// Facade-owned composition accounting, separate from selected-engine facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyCompositionAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub source_preflight_work: u64,
    pub parser_work: u64,
    pub composition_work: u64,
    pub hir_capacity_bytes: usize,
    pub literal_view_capacity_bytes: usize,
    pub report_capacity_bytes: usize,
    pub identity_pattern_capacity_bytes: usize,
    pub scratch_bytes: usize,
}

/// Exact selected-engine construction accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateManyBuildAccounting {
    OrderedLiteral(OrderedLiteralAggregateBuildAccounting),
    Continuation(CompileAccounting),
}

/// Auditable immutable report for an ordered multi-pattern plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManyBuildReport {
    pub schema_version: u32,
    pub patterns: Vec<AggregateManyPatternReport>,
    pub profile: RustProfile,
    pub operation: AggregateManyOperation,
    pub plan: AggregateManyPlanKind,
    pub strategy: Option<Strategy>,
    pub captures_erased: usize,
    pub capture_semantics: Option<AggregateManyCaptureSemantics>,
    pub participating_captures_per_match: Option<usize>,
    pub composition: AggregateManyCompositionAccounting,
    pub build: AggregateManyBuildAccounting,
    pub plan_identity: AggregateManyPlanIdentity,
    pub retained_capacity_bytes: usize,
}

/// Typed construction refusal. No executable plan is published on error.
#[derive(Debug)]
#[non_exhaustive]
pub enum AggregateManyBuildError {
    UnsupportedOutput {
        requested: AggregateManyOutput,
    },
    EmptyPatternSet,
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
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
    ReportCapacityLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    Syntax {
        pattern: usize,
        source: ParseError,
    },
    UnicodeNonLiteral {
        pattern: usize,
    },
    CaptureIneligible {
        pattern: usize,
        reason: AggregateManyCaptureIneligibility,
    },
    OrderedLiteralBuild {
        operation: AggregateManyOperation,
        source: OrderedLiteralAggregateBuildError,
    },
    ContinuationCompile {
        operation: AggregateManyOperation,
        strategy: Strategy,
        source: AggregateEngineError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for AggregateManyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOutput { requested } => {
                write!(f, "ordered build-many output {requested:?} is unsupported")
            }
            Self::EmptyPatternSet => write!(f, "ordered build-many requires at least one pattern"),
            Self::PatternLimit { needed, limit } => {
                write!(
                    f,
                    "ordered build-many needs {needed} patterns, limit is {limit}"
                )
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                f,
                "ordered build-many needs {needed} pattern bytes, limit is {limit}"
            ),
            Self::CompositionWorkLimit { needed, limit } => write!(
                f,
                "ordered build-many composition needs {needed} work, limit is {limit}"
            ),
            Self::CompositionScratchLimit { needed, limit } => write!(
                f,
                "ordered build-many composition needs {needed} scratch bytes, limit is {limit}"
            ),
            Self::ReportCapacityLimit { needed, limit } => write!(
                f,
                "ordered build-many reports retain {needed} capacity bytes, limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => write!(
                f,
                "ordered build-many retains {needed} bytes, limit is {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to reserve {additional} entries for {structure}"),
            Self::Syntax { pattern, source } => {
                write!(
                    f,
                    "ordered build-many pattern {pattern} syntax failed: {source}"
                )
            }
            Self::UnicodeNonLiteral { pattern } => write!(
                f,
                "Unicode ordered build-many pattern {pattern} is not one nonempty canonical UTF-8 literal"
            ),
            Self::CaptureIneligible { pattern, reason } => write!(
                f,
                "ordered build-many capture pattern {pattern} lacks the uniform whole-match proof: {reason:?}"
            ),
            Self::OrderedLiteralBuild { operation, source } => write!(
                f,
                "ordered build-many {operation:?} literal construction failed: {source}"
            ),
            Self::ContinuationCompile {
                operation,
                strategy,
                source,
            } => write!(
                f,
                "ordered build-many {operation:?}/{strategy:?} continuation construction failed: {source}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "ordered build-many overflow computing {computation}")
            }
            Self::InternalInvariant(detail) => {
                write!(f, "ordered build-many invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for AggregateManyBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax { source, .. } => Some(source),
            Self::OrderedLiteralBuild { source, .. } => Some(source),
            Self::ContinuationCompile { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Complete per-invocation limits for either selected plan family.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateManyRunLimits {
    pub ordered_literal: OrderedLiteralAggregateReduceLimits,
    pub continuation: OperationLimits,
}

impl AggregateManyRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            ordered_literal: OrderedLiteralAggregateReduceLimits::unlimited(),
            continuation: OperationLimits {
                max_boundaries: usize::MAX,
                max_table_cells: usize::MAX,
                max_random_access_bytes: usize::MAX,
                max_scratch_bytes: usize::MAX,
                max_log_bytes: usize::MAX,
                max_sequential_bytes: usize::MAX,
                max_match_events: usize::MAX,
                max_output_matches: usize::MAX,
                max_output_bytes: usize::MAX,
                max_span_sum: usize::MAX,
                max_peak_bytes: usize::MAX,
                max_work: usize::MAX,
            },
        }
    }
}

/// Complete limits for one uniform ordered multi-pattern capture reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyCaptureRunLimits {
    /// Limits for the capture-erased ordered whole-match selector.
    pub selector: AggregateManyRunLimits,
    /// Maximum group slots visited by the capture reducer.
    pub max_capture_events: u64,
    /// Maximum participating groups in the published result.
    pub max_capture_count: u64,
}

impl AggregateManyCaptureRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            selector: AggregateManyRunLimits::unlimited(),
            max_capture_events: u64::MAX,
            max_capture_count: u64::MAX,
        }
    }
}

impl Default for AggregateManyCaptureRunLimits {
    fn default() -> Self {
        Self {
            selector: AggregateManyRunLimits::default(),
            max_capture_events: 1_000_000_000,
            max_capture_count: 1_000_000_000,
        }
    }
}

/// Typed selected-plan execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateManyExecutionSource {
    OrderedLiteral(OrderedLiteralAggregateReduceError),
    Continuation(AggregateEngineError),
    CaptureEventsLimit { needed: u64, limit: u64 },
    CaptureCountLimit { needed: u64, limit: u64 },
    ArithmeticOverflow { computation: &'static str },
    InternalInvariant(&'static str),
}

/// Whole-operation failure. No plan or strategy fallback occurs after this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManyExecutionError {
    pub operation: AggregateManyOperation,
    pub plan: AggregateManyPlanKind,
    pub source: AggregateManyExecutionSource,
}

impl fmt::Display for AggregateManyExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ordered build-many {:?}/{:?} execution failed: {:?}",
            self.operation, self.plan, self.source
        )
    }
}

impl std::error::Error for AggregateManyExecutionError {}

/// Exact execution accounting detached from any plan-borrowing kernel identity.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "continuation accounting is an allocation-free authenticated receipt; boxing it would introduce an unreported heap allocation"
)]
pub enum AggregateManyExecutionDetails {
    OrderedLiteral {
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    Continuation {
        certificate: OperationCertificate,
        accounting: ExecutionAccounting,
    },
}

/// Complete admitted count value and selected-plan accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManyCountResult {
    value: u64,
    details: AggregateManyExecutionDetails,
}

/// Complete admitted uniform capture count and selector accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManyCaptureCountResult {
    value: u64,
    matches: u64,
    capture_events: u64,
    details: AggregateManyExecutionDetails,
}

impl AggregateManyCaptureCountResult {
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn matches(&self) -> u64 {
        self.matches
    }

    #[must_use]
    pub const fn capture_events(&self) -> u64 {
        self.capture_events
    }

    #[must_use]
    pub const fn details(&self) -> &AggregateManyExecutionDetails {
        &self.details
    }
}

impl AggregateManyCountResult {
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn details(&self) -> &AggregateManyExecutionDetails {
        &self.details
    }
}

/// Complete admitted span-sum value and selected-plan accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManySpanSumResult {
    value: u64,
    details: AggregateManyExecutionDetails,
}

/// Fully admitted immutable whole-match sequence for ordered patterns.
#[derive(Debug)]
pub struct AggregateManySpans {
    admitted: AdmittedSpans,
    details: AggregateManyExecutionDetails,
}

impl AggregateManySpans {
    #[must_use]
    pub fn iter(&self) -> AggregateManySpanIter<'_> {
        AggregateManySpanIter {
            inner: self.admitted.iter(),
        }
    }

    #[must_use]
    pub const fn details(&self) -> &AggregateManyExecutionDetails {
        &self.details
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.admitted.as_slice().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admitted.as_slice().is_empty()
    }
}

impl<'a> IntoIterator for &'a AggregateManySpans {
    type Item = crate::Match;
    type IntoIter = AggregateManySpanIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Infallible iterator over an operation that was admitted in full.
#[derive(Clone, Debug)]
pub struct AggregateManySpanIter<'a> {
    inner: SpanIter<'a>,
}

impl Iterator for AggregateManySpanIter<'_> {
    type Item = crate::Match;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|span| crate::Match {
            start: span.start,
            end: span.end,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for AggregateManySpanIter<'_> {}
impl core::iter::FusedIterator for AggregateManySpanIter<'_> {}

impl AggregateManySpanSumResult {
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn details(&self) -> &AggregateManyExecutionDetails {
        &self.details
    }
}

/// Borrowing builder that performs cardinality and source-byte preflight before parsing.
#[derive(Clone, Debug)]
pub struct AggregateManyBuilder<'a> {
    patterns: &'a [String],
    profile: RustProfile,
    limits: AggregateManyBuildLimits,
    strategy: Strategy,
}

impl<'a> AggregateManyBuilder<'a> {
    #[must_use]
    pub fn new(patterns: &'a [String]) -> Self {
        Self {
            patterns,
            profile: RustProfile::default(),
            limits: AggregateManyBuildLimits::default(),
            strategy: Strategy::ReverseSequentialRows,
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
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: AggregateManyBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub const fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn build_count(self) -> Result<AggregateManyCountRegex, AggregateManyBuildError> {
        self.build_plan(AggregateManyOperation::Count)
            .map(AggregateManyCountRegex)
    }

    /// Construct an ordered multi-pattern capture reducer only when every
    /// pattern has the same statically proved capture participation.
    pub fn build_capture_count(
        self,
    ) -> Result<AggregateManyCaptureCountRegex, AggregateManyBuildError> {
        self.build_plan(AggregateManyOperation::CaptureCount)
            .map(AggregateManyCaptureCountRegex)
    }

    /// Construct and publish a fresh complete ordered multi-pattern artifact.
    ///
    /// [`AggregateManyCompileRegex::verify_count`] executes only the retained
    /// plan; it does not parse, compile, reselect, or fall back.
    pub fn build_compile(self) -> Result<AggregateManyCompileRegex, AggregateManyBuildError> {
        self.build_plan(AggregateManyOperation::Compile)
            .map(AggregateManyCompileRegex)
    }

    pub fn build_span_sum(self) -> Result<AggregateManySpanSumRegex, AggregateManyBuildError> {
        self.build_plan(AggregateManyOperation::SpanSum)
            .map(AggregateManySpanSumRegex)
    }

    /// Construct complete ordered multi-pattern span materialization.
    ///
    /// This operation deliberately selects the bounded continuation program:
    /// the ordered-literal reducer does not retain complete spans.
    pub fn build_spans(self) -> Result<AggregateManySpansRegex, AggregateManyBuildError> {
        self.build_plan(AggregateManyOperation::Spans)
            .map(AggregateManySpansRegex)
    }

    pub fn build_output(
        self,
        output: AggregateManyOutput,
    ) -> Result<AggregateManyRegex, AggregateManyBuildError> {
        match output {
            AggregateManyOutput::Count => self.build_count().map(AggregateManyRegex::Count),
            AggregateManyOutput::CaptureCount => self
                .build_capture_count()
                .map(AggregateManyRegex::CaptureCount),
            AggregateManyOutput::SpanSum => self.build_span_sum().map(AggregateManyRegex::SpanSum),
            AggregateManyOutput::Spans => self.build_spans().map(AggregateManyRegex::Spans),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps source preflight, independent parse identities, plan selection and publication ordered"
    )]
    fn build_plan(
        self,
        operation: AggregateManyOperation,
    ) -> Result<AggregateManyPlan, AggregateManyBuildError> {
        let count = self.patterns.len();
        if count == 0 {
            return Err(AggregateManyBuildError::EmptyPatternSet);
        }
        enforce_usize(count, self.limits.max_patterns, |needed, limit| {
            AggregateManyBuildError::PatternLimit { needed, limit }
        })?;
        let pattern_bytes = self.patterns.iter().try_fold(0_usize, |total, pattern| {
            total
                .checked_add(pattern.len())
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "pattern byte sum",
                })
        })?;
        enforce_usize(
            pattern_bytes,
            self.limits.max_pattern_bytes,
            |needed, limit| AggregateManyBuildError::PatternBytesLimit { needed, limit },
        )?;
        let count_u64 =
            u64::try_from(count).map_err(|_| AggregateManyBuildError::ArithmeticOverflow {
                computation: "pattern count as work",
            })?;
        let bytes_u64 = u64::try_from(pattern_bytes).map_err(|_| {
            AggregateManyBuildError::ArithmeticOverflow {
                computation: "pattern bytes as work",
            }
        })?;
        let source_preflight_work = count_u64.checked_add(bytes_u64).ok_or(
            AggregateManyBuildError::ArithmeticOverflow {
                computation: "source preflight work",
            },
        )?;
        enforce_u64(source_preflight_work, self.limits.max_composition_work)?;

        let logical_hir_bytes = count.checked_mul(size_of::<Hir>()).ok_or(
            AggregateManyBuildError::ArithmeticOverflow {
                computation: "logical HIR vector bytes",
            },
        )?;
        // Complete spans always use the continuation engine. They never build
        // the temporary ordered-literal view vector, so charging that vector
        // here would make the published exact scratch requirement unusable as
        // a construction limit.
        let logical_literal_view_bytes = if operation == AggregateManyOperation::Spans {
            0
        } else {
            count.checked_mul(size_of::<&[u8]>()).ok_or(
                AggregateManyBuildError::ArithmeticOverflow {
                    computation: "logical literal-view bytes",
                },
            )?
        };
        let logical_scratch = logical_hir_bytes
            .checked_add(logical_literal_view_bytes)
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "logical composition scratch",
            })?;
        enforce_scratch(logical_scratch, self.limits.max_composition_scratch_bytes)?;
        let logical_report_bytes = count
            .checked_mul(size_of::<AggregateManyPatternReport>())
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "logical report capacity",
            })?;
        enforce_report(logical_report_bytes, self.limits.max_report_capacity_bytes)?;

        let mut hirs = Vec::new();
        hirs.try_reserve_exact(count)
            .map_err(|_| AggregateManyBuildError::AllocationFailed {
                structure: "per-pattern HIRs",
                additional: count,
            })?;
        let hir_capacity_bytes = capacity_bytes::<Hir>(hirs.capacity(), "HIR capacity bytes")?;
        let mut reports = Vec::new();
        reports.try_reserve_exact(count).map_err(|_| {
            AggregateManyBuildError::AllocationFailed {
                structure: "per-pattern reports",
                additional: count,
            }
        })?;
        let report_capacity_bytes = capacity_bytes::<AggregateManyPatternReport>(
            reports.capacity(),
            "report capacity bytes",
        )?;
        enforce_report(report_capacity_bytes, self.limits.max_report_capacity_bytes)?;
        enforce_scratch(
            hir_capacity_bytes,
            self.limits.max_composition_scratch_bytes,
        )?;

        let compatibility = CompatibilityProfile::RustBytes(self.profile.clone());
        let mut parser_work = 0_u64;
        let mut captures = 0_usize;
        let mut identity_pattern_capacity_bytes = 0_usize;
        for (ordinal, pattern) in self.patterns.iter().enumerate() {
            let request = fre_syntax::ParseRequest::rust(pattern.as_str(), compatibility.clone())
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety);
            let parsed =
                fre_syntax::parse(request).map_err(|source| AggregateManyBuildError::Syntax {
                    pattern: ordinal,
                    source,
                })?;
            parser_work = parser_work.checked_add(parsed.summary.parse_work).ok_or(
                AggregateManyBuildError::ArithmeticOverflow {
                    computation: "parser work sum",
                },
            )?;
            let parsed_captures = usize::try_from(parsed.summary.captures).map_err(|_| {
                AggregateManyBuildError::ArithmeticOverflow {
                    computation: "capture count as usize",
                }
            })?;
            captures = captures.checked_add(parsed_captures).ok_or(
                AggregateManyBuildError::ArithmeticOverflow {
                    computation: "capture count sum",
                },
            )?;
            identity_pattern_capacity_bytes = identity_pattern_capacity_bytes
                .checked_add(parsed.key.pattern.capacity_bytes())
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "source identity capacity sum",
                })?;
            let CanonicalPattern::Rust(rust) = parsed.pattern else {
                return Err(AggregateManyBuildError::InternalInvariant(
                    "Rust bytes request produced non-Rust canonical pattern",
                ));
            };
            if operation == AggregateManyOperation::CaptureCount {
                if parsed_captures != 1 {
                    return Err(AggregateManyBuildError::CaptureIneligible {
                        pattern: ordinal,
                        reason: AggregateManyCaptureIneligibility::CaptureCountNotOne,
                    });
                }
                if !matches!(rust.hir.kind(), HirKind::Capture(_)) {
                    return Err(AggregateManyBuildError::CaptureIneligible {
                        pattern: ordinal,
                        reason: AggregateManyCaptureIneligibility::CaptureNotAtRoot,
                    });
                }
                if !matches!(rust.hir.properties().minimum_len(), Some(minimum) if minimum > 0) {
                    return Err(AggregateManyBuildError::CaptureIneligible {
                        pattern: ordinal,
                        reason: AggregateManyCaptureIneligibility::EmptyMatchPossible,
                    });
                }
            }
            reports.push(AggregateManyPatternReport {
                ordinal,
                syntax_key: parsed.key,
                admission: parsed.admission_status,
                syntax: parsed.summary,
            });
            hirs.push(rust.hir);
        }
        let composition_visits =
            count_u64
                .checked_add(1)
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "composition visits",
                })?;
        let composition_work = source_preflight_work
            .checked_add(parser_work)
            .and_then(|work| work.checked_add(composition_visits))
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "total composition work",
            })?;
        enforce_u64(composition_work, self.limits.max_composition_work)?;
        let metadata_persistent_bytes = report_capacity_bytes
            .checked_add(identity_pattern_capacity_bytes)
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "retained metadata bytes",
            })?;
        if metadata_persistent_bytes > self.limits.max_persistent_bytes {
            return Err(AggregateManyBuildError::PersistentLimit {
                needed: metadata_persistent_bytes,
                limit: self.limits.max_persistent_bytes,
            });
        }
        let engine_persistent_limit = self
            .limits
            .max_persistent_bytes
            .checked_sub(metadata_persistent_bytes)
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "engine persistent allowance",
            })?;

        let unicode = self.profile.options.unicode;
        let case_insensitive = self.profile.options.case_insensitive;
        let mut all_literals = !case_insensitive;
        let mut first_nonliteral = None;
        if all_literals {
            for (ordinal, hir) in hirs.iter().enumerate() {
                if direct_whole_match_literal(hir, unicode).is_none() {
                    all_literals = false;
                    first_nonliteral = Some(ordinal);
                    break;
                }
            }
        } else {
            first_nonliteral = Some(0);
        }
        if unicode && !all_literals {
            return Err(AggregateManyBuildError::UnicodeNonLiteral {
                pattern: first_nonliteral.unwrap_or(0),
            });
        }

        let mut literal_view_capacity_bytes = 0_usize;
        let ordered_literal_operation = operation != AggregateManyOperation::Spans;
        let (engine, plan, build, plan_identity, engine_persistent) = if all_literals
            && ordered_literal_operation
        {
            let mut literals = Vec::new();
            literals.try_reserve_exact(count).map_err(|_| {
                AggregateManyBuildError::AllocationFailed {
                    structure: "ordered literal views",
                    additional: count,
                }
            })?;
            literal_view_capacity_bytes =
                capacity_bytes::<&[u8]>(literals.capacity(), "literal-view capacity bytes")?;
            let scratch_bytes = hir_capacity_bytes
                .checked_add(literal_view_capacity_bytes)
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "observed composition scratch",
                })?;
            enforce_scratch(scratch_bytes, self.limits.max_composition_scratch_bytes)?;
            for hir in &hirs {
                let literal = direct_whole_match_literal(hir, unicode).ok_or(
                    AggregateManyBuildError::InternalInvariant(
                        "literal plan lost its direct-root proof",
                    ),
                )?;
                literals.push(literal);
            }
            match operation {
                AggregateManyOperation::Compile
                | AggregateManyOperation::Count
                | AggregateManyOperation::CaptureCount => {
                    let mut literal_limits = self.limits.ordered_literal;
                    literal_limits.max_persistent_bytes = literal_limits
                        .max_persistent_bytes
                        .min(engine_persistent_limit);
                    let plan = OrderedLiteralCountPlan::build(&literals, literal_limits).map_err(
                        |source| AggregateManyBuildError::OrderedLiteralBuild { operation, source },
                    )?;
                    let accounting = plan.build_accounting();
                    (
                        AggregateManyEngine::OrderedLiteralCount(plan),
                        AggregateManyPlanKind::OrderedLiteral,
                        AggregateManyBuildAccounting::OrderedLiteral(accounting),
                        AggregateManyPlanIdentity::OrderedLiteral {
                            algorithm: ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                            operation: ORDERED_LITERAL_COUNT_PLAN_ID,
                            semantics: literal_semantics(unicode),
                        },
                        accounting.persistent_bytes,
                    )
                }
                AggregateManyOperation::SpanSum => {
                    let mut literal_limits = self.limits.ordered_literal;
                    literal_limits.max_persistent_bytes = literal_limits
                        .max_persistent_bytes
                        .min(engine_persistent_limit);
                    let plan = OrderedLiteralSpanSumPlan::build(&literals, literal_limits)
                        .map_err(|source| AggregateManyBuildError::OrderedLiteralBuild {
                            operation,
                            source,
                        })?;
                    let accounting = plan.build_accounting();
                    (
                        AggregateManyEngine::OrderedLiteralSpanSum(plan),
                        AggregateManyPlanKind::OrderedLiteral,
                        AggregateManyBuildAccounting::OrderedLiteral(accounting),
                        AggregateManyPlanIdentity::OrderedLiteral {
                            algorithm: ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                            operation: ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
                            semantics: literal_semantics(unicode),
                        },
                        accounting.persistent_bytes,
                    )
                }
                AggregateManyOperation::Spans => {
                    return Err(AggregateManyBuildError::InternalInvariant(
                        "span materialization reached ordered-literal construction",
                    ));
                }
            }
        } else {
            let combined = Hir::alternation(hirs);
            let mut continuation_limits = self.limits.continuation;
            continuation_limits.max_program_bytes = continuation_limits
                .max_program_bytes
                .min(engine_persistent_limit);
            let continuation_profile = if unicode {
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
            } else {
                RustByteProfile::PINNED_1_12_4
            };
            let engine = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &combined,
                continuation_profile,
                continuation_limits,
            )
            .map_err(|source| AggregateManyBuildError::ContinuationCompile {
                operation,
                strategy: self.strategy,
                source,
            })?;
            let accounting = engine.compile_accounting();
            if accounting.captures_erased != captures {
                return Err(AggregateManyBuildError::InternalInvariant(
                    "combined compiler capture accounting differs from parsed patterns",
                ));
            }
            let identity = engine.plan_id();
            (
                AggregateManyEngine::Continuation(engine),
                AggregateManyPlanKind::ContinuationProgram,
                AggregateManyBuildAccounting::Continuation(accounting),
                AggregateManyPlanIdentity::Continuation(identity),
                accounting.program_bytes,
            )
        };
        let retained_capacity_bytes = engine_persistent
            .checked_add(report_capacity_bytes)
            .and_then(|bytes| bytes.checked_add(identity_pattern_capacity_bytes))
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "facade persistent bytes",
            })?;
        if retained_capacity_bytes > self.limits.max_persistent_bytes {
            return Err(AggregateManyBuildError::PersistentLimit {
                needed: retained_capacity_bytes,
                limit: self.limits.max_persistent_bytes,
            });
        }
        let scratch_bytes = hir_capacity_bytes
            .checked_add(literal_view_capacity_bytes)
            .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                computation: "published composition scratch",
            })?;
        let composition = AggregateManyCompositionAccounting {
            patterns: count,
            pattern_bytes,
            source_preflight_work,
            parser_work,
            composition_work,
            hir_capacity_bytes,
            literal_view_capacity_bytes,
            report_capacity_bytes,
            identity_pattern_capacity_bytes,
            scratch_bytes,
        };
        let report = AggregateManyBuildReport {
            schema_version: AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION,
            patterns: reports,
            profile: self.profile,
            operation,
            plan,
            strategy: (plan == AggregateManyPlanKind::ContinuationProgram).then_some(self.strategy),
            captures_erased: captures,
            capture_semantics: (operation == AggregateManyOperation::CaptureCount)
                .then_some(AggregateManyCaptureSemantics::UniformSingleWholeMatchCaptureNonempty),
            participating_captures_per_match: (operation == AggregateManyOperation::CaptureCount)
                .then_some(1),
            composition,
            build,
            plan_identity,
            retained_capacity_bytes,
        };
        Ok(AggregateManyPlan {
            engine,
            report,
            strategy: self.strategy,
        })
    }
}

/// Operation-typed result of [`AggregateManyBuilder::build_output`].
#[derive(Debug)]
pub enum AggregateManyRegex {
    Count(AggregateManyCountRegex),
    CaptureCount(AggregateManyCaptureCountRegex),
    SpanSum(AggregateManySpanSumRegex),
    Spans(AggregateManySpansRegex),
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a selected immutable plan would add an otherwise unnecessary unaccounted allocation"
)]
enum AggregateManyEngine {
    OrderedLiteralCount(OrderedLiteralCountPlan),
    OrderedLiteralSpanSum(OrderedLiteralSpanSumPlan),
    Continuation(CompiledRegex),
}

#[derive(Debug)]
struct AggregateManyPlan {
    engine: AggregateManyEngine,
    report: AggregateManyBuildReport,
    strategy: Strategy,
}

impl AggregateManyPlan {
    fn execution_error(&self, source: AggregateManyExecutionSource) -> AggregateManyExecutionError {
        AggregateManyExecutionError {
            operation: self.report.operation,
            plan: self.report.plan,
            source,
        }
    }

    fn count(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<AggregateManyCountResult, AggregateManyExecutionError> {
        match &self.engine {
            AggregateManyEngine::OrderedLiteralCount(plan) => {
                let result = plan
                    .count(haystack, limits.ordered_literal)
                    .map_err(|source| {
                        self.execution_error(AggregateManyExecutionSource::OrderedLiteral(source))
                    })?;
                Ok(AggregateManyCountResult {
                    value: result.count,
                    details: AggregateManyExecutionDetails::OrderedLiteral {
                        upper_bounds: result.accounting.upper_bounds,
                        actual: result.accounting.actual,
                    },
                })
            }
            AggregateManyEngine::Continuation(engine) => {
                let (admitted, value) =
                    self.admit_continuation_count(engine, haystack, limits.continuation)?;
                Ok(AggregateManyCountResult {
                    value,
                    details: AggregateManyExecutionDetails::Continuation {
                        certificate: admitted.certificate().clone(),
                        accounting: admitted.accounting(),
                    },
                })
            }
            AggregateManyEngine::OrderedLiteralSpanSum(_) => Err(self.execution_error(
                AggregateManyExecutionSource::InternalInvariant(
                    "count operation retained a span-sum engine",
                ),
            )),
        }
    }

    fn count_value(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        match &self.engine {
            // The ordered-literal kernel currently publishes exact reducer
            // accounting with its value, so retain that established path.
            AggregateManyEngine::OrderedLiteralCount(_) => {
                self.count(haystack, limits).map(|result| result.value)
            }
            AggregateManyEngine::Continuation(engine) => {
                let value = engine
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        self.strategy,
                        limits.continuation,
                    )
                    .map_err(|source| {
                        self.execution_error(AggregateManyExecutionSource::Continuation(source))
                    })?;
                u64::try_from(value).map_err(|_| {
                    self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                        "continuation count does not fit u64",
                    ))
                })
            }
            AggregateManyEngine::OrderedLiteralSpanSum(_) => Err(self.execution_error(
                AggregateManyExecutionSource::InternalInvariant(
                    "count operation retained a span-sum engine",
                ),
            )),
        }
    }

    fn admit_continuation_count(
        &self,
        engine: &CompiledRegex,
        haystack: &[u8],
        limits: OperationLimits,
    ) -> Result<(AdmittedCount, u64), AggregateManyExecutionError> {
        let admitted = engine
            .admit_count(haystack, 0..haystack.len(), self.strategy, limits)
            .map_err(|source| {
                self.execution_error(AggregateManyExecutionSource::Continuation(source))
            })?;
        let value = u64::try_from(admitted.value()).map_err(|_| {
            self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                "continuation count does not fit u64",
            ))
        })?;
        Ok((admitted, value))
    }

    fn admit_continuation_span_sum(
        &self,
        engine: &CompiledRegex,
        haystack: &[u8],
        limits: OperationLimits,
    ) -> Result<(AdmittedSpanSum, u64), AggregateManyExecutionError> {
        let admitted = engine
            .admit_span_sum(haystack, 0..haystack.len(), self.strategy, limits)
            .map_err(|source| {
                self.execution_error(AggregateManyExecutionSource::Continuation(source))
            })?;
        let value = u64::try_from(admitted.value()).map_err(|_| {
            self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                "continuation span sum does not fit u64",
            ))
        })?;
        Ok((admitted, value))
    }

    fn continuation_span_sum_value(
        &self,
        engine: &CompiledRegex,
        haystack: &[u8],
        limits: OperationLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        let value = engine
            .span_sum_value(haystack, 0..haystack.len(), self.strategy, limits)
            .map_err(|source| {
                self.execution_error(AggregateManyExecutionSource::Continuation(source))
            })?;
        u64::try_from(value).map_err(|_| {
            self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                "continuation span sum does not fit u64",
            ))
        })
    }
}

/// Fresh complete ordered multi-pattern compile artifact.
#[derive(Debug)]
pub struct AggregateManyCompileRegex(AggregateManyPlan);

impl AggregateManyCompileRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateManyBuildReport {
        &self.0.report
    }

    /// Verify whole-match count with the already-published immutable plan.
    pub fn verify_count(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<AggregateManyCountResult, AggregateManyExecutionError> {
        self.0.count(haystack, limits)
    }
}

/// Compiled ordered multi-pattern count operation.
#[derive(Debug)]
pub struct AggregateManyCountRegex(AggregateManyPlan);

impl AggregateManyCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateManyBuildReport {
        &self.0.report
    }

    pub fn count(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<AggregateManyCountResult, AggregateManyExecutionError> {
        self.0.count(haystack, limits)
    }

    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        self.0.count_value(haystack, limits)
    }
}

/// Compiled ordered multi-pattern uniform capture-count operation.
#[derive(Debug)]
pub struct AggregateManyCaptureCountRegex(AggregateManyPlan);

impl AggregateManyCaptureCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateManyBuildReport {
        &self.0.report
    }

    pub fn count_captures(
        &self,
        haystack: &[u8],
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<AggregateManyCaptureCountResult, AggregateManyExecutionError> {
        let selected = self.0.count(haystack, limits.selector)?;
        let participating = self
            .0
            .report
            .participating_captures_per_match
            .ok_or_else(|| {
                self.0
                    .execution_error(AggregateManyExecutionSource::InternalInvariant(
                        "capture-count plan lacks participation proof",
                    ))
            })?;
        if self.0.report.capture_semantics
            != Some(AggregateManyCaptureSemantics::UniformSingleWholeMatchCaptureNonempty)
            || participating != 1
        {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture-count plan retained an invalid participation proof",
                )));
        }
        let groups_per_match = u64::try_from(participating)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                self.0
                    .execution_error(AggregateManyExecutionSource::ArithmeticOverflow {
                        computation: "capture groups per match",
                    })
            })?;
        let capture_events = selected
            .value
            .checked_mul(groups_per_match)
            .ok_or_else(|| {
                self.0
                    .execution_error(AggregateManyExecutionSource::ArithmeticOverflow {
                        computation: "capture events",
                    })
            })?;
        if capture_events > limits.max_capture_events {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureEventsLimit {
                    needed: capture_events,
                    limit: limits.max_capture_events,
                }));
        }
        let value = capture_events;
        if value > limits.max_capture_count {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureCountLimit {
                    needed: value,
                    limit: limits.max_capture_count,
                }));
        }
        Ok(AggregateManyCaptureCountResult {
            value,
            matches: selected.value,
            capture_events,
            details: selected.details,
        })
    }

    pub fn count_captures_value(
        &self,
        haystack: &[u8],
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        self.count_captures(haystack, limits)
            .map(|result| result.value)
    }
}

/// Compiled ordered multi-pattern complete-span operation.
#[derive(Debug)]
pub struct AggregateManySpansRegex(AggregateManyPlan);

impl AggregateManySpansRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateManyBuildReport {
        &self.0.report
    }

    /// Execute once over the complete original haystack.
    pub fn spans(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<AggregateManySpans, AggregateManyExecutionError> {
        let AggregateManyEngine::Continuation(engine) = &self.0.engine else {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "span operation retained a non-continuation engine",
                )));
        };
        let admitted = engine
            .admit_spans(
                haystack,
                0..haystack.len(),
                self.0.strategy,
                limits.continuation,
            )
            .map_err(|source| {
                self.0
                    .execution_error(AggregateManyExecutionSource::Continuation(source))
            })?;
        let details = AggregateManyExecutionDetails::Continuation {
            certificate: admitted.certificate().clone(),
            accounting: admitted.accounting(),
        };
        Ok(AggregateManySpans { admitted, details })
    }
}

/// Compiled ordered multi-pattern matched-byte-sum operation.
#[derive(Debug)]
pub struct AggregateManySpanSumRegex(AggregateManyPlan);

impl AggregateManySpanSumRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateManyBuildReport {
        &self.0.report
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<AggregateManySpanSumResult, AggregateManyExecutionError> {
        match &self.0.engine {
            AggregateManyEngine::OrderedLiteralSpanSum(plan) => {
                let result = plan
                    .span_sum(haystack, limits.ordered_literal)
                    .map_err(|source| {
                        self.0
                            .execution_error(AggregateManyExecutionSource::OrderedLiteral(source))
                    })?;
                Ok(AggregateManySpanSumResult {
                    value: result.span_sum,
                    details: AggregateManyExecutionDetails::OrderedLiteral {
                        upper_bounds: result.accounting.upper_bounds,
                        actual: result.accounting.actual,
                    },
                })
            }
            AggregateManyEngine::Continuation(engine) => {
                let (admitted, value) =
                    self.0
                        .admit_continuation_span_sum(engine, haystack, limits.continuation)?;
                Ok(AggregateManySpanSumResult {
                    value,
                    details: AggregateManyExecutionDetails::Continuation {
                        certificate: admitted.certificate().clone(),
                        accounting: admitted.accounting(),
                    },
                })
            }
            AggregateManyEngine::OrderedLiteralCount(_) => {
                Err(self
                    .0
                    .execution_error(AggregateManyExecutionSource::InternalInvariant(
                        "span-sum wrapper retained a count engine",
                    )))
            }
        }
    }

    pub fn span_sum_value(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        match &self.0.engine {
            // Preserve the established ordered-literal accounting path while
            // specializing only the distinct continuation branch.
            AggregateManyEngine::OrderedLiteralSpanSum(_) => {
                self.span_sum(haystack, limits).map(|result| result.value)
            }
            AggregateManyEngine::Continuation(engine) => {
                self.0
                    .continuation_span_sum_value(engine, haystack, limits.continuation)
            }
            AggregateManyEngine::OrderedLiteralCount(_) => {
                Err(self
                    .0
                    .execution_error(AggregateManyExecutionSource::InternalInvariant(
                        "span-sum wrapper retained a count engine",
                    )))
            }
        }
    }
}

fn direct_whole_match_literal(hir: &Hir, unicode: bool) -> Option<&[u8]> {
    if unicode {
        return match hir.kind() {
            HirKind::Literal(literal)
                if !literal.0.is_empty() && core::str::from_utf8(literal.0.as_ref()).is_ok() =>
            {
                Some(literal.0.as_ref())
            }
            _ => None,
        };
    }
    let mut current = hir;
    loop {
        match current.kind() {
            HirKind::Capture(capture) => current = capture.sub.as_ref(),
            HirKind::Empty => return Some(b""),
            HirKind::Literal(literal) => return Some(literal.0.as_ref()),
            _ => return None,
        }
    }
}

const fn literal_semantics(unicode: bool) -> AggregateManyLiteralSemantics {
    if unicode {
        AggregateManyLiteralSemantics::UnicodeOnNonemptyUtf8Literals
    } else {
        AggregateManyLiteralSemantics::UnicodeOffByteBoundaries
    }
}

fn capacity_bytes<T>(
    capacity: usize,
    computation: &'static str,
) -> Result<usize, AggregateManyBuildError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(AggregateManyBuildError::ArithmeticOverflow { computation })
}

fn enforce_usize(
    needed: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> AggregateManyBuildError,
) -> Result<(), AggregateManyBuildError> {
    if needed > limit {
        Err(error(needed, limit))
    } else {
        Ok(())
    }
}

fn enforce_u64(needed: u64, limit: u64) -> Result<(), AggregateManyBuildError> {
    if needed > limit {
        Err(AggregateManyBuildError::CompositionWorkLimit { needed, limit })
    } else {
        Ok(())
    }
}

fn enforce_scratch(needed: usize, limit: usize) -> Result<(), AggregateManyBuildError> {
    if needed > limit {
        Err(AggregateManyBuildError::CompositionScratchLimit { needed, limit })
    } else {
        Ok(())
    }
}

fn enforce_report(needed: usize, limit: usize) -> Result<(), AggregateManyBuildError> {
    if needed > limit {
        Err(AggregateManyBuildError::ReportCapacityLimit { needed, limit })
    } else {
        Ok(())
    }
}
