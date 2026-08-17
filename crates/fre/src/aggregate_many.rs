use core::{fmt, mem::size_of, ops::Range};

use fre_aggregate::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, CachedCountSession, CachedCountSessionFootprint,
    CompileAccounting, CompileLimits, CompiledRegex, ContinuationSweepWorkspace,
    CountValueCounterAttempt, Error as AggregateEngineError, ExecutionAccounting,
    OperationAttemptKind, OperationCertificate, OperationCounterValue, OperationLimits,
    OperationPhysicalRoute, OperationPrepublicationFallback, PlanId, Resource as AggregateResource,
    RustByteProfile, SpanIter, Strategy,
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
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind, Look};

/// Stable report schema for one ordered multi-pattern aggregate plan.
pub const AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION: u32 = 5;

/// Stable identity for the source-independent total byte-cover theorem.
pub const AGGREGATE_MANY_TOTAL_BYTE_COVER_SPAN_SUM_ALGORITHM_ID: &str =
    "aggregate-many.nonnullable-look-free-one-byte-cover-span-sum.v1";

/// Stable identity for the construction-sealed byte unit-cover proof.
pub const AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID: &str =
    "aggregate-many.nonnullable-look-free-one-byte-cover-proof.v1";

/// Stable identity for removing a contiguous block of guarded ASCII words
/// immediately shadowed by a greedy ASCII-word fallback.
pub const AGGREGATE_MANY_ASCII_WORD_SHADOW_ALGORITHM_ID: &str =
    "aggregate-many.guarded-ascii-word-fallback-shadow.v1";

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
    /// Nonnullable byte languages with a look-free one-byte total cover.
    TotalByteCoverSpanSum,
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
    TotalByteCoverSpanSum(AggregateManyTotalByteCoverIdentity),
    Continuation(PlanId),
}

/// Structural facts that prove every source byte belongs to one selected match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyTotalByteCoverIdentity {
    pub algorithm: &'static str,
    pub patterns: usize,
    pub nonnullable_patterns: usize,
    pub look_free_patterns: usize,
    pub contributing_patterns: usize,
    pub covered_bytes: usize,
    pub unicode: bool,
}

/// Exact construction accounting for the source-independent total-cover proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyTotalByteCoverBuildAccounting {
    pub patterns: usize,
    pub nonnullable_patterns: usize,
    pub look_free_patterns: usize,
    pub contributing_patterns: usize,
    pub covered_bytes: usize,
    pub hir_visits: usize,
    pub class_byte_visits: usize,
    pub union_word_visits: usize,
    pub work: usize,
    pub allocations: usize,
    pub persistent_bytes: usize,
}

/// Construction-sealed proof that every source byte begins at least one
/// accepted one-byte witness.
///
/// Earlier ordered arms may contain assertions or accept longer strings. The
/// proof requires every arm to be non-nullable and only uses the exact
/// one-byte languages of look-free arms as witnesses. A complete 256-byte
/// union therefore proves that ordered matching advances from every source
/// boundary without changing priority or match length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyByteUnitCoverProof {
    pub algorithm: &'static str,
    pub patterns: usize,
    pub nonnullable_patterns: usize,
    pub look_free_patterns: usize,
    pub contributing_patterns: usize,
    pub covered_bytes: usize,
    pub unicode: bool,
    pub hir_visits: usize,
    pub class_byte_visits: usize,
    pub union_word_visits: usize,
    pub work: usize,
    pub allocations: usize,
}

/// Source-independent proof that a contiguous ordered block contributes no
/// distinct whole-match spans. Every removed arm is `\bL\b`, and the arm
/// immediately following the block is a greedy ASCII-word identifier that
/// accepts exactly the same endpoint whenever that literal arm accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyAsciiWordShadowProof {
    pub algorithm: &'static str,
    pub source_patterns: usize,
    pub first_shadowed_pattern: usize,
    pub shadowed_patterns: usize,
    pub fallback_pattern: usize,
    pub shadowed_literal_bytes: usize,
    pub hir_visits: usize,
    pub class_range_visits: usize,
    pub byte_visits: usize,
    pub work: usize,
    pub allocations: usize,
}

/// Source-independent execution envelope for one total-cover span sum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyTotalByteCoverUpperBounds {
    pub input_bytes: usize,
    pub boundaries: usize,
    pub logical_source_bytes: usize,
    pub work: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub span_sum: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact counters committed by one total-cover span sum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateManyTotalByteCoverActual {
    pub logical_source_bytes: usize,
    pub work: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub span_sum: usize,
    pub scratch_bytes: usize,
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
    /// Exact source-independent HIR work sealed by a retained byte unit-cover
    /// proof for `CaptureCount`; zero when no proof is published.
    pub byte_unit_cover_proof_work: u64,
    /// Exact source-independent HIR/class work for an optional guarded-word
    /// shadow proof retained by a complete-span plan.
    pub ascii_word_shadow_proof_work: u64,
    pub composition_work: u64,
    pub hir_capacity_bytes: usize,
    pub literal_view_capacity_bytes: usize,
    pub report_capacity_bytes: usize,
    pub identity_pattern_capacity_bytes: usize,
    pub scratch_bytes: usize,
}

/// Exact selected-engine construction accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "continuation accounting is an allocation-free authenticated receipt; boxing it would break Copy and introduce an unreported heap allocation"
)]
pub enum AggregateManyBuildAccounting {
    OrderedLiteral(OrderedLiteralAggregateBuildAccounting),
    TotalByteCoverSpanSum(AggregateManyTotalByteCoverBuildAccounting),
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
    /// Optional construction-sealed eligibility proof for a caller-owned
    /// cached `CaptureCount` session.
    pub byte_unit_cover: Option<AggregateManyByteUnitCoverProof>,
    /// Optional complete-span equivalence proof used to simplify the retained
    /// ordered selector before continuation compilation.
    pub ascii_word_shadow: Option<AggregateManyAsciiWordShadowProof>,
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
    TotalByteCoverBuild {
        source: AggregateEngineError,
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
            Self::TotalByteCoverBuild { source } => write!(
                f,
                "ordered build-many total-byte-cover construction failed: {source}"
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
            Self::TotalByteCoverBuild { source } | Self::ContinuationCompile { source, .. } => {
                Some(source)
            }
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
    TotalByteCover(AggregateEngineError),
    Continuation(AggregateEngineError),
    CaptureSessionPlanMismatch,
    CaptureSessionHaystackLengthMismatch { expected: usize, actual: usize },
    CaptureSessionLimitsMismatch,
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
    TotalByteCover {
        upper_bounds: AggregateManyTotalByteCoverUpperBounds,
        actual: AggregateManyTotalByteCoverActual,
    },
    Continuation {
        certificate: OperationCertificate,
        accounting: ExecutionAccounting,
    },
    /// Exact summary from the persistent ordered continuation sweep. The
    /// enclosing complete-span reducer independently observes every emitted
    /// endpoint pair.
    ContinuationSweep {
        plan_id: PlanId,
        range: Range<usize>,
        limits: OperationLimits,
        matches: usize,
        span_sum: usize,
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

/// Exact retained storage for one aggregate-many capture Count session.
pub type AggregateManyCaptureCountSessionFootprint = CachedCountSessionFootprint;

/// Caller-owned reusable value-only session for one semantically proved
/// Unicode-off aggregate-many `CaptureCount` plan.
///
/// The session is bound to one compiled plan, one exact haystack length and
/// one exact complete capture policy. It retains no source bytes, match spans,
/// capture offsets or prior result.
#[derive(Debug)]
pub struct AggregateManyCaptureCountSession {
    selector: CachedCountSession,
    plan_id: PlanId,
    haystack_len: usize,
    limits: AggregateManyCaptureRunLimits,
}

impl AggregateManyCaptureCountSession {
    /// Exact source-free storage retained by this session.
    #[must_use]
    pub const fn footprint(&self) -> AggregateManyCaptureCountSessionFootprint {
        self.selector.footprint()
    }

    /// Exact haystack length sealed at construction.
    #[must_use]
    pub const fn haystack_len(&self) -> usize {
        self.haystack_len
    }
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

/// Summary and selected-plan identity for a one-pass complete-span visit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManySpanVisit {
    matches: usize,
    span_sum: usize,
    details: AggregateManyExecutionDetails,
}

impl AggregateManySpanVisit {
    /// Number of complete spans delivered to the visitor.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.matches
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matches == 0
    }

    /// Checked sum of every delivered span width.
    #[must_use]
    pub const fn span_sum(&self) -> usize {
        self.span_sum
    }

    /// Selected continuation certificate and exact execution accounting.
    #[must_use]
    pub const fn details(&self) -> &AggregateManyExecutionDetails {
        &self.details
    }
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
        let unicode = self.profile.options.unicode;
        // This pruning theorem remains available to explicitly opted-in
        // generic callers, but it is a workload-specific intrinsic for formal
        // benchmark policy. Reuse the continuation policy bit so ordered-many
        // construction cannot silently re-enable it when continuation
        // intrinsics are quarantined by the caller.
        let ascii_word_shadow = if self.limits.continuation.allow_workload_specific_intrinsics
            && operation == AggregateManyOperation::Spans
            && !unicode
            && !self.profile.options.case_insensitive
        {
            ascii_word_shadow_proof(&hirs)
        } else {
            None
        };
        if let Some(proof) = ascii_word_shadow {
            let end = proof
                .first_shadowed_pattern
                .checked_add(proof.shadowed_patterns)
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "ASCII word-shadow removal end",
                })?;
            hirs.drain(proof.first_shadowed_pattern..end);
        }
        let byte_cover_shape = (!unicode
            && matches!(
                operation,
                AggregateManyOperation::CaptureCount | AggregateManyOperation::SpanSum
            ))
        .then(|| total_byte_cover_shape(&hirs))
        .flatten();
        let byte_unit_cover = if operation == AggregateManyOperation::CaptureCount {
            byte_cover_shape.map(|shape| AggregateManyByteUnitCoverProof {
                algorithm: AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID,
                patterns: shape.patterns,
                nonnullable_patterns: shape.nonnullable_patterns,
                look_free_patterns: shape.look_free_patterns,
                contributing_patterns: shape.contributing_patterns,
                covered_bytes: shape.covered_bytes,
                unicode: false,
                hir_visits: shape.hir_visits,
                class_byte_visits: shape.byte_visits,
                union_word_visits: shape.union_word_visits,
                work: shape.work,
                allocations: 0,
            })
        } else {
            None
        };
        let byte_unit_cover_proof_work = byte_unit_cover
            .map(|proof| {
                u64::try_from(proof.work).map_err(|_| AggregateManyBuildError::ArithmeticOverflow {
                    computation: "byte unit-cover proof work as u64",
                })
            })
            .transpose()?
            .unwrap_or(0);
        let ascii_word_shadow_proof_work = ascii_word_shadow
            .map(|proof| {
                u64::try_from(proof.work).map_err(|_| AggregateManyBuildError::ArithmeticOverflow {
                    computation: "ASCII word-shadow proof work as u64",
                })
            })
            .transpose()?
            .unwrap_or(0);
        let composition_visits =
            count_u64
                .checked_add(1)
                .ok_or(AggregateManyBuildError::ArithmeticOverflow {
                    computation: "composition visits",
                })?;
        let composition_work = source_preflight_work
            .checked_add(parser_work)
            .and_then(|work| work.checked_add(composition_visits))
            .and_then(|work| work.checked_add(byte_unit_cover_proof_work))
            .and_then(|work| work.checked_add(ascii_word_shadow_proof_work))
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
        let total_byte_cover_shape = (operation == AggregateManyOperation::SpanSum)
            .then_some(byte_cover_shape)
            .flatten();
        if unicode && !all_literals {
            return Err(AggregateManyBuildError::UnicodeNonLiteral {
                pattern: first_nonliteral.unwrap_or(0),
            });
        }

        let mut literal_view_capacity_bytes = 0_usize;
        let ordered_literal_operation = operation != AggregateManyOperation::Spans;
        let (engine, plan, build, plan_identity, engine_persistent) = if let Some(shape) =
            total_byte_cover_shape
        {
            let plan = TotalByteCoverSpanSumPlan::build(
                shape,
                self.limits.continuation,
                engine_persistent_limit,
            )
            .map_err(|source| AggregateManyBuildError::TotalByteCoverBuild { source })?;
            let accounting = plan.build_accounting;
            (
                AggregateManyEngine::TotalByteCoverSpanSum(plan),
                AggregateManyPlanKind::TotalByteCoverSpanSum,
                AggregateManyBuildAccounting::TotalByteCoverSpanSum(accounting),
                AggregateManyPlanIdentity::TotalByteCoverSpanSum(
                    AggregateManyTotalByteCoverIdentity {
                        algorithm: AGGREGATE_MANY_TOTAL_BYTE_COVER_SPAN_SUM_ALGORITHM_ID,
                        patterns: accounting.patterns,
                        nonnullable_patterns: accounting.nonnullable_patterns,
                        look_free_patterns: accounting.look_free_patterns,
                        contributing_patterns: accounting.contributing_patterns,
                        covered_bytes: accounting.covered_bytes,
                        unicode: false,
                    },
                ),
                accounting.persistent_bytes,
            )
        } else if all_literals && ordered_literal_operation {
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
            let compiled_captures = captures
                .checked_sub(ascii_word_shadow.map_or(0, |proof| proof.shadowed_patterns))
                .ok_or(AggregateManyBuildError::InternalInvariant(
                    "ASCII word-shadow capture removal exceeded parsed captures",
                ))?;
            if accounting.captures_erased != compiled_captures {
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
            byte_unit_cover_proof_work,
            ascii_word_shadow_proof_work,
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
            byte_unit_cover,
            ascii_word_shadow,
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
    TotalByteCoverSpanSum(TotalByteCoverSpanSumPlan),
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
            AggregateManyEngine::TotalByteCoverSpanSum(_) => Err(self.execution_error(
                AggregateManyExecutionSource::InternalInvariant(
                    "count operation retained a total-byte-cover span-sum engine",
                ),
            )),
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
            AggregateManyEngine::TotalByteCoverSpanSum(_) => Err(self.execution_error(
                AggregateManyExecutionSource::InternalInvariant(
                    "count operation retained a total-byte-cover span-sum engine",
                ),
            )),
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

    fn capture_count_session_engine(
        &self,
    ) -> Result<Option<&CompiledRegex>, AggregateManyExecutionError> {
        if self.report.operation != AggregateManyOperation::CaptureCount {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session requested from another operation",
                )),
            );
        }
        if self.report.profile.options.unicode
            || self.report.plan != AggregateManyPlanKind::ContinuationProgram
            || self.strategy != Strategy::ReverseSequentialRows
        {
            return Ok(None);
        }
        let Some(proof) = self.report.byte_unit_cover else {
            return Ok(None);
        };
        let proof_work = u64::try_from(proof.work).map_err(|_| {
            self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                "byte unit-cover proof work does not fit u64",
            ))
        })?;
        if proof.algorithm != AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID
            || proof.patterns != self.report.patterns.len()
            || proof.nonnullable_patterns != proof.patterns
            || proof.covered_bytes != 256
            || proof.unicode
            || proof.allocations != 0
            || proof_work != self.report.composition.byte_unit_cover_proof_work
            || self.report.capture_semantics
                != Some(AggregateManyCaptureSemantics::UniformSingleWholeMatchCaptureNonempty)
            || self.report.participating_captures_per_match != Some(1)
            || self.report.captures_erased != proof.patterns
            || self.report.strategy != Some(self.strategy)
        {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session proof does not close",
                )),
            );
        }
        let AggregateManyPlanIdentity::Continuation(identity) = self.report.plan_identity else {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session plan identity is not a continuation",
                )),
            );
        };
        let AggregateManyBuildAccounting::Continuation(_) = self.report.build else {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session build accounting is not a continuation",
                )),
            );
        };
        let AggregateManyEngine::Continuation(engine) = &self.engine else {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session retained a non-continuation engine",
                )),
            );
        };
        if identity != engine.plan_id() {
            return Err(
                self.execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "capture Count session engine identity differs from its report",
                )),
            );
        }
        Ok(Some(engine))
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
        let value = self.capture_value_from_matches(selected.value, limits)?;
        Ok(AggregateManyCaptureCountResult {
            value,
            matches: selected.value,
            capture_events: value,
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

    /// Return the exact source-free retained storage required by an eligible
    /// caller-owned cached `CaptureCount` session.
    ///
    /// `Ok(None)` means the immutable plan lacks the byte unit-cover,
    /// Unicode-off continuation, reverse-row, or byte-transition proof. No
    /// source bytes are inspected.
    pub fn cached_count_session_footprint(
        &self,
        haystack_len: usize,
    ) -> Result<Option<AggregateManyCaptureCountSessionFootprint>, AggregateManyExecutionError>
    {
        let Some(engine) = self.0.capture_count_session_engine()? else {
            return Ok(None);
        };
        engine
            .cached_count_session_footprint(haystack_len)
            .map_err(|source| {
                self.0
                    .execution_error(AggregateManyExecutionSource::Continuation(source))
            })
    }

    /// Construct a caller-owned session for repeated full-haystack
    /// `CaptureCount` operations at one exact input length and policy.
    ///
    /// Construction allocates the complete fixed storage. Every successful
    /// operation through the returned session performs zero allocation.
    pub fn prepare_cached_count_session(
        &self,
        haystack_len: usize,
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<Option<AggregateManyCaptureCountSession>, AggregateManyExecutionError> {
        let Some(engine) = self.0.capture_count_session_engine()? else {
            return Ok(None);
        };
        let maximum_matches = u64::try_from(haystack_len).map_err(|_| {
            self.0
                .execution_error(AggregateManyExecutionSource::ArithmeticOverflow {
                    computation: "capture session maximum matches",
                })
        })?;
        let maximum_capture_events = maximum_matches.checked_mul(2).ok_or_else(|| {
            self.0
                .execution_error(AggregateManyExecutionSource::ArithmeticOverflow {
                    computation: "capture session maximum capture events",
                })
        })?;
        if maximum_capture_events > limits.max_capture_events
            || maximum_capture_events > limits.max_capture_count
        {
            return Ok(None);
        }
        let Some(selector) = engine
            .cached_count_session(haystack_len, limits.selector.continuation)
            .map_err(|source| {
                self.0
                    .execution_error(AggregateManyExecutionSource::Continuation(source))
            })?
        else {
            return Ok(None);
        };
        Ok(Some(AggregateManyCaptureCountSession {
            selector,
            plan_id: engine.plan_id(),
            haystack_len,
            limits,
        }))
    }

    /// Execute one full-haystack value-only `CaptureCount` operation through a
    /// caller-owned cache.
    ///
    /// Cache saturation or an operation-local refusal cold-replays through
    /// the ordinary admitted path and authenticates its complete accounting.
    /// Plan, length and policy binding failures refuse before source access.
    pub fn count_captures_value_with_session(
        &self,
        session: &mut AggregateManyCaptureCountSession,
        haystack: &[u8],
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        let Some(engine) = self.0.capture_count_session_engine()? else {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureSessionPlanMismatch));
        };
        if session.plan_id != engine.plan_id() {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureSessionPlanMismatch));
        }
        if session.haystack_len != haystack.len() {
            return Err(self.0.execution_error(
                AggregateManyExecutionSource::CaptureSessionHaystackLengthMismatch {
                    expected: session.haystack_len,
                    actual: haystack.len(),
                },
            ));
        }
        if session.limits != limits {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureSessionLimitsMismatch));
        }

        let attempt = engine.count_value_with_cached_session_and_counters(
            &mut session.selector,
            haystack,
            limits.selector.continuation,
        );
        if let Err(
            AggregateEngineError::SessionPlanMismatch
            | AggregateEngineError::SessionHaystackLengthMismatch { .. }
            | AggregateEngineError::SessionLimitsMismatch,
        ) = &attempt
        {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "validated aggregate session diverged from its selector binding",
                )));
        }
        match attempt {
            Ok(attempt)
                if Self::cached_count_attempt_closes(
                    engine,
                    &attempt,
                    session.footprint(),
                    haystack.len(),
                    limits,
                ) =>
            {
                let matches = u64::try_from(attempt.value).map_err(|_| {
                    self.0
                        .execution_error(AggregateManyExecutionSource::InternalInvariant(
                            "cached continuation Count does not fit u64",
                        ))
                })?;
                self.capture_value_from_matches(matches, limits)
            }
            Ok(_) | Err(_) => self.authenticated_cold_replay(haystack, limits),
        }
    }

    fn capture_value_from_matches(
        &self,
        matches: u64,
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
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
        let capture_events = matches.checked_mul(groups_per_match).ok_or_else(|| {
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
        if capture_events > limits.max_capture_count {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::CaptureCountLimit {
                    needed: capture_events,
                    limit: limits.max_capture_count,
                }));
        }
        Ok(capture_events)
    }

    fn cached_count_attempt_closes(
        engine: &CompiledRegex,
        attempt: &CountValueCounterAttempt,
        footprint: AggregateManyCaptureCountSessionFootprint,
        haystack_len: usize,
        limits: AggregateManyCaptureRunLimits,
    ) -> bool {
        let receipt = &attempt.receipt;
        let certificate = &receipt.certificate;
        receipt.closes()
            && receipt.value == OperationCounterValue::Count(attempt.value)
            && certificate.regex_plan_id == engine.plan_id()
            && certificate.authenticates_limits(limits.selector.continuation)
            && certificate.strategy == Strategy::ReverseSequentialRows
            && certificate.operation == OperationAttemptKind::Count
            && certificate.physical_route == OperationPhysicalRoute::CachedFrontier
            && certificate.prepublication_fallback == OperationPrepublicationFallback::None
            && certificate.range == (0..haystack_len)
            && certificate.actual_allocations == 0
            && certificate.prospective_allocations == 0
            && certificate.log_bytes == footprint.boundary_bytes
            && certificate.random_access_bytes == footprint.cache_bytes
            && certificate.scratch_bytes == footprint.cache_bytes
            && certificate.sequential_bytes_bound == footprint.sequential_bytes
            && certificate.peak_bytes == footprint.retained_bytes
            && receipt.accounting.log_bytes == footprint.boundary_bytes
            && receipt.accounting.random_access_peak_bytes == footprint.cache_bytes
            && receipt.accounting.scratch_peak_bytes == footprint.cache_bytes
            && receipt.accounting.peak_bytes == footprint.retained_bytes
            && receipt.accounting.emitted_matches == attempt.value
            && receipt.counters.allocations == 0
    }

    fn authenticated_cold_replay(
        &self,
        haystack: &[u8],
        limits: AggregateManyCaptureRunLimits,
    ) -> Result<u64, AggregateManyExecutionError> {
        let result = self.count_captures(haystack, limits)?;
        let AggregateManyExecutionDetails::Continuation {
            certificate,
            accounting,
        } = result.details()
        else {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "cached capture Count cold replay selected a non-continuation plan",
                )));
        };
        let AggregateManyPlanIdentity::Continuation(plan_id) = self.0.report.plan_identity else {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "cached capture Count cold replay lost its continuation identity",
                )));
        };
        if !continuation_count_accounting_closes(
            certificate,
            accounting,
            plan_id,
            haystack.len(),
            limits.selector.continuation,
            result.matches(),
        ) || result.capture_events() != result.value()
            || self.capture_value_from_matches(result.matches(), limits)? != result.value()
        {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "cached capture Count cold replay accounting did not close",
                )));
        }
        Ok(result.value())
    }
}

fn continuation_count_accounting_closes(
    certificate: &OperationCertificate,
    accounting: &ExecutionAccounting,
    plan_id: PlanId,
    haystack_len: usize,
    limits: OperationLimits,
    matches: u64,
) -> bool {
    let Ok(matches) = usize::try_from(matches) else {
        return false;
    };
    let Some(sequential_bytes) = accounting
        .sequential_bytes_written
        .checked_add(accounting.sequential_bytes_read)
    else {
        return false;
    };
    certificate.regex_plan_id == plan_id
        && certificate.authenticates_limits(limits)
        && certificate.strategy == Strategy::ReverseSequentialRows
        && certificate.operation == OperationAttemptKind::Count
        && certificate.range == (0..haystack_len)
        && certificate.actual_allocations <= certificate.prospective_allocations
        && sequential_bytes <= certificate.sequential_bytes_bound
        && accounting.random_access_peak_bytes <= certificate.random_access_bytes
        && accounting.scratch_peak_bytes <= certificate.scratch_bytes
        && accounting.log_bytes <= certificate.log_bytes
        && accounting.output_bytes <= certificate.output_bytes
        && accounting.peak_bytes <= certificate.peak_bytes
        && accounting.work <= certificate.work_bound
        && accounting.successful_paths <= certificate.match_events
        && accounting.emitted_matches == matches
        && matches <= certificate.output_matches
}

/// Compiled ordered multi-pattern complete-span operation.
#[derive(Debug)]
pub struct AggregateManySpansRegex(AggregateManyPlan);

/// Caller-owned persistent workspace for complete aggregate-many span visits.
#[derive(Debug, Default)]
pub struct AggregateManySpansWorkspace {
    sweep: ContinuationSweepWorkspace,
}

impl AggregateManySpansWorkspace {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sweep: ContinuationSweepWorkspace::new(),
        }
    }
}

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

    /// Visit every complete non-overlapping match span in one continuation
    /// scan without allocating an output span vector.
    ///
    /// The visitor receives absolute half-open offsets in the original
    /// haystack. Pattern priority and empty-match progress are those of the
    /// construction-selected ordered alternation.
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
        visitor: F,
    ) -> Result<AggregateManySpanVisit, AggregateManyExecutionError>
    where
        F: FnMut(crate::Match),
    {
        let mut workspace = AggregateManySpansWorkspace::new();
        self.visit_spans_with_workspace(haystack, limits, &mut workspace, visitor)
    }

    /// Visit every complete span while retaining learned ordered-DFA
    /// transitions in a caller-owned workspace when construction published an
    /// ASCII-word shadow proof. All other plans use the incumbent visitor.
    pub fn visit_spans_with_workspace<F>(
        &self,
        haystack: &[u8],
        limits: AggregateManyRunLimits,
        workspace: &mut AggregateManySpansWorkspace,
        mut visitor: F,
    ) -> Result<AggregateManySpanVisit, AggregateManyExecutionError>
    where
        F: FnMut(crate::Match),
    {
        let AggregateManyEngine::Continuation(engine) = &self.0.engine else {
            return Err(self
                .0
                .execution_error(AggregateManyExecutionSource::InternalInvariant(
                    "span visit retained a non-continuation engine",
                )));
        };
        if self.0.report.ascii_word_shadow.is_some() {
            let swept = engine
                .visit_spans_with_sweep_workspace(
                    haystack,
                    0..haystack.len(),
                    self.0.strategy,
                    limits.continuation,
                    &mut workspace.sweep,
                    |span| {
                        visitor(crate::Match {
                            start: span.start,
                            end: span.end,
                        });
                    },
                )
                .map_err(|source| {
                    self.0
                        .execution_error(AggregateManyExecutionSource::Continuation(source))
                })?;
            if let Some(swept) = swept {
                let matches = swept.len();
                let span_sum = swept.span_sum();
                return Ok(AggregateManySpanVisit {
                    matches,
                    span_sum,
                    details: AggregateManyExecutionDetails::ContinuationSweep {
                        plan_id: engine.plan_id(),
                        range: 0..haystack.len(),
                        limits: limits.continuation,
                        matches,
                        span_sum,
                    },
                });
            }
        }
        let attempt = engine
            .admit_span_visit_cached_when_amortized_with_receipt(
                haystack,
                0..haystack.len(),
                self.0.strategy,
                limits.continuation,
                |span| {
                    visitor(crate::Match {
                        start: span.start,
                        end: span.end,
                    });
                },
            )
            .map_err(|error| {
                self.0
                    .execution_error(AggregateManyExecutionSource::Continuation(error.source))
            })?;
        let details = AggregateManyExecutionDetails::Continuation {
            certificate: attempt.admitted.certificate().clone(),
            accounting: attempt.admitted.accounting(),
        };
        Ok(AggregateManySpanVisit {
            matches: attempt.admitted.matches(),
            span_sum: attempt.admitted.span_sum(),
            details,
        })
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
            AggregateManyEngine::TotalByteCoverSpanSum(plan) => {
                let (value, upper_bounds, actual) = plan
                    .span_sum(haystack.len(), limits.continuation)
                    .map_err(|source| {
                        self.0
                            .execution_error(AggregateManyExecutionSource::TotalByteCover(source))
                    })?;
                Ok(AggregateManySpanSumResult {
                    value,
                    details: AggregateManyExecutionDetails::TotalByteCover {
                        upper_bounds,
                        actual,
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
            AggregateManyEngine::TotalByteCoverSpanSum(plan) => plan
                .span_sum(haystack.len(), limits.continuation)
                .map(|(value, _, _)| value)
                .map_err(|source| {
                    self.0
                        .execution_error(AggregateManyExecutionSource::TotalByteCover(source))
                }),
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

#[derive(Clone, Copy, Debug)]
struct TotalByteCoverShape {
    patterns: usize,
    nonnullable_patterns: usize,
    look_free_patterns: usize,
    contributing_patterns: usize,
    covered_bytes: usize,
    hir_visits: usize,
    byte_visits: usize,
    union_word_visits: usize,
    work: usize,
}

#[derive(Debug)]
struct TotalByteCoverSpanSumPlan {
    build_accounting: AggregateManyTotalByteCoverBuildAccounting,
}

impl TotalByteCoverSpanSumPlan {
    fn build(
        shape: TotalByteCoverShape,
        limits: CompileLimits,
        persistent_limit: usize,
    ) -> Result<Self, AggregateEngineError> {
        enforce_total_cover_resource(shape.work, limits.max_work, AggregateResource::CompileWork)?;
        let persistent_bytes = size_of::<Self>();
        enforce_total_cover_resource(
            persistent_bytes,
            limits.max_program_bytes.min(persistent_limit),
            AggregateResource::ProgramBytes,
        )?;
        Ok(Self {
            build_accounting: AggregateManyTotalByteCoverBuildAccounting {
                patterns: shape.patterns,
                nonnullable_patterns: shape.nonnullable_patterns,
                look_free_patterns: shape.look_free_patterns,
                contributing_patterns: shape.contributing_patterns,
                covered_bytes: shape.covered_bytes,
                hir_visits: shape.hir_visits,
                class_byte_visits: shape.byte_visits,
                union_word_visits: shape.union_word_visits,
                work: shape.work,
                allocations: 0,
                persistent_bytes,
            },
        })
    }

    fn span_sum(
        &self,
        input_bytes: usize,
        limits: OperationLimits,
    ) -> Result<
        (
            u64,
            AggregateManyTotalByteCoverUpperBounds,
            AggregateManyTotalByteCoverActual,
        ),
        AggregateEngineError,
    > {
        let boundaries =
            input_bytes
                .checked_add(1)
                .ok_or(AggregateEngineError::ArithmeticOverflow {
                    resource: AggregateResource::Boundaries,
                })?;
        let upper_bounds = AggregateManyTotalByteCoverUpperBounds {
            input_bytes,
            boundaries,
            logical_source_bytes: 0,
            work: 1,
            match_events: input_bytes,
            output_matches: input_bytes,
            span_sum: input_bytes,
            scratch_bytes: 0,
            persistent_bytes: self.build_accounting.persistent_bytes,
            peak_bytes: self.build_accounting.persistent_bytes,
        };
        for (required, limit, resource) in [
            (
                upper_bounds.boundaries,
                limits.max_boundaries,
                AggregateResource::Boundaries,
            ),
            (
                upper_bounds.logical_source_bytes,
                limits.max_random_access_bytes,
                AggregateResource::RandomAccessBytes,
            ),
            (
                upper_bounds.scratch_bytes,
                limits.max_scratch_bytes,
                AggregateResource::ScratchBytes,
            ),
            (
                upper_bounds.match_events,
                limits.max_match_events,
                AggregateResource::MatchEvents,
            ),
            (
                upper_bounds.output_matches,
                limits.max_output_matches,
                AggregateResource::OutputMatches,
            ),
            (
                upper_bounds.span_sum,
                limits.max_span_sum,
                AggregateResource::SpanSum,
            ),
            (
                upper_bounds.peak_bytes,
                limits.max_peak_bytes,
                AggregateResource::PeakBytes,
            ),
            (
                upper_bounds.work,
                limits.max_work,
                AggregateResource::ExecutionWork,
            ),
        ] {
            enforce_total_cover_resource(required, limit, resource)?;
        }
        let value =
            u64::try_from(input_bytes).map_err(|_| AggregateEngineError::ArithmeticOverflow {
                resource: AggregateResource::SpanSum,
            })?;
        let actual = AggregateManyTotalByteCoverActual {
            logical_source_bytes: 0,
            work: 1,
            match_events: 0,
            output_matches: 0,
            span_sum: input_bytes,
            scratch_bytes: 0,
        };
        Ok((value, upper_bounds, actual))
    }
}

fn enforce_total_cover_resource(
    required: usize,
    limit: usize,
    resource: AggregateResource,
) -> Result<(), AggregateEngineError> {
    if required > limit {
        return Err(AggregateEngineError::ResourceLimit {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct ByteSet([u64; 4]);

impl ByteSet {
    fn insert(&mut self, byte: u8) {
        let index = usize::from(byte);
        self.0[index / 64] |= 1_u64 << (index % 64);
    }

    fn union_with(&mut self, other: Self, analysis: &mut TotalByteCoverAnalysis) -> Option<()> {
        for (left, right) in self.0.iter_mut().zip(other.0) {
            analysis.union_words = analysis.union_words.checked_add(1)?;
            *left |= right;
        }
        Some(())
    }

    fn len(self) -> usize {
        self.0
            .into_iter()
            .map(|word| usize::from(u8::try_from(word.count_ones()).unwrap_or(u8::MAX)))
            .sum()
    }

    fn is_empty(self) -> bool {
        self.0 == [0; 4]
    }
}

#[derive(Clone, Copy, Debug)]
struct ZeroAndOneByteLanguage {
    empty: bool,
    one_byte: ByteSet,
}

#[derive(Clone, Copy, Debug, Default)]
struct TotalByteCoverAnalysis {
    hir: usize,
    bytes: usize,
    union_words: usize,
}

impl TotalByteCoverAnalysis {
    fn one_byte_language(&mut self, hir: &Hir) -> Option<ZeroAndOneByteLanguage> {
        self.hir = self.hir.checked_add(1)?;
        match hir.kind() {
            HirKind::Empty => Some(ZeroAndOneByteLanguage {
                empty: true,
                one_byte: ByteSet::default(),
            }),
            HirKind::Literal(literal) => {
                let mut one_byte = ByteSet::default();
                if let [byte] = literal.0.as_ref() {
                    self.bytes = self.bytes.checked_add(1)?;
                    one_byte.insert(*byte);
                }
                Some(ZeroAndOneByteLanguage {
                    empty: literal.0.is_empty(),
                    one_byte,
                })
            }
            HirKind::Class(Class::Bytes(class)) => {
                let mut one_byte = ByteSet::default();
                for range in class.iter() {
                    for byte in range.start()..=range.end() {
                        self.bytes = self.bytes.checked_add(1)?;
                        one_byte.insert(byte);
                    }
                }
                Some(ZeroAndOneByteLanguage {
                    empty: false,
                    one_byte,
                })
            }
            HirKind::Class(Class::Unicode(class)) => {
                let mut one_byte = ByteSet::default();
                for range in class.iter() {
                    let start = u32::from(range.start());
                    if start > 0x7F {
                        continue;
                    }
                    let end = u32::from(range.end()).min(0x7F);
                    for scalar in start..=end {
                        self.bytes = self.bytes.checked_add(1)?;
                        one_byte.insert(u8::try_from(scalar).ok()?);
                    }
                }
                Some(ZeroAndOneByteLanguage {
                    empty: false,
                    one_byte,
                })
            }
            HirKind::Look(_) => None,
            HirKind::Repetition(repetition) => {
                let sub = self.one_byte_language(repetition.sub.as_ref())?;
                let can_repeat = repetition.max != Some(0);
                let one_byte = if can_repeat && (repetition.min <= 1 || sub.empty) {
                    sub.one_byte
                } else {
                    ByteSet::default()
                };
                Some(ZeroAndOneByteLanguage {
                    empty: repetition.min == 0 || sub.empty,
                    one_byte,
                })
            }
            HirKind::Capture(capture) => self.one_byte_language(capture.sub.as_ref()),
            HirKind::Concat(parts) => {
                let mut combined = ZeroAndOneByteLanguage {
                    empty: true,
                    one_byte: ByteSet::default(),
                };
                for part in parts {
                    let right = self.one_byte_language(part)?;
                    let mut one_byte = ByteSet::default();
                    if right.empty {
                        one_byte.union_with(combined.one_byte, self)?;
                    }
                    if combined.empty {
                        one_byte.union_with(right.one_byte, self)?;
                    }
                    combined = ZeroAndOneByteLanguage {
                        empty: combined.empty && right.empty,
                        one_byte,
                    };
                }
                Some(combined)
            }
            HirKind::Alternation(parts) => {
                let mut combined = ZeroAndOneByteLanguage {
                    empty: false,
                    one_byte: ByteSet::default(),
                };
                for part in parts {
                    let branch = self.one_byte_language(part)?;
                    combined.empty |= branch.empty;
                    combined.one_byte.union_with(branch.one_byte, self)?;
                }
                Some(combined)
            }
        }
    }
}

/// Prove a source-independent span-sum identity.
///
/// At every byte position, the look-free witnesses collectively accept the
/// exact one-byte string beginning there. Ordered `find_iter` therefore cannot
/// skip that position, although an earlier pattern may select a longer match.
/// Since every pattern is nonnullable, each selected match advances. Induction
/// from position zero partitions the complete haystack into adjacent nonempty
/// matches, so the sum of their lengths is exactly the haystack length.
fn total_byte_cover_shape(hirs: &[Hir]) -> Option<TotalByteCoverShape> {
    let mut analysis = TotalByteCoverAnalysis::default();
    let mut coverage = ByteSet::default();
    let mut nonnullable_patterns = 0_usize;
    let mut look_free_patterns = 0_usize;
    let mut contributing_patterns = 0_usize;
    for hir in hirs {
        if !matches!(hir.properties().minimum_len(), Some(minimum) if minimum > 0) {
            return None;
        }
        nonnullable_patterns = nonnullable_patterns.checked_add(1)?;
        let Some(language) = analysis.one_byte_language(hir) else {
            continue;
        };
        look_free_patterns = look_free_patterns.checked_add(1)?;
        if !language.one_byte.is_empty() {
            contributing_patterns = contributing_patterns.checked_add(1)?;
        }
        coverage.union_with(language.one_byte, &mut analysis)?;
    }
    let covered_bytes = coverage.len();
    if covered_bytes != 256 {
        return None;
    }
    let work = hirs
        .len()
        .checked_add(analysis.hir)?
        .checked_add(analysis.bytes)?
        .checked_add(analysis.union_words)?;
    Some(TotalByteCoverShape {
        patterns: hirs.len(),
        nonnullable_patterns,
        look_free_patterns,
        contributing_patterns,
        covered_bytes,
        hir_visits: analysis.hir,
        byte_visits: analysis.bytes,
        union_word_visits: analysis.union_words,
        work,
    })
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

#[derive(Default)]
struct AsciiWordShadowMeter {
    hir_visits: usize,
    class_range_visits: usize,
    byte_visits: usize,
}

impl AsciiWordShadowMeter {
    fn hir(&mut self) -> Option<()> {
        self.hir_visits = self.hir_visits.checked_add(1)?;
        Some(())
    }

    fn ranges(&mut self, count: usize) -> Option<()> {
        self.class_range_visits = self.class_range_visits.checked_add(count)?;
        Some(())
    }

    fn bytes(&mut self, count: usize) -> Option<()> {
        self.byte_visits = self.byte_visits.checked_add(count)?;
        Some(())
    }

    fn work(&self) -> Option<usize> {
        self.hir_visits
            .checked_add(self.class_range_visits)?
            .checked_add(self.byte_visits)
    }
}

fn root_capture_body<'a>(hir: &'a Hir, meter: &mut AsciiWordShadowMeter) -> Option<&'a Hir> {
    meter.hir()?;
    let HirKind::Capture(capture) = hir.kind() else {
        return None;
    };
    Some(capture.sub.as_ref())
}

fn ascii_word_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn class_is_nonempty_ascii_word_subset(
    class: &ClassBytes,
    meter: &mut AsciiWordShadowMeter,
) -> Option<bool> {
    meter.ranges(class.ranges().len())?;
    Some(
        !class.ranges().is_empty()
            && class
                .ranges()
                .iter()
                .all(|range| (range.start()..=range.end()).all(ascii_word_byte)),
    )
}

fn class_contains_byte(
    class: &ClassBytes,
    byte: u8,
    meter: &mut AsciiWordShadowMeter,
) -> Option<bool> {
    meter.ranges(class.ranges().len())?;
    Some(
        class
            .ranges()
            .iter()
            .any(|range| range.start() <= byte && byte <= range.end()),
    )
}

fn ascii_identifier_fallback<'a>(
    hir: &'a Hir,
    meter: &mut AsciiWordShadowMeter,
) -> Option<(&'a ClassBytes, &'a ClassBytes)> {
    let body = root_capture_body(hir, meter)?;
    meter.hir()?;
    let HirKind::Concat(parts) = body.kind() else {
        return None;
    };
    let [first, rest] = parts.as_slice() else {
        return None;
    };
    meter.hir()?;
    let HirKind::Class(Class::Bytes(first)) = first.kind() else {
        return None;
    };
    meter.hir()?;
    let HirKind::Repetition(repetition) = rest.kind() else {
        return None;
    };
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return None;
    }
    meter.hir()?;
    let HirKind::Class(Class::Bytes(rest)) = repetition.sub.kind() else {
        return None;
    };
    if !class_is_nonempty_ascii_word_subset(first, meter)?
        || !class_is_nonempty_ascii_word_subset(rest, meter)?
    {
        return None;
    }
    Some((first, rest))
}

fn guarded_ascii_word_literal<'a>(
    hir: &'a Hir,
    meter: &mut AsciiWordShadowMeter,
) -> Option<&'a [u8]> {
    let body = root_capture_body(hir, meter)?;
    meter.hir()?;
    let HirKind::Concat(parts) = body.kind() else {
        return None;
    };
    let [left, literal, right] = parts.as_slice() else {
        return None;
    };
    meter.hir()?;
    if !matches!(left.kind(), HirKind::Look(Look::WordAscii)) {
        return None;
    }
    meter.hir()?;
    let HirKind::Literal(literal) = literal.kind() else {
        return None;
    };
    meter.bytes(literal.0.len())?;
    if literal.0.is_empty() || !literal.0.iter().copied().all(ascii_word_byte) {
        return None;
    }
    meter.hir()?;
    if !matches!(right.kind(), HirKind::Look(Look::WordAscii)) {
        return None;
    }
    Some(literal.0.as_ref())
}

fn ascii_word_shadow_proof(hirs: &[Hir]) -> Option<AggregateManyAsciiWordShadowProof> {
    let mut meter = AsciiWordShadowMeter::default();
    let mut best = None::<(usize, usize, usize)>;
    for fallback in 1..hirs.len() {
        let Some((first_class, rest_class)) =
            ascii_identifier_fallback(&hirs[fallback], &mut meter)
        else {
            continue;
        };
        let mut first_shadowed = fallback;
        let mut literal_bytes = 0_usize;
        while first_shadowed > 0 {
            let Some(literal) = guarded_ascii_word_literal(&hirs[first_shadowed - 1], &mut meter)
            else {
                break;
            };
            if !class_contains_byte(first_class, literal[0], &mut meter)?
                || !literal[1..]
                    .iter()
                    .copied()
                    .all(|byte| class_contains_byte(rest_class, byte, &mut meter).unwrap_or(false))
            {
                break;
            }
            literal_bytes = literal_bytes.checked_add(literal.len())?;
            first_shadowed -= 1;
        }
        let shadowed = fallback - first_shadowed;
        if shadowed > 0 && best.is_none_or(|(_, old, _)| shadowed > old) {
            best = Some((first_shadowed, shadowed, literal_bytes));
        }
    }
    let (first_shadowed_pattern, shadowed_patterns, shadowed_literal_bytes) = best?;
    Some(AggregateManyAsciiWordShadowProof {
        algorithm: AGGREGATE_MANY_ASCII_WORD_SHADOW_ALGORITHM_ID,
        source_patterns: hirs.len(),
        first_shadowed_pattern,
        shadowed_patterns,
        fallback_pattern: first_shadowed_pattern.checked_add(shadowed_patterns)?,
        shadowed_literal_bytes,
        hir_visits: meter.hir_visits,
        class_range_visits: meter.class_range_visits,
        byte_visits: meter.byte_visits,
        work: meter.work()?,
        allocations: 0,
    })
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
