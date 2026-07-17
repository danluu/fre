//! Honest operation-specific facade for the currently certified FRE subsets.
//!
//! [`PortableRegex`] provides bounded single-search operations for the HIR
//! subset that `fre-lower` can prove exact. [`PortableRegexSetBuilder`] and
//! [`PortableTextRegexSetBuilder`] compose independently admitted matchers
//! with exact ascending pattern-ID semantics. [`AggregateBuilder`] constructs
//! separate complete-span, count, or matched-byte-sum plans for the bounded
//! `fre-aggregate` Rust-byte subset. [`AggregateManyBuilder`] retains each
//! pattern's syntax identity and composes ordered whole-match compile/count/
//! span-sum/complete-span plans without source concatenation. Whole-match
//! aggregate plans may erase capture annotations. Their complete spans also
//! provide bounded byte `split`/`splitn` and literal/no-expansion replacement/
//! `replacen`.
//! [`CaptureBuilder`] separately preserves capture histories for the
//! participating-group reducer on its certified Rust-byte subset; it is not a
//! general capture-record facade. None of these types is named `Regex`:
//! unsupported syntax/profile/operation combinations are typed build errors,
//! and there is no full Rust-regex/RE2 or JIT claim.

#![forbid(unsafe_code)]

use core::fmt;

use regex_syntax::hir::{Hir, HirKind};

mod aggregate;
mod aggregate_many;
mod captures;
mod finite;
mod forward_anchored;
mod replacement;
mod required_literal;
mod set;
mod split;
mod text;
mod text_set;
mod unicode_word_run;

pub use aggregate::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuildLimits, AggregateBuildReport, AggregateBuilder, AggregateCacheIdentity,
    AggregateCaptureSemantics, AggregateCompileRegex, AggregateContinuationIdentity,
    AggregateContinuationSemantics, AggregateCountRegex, AggregateCountResult,
    AggregateExactLiteralIdentity, AggregateExactLiteralSemantics, AggregateExecutionDetails,
    AggregateExecutionError, AggregateExecutionReport, AggregateExecutionSource,
    AggregateFiniteLiteralIdentity, AggregateFixedClassSandwichIdentity,
    AggregateFixedClassSandwichSemantics, AggregateLiteralIneligibility, AggregateOperation,
    AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits,
    AggregateSearchStep, AggregateSearchStepIter, AggregateSpanIter, AggregateSpanSumRegex,
    AggregateSpanSumResult, AggregateSpans, AggregateSpansRegex, AggregateStrategy,
    AggregateUnicodeScalarIdentity, AggregateUnicodeScalarSemantics,
};
pub use aggregate_many::{
    AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION, AggregateManyBuildAccounting, AggregateManyBuildError,
    AggregateManyBuildLimits, AggregateManyBuildReport, AggregateManyBuilder,
    AggregateManyCompileRegex, AggregateManyCompositionAccounting, AggregateManyCountRegex,
    AggregateManyCountResult, AggregateManyExecutionDetails, AggregateManyExecutionError,
    AggregateManyExecutionSource, AggregateManyLiteralSemantics, AggregateManyOperation,
    AggregateManyOutput, AggregateManyPatternReport, AggregateManyPlanIdentity,
    AggregateManyPlanKind, AggregateManyRegex, AggregateManyRunLimits, AggregateManySpanIter,
    AggregateManySpanSumRegex, AggregateManySpanSumResult, AggregateManySpans,
    AggregateManySpansRegex,
};
pub use captures::{
    CaptureBuildError, CaptureBuildLimits, CaptureBuildReport, CaptureBuilder,
    CaptureCacheIdentity, CaptureExecutionError, CaptureExecutionReport, CaptureExecutionSource,
    CaptureHirAccounting, CaptureIterationError, CaptureIterationIdentity,
    CaptureIterationPlanKind, CaptureIterationReport, CaptureOperation, CapturePlanIdentity,
    CapturePlanKind, CaptureRegex, CaptureRunLimits, CaptureUnsupported,
    PortableTextCaptureBuildError, PortableTextCaptureBuildReport, PortableTextCaptureBuilder,
    PortableTextCaptureIterationError, PortableTextCaptureMatch, PortableTextCaptureRegex,
    PortableTextCaptureSearchError, PortableTextCaptures,
};
pub use fre_aggregate::{
    CompileAccounting as AggregateCompileAccounting, CompileLimits as AggregateCompileLimits,
    Error as AggregateEngineError, ExecutionAccounting as AggregateExecutionAccounting,
    OperationCertificate as AggregateOperationCertificate, OperationId as AggregateOperationId,
    OperationLimits as AggregateOperationLimits, PlanId as AggregatePlanId,
    Resource as AggregateResource, Span as AggregateSpan, Unsupported as AggregateUnsupported,
};
pub use fre_capture_lab::{
    AggregateLimits as CaptureAggregateLimits, BuildError as CaptureEngineBuildError,
    BuildLimits as CaptureEngineBuildLimits, BuildReport as CaptureEngineBuildReport,
    CaptureCountOutcome, CaptureRecord, GroupRecord as CaptureGroupRecord,
    ResourceKind as CaptureResource, RunReport as CaptureSearchAccounting,
    SearchError as CaptureSearchError, SearchLimits as CaptureSearchLimits,
    SearchOutcome as CaptureSearchOutcome, Span as CaptureSpan,
};
pub use fre_kernels::{
    FIXED_CLASS_SANDWICH_COUNT_OPERATION_ID, FIXED_CLASS_SANDWICH_PLAN_ID,
    FIXED_CLASS_SANDWICH_SPAN_SUM_OPERATION_ID, FixedClassSandwichActualCounters,
    FixedClassSandwichBuildAccounting, FixedClassSandwichBuildError, FixedClassSandwichBuildLimits,
    FixedClassSandwichOperation, FixedClassSandwichOperationIdentity,
    FixedClassSandwichReduceAccounting, FixedClassSandwichReduceError,
    FixedClassSandwichReduceLimits, FixedClassSandwichSemantics, FixedClassSandwichUpperBounds,
    LiteralAggregateActualCounters, LiteralAggregateBuildAccounting, LiteralAggregateBuildError,
    LiteralAggregateBuildLimits, LiteralAggregateOperation, LiteralAggregateOperationIdentity,
    LiteralAggregateReduceAccounting, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    LiteralAggregateUpperBounds, ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    ORDERED_LITERAL_COUNT_PLAN_ID, ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    OrderedLiteralAggregateActualCounters, OrderedLiteralAggregateBuildAccounting,
    OrderedLiteralAggregateBuildError, OrderedLiteralAggregateBuildLimits,
    OrderedLiteralAggregateReduceError, OrderedLiteralAggregateReduceLimits,
    OrderedLiteralAggregateUpperBounds, UnicodeScalarAggregateBuildAccounting,
    UnicodeScalarAggregateBuildError, UnicodeScalarAggregateBuildLimits,
    UnicodeScalarAggregateOperation, UnicodeScalarAggregateOperationIdentity,
    UnicodeScalarAggregateReduceAccounting, UnicodeScalarAggregateReduceError,
    UnicodeScalarAggregateReduceLimits, UnicodeScalarAggregateRepetition,
    UnicodeScalarAggregateSemantics, UnicodeScalarAggregateUpperBounds,
};
pub use replacement::{
    CaptureExpansionAccounting, CaptureExpansionError, CaptureExpansionLimits,
    CaptureExpansionReport, CaptureExpansionResult, FunctionalReplacementAccounting,
    FunctionalReplacementError, FunctionalReplacementErrorSource, FunctionalReplacementIdentity,
    FunctionalReplacementLimits, FunctionalReplacementReport, FunctionalReplacementResult,
    LiteralReplacementAccounting, LiteralReplacementError, LiteralReplacementErrorSource,
    LiteralReplacementIdentity, LiteralReplacementLimits, LiteralReplacementReport,
    LiteralReplacementResult, LiteralReplacer, NoExpand,
};
pub use set::{
    PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION, PortableRegexSet, PortableRegexSetBuildError,
    PortableRegexSetBuildLimits, PortableRegexSetBuildReport, PortableRegexSetBuilder,
    PortableRegexSetExecutionError, PortableRegexSetExecutionReport, PortableRegexSetRunLimits,
    PortableSetMatches, PortableSetMatchesIntoIter, PortableSetMatchesIter,
};
pub use split::{AggregateSplit, PortableSplit};
pub use text::{
    PortableTextBuildError, PortableTextBuildReport, PortableTextBuilder, PortableTextProof,
    PortableTextRegex, PortableTextSearchError,
};
pub use text_set::{
    PORTABLE_TEXT_REGEX_SET_EXPLAIN_SCHEMA_VERSION, PortableTextRegexSet,
    PortableTextRegexSetBuildError, PortableTextRegexSetBuildReport, PortableTextRegexSetBuilder,
};

use fre_automata::{Automaton, EarliestEnd, Exists, K0Workspace, SelectedEnd, Span};
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

pub use fre_syntax::{CompatibilityProfile, RustProfile};

pub use fre_automata::{
    SearchError as K0SearchError, SearchLimits, SearchWindow,
    SetupAccounting as SearchSessionSetupAccounting, WorkspaceLimits as SearchSessionLimits,
};
pub use unicode_word_run::{Accounting as UnicodeWordRunAccounting, Error as UnicodeWordRunError};

/// Stable schema for facade-level explanation records.
pub const EXPLAIN_SCHEMA_VERSION: u32 = 5;

/// Escapes all regular-expression meta characters in `pattern`.
///
/// The returned string is safe to use as a literal in a Rust-compatible
/// regular expression. Its behavior is pinned by FRE's exact
/// `regex-syntax` 0.8.11 dependency, which is also part of
/// [`RustProfile::regex_1_12_4`].
#[must_use]
pub fn escape(pattern: &str) -> String {
    regex_syntax::escape(pattern)
}

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
    /// Maximum logical bytes retained by the published source, capture-name
    /// metadata and selected execution plan.
    pub max_persistent_bytes: usize,
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
            max_persistent_bytes: 268_435_456,
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

    /// Number of matched bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(self) -> core::ops::Range<usize> {
        self.start..self.end
    }
}

/// A byte match that retains the exact original haystack it was selected from.
///
/// [`Match`] remains the small offset-only value used by accounting-oriented
/// APIs. This companion preserves the pinned Rust bytes API's borrowed-match
/// contract, including direct access to the matched bytes and lossless
/// conversion to either the bytes or their original range.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ByteMatch<'h> {
    haystack: &'h [u8],
    span: Match,
}

impl<'h> ByteMatch<'h> {
    /// Inclusive byte start in the original haystack.
    #[must_use]
    pub const fn start(self) -> usize {
        self.span.start()
    }

    /// Exclusive byte end in the original haystack.
    #[must_use]
    pub const fn end(self) -> usize {
        self.span.end()
    }

    /// Whether the selected match consumed no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.span.is_empty()
    }

    /// Number of matched bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.span.len()
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(self) -> core::ops::Range<usize> {
        self.span.range()
    }

    /// The exact bytes selected from the original haystack.
    #[must_use]
    pub fn as_bytes(&self) -> &'h [u8] {
        &self.haystack[self.span.range()]
    }
}

impl fmt::Debug for ByteMatch<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteMatch")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("bytes", &DebugMatchBytes(self.as_bytes()))
            .finish()
    }
}

/// Pinned Rust-regex debug escaping for a byte match's selected haystack.
///
/// Valid UTF-8 is formatted like a Rust string while each byte that cannot be
/// decoded is emitted as a lower-case hexadecimal escape. Keeping this helper
/// private avoids adding a formatting type to the public compatibility
/// surface.
struct DebugMatchBytes<'a>(&'a [u8]);

impl fmt::Debug for DebugMatchBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"")?;
        let mut bytes = self.0;
        while !bytes.is_empty() {
            match core::str::from_utf8(bytes) {
                Ok(valid) => {
                    write_debug_match_str(formatter, valid)?;
                    bytes = &[];
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    let valid = core::str::from_utf8(&bytes[..valid_up_to])
                        .expect("UTF-8 error's valid prefix must decode");
                    write_debug_match_str(formatter, valid)?;
                    write!(formatter, r"\x{:02x}", bytes[valid_up_to])?;
                    bytes = &bytes[valid_up_to.saturating_add(1)..];
                }
            }
        }
        formatter.write_str("\"")
    }
}

fn write_debug_match_str(formatter: &mut fmt::Formatter<'_>, valid: &str) -> fmt::Result {
    for character in valid.chars() {
        match character {
            '\0' => formatter.write_str("\\0")?,
            '\u{1}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{19}' | '\u{7f}' => {
                write!(formatter, "\\x{:02x}", u32::from(character))?;
            }
            _ => write!(formatter, "{}", character.escape_debug())?,
        }
    }
    Ok(())
}

impl<'h> From<ByteMatch<'h>> for &'h [u8] {
    fn from(matched: ByteMatch<'h>) -> Self {
        matched.as_bytes()
    }
}

impl From<ByteMatch<'_>> for core::ops::Range<usize> {
    fn from(matched: ByteMatch<'_>) -> Self {
        matched.range()
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
    /// Exact retained bytes for the original pattern source.
    pub source_storage_bytes: usize,
    /// Exact logical heap bytes retained for indexed capture-name metadata.
    pub capture_name_storage_bytes: usize,
    /// Checked sum of source, capture-name and selected-plan logical bytes.
    pub charged_persistent_bytes: usize,
    /// Total persistent-byte ceiling enforced before publication.
    pub persistent_byte_limit: usize,
    /// Total capture slots, including the implicit whole-match slot.
    pub captures_len: usize,
    /// Capture slots present in every possible match, including the implicit
    /// whole-match slot, or `None` when participation cardinality can vary.
    pub static_captures_len: Option<usize>,
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
    /// Linear canonical ASCII or Unicode `\b\w{m,}\b` word-run scan.
    UnicodeWordRun,
}

/// Construction failure without semantic fallback.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// Syntax/profile/admission failure.
    Syntax(fre_syntax::ParseError),
    /// The syntax was valid but is outside the certified portable lowering.
    Lower(fre_lower::LowerError),
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
    /// Persistent-byte accounting overflowed `usize`.
    PersistentBytesOverflow,
    /// The completed matcher exceeded the total persistent-byte ceiling.
    PersistentBytesLimit { needed: usize, limit: usize },
    /// A planner buffer could not be reserved.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// Internal facade/profile mismatch.
    InternalInvariant(&'static str),
}

/// Stable top-level classification for a failed portable construction.
///
/// This is deliberately coarser than [`BuildError`]. It lets conformance
/// adapters distinguish an upstream-invalid pattern from an FRE capability
/// gap, an explicitly configured resource refusal, invalid profile state, or
/// an internal construction failure without parsing diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildFailureClass {
    /// The pinned syntax front-end rejected the pattern or its encoding.
    ExpectedInvalid,
    /// The pattern is valid but outside the currently certified executor.
    Unsupported,
    /// A checked caller-configured construction bound was exceeded.
    ResourceLimit,
    /// The requested compatibility profile or builder configuration is invalid.
    InvalidConfiguration,
    /// Allocation, arithmetic, emitted-plan, or facade invariants failed.
    InternalFailure,
}

impl BuildError {
    /// Classify this failure without inspecting its human-readable message.
    #[must_use]
    pub fn failure_class(&self) -> BuildFailureClass {
        match self {
            Self::Syntax(error) => match &error.category {
                fre_syntax::ErrorCategory::InvalidPatternEncoding
                | fre_syntax::ErrorCategory::UpstreamRustSyntax
                | fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { .. }
                | fre_syntax::ErrorCategory::Re2Syntax { .. } => BuildFailureClass::ExpectedInvalid,
                fre_syntax::ErrorCategory::FreResourceLimit { .. }
                | fre_syntax::ErrorCategory::StrictQualificationFailure { .. } => {
                    BuildFailureClass::ResourceLimit
                }
                fre_syntax::ErrorCategory::UnsupportedNotYetImplemented { .. } => {
                    BuildFailureClass::Unsupported
                }
                fre_syntax::ErrorCategory::InvalidConfiguration => {
                    BuildFailureClass::InvalidConfiguration
                }
            },
            Self::Lower(error) => lower_failure_class(error),
            Self::Literal(error) => match error {
                LiteralError::NeedleLimit { .. } | LiteralError::LinearTermLimit { .. } => {
                    BuildFailureClass::ResourceLimit
                }
                _ => BuildFailureClass::InternalFailure,
            },
            Self::LiteralSet(error) => match error {
                LiteralSetError::PatternLimit { .. }
                | LiteralSetError::PatternBytesLimit { .. }
                | LiteralSetError::BuildWorkLimit { .. }
                | LiteralSetError::BuildBytesLimit { .. }
                | LiteralSetError::PersistentBytesLimit { .. }
                | LiteralSetError::TransitionLimit { .. } => BuildFailureClass::ResourceLimit,
                _ => BuildFailureClass::InternalFailure,
            },
            Self::RequiredLiteral(error) => required_literal_failure_class(error),
            Self::RequiredLiteralShape | Self::ForwardAnchoredShape => {
                BuildFailureClass::Unsupported
            }
            Self::ForwardAnchored(error) => forward_anchored_failure_class(error),
            Self::PlannerWorkLimit { .. } | Self::PersistentBytesLimit { .. } => {
                BuildFailureClass::ResourceLimit
            }
            Self::PersistentBytesOverflow
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => BuildFailureClass::InternalFailure,
        }
    }
}

fn lower_failure_class(error: &fre_lower::LowerError) -> BuildFailureClass {
    match error {
        fre_lower::LowerError::Unsupported(_) => BuildFailureClass::Unsupported,
        fre_lower::LowerError::ResourceLimit { .. }
        | fre_lower::LowerError::Automata(fre_automata::CompileError::ResourceLimit { .. }) => {
            BuildFailureClass::ResourceLimit
        }
        _ => BuildFailureClass::InternalFailure,
    }
}

fn required_literal_failure_class(error: &RequiredLiteralBuildError) -> BuildFailureClass {
    if error.is_semantic_refusal() {
        return BuildFailureClass::Unsupported;
    }
    match error {
        RequiredLiteralBuildError::SuffixLimit { .. }
        | RequiredLiteralBuildError::WorkLimit { .. }
        | RequiredLiteralBuildError::ScratchLimit { .. }
        | RequiredLiteralBuildError::PersistentLimit { .. }
        | RequiredLiteralBuildError::PeakLimit { .. } => BuildFailureClass::ResourceLimit,
        _ => BuildFailureClass::InternalFailure,
    }
}

fn forward_anchored_failure_class(error: &ForwardAnchoredBuildError) -> BuildFailureClass {
    if error.is_semantic_refusal() {
        return BuildFailureClass::Unsupported;
    }
    match error {
        ForwardAnchoredBuildError::SuffixLimit { .. }
        | ForwardAnchoredBuildError::WorkLimit { .. }
        | ForwardAnchoredBuildError::ScratchLimit { .. }
        | ForwardAnchoredBuildError::PersistentLimit { .. }
        | ForwardAnchoredBuildError::PeakLimit { .. } => BuildFailureClass::ResourceLimit,
        _ => BuildFailureClass::InternalFailure,
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "syntax construction failed: {error}"),
            Self::Lower(error) => write!(f, "portable lowering failed: {error}"),
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
            Self::PersistentBytesOverflow => {
                f.write_str("portable matcher persistent-byte accounting overflowed usize")
            }
            Self::PersistentBytesLimit { needed, limit } => write!(
                f,
                "portable matcher needs {needed} persistent bytes, exceeding {limit}"
            ),
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
            | Self::ForwardAnchoredShape
            | Self::PlannerWorkLimit { .. }
            | Self::PersistentBytesOverflow
            | Self::PersistentBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl BuildReport {
    fn enforce_persistent_limit(mut self, limit: usize) -> Result<Self, BuildError> {
        let needed = self
            .source_storage_bytes
            .checked_add(self.capture_name_storage_bytes)
            .and_then(|bytes| bytes.checked_add(self.plan_storage_bytes))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        if needed > limit {
            return Err(BuildError::PersistentBytesLimit { needed, limit });
        }
        self.charged_persistent_bytes = needed;
        self.persistent_byte_limit = limit;
        Ok(self)
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

#[derive(Debug)]
struct CaptureNameMetadata {
    names: Box<[Option<Box<str>>]>,
    captures_len: usize,
    storage_bytes: usize,
}

fn capture_slot_len(
    hir: &Hir,
    explicit_captures: usize,
    hir_nodes: usize,
) -> Result<usize, BuildError> {
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(hir_nodes)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-slot HIR traversal",
            additional: hir_nodes,
        })?;
    stack.push(hir);
    let mut visited = 0_usize;
    let mut capture_nodes = 0_usize;
    let mut maximum_index = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.checked_add(1).ok_or(BuildError::InternalInvariant(
            "capture-slot HIR traversal count overflowed",
        ))?;
        if visited > hir_nodes {
            return Err(BuildError::InternalInvariant(
                "capture-slot traversal exceeded parsed HIR accounting",
            ));
        }
        if let HirKind::Capture(capture) = node.kind() {
            let index = usize::try_from(capture.index).map_err(|_| {
                BuildError::InternalInvariant("capture-slot index does not fit usize")
            })?;
            if index == 0 {
                return Err(BuildError::InternalInvariant(
                    "canonical HIR used the implicit whole-match capture index",
                ));
            }
            capture_nodes = capture_nodes
                .checked_add(1)
                .ok_or(BuildError::InternalInvariant(
                    "capture-slot count overflowed",
                ))?;
            maximum_index = maximum_index.max(index);
        }
        for child in node.kind().subs() {
            if stack.len() >= hir_nodes {
                return Err(BuildError::InternalInvariant(
                    "capture-slot traversal stack exceeded parsed HIR accounting",
                ));
            }
            stack.push(child);
        }
    }
    if visited != hir_nodes || capture_nodes != explicit_captures {
        return Err(BuildError::InternalInvariant(
            "capture-slot metadata differs from parsed HIR accounting",
        ));
    }
    maximum_index
        .checked_add(1)
        .ok_or(BuildError::InternalInvariant(
            "capture count including group zero overflowed usize",
        ))
}

fn capture_name_metadata(
    hir: &Hir,
    explicit_captures: usize,
    hir_nodes: u64,
) -> Result<CaptureNameMetadata, BuildError> {
    let hir_nodes = usize::try_from(hir_nodes)
        .map_err(|_| BuildError::InternalInvariant("HIR node count does not fit usize"))?;
    if hir_nodes == 0 {
        return Err(BuildError::InternalInvariant(
            "capture metadata received an empty HIR inventory",
        ));
    }

    let captures_len = capture_slot_len(hir, explicit_captures, hir_nodes)?;

    let mut names = Vec::new();
    names
        .try_reserve_exact(captures_len)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name slots",
            additional: captures_len,
        })?;
    names.resize_with(captures_len, || None);

    let mut seen = Vec::new();
    seen.try_reserve_exact(captures_len)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name validation bitmap",
            additional: captures_len,
        })?;
    seen.resize(captures_len, false);
    seen[0] = true;

    let mut stack = Vec::new();
    stack
        .try_reserve_exact(hir_nodes)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name HIR traversal",
            additional: hir_nodes,
        })?;
    stack.push(hir);
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.checked_add(1).ok_or(BuildError::InternalInvariant(
            "capture-name HIR traversal count overflowed",
        ))?;
        if visited > hir_nodes {
            return Err(BuildError::InternalInvariant(
                "capture-name traversal exceeded parsed HIR accounting",
            ));
        }
        if let HirKind::Capture(capture) = node.kind() {
            let index = usize::try_from(capture.index).map_err(|_| {
                BuildError::InternalInvariant("capture-name index does not fit usize")
            })?;
            if index == 0 || index >= captures_len {
                return Err(BuildError::InternalInvariant(
                    "capture-name index is outside parsed capture cardinality",
                ));
            }
            if seen[index] {
                return Err(BuildError::InternalInvariant(
                    "capture-name index appeared more than once in canonical HIR",
                ));
            }
            seen[index] = true;
            names[index].clone_from(&capture.name);
        }
        for child in node.kind().subs() {
            if stack.len() >= hir_nodes {
                return Err(BuildError::InternalInvariant(
                    "capture-name traversal stack exceeded parsed HIR accounting",
                ));
            }
            stack.push(child);
        }
    }
    if visited != hir_nodes
        || seen.iter().skip(1).filter(|was_seen| **was_seen).count() != explicit_captures
    {
        return Err(BuildError::InternalInvariant(
            "capture-name metadata differs from parsed HIR accounting",
        ));
    }

    let slot_bytes = core::mem::size_of::<Option<Box<str>>>()
        .checked_mul(names.len())
        .ok_or(BuildError::InternalInvariant(
            "capture-name slot byte accounting overflowed",
        ))?;
    let storage_bytes = names.iter().try_fold(slot_bytes, |total, name| {
        total
            .checked_add(name.as_deref().map_or(0, str::len))
            .ok_or(BuildError::InternalInvariant(
                "capture-name string byte accounting overflowed",
            ))
    })?;
    Ok(CaptureNameMetadata {
        names: names.into_boxed_slice(),
        captures_len,
        storage_bytes,
    })
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
    /// Exact linear Unicode word-run counters.
    UnicodeWordRun(UnicodeWordRunAccounting),
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
            Self::UnicodeWordRun(_) => PlanKind::UnicodeWordRun,
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
            Self::UnicodeWordRun(accounting) => accounting.work(),
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
    UnicodeWordRun(UnicodeWordRunError),
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
            Self::UnicodeWordRun(error) => write!(f, "Unicode word-run search failed: {error}"),
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
            Self::UnicodeWordRun(error) => Some(error),
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

impl From<UnicodeWordRunError> for SearchError {
    fn from(value: UnicodeWordRunError) -> Self {
        Self::UnicodeWordRun(value)
    }
}

/// Hard limits for complete non-overlapping byte match iteration.
///
/// `max_search_calls` bounds the whole iterator, including searches that
/// suppress a repeated empty match while making byte-wise progress. The
/// session and per-search limits retain their existing operation-specific
/// meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableFindIterLimits {
    /// One-time reusable K0 workspace construction limits.
    pub session: SearchSessionLimits,
    /// Limits applied independently to each contextual search.
    pub search: SearchLimits,
    /// Maximum contextual searches across the entire iterator.
    pub max_search_calls: usize,
}

impl PortableFindIterLimits {
    /// Limits that accept every representable iterator execution.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            session: SearchSessionLimits::unlimited(),
            search: SearchLimits::unlimited(),
            max_search_calls: usize::MAX,
        }
    }
}

impl Default for PortableFindIterLimits {
    fn default() -> Self {
        Self {
            session: SearchSessionLimits::default(),
            search: SearchLimits::default(),
            max_search_calls: 1_000_000,
        }
    }
}

/// Exact no-clock accounting accumulated by [`PortableMatches`] or
/// [`PortableByteMatches`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortableFindIterAccounting {
    /// Contextual search invocations, including the final miss and suppressed
    /// repeated empty matches.
    pub search_calls: usize,
    /// Non-overlapping matches returned to the caller.
    pub matches: usize,
    /// Repeated empty matches suppressed to guarantee byte-wise progress.
    pub suppressed_empty: usize,
    /// Sum of charged work or conservative linear terms from successful
    /// contextual searches.
    pub work_or_linear_terms: u64,
}

/// Checked terminal failure from complete byte match iteration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableFindIterError {
    /// One contextual search failed under its operation-specific limits.
    Search(SearchError),
    /// The next contextual search would exceed the whole-iterator call cap.
    SearchCallLimit { needed: usize, limit: usize },
    /// An exact whole-iterator counter could not be incremented.
    AccountingOverflow { counter: &'static str },
}

impl fmt::Display for PortableFindIterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(error) => write!(formatter, "portable iteration search failed: {error}"),
            Self::SearchCallLimit { needed, limit } => write!(
                formatter,
                "portable iteration needs {needed} search calls, exceeding {limit}",
            ),
            Self::AccountingOverflow { counter } => {
                write!(
                    formatter,
                    "portable iteration {counter} accounting overflowed"
                )
            }
        }
    }
}

impl std::error::Error for PortableFindIterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::SearchCallLimit { .. } | Self::AccountingOverflow { .. } => None,
        }
    }
}

impl From<SearchError> for PortableFindIterError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
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
    set_admitted: bool,
    utf8_start_guarded: bool,
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
            set_admitted: false,
            utf8_start_guarded: false,
        }
    }

    /// Select the complete Rust release-stack and constructor identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_builder();
        self
    }

    /// Retain a set-constructor stamp while building one already-associated
    /// constituent. Only the set builder may use this path; public single-
    /// pattern construction always normalizes to `RegexBuilder` identity.
    #[must_use]
    fn set_constituent_profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the Rust bytes facade's Unicode mode before parsing.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set case-insensitive mode for the complete pattern before parsing.
    ///
    /// Inline `i` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes builder.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Set multiline mode for `^` and `$` before parsing.
    #[must_use]
    pub fn multi_line(mut self, enabled: bool) -> Self {
        self.profile.options.multi_line = enabled;
        self
    }

    /// Set whether `.` matches the configured line terminator.
    #[must_use]
    pub fn dot_matches_new_line(mut self, enabled: bool) -> Self {
        self.profile.options.dot_matches_new_line = enabled;
        self
    }

    /// Set CRLF mode for the complete pattern before parsing.
    ///
    /// This makes both carriage return and line feed line terminators for
    /// dot and multiline assertions. Inline `R` flag groups may still
    /// override this setting locally, just as they do in the pinned Rust
    /// bytes builder.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics before parsing.
    ///
    /// Inline `U` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes builder.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose mode before parsing, ignoring unescaped pattern whitespace
    /// and treating `#` as the start of a line comment.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escape syntax before parsing.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the parser's abstract-syntax-tree nesting limit.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline `^` and `$` assertions.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the pinned high-level builder's approximate compiled-regex limit.
    ///
    /// FRE applies this limit with the same pinned meta-construction path and
    /// configuration used by `regex` 1.12.4 before selecting an FRE executor.
    /// A pattern that exceeds the limit is therefore an upstream constructor
    /// rejection, not an FRE capability or plan-resource refusal. The
    /// distinct direct-Rebar constructor profile has no corresponding high-
    /// level option and is left unchanged.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
            &mut self.profile.constructor
        {
            *size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Set the pinned high-level builder's lazy-DFA cache capacity identity.
    ///
    /// FRE's portable plans do not use the upstream lazy-DFA cache, so this
    /// option cannot weaken their independently checked construction and
    /// execution limits. It is nevertheless retained in the compatibility
    /// profile exactly because it is part of the public Rust bytes builder
    /// configuration. The distinct direct-Rebar constructor profile has no
    /// corresponding high-level option and is left unchanged.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Replace every checked construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: BuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the total logical persistent-byte ceiling for the published
    /// matcher without changing any plan-specific construction limits.
    #[must_use]
    pub const fn max_persistent_bytes(mut self, limit: usize) -> Self {
        self.limits.max_persistent_bytes = limit;
        self
    }

    /// Force one plan so tests and qualification cannot accidentally exercise
    /// an alternative implementation.
    #[must_use]
    pub const fn plan_selection(mut self, selection: PlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Use the already-completed aggregate Rust-set constructor admission.
    pub(crate) const fn after_set_admission(mut self) -> Self {
        self.set_admitted = true;
        self
    }

    pub(crate) const fn after_set_admission_if(mut self, admitted: bool) -> Self {
        self.set_admitted = admitted;
        self
    }

    /// Restrict every candidate match start to a UTF-8 scalar boundary. The
    /// text facade is the sole caller and proves valid UTF-8 input plus HIR
    /// equivalence before enabling this synthesized K0 guard.
    pub(crate) const fn with_utf8_start_guard(mut self) -> Self {
        self.utf8_start_guarded = true;
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
        let parsed = if self.set_admitted {
            fre_syntax::parse_rust_regex_set_constituent(request)?
        } else {
            fre_syntax::parse(request)?
        };
        let source = String::from_utf8(parsed.key.pattern.into_bytes())
            .map_err(|_| {
                BuildError::InternalInvariant("Rust parse retained a non-UTF-8 source pattern")
            })?
            .into_boxed_str();
        let source_storage_bytes = source.len();
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(BuildError::InternalInvariant(
                "Rust bytes request produced a non-Rust canonical pattern",
            ));
        };
        let explicit_captures = usize::try_from(syntax.captures).map_err(|_| {
            BuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if explicit_captures != rust.hir.properties().explicit_captures_len() {
            return Err(BuildError::InternalInvariant(
                "syntax capture count differs from HIR properties",
            ));
        }
        let static_captures_len = rust
            .hir
            .properties()
            .static_explicit_captures_len()
            .map(|len| {
                len.checked_add(1).ok_or(BuildError::InternalInvariant(
                    "static capture count including group zero overflowed usize",
                ))
            })
            .transpose()?;
        let CaptureNameMetadata {
            names: capture_names,
            captures_len,
            storage_bytes: capture_name_storage_bytes,
        } = capture_name_metadata(&rust.hir, explicit_captures, syntax.hir_nodes)?;
        let minimum_match_bytes = rust.hir.properties().minimum_len();
        if self.utf8_start_guarded
            && !matches!(self.selection, PlanSelection::Auto | PlanSelection::ForceK0)
        {
            return Err(BuildError::InternalInvariant(
                "UTF-8 start guard requires automatic or forced K0 selection",
            ));
        }
        if self.selection == PlanSelection::ForceK0 || self.utf8_start_guarded {
            let lowered = if self.utf8_start_guarded {
                fre_lower::lower_utf8_start_guarded(
                    &rust,
                    OperationSemantics::CaptureFree,
                    self.limits.lowering,
                )?
            } else {
                fre_lower::lower(&rust, OperationSemantics::CaptureFree, self.limits.lowering)?
            };
            let lowering = lowered.stats();
            let automaton = lowered
                .into_automaton()
                .with_line_terminator(self.profile.options.line_terminator);
            let plan = automaton.stats();
            return Ok(PortableRegex {
                source,
                capture_names,
                plan: PortablePlan::K0(automaton),
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
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
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: 0,
                    persistent_byte_limit: 0,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    forward_anchored: None,
                }
                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
            });
        }
        if self.selection == PlanSelection::Auto
            && let Some(plan) = unicode_word_run::extract(&rust.hir)
        {
            return Ok(PortableRegex {
                source,
                capture_names,
                plan: PortablePlan::UnicodeWordRun(plan),
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::UnicodeWordRun,
                    planner_work: 1,
                    lowering: None,
                    states: 0,
                    edges: 0,
                    plan_storage_bytes: core::mem::size_of::<unicode_word_run::Plan>(),
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: 0,
                    persistent_byte_limit: 0,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    forward_anchored: None,
                }
                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
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
                        source,
                        capture_names,
                        plan: PortablePlan::ForwardEndFixed(plan),
                        profile: profile.clone(),
                        limits: self.limits,
                        selection: self.selection,
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
                            source_storage_bytes,
                            capture_name_storage_bytes,
                            charged_persistent_bytes: 0,
                            persistent_byte_limit: 0,
                            captures_len,
                            static_captures_len,
                            minimum_match_bytes,
                            required_literal: None,
                            forward_anchored: Some(build),
                        }
                        .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
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
                            source,
                            capture_names,
                            plan: PortablePlan::ForwardAnchored(plan),
                            profile: profile.clone(),
                            limits: self.limits,
                            selection: self.selection,
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
                                source_storage_bytes,
                                capture_name_storage_bytes,
                                charged_persistent_bytes: 0,
                                persistent_byte_limit: 0,
                                captures_len,
                                static_captures_len,
                                minimum_match_bytes,
                                required_literal: None,
                                forward_anchored: Some(build),
                            }
                            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
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
                            source,
                            capture_names,
                            plan: PortablePlan::RequiredLiteral(plan),
                            profile: profile.clone(),
                            limits: self.limits,
                            selection: self.selection,
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
                                source_storage_bytes,
                                capture_name_storage_bytes,
                                charged_persistent_bytes: 0,
                                persistent_byte_limit: 0,
                                captures_len,
                                static_captures_len,
                                minimum_match_bytes,
                                required_literal: Some(build),
                                forward_anchored: None,
                            }
                            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
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
                    source,
                    capture_names,
                    plan: PortablePlan::ExactLiteral(literal),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
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
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes: 0,
                        persistent_byte_limit: 0,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        forward_anchored: None,
                    }
                    .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                });
            }
            if words.len() > 1 {
                if let Ok(packed) =
                    PackedLiteralSetPlan::new(&words, self.limits.packed_literal_set)
                {
                    let storage = packed.build_accounting().persistent_bytes;
                    return Ok(PortableRegex {
                        source,
                        capture_names,
                        plan: PortablePlan::PackedLiteralSet(packed),
                        profile: profile.clone(),
                        limits: self.limits,
                        selection: self.selection,
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
                            source_storage_bytes,
                            capture_name_storage_bytes,
                            charged_persistent_bytes: 0,
                            persistent_byte_limit: 0,
                            captures_len,
                            static_captures_len,
                            minimum_match_bytes,
                            required_literal: None,
                            forward_anchored: None,
                        }
                        .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                    });
                }
                let literal_set = LiteralSetPlan::new(&words, self.limits.literal_set)?;
                let storage = literal_set.build_accounting().persistent_bytes;
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    plan: PortablePlan::LiteralSetDfa(literal_set),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
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
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes: 0,
                        persistent_byte_limit: 0,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        forward_anchored: None,
                    }
                    .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                });
            }
        }
        let lowered =
            fre_lower::lower(&rust, OperationSemantics::CaptureFree, self.limits.lowering)?;
        let lowering = lowered.stats();
        let automaton = lowered
            .into_automaton()
            .with_line_terminator(self.profile.options.line_terminator);
        let plan = automaton.stats();
        Ok(PortableRegex {
            source,
            capture_names,
            plan: PortablePlan::K0(automaton),
            profile: profile.clone(),
            limits: self.limits,
            selection: self.selection,
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
                source_storage_bytes,
                capture_name_storage_bytes,
                charged_persistent_bytes: 0,
                persistent_byte_limit: 0,
                captures_len,
                static_captures_len,
                minimum_match_bytes,
                required_literal: None,
                forward_anchored: None,
            }
            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
        })
    }
}

/// Immutable, shareable matcher for the certified capture-free byte subset.
pub struct PortableRegex {
    source: Box<str>,
    capture_names: Box<[Option<Box<str>>]>,
    plan: PortablePlan,
    profile: CompatibilityProfile,
    limits: BuildLimits,
    selection: PlanSelection,
    report: BuildReport,
}

/// An iterator over capture names in opening-parenthesis index order.
///
/// The first item is always `None` for the implicit whole-match slot. Unnamed
/// explicit groups also yield `None`.
#[derive(Clone, Debug)]
pub struct PortableCaptureNames<'r> {
    names: core::slice::Iter<'r, Option<Box<str>>>,
}

impl<'r> Iterator for PortableCaptureNames<'r> {
    type Item = Option<&'r str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.names.next().map(Option::as_deref)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.names.size_hint()
    }

    fn count(self) -> usize {
        self.names.len()
    }
}

impl ExactSizeIterator for PortableCaptureNames<'_> {}
impl core::iter::FusedIterator for PortableCaptureNames<'_> {}

/// Reusable byte offsets for every capture slot in a portable regex.
///
/// A newly allocated buffer contains no matched locations. Its cardinality is
/// nevertheless fixed by the regex and includes the implicit whole-match slot
/// at index zero. This is the reusable-buffer half of the pinned Rust bytes
/// `CaptureLocations` contract; [`PortableRegex::captures_read`] populates its
/// admitted capture-free group-zero slice.
#[derive(Clone, Debug)]
pub struct PortableCaptureLocations {
    slots: Box<[Option<(usize, usize)>]>,
}

/// Compatibility alias mirroring the pinned bytes API's legacy `Locations`.
#[doc(hidden)]
pub type PortableLocations = PortableCaptureLocations;

#[allow(
    clippy::len_without_is_empty,
    reason = "the pinned buffer always has the implicit whole-match slot and exposes len without is_empty"
)]
impl PortableCaptureLocations {
    /// Return the matched byte offsets for capture slot `index`.
    ///
    /// A fresh buffer and an unmatched slot both return `None`. An index that
    /// is not a capture slot also returns `None`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<(usize, usize)> {
        self.slots.get(index).copied().flatten()
    }

    /// Return the fixed number of capture slots represented by this buffer.
    ///
    /// This is always at least one because slot zero is the whole match.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slots.len()
    }

    /// Compatibility alias mirroring the pinned bytes API's legacy `pos`.
    #[doc(hidden)]
    #[must_use]
    pub fn pos(&self, index: usize) -> Option<(usize, usize)> {
        self.get(index)
    }
}

/// Failure while populating reusable portable capture locations.
///
/// The portable whole-match executors can populate group zero exactly for a
/// capture-free pattern. Explicit subgroup preservation remains a separate
/// capability and is refused instead of publishing incomplete locations.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableCapturesReadError {
    /// The caller supplied a location buffer created for another regex.
    LocationCount {
        /// Capture slots required by this regex.
        expected: usize,
        /// Capture slots present in the supplied buffer.
        actual: usize,
    },
    /// The regex contains explicit groups whose offsets are not preserved by
    /// the selected portable whole-match executor.
    ExplicitCapturesUnsupported {
        /// Number of explicit groups, excluding the whole-match slot.
        captures: usize,
    },
    /// The selected whole-match executor refused the bounded search.
    Search(SearchError),
}

impl fmt::Display for PortableCapturesReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocationCount { expected, actual } => write!(
                formatter,
                "capture location count mismatch: expected {expected}, got {actual}"
            ),
            Self::ExplicitCapturesUnsupported { captures } => write!(
                formatter,
                "portable capture reading does not yet preserve {captures} explicit capture groups"
            ),
            Self::Search(error) => write!(formatter, "portable capture search failed: {error}"),
        }
    }
}

impl std::error::Error for PortableCapturesReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::LocationCount { .. } | Self::ExplicitCapturesUnsupported { .. } => None,
        }
    }
}

impl From<SearchError> for PortableCapturesReadError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
    }
}

impl Clone for PortableRegex {
    /// Rebuild an equivalent immutable matcher under its original profile,
    /// limits, and planner-selection contract.
    ///
    /// Some certified native plans deliberately do not expose `Clone`, so the
    /// facade replays its already-admitted deterministic construction instead
    /// of weakening those plan-level ownership contracts.
    fn clone(&self) -> Self {
        let profile = match &self.profile {
            CompatibilityProfile::RustBytes(profile) => profile.clone(),
            CompatibilityProfile::RustText(_) | CompatibilityProfile::Re2(_) => {
                panic!("portable byte regex retained a non-byte profile")
            }
        };
        PortableBuilder::new(self.as_str())
            .set_constituent_profile(profile)
            .limits(self.limits)
            .plan_selection(self.selection)
            .build()
            .unwrap_or_else(|error| {
                panic!("previously admitted portable regex could not be cloned: {error}")
            })
    }
}

impl fmt::Display for PortableRegex {
    /// Show the original regular expression source.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for PortableRegex {
    /// Show the original source under the facade's honest public type name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PortableRegex")
            .field(&self.as_str())
            .finish()
    }
}

impl core::str::FromStr for PortableRegex {
    type Err = BuildError;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        Self::new(pattern)
    }
}

impl TryFrom<&str> for PortableRegex {
    type Error = BuildError;

    fn try_from(pattern: &str) -> Result<Self, Self::Error> {
        Self::new(pattern)
    }
}

impl TryFrom<String> for PortableRegex {
    type Error = BuildError;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        Self::new(pattern)
    }
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
    UnicodeWordRun(unicode_word_run::Plan),
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
            Self::UnicodeWordRun(plan) => plan.plan_id(),
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

    /// Return the original pattern source exactly as supplied at construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Iterate over every capture slot's optional name in capture-index order.
    ///
    /// This metadata is retained before capture-erasing execution planning,
    /// so it remains identical across every portable plan family.
    #[must_use]
    pub fn capture_names(&self) -> PortableCaptureNames<'_> {
        PortableCaptureNames {
            names: self.capture_names.iter(),
        }
    }

    /// Return the number of capture slots, including the implicit unnamed
    /// slot for the overall match.
    ///
    /// This metadata is preserved before capture-erasing execution planning,
    /// so it is identical for every selected portable plan family.
    #[must_use]
    pub const fn captures_len(&self) -> usize {
        self.report.captures_len
    }

    /// Return the number of capture slots that participate in every possible
    /// match, including the implicit whole-match slot.
    ///
    /// `None` means that capture participation cardinality can vary across
    /// alternatives or repetitions. This is construction metadata and does
    /// not execute a search.
    #[must_use]
    pub const fn static_captures_len(&self) -> Option<usize> {
        self.report.static_captures_len
    }

    /// Allocate fresh reusable locations for every capture slot.
    ///
    /// The returned buffer has the same fixed cardinality as
    /// [`Self::captures_len`] and initially contains no matched offsets.
    #[must_use]
    pub fn capture_locations(&self) -> PortableCaptureLocations {
        PortableCaptureLocations {
            slots: vec![None; self.captures_len()].into_boxed_slice(),
        }
    }

    /// Compatibility alias mirroring the pinned bytes API's legacy method.
    #[doc(hidden)]
    #[must_use]
    pub fn locations(&self) -> PortableCaptureLocations {
        self.capture_locations()
    }

    /// Search and populate reusable locations for a capture-free regex.
    ///
    /// This is the admitted group-zero slice of the pinned Rust bytes
    /// `captures_read` contract. The buffer is cleared before every attempt,
    /// including typed refusals, and a successful match stores its offsets in
    /// slot zero. Patterns with explicit capture groups are refused until the
    /// portable facade has a capture-preserving executor for their offsets.
    ///
    /// # Errors
    ///
    /// Returns [`PortableCapturesReadError`] if `locations` belongs to a regex
    /// with different capture cardinality, explicit subgroups require an
    /// unavailable capability, or the selected search exceeds its limits.
    pub fn captures_read<'h>(
        &self,
        locations: &mut PortableCaptureLocations,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), PortableCapturesReadError> {
        locations.slots.fill(None);
        if locations.len() != self.captures_len() {
            return Err(PortableCapturesReadError::LocationCount {
                expected: self.captures_len(),
                actual: locations.len(),
            });
        }
        let explicit_captures = self.captures_len().saturating_sub(1);
        if explicit_captures != 0 {
            return Err(PortableCapturesReadError::ExplicitCapturesUnsupported {
                captures: explicit_captures,
            });
        }
        let (matched, accounting) = self.find_borrowed(haystack, limits)?;
        if let Some(matched) = matched {
            locations.slots[0] = Some((matched.start(), matched.end()));
        }
        Ok((matched, accounting))
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

    /// Prepare allocation-free repeated searches over this immutable matcher.
    ///
    /// K0 allocates and fully initializes one fixed-capacity workspace here;
    /// every subsequent session call reuses it without growing. Native plans
    /// retain their existing operation-specific dispatch and need no session
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if K0 workspace construction exceeds the
    /// supplied setup-work or scratch limit, or if allocation fails. Native
    /// specialized plans ignore these limits because they construct no K0
    /// workspace.
    pub fn search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableSearchSession<'_>, SearchError> {
        let plan = match &self.plan {
            PortablePlan::K0(automaton) => {
                let workspace = K0Workspace::new(
                    automaton,
                    SearchSessionLimits {
                        max_setup_work: limits.max_setup_work,
                        max_scratch_bytes: limits.max_scratch_bytes,
                    },
                )?;
                PortableSearchSessionPlan::K0 {
                    automaton,
                    workspace,
                }
            }
            _ => PortableSearchSessionPlan::Native(self),
        };
        Ok(PortableSearchSession { plan })
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
        self.is_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists without constructing facade diagnostic
    /// accounting on the success path.
    ///
    /// This is the value-only counterpart to [`Self::is_match`]. It preserves
    /// the same selected plan, checked execution limits and typed failures,
    /// while keeping callers that only consume the boolean outside the
    /// [`SearchAccounting`] projection boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn is_match_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists at or after `start`.
    ///
    /// Assertions inspect the complete original haystack. Unlike the pinned
    /// Rust API, an out-of-bounds `start` is returned as a typed error instead
    /// of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn is_match_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists at or after `start` without
    /// constructing facade diagnostic accounting on the success path.
    ///
    /// Assertions inspect the complete original haystack. Range validation,
    /// execution limits and typed failures are identical to
    /// [`Self::is_match_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn is_match_value_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists wholly inside a search range.
    ///
    /// Assertions retain original-haystack context. K0 executes its typed
    /// existence contract directly instead of materializing a match span.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.is_some(),
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
                    matched.is_some(),
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
                    matched.is_some(),
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
                    matched.is_some(),
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
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::K0(automaton) => {
                let report = automaton
                    .prepare::<Exists>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
        }
    }

    /// Whether a selected match exists wholly inside a search range without
    /// constructing facade diagnostic accounting on the success path.
    ///
    /// Assertions retain original-haystack context and every plan executes
    /// the same existence operation as [`Self::is_match_window`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => literal
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::PackedLiteralSet(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    packed_literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::LiteralSetDfa(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::RequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::ForwardAnchored(forward) => forward
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::ForwardEndFixed(fixed) => fixed
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::K0(automaton) => automaton
                .prepare::<Exists>()
                .search_window(haystack, window, limits)
                .map(fre_automata::SearchReport::into_output)
                .map_err(SearchError::from),
            PortablePlan::UnicodeWordRun(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
        }
    }

    /// Return the end offset at the first boundary where a match is detected.
    ///
    /// Like the pinned Rust bytes API, this may be shorter than the end of the
    /// leftmost-first match returned by [`Self::find`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn shortest_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the first detected match end at or after `start`.
    ///
    /// Assertions inspect the complete original haystack and the returned
    /// offset remains relative to it. Unlike the pinned Rust API, an
    /// out-of-bounds `start` is returned as a typed error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn shortest_match_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    fn shortest_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
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
                    matched.map(|(_, end)| end),
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
                let end = if self.report.minimum_match_bytes == Some(0) {
                    Some(window.start())
                } else {
                    matched.map(|(_, end)| end)
                };
                Ok((end, SearchAccounting::LiteralSetDfa(accounting)))
            }
            PortablePlan::RequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
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
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::K0(automaton) => {
                let report = automaton
                    .prepare::<EarliestEnd>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
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
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
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

    /// Return the profile-selected leftmost-first match while retaining the
    /// exact original haystack.
    ///
    /// This is the borrowed-byte companion to [`Self::find`]. It preserves the
    /// same selected span and execution accounting, while [`ByteMatch`]
    /// supplies the pinned Rust bytes match accessors and conversions.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn find_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Iterate over every non-overlapping match with Rust bytes empty-match
    /// progress and original-haystack assertion context.
    ///
    /// K0 prepares one reusable workspace before iteration. Every subsequent
    /// search is allocation-free for K0, while native plans retain their
    /// selected dispatch. Iterator items are errors so a resource refusal is
    /// never silently treated as exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if reusable K0 workspace construction exceeds
    /// `limits.session`. Per-search and whole-iterator failures are yielded as
    /// [`PortableFindIterError`] items.
    pub fn find_iter<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
    ) -> Result<PortableMatches<'r, 'h>, SearchError> {
        let session = self.search_session(limits.session)?;
        Ok(PortableMatches {
            session,
            haystack,
            limits,
            start: 0,
            last_match_end: None,
            accounting: PortableFindIterAccounting::default(),
            finished: false,
        })
    }

    /// Iterate over every non-overlapping match while retaining the exact
    /// original haystack in each emitted [`ByteMatch`].
    ///
    /// Selection, empty-match progress, workspace reuse, resource limits and
    /// accounting are identical to [`Self::find_iter`]. The companion
    /// [`PortableByteMatches`] iterator only projects each selected span into
    /// the pinned Rust bytes match-value contract.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same construction contract as
    /// [`Self::find_iter`]. Per-search and whole-iterator failures are yielded
    /// as [`PortableFindIterError`] items.
    pub fn find_iter_borrowed<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
    ) -> Result<PortableByteMatches<'r, 'h>, SearchError> {
        Ok(PortableByteMatches {
            inner: self.find_iter(haystack, limits)?,
        })
    }

    /// Return the selected match at or after `start`.
    ///
    /// Assertions inspect the complete original haystack and returned offsets
    /// remain relative to it. Unlike the pinned Rust API, an out-of-bounds
    /// `start` is returned as a typed error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn find_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return the selected match at or after `start` while retaining the
    /// complete original haystack.
    ///
    /// This is the ranged companion to [`Self::find_borrowed`]. Assertions
    /// still inspect bytes before `start`, and [`ByteMatch`] offsets and bytes
    /// are both relative to the unsliced original haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::find_at`].
    pub fn find_at_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find_at(haystack, start, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
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
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::UnicodeWordRun(accounting)))
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

/// Operation-local reusable search state for one immutable portable matcher.
///
/// This keeps construction-selected specialized plans unchanged. Only K0 owns
/// mutable state, consisting of one fixed-capacity workspace whose size is
/// determined entirely by the validated automaton.
#[derive(Debug)]
pub struct PortableSearchSession<'a> {
    plan: PortableSearchSessionPlan<'a>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing K0 would add a second allocation and falsify workspace setup accounting"
)]
enum PortableSearchSessionPlan<'a> {
    Native(&'a PortableRegex),
    K0 {
        automaton: &'a Automaton,
        workspace: K0Workspace,
    },
}

impl PortableSearchSession<'_> {
    /// Stable runtime identity of the borrowed matcher.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        match &self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.runtime_implementation_id(),
            PortableSearchSessionPlan::K0 { .. } => "k0",
        }
    }

    /// One-time K0 workspace allocation and initialization facts.
    ///
    /// Native specialized plans return `None` because the session allocates no
    /// storage for them.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        match &self.plan {
            PortableSearchSessionPlan::Native(_) => None,
            PortableSearchSessionPlan::K0 { workspace, .. } => {
                Some(workspace.construction_accounting())
            }
        }
    }

    /// Whether a selected match exists, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::is_match`].
    pub fn is_match(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists without constructing facade diagnostic
    /// accounting on the success path, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::is_match_value`].
    pub fn is_match_value(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists at or after `start`, reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_at`].
    pub fn is_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists at or after `start` without
    /// constructing facade diagnostic accounting, reusing K0 state when
    /// applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_value_at`].
    pub fn is_match_value_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists wholly inside a range, reusing K0
    /// state and retaining original-haystack assertion context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_window`].
    pub fn is_match_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.is_match_window(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 {
                automaton,
                workspace,
            } => {
                let report = automaton
                    .prepare::<Exists>()
                    .search_window_with_workspace(haystack, window, workspace, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Whether a selected match exists wholly inside a range without
    /// constructing facade diagnostic accounting, reusing K0 state when
    /// applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_window_value`].
    pub fn is_match_window_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.is_match_window_value(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 {
                automaton,
                workspace,
            } => automaton
                .prepare::<Exists>()
                .search_window_with_workspace(haystack, window, workspace, limits)
                .map(fre_automata::SearchReport::into_output)
                .map_err(SearchError::from),
        }
    }

    /// Return the first detected match end, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::shortest_match`].
    pub fn shortest_match(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the first detected match end at or after `start`, reusing K0
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::shortest_match_at`].
    pub fn shortest_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    fn shortest_match_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.shortest_match_window(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 {
                automaton,
                workspace,
            } => {
                let report = automaton
                    .prepare::<EarliestEnd>()
                    .search_window_with_workspace(haystack, window, workspace, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the selected match end, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::selected_end`].
    pub fn selected_end(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.selected_end(haystack, limits),
            PortableSearchSessionPlan::K0 {
                automaton,
                workspace,
            } => {
                let report = automaton
                    .prepare::<SelectedEnd>()
                    .search_with_workspace(haystack, workspace, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the profile-selected leftmost-first match.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::find`].
    pub fn find(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the selected match while retaining the complete original
    /// haystack and reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`Self::find`].
    pub fn find_borrowed<'h>(
        &mut self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Return the selected match at or after `start`, reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::find_at`].
    pub fn find_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return the selected match at or after `start` while retaining the
    /// complete original haystack and reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::find_at`].
    pub fn find_at_borrowed<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find_at(haystack, start, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Search a range while assertions retain original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::find_window`].
    pub fn find_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.find_window(haystack, window, limits),
            PortableSearchSessionPlan::K0 {
                automaton,
                workspace,
            } => {
                let report = automaton
                    .prepare::<Span>()
                    .search_window_with_workspace(haystack, window, workspace, limits)?;
                let accounting = report.accounting();
                let matched = report.into_output().map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                });
                Ok((matched, SearchAccounting::K0(accounting)))
            }
        }
    }
}

/// Fallible iterator over every non-overlapping byte match.
///
/// Repeated empty matches at the previous match end are suppressed before the
/// next byte position is searched. This preserves the pinned Rust bytes
/// iterator's adjacent-empty behavior without reinterpreting anchors against
/// sliced suffixes.
#[derive(Debug)]
pub struct PortableMatches<'r, 'h> {
    session: PortableSearchSession<'r>,
    haystack: &'h [u8],
    limits: PortableFindIterLimits,
    start: usize,
    last_match_end: Option<usize>,
    accounting: PortableFindIterAccounting,
    finished: bool,
}

impl PortableMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.accounting
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.session.workspace_setup_accounting()
    }

    fn fail(&mut self, error: PortableFindIterError) -> Result<Match, PortableFindIterError> {
        self.finished = true;
        Err(error)
    }

    fn begin_search(&mut self) -> Result<(), PortableFindIterError> {
        let needed = self.accounting.search_calls.checked_add(1).ok_or(
            PortableFindIterError::AccountingOverflow {
                counter: "search-call",
            },
        )?;
        if needed > self.limits.max_search_calls {
            return Err(PortableFindIterError::SearchCallLimit {
                needed,
                limit: self.limits.max_search_calls,
            });
        }
        self.accounting.search_calls = needed;
        Ok(())
    }

    fn record_search(
        &mut self,
        accounting: &SearchAccounting,
    ) -> Result<(), PortableFindIterError> {
        self.accounting.work_or_linear_terms = self
            .accounting
            .work_or_linear_terms
            .checked_add(accounting.work_or_linear_terms())
            .ok_or(PortableFindIterError::AccountingOverflow { counter: "work" })?;
        Ok(())
    }
}

impl Iterator for PortableMatches<'_, '_> {
    type Item = Result<Match, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            if let Err(error) = self.begin_search() {
                return Some(self.fail(error));
            }
            let searched = self.session.find_window(
                self.haystack,
                SearchWindow::new(self.start, self.haystack.len()),
                self.limits.search,
            );
            let (matched, search_accounting) = match searched {
                Ok(result) => result,
                Err(error) => return Some(self.fail(PortableFindIterError::Search(error))),
            };
            if let Err(error) = self.record_search(&search_accounting) {
                return Some(self.fail(error));
            }
            let Some(matched) = matched else {
                self.finished = true;
                return None;
            };

            if matched.is_empty() && self.last_match_end == Some(matched.end()) {
                let Some(suppressed_empty) = self.accounting.suppressed_empty.checked_add(1) else {
                    return Some(self.fail(PortableFindIterError::AccountingOverflow {
                        counter: "suppressed-empty",
                    }));
                };
                self.accounting.suppressed_empty = suppressed_empty;
                if self.start == self.haystack.len() {
                    self.finished = true;
                    return None;
                }
                self.start = self.start.saturating_add(1);
                continue;
            }

            self.start = matched.end();
            self.last_match_end = Some(matched.end());
            let Some(emitted_count) = self.accounting.matches.checked_add(1) else {
                return Some(
                    self.fail(PortableFindIterError::AccountingOverflow { counter: "match" }),
                );
            };
            self.accounting.matches = emitted_count;
            return Some(Ok(matched));
        }
        None
    }
}

impl core::iter::FusedIterator for PortableMatches<'_, '_> {}

/// Fallible iterator over borrowed, non-overlapping byte matches.
///
/// This is the match-value projection of [`PortableMatches`]. It retains the
/// complete original haystack for [`ByteMatch::as_bytes`] while delegating all
/// search and progress state to the offset iterator.
#[derive(Debug)]
pub struct PortableByteMatches<'r, 'h> {
    inner: PortableMatches<'r, 'h>,
}

impl PortableByteMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.inner.accounting()
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }
}

impl<'h> Iterator for PortableByteMatches<'_, 'h> {
    type Item = Result<ByteMatch<'h>, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        let haystack = self.inner.haystack;
        self.inner
            .next()
            .map(|result| result.map(|span| ByteMatch { haystack, span }))
    }
}

impl core::iter::FusedIterator for PortableByteMatches<'_, '_> {}

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
    fn certified_ordered_empty_loops_build_through_k0() {
        let certified = PortableBuilder::new("(?:|a)*")
            .unicode(false)
            .build()
            .expect("empty-first nullable loop is normalized");
        assert_eq!(certified.build_report().plan, PlanKind::K0);
        assert_eq!(
            certified
                .build_report()
                .lowering
                .expect("K0 lowering report")
                .normalized_nullable_repetitions(),
            1
        );

        let consuming_first = PortableBuilder::new("(?:a|)*b")
            .unicode(false)
            .build()
            .expect("one-byte consuming-first nullable loop is normalized");
        assert_eq!(consuming_first.build_report().plan, PlanKind::K0);
        let (matched, _) = consuming_first
            .find(b"aaab", SearchLimits::unlimited())
            .expect("normalized K0 search succeeds");
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((0, 4))
        );
    }

    #[test]
    fn uncertified_nullable_loop_is_a_build_error() {
        let error = PortableBuilder::new("(?:ab|)*b")
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
