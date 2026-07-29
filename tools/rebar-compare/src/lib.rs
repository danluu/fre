//! Exact semantic comparator and receipt generator for FRE qualification.
//!
//! This crate deliberately separates input authentication, reference adapter
//! execution and candidate adapter execution. A missing runtime, an unsupported
//! candidate operation and a wrong answer are distinct receipt states.

#![forbid(unsafe_code)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Instant,
};
use std::{fmt::Write as _, io::Write as _};

use bstr::ByteSlice;
use fre::{
    ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN,
    ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK, ANCHORED_LINE_CAPTURE_ACCOUNTING_VERSION,
    ANCHORED_LINE_CAPTURE_ALGORITHM_VERSION, ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID,
    ANCHORED_LINE_CAPTURE_PLAN_ID, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuildLimits, AggregateBuildReport, AggregateBuilder, AggregateCaptureSemantics,
    AggregateCompileRegex, AggregateContinuationSemantics, AggregateCountRegex,
    AggregateEngineError, AggregateExactLiteralSemantics, AggregateExecutionDetails,
    AggregateExecutionReport, AggregateExecutionSource, AggregateFiniteLiteralIdentity,
    AggregateFiniteLiteralSemantics, AggregateFixedClassSandwichSemantics,
    AggregateGraphemeScalarDfaSemantics, AggregateManyBuildAccounting, AggregateManyBuildError,
    AggregateManyBuildLimits, AggregateManyBuildReport, AggregateManyBuilder,
    AggregateManyCaptureCountRegex, AggregateManyCaptureRunLimits, AggregateManyCaptureSemantics,
    AggregateManyCompileRegex, AggregateManyCountRegex, AggregateManyExecutionSource,
    AggregateManyLiteralSemantics, AggregateManyOperation, AggregateManyPlanIdentity,
    AggregateManyPlanKind, AggregateManyRunLimits, AggregateManySpanSumRegex, AggregateOperation,
    AggregateOperationCounterReceipt, AggregateOperationLimits, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateSpanSumRegex,
    AggregateStrategy, AggregateUnicodeScalarSemantics, AnchoredLineCaptureBuildError,
    AnchoredLineCaptureBuildLimits, AnchoredLineCaptureBuilder, AnchoredLineCapturePlan,
    AnchoredLineCaptureRunError, AnchoredLineCaptureRunLimits, BlockingDelimiterBuildAccounting,
    BlockingDelimiterBuildError, BlockingDelimiterBuildLimits, BlockingDelimiterReduceError,
    BlockingDelimiterReduceLimits, BoundedClassSequenceBuildError, BoundedClassSequenceBuildLimits,
    BoundedClassSequenceReduceError, BoundedClassSequenceReduceLimits,
    BoundedSeparatedFieldsBuildError, BoundedSeparatedFieldsBuildLimits,
    BoundedSeparatedFieldsReduceError, BoundedSeparatedFieldsReduceLimits, CaptureAggregateLimits,
    CaptureBuildError, CaptureBuildLimits, CaptureBuilder, CaptureExecutionSource,
    CaptureOperation, CapturePlanKind, CaptureRegex, CaptureRequiredLiteralBuildLimits,
    CaptureRequiredLiteralPlan, CaptureRequiredLiteralRunLimits,
    CaptureRequiredLiteralSearchOperation, CaptureRunLimits, CaptureSearchError,
    CaptureSearchLimits, CaptureStreamDomains, CaptureStreamProjection, CaptureStreamSession,
    CompatibilityProfile, DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID,
    FixedClassSandwichBuildError, FixedClassSandwichBuildLimits, FixedClassSandwichOperation,
    FixedClassSandwichReduceError, FixedClassSandwichReduceLimits, FixedPredicateWord64BuildError,
    FixedPredicateWord64MatchSelection, FixedPredicateWord64MatchSemantics,
    FixedPredicateWord64Operation, FixedPredicateWord64ReduceError,
    GraphemeScalarDfaBuildAccounting, GraphemeScalarDfaBuildError, GraphemeScalarDfaBuildLimits,
    GraphemeScalarDfaOperation, GraphemeScalarDfaReduceError, GraphemeScalarDfaReduceLimits,
    HotByteProgramArtifact, HotByteProgramBuilder, HotByteRunLimits,
    LITERAL_CLASS_RUN_LITERAL_COUNT_OPERATION_ID, LITERAL_CLASS_RUN_LITERAL_PLAN_ID,
    LITERAL_CLASS_RUN_LITERAL_SPAN_SUM_OPERATION_ID, LineCaptureBuildError, LineCaptureBuildLimits,
    LineCaptureBuilder, LineCapturePlan, LineCapturePlanKind, LineCaptureRunError,
    LineCaptureRunLimits, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateOperation, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    LiteralAssertionsBuildAccounting, LiteralAssertionsBuildError, LiteralAssertionsBuildLimits,
    LiteralAssertionsReduceError, LiteralAssertionsReduceLimits,
    LiteralClassRunLiteralBuildAccounting, LiteralClassRunLiteralBuildError,
    LiteralClassRunLiteralBuildLimits, LiteralClassRunLiteralReduceError,
    LiteralClassRunLiteralReduceLimits, LiteralReplacementErrorSource, LiteralReplacementLimits,
    NoqaBuildError, NoqaBuildLimits, NoqaGrepCaptureBuilder, NoqaGrepCaptureRegex, NoqaRunError,
    NoqaRunLimits, ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, ORDERED_LITERAL_COUNT_PLAN_ID,
    ORDERED_LITERAL_SPAN_SUM_PLAN_ID, OperationSession, OperationSessionLeaf,
    OperationSessionReducer, OperationSessionResetLimits, OperationSessionRunLimits,
    OperationSessionValue, OrderedLiteralAggregateBuildError, OrderedLiteralAggregateBuildLimits,
    OrderedLiteralAggregateReduceError, OrderedLiteralAggregateReduceLimits,
    PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID, PREFIX_CLASS_ALTERNATION_PLAN_ID, PortableBuilder,
    PrefixClassAlternationBuildError, PrefixClassAlternationBuildLimits,
    PrefixClassAlternationReduceError, PrefixClassAlternationReduceLimits,
    PrefixClassUniformParticipationBuildLimits, RustProfile, SHEBANG_CAPTURE_PATTERN,
    SHEBANG_INSPECTION_WORK, SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
    SPACE_AROUND_OPERATOR_INSPECTION_WORK, SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID, SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    STRING_QUOTE_PREFIX_CAPTURE_PATTERN, STRING_QUOTE_PREFIX_INSPECTION_WORK, SearchLimits,
    SearchSessionLimits, SparseOrderedLiteralAggregateBuildError,
    SparseOrderedLiteralAggregateReduceError, TokenPhraseBuildAccounting, TokenPhraseBuildError,
    TokenPhraseBuildLimits, TokenPhraseReduceError, TokenPhraseReduceLimits,
    UnicodeScalarAggregateBuildError, UnicodeScalarAggregateOperation,
    UnicodeScalarAggregateReduceError, UnicodeScalarAggregateReduceLimits,
    WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN, WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
    guarded_ascii_word,
};
use rebar_expand::{ExpandedRegex, HaystackTransforms, Job, Manifest, PatternBlob};
use regex_automata::{Input, meta::Regex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod canonical_case_fold;
pub mod optimizing_count_v3;
pub mod p128_forced_priority;
pub mod p128_forced_registry;
pub mod p128_foundation;
pub mod performance_contract;

/// Stable schema for deterministic semantic comparison reports.
pub const REPORT_SCHEMA: &str = "fre.rebar.comparison.v2";
/// Non-normative local timing-slice schema for exact-literal receipts.
pub const LITERAL_AGGREGATE_TIMING_SCHEMA: &str = "fre.rebar.literal-aggregate-timing.v1";
/// Non-normative local timing-slice schema for the value-only exact-literal API.
pub const LITERAL_AGGREGATE_VALUE_TIMING_SCHEMA: &str =
    "fre.rebar.literal-aggregate-value-timing.v1";
/// Deterministic affected-family semantic sentinel for Unicode exact literals.
pub const UNICODE_LITERAL_SENTINEL_SCHEMA: &str = "fre.rebar.unicode-exact-literal-sentinel.v3";
/// Candidate identity expected only while reading the canonical v2 baseline.
pub const LEGACY_FRE_ADAPTER_V2: &str = "fre-current-aggregate-v2";
/// Exact Rebar revision accepted by this implementation.
pub const AUDITED_REBAR_REVISION: &str = rebar_expand::AUDITED_REBAR_REVISION;
/// Exact Rust adapter package version.
pub const RUST_REGEX_VERSION: &str = "1.12.4";
/// Exact direct adapter dependency version.
pub const REGEX_AUTOMATA_VERSION: &str = "0.4.14";
/// Exact RE2 version recorded by the pinned Rebar adapter.
pub const RE2_VERSION: &str = "2025-11-05";
/// Stable plan label emitted by the authenticated current-FRE capture adapter.
pub const CURRENT_FRE_CAPTURE_PLAN: &str = "capture-linear-selector-persistent-history";
/// Stable plan label for aggregate-only capture-history quotient replay.
pub const CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN: &str =
    "capture-linear-selector-participation-quotient-v1";
/// Stable plan label for the fused reusable participation frontier.
pub const CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN: &str =
    "capture-fused-participation-stream-v1";
/// Stable plan label for the fused reusable persistent-history frontier.
pub const CURRENT_FRE_CAPTURE_STREAM_HISTORY_PLAN: &str =
    "capture-fused-persistent-history-stream-v1";
/// Stable plan label for capture-erased selection with proved participation.
pub const CURRENT_FRE_CAPTURE_UNIFORM_PLAN: &str = "capture-linear-selector-uniform-participation";
/// Stable plan label for one-pass source-ordered root capture-many counting.
pub const CURRENT_FRE_CAPTURE_ORDERED_ROOT_COUNT_PLAN: &str =
    "capture-ordered-root-capture-many-count-v1";
/// Stable plan label for direct Unicode-off two-arm prefix/class participation.
pub const CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN: &str =
    fre::PREFIX_CLASS_UNIFORM_PARTICIPATION_OPERATION_ID;
/// Stable plan label for the proved uniform captured scalar-alternation path.
pub const CURRENT_FRE_CAPTURE_SCALAR_PLAN: &str = "capture-uniform-alternation-unicode-scalar";
/// Stable plan label for the exact-HIR allocation-free hard Ruff line reducer.
pub const CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN: &str = fre::SPACE_AROUND_OPERATOR_OPERATION_ID;
/// Stable plan label for Ruff's exact start-anchored shebang stream.
pub const CURRENT_FRE_CAPTURE_SHEBANG_PLAN: &str = fre::SHEBANG_OPERATION_ID;
/// Stable plan label for Ruff's exact whole-line quote-prefix stream.
pub const CURRENT_FRE_CAPTURE_STRING_QUOTE_PLAN: &str = fre::STRING_QUOTE_PREFIX_OPERATION_ID;
/// Stable plan label for Ruff's exact Unicode-word Python-keyword stream.
pub const CURRENT_FRE_CAPTURE_KEYWORDS_PLAN: &str = fre::WHITESPACE_AROUND_KEYWORDS_OPERATION_ID;
/// Stable plan label for generic required-literal line pruning plus exact capture replay.
pub const CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN: &str = fre::CAPTURE_REQUIRED_LITERAL_PLAN_ID;
/// Stable plan label for Unicode-off anchored ASCII separated fields.
pub const CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN: &str =
    fre::ANCHORED_ASCII_SEPARATED_FIELDS_OPERATION_ID;
/// Stable plan label for a generic deterministic absolute-start byte line.
pub const CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN: &str =
    fre::ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID;

fn is_current_fre_capture_plan(plan: &str) -> bool {
    matches!(
        plan,
        CURRENT_FRE_CAPTURE_PLAN
            | CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN
            | CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN
            | CURRENT_FRE_CAPTURE_STREAM_HISTORY_PLAN
            | CURRENT_FRE_CAPTURE_UNIFORM_PLAN
            | CURRENT_FRE_CAPTURE_ORDERED_ROOT_COUNT_PLAN
            | CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN
            | CURRENT_FRE_CAPTURE_SCALAR_PLAN
            | CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN
            | CURRENT_FRE_CAPTURE_SHEBANG_PLAN
            | CURRENT_FRE_CAPTURE_STRING_QUOTE_PLAN
            | CURRENT_FRE_CAPTURE_KEYWORDS_PLAN
            | CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN
            | CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN
            | CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN
            | fre::NOQA_ASCII_LEADING_PLAN_ID
            | fre::NOQA_ASCII_NO_LEADING_PLAN_ID
            | fre::NOQA_UNICODE_LEADING_PLAN_ID
    )
}

fn is_current_fre_capture_route(model: &str, plan: &str) -> bool {
    if !is_current_fre_capture_plan(plan) {
        return false;
    }
    match model {
        "count-captures" => !matches!(
            plan,
            CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN
                | CURRENT_FRE_CAPTURE_SHEBANG_PLAN
                | CURRENT_FRE_CAPTURE_STRING_QUOTE_PLAN
                | CURRENT_FRE_CAPTURE_KEYWORDS_PLAN
                | CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN
                | CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN
                | CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN
                | fre::NOQA_ASCII_LEADING_PLAN_ID
                | fre::NOQA_ASCII_NO_LEADING_PLAN_ID
                | fre::NOQA_UNICODE_LEADING_PLAN_ID
        ),
        "grep-captures" => true,
        _ => false,
    }
}

const RUST_ADAPTER: &str = "rebar-rust-regex-1.12.4";
const RE2_ADAPTER: &str = "rebar-re2-2025-11-05";
const FRE_ADAPTER: &str = "fre-current-aggregate-capture-v42-fused-capture-stream-v1-persistent-capture-participation-quotient-v1-anchored-line-capture-v1-bounded-affix-span-sum-v1-terminal-class-frontier-v1-unicode-casefold-suffix-domain-v2-required-literal-line-partition-v1-noqa-v1-portable-word-run-v2-aggregate-word-run-v1-literal-assertions-v1-blocking-delimiter-v1-token-phrase-v1-unicode-scalar-run-v4-capture-scalar-alternation-v1-line-space-operator-v2-line-configured-ruff-three-v1-line-ascii-separated-fields-v1-finite-dfa-v2-packed-v2-sparse-v1-guarded-ascii-word-v1-fixed-predicate-word64-v1-fixed-class-sandwich-v1-literal-class-run-literal-v1-bounded-literal-pair-v1-grapheme-scalar-dfa-v2-bounded-class-sequence-v1-bounded-separated-fields-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-capture-count-v3-ordered-root-count-v1-continuation-accounting-v4-uniform-prefix-class-participation-v2-required-internal-anchor-v3-structural-quota-v8-regex-redux-composite-v2-url-aggregate-v1-fixed-absolute-domain-v1-terminal-greedy-class-v1-grep-stream-v1-k0-search-session-v1";
const NFA_SIZE_LIMIT: usize = 100 * 1_048_576;
const UNICODE_LITERAL_SEMANTIC_DOMAIN: &str =
    "rust-bytes.unicode-on.case-sensitive.canonical-nonempty-valid-utf8-literal.v2";
const UNICODE_LITERAL_RETAINED_UNSUPPORTED_JOBS: usize = 74;
const UNICODE_LITERAL_RETAINED_UNSUPPORTED_REASONS_SHA256: &str =
    "9e8a2d9ef8da3c3783742f9f5107db3a26ee1ccbbdefa0c4c0d9a9b49a835c4a";
const UNICODE_LITERAL_RETAINED_UNSUPPORTED_RECEIPTS_SHA256: &str =
    "fd31d8f0df856928045bff71d63235e6d34d6fa106aebeaf2b16ff892df3ec70";
const UNICODE_LITERAL_SENTINEL_JOB_IDS: [&str; 5] = [
    "curated/01-literal/sherlock-ru@rust/regex",
    "curated/01-literal/sherlock-zh@rust/regex",
    "hyperscan/literal-russian-nosom@rust/regex",
    "hyperscan/literal-russian-som@rust/regex",
    "opt/prefilter/literal-russian@rust/regex",
];

fn rebar_profile() -> RustProfile {
    RustProfile::rebar_1_12_4()
}

/// Hard deterministic resource limits for one report generation.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct RunLimits {
    /// Maximum manifest jobs.
    pub jobs: usize,
    /// Maximum patterns in one job.
    pub patterns_per_job: usize,
    /// Maximum aggregate pattern bytes in one job.
    pub pattern_bytes_per_job: usize,
    /// Maximum transformed haystack bytes in one job.
    pub haystack_bytes: usize,
    /// Maximum bytes retained by the authenticated input cache.
    pub cache_bytes: usize,
    /// Maximum reducer events (matches, groups or lines) per job.
    pub reducer_steps: u64,
    /// Maximum work allowed by one FRE search.
    pub fre_search_work: u64,
    /// Maximum scratch allowed by one FRE search.
    pub fre_scratch_bytes: usize,
    /// Maximum work allowed by one FRE aggregate compilation.
    pub fre_aggregate_compile_work: usize,
    /// Maximum HIR nodes validated by one FRE aggregate compilation.
    pub fre_aggregate_hir_nodes: usize,
    /// Maximum explicit HIR traversal stack items retained during one FRE
    /// aggregate compilation.
    pub fre_aggregate_hir_stack_items: usize,
    /// Maximum finite repetition bound expanded by one FRE aggregate
    /// compilation.
    pub fre_aggregate_repeat_bound: u32,
    /// Maximum retained continuation-program capacity for one aggregate plan.
    pub fre_aggregate_program_bytes: usize,
    /// Maximum retained capture-selector program capacity. This is separate
    /// from capture-history storage and capture-free aggregate programs.
    pub fre_capture_selector_program_bytes: usize,
    /// Maximum structural inspection work for the capture-specific uniform
    /// scalar-alternation proof.
    pub fre_capture_scalar_planner_work: usize,
    /// Maximum independent bounded-affix structural inspection work.
    pub fre_bounded_affix_planner_work: usize,
    /// Maximum allocation-free canonical-HIR literal inspection work.
    pub fre_literal_planner_work: usize,
    /// Maximum exact-literal needle bytes retained by one aggregate plan.
    pub fre_literal_build_needle_bytes: usize,
    /// Maximum exact-literal construction work.
    pub fre_literal_build_work: u64,
    /// Maximum exact-literal construction scratch bytes.
    pub fre_literal_build_scratch_bytes: usize,
    /// Maximum exact-literal persistent bytes.
    pub fre_literal_build_persistent_bytes: usize,
    /// Maximum exact-literal construction peak bytes.
    pub fre_literal_build_peak_bytes: usize,
    /// Maximum root Unicode scalar planner structural work. One unit is one
    /// examined HIR node or canonical scalar range, not one CPU instruction.
    pub fre_unicode_scalar_planner_work: usize,
    /// Maximum canonical source ranges accepted by one scalar plan build.
    pub fre_unicode_scalar_build_source_ranges: usize,
    /// Maximum scalar plan construction structural work.
    pub fre_unicode_scalar_build_work: usize,
    /// Maximum temporary scalar plan construction capacity bytes.
    pub fre_unicode_scalar_build_scratch_bytes: usize,
    /// Maximum persistent bytes retained by one scalar plan.
    pub fre_unicode_scalar_build_persistent_bytes: usize,
    /// Maximum scalar plan construction peak bytes.
    pub fre_unicode_scalar_build_peak_bytes: usize,
    /// Maximum exact-literal `haystack + needle` linear terms.
    pub fre_literal_linear_terms: usize,
    /// Maximum possible exact-literal match events.
    pub fre_literal_match_events: usize,
    /// Maximum possible exact-literal count result.
    pub fre_literal_count: u64,
    /// Maximum possible exact-literal span-sum result.
    pub fre_literal_span_sum: u64,
    /// Maximum exact-literal iterator or formula steps.
    pub fre_literal_reducer_steps: usize,
    /// Maximum exact-literal dynamic operation scratch.
    pub fre_literal_scratch_bytes: usize,
    /// Maximum exact-literal retained-plan plus operation peak bytes.
    pub fre_literal_peak_bytes: usize,
    /// Maximum work allowed by one complete aggregate execution.
    pub fre_aggregate_operation_work: usize,
    /// Maximum random-access bytes for one aggregate execution.
    pub fre_aggregate_random_access_bytes: usize,
    /// Maximum scratch bytes for one aggregate execution.
    pub fre_aggregate_scratch_bytes: usize,
    /// Maximum reverse-row log bytes retained by one aggregate execution.
    pub fre_aggregate_log_bytes: usize,
    /// Maximum sequential bytes written and read by one aggregate execution.
    pub fre_aggregate_sequential_bytes: usize,
    /// Maximum aggregate execution peak bytes.
    pub fre_aggregate_peak_bytes: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            jobs: 10_000,
            patterns_per_job: 1_000_000,
            pattern_bytes_per_job: 512 * 1_048_576,
            haystack_bytes: 512 * 1_048_576,
            cache_bytes: 768 * 1_048_576,
            reducer_steps: 1_000_000_000,
            fre_search_work: 1_000_000_000,
            fre_scratch_bytes: 256 * 1_048_576,
            fre_aggregate_compile_work: 16 * 1_048_576,
            fre_aggregate_hir_nodes: 1 << 16,
            fre_aggregate_hir_stack_items: 1 << 16,
            fre_aggregate_repeat_bound: 1 << 10,
            fre_aggregate_program_bytes: 16 * 1_048_576,
            fre_capture_selector_program_bytes: 32 * 1_048_576,
            fre_capture_scalar_planner_work: 8_192,
            fre_bounded_affix_planner_work: 4_096,
            fre_literal_planner_work: 4_096,
            fre_literal_build_needle_bytes: 32 * 1_048_576,
            fre_literal_build_work: 64 * 1_048_576,
            fre_literal_build_scratch_bytes: 32 * 1_048_576,
            fre_literal_build_persistent_bytes: 64 * 1_048_576,
            fre_literal_build_peak_bytes: 96 * 1_048_576,
            fre_unicode_scalar_planner_work: 4_096,
            fre_unicode_scalar_build_source_ranges: 1 << 16,
            fre_unicode_scalar_build_work: 1 << 20,
            fre_unicode_scalar_build_scratch_bytes: 1 << 20,
            fre_unicode_scalar_build_persistent_bytes: 1 << 20,
            fre_unicode_scalar_build_peak_bytes: 2 << 20,
            fre_literal_linear_terms: 512 * 1_048_576,
            fre_literal_match_events: 512 * 1_048_576,
            fre_literal_count: 1_000_000_000,
            fre_literal_span_sum: 512 * 1_048_576,
            fre_literal_reducer_steps: 512 * 1_048_576 + 1,
            fre_literal_scratch_bytes: 0,
            fre_literal_peak_bytes: 64 * 1_048_576,
            fre_aggregate_operation_work: 1 << 29,
            fre_aggregate_random_access_bytes: 256 * 1_048_576,
            fre_aggregate_scratch_bytes: 256 * 1_048_576,
            fre_aggregate_log_bytes: 128 * 1_048_576,
            fre_aggregate_sequential_bytes: 512 * 1_048_576,
            fre_aggregate_peak_bytes: 512 * 1_048_576,
        }
    }
}

/// Complete deterministic run configuration.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Expanded manifest path.
    pub manifest: PathBuf,
    /// Pinned Rebar checkout.
    pub checkout: PathBuf,
    /// Optional exact Rebar Rust adapter used for KLV differential checks.
    pub rebar_rust_runner: Option<PathBuf>,
    /// Optional exact Rebar RE2 adapter used for all RE2 semantic receipts.
    pub rebar_re2_runner: Option<PathBuf>,
    /// Whether to emit and execute honest current-FRE candidate receipts.
    pub run_fre: bool,
    /// Resource limits.
    pub limits: RunLimits,
}

/// Authenticated, borrowed input presented to a candidate adapter.
#[derive(Clone, Copy, Debug)]
pub struct CandidateRequest<'a> {
    /// Expanded manifest job ID.
    pub job_id: &'a str,
    /// Rebar operation model.
    pub model: &'a str,
    /// Ordered transformed UTF-8 patterns.
    pub patterns: &'a [String],
    /// Exact transformed haystack bytes.
    pub haystack: &'a [u8],
    /// Rust-regex Unicode flag.
    pub unicode: bool,
    /// Rust-regex case-insensitive flag.
    pub case_insensitive: bool,
}

/// Candidate execution result before comparison with the expected reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateOutcome {
    /// Execution completed with this reducer.
    Executed(u64),
    /// Execution completed and published the construction-selected plan used
    /// for this exact reducer. This label is evidence, not a fallback hint.
    ExecutedWithPlan { actual: u64, plan: String },
    /// The candidate does not currently implement the input/operation.
    Unsupported(String),
    /// Required dynamic state is absent.
    Unresolved(String),
    /// Execution attempted but failed.
    Fault(String),
}

/// Pluggable candidate surface kept separate from reference adapters.
pub trait CandidateAdapter {
    /// Stable adapter ID used in receipts.
    fn adapter(&self) -> &'static str;
    /// Deterministic identity for the report.
    fn identity(&self) -> AdapterIdentity;
    /// Execute one authenticated job without consulting its expected value.
    fn execute(&self, request: CandidateRequest<'_>, limits: &RunLimits) -> CandidateOutcome;
}

/// Adapter for the current honest `fre::PortableRegex` facade.
#[derive(Clone, Copy, Debug, Default)]
pub struct CurrentFreAdapter;

/// One of the five non-overlapping qualification outcomes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Actual reducer equals the exact expected value.
    Pass,
    /// Execution completed but returned a different reducer.
    Fail,
    /// The adapter honestly does not implement this operation/input.
    Unsupported,
    /// Required dynamic state was not established.
    Unresolved,
    /// Authenticated input or adapter execution failed.
    Fault,
}

/// Authenticated input identity repeated in each receipt.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct InputReceipt {
    /// Ordered transformed pattern hashes.
    pub pattern_sha256: Vec<String>,
    /// Transformed haystack hash.
    pub haystack_sha256: String,
    /// Transformed haystack length.
    pub haystack_bytes: usize,
    /// Regex Unicode flag.
    pub unicode: bool,
    /// Regex case-insensitive flag.
    pub case_insensitive: bool,
}

/// Deterministic result for one `(manifest job, execution adapter)` pair.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Receipt {
    /// Stable expanded-manifest job ID.
    pub job_id: String,
    /// Stable benchmark name.
    pub benchmark: String,
    /// Engine whose expected semantics are being checked.
    pub target_engine: String,
    /// Concrete executing adapter.
    pub adapter: String,
    /// Rebar operation model.
    pub model: String,
    /// Authenticated inputs and flags.
    pub input: InputReceipt,
    /// Exact Rebar expected reducer.
    pub expected: u64,
    /// Actual reducer, only when execution completed.
    pub actual: Option<u64>,
    /// Candidate-selected plan, when the adapter exposes an auditable plan
    /// boundary. Reference adapters do not synthesize this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_plan: Option<String>,
    /// Qualification state.
    pub status: Status,
    /// Stable reason for every non-pass result.
    pub reason: Option<String>,
}

/// One direct comparison against the pinned upstream KLV runner.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KlvDifferential {
    /// Manifest job used as the KLV input.
    pub job_id: String,
    /// Model covered by this check.
    pub model: String,
    /// Reducer returned by this implementation.
    pub local: Option<u64>,
    /// Reducer returned by the exact Rebar adapter executable.
    pub upstream: Option<u64>,
    /// Comparison state.
    pub status: Status,
    /// Stable diagnostic.
    pub reason: Option<String>,
}

/// Adapter identity included in the report rather than inferred from a host.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdapterIdentity {
    /// Receipt adapter identifier.
    pub adapter: String,
    /// Static identity/configuration string.
    pub identity: String,
    /// Runtime availability state.
    pub availability: String,
    /// Exact runtime executable digest, when an external adapter was supplied.
    pub runtime_sha256: Option<String>,
}

impl CandidateAdapter for CurrentFreAdapter {
    fn adapter(&self) -> &'static str {
        FRE_ADAPTER
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the immutable adapter receipt enumerates every independently selected physical route"
    )]
    fn identity(&self) -> AdapterIdentity {
        let profile = rebar_profile();
        let runtime_sha256 = std::env::var("FRE_CANDIDATE_RUNTIME_SHA256")
            .ok()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        let mut identity = AdapterIdentity {
            adapter: FRE_ADAPTER.to_string(),
            identity: format!(
                "{}; fre Rust-bytes facade: PortableRegex grep with absolute/LF-line/ASCII-word/positive-Unicode-word assertions and a linear canonical Unicode word-run plan plus construction-selected one-pattern compile/count/span-sum and ordered build-many compile/count/span-sum/uniform-capture-count; exact literal, direct Unicode scalar-class/counted-run, bounded fixed class-sandwich, ordered grapheme scalar DFA, linear bounded compound byte-class sequence count, constant-frontier bounded separated-field count, shared finite-language dense/sparse automaton, guarded finite ASCII-word dictionary scan, allocation-free ASCII fixed-predicate Word64 Shift-And, full-Unicode variable-width canonical case-fold alternatives, fixed-class/bounded-gap literal context count, ordered literal, or reverse-sequential-rows continuation with HIR-certified required internal-anchor and exact URL count/span-sum routes; compact canonical scalar ranges; regex-redux uses a prospectively bounded 15-stage sequential composite with one fresh Auto count or literal-replacement artifact live at a time; grep-capture participation additionally recognizes three exact literal-anchored noqa HIRs with separate ASCII-leading, ASCII-no-leading, and Unicode-leading identities and allocation-free prospective whole-haystack bounds plus four exact-HIR allocation-free Ruff line-stream configurations and one additional exact-HIR allocation-free Unicode-off anchored ASCII separated-fields HIR, with distinct immutable identities and a same-parse bounded required-any-literal DFA whose construction proves delimiter safety before one checked whole-input literal stream prunes impossible LF-framed lines for unchanged selector/replay, with an independent per-line fallback otherwise; other capture participation uses a direct Unicode-off two-arm prefix/class uniform-participation count, a uniform whole-match proof, a proved uniform captured Unicode-scalar alternation, whole-operation capture-erased span selection with a structural fixed-participation proof, or exact-span persistent tagged-history replay",
                profile.identity_string()
            ),
            availability: "one-pattern compile/count/count-spans auto-select exact canonical literals, canonical nonempty root Unicode scalar classes and greedy/lazy non-nullable root scalar repetitions, span-sum also admits greedy nullable unbounded root scalar repetition by erasing its zero-length matches, exact PREFIX MIDDLE{N} SUFFIX byte/scalar class sandwiches, Unicode-off count for greedy bounded repetitions of pairwise-disjoint HEAD BODY+ TRAIL* byte-class units, Unicode-off fixed-count identical bounded byte-class fields separated by one disjoint byte, Unicode-off fixed-class/bounded-gap literal contexts, a bounded finite-language shared dense or sparse reversed automaton (including nonempty valid-UTF8 Unicode words), a bounded Unicode-off dictionary scan for finite nonempty ASCII-word bodies with proved directional word guards, an allocation-free Unicode-off fixed-predicate Word64 reducer after a typed finite refusal, a full-Unicode variable-width canonical case-fold alternative count plan, or a bounded continuation program including structurally certified internal-anchor and exact ordered-TLD URL reducers; regex-redux composes one cleanup replacement, nine independent finite-language counts, and five ordered literal replacements serially under cumulative checked work/output/allocation/peak limits without job-name or expected-value dispatch; the direct scalar and fixed-class plans decode valid UTF-8 once and advance one byte over invalid encoding; the direct scalar plan keeps counted and lower-bounded repetition symbolic and supports count/span-sum without materializing matches; fixed-class reduction uses bounded N+2 circular state without a continuation log; bounded compound class count uses three inline byte masks and constant execution state; bounded separated-field count uses inline byte masks and a constant frontier; bounded-context count uses monotone suffix intervals and one non-overlapping unbordered-literal stream in O(N+Q); the finite-language DFA preserves leftmost-first HIR order and empty-match progress while using either dense shared transitions or sorted sparse edges with bounded failure links; the guarded dictionary preserves source order, duplicates, full bytes and directional guards while scanning exact maximal ASCII-word runs without allocation; Unicode-on finite execution rejects empty words and invalid UTF-8 words before selection; Unicode-on continuation admits compact canonical-scalar transitions with bounded UTF-8 decoding plus positive Unicode word boundaries on valid UTF-8, while local Unicode-off raw bytes remain byte-oriented and malformed word-boundary input plus remaining Unicode-word/CRLF assertions stay typed refusals; ordered build-many compile/count/count-spans preserve leftmost-first input priority, use the ordered literal plan for eligible sets, and otherwise use the Unicode-off bounded continuation while retaining every pattern's syntax/profile identity; ordered build-many count-captures additionally requires every nonempty pattern to have exactly one root capture, then reduces ordered matches to the implicit whole-match group plus that uniformly participating capture; one-pattern grep-captures first admits only three exact literal-anchored noqa HIRs under route-specific prospective O(N) work and sequential-byte bounds with zero dynamic scratch or four exact Unicode-on Ruff line HIRs plus one Unicode-off anchored ASCII separated-fields HIR through one allocation-free configured stream envelope with fixed participation, single-load decoding, and distinct plan identities, then may certify an ordered required-any-literal set from the same capture HIR and, when construction proves every effective literal delimiter-free, prune impossible lines through one checked whole-input non-overlapping stream before unchanged exact selector/replay; delimiter-sensitive required sets retain an independent checked per-line fallback; other one-pattern count-captures/grep-captures normalize a proved descending uniform captured Unicode-scalar alternation to one bounded scalar run, use a complete reverse-row selector without tagged replay when the same HIR traversal proves fixed capture participation, and otherwise retain exact-span tagged-history replay; compile constructs a fresh complete artifact before untimed verification; portable grep construction-selects a linear canonical \\b\\w{m,}\\b Unicode scalar-run plan and otherwise executes bounded compact canonical-scalar transitions plus absolute/LF-line/ASCII-word and positive Unicode-word assertions; invalid UTF-8 is non-word context for positive Unicode boundaries, while CRLF and remaining Unicode-word looks stay typed refusals; general capture-record/span outputs and all other inputs are unsupported"
                .to_string(),
            runtime_sha256,
        };
        identity.identity.push_str(
            "; finite-packed-v2 selects a ranked-anchor packed literal scanner as a distinct physical finite-language plan before dense construction",
        );
        identity.availability.push_str(
            "; eligible small nonempty finite literal languages use the bounded packed scanner under the existing finite build and run envelope",
        );
        identity.identity.push_str(
            "; unicode-casefold-suffix-domain-v2 retains at most eight canonical terminal Unicode scalars as exact UTF-8 candidate domains while the original scalar continuation program remains the semantic authority, derives route storage P from intrinsic engine limits before caller-policy refusal while observed work stays caller-capped, and receipt-meters every logical required-suffix-row construction and replay source read",
        );
        identity.availability.push_str(
            "; Unicode-on continuation count may use compact canonical terminal-scalar encodings to seed prospectively bounded required-suffix reverse rows, with wide domains retaining the incumbent route",
        );
        identity
            .identity
            .push_str("; fixed-absolute-domain-v1 canonical-HIR generic reducers with sealed exact P/A accounting");
        identity.identity.push_str(
            "; persistent-capture-participation-quotient-v1 projects prioritized exact-span tagged histories to fixed open/completed group masks, authenticates group zero, retains no offsets/history nodes, and binds source-independent state/scratch accounting",
        );
        identity.availability.push_str(
            "; nonuniform capture Count schemas fitting the fixed participation mask publish the quotient before source access, while larger schemas publish unchanged persistent-history replay and no execution-time fallback is permitted",
        );
        identity.identity.push_str(
            "; fused-capture-stream-v1 compiles prioritized tag actions once, reuses ordered frontiers and fixed participation masks across whole-input and Rebar LF/CRLF domains, preserves absolute tag offsets and clipped anchor context, and retains a prospectively bounded persistent-history fallback for wide schemas with exact construction and operation receipts",
        );
        identity.availability.push_str(
            "; eligible one-pattern grep-captures may bind one caller-owned authenticated whole-input LF/CRLF stream with reusable state/tag storage at the retained lifecycle boundary; direct one-shot reductions retain the unchanged generic per-line selector/replay, and source-free stream construction refusal selects that same fallback before source access",
        );
        identity.identity.push_str(
            "; anchored-line-capture-v1 lowers generic Unicode-off absolute-start deterministic byte HIRs to fixed inline masks and counts mandatory capture participation in one raw LF/CRLF pass",
        );
        identity.availability.push_str(
            "; grep-captures admits bounded absolute-start literal/byte-class/greedy-single-byte-repeat sequences whose variable boundaries are disjoint, with mandatory positive-width root captures and zero execution allocation/scratch/output",
        );
        identity.identity.push_str(
            "; bounded-affix-span-sum-v1 extends the HIR-derived LEFT MIDDLE{0,max} LITERAL RIGHT reducer with checked non-overlapping match-width accumulation",
        );
        identity.availability.push_str(
            "; Unicode-off bounded-affix count/span-sum scans maximal middle-byte runs once, verifies only suffix literals at disjoint right endpoints, and uses zero execution scratch",
        );
        identity.identity.push_str(
            "; aggregate-word-run-v1 is a direct aggregate word-run with independent pre-source prospective limits and checked actual counters",
        );
        identity.availability.push_str(
            "; the direct word-run reduces canonical complete-boundary ASCII/Unicode runs once with zero execution scratch",
        );
        identity.identity.push_str(
            "; fixed-class-chunks-v1 authenticates arbitrary canonical Unicode-off byte classes and nonzero exact widths with operation-specific count/span-sum identities",
        );
        identity.availability.push_str(
            "; the fixed-class chunk reducer scans each maximal admitted byte run once and emits every leftmost non-overlapping exact-width chunk with zero execution scratch",
        );
        identity.identity.push_str(
            "; literal-assertions-v1 authenticates ordered (?m:^L)|(?m:L$) count/span-sum with overlap-complete candidate discovery and complete pre-source bounds",
        );
        identity.availability.push_str(
            "; the direct literal-assertions reducer scans one monotone candidate stream with zero execution scratch",
        );
        identity.identity.push_str(
            "; blocking-delimiter-v1 authenticates Unicode-off D [^D]{0,N} T D count/span-sum with consecutive-delimiter restart and complete pre-source bounds",
        );
        identity.availability.push_str(
            "; the direct blocking-delimiter reducer scans one monotone delimiter-pair stream with zero execution scratch",
        );
        identity.identity.push_str(
            "; token-phrase-v1 authenticates Unicode-off ASCII W+ S+ L S+ W+ count/span-sum with optional redundant outer word boundaries and complete pre-source bounds",
        );
        identity.availability.push_str(
            "; the direct token-phrase reducer scans one monotone maximal-token stream with zero execution scratch",
        );
        identity.identity.push_str(
            "; literal-class-run-literal-v1 authenticates count/span-sum for fixed byte literals bracketing one greedy nonempty byte-class run",
        );
        identity.availability.push_str(
            "; the literal/class-run/literal reducer selects the longer fixed literal as an overlap-complete monotone memmem anchor, then verifies only its adjacent maximal byte-class run and opposite literal under complete prospective bounds with zero execution scratch",
        );
        identity
            .availability
            .push_str("; fixed-absolute-domain-v1 supports authenticated endpoint, whole-input and start-prefix count/span-sum routes");
        identity.identity.push_str(
            "; terminal-greedy-class-v1 authenticates a canonical greedy byte-class plus literal EndText span-sum theorem with full-haystack pre-source P/A",
        );
        identity.availability.push_str(
            "; terminal-greedy-class-v1 verifies the EOF suffix then reverse-scans the maximal predecessor class without allocation or job dispatch",
        );
        identity
            .identity
            .push_str("; bounded-literal-pair-v1 authenticates count/span-sum for two swapped literal endpoints separated by one finite greedy byte class");
        identity
            .availability
            .push_str("; bounded-literal-pair-v1 uses a prospectively capped active-start frontier and preserves greedy endpoints before non-overlapping restart");
        identity
    }

    fn execute(&self, request: CandidateRequest<'_>, limits: &RunLimits) -> CandidateOutcome {
        match fre_reducer(request, limits) {
            Ok(reduction) => CandidateOutcome::ExecutedWithPlan {
                actual: reduction.actual,
                plan: reduction.plan.to_string(),
            },
            Err(error) if error.status == Status::Unsupported => {
                CandidateOutcome::Unsupported(error.message)
            }
            Err(error) if error.status == Status::Unresolved => {
                CandidateOutcome::Unresolved(error.message)
            }
            Err(error) => CandidateOutcome::Fault(error.message),
        }
    }
}

/// Exact coverage counts.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Coverage {
    /// Receipt count by adapter and status.
    pub by_adapter_status: BTreeMap<String, BTreeMap<Status, usize>>,
    /// Receipt count by model and status.
    pub by_model_status: BTreeMap<String, BTreeMap<Status, usize>>,
    /// Total receipts.
    pub total: usize,
}

/// Deterministic semantic qualification report.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Report {
    /// Report schema.
    pub schema: String,
    /// Expanded input schema.
    pub input_schema: String,
    /// SHA-256 of exact manifest bytes.
    pub manifest_sha256: String,
    /// Pinned source revision.
    pub rebar_revision: String,
    /// Static and runtime adapter identities.
    pub adapters: Vec<AdapterIdentity>,
    /// Exact receipt coverage.
    pub coverage: Coverage,
    /// SHA-256 of the compact JSON serialization of the `receipts` array.
    pub receipts_sha256: String,
    /// Every receipt, sorted by `(job_id, adapter)`.
    pub receipts: Vec<Receipt>,
    /// Representative direct KLV differential checks.
    pub klv_differentials: Vec<KlvDifferential>,
}

/// Local, non-normative timing evidence for every semantic receipt that
/// executed the exact-literal aggregate plan.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LiteralAggregateTimingReport {
    /// Timing artifact schema.
    pub schema: String,
    /// SHA-256 of the exact semantic report serialization selecting the jobs.
    pub semantic_report_sha256: String,
    /// SHA-256 of the authenticated expanded manifest.
    pub manifest_sha256: String,
    /// Stable candidate plan label used to select receipts.
    pub candidate_plan: String,
    /// Number of exact-plan semantic receipts selected before loading.
    pub selected_receipts: usize,
    /// Precise timing boundary shared by every row.
    pub timing_boundary: String,
    /// Number of alternating samples per engine and job.
    pub samples_per_engine: usize,
    /// Target authenticated haystack bytes processed per sample before caps.
    pub target_bytes_per_sample: usize,
    /// Maximum operation calls per sample for tiny inputs.
    pub max_iterations_per_sample: usize,
    /// Host operating-system family reported by the Rust target.
    pub host_os: String,
    /// Host architecture reported by the Rust target.
    pub host_arch: String,
    /// Fresh timing process identifier, useful only for run separation.
    pub process_id: u32,
    /// One row for every exact-plan semantic receipt.
    pub jobs: Vec<LiteralAggregateTimingJob>,
}

/// One exact-literal aggregate timing row. Raw per-iteration sample values are
/// retained so medians and noise can be independently inspected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LiteralAggregateTimingJob {
    /// Stable expanded-manifest job ID.
    pub job_id: String,
    /// Rebar reducer model (`count` or `count-spans`).
    pub model: String,
    /// Authenticated transformed haystack bytes.
    pub haystack_bytes: usize,
    /// Exact semantic reducer checked before measurement.
    pub expected: u64,
    /// Operation calls in each sample.
    pub iterations_per_sample: usize,
    /// Full FRE facade nanoseconds per call for each sample.
    pub fre_ns_per_iteration: Vec<u64>,
    /// Pinned Rust meta-regex reducer nanoseconds per call for each sample.
    pub rust_ns_per_iteration: Vec<u64>,
    /// Median full FRE facade nanoseconds per call.
    pub fre_median_ns: u64,
    /// Median pinned Rust reducer nanoseconds per call.
    pub rust_median_ns: u64,
    /// `rust_median / fre_median` scaled by one million.
    pub rust_over_fre_millionths: u64,
}

/// Deterministic semantic evidence for the five projected Unicode literal
/// jobs, without regenerating the canonical full comparison report.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnicodeLiteralSentinelReport {
    /// Sentinel artifact schema.
    pub schema: String,
    /// SHA-256 of the authenticated expanded manifest.
    pub manifest_sha256: String,
    /// SHA-256 of the authenticated canonical report defining the old
    /// unsupported Unicode aggregate frontier.
    pub baseline_report_sha256: String,
    /// Stable semantic-domain tag required of every Unicode exact execution.
    pub semantic_domain: String,
    /// SHA-256 of `semantic_domain` bytes.
    pub semantic_domain_sha256: String,
    /// Pinned Rebar source revision.
    pub rebar_revision: String,
    /// Exact closed job set required by this sentinel.
    pub job_ids: Vec<String>,
    /// Number of formerly unsupported Unicode count/count-spans jobs audited.
    pub frontier_jobs: usize,
    /// Exact projected newly executable set, required to equal `job_ids`.
    pub newly_executable_job_ids: Vec<String>,
    /// Exact number of frontier jobs that must retain their refusal.
    pub retained_unsupported_jobs: usize,
    /// Pinned digest of sorted `(job_id, exact reason)` refusal records.
    pub retained_unsupported_reasons_sha256: String,
    /// Pinned digest of every complete retained Unsupported receipt.
    pub retained_unsupported_receipts_sha256: String,
    /// Compact-serialization SHA-256 of every candidate frontier receipt.
    pub frontier_receipts_sha256: String,
    /// Candidate-only projection for the complete authenticated old frontier.
    pub frontier_receipts: Vec<Receipt>,
    /// Compact-serialization SHA-256 of the sorted Rust and FRE receipts.
    pub receipts_sha256: String,
    /// Two passing receipts per job: pinned Rust and the current FRE adapter.
    pub receipts: Vec<Receipt>,
}

#[derive(Serialize)]
struct UnicodeUnsupportedReasonPin<'a> {
    job_id: &'a str,
    reason: &'a str,
}

/// Fatal report-generation error. Per-job problems are receipts, not this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompareError(String);

impl CompareError {
    /// Construct one fatal authentication or execution diagnostic.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for CompareError {}

#[derive(Debug)]
struct LoadedJob {
    patterns: Vec<String>,
    haystack: Arc<[u8]>,
}

#[derive(Debug)]
struct Loader<'a> {
    manifest_root: &'a Path,
    checkout: &'a Path,
    limits: &'a RunLimits,
    patterns: BTreeMap<String, Arc<[u8]>>,
    haystacks: BTreeMap<String, Arc<[u8]>>,
    definitions: BTreeMap<String, toml::Value>,
    cached_bytes: usize,
}

impl<'a> Loader<'a> {
    fn new(manifest_root: &'a Path, checkout: &'a Path, limits: &'a RunLimits) -> Self {
        Self {
            manifest_root,
            checkout,
            limits,
            patterns: BTreeMap::new(),
            haystacks: BTreeMap::new(),
            definitions: BTreeMap::new(),
            cached_bytes: 0,
        }
    }

    fn load(&mut self, job: &Job) -> Result<LoadedJob, CompareError> {
        self.verify_definition(job)?;
        let mut patterns = Vec::new();
        patterns
            .try_reserve_exact(job.regex.patterns.len())
            .map_err(|error| CompareError::new(format!("reserve patterns: {error}")))?;
        let mut pattern_bytes = 0usize;
        for (index, descriptor) in job.regex.patterns.iter().enumerate() {
            if descriptor.ordinal != index {
                return Err(CompareError::new(format!(
                    "{} pattern ordinal {} is not {index}",
                    job.id, descriptor.ordinal
                )));
            }
            let bytes = self.pattern(descriptor)?;
            pattern_bytes = pattern_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| CompareError::new("pattern byte sum overflow"))?;
            let pattern = std::str::from_utf8(&bytes).map_err(|error| {
                CompareError::new(format!("{} pattern {index} is not UTF-8: {error}", job.id))
            })?;
            patterns.push(pattern.to_string());
        }
        if patterns.len() > self.limits.patterns_per_job {
            return Err(CompareError::new(format!(
                "pattern count {} exceeds limit {}",
                patterns.len(),
                self.limits.patterns_per_job
            )));
        }
        if pattern_bytes > self.limits.pattern_bytes_per_job {
            return Err(CompareError::new(format!(
                "pattern bytes {pattern_bytes} exceed limit {}",
                self.limits.pattern_bytes_per_job
            )));
        }
        let reconstructed = self.reconstruct_patterns(job)?;
        if reconstructed != patterns {
            return Err(CompareError::new(format!(
                "{} transformed patterns differ from pinned definition recipe",
                job.id
            )));
        }
        let haystack = self.haystack(job)?;
        Ok(LoadedJob { patterns, haystack })
    }

    fn pattern(&mut self, descriptor: &PatternBlob) -> Result<Arc<[u8]>, CompareError> {
        if let Some(bytes) = self.patterns.get(&descriptor.sha256) {
            return Ok(Arc::clone(bytes));
        }
        let path = safe_join(self.manifest_root, &descriptor.blob)?;
        let bytes = read_limited(&path, self.limits.pattern_bytes_per_job)?;
        verify_bytes(&bytes, descriptor.bytes, &descriptor.sha256, "pattern blob")?;
        self.charge_cache(bytes.len())?;
        let bytes: Arc<[u8]> = Arc::from(bytes);
        self.patterns
            .insert(descriptor.sha256.clone(), Arc::clone(&bytes));
        Ok(bytes)
    }

    fn haystack(&mut self, job: &Job) -> Result<Arc<[u8]>, CompareError> {
        if let Some(bytes) = self.haystacks.get(&job.haystack.sha256) {
            return Ok(Arc::clone(bytes));
        }
        if job.haystack.bytes > self.limits.haystack_bytes {
            return Err(CompareError::new(format!(
                "haystack bytes {} exceed limit {}",
                job.haystack.bytes, self.limits.haystack_bytes
            )));
        }
        let raw = self.raw_haystack(job)?;
        verify_bytes(
            &raw,
            job.haystack.source.bytes,
            &job.haystack.source.sha256,
            "raw haystack",
        )?;
        let bytes = transform_haystack(&raw, &job.haystack.transforms, self.limits.haystack_bytes)?;
        verify_bytes(
            &bytes,
            job.haystack.bytes,
            &job.haystack.sha256,
            "transformed haystack",
        )?;
        if std::str::from_utf8(&bytes).is_ok() != job.haystack.valid_utf8 {
            return Err(CompareError::new(format!(
                "{} haystack UTF-8 validity differs",
                job.id
            )));
        }
        self.charge_cache(bytes.len())?;
        let bytes: Arc<[u8]> = Arc::from(bytes);
        self.haystacks
            .insert(job.haystack.sha256.clone(), Arc::clone(&bytes));
        Ok(bytes)
    }

    fn raw_haystack(&mut self, job: &Job) -> Result<Vec<u8>, CompareError> {
        match job.haystack.source.kind.as_str() {
            "file" => {
                let relative = job
                    .haystack
                    .source
                    .path
                    .as_deref()
                    .ok_or_else(|| CompareError::new("file haystack has no source path"))?;
                let path = safe_join(self.checkout, relative)?;
                read_limited(&path, self.limits.haystack_bytes)
            }
            "inline" => {
                let bench = self.definition_bench(job)?;
                inline_haystack(&bench)
            }
            other => Err(CompareError::new(format!(
                "unsupported haystack source kind {other}"
            ))),
        }
    }

    fn reconstruct_patterns(&mut self, job: &Job) -> Result<Vec<String>, CompareError> {
        let bench = self.definition_bench(job)?;
        reconstruct_patterns(
            self.checkout,
            &bench,
            &job.regex,
            self.limits.pattern_bytes_per_job,
        )
    }

    fn verify_definition(&mut self, job: &Job) -> Result<(), CompareError> {
        let bench = self.definition_bench(job)?;
        let table = bench
            .as_table()
            .ok_or_else(|| CompareError::new("bench entry is not a table"))?;
        compare_string(table, "model", &job.model)?;
        let case_insensitive = table
            .get("case-insensitive")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let unicode = table
            .get("unicode")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if case_insensitive != job.regex.case_insensitive || unicode != job.regex.unicode {
            return Err(CompareError::new(format!(
                "{} regex flags differ from definition",
                job.id
            )));
        }
        let local_name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CompareError::new("definition name is missing"))?;
        let group = definition_group(&job.provenance.definition_file)?;
        if format!("{group}/{local_name}") != job.benchmark {
            return Err(CompareError::new(format!(
                "{} benchmark name differs from definition",
                job.id
            )));
        }
        let (count, selected_by) = definition_count(table, &job.engine)?;
        if count != job.expected.count || selected_by != job.expected.selected_by {
            return Err(CompareError::new(format!(
                "{} expected result differs from first matching definition rule",
                job.id
            )));
        }
        if job.expected.reducer_contract != format!("model:{}", job.model) {
            return Err(CompareError::new(format!(
                "{} reducer contract does not identify its model",
                job.id
            )));
        }
        Ok(())
    }

    fn definition_bench(&mut self, job: &Job) -> Result<toml::Value, CompareError> {
        let relative = &job.provenance.definition_file;
        if !self.definitions.contains_key(relative) {
            let path = safe_join(self.checkout, relative)?;
            let bytes = read_limited(&path, self.limits.pattern_bytes_per_job)?;
            verify_bytes(
                &bytes,
                bytes.len(),
                &job.provenance.definition_file_sha256,
                "definition file",
            )?;
            let value: toml::Value = toml::from_slice(&bytes).map_err(|error| {
                CompareError::new(format!("decode definition {relative}: {error}"))
            })?;
            self.definitions.insert(relative.clone(), value);
        }
        let value = self
            .definitions
            .get(relative)
            .ok_or_else(|| CompareError::new("definition cache insertion failed"))?;
        let benches = value
            .get("bench")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| CompareError::new(format!("{relative} has no bench array")))?;
        benches
            .get(job.provenance.bench_index)
            .cloned()
            .ok_or_else(|| CompareError::new(format!("{relative} bench index is out of range")))
    }

    fn charge_cache(&mut self, bytes: usize) -> Result<(), CompareError> {
        let needed = self
            .cached_bytes
            .checked_add(bytes)
            .ok_or_else(|| CompareError::new("input cache size overflow"))?;
        if needed > self.limits.cache_bytes {
            return Err(CompareError::new(format!(
                "input cache needs {needed} bytes, exceeding {}",
                self.limits.cache_bytes
            )));
        }
        self.cached_bytes = needed;
        Ok(())
    }
}

/// Authenticate, execute and compare every selected manifest job.
///
/// # Errors
///
/// Returns an error only when the report itself cannot be authenticated or
/// constructed. Individual adapter/input problems are retained as receipts.
pub fn run(config: &RunConfig) -> Result<Report, CompareError> {
    let fre = CurrentFreAdapter;
    let candidate: Option<&dyn CandidateAdapter> = if config.run_fre { Some(&fre) } else { None };
    run_with_candidate(config, candidate)
}

/// Read a canonical comparison report and authenticate its sibling SHA-256
/// sidecar before returning any receipt data.
///
/// # Errors
///
/// Returns an error for an absent/mismatching sidecar, oversized or malformed
/// JSON, or bytes that are not the comparator's canonical serialization.
pub fn read_authenticated_report(path: &Path) -> Result<Report, CompareError> {
    let bytes = read_limited(path, 64 * 1_048_576)?;
    let digest = sha256(&bytes);
    verify_sidecar_hash(path, &digest)?;
    let report: Report = serde_json::from_slice(&bytes)
        .map_err(|error| CompareError::new(format!("decode report: {error}")))?;
    let canonical = report_bytes(&report)?;
    if canonical != bytes {
        return Err(CompareError::new(
            "comparison report is not in canonical comparator serialization",
        ));
    }
    Ok(report)
}

/// Return the exact single-search limits used by the authenticated current-FRE
/// Rebar adapter.
#[must_use]
pub fn current_fre_rebar_search_limits() -> SearchLimits {
    let limits = RunLimits::default();
    SearchLimits {
        max_work: limits.fre_search_work,
        max_scratch_bytes: limits.fre_scratch_bytes,
    }
}

/// Construct the exact aggregate builder used by the authenticated
/// current-FRE Rebar adapter.
#[must_use]
pub fn current_fre_rebar_aggregate_builder(
    pattern: impl Into<String>,
    unicode: bool,
    case_insensitive: bool,
) -> AggregateBuilder {
    let limits = RunLimits::default();
    AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .limits(aggregate_build_limits(&limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
}

/// Construct the exact ordered multi-pattern aggregate builder used by the
/// authenticated current-FRE Rebar adapter.
#[must_use]
pub fn current_fre_rebar_aggregate_many_builder(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
) -> AggregateManyBuilder<'_> {
    let limits = RunLimits::default();
    aggregate_many_builder_with_limits(patterns, unicode, case_insensitive, &limits)
}

fn aggregate_many_builder_with_limits<'a>(
    patterns: &'a [String],
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> AggregateManyBuilder<'a> {
    AggregateManyBuilder::new(patterns)
        .profile(rebar_profile())
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .limits(aggregate_many_build_limits(limits))
        .strategy(AggregateStrategy::ReverseSequentialRows)
}

/// Reconstructible compile request for the exact pinned Rust-regex reference
/// adapter.
///
/// Construction is deliberately deferred so an executor can measure exactly
/// one fresh complete regex construction. Semantic verification is performed
/// on the returned artifact after the construction duration is captured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustRegexReferenceCompileLifecycle {
    patterns: Vec<String>,
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
}

/// Fresh complete pinned Rust-regex artifact returned by one deferred
/// construction.
#[derive(Debug)]
pub struct RustRegexReferenceCompileArtifact {
    regex: Regex,
}

impl RustRegexReferenceCompileLifecycle {
    /// Construct one fresh complete pinned Rust-regex artifact. Builder
    /// configuration and construction are both inside this call; semantic
    /// verification is not.
    ///
    /// # Errors
    ///
    /// Returns the exact pinned adapter compilation failure.
    pub fn construct(&self) -> Result<RustRegexReferenceCompileArtifact, CompareError> {
        let regex = rust_compile_options(&self.patterns, self.unicode, self.case_insensitive)
            .map_err(|error| CompareError::new(error.message))?;
        Ok(RustRegexReferenceCompileArtifact { regex })
    }
}

impl RustRegexReferenceCompileArtifact {
    /// Verify the compiled artifact outside its construction measurement using
    /// the compile model's exact semantic reducer.
    ///
    /// # Errors
    ///
    /// Returns an error for input-length mismatch or reducer failure.
    pub fn verify(
        &self,
        lifecycle: &RustRegexReferenceCompileLifecycle,
        haystack: &[u8],
    ) -> Result<u64, CompareError> {
        if haystack.len() != lifecycle.haystack_len {
            return Err(CompareError::new(format!(
                "Rust reference compile lifecycle haystack length {} differs from prepared {}",
                haystack.len(),
                lifecycle.haystack_len
            )));
        }
        count_matches(&self.regex, haystack, RunLimits::default().reducer_steps)
            .map_err(|error| CompareError::new(error.message))
    }
}

/// Create a deferred pinned Rust-regex compile lifecycle bound to one exact
/// input length.
///
/// # Errors
///
/// Returns an error for an empty pattern set.
pub fn rust_regex_reference_compile_lifecycle(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<RustRegexReferenceCompileLifecycle, CompareError> {
    if patterns.is_empty() {
        return Err(CompareError::new(
            "Rust reference compile lifecycle requires at least one pattern",
        ));
    }
    Ok(RustRegexReferenceCompileLifecycle {
        patterns: patterns.to_vec(),
        unicode,
        case_insensitive,
        haystack_len,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustRegexReferenceOperationModel {
    Count,
    CountSpans,
    CountCaptures,
    Grep,
    GrepCaptures,
}

impl RustRegexReferenceOperationModel {
    fn parse(model: &str) -> Result<Self, CompareError> {
        match model {
            "count" => Ok(Self::Count),
            "count-spans" => Ok(Self::CountSpans),
            "count-captures" => Ok(Self::CountCaptures),
            "grep" => Ok(Self::Grep),
            "grep-captures" => Ok(Self::GrepCaptures),
            other => Err(CompareError::new(format!(
                "unexpected Rust reference operation lifecycle model {other}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::CountSpans => "count-spans",
            Self::CountCaptures => "count-captures",
            Self::Grep => "grep",
            Self::GrepCaptures => "grep-captures",
        }
    }
}

/// One already-built pinned Rust-regex artifact for first/steady public
/// operation reference boundaries.
#[derive(Debug)]
pub struct RustRegexReferenceOperationLifecycle {
    model: RustRegexReferenceOperationModel,
    regex: Regex,
    haystack_len: usize,
    reducer_steps: u64,
}

impl RustRegexReferenceOperationLifecycle {
    /// Exact Rebar operation model retained by this artifact.
    #[must_use]
    pub const fn model(&self) -> &'static str {
        self.model.as_str()
    }

    /// Execute one complete reference operation on the same retained artifact.
    /// Calling this once is the first-operation boundary; one verified untimed
    /// call followed by another call is the steady-operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for input-length mismatch or checked reducer failure.
    pub fn execute(&self, haystack: &[u8]) -> Result<u64, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "Rust reference operation haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let reduced = match self.model {
            RustRegexReferenceOperationModel::Count => {
                count_matches(&self.regex, haystack, self.reducer_steps)
            }
            RustRegexReferenceOperationModel::CountSpans => {
                count_spans(&self.regex, haystack, self.reducer_steps)
            }
            RustRegexReferenceOperationModel::CountCaptures => {
                count_captures(&self.regex, haystack, self.reducer_steps)
            }
            RustRegexReferenceOperationModel::Grep => {
                grep(&self.regex, haystack, self.reducer_steps)
            }
            RustRegexReferenceOperationModel::GrepCaptures => {
                grep_captures(&self.regex, haystack, self.reducer_steps)
            }
        };
        reduced.map_err(|error| CompareError::new(error.message))
    }
}

/// Build one exact pinned Rust-regex operation lifecycle outside the measured
/// first/steady public operation boundary.
///
/// # Errors
///
/// Returns an error for an empty pattern set, a non-operation model, or exact
/// pinned adapter compilation failure.
pub fn rust_regex_reference_operation_lifecycle(
    model: &str,
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<RustRegexReferenceOperationLifecycle, CompareError> {
    if patterns.is_empty() {
        return Err(CompareError::new(
            "Rust reference operation lifecycle requires at least one pattern",
        ));
    }
    let model = RustRegexReferenceOperationModel::parse(model)?;
    let regex = rust_compile_options(patterns, unicode, case_insensitive)
        .map_err(|error| CompareError::new(error.message))?;
    Ok(RustRegexReferenceOperationLifecycle {
        model,
        regex,
        haystack_len,
        reducer_steps: RunLimits::default().reducer_steps,
    })
}

/// Reconstructible compile request for one exact authenticated aggregate row.
///
/// Construction is deliberately deferred so an executor can place precisely
/// one fresh public construction inside a contracted measurement boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentFreAggregateCompileLifecycle {
    patterns: Vec<String>,
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
}

/// Fresh complete compile artifact returned by one deferred construction.
#[derive(Debug)]
pub struct CurrentFreAggregateCompileArtifact {
    inner: CurrentFreAggregateCompileArtifactInner,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an allocation inside the exact fresh-construction boundary"
)]
enum CurrentFreAggregateCompileArtifactInner {
    Single(AggregateCompileRegex),
    Many(AggregateManyCompileRegex),
}

impl CurrentFreAggregateCompileLifecycle {
    /// Construct one fresh complete public artifact. Builder configuration and
    /// construction are both inside this call; semantic verification is not.
    ///
    /// # Errors
    ///
    /// Returns an exact builder refusal/fault without selecting another plan.
    pub fn construct(&self) -> Result<CurrentFreAggregateCompileArtifact, CompareError> {
        let inner = if self.patterns.len() == 1 {
            CurrentFreAggregateCompileArtifactInner::Single(
                current_fre_rebar_aggregate_builder(
                    self.patterns[0].clone(),
                    self.unicode,
                    self.case_insensitive,
                )
                .build_compile()
                .map_err(|error| {
                    CompareError::new(format!("FRE compile lifecycle construction: {error}"))
                })?,
            )
        } else {
            CurrentFreAggregateCompileArtifactInner::Many(
                current_fre_rebar_aggregate_many_builder(
                    &self.patterns,
                    self.unicode,
                    self.case_insensitive,
                )
                .build_compile()
                .map_err(|error| {
                    CompareError::new(format!("FRE compile-many lifecycle construction: {error}"))
                })?,
            )
        };
        Ok(CurrentFreAggregateCompileArtifact { inner })
    }
}

impl CurrentFreAggregateCompileArtifact {
    /// Authenticate the selected plan and return its exact semantic plan label.
    ///
    /// # Errors
    ///
    /// Returns an error if this artifact does not bind the lifecycle's exact
    /// pattern order, profile, operation, and selected-plan semantics.
    pub fn plan(
        &self,
        lifecycle: &CurrentFreAggregateCompileLifecycle,
    ) -> Result<&'static str, CompareError> {
        match (&self.inner, lifecycle.patterns.as_slice()) {
            (CurrentFreAggregateCompileArtifactInner::Single(regex), [_]) => {
                current_fre_rebar_validate_aggregate_identity(
                    regex.build_report(),
                    lifecycle.unicode,
                    "compile",
                )?;
                Ok(aggregate_single_plan_label("compile", regex.build_report()))
            }
            (CurrentFreAggregateCompileArtifactInner::Many(regex), patterns)
                if patterns.len() > 1 =>
            {
                current_fre_rebar_validate_aggregate_many_identity(
                    patterns,
                    regex.build_report(),
                    lifecycle.unicode,
                    lifecycle.case_insensitive,
                    "compile",
                )?;
                Ok(match regex.build_report().plan {
                    AggregateManyPlanKind::OrderedLiteral => "compile-many-ordered-literal",
                    AggregateManyPlanKind::ContinuationProgram => {
                        "compile-many-continuation-program"
                    }
                })
            }
            _ => Err(CompareError::new(
                "FRE compile artifact multiplicity differs from its lifecycle",
            )),
        }
    }

    /// Verify the compiled artifact outside its construction measurement.
    ///
    /// # Errors
    ///
    /// Returns an error for lifecycle identity mismatch, input-length mismatch,
    /// limit derivation failure, or retained-plan execution failure.
    pub fn verify(
        &self,
        lifecycle: &CurrentFreAggregateCompileLifecycle,
        haystack: &[u8],
    ) -> Result<u64, CompareError> {
        let _ = self.plan(lifecycle)?;
        if haystack.len() != lifecycle.haystack_len {
            return Err(CompareError::new(format!(
                "compile lifecycle haystack length {} differs from prepared {}",
                haystack.len(),
                lifecycle.haystack_len
            )));
        }
        match &self.inner {
            CurrentFreAggregateCompileArtifactInner::Single(regex) => {
                let limits = current_fre_rebar_compile_run_limits(haystack.len(), regex)?;
                regex
                    .verify_count(haystack, limits)
                    .map(|result| result.value())
                    .map_err(|error| {
                        CompareError::new(format!("FRE compile lifecycle verification: {error}"))
                    })
            }
            CurrentFreAggregateCompileArtifactInner::Many(regex) => {
                let limits = current_fre_rebar_aggregate_many_run_limits(
                    haystack.len(),
                    regex.build_report(),
                )?;
                regex
                    .verify_count(haystack, limits)
                    .map(|result| result.value())
                    .map_err(|error| {
                        CompareError::new(format!(
                            "FRE compile-many lifecycle verification: {error}"
                        ))
                    })
            }
        }
    }
}

/// Create a deferred aggregate compile lifecycle bound to one input length.
///
/// # Errors
///
/// Returns an error for an empty pattern set.
pub fn current_fre_rebar_aggregate_compile_lifecycle(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreAggregateCompileLifecycle, CompareError> {
    if patterns.is_empty() {
        return Err(CompareError::new(
            "FRE aggregate compile lifecycle requires at least one pattern",
        ));
    }
    Ok(CurrentFreAggregateCompileLifecycle {
        patterns: patterns.to_vec(),
        unicode,
        case_insensitive,
        haystack_len,
    })
}

/// Stable plan label for the explicit planner-disabled hot-byte compiler.
pub const CURRENT_FRE_HOT_BYTE_PROGRAM_PLAN: &str = "hot-byte-programs-simd-v1";

/// One explicitly requested fixed-byte-program artifact and its retained
/// allocation-free operation session.
#[derive(Debug)]
pub struct CurrentFreHotByteOperationLifecycle {
    model: p128_forced_registry::P128ForcedModel,
    haystack_len: usize,
    artifact: HotByteProgramArtifact,
    session: RefCell<OperationSession>,
    limits: HotByteRunLimits,
}

impl CurrentFreHotByteOperationLifecycle {
    /// Exact Rebar model retained by this forced artifact.
    #[must_use]
    pub const fn model(&self) -> &'static str {
        self.model.as_str()
    }

    /// Stable planner-disabled plan label.
    #[must_use]
    pub const fn plan(&self) -> &'static str {
        CURRENT_FRE_HOT_BYTE_PROGRAM_PLAN
    }

    /// Execute one complete public `Count` or `SpanSum` operation on the retained
    /// artifact and session.
    ///
    /// # Errors
    ///
    /// Returns an error for an input-length mismatch, exact resource refusal,
    /// receipt authentication failure, or reducer/value mismatch.
    pub fn execute(&self, haystack: &[u8]) -> Result<u64, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "hot-byte operation haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let reducer = match self.model {
            p128_forced_registry::P128ForcedModel::Count => OperationSessionReducer::Count,
            p128_forced_registry::P128ForcedModel::SpanSum => OperationSessionReducer::SpanSum,
            p128_forced_registry::P128ForcedModel::CountCaptures
            | p128_forced_registry::P128ForcedModel::GrepCaptures => {
                return Err(CompareError::new(
                    "hot-byte lifecycle retained an unsupported reducer",
                ));
            }
        };
        let receipt = self
            .artifact
            .execute_with_limits(
                &mut self.session.borrow_mut(),
                haystack,
                0..haystack.len(),
                reducer,
                self.limits,
            )
            .map_err(|error| CompareError::new(format!("FRE hot-byte lifecycle: {error}")))?;
        if !receipt.closes() {
            return Err(CompareError::new(
                "FRE hot-byte lifecycle returned an unauthenticated receipt",
            ));
        }
        match (self.model, receipt.value) {
            (
                p128_forced_registry::P128ForcedModel::Count,
                Some(OperationSessionValue::Count(value)),
            )
            | (
                p128_forced_registry::P128ForcedModel::SpanSum,
                Some(OperationSessionValue::SpanSum(value)),
            ) => Ok(value),
            _ => Err(CompareError::new(
                "FRE hot-byte lifecycle returned the wrong typed value",
            )),
        }
    }
}

/// Build the one executable planner-disabled compiler selected by exact
/// compiler ID. No benchmark identity, expected result, or source bytes enter
/// this construction boundary.
///
/// # Errors
///
/// Returns an error for an unknown/mismatched compiler ID, a multi-pattern
/// request, structural ineligibility, missing retained SIMD classifier, exact
/// descriptor/session refusal, or checked limit derivation failure.
pub fn current_fre_rebar_hot_byte_operation_lifecycle(
    compiler_id: &str,
    model: &str,
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreHotByteOperationLifecycle, CompareError> {
    let model = p128_forced_registry::P128ForcedModel::parse(model)?;
    let contract =
        p128_forced_registry::P128ForcedCompilerManifest::load().resolve(compiler_id, model)?;
    if contract.compiler() != p128_forced_registry::P128ForcedCompiler::HotBytePrograms {
        return Err(CompareError::new(
            "requested forced compiler has no hot-byte executable lifecycle",
        ));
    }
    let [pattern] = patterns else {
        return Err(CompareError::new(
            "hot-byte forced lifecycle requires exactly one pattern",
        ));
    };
    let mut profile = rebar_profile();
    profile.options.unicode = unicode;
    profile.options.case_insensitive = case_insensitive;
    let artifact = HotByteProgramBuilder::new(pattern.clone())
        .profile(profile)
        .build()
        .map_err(|error| CompareError::new(format!("FRE hot-byte lifecycle build: {error}")))?;
    if artifact.build_receipt().actual().simd_classifiers == 0 {
        return Err(CompareError::new(
            "hot-byte forced lifecycle requires a retained SIMD classifier",
        ));
    }
    let session = artifact
        .new_session()
        .map_err(|error| CompareError::new(format!("FRE hot-byte session build: {error:?}")))?;
    let prospective = artifact
        .prospective(0..haystack_len)
        .map_err(|error| CompareError::new(format!("FRE hot-byte preflight: {error:?}")))?;
    let reset = session
        .reset_prospective(OperationSessionLeaf::Hot, 1)
        .map_err(|error| CompareError::new(format!("FRE hot-byte reset preflight: {error:?}")))?;
    let reset = OperationSessionResetLimits::exact(&reset)
        .ok_or_else(|| CompareError::new("FRE hot-byte reset limit conversion overflow"))?;
    let limits = HotByteRunLimits {
        reset,
        run: OperationSessionRunLimits::exact(prospective),
    };
    Ok(CurrentFreHotByteOperationLifecycle {
        model,
        haystack_len,
        artifact,
        session: RefCell::new(session),
        limits,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentFreAggregateOperationModel {
    Count,
    SpanSum,
}

impl CurrentFreAggregateOperationModel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::SpanSum => "count-spans",
        }
    }
}

/// One already-built aggregate artifact for first/steady public operations.
#[derive(Debug)]
pub struct CurrentFreAggregateOperationLifecycle {
    model: CurrentFreAggregateOperationModel,
    plan: &'static str,
    haystack_len: usize,
    inner: CurrentFreAggregateOperationInner,
}

#[derive(Debug)]
enum CurrentFreAggregateOperationInner {
    CountSingle(AggregateCountRegex, AggregateRunLimits),
    CountMany(AggregateManyCountRegex, AggregateManyRunLimits),
    SpanSumSingle(AggregateSpanSumRegex, AggregateRunLimits),
    SpanSumMany(AggregateManySpanSumRegex, AggregateManyRunLimits),
}

/// Value produced by the reusable aggregate operation shell together with an
/// optional immutable continuation counter receipt.
///
/// This result intentionally carries no benchmark name, fixture identity,
/// expected value, result hash, or timing observation. Callers may attach
/// attribution only after this shell has finished its structurally selected
/// operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentFreAggregateCounterReceiptStatus {
    /// The single-pattern continuation route published a sealed P/A receipt.
    Continuation(Box<AggregateOperationCounterReceipt>),
    /// A single-pattern direct route completed without a continuation receipt.
    DirectSelectedPlan,
    /// A multi-pattern route completed before its native counter receipt is
    /// implemented. This is deliberately not represented as zero counters.
    MissingMultiPlanReceipt,
}

/// Value produced by the reusable aggregate operation shell together with its
/// explicit native counter-receipt status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentFreAggregateOperationCounterResult {
    value: u64,
    receipt_status: CurrentFreAggregateCounterReceiptStatus,
}

impl CurrentFreAggregateOperationCounterResult {
    /// Value-only reducer output.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Optional immutable structural receipt from a continuation operation.
    #[must_use]
    pub const fn continuation_receipt(&self) -> Option<&AggregateOperationCounterReceipt> {
        match &self.receipt_status {
            CurrentFreAggregateCounterReceiptStatus::Continuation(receipt) => Some(receipt),
            CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
            | CurrentFreAggregateCounterReceiptStatus::MissingMultiPlanReceipt => None,
        }
    }

    /// Exact native evidence status after the operation completed.
    #[must_use]
    pub const fn receipt_status(&self) -> &CurrentFreAggregateCounterReceiptStatus {
        &self.receipt_status
    }
}

impl CurrentFreAggregateOperationLifecycle {
    /// Exact Rebar model retained by this artifact.
    #[must_use]
    pub const fn model(&self) -> &'static str {
        self.model.as_str()
    }

    /// Exact authenticated construction-selected plan label.
    #[must_use]
    pub const fn plan(&self) -> &'static str {
        self.plan
    }

    /// Execute one complete public operation on the same retained artifact.
    /// Calling this once is the first-operation boundary; an untimed call then
    /// another call is the steady-operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for input-length mismatch or retained-plan refusal.
    pub fn execute(&self, haystack: &[u8]) -> Result<u64, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "aggregate operation haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        match &self.inner {
            CurrentFreAggregateOperationInner::CountSingle(regex, limits) => {
                regex.count_value(haystack, limits).map_err(|error| {
                    let message = format!("FRE count lifecycle: {error}");
                    CompareError::new(aggregate_attempt_error(&error, message).message)
                })
            }
            CurrentFreAggregateOperationInner::CountMany(regex, limits) => regex
                .count_value(haystack, *limits)
                .map_err(|error| CompareError::new(format!("FRE count-many lifecycle: {error}"))),
            CurrentFreAggregateOperationInner::SpanSumSingle(regex, limits) => {
                regex.span_sum_value(haystack, limits).map_err(|error| {
                    let message = format!("FRE span-sum lifecycle: {error}");
                    CompareError::new(aggregate_attempt_error(&error, message).message)
                })
            }
            CurrentFreAggregateOperationInner::SpanSumMany(regex, limits) => {
                regex.span_sum_value(haystack, *limits).map_err(|error| {
                    CompareError::new(format!("FRE span-sum-many lifecycle: {error}"))
                })
            }
        }
    }

    /// Execute the same retained value-only operation as [`Self::execute`]
    /// and publish an optional continuation counter receipt after completion.
    ///
    /// This is deliberately an out-of-timed-boundary diagnostic seam. It
    /// reuses the same prebuilt artifact and exact derived limits, but is not
    /// called by the benchmark runner. It cannot steer construction or route
    /// selection because it receives no benchmark or fixture metadata.
    ///
    /// # Errors
    ///
    /// Returns the same input-length and retained-plan errors as
    /// [`Self::execute`].
    pub fn execute_with_counters(
        &self,
        haystack: &[u8],
    ) -> Result<CurrentFreAggregateOperationCounterResult, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "aggregate operation haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        match &self.inner {
            CurrentFreAggregateOperationInner::CountSingle(regex, limits) => regex
                .count_value_with_counters(haystack, limits)
                .map(|result| CurrentFreAggregateOperationCounterResult {
                    value: result.value(),
                    receipt_status: result.continuation_receipt().cloned().map_or(
                        CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan,
                        |receipt| {
                            CurrentFreAggregateCounterReceiptStatus::Continuation(Box::new(receipt))
                        },
                    ),
                })
                .map_err(|error| {
                    let message = format!("FRE count lifecycle: {error}");
                    CompareError::new(aggregate_attempt_error(&error, message).message)
                }),
            CurrentFreAggregateOperationInner::CountMany(regex, limits) => regex
                .count_value(haystack, *limits)
                .map(|value| CurrentFreAggregateOperationCounterResult {
                    value,
                    receipt_status:
                        CurrentFreAggregateCounterReceiptStatus::MissingMultiPlanReceipt,
                })
                .map_err(|error| CompareError::new(format!("FRE count-many lifecycle: {error}"))),
            CurrentFreAggregateOperationInner::SpanSumSingle(regex, limits) => regex
                .span_sum_value_with_counters(haystack, limits)
                .map(|result| CurrentFreAggregateOperationCounterResult {
                    value: result.value(),
                    receipt_status: result.continuation_receipt().cloned().map_or(
                        CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan,
                        |receipt| {
                            CurrentFreAggregateCounterReceiptStatus::Continuation(Box::new(receipt))
                        },
                    ),
                })
                .map_err(|error| {
                    let message = format!("FRE span-sum lifecycle: {error}");
                    CompareError::new(aggregate_attempt_error(&error, message).message)
                }),
            CurrentFreAggregateOperationInner::SpanSumMany(regex, limits) => regex
                .span_sum_value(haystack, *limits)
                .map(|value| CurrentFreAggregateOperationCounterResult {
                    value,
                    receipt_status:
                        CurrentFreAggregateCounterReceiptStatus::MissingMultiPlanReceipt,
                })
                .map_err(|error| {
                    CompareError::new(format!("FRE span-sum-many lifecycle: {error}"))
                }),
        }
    }
}

/// Build one exact aggregate operation lifecycle outside the measured public
/// operation boundary.
///
/// # Errors
///
/// Returns an error for an empty pattern set, non-operation model, builder
/// refusal, semantic identity mismatch, or limit-derivation failure.
pub fn current_fre_rebar_aggregate_operation_lifecycle(
    model: &str,
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreAggregateOperationLifecycle, CompareError> {
    if patterns.is_empty() {
        return Err(CompareError::new(
            "FRE aggregate operation lifecycle requires at least one pattern",
        ));
    }
    match model {
        "count" => {
            build_current_fre_count_lifecycle(patterns, unicode, case_insensitive, haystack_len)
        }
        "count-spans" => {
            build_current_fre_span_sum_lifecycle(patterns, unicode, case_insensitive, haystack_len)
        }
        other => Err(CompareError::new(format!(
            "unexpected aggregate operation lifecycle model {other}"
        ))),
    }
}

fn build_current_fre_count_lifecycle(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreAggregateOperationLifecycle, CompareError> {
    let (plan, inner) = if let [pattern] = patterns {
        let regex = current_fre_rebar_aggregate_builder(pattern.clone(), unicode, case_insensitive)
            .build_count()
            .map_err(|error| CompareError::new(format!("FRE count lifecycle build: {error}")))?;
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), unicode, "count")?;
        let plan = aggregate_single_plan_label("count", regex.build_report());
        let retained_upper_bounds = regex
            .retained_full_window_upper_bounds(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE count lifecycle retained-owner preflight: {error}"
                ))
            })?;
        let fixed_absolute_prospective = regex
            .fixed_absolute_domain_full_window_prospective(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE count lifecycle fixed-domain preflight: {error}"
                ))
            })?;
        let fixed_absolute_composite = regex
            .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE count lifecycle fixed-domain composite preflight: {error}"
                ))
            })?;
        let limits = aggregate_run_limits_with_fixed_absolute(
            haystack_len,
            regex.build_report(),
            retained_upper_bounds,
            fixed_absolute_prospective,
            fixed_absolute_composite,
            &RunLimits::default(),
        )
        .map_err(|error| CompareError::new(error.message))?;
        (
            plan,
            CurrentFreAggregateOperationInner::CountSingle(regex, limits),
        )
    } else {
        let regex = current_fre_rebar_aggregate_many_builder(patterns, unicode, case_insensitive)
            .build_count()
            .map_err(|error| {
                CompareError::new(format!("FRE count-many lifecycle build: {error}"))
            })?;
        current_fre_rebar_validate_aggregate_many_identity(
            patterns,
            regex.build_report(),
            unicode,
            case_insensitive,
            "count",
        )?;
        let plan = aggregate_many_plan_label("count", regex.build_report().plan);
        let limits =
            current_fre_rebar_aggregate_many_run_limits(haystack_len, regex.build_report())?;
        (
            plan,
            CurrentFreAggregateOperationInner::CountMany(regex, limits),
        )
    };
    Ok(CurrentFreAggregateOperationLifecycle {
        model: CurrentFreAggregateOperationModel::Count,
        plan,
        haystack_len,
        inner,
    })
}

fn build_current_fre_span_sum_lifecycle(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreAggregateOperationLifecycle, CompareError> {
    let (plan, inner) = if let [pattern] = patterns {
        let regex = current_fre_rebar_aggregate_builder(pattern.clone(), unicode, case_insensitive)
            .build_span_sum()
            .map_err(|error| CompareError::new(format!("FRE span-sum lifecycle build: {error}")))?;
        current_fre_rebar_validate_aggregate_identity(
            regex.build_report(),
            unicode,
            "count-spans",
        )?;
        let plan = aggregate_single_plan_label("count-spans", regex.build_report());
        let retained_upper_bounds = regex
            .retained_full_window_upper_bounds(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE span-sum lifecycle retained-owner preflight: {error}"
                ))
            })?;
        let fixed_absolute_prospective = regex
            .fixed_absolute_domain_full_window_prospective(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE span-sum lifecycle fixed-domain preflight: {error}"
                ))
            })?;
        let fixed_absolute_composite = regex
            .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE span-sum lifecycle fixed-domain composite preflight: {error}"
                ))
            })?;
        let limits = aggregate_run_limits_with_fixed_absolute(
            haystack_len,
            regex.build_report(),
            retained_upper_bounds,
            fixed_absolute_prospective,
            fixed_absolute_composite,
            &RunLimits::default(),
        )
        .map_err(|error| CompareError::new(error.message))?;
        (
            plan,
            CurrentFreAggregateOperationInner::SpanSumSingle(regex, limits),
        )
    } else {
        let regex = current_fre_rebar_aggregate_many_builder(patterns, unicode, case_insensitive)
            .build_span_sum()
            .map_err(|error| {
                CompareError::new(format!("FRE span-sum-many lifecycle build: {error}"))
            })?;
        current_fre_rebar_validate_aggregate_many_identity(
            patterns,
            regex.build_report(),
            unicode,
            case_insensitive,
            "count-spans",
        )?;
        let plan = aggregate_many_plan_label("count-spans", regex.build_report().plan);
        let limits =
            current_fre_rebar_aggregate_many_run_limits(haystack_len, regex.build_report())?;
        (
            plan,
            CurrentFreAggregateOperationInner::SpanSumMany(regex, limits),
        )
    };
    Ok(CurrentFreAggregateOperationLifecycle {
        model: CurrentFreAggregateOperationModel::SpanSum,
        plan,
        haystack_len,
        inner,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive stable plan-label dispatch keeps every public route adjacent"
)]
fn aggregate_single_plan_label(model: &str, report: &AggregateBuildReport) -> &'static str {
    let url_plan = matches!(
        report.build,
        AggregateBuildAccounting::Continuation(compile)
            if compile.url_aggregate_plans == 1
    ) && report.authenticates_url_aggregate_identity();
    let url_route = report.continuation_strategy == Some(AggregateStrategy::ReverseSequentialRows)
        && matches!(
            (model, report.operation),
            ("count", AggregateOperation::Count) | ("count-spans", AggregateOperation::SpanSum)
        );
    if url_plan && (model == "compile" || url_route) {
        return if model == "compile" {
            "compile-aggregate-url"
        } else {
            "aggregate-url"
        };
    }
    if matches!(
        report.plan_identity,
        AggregatePlanIdentity::BoundedContext(identity)
            if identity.kernel.plan_id == fre::BOUNDED_AFFIX_PLAN_ID
    ) {
        return if model == "compile" {
            "compile-aggregate-bounded-affix"
        } else {
            "aggregate-bounded-affix"
        };
    }
    if matches!(
        report.plan_identity,
        AggregatePlanIdentity::WordRun(identity)
            if identity.semantics
                == fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks
    ) {
        return if model == "compile" {
            "compile-aggregate-fixed-class-chunks-v1"
        } else {
            "aggregate-fixed-class-chunks-v1"
        };
    }
    let sparse = matches!(
        report.build,
        AggregateBuildAccounting::SparseFiniteLiteral(_)
    );
    match (model, report.plan, sparse) {
        ("compile", AggregatePlanKind::ExactLiteral, _) => "compile-aggregate-exact-literal",
        ("compile", AggregatePlanKind::UnicodeScalarClass, _) => {
            "compile-aggregate-unicode-scalar-class"
        }
        ("compile", AggregatePlanKind::WordRun, _) => "compile-aggregate-word-run-v1",
        ("compile", AggregatePlanKind::LiteralAssertions, _) => {
            "compile-aggregate-literal-assertions-v1"
        }
        ("compile", AggregatePlanKind::BlockingDelimiter, _) => {
            "compile-aggregate-blocking-delimiter-v1"
        }
        ("compile", AggregatePlanKind::TokenPhrase, _) => "compile-aggregate-token-phrase-v1",
        ("compile", AggregatePlanKind::FixedClassSandwich, _) => {
            "compile-aggregate-fixed-class-sandwich"
        }
        ("compile", AggregatePlanKind::LiteralClassRunLiteral, _) => {
            "compile-aggregate-literal-class-run-literal-v1"
        }
        ("compile", AggregatePlanKind::GraphemeScalarDfa, _) => {
            "compile-aggregate-grapheme-scalar-dfa"
        }
        ("compile", AggregatePlanKind::BoundedClassSequence, _) => {
            "compile-aggregate-bounded-class-sequence"
        }
        ("compile", AggregatePlanKind::BoundedSeparatedFields, _) => {
            "compile-aggregate-bounded-separated-fields"
        }
        ("compile", AggregatePlanKind::PrefixClassAlternation, _) => {
            "compile-aggregate-prefix-class-alternation"
        }
        ("compile", AggregatePlanKind::BoundedContext, _) => "compile-aggregate-bounded-context",
        ("compile", AggregatePlanKind::FixedAbsoluteDomain, _) => {
            "compile-aggregate-fixed-absolute-domain"
        }
        ("compile", AggregatePlanKind::BoundedLiteralPair, _) => {
            "compile-aggregate-bounded-literal-pair-v1"
        }
        ("compile", AggregatePlanKind::FiniteLiteralDfa, true) => {
            "compile-aggregate-finite-literal-sparse"
        }
        ("compile", AggregatePlanKind::FiniteLiteralDfa, false) => {
            "compile-aggregate-finite-literal-dfa"
        }
        ("compile", AggregatePlanKind::PackedFiniteLiteral, _) => {
            "compile-aggregate-finite-literal-packed-v2"
        }
        ("compile", AggregatePlanKind::GuardedAsciiWordDictionary, _) => {
            "compile-aggregate-guarded-ascii-word"
        }
        ("compile", AggregatePlanKind::FixedPredicateWord64, _) => {
            "compile-aggregate-fixed-predicate-word64"
        }
        ("compile", AggregatePlanKind::ContinuationProgram, _) => {
            "compile-aggregate-continuation-program"
        }
        (_, AggregatePlanKind::ExactLiteral, _) => "aggregate-exact-literal",
        (_, AggregatePlanKind::UnicodeScalarClass, _) => "aggregate-unicode-scalar-class",
        (_, AggregatePlanKind::WordRun, _) => "aggregate-word-run-v1",
        (_, AggregatePlanKind::LiteralAssertions, _) => "aggregate-literal-assertions-v1",
        (_, AggregatePlanKind::BlockingDelimiter, _) => "aggregate-blocking-delimiter-v1",
        (_, AggregatePlanKind::TokenPhrase, _) => "aggregate-token-phrase-v1",
        (_, AggregatePlanKind::FixedClassSandwich, _) => "aggregate-fixed-class-sandwich",
        (_, AggregatePlanKind::LiteralClassRunLiteral, _) => {
            "aggregate-literal-class-run-literal-v1"
        }
        (_, AggregatePlanKind::GraphemeScalarDfa, _) => "aggregate-grapheme-scalar-dfa",
        (_, AggregatePlanKind::BoundedClassSequence, _) => "aggregate-bounded-class-sequence",
        (_, AggregatePlanKind::BoundedSeparatedFields, _) => "aggregate-bounded-separated-fields",
        (_, AggregatePlanKind::PrefixClassAlternation, _) => "aggregate-prefix-class-alternation",
        (_, AggregatePlanKind::BoundedContext, _) => "aggregate-bounded-context",
        (_, AggregatePlanKind::FixedAbsoluteDomain, _) => "aggregate-fixed-absolute-domain",
        (_, AggregatePlanKind::BoundedLiteralPair, _) => "aggregate-bounded-literal-pair-v1",
        (_, AggregatePlanKind::FiniteLiteralDfa, true) => "aggregate-finite-literal-sparse",
        (_, AggregatePlanKind::FiniteLiteralDfa, false) => "aggregate-finite-literal-dfa",
        (_, AggregatePlanKind::PackedFiniteLiteral, _) => "aggregate-finite-literal-packed-v2",
        (_, AggregatePlanKind::GuardedAsciiWordDictionary, _) => "aggregate-guarded-ascii-word",
        (_, AggregatePlanKind::FixedPredicateWord64, _) => "aggregate-fixed-predicate-word64",
        (_, AggregatePlanKind::ContinuationProgram, _) => "aggregate-continuation-program",
    }
}

fn aggregate_many_plan_label(model: &str, plan: AggregateManyPlanKind) -> &'static str {
    match (model, plan) {
        ("compile", AggregateManyPlanKind::OrderedLiteral) => "compile-many-ordered-literal",
        ("compile", AggregateManyPlanKind::ContinuationProgram) => {
            "compile-many-continuation-program"
        }
        (_, AggregateManyPlanKind::OrderedLiteral) => "aggregate-many-ordered-literal",
        (_, AggregateManyPlanKind::ContinuationProgram) => "aggregate-many-continuation-program",
    }
}

/// Construct the exact portable-search builder used by the authenticated
/// current-FRE Rebar adapter.
///
/// # Errors
///
/// Returns an error for the case-insensitive inputs the semantic adapter
/// currently refuses rather than silently widening timing coverage.
pub fn current_fre_rebar_portable_builder(
    pattern: impl Into<String>,
    unicode: bool,
    case_insensitive: bool,
) -> Result<PortableBuilder, CompareError> {
    if case_insensitive {
        return Err(CompareError::new(
            "current FRE facade has no case-insensitive builder option",
        ));
    }
    Ok(PortableBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentFreCaptureModel {
    CountCaptures,
    GrepCaptures,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the caller-owned session stays inline so its exact construction allocation remains receipted"
)]
enum CurrentFreCapturePreparation {
    Count(Box<CaptureRunLimits>),
    Grep,
    Stream(CaptureStreamSession),
    RuffGrep(Box<LineCaptureRunLimits>),
    AnchoredLineGrep(Box<AnchoredLineCaptureRunLimits>),
}

#[derive(Clone, Debug)]
enum CurrentFreCaptureRegex {
    General(Box<CaptureRegex>),
    Noqa(Box<NoqaGrepCaptureRegex>),
    Ruff(Box<LineCapturePlan>),
    AnchoredLine(Box<AnchoredLineCapturePlan>),
}

impl CurrentFreCaptureModel {
    fn parse(model: &str) -> Result<Self, CompareError> {
        match model {
            "count-captures" => Ok(Self::CountCaptures),
            "grep-captures" => Ok(Self::GrepCaptures),
            other => Err(CompareError::new(format!(
                "unexpected capture lifecycle model {other}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::CountCaptures => "count-captures",
            Self::GrepCaptures => "grep-captures",
        }
    }
}

/// One already-built capture artifact at the public operation lifecycle
/// boundary used by the authenticated current-FRE Rebar adapter.
///
/// The first call to [`Self::execute`] is the contracted first-operation
/// boundary. Later calls on the same value are steady-operation boundaries.
/// Construction and input loading are outside both boundaries.
#[derive(Debug)]
pub struct CurrentFreCaptureLifecycle {
    model: CurrentFreCaptureModel,
    regex: CurrentFreCaptureRegex,
    limits: RunLimits,
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
    preparation: CurrentFreCapturePreparation,
}

impl CurrentFreCaptureLifecycle {
    /// Exact Rebar model bound into this lifecycle producer.
    #[must_use]
    pub const fn model(&self) -> &'static str {
        self.model.as_str()
    }

    /// Stable authenticated plan label expected by the timing runner.
    #[must_use]
    pub fn plan(&self) -> &'static str {
        if let CurrentFreCapturePreparation::Stream(session) = &self.preparation {
            return match session.operation_prospective().construction.projection {
                CaptureStreamProjection::ParticipationMask => {
                    CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN
                }
                CaptureStreamProjection::PersistentHistory => {
                    CURRENT_FRE_CAPTURE_STREAM_HISTORY_PLAN
                }
            };
        }
        match &self.regex {
            CurrentFreCaptureRegex::General(regex) => match self.model {
                CurrentFreCaptureModel::CountCaptures => capture_plan_label(regex),
                CurrentFreCaptureModel::GrepCaptures => capture_grep_plan_label(regex),
            },
            CurrentFreCaptureRegex::Noqa(regex) => regex.build_report().plan_identity.plan_id,
            CurrentFreCaptureRegex::Ruff(plan) => {
                plan.build_report().identity.operation.operation_id
            }
            CurrentFreCaptureRegex::AnchoredLine(plan) => {
                plan.build_report().identity.kernel.operation_id
            }
        }
    }

    /// Exact Rust-regex Unicode option bound at construction.
    #[must_use]
    pub const fn unicode(&self) -> bool {
        self.unicode
    }

    /// Exact Rust-regex case-insensitive option bound at construction.
    #[must_use]
    pub const fn case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Execute one complete public model operation on the retained artifact.
    ///
    /// # Errors
    ///
    /// Returns an error if checked reducer limits or the capture engine refuse
    /// the operation, or if the input length differs from the authenticated
    /// preparation. No alternate implementation is selected.
    pub fn execute(&mut self, haystack: &[u8]) -> Result<u64, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "capture lifecycle haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let result = match (&self.regex, &mut self.preparation) {
            (
                CurrentFreCaptureRegex::General(regex),
                CurrentFreCapturePreparation::Count(run_limits),
            ) => execute_count_captures_with_limits(regex, haystack, run_limits),
            (CurrentFreCaptureRegex::General(regex), CurrentFreCapturePreparation::Grep) => {
                execute_grep_captures(regex, haystack, &self.limits)
            }
            (CurrentFreCaptureRegex::General(_), CurrentFreCapturePreparation::Stream(session)) => {
                session
                    .execute(haystack)
                    .map_err(|error| {
                        ExecutionError::fault(format!(
                            "FRE prepared capture-stream session refused execution: {error}"
                        ))
                    })
                    .and_then(|result| {
                        u64::try_from(result.accounting.count).map_err(|_| {
                            ExecutionError::fault("FRE stream capture count does not fit u64")
                        })
                    })
            }
            (CurrentFreCaptureRegex::Noqa(regex), CurrentFreCapturePreparation::Grep) => {
                execute_noqa_grep_captures(regex, haystack, &self.limits)
            }
            (
                CurrentFreCaptureRegex::Ruff(plan),
                CurrentFreCapturePreparation::RuffGrep(run_limits),
            ) => execute_ruff_line_capture_with_limits(plan, haystack, **run_limits),
            (
                CurrentFreCaptureRegex::AnchoredLine(plan),
                CurrentFreCapturePreparation::AnchoredLineGrep(run_limits),
            ) => execute_anchored_line_capture_with_limits(plan, haystack, **run_limits),
            (CurrentFreCaptureRegex::Noqa(_), CurrentFreCapturePreparation::Count(_)) => {
                return Err(CompareError::new(
                    "noqa grep-only artifact reached count-captures lifecycle",
                ));
            }
            (CurrentFreCaptureRegex::Ruff(_), _) => {
                return Err(CompareError::new(
                    "Ruff grep-only artifact reached an incompatible capture lifecycle",
                ));
            }
            (CurrentFreCaptureRegex::AnchoredLine(_), _) => {
                return Err(CompareError::new(
                    "anchored-line grep-only artifact reached an incompatible capture lifecycle",
                ));
            }
            (_, CurrentFreCapturePreparation::RuffGrep(_)) => {
                return Err(CompareError::new(
                    "Ruff grep preparation reached an incompatible capture artifact",
                ));
            }
            (_, CurrentFreCapturePreparation::AnchoredLineGrep(_)) => {
                return Err(CompareError::new(
                    "anchored-line grep preparation reached an incompatible capture artifact",
                ));
            }
            (_, CurrentFreCapturePreparation::Stream(_)) => {
                return Err(CompareError::new(
                    "prepared capture stream reached an incompatible capture artifact",
                ));
            }
        };
        result.map_err(|error| CompareError::new(error.message))
    }
}

/// Construct the exact capture lifecycle producer used by the authenticated
/// current-FRE Rebar adapter.
///
/// # Errors
///
/// `haystack_len` binds checked operation limits before the lifecycle boundary.
/// Returns an error for a non-capture model, unsupported syntax/profile, or an
/// unexpected capture plan identity. It never substitutes another engine.
pub fn current_fre_rebar_capture_lifecycle(
    model: &str,
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
) -> Result<CurrentFreCaptureLifecycle, CompareError> {
    current_fre_rebar_capture_lifecycle_with_limits(
        model,
        pattern,
        unicode,
        case_insensitive,
        haystack_len,
        RunLimits::default(),
    )
}

fn current_fre_rebar_capture_lifecycle_with_limits(
    model: &str,
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
    limits: RunLimits,
) -> Result<CurrentFreCaptureLifecycle, CompareError> {
    let model = CurrentFreCaptureModel::parse(model)?;
    let (regex, preparation) = match model {
        CurrentFreCaptureModel::CountCaptures => {
            let regex = capture_regex_one(pattern, unicode, case_insensitive, &limits)
                .map_err(|error| CompareError::new(error.message))?;
            let run_limits = capture_count_run_limits(&regex, haystack_len, &limits)
                .map_err(|error| CompareError::new(error.message))?;
            (
                CurrentFreCaptureRegex::General(Box::new(regex)),
                CurrentFreCapturePreparation::Count(Box::new(run_limits)),
            )
        }
        CurrentFreCaptureModel::GrepCaptures => {
            let (regex, preparation) = if let Some(regex) =
                noqa_grep_capture_regex_one(pattern, unicode, case_insensitive, &limits)
                    .map_err(|error| CompareError::new(error.message))?
            {
                (
                    CurrentFreCaptureRegex::Noqa(Box::new(regex)),
                    CurrentFreCapturePreparation::Grep,
                )
            } else if let Some(plan) =
                ruff_line_capture_plan_one(pattern, unicode, case_insensitive, &limits)
                    .map_err(|error| CompareError::new(error.message))?
            {
                let run_limits = ruff_line_capture_run_limits(&plan, haystack_len, &limits)
                    .map_err(|error| CompareError::new(error.message))?;
                (
                    CurrentFreCaptureRegex::Ruff(Box::new(plan)),
                    CurrentFreCapturePreparation::RuffGrep(Box::new(run_limits)),
                )
            } else if let Some(plan) =
                anchored_line_capture_plan_one(pattern, unicode, case_insensitive, &limits)
                    .map_err(|error| CompareError::new(error.message))?
            {
                let run_limits = anchored_line_capture_run_limits(&plan, haystack_len, &limits)
                    .map_err(|error| CompareError::new(error.message))?;
                (
                    CurrentFreCaptureRegex::AnchoredLine(Box::new(plan)),
                    CurrentFreCapturePreparation::AnchoredLineGrep(Box::new(run_limits)),
                )
            } else {
                let general = capture_grep_regex_one(pattern, unicode, case_insensitive, &limits)
                    .map_err(|error| CompareError::new(error.message))?;
                let preparation = if active_capture_required_literal_plan(&general).is_some() {
                    // The certified required-literal route remains its own
                    // generic lifecycle. A reusable stream is only selected
                    // where it is the authenticated public operation route.
                    CurrentFreCapturePreparation::Grep
                } else {
                    let run_limits = capture_count_run_limits(&general, haystack_len, &limits)
                        .map_err(|error| CompareError::new(error.message))?;
                    general
                        .prepare_capture_stream_session(
                            haystack_len,
                            run_limits,
                            CaptureStreamDomains::RebarLines,
                        )
                        .map_err(|error| {
                            CompareError::new(format!(
                                "FRE capture-stream session preflight refused construction: {error}"
                            ))
                        })?
                        .map_or(
                            CurrentFreCapturePreparation::Grep,
                            CurrentFreCapturePreparation::Stream,
                        )
                };
                (
                    CurrentFreCaptureRegex::General(Box::new(general)),
                    preparation,
                )
            };
            (regex, preparation)
        }
    };
    Ok(CurrentFreCaptureLifecycle {
        model,
        regex,
        limits,
        unicode,
        case_insensitive,
        haystack_len,
        preparation,
    })
}

/// Derive whole-operation limits for a report-authenticated aggregate plan.
/// Every Unicode-scalar, prefix/class, literal/class-run/literal, bounded-
/// context, and fixed absolute-domain plan requires the retained artifact.
/// The copied report intentionally cannot distinguish scalar from private
/// dispatched owners, so callers for any of those families must use
/// [`current_fre_rebar_compile_run_limits`],
/// [`current_fre_rebar_count_run_limits`] or
/// [`current_fre_rebar_span_sum_run_limits`] instead.
///
/// # Errors
///
/// Returns an authentication/resource error if a bound cannot be represented.
pub fn current_fre_rebar_aggregate_run_limits(
    haystack_len: usize,
    report: &AggregateBuildReport,
) -> Result<AggregateRunLimits, CompareError> {
    aggregate_run_limits(haystack_len, report, &RunLimits::default())
        .map_err(|error| CompareError::new(error.message))
}

fn compile_run_limits_with_policy(
    haystack_len: usize,
    regex: &AggregateCompileRegex,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    let retained_upper_bounds = regex
        .retained_full_window_upper_bounds(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE compile retained-owner preflight: {error}"))
        })?;
    let fixed_absolute_prospective = regex
        .fixed_absolute_domain_full_window_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE compile fixed-domain preflight: {error}"))
        })?;
    let fixed_absolute_composite = regex
        .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!(
                "FRE compile fixed-domain composite preflight: {error}"
            ))
        })?;
    aggregate_run_limits_with_fixed_absolute(
        haystack_len,
        regex.build_report(),
        retained_upper_bounds,
        fixed_absolute_prospective,
        fixed_absolute_composite,
        limits,
    )
}

fn count_run_limits_with_policy(
    haystack_len: usize,
    regex: &AggregateCountRegex,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    let retained_upper_bounds = regex
        .retained_full_window_upper_bounds(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE count retained-owner preflight: {error}"))
        })?;
    let fixed_absolute_prospective = regex
        .fixed_absolute_domain_full_window_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE count fixed-domain preflight: {error}"))
        })?;
    let fixed_absolute_composite = regex
        .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!(
                "FRE count fixed-domain composite preflight: {error}"
            ))
        })?;
    aggregate_run_limits_with_fixed_absolute(
        haystack_len,
        regex.build_report(),
        retained_upper_bounds,
        fixed_absolute_prospective,
        fixed_absolute_composite,
        limits,
    )
}

fn span_sum_run_limits_with_policy(
    haystack_len: usize,
    regex: &AggregateSpanSumRegex,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    let retained_upper_bounds = regex
        .retained_full_window_upper_bounds(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE span-sum retained-owner preflight: {error}"))
        })?;
    let fixed_absolute_prospective = regex
        .fixed_absolute_domain_full_window_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!("FRE span-sum fixed-domain preflight: {error}"))
        })?;
    let fixed_absolute_composite = regex
        .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!(
                "FRE span-sum fixed-domain composite preflight: {error}"
            ))
        })?;
    aggregate_run_limits_with_fixed_absolute(
        haystack_len,
        regex.build_report(),
        retained_upper_bounds,
        fixed_absolute_prospective,
        fixed_absolute_composite,
        limits,
    )
}

/// Derive exact verification limits from one retained compile artifact.
///
/// # Errors
///
/// Returns an authentication/resource error if the artifact cannot publish
/// its source-free full-window envelopes.
pub fn current_fre_rebar_compile_run_limits(
    haystack_len: usize,
    regex: &AggregateCompileRegex,
) -> Result<AggregateRunLimits, CompareError> {
    compile_run_limits_with_policy(haystack_len, regex, &RunLimits::default())
        .map_err(|error| CompareError::new(error.message))
}

/// Derive exact operation limits from one retained count artifact, including
/// its private fixed absolute-domain seal when that generic route is selected.
///
/// # Errors
///
/// Returns an authentication/resource error if the artifact cannot publish an
/// exact source-free full-window prospective envelope.
pub fn current_fre_rebar_count_run_limits(
    haystack_len: usize,
    regex: &AggregateCountRegex,
) -> Result<AggregateRunLimits, CompareError> {
    count_run_limits_with_policy(haystack_len, regex, &RunLimits::default())
        .map_err(|error| CompareError::new(error.message))
}

/// Derive exact operation limits from one retained span-sum artifact,
/// including its private fixed absolute-domain seal when selected.
///
/// # Errors
///
/// Returns an authentication/resource error if the artifact cannot publish an
/// exact source-free full-window prospective envelope.
pub fn current_fre_rebar_span_sum_run_limits(
    haystack_len: usize,
    regex: &AggregateSpanSumRegex,
) -> Result<AggregateRunLimits, CompareError> {
    span_sum_run_limits_with_policy(haystack_len, regex, &RunLimits::default())
        .map_err(|error| CompareError::new(error.message))
}

/// Derive the exact whole-operation limits used by the authenticated
/// current-FRE Rebar adapter for one already-published multi-pattern plan.
///
/// # Errors
///
/// Returns an authentication/resource error if a bound cannot be represented.
pub fn current_fre_rebar_aggregate_many_run_limits(
    haystack_len: usize,
    report: &AggregateManyBuildReport,
) -> Result<AggregateManyRunLimits, CompareError> {
    aggregate_many_run_limits(haystack_len, report, &RunLimits::default())
        .map_err(|error| CompareError::new(error.message))
}

/// Check the aggregate semantic identity required by the authenticated adapter
/// for one operation model.
///
/// # Errors
///
/// Returns an identity error for an unexpected model or semantic certificate.
pub fn current_fre_rebar_validate_aggregate_identity(
    report: &AggregateBuildReport,
    unicode: bool,
    model: &str,
) -> Result<(), CompareError> {
    let (facade_operation, literal_operation) = match model {
        "compile" => (
            AggregateOperation::Compile,
            LiteralAggregateOperation::Count,
        ),
        "count" => (AggregateOperation::Count, LiteralAggregateOperation::Count),
        "count-spans" => (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum,
        ),
        other => {
            return Err(CompareError::new(format!(
                "unexpected aggregate model {other}"
            )));
        }
    };
    if report.operation != facade_operation {
        return Err(CompareError::new(format!(
            "aggregate operation identity mismatch for {model}: expected {facade_operation:?}, got {:?}",
            report.operation
        )));
    }
    require_unicode_plan_identity(report, unicode, literal_operation)
        .map_err(|error| CompareError::new(error.message))
}

/// Check the ordered multi-pattern semantic identity required by the
/// authenticated adapter for one operation model.
///
/// # Errors
///
/// Returns an identity error for an unexpected model, profile, source order,
/// operation, or selected-plan semantic certificate.
pub fn current_fre_rebar_validate_aggregate_many_identity(
    patterns: &[String],
    report: &AggregateManyBuildReport,
    unicode: bool,
    case_insensitive: bool,
    model: &str,
) -> Result<(), CompareError> {
    let operation = match model {
        "compile" => AggregateManyOperation::Compile,
        "count" => AggregateManyOperation::Count,
        "count-captures" => AggregateManyOperation::CaptureCount,
        "count-spans" => AggregateManyOperation::SpanSum,
        other => {
            return Err(CompareError::new(format!(
                "unexpected aggregate-many model {other}"
            )));
        }
    };
    require_aggregate_many_report_identity(patterns, unicode, case_insensitive, report, operation)
        .map_err(|error| CompareError::new(error.message))
}

#[derive(Clone, Copy)]
enum LiteralAggregateTimingBoundary {
    FullReport,
    ValueOnly,
}

impl LiteralAggregateTimingBoundary {
    const fn schema(self) -> &'static str {
        match self {
            Self::FullReport => LITERAL_AGGREGATE_TIMING_SCHEMA,
            Self::ValueOnly => LITERAL_AGGREGATE_VALUE_TIMING_SCHEMA,
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::FullReport => {
                "compile/authentication/limit-derivation excluded; each operation call includes the full public FRE result+execution-report construction and drop (including Arc<CacheKey> refcount traffic), versus the pinned Rust meta iterator plus exact Rebar reducer; alternating engine order"
            }
            Self::ValueOnly => {
                "compile/authentication/limit-derivation excluded; each operation call uses the public FRE value-only API with identical selected-plan preflight but no successful execution-report/cache-identity/Arc<CacheKey> clone, versus the pinned Rust meta iterator plus exact Rebar reducer; alternating engine order"
            }
        }
    }
}

/// Measure the full-report FRE aggregate facade and pinned Rust reducer on
/// every passing `aggregate-exact-literal` semantic receipt.
///
/// # Errors
///
/// Returns an error for failed authentication, receipt-set disagreement,
/// semantic mismatch, or operation refusal.
pub fn time_literal_aggregate_receipts(
    config: &RunConfig,
    semantic_report: &Report,
    samples_per_engine: usize,
    target_bytes_per_sample: usize,
    max_iterations_per_sample: usize,
) -> Result<LiteralAggregateTimingReport, CompareError> {
    time_literal_aggregate_receipts_with_boundary(
        config,
        semantic_report,
        samples_per_engine,
        target_bytes_per_sample,
        max_iterations_per_sample,
        LiteralAggregateTimingBoundary::FullReport,
    )
}

/// Measure the value-only FRE aggregate facade and pinned Rust reducer on
/// every passing `aggregate-exact-literal` semantic receipt.
///
/// # Errors
///
/// Returns an error for failed authentication, receipt-set disagreement,
/// semantic mismatch, or operation refusal.
pub fn time_literal_aggregate_value_receipts(
    config: &RunConfig,
    semantic_report: &Report,
    samples_per_engine: usize,
    target_bytes_per_sample: usize,
    max_iterations_per_sample: usize,
) -> Result<LiteralAggregateTimingReport, CompareError> {
    time_literal_aggregate_receipts_with_boundary(
        config,
        semantic_report,
        samples_per_engine,
        target_bytes_per_sample,
        max_iterations_per_sample,
        LiteralAggregateTimingBoundary::ValueOnly,
    )
}

/// Authenticate and execute only the five projected Unicode exact-literal
/// Rebar jobs against both pinned Rust and the current FRE facade.
///
/// This is an affected-family checkpoint, not a replacement for canonical
/// full-report regeneration. It fails closed instead of retaining a non-pass
/// receipt: every selected input, expected reducer, and exact-plan identity
/// must agree before an artifact can be returned.
///
/// # Errors
///
/// Returns an error for manifest/authentication disagreement, a missing or
/// malformed sentinel job, any semantic/resource refusal, or any plan other
/// than the Unicode exact-literal candidate.
#[allow(
    clippy::too_many_lines,
    reason = "the closed frontier proof keeps authentication, projection, and exact-set rejection auditable together"
)]
pub fn run_unicode_literal_sentinel(
    config: &RunConfig,
    baseline_report_path: &Path,
) -> Result<UnicodeLiteralSentinelReport, CompareError> {
    let baseline = read_authenticated_report(baseline_report_path)?;
    if baseline.schema != REPORT_SCHEMA {
        return Err(CompareError::new(format!(
            "Unicode literal sentinel requires {REPORT_SCHEMA}, got {}",
            baseline.schema
        )));
    }
    let baseline_receipt_bytes = serde_json::to_vec(&baseline.receipts)
        .map_err(|error| CompareError::new(format!("serialize baseline receipts: {error}")))?;
    let baseline_receipt_hash = sha256(&baseline_receipt_bytes);
    if baseline_receipt_hash != baseline.receipts_sha256 {
        return Err(CompareError::new(format!(
            "Unicode literal sentinel baseline receipt digest {baseline_receipt_hash} differs from embedded {}",
            baseline.receipts_sha256
        )));
    }
    let baseline_bytes = report_bytes(&baseline)?;
    let baseline_report_hash = sha256(&baseline_bytes);
    let manifest_bytes = read_limited(&config.manifest, 64 * 1_048_576)?;
    let manifest_hash = sha256(&manifest_bytes);
    verify_sidecar_hash(&config.manifest, &manifest_hash)?;
    if baseline.manifest_sha256 != manifest_hash {
        return Err(CompareError::new(
            "Unicode literal sentinel baseline report does not authenticate this manifest",
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| CompareError::new(format!("decode manifest: {error}")))?;
    validate_manifest(&manifest, &config.checkout, &config.limits)?;
    if baseline.rebar_revision != manifest.source.revision {
        return Err(CompareError::new(
            "Unicode literal sentinel report and manifest Rebar revisions differ",
        ));
    }
    let manifest_root = config
        .manifest
        .parent()
        .ok_or_else(|| CompareError::new("manifest has no parent directory"))?;
    let mut loader = Loader::new(manifest_root, &config.checkout, &config.limits);
    let candidate = CurrentFreAdapter;

    let expected_new: BTreeSet<&str> = UNICODE_LITERAL_SENTINEL_JOB_IDS.into_iter().collect();
    let mut frontier_remaining = BTreeSet::new();
    for receipt in &baseline.receipts {
        if receipt.adapter == LEGACY_FRE_ADAPTER_V2
            && receipt.status == Status::Unsupported
            && receipt.input.unicode
            && matches!(receipt.model.as_str(), "count" | "count-spans")
            && !frontier_remaining.insert(receipt.job_id.clone())
        {
            return Err(CompareError::new(format!(
                "duplicate Unicode aggregate frontier receipt {}",
                receipt.job_id
            )));
        }
    }
    for expected in expected_new.iter().copied() {
        if !frontier_remaining.contains(expected) {
            return Err(CompareError::new(format!(
                "projected Unicode literal job {expected} is not in the authenticated old unsupported frontier"
            )));
        }
    }
    let frontier_jobs = frontier_remaining.len();
    let mut frontier_receipts = Vec::new();
    frontier_receipts
        .try_reserve_exact(frontier_jobs)
        .map_err(|error| CompareError::new(format!("reserve frontier receipts: {error}")))?;
    let mut newly_executable = BTreeSet::new();
    for job in &manifest.jobs {
        if !frontier_remaining.remove(&job.id) {
            continue;
        }
        let input_result = loader.load(job);
        let projected = execute_receipt(
            job,
            candidate.adapter(),
            &input_result,
            &config.limits,
            |input| candidate_reducer(&candidate, job, input, &config.limits),
        );
        if expected_new.contains(job.id.as_str()) {
            if projected.status != Status::Pass
                || projected.candidate_plan.as_deref() != Some("aggregate-exact-literal")
            {
                return Err(CompareError::new(format!(
                    "projected Unicode literal frontier job {} is {:?} with plan {:?}: {}",
                    job.id,
                    projected.status,
                    projected.candidate_plan,
                    projected.reason.as_deref().unwrap_or("no diagnostic")
                )));
            }
            newly_executable.insert(job.id.clone());
        } else if projected.status != Status::Unsupported {
            return Err(CompareError::new(format!(
                "Unicode frontier audit event: non-projected job {} became {:?} with plan {:?}: {}",
                job.id,
                projected.status,
                projected.candidate_plan,
                projected.reason.as_deref().unwrap_or("no diagnostic")
            )));
        }
        frontier_receipts.push(projected);
    }
    if let Some(missing) = frontier_remaining.first() {
        return Err(CompareError::new(format!(
            "Unicode aggregate frontier job {missing} is absent from the manifest"
        )));
    }
    let new_job_ids: Vec<_> = newly_executable.into_iter().collect();
    let expected_job_ids: Vec<_> = UNICODE_LITERAL_SENTINEL_JOB_IDS
        .into_iter()
        .map(str::to_string)
        .collect();
    if new_job_ids != expected_job_ids {
        return Err(CompareError::new(format!(
            "Unicode newly executable set {new_job_ids:?} differs from projected {expected_job_ids:?}"
        )));
    }
    frontier_receipts.sort_by(|left, right| left.job_id.cmp(&right.job_id));
    let mut retained_reason_pins = Vec::new();
    let mut retained_receipts = Vec::new();
    retained_reason_pins
        .try_reserve_exact(UNICODE_LITERAL_RETAINED_UNSUPPORTED_JOBS)
        .map_err(|error| CompareError::new(format!("reserve retained reason pins: {error}")))?;
    retained_receipts
        .try_reserve_exact(UNICODE_LITERAL_RETAINED_UNSUPPORTED_JOBS)
        .map_err(|error| CompareError::new(format!("reserve retained receipts: {error}")))?;
    for receipt in &frontier_receipts {
        if receipt.status != Status::Unsupported {
            continue;
        }
        let reason = receipt.reason.as_deref().ok_or_else(|| {
            CompareError::new(format!(
                "retained Unsupported frontier receipt {} has no exact reason",
                receipt.job_id
            ))
        })?;
        retained_reason_pins.push(UnicodeUnsupportedReasonPin {
            job_id: &receipt.job_id,
            reason,
        });
        retained_receipts.push(receipt);
    }
    if retained_reason_pins.len() != UNICODE_LITERAL_RETAINED_UNSUPPORTED_JOBS {
        return Err(CompareError::new(format!(
            "Unicode frontier retained {} Unsupported receipts, expected {UNICODE_LITERAL_RETAINED_UNSUPPORTED_JOBS}",
            retained_reason_pins.len()
        )));
    }
    let retained_reason_bytes = serde_json::to_vec(&retained_reason_pins)
        .map_err(|error| CompareError::new(format!("serialize retained reason pins: {error}")))?;
    let retained_reason_hash = sha256(&retained_reason_bytes);
    if retained_reason_hash != UNICODE_LITERAL_RETAINED_UNSUPPORTED_REASONS_SHA256 {
        return Err(CompareError::new(format!(
            "Unicode frontier exact refusal-reason digest {retained_reason_hash} differs from pinned {UNICODE_LITERAL_RETAINED_UNSUPPORTED_REASONS_SHA256}"
        )));
    }
    let legacy_retained_receipts: Vec<_> = retained_receipts
        .iter()
        .map(|receipt| {
            let mut legacy = (*receipt).clone();
            legacy.adapter = LEGACY_FRE_ADAPTER_V2.to_string();
            legacy
        })
        .collect();
    let retained_receipt_bytes = serde_json::to_vec(&legacy_retained_receipts)
        .map_err(|error| CompareError::new(format!("serialize retained receipts: {error}")))?;
    let retained_receipt_hash = sha256(&retained_receipt_bytes);
    if retained_receipt_hash != UNICODE_LITERAL_RETAINED_UNSUPPORTED_RECEIPTS_SHA256 {
        return Err(CompareError::new(format!(
            "Unicode frontier retained receipt digest {retained_receipt_hash} differs from pinned {UNICODE_LITERAL_RETAINED_UNSUPPORTED_RECEIPTS_SHA256}"
        )));
    }
    let retained_unsupported_jobs = retained_reason_pins.len();
    drop(retained_reason_pins);
    drop(retained_receipts);
    let frontier_receipt_bytes = serde_json::to_vec(&frontier_receipts)
        .map_err(|error| CompareError::new(format!("serialize frontier receipts: {error}")))?;

    let mut remaining: BTreeSet<&str> = UNICODE_LITERAL_SENTINEL_JOB_IDS.into_iter().collect();
    let mut receipts = Vec::new();
    let closed_receipt_count = UNICODE_LITERAL_SENTINEL_JOB_IDS
        .len()
        .checked_mul(2)
        .ok_or_else(|| CompareError::new("sentinel receipt count overflow"))?;
    receipts
        .try_reserve_exact(closed_receipt_count)
        .map_err(|error| CompareError::new(format!("reserve sentinel receipts: {error}")))?;

    for job in &manifest.jobs {
        if !remaining.remove(job.id.as_str()) {
            continue;
        }
        if job.engine != "rust/regex"
            || !matches!(job.model.as_str(), "count" | "count-spans")
            || !job.regex.unicode
            || job.regex.case_insensitive
            || job.regex.patterns.len() != 1
        {
            return Err(CompareError::new(format!(
                "Unicode literal sentinel job {} has an unexpected engine/model/profile/pattern count",
                job.id
            )));
        }
        let input_result = loader.load(job);
        let rust = execute_receipt(job, RUST_ADAPTER, &input_result, &config.limits, |input| {
            rust_reducer(job, input, &config.limits).map(AdapterReduction::unplanned)
        });
        if rust.status != Status::Pass {
            return Err(CompareError::new(format!(
                "Unicode literal sentinel pinned Rust receipt {} is {:?}: {}",
                job.id,
                rust.status,
                rust.reason.as_deref().unwrap_or("no diagnostic")
            )));
        }
        let fre = execute_receipt(
            job,
            candidate.adapter(),
            &input_result,
            &config.limits,
            |input| candidate_reducer(&candidate, job, input, &config.limits),
        );
        if fre.status != Status::Pass
            || fre.candidate_plan.as_deref() != Some("aggregate-exact-literal")
        {
            return Err(CompareError::new(format!(
                "Unicode literal sentinel FRE receipt {} is {:?} with plan {:?}: {}",
                job.id,
                fre.status,
                fre.candidate_plan,
                fre.reason.as_deref().unwrap_or("no diagnostic")
            )));
        }
        receipts.push(rust);
        receipts.push(fre);
    }
    if let Some(missing) = remaining.first() {
        return Err(CompareError::new(format!(
            "Unicode literal sentinel job {missing} is absent from the manifest"
        )));
    }
    if receipts.len() != closed_receipt_count {
        return Err(CompareError::new(
            "Unicode literal sentinel did not produce exactly two receipts per job",
        ));
    }
    receipts
        .sort_by(|left, right| (&left.job_id, &left.adapter).cmp(&(&right.job_id, &right.adapter)));
    let receipt_bytes = serde_json::to_vec(&receipts)
        .map_err(|error| CompareError::new(format!("serialize sentinel receipts: {error}")))?;
    Ok(UnicodeLiteralSentinelReport {
        schema: UNICODE_LITERAL_SENTINEL_SCHEMA.to_string(),
        manifest_sha256: manifest_hash,
        baseline_report_sha256: baseline_report_hash,
        semantic_domain: UNICODE_LITERAL_SEMANTIC_DOMAIN.to_string(),
        semantic_domain_sha256: sha256(UNICODE_LITERAL_SEMANTIC_DOMAIN.as_bytes()),
        rebar_revision: manifest.source.revision,
        job_ids: expected_job_ids,
        frontier_jobs,
        newly_executable_job_ids: new_job_ids,
        retained_unsupported_jobs,
        retained_unsupported_reasons_sha256: retained_reason_hash,
        retained_unsupported_receipts_sha256: retained_receipt_hash,
        frontier_receipts_sha256: sha256(&frontier_receipt_bytes),
        frontier_receipts,
        receipts_sha256: sha256(&receipt_bytes),
        receipts,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "authentication, exact receipt-set proof, and timing-row construction remain auditable together"
)]
fn time_literal_aggregate_receipts_with_boundary(
    config: &RunConfig,
    semantic_report: &Report,
    samples_per_engine: usize,
    target_bytes_per_sample: usize,
    max_iterations_per_sample: usize,
    boundary: LiteralAggregateTimingBoundary,
) -> Result<LiteralAggregateTimingReport, CompareError> {
    if samples_per_engine == 0 || samples_per_engine.is_multiple_of(2) {
        return Err(CompareError::new(
            "literal timing samples must be a positive odd number",
        ));
    }
    if target_bytes_per_sample == 0 || max_iterations_per_sample == 0 {
        return Err(CompareError::new(
            "literal timing byte target and iteration cap must be nonzero",
        ));
    }
    if semantic_report.schema != REPORT_SCHEMA {
        return Err(CompareError::new(format!(
            "literal timing requires {REPORT_SCHEMA}, got {}",
            semantic_report.schema
        )));
    }
    let receipt_bytes = serde_json::to_vec(&semantic_report.receipts)
        .map_err(|error| CompareError::new(format!("serialize timing receipts: {error}")))?;
    let receipt_digest = sha256(&receipt_bytes);
    if receipt_digest != semantic_report.receipts_sha256 {
        return Err(CompareError::new(format!(
            "semantic report receipt digest {receipt_digest} differs from embedded {}",
            semantic_report.receipts_sha256
        )));
    }
    let manifest_bytes = read_limited(&config.manifest, 64 * 1_048_576)?;
    let manifest_hash = sha256(&manifest_bytes);
    verify_sidecar_hash(&config.manifest, &manifest_hash)?;
    if semantic_report.manifest_sha256 != manifest_hash {
        return Err(CompareError::new(
            "literal timing semantic report does not authenticate this manifest",
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| CompareError::new(format!("decode manifest: {error}")))?;
    validate_manifest(&manifest, &config.checkout, &config.limits)?;
    if semantic_report.rebar_revision != manifest.source.revision {
        return Err(CompareError::new(
            "literal timing report and manifest Rebar revisions differ",
        ));
    }

    let mut selected = BTreeSet::new();
    for receipt in &semantic_report.receipts {
        if receipt.adapter == FRE_ADAPTER
            && receipt.candidate_plan.as_deref() == Some("aggregate-exact-literal")
        {
            if receipt.status != Status::Pass || receipt.actual != Some(receipt.expected) {
                return Err(CompareError::new(format!(
                    "exact-plan timing receipt {} is not a semantic pass",
                    receipt.job_id
                )));
            }
            if !selected.insert(receipt.job_id.clone()) {
                return Err(CompareError::new(format!(
                    "duplicate exact-plan timing receipt {}",
                    receipt.job_id
                )));
            }
        }
    }
    if selected.is_empty() {
        return Err(CompareError::new(
            "semantic report contains no passing exact-literal aggregate receipts",
        ));
    }
    let selected_receipts = selected.len();

    let manifest_root = config
        .manifest
        .parent()
        .ok_or_else(|| CompareError::new("manifest has no parent directory"))?;
    let mut loader = Loader::new(manifest_root, &config.checkout, &config.limits);
    let mut jobs = Vec::new();
    jobs.try_reserve_exact(selected.len())
        .map_err(|error| CompareError::new(format!("reserve timing rows: {error}")))?;
    for job in &manifest.jobs {
        if !selected.remove(&job.id) {
            continue;
        }
        let input = loader.load(job)?;
        jobs.push(time_literal_aggregate_job(
            job,
            &input,
            &config.limits,
            samples_per_engine,
            target_bytes_per_sample,
            max_iterations_per_sample,
            boundary,
        )?);
    }
    if let Some(missing) = selected.first() {
        return Err(CompareError::new(format!(
            "exact-plan receipt {missing} is absent from the manifest"
        )));
    }
    if jobs.len() != selected_receipts {
        return Err(CompareError::new(format!(
            "loaded {} timing jobs for {selected_receipts} exact-plan receipts",
            jobs.len()
        )));
    }

    let semantic_bytes = report_bytes(semantic_report)?;
    Ok(LiteralAggregateTimingReport {
        schema: boundary.schema().to_string(),
        semantic_report_sha256: sha256(&semantic_bytes),
        manifest_sha256: manifest_hash,
        candidate_plan: "aggregate-exact-literal".to_string(),
        selected_receipts,
        timing_boundary: boundary.description().to_string(),
        samples_per_engine,
        target_bytes_per_sample,
        max_iterations_per_sample,
        host_os: std::env::consts::OS.to_string(),
        host_arch: std::env::consts::ARCH.to_string(),
        process_id: std::process::id(),
        jobs,
    })
}

/// Run the gate with an optional custom candidate adapter.
///
/// # Errors
///
/// Returns the same fatal authentication/construction errors as [`run`]. A
/// candidate's per-job problems are always retained as receipts.
pub fn run_with_candidate(
    config: &RunConfig,
    candidate: Option<&dyn CandidateAdapter>,
) -> Result<Report, CompareError> {
    let manifest_bytes = read_limited(&config.manifest, 64 * 1_048_576)?;
    let manifest_hash = sha256(&manifest_bytes);
    verify_sidecar_hash(&config.manifest, &manifest_hash)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| CompareError::new(format!("decode manifest: {error}")))?;
    validate_manifest(&manifest, &config.checkout, &config.limits)?;
    let manifest_root = config
        .manifest
        .parent()
        .ok_or_else(|| CompareError::new("manifest has no parent directory"))?;
    let adapters = adapter_identities(
        &manifest,
        config.rebar_rust_runner.as_deref(),
        config.rebar_re2_runner.as_deref(),
        candidate,
    )?;
    let mut loader = Loader::new(manifest_root, &config.checkout, &config.limits);
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(
            manifest
                .jobs
                .len()
                .checked_mul(2)
                .ok_or_else(|| CompareError::new("receipt capacity overflow"))?,
        )
        .map_err(|error| CompareError::new(format!("reserve receipts: {error}")))?;

    for job in &manifest.jobs {
        let input_result = loader.load(job);
        match job.engine.as_str() {
            "rust/regex" => {
                let baseline =
                    execute_receipt(job, RUST_ADAPTER, &input_result, &config.limits, |input| {
                        rust_reducer(job, input, &config.limits).map(AdapterReduction::unplanned)
                    });
                receipts.push(baseline);
                if let Some(candidate) = candidate {
                    receipts.push(execute_receipt(
                        job,
                        candidate.adapter(),
                        &input_result,
                        &config.limits,
                        |input| candidate_reducer(candidate, job, input, &config.limits),
                    ));
                }
            }
            "re2" => {
                if let Some(runner) = &config.rebar_re2_runner {
                    receipts.push(external_re2_receipt(job, &input_result, runner));
                } else {
                    receipts.push(unresolved_re2_receipt(job, &input_result));
                }
            }
            other => {
                return Err(CompareError::new(format!(
                    "manifest contains unexpected engine {other}"
                )));
            }
        }
    }
    receipts
        .sort_by(|left, right| (&left.job_id, &left.adapter).cmp(&(&right.job_id, &right.adapter)));
    let klv_differentials = if let Some(runner) = &config.rebar_rust_runner {
        run_klv_differentials(&manifest, &mut loader, runner, &config.limits, &receipts)?
    } else {
        Vec::new()
    };
    let coverage = coverage(&receipts)?;
    let receipt_bytes = serde_json::to_vec(&receipts)
        .map_err(|error| CompareError::new(format!("serialize receipts: {error}")))?;
    let receipts_sha256 = sha256(&receipt_bytes);
    Ok(Report {
        schema: REPORT_SCHEMA.to_string(),
        input_schema: manifest.schema,
        manifest_sha256: manifest_hash,
        rebar_revision: manifest.source.revision,
        adapters,
        coverage,
        receipts_sha256,
        receipts,
        klv_differentials,
    })
}

fn execute_receipt(
    job: &Job,
    adapter: &str,
    loaded: &Result<LoadedJob, CompareError>,
    _limits: &RunLimits,
    execute: impl FnOnce(&LoadedJob) -> Result<AdapterReduction, ExecutionError>,
) -> Receipt {
    match loaded {
        Err(error) => receipt(job, adapter, Status::Fault, None, Some(error.to_string())),
        Ok(input) => match execute(input) {
            Ok(reduction) if reduction.actual == job.expected.count => {
                let mut receipt = receipt(job, adapter, Status::Pass, Some(reduction.actual), None);
                receipt.candidate_plan = reduction.plan;
                receipt
            }
            Ok(reduction) => {
                let mut receipt = receipt(
                    job,
                    adapter,
                    Status::Fail,
                    Some(reduction.actual),
                    Some(format!(
                        "actual reducer {} differs from expected {}",
                        reduction.actual, job.expected.count
                    )),
                );
                receipt.candidate_plan = reduction.plan;
                receipt
            }
            Err(error) => receipt(job, adapter, error.status, None, Some(error.message)),
        },
    }
}

fn unresolved_re2_receipt(job: &Job, loaded: &Result<LoadedJob, CompareError>) -> Receipt {
    match loaded {
        Err(error) => receipt(
            job,
            RE2_ADAPTER,
            Status::Fault,
            None,
            Some(error.to_string()),
        ),
        Ok(_) => receipt(
            job,
            RE2_ADAPTER,
            Status::Unresolved,
            None,
            Some(
                "exact Rebar RE2 build is unavailable: pkg-config absl_base receipt was not established"
                    .to_string(),
            ),
        ),
    }
}

fn external_re2_receipt(
    job: &Job,
    loaded: &Result<LoadedJob, CompareError>,
    runner: &Path,
) -> Receipt {
    let input = match loaded {
        Ok(input) => input,
        Err(error) => {
            return receipt(
                job,
                RE2_ADAPTER,
                Status::Fault,
                None,
                Some(error.to_string()),
            );
        }
    };
    match run_upstream_klv(runner, job, input) {
        Ok(actual) if actual == job.expected.count => {
            receipt(job, RE2_ADAPTER, Status::Pass, Some(actual), None)
        }
        Ok(actual) => receipt(
            job,
            RE2_ADAPTER,
            Status::Fail,
            Some(actual),
            Some(format!(
                "actual reducer {actual} differs from expected {}",
                job.expected.count
            )),
        ),
        Err(error) => receipt(
            job,
            RE2_ADAPTER,
            Status::Fault,
            None,
            Some(format!("exact Rebar RE2 adapter failed: {error}")),
        ),
    }
}

fn receipt(
    job: &Job,
    adapter: &str,
    status: Status,
    actual: Option<u64>,
    reason: Option<String>,
) -> Receipt {
    Receipt {
        job_id: job.id.clone(),
        benchmark: job.benchmark.clone(),
        target_engine: job.engine.clone(),
        adapter: adapter.to_string(),
        model: job.model.clone(),
        input: InputReceipt {
            pattern_sha256: job
                .regex
                .patterns
                .iter()
                .map(|pattern| pattern.sha256.clone())
                .collect(),
            haystack_sha256: job.haystack.sha256.clone(),
            haystack_bytes: job.haystack.bytes,
            unicode: job.regex.unicode,
            case_insensitive: job.regex.case_insensitive,
        },
        expected: job.expected.count,
        actual,
        candidate_plan: None,
        status,
        reason,
    }
}

#[derive(Clone, Debug)]
struct ExecutionError {
    status: Status,
    message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdapterReduction {
    actual: u64,
    plan: Option<String>,
}

impl AdapterReduction {
    fn unplanned(actual: u64) -> Self {
        Self { actual, plan: None }
    }
}

impl ExecutionError {
    fn fault(message: impl Into<String>) -> Self {
        Self {
            status: Status::Fault,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            status: Status::Unsupported,
            message: message.into(),
        }
    }
}

fn rust_compile(job: &Job, patterns: &[String]) -> Result<Regex, ExecutionError> {
    rust_compile_options(patterns, job.regex.unicode, job.regex.case_insensitive)
}

fn rust_compile_options(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
) -> Result<Regex, ExecutionError> {
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(NFA_SIZE_LIMIT));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(unicode)
        .case_insensitive(case_insensitive);
    Regex::builder()
        .configure(config)
        .syntax(syntax)
        .build_many(patterns)
        .map_err(|error| ExecutionError::fault(format!("Rust adapter compile failed: {error}")))
}

fn rust_reducer(job: &Job, loaded: &LoadedJob, limits: &RunLimits) -> Result<u64, ExecutionError> {
    if job.model == "regex-redux" {
        return regex_redux(job, &loaded.haystack, limits);
    }
    let regex = rust_compile(job, &loaded.patterns)?;
    match job.model.as_str() {
        "compile" | "count" => count_matches(&regex, &loaded.haystack, limits.reducer_steps),
        "count-spans" => count_spans(&regex, &loaded.haystack, limits.reducer_steps),
        "count-captures" => count_captures(&regex, &loaded.haystack, limits.reducer_steps),
        "grep" => grep(&regex, &loaded.haystack, limits.reducer_steps),
        "grep-captures" => grep_captures(&regex, &loaded.haystack, limits.reducer_steps),
        other => Err(ExecutionError::fault(format!(
            "unrecognized Rebar model {other}"
        ))),
    }
}

fn count_matches(regex: &Regex, haystack: &[u8], limit: u64) -> Result<u64, ExecutionError> {
    let mut count = 0u64;
    for _ in regex.find_iter(haystack) {
        charge(&mut count, 1, limit, "match count")?;
    }
    Ok(count)
}

fn count_spans(regex: &Regex, haystack: &[u8], limit: u64) -> Result<u64, ExecutionError> {
    let mut events = 0u64;
    let mut total = 0u64;
    for matched in regex.find_iter(haystack) {
        charge(&mut events, 1, limit, "span events")?;
        let length = u64::try_from(matched.len())
            .map_err(|_| ExecutionError::fault("match span does not fit u64"))?;
        total = total
            .checked_add(length)
            .ok_or_else(|| ExecutionError::fault("span reducer overflow"))?;
    }
    Ok(total)
}

fn count_captures(regex: &Regex, haystack: &[u8], limit: u64) -> Result<u64, ExecutionError> {
    let mut input = Input::new(haystack);
    let mut captures = regex.create_captures();
    let mut count = 0u64;
    let mut events = 0u64;
    loop {
        regex.search_captures(&input, &mut captures);
        let Some(matched) = captures.get_match() else {
            break;
        };
        if matched.end() == input.start() {
            return Err(ExecutionError::fault(
                "capture model violated its non-empty-match promise",
            ));
        }
        for index in 0..captures.group_len() {
            charge(&mut events, 1, limit, "capture group events")?;
            if captures.get_group(index).is_some() {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| ExecutionError::fault("capture reducer overflow"))?;
            }
        }
        input.set_start(matched.end());
    }
    Ok(count)
}

fn grep(regex: &Regex, haystack: &[u8], limit: u64) -> Result<u64, ExecutionError> {
    let mut count = 0u64;
    let mut events = 0u64;
    for line in haystack.lines() {
        charge(&mut events, 1, limit, "grep line events")?;
        if regex.is_match(line) {
            count = count
                .checked_add(1)
                .ok_or_else(|| ExecutionError::fault("grep reducer overflow"))?;
        }
    }
    Ok(count)
}

fn grep_captures(regex: &Regex, haystack: &[u8], limit: u64) -> Result<u64, ExecutionError> {
    let mut captures = regex.create_captures();
    let mut count = 0u64;
    let mut events = 0u64;
    for line in haystack.lines() {
        charge(&mut events, 1, limit, "grep-captures line events")?;
        let mut input = Input::new(line);
        loop {
            regex.search_captures(&input, &mut captures);
            let Some(matched) = captures.get_match() else {
                break;
            };
            if matched.end() == input.start() {
                return Err(ExecutionError::fault(
                    "grep-captures violated its non-empty-match promise",
                ));
            }
            for index in 0..captures.group_len() {
                charge(&mut events, 1, limit, "grep-captures group events")?;
                if captures.get_group(index).is_some() {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| ExecutionError::fault("grep-captures reducer overflow"))?;
                }
            }
            input.set_start(matched.end());
        }
    }
    Ok(count)
}

fn charge(value: &mut u64, amount: u64, limit: u64, what: &str) -> Result<(), ExecutionError> {
    let needed = value
        .checked_add(amount)
        .ok_or_else(|| ExecutionError::fault(format!("{what} overflow")))?;
    if needed > limit {
        return Err(ExecutionError::fault(format!(
            "{what} needs {needed} events, exceeding {limit}"
        )));
    }
    *value = needed;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositeStage {
    Count {
        pattern: &'static str,
        output: usize,
    },
    ReplaceAllLiteral {
        pattern: &'static str,
        replacement: &'static [u8],
        minimum_match_bytes: usize,
        records_clean_length: bool,
    },
}

const REGEX_REDUX_COUNT_SLOTS: usize = 9;
const REGEX_REDUX_REPLACEMENT_STAGES: usize = 6;

#[derive(Clone, Copy, Debug)]
struct CompositeProgram<'a> {
    stages: &'a [CompositeStage],
    count_labels: [&'static str; REGEX_REDUX_COUNT_SLOTS],
}

impl<'a> CompositeProgram<'a> {
    fn authenticate(stages: &'a [CompositeStage]) -> Result<Self, ExecutionError> {
        let mut count_labels = [""; REGEX_REDUX_COUNT_SLOTS];
        let mut count_seen = [false; REGEX_REDUX_COUNT_SLOTS];
        let mut count_slots = 0_usize;
        let mut replacement_stages = 0_usize;
        let mut clean_length_stages = 0_usize;
        for stage in stages {
            match *stage {
                CompositeStage::Count { pattern, output } => {
                    let seen = count_seen.get_mut(output).ok_or_else(|| {
                        ExecutionError::fault("regex-redux count output slot is out of range")
                    })?;
                    if *seen {
                        return Err(ExecutionError::fault(
                            "regex-redux count output slot is duplicated",
                        ));
                    }
                    *seen = true;
                    count_labels[output] = pattern;
                    count_slots = count_slots.checked_add(1).ok_or_else(|| {
                        ExecutionError::fault("regex-redux count-slot cardinality overflow")
                    })?;
                }
                CompositeStage::ReplaceAllLiteral {
                    records_clean_length,
                    ..
                } => {
                    replacement_stages = replacement_stages.checked_add(1).ok_or_else(|| {
                        ExecutionError::fault("regex-redux replacement cardinality overflow")
                    })?;
                    if records_clean_length {
                        clean_length_stages =
                            clean_length_stages.checked_add(1).ok_or_else(|| {
                                ExecutionError::fault(
                                    "regex-redux clean-length cardinality overflow",
                                )
                            })?;
                    }
                }
            }
        }
        if count_slots != REGEX_REDUX_COUNT_SLOTS || count_seen.iter().any(|seen| !seen) {
            return Err(ExecutionError::fault(
                "regex-redux stage program does not define every count output exactly once",
            ));
        }
        if replacement_stages != REGEX_REDUX_REPLACEMENT_STAGES || clean_length_stages != 1 {
            return Err(ExecutionError::fault(
                "regex-redux stage program has the wrong replacement or clean-length cardinality",
            ));
        }
        Ok(Self {
            stages,
            count_labels,
        })
    }
}

const REGEX_REDUX_VARIANTS: [&str; 9] = [
    r"agggtaaa|tttaccct",
    r"[cgt]gggtaaa|tttaccc[acg]",
    r"a[act]ggtaaa|tttacc[agt]t",
    r"ag[act]gtaaa|tttac[agt]ct",
    r"agg[act]taaa|ttta[agt]cct",
    r"aggg[acg]aaa|ttt[cgt]ccct",
    r"agggt[cgt]aa|tt[acg]accct",
    r"agggta[cgt]a|t[acg]taccct",
    r"agggtaa[cgt]|[acg]ttaccct",
];

const REGEX_REDUX_STAGES: [CompositeStage; 15] = [
    CompositeStage::ReplaceAllLiteral {
        pattern: r">[^\n]*\n|\n",
        replacement: b"",
        minimum_match_bytes: 1,
        records_clean_length: true,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[0],
        output: 0,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[1],
        output: 1,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[2],
        output: 2,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[3],
        output: 3,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[4],
        output: 4,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[5],
        output: 5,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[6],
        output: 6,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[7],
        output: 7,
    },
    CompositeStage::Count {
        pattern: REGEX_REDUX_VARIANTS[8],
        output: 8,
    },
    CompositeStage::ReplaceAllLiteral {
        pattern: r"tHa[Nt]",
        replacement: b"<4>",
        minimum_match_bytes: 4,
        records_clean_length: false,
    },
    CompositeStage::ReplaceAllLiteral {
        pattern: r"aND|caN|Ha[DS]|WaS",
        replacement: b"<3>",
        minimum_match_bytes: 3,
        records_clean_length: false,
    },
    CompositeStage::ReplaceAllLiteral {
        pattern: r"a[NSt]|BY",
        replacement: b"<2>",
        minimum_match_bytes: 2,
        records_clean_length: false,
    },
    CompositeStage::ReplaceAllLiteral {
        pattern: r"<[^>]*>",
        replacement: b"|",
        minimum_match_bytes: 2,
        records_clean_length: false,
    },
    CompositeStage::ReplaceAllLiteral {
        pattern: r"\|[^|][^|]*\|",
        replacement: b"-",
        minimum_match_bytes: 3,
        records_clean_length: false,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompositeLimits {
    stages: usize,
    pattern_bytes: usize,
    replacement_bytes: usize,
    input_bytes: usize,
    intermediate_bytes: usize,
    initial_requested_bytes: usize,
    initial_capacity_bytes: usize,
    replacement_requested_bytes: [usize; REGEX_REDUX_REPLACEMENT_STAGES],
    replacement_capacity_bytes: [usize; REGEX_REDUX_REPLACEMENT_STAGES],
    report_capacity_bytes: usize,
    build_work: u64,
    execution_work: u64,
    match_events: u64,
    span_visits: u64,
    copied_bytes: u64,
    allocation_bytes: u64,
    capacity_bytes: u64,
    prospective_owned_peak_bytes: usize,
    owned_peak_bytes: usize,
    report_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CompositeAccounting {
    stages: usize,
    pattern_bytes: usize,
    replacement_bytes: usize,
    build_work: u64,
    execution_work: u64,
    match_events: u64,
    span_visits: u64,
    copied_bytes: u64,
    allocation_bytes: u64,
    capacity_bytes: u64,
    initial_capacity_bytes: usize,
    replacement_capacity_bytes: [usize; REGEX_REDUX_REPLACEMENT_STAGES],
    report_capacity_bytes: usize,
    current_sequence_capacity_bytes: usize,
    max_intermediate_bytes: usize,
    owned_peak_bytes: usize,
    report_bytes: usize,
}

#[derive(Debug)]
struct CompositeResult {
    counts: [u64; 9],
    input_length: usize,
    clean_length: usize,
    final_bytes: Vec<u8>,
    report: String,
    accounting: CompositeAccounting,
}

fn composite_checked_add(left: u64, right: u64, dimension: &str) -> Result<u64, ExecutionError> {
    left.checked_add(right)
        .ok_or_else(|| ExecutionError::fault(format!("regex-redux {dimension} overflow")))
}

fn composite_checked_mul(left: u64, right: u64, dimension: &str) -> Result<u64, ExecutionError> {
    left.checked_mul(right)
        .ok_or_else(|| ExecutionError::fault(format!("regex-redux {dimension} overflow")))
}

fn composite_usize_add(
    left: usize,
    right: usize,
    dimension: &str,
) -> Result<usize, ExecutionError> {
    left.checked_add(right)
        .ok_or_else(|| ExecutionError::fault(format!("regex-redux {dimension} overflow")))
}

fn composite_usize_mul(
    left: usize,
    right: usize,
    dimension: &str,
) -> Result<usize, ExecutionError> {
    left.checked_mul(right)
        .ok_or_else(|| ExecutionError::fault(format!("regex-redux {dimension} overflow")))
}

fn composite_replacement_span_visits(selected_matches: usize) -> Result<usize, ExecutionError> {
    composite_usize_mul(selected_matches, 2, "replacement span visits")
}

fn composite_count_match_events(sequence_len: usize) -> Result<usize, ExecutionError> {
    composite_usize_add(sequence_len, 1, "count match-event boundaries")
}

fn composite_replacement_match_events(sequence_len: usize) -> Result<usize, ExecutionError> {
    composite_usize_add(sequence_len, 1, "replacement match boundaries")
}

fn composite_continuation_match_events(sequence_len: usize) -> Result<usize, ExecutionError> {
    let boundaries = composite_usize_add(sequence_len, 1, "span boundaries")?;
    composite_usize_mul(boundaries, 2, "continuation match-event ceiling")
}

fn composite_u64(value: usize, dimension: &str) -> Result<u64, ExecutionError> {
    u64::try_from(value)
        .map_err(|_| ExecutionError::fault(format!("regex-redux {dimension} does not fit u64")))
}

fn composite_enforce(needed: u64, limit: u64, dimension: &str) -> Result<(), ExecutionError> {
    if needed > limit {
        return Err(ExecutionError::unsupported(format!(
            "regex-redux {dimension} needs {needed}, exceeding {limit}"
        )));
    }
    Ok(())
}

fn composite_limits(limits: &RunLimits) -> Result<CompositeLimits, ExecutionError> {
    let stage_build = limits
        .fre_aggregate_compile_work
        .max(usize::try_from(limits.fre_literal_build_work).unwrap_or(usize::MAX));
    let build_work = composite_u64(
        composite_usize_mul(REGEX_REDUX_STAGES.len(), stage_build, "build ceiling")?,
        "build ceiling",
    )?;
    let execution_work = composite_u64(
        composite_usize_mul(
            REGEX_REDUX_STAGES.len(),
            limits.fre_aggregate_operation_work,
            "execution ceiling",
        )?,
        "execution ceiling",
    )?;
    let replacement_stages = REGEX_REDUX_STAGES
        .iter()
        .filter(|stage| matches!(stage, CompositeStage::ReplaceAllLiteral { .. }))
        .count();
    let pipeline_copies = replacement_stages
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("regex-redux copy count overflow"))?;
    let copied_bytes = composite_u64(
        composite_usize_mul(limits.haystack_bytes, pipeline_copies, "copy ceiling")?,
        "copy ceiling",
    )?;
    let allocation_bytes = composite_u64(
        composite_usize_mul(limits.haystack_bytes, 32, "allocation ceiling")?,
        "allocation ceiling",
    )?;
    let owned_peak_bytes = [
        composite_usize_mul(limits.haystack_bytes, 3, "owned input/output peak")?,
        limits.fre_aggregate_peak_bytes,
        limits.fre_aggregate_program_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, |sum, term| {
        composite_usize_add(sum, term, "owned peak ceiling")
    })?;
    let doubled_reducer_steps =
        composite_checked_mul(limits.reducer_steps, 2, "reducer step doubling")?;
    Ok(CompositeLimits {
        stages: REGEX_REDUX_STAGES.len(),
        pattern_bytes: limits.pattern_bytes_per_job,
        replacement_bytes: limits.pattern_bytes_per_job,
        input_bytes: limits.haystack_bytes,
        intermediate_bytes: limits.haystack_bytes,
        initial_requested_bytes: limits.haystack_bytes,
        initial_capacity_bytes: limits.haystack_bytes,
        replacement_requested_bytes: [limits.haystack_bytes; REGEX_REDUX_REPLACEMENT_STAGES],
        replacement_capacity_bytes: [limits.haystack_bytes; REGEX_REDUX_REPLACEMENT_STAGES],
        report_capacity_bytes: limits.pattern_bytes_per_job,
        build_work,
        execution_work: composite_checked_add(
            composite_checked_add(execution_work, copied_bytes, "execution plus copy ceiling")?,
            composite_checked_add(
                composite_u64(limits.haystack_bytes, "validation ceiling")?,
                doubled_reducer_steps,
                "validation plus span ceiling",
            )?,
            "execution plus copy ceiling",
        )?,
        match_events: limits.reducer_steps,
        span_visits: doubled_reducer_steps,
        copied_bytes,
        allocation_bytes,
        capacity_bytes: allocation_bytes,
        prospective_owned_peak_bytes: owned_peak_bytes,
        owned_peak_bytes,
        report_bytes: limits.pattern_bytes_per_job,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CompositeProspective {
    pattern_bytes: usize,
    replacement_bytes: usize,
    sequence_bytes: usize,
    replacement_output_bytes: [usize; REGEX_REDUX_REPLACEMENT_STAGES],
    copied_bytes: usize,
    allocation_bytes: usize,
    span_visits: usize,
    match_events: usize,
    owned_peak_bytes: usize,
    declared_build_work: u64,
    declared_execution_work: u64,
    report_bytes: usize,
}

fn preflight_replacement_stage(
    prospective: &mut CompositeProspective,
    replacement_index: usize,
    replacement: &[u8],
    run_limits: &RunLimits,
) -> Result<(), ExecutionError> {
    prospective.replacement_bytes = composite_usize_add(
        prospective.replacement_bytes,
        replacement.len(),
        "replacement bytes",
    )?;
    let old_sequence = prospective.sequence_bytes;
    // This whole-program envelope deliberately does not read the caller's
    // declared HIR minimum. N+1 is safe even for a nullable pattern. The
    // tighter operation-local ceiling is derived only after the built
    // artifact authenticates a nonzero HIR minimum and declaration equality.
    let matches = composite_replacement_match_events(old_sequence)?;
    prospective.match_events = composite_usize_add(
        prospective.match_events,
        matches,
        "replacement match events",
    )?;
    let inserted = composite_usize_mul(matches, replacement.len(), "inserted bytes")?;
    prospective.sequence_bytes = composite_usize_add(old_sequence, inserted, "intermediate bytes")?;
    let output = prospective
        .replacement_output_bytes
        .get_mut(replacement_index)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index is out of range"))?;
    *output = prospective.sequence_bytes;
    prospective.copied_bytes = composite_usize_add(
        prospective.copied_bytes,
        prospective.sequence_bytes,
        "copy bytes",
    )?;
    prospective.span_visits = composite_usize_add(
        prospective.span_visits,
        composite_usize_mul(matches, 2, "span visits")?,
        "span visits",
    )?;
    let span_bytes = composite_usize_mul(
        matches,
        core::mem::size_of::<fre::AggregateSpan>(),
        "selector span bytes",
    )?;
    prospective.allocation_bytes = composite_usize_add(
        prospective.allocation_bytes,
        composite_usize_add(prospective.sequence_bytes, span_bytes, "stage allocation")?,
        "allocation bytes",
    )?;
    let live = [
        old_sequence,
        run_limits.fre_aggregate_program_bytes,
        run_limits.fre_aggregate_peak_bytes,
        prospective.sequence_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, |sum, term| {
        composite_usize_add(sum, term, "owned peak bytes")
    })?;
    prospective.owned_peak_bytes = prospective.owned_peak_bytes.max(live);
    Ok(())
}

fn composite_prospective(
    input_len: usize,
    program: &CompositeProgram<'_>,
    run_limits: &RunLimits,
) -> Result<CompositeProspective, ExecutionError> {
    let stage_build = run_limits
        .fre_aggregate_compile_work
        .max(usize::try_from(run_limits.fre_literal_build_work).unwrap_or(usize::MAX));
    let mut prospective = CompositeProspective {
        sequence_bytes: input_len,
        copied_bytes: input_len,
        allocation_bytes: input_len,
        owned_peak_bytes: input_len,
        declared_build_work: composite_u64(
            composite_usize_mul(program.stages.len(), stage_build, "declared build work")?,
            "declared build work",
        )?,
        ..CompositeProspective::default()
    };
    let mut replacement_index = 0_usize;
    for stage in program.stages {
        let pattern = match stage {
            CompositeStage::Count { pattern, .. }
            | CompositeStage::ReplaceAllLiteral { pattern, .. } => pattern,
        };
        prospective.pattern_bytes =
            composite_usize_add(prospective.pattern_bytes, pattern.len(), "pattern bytes")?;
        match stage {
            CompositeStage::Count { .. } => {
                let boundaries = composite_count_match_events(prospective.sequence_bytes)?;
                prospective.match_events = composite_usize_add(
                    prospective.match_events,
                    boundaries,
                    "count match events",
                )?;
            }
            CompositeStage::ReplaceAllLiteral { replacement, .. } => preflight_replacement_stage(
                &mut prospective,
                replacement_index,
                replacement,
                run_limits,
            )?,
        }
        if matches!(stage, CompositeStage::ReplaceAllLiteral { .. }) {
            replacement_index = replacement_index
                .checked_add(1)
                .ok_or_else(|| ExecutionError::fault("regex-redux replacement index overflow"))?;
        }
    }
    let stage_execution = composite_usize_mul(
        program.stages.len(),
        run_limits.fre_aggregate_operation_work,
        "declared stage execution work",
    )?;
    prospective.declared_execution_work = composite_u64(
        [
            stage_execution,
            input_len,
            prospective.copied_bytes,
            prospective.span_visits,
        ]
        .into_iter()
        .try_fold(0_usize, |sum, term| {
            composite_usize_add(sum, term, "declared execution work")
        })?,
        "declared execution work",
    )?;
    prospective.report_bytes = program
        .count_labels
        .iter()
        .try_fold(1_usize, |sum, pattern| {
            composite_usize_add(sum, pattern.len(), "report pattern bytes")
                .and_then(|sum| composite_usize_add(sum, 22, "report count bytes"))
        })
        .and_then(|sum| composite_usize_add(sum, 63, "report length bytes"))?;
    prospective.allocation_bytes = composite_usize_add(
        prospective.allocation_bytes,
        prospective.report_bytes,
        "report allocation",
    )?;
    prospective.owned_peak_bytes = prospective.owned_peak_bytes.max(composite_usize_add(
        prospective.sequence_bytes,
        prospective.report_bytes,
        "report owned peak",
    )?);
    Ok(prospective)
}

fn enforce_composite_prospective(
    input_len: usize,
    program: &CompositeProgram<'_>,
    prospective: CompositeProspective,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    for (needed, limit, dimension) in [
        (program.stages.len(), limits.stages, "stages"),
        (input_len, limits.input_bytes, "input bytes"),
        (
            input_len,
            limits.initial_requested_bytes,
            "initial requested bytes",
        ),
        (
            prospective.pattern_bytes,
            limits.pattern_bytes,
            "pattern bytes",
        ),
        (
            prospective.replacement_bytes,
            limits.replacement_bytes,
            "replacement bytes",
        ),
        (
            prospective.sequence_bytes,
            limits.intermediate_bytes,
            "intermediate bytes",
        ),
        (
            prospective.owned_peak_bytes,
            limits.prospective_owned_peak_bytes,
            "prospective owned peak bytes",
        ),
        (
            prospective.report_bytes,
            limits.report_bytes,
            "report bytes",
        ),
    ] {
        composite_enforce(
            composite_u64(needed, dimension)?,
            composite_u64(limit, dimension)?,
            dimension,
        )?;
    }
    for (needed, limit) in prospective
        .replacement_output_bytes
        .iter()
        .zip(limits.replacement_requested_bytes)
    {
        composite_enforce(
            composite_u64(*needed, "replacement requested bytes")?,
            composite_u64(limit, "replacement requested byte limit")?,
            "replacement requested bytes",
        )?;
    }
    for (needed, limit, dimension) in [
        (
            prospective.declared_build_work,
            limits.build_work,
            "declared build work",
        ),
        (
            prospective.declared_execution_work,
            limits.execution_work,
            "declared execution work",
        ),
        (
            composite_u64(prospective.match_events, "match events")?,
            limits.match_events,
            "match events",
        ),
        (
            composite_u64(prospective.span_visits, "span visits")?,
            limits.span_visits,
            "span visits",
        ),
        (
            composite_u64(prospective.copied_bytes, "copy bytes")?,
            limits.copied_bytes,
            "copy bytes",
        ),
        (
            composite_u64(prospective.allocation_bytes, "allocation bytes")?,
            limits.allocation_bytes,
            "allocation bytes",
        ),
    ] {
        composite_enforce(needed, limit, dimension)?;
    }
    Ok(())
}

fn composite_preflight(
    input_len: usize,
    program: &CompositeProgram<'_>,
    run_limits: &RunLimits,
    limits: CompositeLimits,
) -> Result<CompositeAccounting, ExecutionError> {
    let prospective = composite_prospective(input_len, program, run_limits)?;
    enforce_composite_prospective(input_len, program, prospective, limits)?;
    Ok(CompositeAccounting {
        pattern_bytes: prospective.pattern_bytes,
        replacement_bytes: prospective.replacement_bytes,
        execution_work: composite_u64(input_len, "UTF-8 validation work")?,
        copied_bytes: composite_u64(input_len, "initial copy bytes")?,
        max_intermediate_bytes: input_len,
        ..CompositeAccounting::default()
    })
}

fn composite_build_work(report: &AggregateBuildReport) -> Result<u64, ExecutionError> {
    let mut work = report.syntax.parse_work;
    let fixed_absolute_planner_work =
        usize::try_from(report.fixed_absolute_planner_work).map_err(|_| {
            ExecutionError::fault("fixed absolute-domain planner work does not fit usize")
        })?;
    for planner in [
        report.planner_work,
        report.unicode_scalar_planner_work,
        report.word_run_planner_work,
        report.literal_assertions_planner_work,
        report.blocking_delimiter_planner_work,
        report.token_phrase_planner_work,
        report.fixed_class_sandwich_planner_work,
        report.bounded_affix_planner_work,
        report.grapheme_scalar_dfa_planner_work,
        report.bounded_class_sequence_planner_work,
        report.bounded_separated_fields_planner_work,
        report.prefix_class_alternation_planner_work,
        report.literal_class_run_literal_planner_work,
        report.bounded_literal_pair_planner_work,
        report.bounded_context_planner_work,
        fixed_absolute_planner_work,
        report.capture_erasure_work,
    ] {
        work = composite_checked_add(work, composite_u64(planner, "planner work")?, "build work")?;
    }
    work = composite_checked_add(work, report.finite_planner_work, "finite planner work")?;
    let selected = match report.build {
        AggregateBuildAccounting::FiniteLiteral(build) => build.build_work_upper_bound,
        AggregateBuildAccounting::PackedFiniteLiteral(build) => build.build_work_upper_bound,
        AggregateBuildAccounting::SparseFiniteLiteral(build) => build.build_work,
        AggregateBuildAccounting::FixedAbsoluteDomain(_) => {
            let build = report
                .fixed_absolute_domain_build_accounting()
                .ok_or_else(|| {
                    ExecutionError::fault(
                        "regex-redux fixed absolute-domain build accounting is not authenticated",
                    )
                })?;
            if !report.has_closed_fixed_absolute_domain_identity() {
                return Err(ExecutionError::fault(
                    "regex-redux fixed absolute-domain build identity is not closed",
                ));
            }
            build.actual.work
        }
        AggregateBuildAccounting::Continuation(build) => composite_u64(build.work, "compile work")?,
        _ => {
            return Err(ExecutionError::fault(
                "regex-redux selected an unauthenticated build family",
            ));
        }
    };
    composite_checked_add(work, selected, "selected build work")
}

fn require_composite_build_source_identity(
    report: &AggregateBuildReport,
    pattern: &str,
    operation: AggregateOperation,
) -> Result<(), ExecutionError> {
    require_closed_construction_attempt(report)?;
    let mut profile = rebar_profile();
    profile.options.unicode = false;
    profile.options.case_insensitive = false;
    if report.operation != operation
        || report.syntax_key.pattern.as_bytes() != pattern.as_bytes()
        || report.syntax_key.profile != CompatibilityProfile::RustBytes(profile)
        || report.capture_semantics != AggregateCaptureSemantics::ErasedForWholeMatchOnly
    {
        return Err(ExecutionError::fault(
            "regex-redux component build identity mismatch",
        ));
    }
    Ok(())
}

fn require_composite_build_plan_identity(
    report: &AggregateBuildReport,
    operation: AggregateOperation,
) -> Result<(), ExecutionError> {
    let valid_plan = match operation {
        AggregateOperation::Count => matches!(
            report.build,
            AggregateBuildAccounting::FiniteLiteral(_)
                | AggregateBuildAccounting::PackedFiniteLiteral(_)
                | AggregateBuildAccounting::SparseFiniteLiteral(_)
        ),
        AggregateOperation::Spans => {
            matches!(report.build, AggregateBuildAccounting::Continuation(_))
        }
        _ => false,
    };
    if !valid_plan {
        return Err(ExecutionError::fault(
            "regex-redux component selected an unexpected plan",
        ));
    }
    Ok(())
}

fn require_composite_count_minimum_identity(
    report: &AggregateBuildReport,
    minimum_match_bytes: usize,
) -> Result<(), ExecutionError> {
    let finite_minimum_matches = match report.build {
        AggregateBuildAccounting::FiniteLiteral(build) => {
            !build.has_empty_pattern
                && build.min_nonempty_pattern_bytes == Some(minimum_match_bytes)
        }
        AggregateBuildAccounting::PackedFiniteLiteral(build) => {
            build.min_pattern_bytes == minimum_match_bytes
        }
        AggregateBuildAccounting::SparseFiniteLiteral(build) => {
            !build.has_empty_pattern
                && build.min_nonempty_pattern_bytes == Some(minimum_match_bytes)
        }
        _ => false,
    };
    if !finite_minimum_matches {
        return Err(ExecutionError::fault(
            "regex-redux count stage finite plan differs from its authenticated nonzero HIR minimum width",
        ));
    }
    Ok(())
}

fn composite_component_build_peak(report: &AggregateBuildReport) -> Result<usize, ExecutionError> {
    let (persistent, peak, valid_peak) = match report.build {
        AggregateBuildAccounting::FiniteLiteral(build) => (
            build.persistent_bytes,
            build.peak_bytes,
            build.persistent_bytes.checked_add(build.scratch_bytes) == Some(build.peak_bytes),
        ),
        AggregateBuildAccounting::PackedFiniteLiteral(build) => (
            build.persistent_bytes,
            build.build_peak_upper_bound,
            build.build_peak_upper_bound >= build.persistent_bytes,
        ),
        AggregateBuildAccounting::SparseFiniteLiteral(build) => (
            build.persistent_bytes,
            build.peak_bytes,
            build.peak_bytes >= build.persistent_bytes && build.peak_bytes >= build.scratch_bytes,
        ),
        AggregateBuildAccounting::FixedAbsoluteDomain(_) => {
            let build = report
                .fixed_absolute_domain_build_accounting()
                .ok_or_else(|| {
                    ExecutionError::fault(
                        "regex-redux fixed absolute-domain build accounting is not authenticated",
                    )
                })?;
            (
                build.actual.persistent_bytes,
                build.actual.peak_bytes,
                report.has_closed_fixed_absolute_domain_identity()
                    && build.actual.published
                    && build.actual.work <= build.prospective.work
                    && build.actual.allocations <= build.prospective.allocations
                    && build.actual.persistent_bytes <= build.prospective.persistent_bytes
                    && build.actual.peak_bytes <= build.prospective.peak_bytes
                    && build.actual.peak_bytes >= build.actual.persistent_bytes
                    && build.kernel.actual.published
                    && fixed_absolute_build_contains(build.kernel.prospective, build.kernel.actual),
            )
        }
        AggregateBuildAccounting::Continuation(build) => (
            build.program_bytes,
            build.construction_peak_bytes,
            build.construction_peak_bytes >= build.program_bytes,
        ),
        _ => {
            return Err(ExecutionError::fault(
                "regex-redux selected an unauthenticated construction-peak family",
            ));
        }
    };
    if report.retained_capacity_bytes != persistent || !valid_peak {
        return Err(ExecutionError::fault(
            "regex-redux component construction-peak identity mismatch",
        ));
    }
    Ok(peak)
}

fn charge_composite_build(
    accounting: &mut CompositeAccounting,
    report: &AggregateBuildReport,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    let work = composite_build_work(report)?;
    accounting.build_work = composite_checked_add(accounting.build_work, work, "build work")?;
    composite_enforce(accounting.build_work, limits.build_work, "build work")?;
    let component_peak = composite_component_build_peak(report)?;
    accounting.owned_peak_bytes = accounting.owned_peak_bytes.max(composite_usize_add(
        accounting.current_sequence_capacity_bytes,
        component_peak,
        "build owned peak",
    )?);
    composite_enforce(
        composite_u64(accounting.owned_peak_bytes, "owned peak bytes")?,
        composite_u64(limits.owned_peak_bytes, "owned peak limit")?,
        "owned peak bytes",
    )
}

fn charge_count_execution(
    accounting: &mut CompositeAccounting,
    report: &AggregateExecutionReport,
    value: u64,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    let details = report.details();
    let (work, events, peak) = match details {
        AggregateExecutionDetails::FiniteLiteral {
            upper_bounds,
            actual,
        } => {
            if actual.total_work > upper_bounds.total_work
                || actual.match_events > composite_u64(upper_bounds.match_events, "match events")?
                || actual.count != Some(value)
            {
                return Err(ExecutionError::fault(
                    "regex-redux dense finite execution accounting mismatch",
                ));
            }
            (
                composite_u64(upper_bounds.total_work, "execution work")?,
                actual.match_events,
                actual.peak_bytes,
            )
        }
        AggregateExecutionDetails::PackedFiniteLiteral {
            operation_identity,
            upper_bounds,
            actual,
        } => {
            let build_identity_matches = matches!(
                report.identity().plan_identity,
                AggregatePlanIdentity::FiniteLiteral(identity)
                    if identity.packed_operation_identity == Some(*operation_identity)
            );
            if !build_identity_matches
                || actual.work > upper_bounds.work
                || actual.match_events
                    > composite_u64(upper_bounds.match_events, "packed match events")?
                || actual.iterator_next_calls > upper_bounds.reducer_steps
                || actual.classified_positions != upper_bounds.candidate_positions
                || actual.candidate_events > upper_bounds.candidate_positions
                || actual.pattern_checks > upper_bounds.pattern_checks
                || actual.source_byte_reads != upper_bounds.source_byte_reads
                || actual.scratch_bytes > upper_bounds.scratch_bytes
                || actual.peak_bytes > upper_bounds.peak_bytes
                || actual.count != Some(value)
            {
                return Err(ExecutionError::fault(
                    "regex-redux packed finite execution accounting mismatch",
                ));
            }
            (upper_bounds.work, actual.match_events, actual.peak_bytes)
        }
        AggregateExecutionDetails::SparseFiniteLiteral {
            upper_bounds,
            actual,
        } => {
            if actual.total_work > upper_bounds.total_work
                || actual.match_events > composite_u64(upper_bounds.match_events, "match events")?
                || actual.count != Some(value)
            {
                return Err(ExecutionError::fault(
                    "regex-redux sparse finite execution accounting mismatch",
                ));
            }
            (
                upper_bounds.total_work,
                actual.match_events,
                actual.peak_bytes,
            )
        }
        _ => {
            return Err(ExecutionError::fault(
                "regex-redux count execution changed plan family",
            ));
        }
    };
    accounting.execution_work =
        composite_checked_add(accounting.execution_work, work, "execution work")?;
    accounting.match_events =
        composite_checked_add(accounting.match_events, events, "match events")?;
    accounting.owned_peak_bytes = accounting.owned_peak_bytes.max(composite_usize_add(
        accounting.current_sequence_capacity_bytes,
        peak,
        "count owned peak",
    )?);
    composite_enforce(
        accounting.execution_work,
        limits.execution_work,
        "execution work",
    )?;
    composite_enforce(accounting.match_events, limits.match_events, "match events")
}

fn composite_report_length(
    labels: &[&str; REGEX_REDUX_COUNT_SLOTS],
    counts: &[u64; 9],
    input: usize,
    clean: usize,
    final_len: usize,
) -> Result<usize, ExecutionError> {
    fn digits(value: u64) -> Result<usize, ExecutionError> {
        if value == 0 {
            Ok(1)
        } else {
            usize::try_from(value.ilog10())
                .ok()
                .and_then(|digits| digits.checked_add(1))
                .ok_or_else(|| ExecutionError::fault("regex-redux decimal width overflow"))
        }
    }
    let mut bytes = 1_usize;
    for (pattern, count) in labels.iter().zip(counts) {
        bytes = composite_usize_add(bytes, pattern.len(), "report bytes")?;
        bytes = composite_usize_add(bytes, 1, "report separator")?;
        bytes = composite_usize_add(bytes, digits(*count)?, "report count")?;
        bytes = composite_usize_add(bytes, 1, "report newline")?;
    }
    for value in [input, clean, final_len] {
        bytes = composite_usize_add(
            bytes,
            composite_usize_add(
                digits(composite_u64(value, "report length")?)?,
                1,
                "report length newline",
            )?,
            "report bytes",
        )?;
    }
    Ok(bytes)
}

#[derive(Debug)]
struct CompositeRunState {
    sequence: Vec<u8>,
    clean_length: Option<usize>,
    counts: [u64; 9],
    count_seen: [bool; 9],
    replacement_index: usize,
    accounting: CompositeAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompositeReplacementUsage {
    work: u64,
    events: u64,
    output: usize,
    peak: usize,
}

fn composite_replacement_usage(
    replaced: &fre::LiteralReplacementResult,
) -> Result<CompositeReplacementUsage, ExecutionError> {
    let report = replaced.report();
    let usage = match &report.selector_details {
        AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } => {
            if accounting.work > certificate.work_bound
                || accounting.emitted_matches > certificate.output_matches
                || accounting.output_bytes > certificate.output_bytes
            {
                return Err(ExecutionError::fault(
                    "regex-redux replacement selector accounting mismatch",
                ));
            }
            CompositeReplacementUsage {
                work: composite_u64(certificate.work_bound, "selector work")?,
                events: composite_u64(accounting.emitted_matches, "selector matches")?,
                output: accounting.output_bytes,
                peak: accounting.peak_bytes,
            }
        }
        _ => {
            return Err(ExecutionError::fault(
                "regex-redux replacement execution changed plan family",
            ));
        }
    };
    let accounting = report.accounting;
    let expected_span_visits = composite_replacement_span_visits(accounting.selected_matches)?;
    if accounting.replacements != accounting.selected_matches
        || accounting.span_visits != expected_span_visits
        || accounting.output_bytes != replaced.as_bytes().len()
    {
        return Err(ExecutionError::fault(
            "regex-redux replacement accounting mismatch",
        ));
    }
    Ok(usage)
}

fn enforce_composite_runtime(
    accounting: &CompositeAccounting,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    for (needed, cap, dimension) in [
        (
            accounting.execution_work,
            limits.execution_work,
            "execution work",
        ),
        (accounting.match_events, limits.match_events, "match events"),
        (accounting.span_visits, limits.span_visits, "span visits"),
        (accounting.copied_bytes, limits.copied_bytes, "copied bytes"),
        (
            accounting.allocation_bytes,
            limits.allocation_bytes,
            "allocation bytes",
        ),
        (
            accounting.capacity_bytes,
            limits.capacity_bytes,
            "observed capacity bytes",
        ),
    ] {
        composite_enforce(needed, cap, dimension)?;
    }
    composite_enforce(
        composite_u64(accounting.owned_peak_bytes, "owned peak bytes")?,
        composite_u64(limits.owned_peak_bytes, "owned peak limit")?,
        "owned peak bytes",
    )
}

fn charge_composite_replacement(
    state: &mut CompositeRunState,
    replaced: &fre::LiteralReplacementResult,
    replacement_index: usize,
    retained_capacity: usize,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    let usage = composite_replacement_usage(replaced)?;
    let replacement = replaced.report().accounting;
    let output_capacity = replaced.capacity_bytes();
    if replacement.output_capacity_bytes != output_capacity {
        return Err(ExecutionError::fault(
            "regex-redux replacement output capacity identity mismatch",
        ));
    }
    let replacement_capacity_limit = *limits
        .replacement_capacity_bytes
        .get(replacement_index)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index is out of range"))?;
    composite_enforce(
        composite_u64(output_capacity, "replacement output capacity")?,
        composite_u64(replacement_capacity_limit, "replacement capacity limit")?,
        "replacement output capacity",
    )?;
    let loop_work = [
        replacement.span_visits,
        replacement.haystack_bytes_copied,
        replacement.replacement_bytes_copied,
    ]
    .into_iter()
    .try_fold(0_usize, |sum, term| {
        composite_usize_add(sum, term, "replacement loop work")
    })?;
    let accounting = &mut state.accounting;
    accounting.execution_work = composite_checked_add(
        accounting.execution_work,
        composite_checked_add(
            usage.work,
            composite_u64(loop_work, "replacement loop work")?,
            "replacement execution work",
        )?,
        "execution work",
    )?;
    accounting.match_events =
        composite_checked_add(accounting.match_events, usage.events, "match events")?;
    accounting.span_visits = composite_checked_add(
        accounting.span_visits,
        composite_u64(replacement.span_visits, "span visits")?,
        "span visits",
    )?;
    accounting.copied_bytes = composite_checked_add(
        accounting.copied_bytes,
        composite_u64(replacement.output_bytes, "copied bytes")?,
        "copied bytes",
    )?;
    let logical_span_bytes = composite_usize_mul(
        replacement.selected_matches,
        core::mem::size_of::<fre::AggregateSpan>(),
        "replacement logical span bytes",
    )?;
    let allocation = composite_usize_add(
        logical_span_bytes,
        replacement.output_bytes,
        "replacement allocation",
    )?;
    accounting.allocation_bytes = composite_checked_add(
        accounting.allocation_bytes,
        composite_u64(allocation, "replacement allocation")?,
        "allocation bytes",
    )?;
    let observed_capacity = composite_usize_add(
        usage.output,
        output_capacity,
        "replacement observed capacity",
    )?;
    accounting.capacity_bytes = composite_checked_add(
        accounting.capacity_bytes,
        composite_u64(observed_capacity, "replacement observed capacity")?,
        "observed capacity bytes",
    )?;
    let recorded_capacity = accounting
        .replacement_capacity_bytes
        .get_mut(replacement_index)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index is out of range"))?;
    *recorded_capacity = output_capacity;
    let next_len = replaced.as_bytes().len();
    accounting.max_intermediate_bytes = accounting.max_intermediate_bytes.max(next_len);
    let retained_input = composite_usize_add(
        state.sequence.capacity(),
        retained_capacity,
        "replacement retained input and artifact",
    )?;
    let selector_live = composite_usize_add(
        retained_input,
        usage.peak,
        "replacement selector-phase owned peak",
    )?;
    let output_live = composite_usize_add(
        composite_usize_add(retained_input, usage.output, "replacement retained spans")?,
        output_capacity,
        "replacement output-copy owned peak",
    )?;
    let live = selector_live.max(output_live);
    accounting.owned_peak_bytes = accounting.owned_peak_bytes.max(live);
    accounting.current_sequence_capacity_bytes = output_capacity;
    enforce_composite_runtime(accounting, limits)
}

fn composite_replacement_component_limits(
    sequence_len: usize,
    report: &AggregateBuildReport,
    minimum_match_bytes: usize,
    run_limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    let AggregateBuildAccounting::Continuation(compile) = report.build else {
        return Err(ExecutionError::fault(
            "regex-redux replacement component is not an authenticated continuation plan",
        ));
    };
    if report.operation != AggregateOperation::Spans || minimum_match_bytes == 0 {
        return Err(ExecutionError::fault(
            "regex-redux replacement component identity is not nonnullable spans",
        ));
    }
    Ok(AggregateRunLimits {
        // This is the authoritative operation-specific component, constructed
        // once without deriving and then overwriting a one-pass ceiling.
        // Every inactive family remains explicit in the cache identity.
        exact_literal: inactive_literal_operation_limits(run_limits),
        unicode_scalar: inactive_unicode_scalar_operation_limits(),
        word_run: inactive_word_run_operation_limits(),
        literal_assertions: inactive_literal_assertions_operation_limits(),
        blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
        token_phrase: inactive_token_phrase_operation_limits(),
        fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
        grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
        bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
        bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
        prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
        literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
        bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
        bounded_context: inactive_bounded_context_operation_limits(),
        fixed_absolute: inactive_fixed_absolute_operation_limits(),
        fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
        finite_literal: ordered_literal_operation_limits(sequence_len, None, run_limits)?,
        continuation: continuation_spans_operation_limits(
            sequence_len,
            compile.into(),
            minimum_match_bytes,
            run_limits,
        )?,
    })
}

fn composite_replacement_run_limits(
    sequence_len: usize,
    report: &AggregateBuildReport,
    minimum_match_bytes: usize,
    run_limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    // The wrapper is intentionally identity-only: component ceilings are
    // already operation-aware, structural and quota-capped. In particular,
    // it cannot widen even one field after authentication.
    composite_replacement_component_limits(sequence_len, report, minimum_match_bytes, run_limits)
}

fn execute_composite_count_stage(
    state: &mut CompositeRunState,
    pattern: &str,
    output: usize,
    run_limits: &RunLimits,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    let slot = state
        .count_seen
        .get_mut(output)
        .ok_or_else(|| ExecutionError::fault("regex-redux count output slot is out of range"))?;
    if *slot {
        return Err(ExecutionError::fault(
            "regex-redux count output slot is duplicated",
        ));
    }
    let regex = AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(false)
        .case_insensitive(false)
        .limits(aggregate_build_limits(run_limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| aggregate_build_error(&error))?;
    require_composite_build_source_identity(
        regex.build_report(),
        pattern,
        AggregateOperation::Count,
    )?;
    let minimum_match_bytes = regex.minimum_match_bytes().ok_or_else(|| {
        ExecutionError::fault(
            "regex-redux count stage has no authenticated nonzero HIR minimum width",
        )
    })?;
    if minimum_match_bytes == 0 {
        return Err(ExecutionError::fault(
            "regex-redux count stage has no authenticated nonzero HIR minimum width",
        ));
    }
    require_composite_count_minimum_identity(regex.build_report(), minimum_match_bytes)?;
    require_composite_build_plan_identity(regex.build_report(), AggregateOperation::Count)?;
    charge_composite_build(&mut state.accounting, regex.build_report(), limits)?;
    let operation_limits = count_run_limits_with_policy(state.sequence.len(), &regex, run_limits)?;
    let result = regex
        .count(&state.sequence, operation_limits)
        .map_err(|error| {
            aggregate_attempt_error(
                &error,
                format!("regex-redux count execution failed: {error}"),
            )
        })?;
    state.counts[output] = result.value();
    *slot = true;
    charge_count_execution(
        &mut state.accounting,
        result.report(),
        result.value(),
        limits,
    )
}

fn execute_composite_replacement_stage(
    state: &mut CompositeRunState,
    component: CompositeStage,
    run_limits: &RunLimits,
    limits: CompositeLimits,
) -> Result<(), ExecutionError> {
    let CompositeStage::ReplaceAllLiteral {
        pattern,
        replacement,
        minimum_match_bytes,
        records_clean_length,
    } = component
    else {
        return Err(ExecutionError::fault(
            "regex-redux replacement helper received a count stage",
        ));
    };
    let regex = AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(false)
        .case_insensitive(false)
        .limits(aggregate_build_limits(run_limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_spans()
        .map_err(|error| aggregate_build_error(&error))?;
    require_composite_build_source_identity(
        regex.build_report(),
        pattern,
        AggregateOperation::Spans,
    )?;
    let authenticated_minimum_match_bytes = regex.minimum_match_bytes().ok_or_else(|| {
        ExecutionError::fault(
            "regex-redux replacement has no authenticated nonzero HIR minimum width",
        )
    })?;
    if authenticated_minimum_match_bytes == 0
        || authenticated_minimum_match_bytes != minimum_match_bytes
    {
        return Err(ExecutionError::fault(
            "regex-redux replacement declaration differs from authenticated nonzero HIR minimum width",
        ));
    }
    require_composite_build_plan_identity(regex.build_report(), AggregateOperation::Spans)?;
    charge_composite_build(&mut state.accounting, regex.build_report(), limits)?;
    let operation_limits = composite_replacement_run_limits(
        state.sequence.len(),
        regex.build_report(),
        authenticated_minimum_match_bytes,
        run_limits,
    )?;
    let replacement_index = state.replacement_index;
    let replacement_requested_limit = *limits
        .replacement_requested_bytes
        .get(replacement_index)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index is out of range"))?;
    let replacement_capacity_limit = *limits
        .replacement_capacity_bytes
        .get(replacement_index)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index is out of range"))?;
    let replaced = regex
        .replace_all_literal(
            &state.sequence,
            replacement,
            LiteralReplacementLimits {
                aggregate: operation_limits,
                max_output_bytes: limits.intermediate_bytes.min(replacement_requested_limit),
                max_output_capacity_bytes: limits
                    .intermediate_bytes
                    .min(replacement_capacity_limit),
            },
        )
        .map_err(|error| match &error.source {
            LiteralReplacementErrorSource::Selector(source) => aggregate_execution_error(
                source,
                format!("regex-redux replacement execution failed: {error}"),
            ),
            LiteralReplacementErrorSource::OutputBytesLimit { .. } => ExecutionError::unsupported(
                format!("regex-redux replacement resource refusal: {error}"),
            ),
            LiteralReplacementErrorSource::OutputCapacityBytesLimit { .. } => {
                ExecutionError::unsupported(format!(
                    "regex-redux replacement capacity refusal: {error}"
                ))
            }
            _ => ExecutionError::fault(format!("regex-redux replacement failed: {error}")),
        })?;
    charge_composite_replacement(
        state,
        &replaced,
        replacement_index,
        regex.build_report().retained_capacity_bytes,
        limits,
    )?;
    state.sequence = replaced.into_bytes();
    state.replacement_index = replacement_index
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("regex-redux replacement index overflow"))?;
    if records_clean_length && state.clean_length.replace(state.sequence.len()).is_some() {
        return Err(ExecutionError::fault(
            "regex-redux clean length was recorded twice",
        ));
    }
    Ok(())
}

fn finish_composite_result(
    mut state: CompositeRunState,
    input_length: usize,
    program: &CompositeProgram<'_>,
    limits: CompositeLimits,
) -> Result<CompositeResult, ExecutionError> {
    if state.accounting.stages != program.stages.len() || state.count_seen.iter().any(|seen| !seen)
    {
        return Err(ExecutionError::fault(
            "regex-redux composite did not publish every stage output",
        ));
    }
    let clean_length = state.clean_length.ok_or_else(|| {
        ExecutionError::fault("regex-redux composite did not record clean length")
    })?;
    let report_bytes = composite_report_length(
        &program.count_labels,
        &state.counts,
        input_length,
        clean_length,
        state.sequence.len(),
    )?;
    composite_enforce(
        composite_u64(report_bytes, "report bytes")?,
        composite_u64(limits.report_bytes, "report limit")?,
        "report bytes",
    )?;
    let mut report = String::new();
    report
        .try_reserve_exact(report_bytes)
        .map_err(|_| ExecutionError::fault("regex-redux report allocation failed"))?;
    let report_capacity = report.capacity();
    composite_enforce(
        composite_u64(report_capacity, "report capacity bytes")?,
        composite_u64(limits.report_capacity_bytes, "report capacity limit")?,
        "report capacity bytes",
    )?;
    state.accounting.report_capacity_bytes = report_capacity;
    state.accounting.capacity_bytes = composite_checked_add(
        state.accounting.capacity_bytes,
        composite_u64(report_capacity, "report capacity bytes")?,
        "observed capacity bytes",
    )?;
    let live = composite_usize_add(
        state.sequence.capacity(),
        report_capacity,
        "report owned peak",
    )?;
    state.accounting.owned_peak_bytes = state.accounting.owned_peak_bytes.max(live);
    enforce_composite_runtime(&state.accounting, limits)?;
    for (pattern, count) in program.count_labels.iter().zip(state.counts) {
        writeln!(&mut report, "{pattern} {count}")
            .map_err(|error| ExecutionError::fault(format!("format regex-redux: {error}")))?;
    }
    writeln!(
        &mut report,
        "\n{input_length}\n{clean_length}\n{}",
        state.sequence.len()
    )
    .map_err(|error| ExecutionError::fault(format!("format regex-redux: {error}")))?;
    if report.len() != report_bytes || report.capacity() != report_capacity {
        return Err(ExecutionError::fault(
            "regex-redux report preflight length mismatch",
        ));
    }
    state.accounting.report_bytes = report_bytes;
    state.accounting.allocation_bytes = composite_checked_add(
        state.accounting.allocation_bytes,
        composite_u64(report_bytes, "report allocation")?,
        "allocation bytes",
    )?;
    enforce_composite_runtime(&state.accounting, limits)?;
    Ok(CompositeResult {
        counts: state.counts,
        input_length,
        clean_length,
        final_bytes: state.sequence,
        report,
        accounting: state.accounting,
    })
}

fn run_fre_composite(
    input: &[u8],
    stages: &[CompositeStage],
    run_limits: &RunLimits,
    limits: CompositeLimits,
) -> Result<CompositeResult, ExecutionError> {
    let program = CompositeProgram::authenticate(stages)?;
    let accounting = composite_preflight(input.len(), &program, run_limits, limits)?;
    std::str::from_utf8(input)
        .map_err(|error| ExecutionError::fault(format!("regex-redux haystack UTF-8: {error}")))?;
    let mut sequence = Vec::new();
    sequence
        .try_reserve_exact(input.len())
        .map_err(|_| ExecutionError::fault("regex-redux initial allocation failed"))?;
    let initial_capacity = sequence.capacity();
    composite_enforce(
        composite_u64(initial_capacity, "initial capacity bytes")?,
        composite_u64(limits.initial_capacity_bytes, "initial capacity limit")?,
        "initial capacity bytes",
    )?;
    let mut accounting = accounting;
    accounting.allocation_bytes = composite_u64(input.len(), "initial allocation bytes")?;
    accounting.capacity_bytes = composite_u64(initial_capacity, "initial capacity bytes")?;
    accounting.initial_capacity_bytes = initial_capacity;
    accounting.current_sequence_capacity_bytes = initial_capacity;
    accounting.owned_peak_bytes = initial_capacity;
    enforce_composite_runtime(&accounting, limits)?;
    sequence.extend_from_slice(input);
    let mut state = CompositeRunState {
        sequence,
        clean_length: None,
        counts: [0_u64; 9],
        count_seen: [false; 9],
        replacement_index: 0,
        accounting,
    };
    for stage in program.stages {
        match *stage {
            CompositeStage::Count { pattern, output } => {
                execute_composite_count_stage(&mut state, pattern, output, run_limits, limits)?;
            }
            replacement @ CompositeStage::ReplaceAllLiteral { .. } => {
                execute_composite_replacement_stage(&mut state, replacement, run_limits, limits)?;
            }
        }
        state.accounting.stages = state
            .accounting
            .stages
            .checked_add(1)
            .ok_or_else(|| ExecutionError::fault("regex-redux stage counter overflow"))?;
    }
    finish_composite_result(state, input.len(), &program, limits)
}

fn fre_regex_redux(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if !request.patterns.is_empty() || request.unicode || request.case_insensitive {
        return Err(ExecutionError::unsupported(
            "regex-redux requires an empty external pattern list, Unicode off and case sensitivity",
        ));
    }
    let result = run_fre_composite(
        request.haystack,
        &REGEX_REDUX_STAGES,
        limits,
        composite_limits(limits)?,
    )?;
    if result.input_length != request.haystack.len()
        || result.report.len() != result.accounting.report_bytes
        || result.accounting.stages != REGEX_REDUX_STAGES.len()
        || result.counts.iter().copied().sum::<u64>() > result.accounting.match_events
        || result.clean_length > result.input_length
    {
        return Err(ExecutionError::fault(
            "regex-redux completed result failed its publication invariants",
        ));
    }
    let actual = composite_u64(result.final_bytes.len(), "final length")?;
    Ok(FreReduction {
        actual,
        plan: "regex-redux-sequential-composite-v1",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreReduction {
    actual: u64,
    plan: &'static str,
}

fn fre_reducer(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    match request.model {
        "regex-redux" => fre_regex_redux(request, limits),
        "compile" => fre_compile_verify(request, limits),
        "count" => fre_aggregate_count(request, limits),
        "count-spans" => fre_aggregate_span_sum(request, limits),
        "count-captures" => fre_count_captures(request, limits),
        "grep" => fre_grep(request, limits),
        "grep-captures" => fre_grep_captures(request, limits),
        other => Err(ExecutionError::unsupported(format!(
            "current FRE facade has no certified {other} operation"
        ))),
    }
}

/// Construct a fresh complete production artifact, then use it only for the
/// compile model's untimed semantic verification. Candidate adapter calls do
/// not retain this value, so samples cannot share warmed state.
fn fre_compile_verify(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if request.patterns.len() != 1 {
        return fre_aggregate_many_compile(request, limits);
    }
    let pattern = one_fre_pattern(request)?;
    let regex = AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_build_limits(limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_compile()
        .map_err(|error| aggregate_build_error(&error))?;
    require_unicode_plan_identity(
        regex.build_report(),
        request.unicode,
        LiteralAggregateOperation::Count,
    )?;
    let operation_limits = compile_run_limits_with_policy(request.haystack.len(), &regex, limits)?;
    let operation_limits = &operation_limits;
    let result = regex
        .verify_count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE compiled artifact failed untimed verification: {error}");
            aggregate_attempt_error(&error, message)
        })?;
    let plan = aggregate_single_plan_label("compile", regex.build_report());
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
}

fn capture_build_error(error: &CaptureBuildError) -> ExecutionError {
    let message = format!("FRE capture build refused input: {error}");
    match error {
        CaptureBuildError::Unsupported(_)
        | CaptureBuildError::HirResource { .. }
        | CaptureBuildError::Engine(fre::CaptureEngineBuildError::Resource { .. })
        | CaptureBuildError::Selector(
            fre::AggregateEngineError::Unsupported(_)
            | fre::AggregateEngineError::ResourceLimit { .. },
        )
        | CaptureBuildError::RequiredLiteral(
            fre::CaptureRequiredLiteralBuildError::Resource { .. }
            | fre::CaptureRequiredLiteralBuildError::Allocation { .. }
            | fre::CaptureRequiredLiteralBuildError::LiteralSet(_),
        )
        | CaptureBuildError::Syntax(_) => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn direct_capture_invocation(
    regex: &CaptureRegex,
    haystack_len: usize,
    run_limits: &CaptureRunLimits,
) -> Option<(
    fre::PrefixClassUniformParticipationIdentity,
    fre::PrefixClassUniformParticipationInvocation,
)> {
    let identity = regex
        .build_report()
        .plan_identity
        .prefix_class_participation?;
    let schema = fre::PrefixClassUniformParticipationSchema {
        participating_with_overall: identity.kernel.participating_with_overall,
        capture_schema_slots: identity.kernel.capture_schema_slots,
    };
    Some((
        identity.kernel,
        fre::PrefixClassUniformParticipationInvocation {
            haystack_bytes: haystack_len,
            schema,
            limits: run_limits.prefix_class_participation,
        },
    ))
}

fn authenticates_direct_capture_error(
    regex: &CaptureRegex,
    haystack_len: usize,
    run_limits: &CaptureRunLimits,
    error: &fre::CaptureExecutionError,
) -> bool {
    if error.identity != regex.cache_identity(*run_limits) {
        return false;
    }
    let Some((identity, invocation)) = direct_capture_invocation(regex, haystack_len, run_limits)
    else {
        return error.prefix_class_participation_receipt.is_none();
    };
    let Some(receipt) = error.prefix_class_participation_receipt.as_ref() else {
        return false;
    };
    let Ok(Some(expected_prospective)) =
        regex.retained_prefix_class_participation_prospective(haystack_len)
    else {
        return false;
    };
    identity.algorithm_version == 1
        && identity.accounting_version == 2
        && receipt.authenticates(identity, invocation)
        && receipt.retains_bounded_actual()
        && receipt.prospective == Some(expected_prospective)
        && receipt.actual_allocations
            <= receipt
                .prospective
                .map_or(0, |prospective| prospective.operation_allocations)
}

fn authenticates_direct_capture_success(
    regex: &CaptureRegex,
    haystack_len: usize,
    run_limits: &CaptureRunLimits,
    result: &fre::CaptureExecutionReport,
) -> bool {
    if result.identity != regex.cache_identity(*run_limits) {
        return false;
    }
    let Some((identity, invocation)) = direct_capture_invocation(regex, haystack_len, run_limits)
    else {
        return result.prefix_class_participation.is_none()
            && result.prefix_class_participation_receipt.is_none();
    };
    let (Some(accounting), Some(receipt)) = (
        result.prefix_class_participation.as_ref(),
        result.prefix_class_participation_receipt.as_ref(),
    ) else {
        return false;
    };
    let Ok(Some(expected_prospective)) =
        regex.retained_prefix_class_participation_prospective(haystack_len)
    else {
        return false;
    };
    identity.algorithm_version == 1
        && identity.accounting_version == 2
        && receipt.authenticates(identity, invocation)
        && accounting.closes_receipt(receipt)
        && result.accounting.matches == receipt.actual.results
        && result.accounting.count == receipt.actual.capture_count
        && result.capture_events == receipt.actual.capture_events
        && receipt.prospective.is_some_and(|prospective| {
            prospective == expected_prospective
                && prospective.haystack_bytes == haystack_len
                && prospective.operation_allocations == 0
                && receipt.actual.operation_allocations == 0
                && receipt.actual_allocations == 0
        })
}

fn capture_execution_error(
    regex: &CaptureRegex,
    haystack_len: usize,
    run_limits: &CaptureRunLimits,
    error: &fre::CaptureExecutionError,
    message: String,
) -> ExecutionError {
    if !authenticates_direct_capture_error(regex, haystack_len, run_limits, error) {
        return ExecutionError::fault(format!(
            "{message}; FRE capture terminal receipt failed identity/P/A authentication"
        ));
    }
    match &error.source {
        CaptureExecutionSource::PrefixClassParticipation(
            fre::PrefixClassUniformParticipationError::WorkLimit { .. }
            | fre::PrefixClassUniformParticipationError::FirstFinderBytesLimit { .. }
            | fre::PrefixClassUniformParticipationError::SecondFinderBytesLimit { .. }
            | fre::PrefixClassUniformParticipationError::PrefixCandidatesLimit { .. }
            | fre::PrefixClassUniformParticipationError::StartArbitrationsLimit { .. }
            | fre::PrefixClassUniformParticipationError::FirstClassProbesLimit { .. }
            | fre::PrefixClassUniformParticipationError::GreedyExtensionReadsLimit { .. }
            | fre::PrefixClassUniformParticipationError::ResultsLimit { .. }
            | fre::PrefixClassUniformParticipationError::CaptureCountLimit { .. }
            | fre::PrefixClassUniformParticipationError::CaptureEventsLimit { .. }
            | fre::PrefixClassUniformParticipationError::OperationAllocationsLimit { .. }
            | fre::PrefixClassUniformParticipationError::OperationBytesLimit { .. }
            | fre::PrefixClassUniformParticipationError::ScratchLimit { .. }
            | fre::PrefixClassUniformParticipationError::PeakLimit { .. },
        )
        | CaptureExecutionSource::CombinedPeak { .. } => ExecutionError::unsupported(message),
        CaptureExecutionSource::Selector(source) => aggregate_engine_error(source, message),
        CaptureExecutionSource::History(CaptureSearchError::Resource { .. })
        | CaptureExecutionSource::Stream(fre::CaptureStreamError::Resource { .. }) => {
            ExecutionError::unsupported(message)
        }
        CaptureExecutionSource::PrefixClassParticipation(_)
        | CaptureExecutionSource::History(_)
        | CaptureExecutionSource::Stream(_)
        | CaptureExecutionSource::InternalInvariant(_) => ExecutionError::fault(message),
    }
}

fn capture_regex(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<CaptureRegex, ExecutionError> {
    let pattern = one_fre_pattern(request)?;
    capture_regex_one(pattern, request.unicode, request.case_insensitive, limits)
}

fn capture_regex_one(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> Result<CaptureRegex, ExecutionError> {
    capture_regex_one_with_build_limits(
        pattern,
        unicode,
        case_insensitive,
        &capture_build_limits(limits),
    )
}

fn capture_regex_one_with_build_limits(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    build_limits: &CaptureBuildLimits,
) -> Result<CaptureRegex, ExecutionError> {
    let regex = CaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .limits(*build_limits)
        .build()
        .map_err(|error| capture_build_error(&error))?;
    let identity = &regex.build_report().plan_identity;
    if identity.operation != CaptureOperation::CountParticipatingNonempty
        || !matches!(
            identity.plan,
            CapturePlanKind::UniformPrefixClassParticipation
                | CapturePlanKind::OrderedRootCaptureManyCount
                | CapturePlanKind::LinearSelectorUniformParticipation
                | CapturePlanKind::LinearSelectorParticipationQuotientV1
                | CapturePlanKind::LinearSelectorPersistentHistory
                | CapturePlanKind::FusedCaptureStreamParticipationV1
                | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1
        )
    {
        return Err(ExecutionError::fault(
            "FRE capture builder returned an unexpected plan identity",
        ));
    }
    Ok(regex)
}

fn capture_grep_regex_one(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> Result<CaptureRegex, ExecutionError> {
    let mut build_limits = capture_build_limits(limits);
    build_limits.required_literal = Some(capture_required_literal_build_limits(limits));
    capture_regex_one_with_build_limits(pattern, unicode, case_insensitive, &build_limits)
}

fn capture_required_literal_build_limits(limits: &RunLimits) -> CaptureRequiredLiteralBuildLimits {
    let mut build = CaptureRequiredLiteralBuildLimits::default();
    build.max_planner_work = limits.fre_literal_planner_work;
    build.max_needle_bytes = build
        .max_needle_bytes
        .min(limits.fre_literal_build_needle_bytes);
    build.max_source_bytes = build
        .max_source_bytes
        .min(limits.fre_literal_build_persistent_bytes);
    build.max_scratch_bytes = build
        .max_scratch_bytes
        .min(limits.fre_literal_build_scratch_bytes);
    build.max_peak_bytes = build
        .max_peak_bytes
        .min(limits.fre_literal_build_peak_bytes);
    build.literal_set.max_patterns = build.max_needles;
    build.literal_set.max_pattern_bytes = build.max_needle_bytes;
    build.literal_set.max_build_work = usize::try_from(limits.fre_literal_build_work)
        .unwrap_or(usize::MAX)
        .min(build.literal_set.max_build_work);
    build.literal_set.max_build_bytes = build
        .literal_set
        .max_build_bytes
        .min(limits.fre_literal_build_peak_bytes);
    build.literal_set.max_persistent_bytes = build
        .literal_set
        .max_persistent_bytes
        .min(limits.fre_literal_build_persistent_bytes);
    build
}

fn capture_plan_label(regex: &CaptureRegex) -> &'static str {
    if active_capture_required_literal_plan(regex).is_some() {
        return CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN;
    }
    match regex.build_report().plan_identity.plan {
        CapturePlanKind::OrderedRootCaptureManyCount => CURRENT_FRE_CAPTURE_ORDERED_ROOT_COUNT_PLAN,
        CapturePlanKind::UniformPrefixClassParticipation => CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN,
        CapturePlanKind::LinearSelectorUniformParticipation => CURRENT_FRE_CAPTURE_UNIFORM_PLAN,
        CapturePlanKind::LinearSelectorParticipationQuotientV1
        | CapturePlanKind::FusedCaptureStreamParticipationV1 => {
            CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN
        }
        CapturePlanKind::LinearSelectorPersistentHistory
        | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1 => CURRENT_FRE_CAPTURE_PLAN,
    }
}

const fn capture_stream_plan_label(projection: CaptureStreamProjection) -> &'static str {
    match projection {
        CaptureStreamProjection::ParticipationMask => CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN,
        CaptureStreamProjection::PersistentHistory => CURRENT_FRE_CAPTURE_STREAM_HISTORY_PLAN,
    }
}

fn capture_grep_plan_label(regex: &CaptureRegex) -> &'static str {
    capture_plan_label(regex)
}

fn active_capture_required_literal_plan(
    regex: &CaptureRegex,
) -> Option<&CaptureRequiredLiteralPlan> {
    regex.required_literal_plan()
}

fn capture_build_limits(limits: &RunLimits) -> CaptureBuildLimits {
    let defaults = CaptureBuildLimits::default();
    let engine = fre::CaptureEngineBuildLimits {
        max_compile_work: limits.fre_aggregate_compile_work,
        max_program_bytes: limits.fre_aggregate_program_bytes,
        ..defaults.engine
    };
    let selector = fre::AggregateCompileLimits {
        max_work: limits.fre_aggregate_compile_work,
        max_program_bytes: limits.fre_capture_selector_program_bytes,
        ..defaults.selector
    };
    CaptureBuildLimits {
        max_hir_work: limits.fre_aggregate_compile_work,
        engine,
        selector,
        max_prefix_class_participation_planner_work: limits.fre_literal_planner_work,
        prefix_class_participation: PrefixClassUniformParticipationBuildLimits {
            max_shape_units: limits.pattern_bytes_per_job,
            max_build_work: limits.fre_aggregate_compile_work,
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_aggregate_program_bytes,
            max_peak_bytes: limits.fre_aggregate_peak_bytes,
            max_allocations: 3,
            max_copied_prefix_bytes: limits.pattern_bytes_per_job,
            max_finder_preprocess_input_bytes: limits.pattern_bytes_per_job,
            max_initialized_bitmap_bytes: 64,
            max_initialized_run_scanner_bytes: defaults
                .prefix_class_participation
                .max_initialized_run_scanner_bytes,
            max_retained_capacity_bytes: limits.fre_aggregate_program_bytes,
        },
        ..defaults
    }
}

fn project_direct_capture_run_limits(
    prospective: Option<fre::PrefixClassUniformParticipationProspective>,
    haystack_len: usize,
    selector_work: usize,
    selector_sequential_bytes: usize,
    reducer_events: usize,
    reducer_count: usize,
    limits: &RunLimits,
) -> Result<fre::PrefixClassUniformParticipationLimits, ExecutionError> {
    let (
        first_finder_bytes,
        second_finder_bytes,
        prefix_candidates,
        start_arbitrations,
        first_class_probes,
        greedy_extension_reads,
        results,
        capture_count,
        capture_events,
        work,
        operation_allocations,
        operation_bytes,
        scratch_bytes,
        peak_bytes,
    ) = if let Some(prospective) = prospective {
        if prospective.haystack_bytes != haystack_len {
            return Err(ExecutionError::fault(
                "FRE retained direct-capture envelope changed its source length",
            ));
        }
        (
            prospective.first_finder_bytes,
            prospective.second_finder_bytes,
            prospective.prefix_candidates,
            prospective.start_arbitrations,
            prospective.first_class_probes,
            prospective.greedy_extension_reads,
            prospective.results,
            prospective.capture_count,
            prospective.capture_events,
            prospective.work,
            prospective.operation_allocations,
            prospective.operation_bytes,
            prospective.scratch_bytes,
            prospective.peak_bytes,
        )
    } else {
        (
            haystack_len,
            haystack_len,
            checked_aggregate_mul(haystack_len, 2, "direct capture prefix candidates")?,
            checked_aggregate_mul(haystack_len, 4, "direct capture start arbitrations")?,
            checked_aggregate_mul(haystack_len, 2, "direct capture first-class probes")?,
            checked_aggregate_mul(haystack_len, 2, "direct capture greedy extension reads")?,
            haystack_len,
            reducer_count,
            reducer_events,
            selector_work,
            0,
            0,
            0,
            limits.fre_aggregate_peak_bytes,
        )
    };
    let finder_bytes = checked_aggregate_add(
        first_finder_bytes,
        second_finder_bytes,
        "direct capture finder source bytes",
    )?;
    let (max_first_finder_bytes, max_second_finder_bytes) =
        if finder_bytes <= selector_sequential_bytes {
            (first_finder_bytes, second_finder_bytes)
        } else {
            (0, 0)
        };
    Ok(fre::PrefixClassUniformParticipationLimits {
        max_work: work.min(selector_work),
        max_first_finder_bytes,
        max_second_finder_bytes,
        max_prefix_candidates: prefix_candidates,
        max_start_arbitrations: start_arbitrations,
        max_first_class_probes: first_class_probes,
        max_greedy_extension_reads: greedy_extension_reads,
        max_results: results,
        max_capture_count: capture_count.min(reducer_count),
        max_capture_events: capture_events.min(reducer_events),
        max_operation_allocations: operation_allocations,
        max_operation_bytes: operation_bytes,
        max_scratch_bytes: scratch_bytes,
        max_peak_bytes: peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "independent capture reducer ledgers remain explicit at each line invocation"
)]
fn capture_run_limits(
    regex: &CaptureRegex,
    haystack_len: usize,
    selector_shape: ContinuationProgramShape,
    selector_work: usize,
    selector_sequential_bytes: usize,
    reducer_events: usize,
    reducer_count: usize,
    state_visits: usize,
    history_nodes: usize,
    history_walk: usize,
    limits: &RunLimits,
) -> Result<CaptureRunLimits, ExecutionError> {
    let searches = checked_aggregate_add(haystack_len, 1, "capture searches")?;
    let search_work = usize::try_from(limits.fre_search_work)
        .map_err(|_| ExecutionError::fault("FRE capture search work does not fit usize"))?;
    let mut selector = continuation_operation_limits(haystack_len, selector_shape, limits)?;
    let boundaries = checked_aggregate_add(haystack_len, 1, "capture selector boundaries")?;
    selector.max_output_bytes = checked_aggregate_mul(
        boundaries,
        core::mem::size_of::<fre::AggregateSpan>(),
        "capture selector output bytes",
    )?
    .min(limits.fre_aggregate_peak_bytes);
    selector.max_sequential_bytes = selector_sequential_bytes;
    selector.max_peak_bytes = limits.fre_aggregate_peak_bytes;
    selector.max_work = selector_work;
    let direct_prospective = regex
        .retained_prefix_class_participation_prospective(haystack_len)
        .map_err(|error| {
            ExecutionError::fault(format!(
                "FRE retained direct-capture preflight failed: {error}"
            ))
        })?;
    let report_has_direct_identity = regex
        .build_report()
        .plan_identity
        .prefix_class_participation
        .is_some();
    let report_has_direct_build = regex.build_report().prefix_class_participation.is_some();
    let report_selects_direct =
        regex.build_report().plan_identity.plan == CapturePlanKind::UniformPrefixClassParticipation;
    if report_has_direct_identity != report_has_direct_build
        || report_has_direct_identity != report_selects_direct
        || report_has_direct_identity != direct_prospective.is_some()
    {
        return Err(ExecutionError::fault(
            "FRE retained direct-capture owner/report binding is absent or transplanted",
        ));
    }
    let prefix_class_participation = project_direct_capture_run_limits(
        direct_prospective,
        haystack_len,
        selector_work,
        selector_sequential_bytes,
        reducer_events,
        reducer_count,
        limits,
    )?;
    Ok(CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            per_search: CaptureSearchLimits {
                max_state_visits: state_visits.min(search_work),
                max_slot_copies: 0,
                max_history_nodes: history_nodes.min(search_work),
                max_history_walk: history_walk.min(search_work),
                max_scratch_bytes: limits.fre_scratch_bytes,
            },
            max_searches: searches,
            max_results: haystack_len,
            max_total_state_visits: state_visits,
            max_total_slot_copies: 0,
            max_total_history_nodes: history_nodes,
            max_total_history_walk: history_walk,
            max_capture_events: reducer_events,
            max_capture_count: reducer_count,
            max_retained_output_bytes: limits.fre_aggregate_peak_bytes,
            max_combined_peak_bytes: limits.fre_aggregate_peak_bytes,
        },
        selector,
        max_combined_peak_bytes: limits.fre_aggregate_peak_bytes,
        prefix_class_participation,
    })
}

fn capture_reducer_budget(limits: &RunLimits) -> Result<(usize, usize), ExecutionError> {
    let reducer = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE capture reducer limit does not fit usize"))?;
    Ok((reducer, limits.fre_aggregate_operation_work))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CaptureSelectorLedger {
    work: usize,
    sequential_bytes: usize,
}

impl CaptureSelectorLedger {
    fn preflight_lf_scan(haystack_len: usize, limits: &RunLimits) -> Result<Self, ExecutionError> {
        if haystack_len > limits.fre_aggregate_operation_work {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures LF scan requires {haystack_len} work, limit is {}",
                limits.fre_aggregate_operation_work
            )));
        }
        if haystack_len > limits.fre_aggregate_sequential_bytes {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures LF scan requires {haystack_len} sequential bytes, limit is {}",
                limits.fre_aggregate_sequential_bytes
            )));
        }
        Ok(Self {
            work: haystack_len,
            sequential_bytes: haystack_len,
        })
    }

    fn preflight_lf_and_required_literal(
        haystack_len: usize,
        prefilter_transitions: usize,
        prefilter_match_events: usize,
        limits: &RunLimits,
    ) -> Result<Self, ExecutionError> {
        let scan_work = checked_aggregate_add(
            haystack_len,
            prefilter_transitions,
            "grep-captures LF and required-literal work",
        )?;
        let work = checked_aggregate_add(
            scan_work,
            prefilter_match_events,
            "grep-captures required-literal match-event work",
        )?;
        let sequential_bytes = checked_aggregate_mul(
            haystack_len,
            2,
            "grep-captures LF and required-literal sequential bytes",
        )?;
        if work > limits.fre_aggregate_operation_work {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures LF and required-literal scans require {work} work, limit is {}",
                limits.fre_aggregate_operation_work
            )));
        }
        if sequential_bytes > limits.fre_aggregate_sequential_bytes {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures LF and required-literal scans require {sequential_bytes} sequential bytes, limit is {}",
                limits.fre_aggregate_sequential_bytes
            )));
        }
        Ok(Self {
            work,
            sequential_bytes,
        })
    }

    fn remaining(self, limits: &RunLimits) -> Result<(usize, usize), ExecutionError> {
        let work = limits
            .fre_aggregate_operation_work
            .checked_sub(self.work)
            .ok_or_else(|| ExecutionError::fault("FRE selector work accounting underflow"))?;
        let sequential = limits
            .fre_aggregate_sequential_bytes
            .checked_sub(self.sequential_bytes)
            .ok_or_else(|| ExecutionError::fault("FRE selector sequential accounting underflow"))?;
        Ok((work, sequential))
    }

    fn charge(
        &mut self,
        work: usize,
        written: usize,
        read: usize,
        limits: &RunLimits,
    ) -> Result<(), ExecutionError> {
        self.work = checked_aggregate_add(self.work, work, "capture selector work")?;
        let line_sequential =
            checked_aggregate_add(written, read, "capture selector line sequential bytes")?;
        self.sequential_bytes = checked_aggregate_add(
            self.sequential_bytes,
            line_sequential,
            "capture selector sequential bytes",
        )?;
        if self.work > limits.fre_aggregate_operation_work
            || self.sequential_bytes > limits.fre_aggregate_sequential_bytes
        {
            return Err(ExecutionError::fault(
                "FRE selector exceeded its cumulative public-operation ledger",
            ));
        }
        Ok(())
    }
}

fn fre_count_captures(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if request.patterns.len() != 1 {
        return fre_aggregate_many_capture_count(request, limits);
    }
    if let Some((regex, participating)) = uniform_capture_scalar_regex(request, limits) {
        let actual =
            execute_uniform_capture_scalar(&regex, participating, request.haystack, false, limits)?;
        return Ok(FreReduction {
            actual,
            plan: CURRENT_FRE_CAPTURE_SCALAR_PLAN,
        });
    }
    let regex = capture_regex(request, limits)?;
    let plan = capture_plan_label(&regex);
    let actual = execute_count_captures(&regex, request.haystack, limits)?;
    Ok(FreReduction { actual, plan })
}

fn execute_count_captures(
    regex: &CaptureRegex,
    haystack: &[u8],
    limits: &RunLimits,
) -> Result<u64, ExecutionError> {
    let run_limits = capture_count_run_limits(regex, haystack.len(), limits)?;
    execute_count_captures_with_limits(regex, haystack, &run_limits)
}

fn capture_count_run_limits(
    regex: &CaptureRegex,
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<CaptureRunLimits, ExecutionError> {
    let (reducer, work) = capture_reducer_budget(limits)?;
    capture_run_limits(
        regex,
        haystack_len,
        regex.build_report().selector.into(),
        work,
        limits.fre_aggregate_sequential_bytes,
        reducer,
        reducer,
        work,
        work,
        work,
        limits,
    )
}

fn execute_count_captures_with_limits(
    regex: &CaptureRegex,
    haystack: &[u8],
    run_limits: &CaptureRunLimits,
) -> Result<u64, ExecutionError> {
    let result = regex
        .count_captures(haystack, *run_limits)
        .map_err(|error| {
            capture_execution_error(
                regex,
                haystack.len(),
                run_limits,
                &error,
                format!("FRE capture reducer refused execution: {error}"),
            )
        })?;
    if !authenticates_direct_capture_success(regex, haystack.len(), run_limits, &result) {
        return Err(ExecutionError::fault(
            "FRE capture result failed identity/P/A authentication",
        ));
    }
    u64::try_from(result.accounting.count)
        .map_err(|_| ExecutionError::fault("FRE capture count does not fit u64"))
}

fn fre_grep_captures(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if let Some(regex) = noqa_grep_capture_regex(request, limits)? {
        let actual = execute_noqa_grep_captures(&regex, request.haystack, limits)?;
        return Ok(FreReduction {
            actual,
            plan: regex.build_report().plan_identity.plan_id,
        });
    }
    if let Some(reduction) = ruff_line_capture_reduction(request, limits)? {
        return Ok(reduction);
    }
    if let Some(reduction) = anchored_line_capture_reduction(request, limits)? {
        return Ok(reduction);
    }
    if let Some((regex, participating)) = uniform_capture_scalar_regex(request, limits) {
        let actual =
            execute_uniform_capture_scalar(&regex, participating, request.haystack, true, limits)?;
        return Ok(FreReduction {
            actual,
            plan: CURRENT_FRE_CAPTURE_SCALAR_PLAN,
        });
    }
    let pattern = one_fre_pattern(request)?;
    let regex = capture_grep_regex_one(pattern, request.unicode, request.case_insensitive, limits)?;
    let report = execute_grep_captures_inner(
        active_capture_required_literal_plan(&regex),
        &regex,
        request.haystack,
        limits,
    )?;
    let plan = report
        .stream_projection
        .map_or_else(|| capture_plan_label(&regex), capture_stream_plan_label);
    Ok(FreReduction {
        actual: report.count,
        plan,
    })
}

fn noqa_grep_capture_regex(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<Option<NoqaGrepCaptureRegex>, ExecutionError> {
    if request.patterns.len() != 1 {
        return Ok(None);
    }
    noqa_grep_capture_regex_one(
        request.patterns[0].as_str(),
        request.unicode,
        request.case_insensitive,
        limits,
    )
}

fn noqa_grep_capture_regex_one(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> Result<Option<NoqaGrepCaptureRegex>, ExecutionError> {
    let regex = NoqaGrepCaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .limits(NoqaBuildLimits {
            max_work: limits.fre_literal_planner_work,
            ..NoqaBuildLimits::default()
        })
        .build();
    match regex {
        Ok(regex) => Ok(Some(regex)),
        Err(NoqaBuildError::Syntax(_) | NoqaBuildError::Unsupported) => Ok(None),
        Err(
            error @ (NoqaBuildError::WorkLimit { .. } | NoqaBuildError::AllocationLimit { .. }),
        ) => Err(ExecutionError::unsupported(format!(
            "FRE noqa grep-capture build refused input: {error}"
        ))),
        Err(error @ (NoqaBuildError::Overflow | NoqaBuildError::InternalInvariant(_))) => Err(
            ExecutionError::fault(format!("FRE noqa grep-capture build faulted: {error}")),
        ),
    }
}

fn noqa_run_limits(limits: &RunLimits) -> Result<NoqaRunLimits, ExecutionError> {
    let reducer = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE noqa reducer limit does not fit usize"))?;
    Ok(NoqaRunLimits {
        max_work: limits.fre_aggregate_operation_work,
        max_sequential_bytes: limits.fre_aggregate_sequential_bytes,
        max_capture_events: reducer,
        max_capture_count: reducer,
    })
}

fn execute_noqa_grep_captures(
    regex: &NoqaGrepCaptureRegex,
    haystack: &[u8],
    limits: &RunLimits,
) -> Result<u64, ExecutionError> {
    let outcome = regex
        .count_captures(haystack, noqa_run_limits(limits)?)
        .map_err(|error| match error {
            NoqaRunError::Resource { .. } => ExecutionError::unsupported(format!(
                "FRE noqa grep-capture reducer refused execution: {error}"
            )),
            NoqaRunError::Overflow => {
                ExecutionError::fault(format!("FRE noqa grep-capture reducer faulted: {error}"))
            }
        })?;
    u64::try_from(outcome.capture_count)
        .map_err(|_| ExecutionError::fault("FRE noqa capture count does not fit u64"))
}

fn ruff_line_capture_plan_one(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> Result<Option<LineCapturePlan>, ExecutionError> {
    if case_insensitive {
        return Ok(None);
    }
    let plan = match LineCaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode)
        .limits(LineCaptureBuildLimits {
            max_inspection_work: limits.fre_capture_scalar_planner_work,
            ..LineCaptureBuildLimits::default()
        })
        .build()
    {
        Ok(plan) => plan,
        Err(LineCaptureBuildError::Unsupported("source identity" | "Rust profile identity")) => {
            return Ok(None);
        }
        Err(error @ LineCaptureBuildError::Unsupported(_)) => {
            return Err(ExecutionError::fault(format!(
                "FRE exact direct line-capture identity was rejected after selection: {error}"
            )));
        }
        Err(
            error @ (LineCaptureBuildError::InspectionWork { .. }
            | LineCaptureBuildError::Resource { .. }),
        ) => {
            return Err(ExecutionError::unsupported(format!(
                "FRE direct line-capture build refused execution: {error}"
            )));
        }
        Err(error) => {
            return Err(ExecutionError::fault(format!(
                "FRE direct line-capture build returned an unknown failure: {error}"
            )));
        }
    };
    authenticate_ruff_line_capture_plan(&plan)?;
    Ok(Some(plan))
}

type ExpectedLineCaptureIdentity = (
    &'static str,
    fre::LineCaptureConfiguration,
    &'static str,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    bool,
);

fn expected_line_capture_identity(plan: LineCapturePlanKind) -> ExpectedLineCaptureIdentity {
    match plan {
        LineCapturePlanKind::SpaceAroundOperator => (
            SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
            fre::LineCaptureConfiguration::SpaceAroundOperator,
            CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN,
            12,
            10,
            12,
            40,
            2,
            SPACE_AROUND_OPERATOR_INSPECTION_WORK,
            2,
            3,
            2,
            true,
        ),
        LineCapturePlanKind::Shebang => (
            SHEBANG_CAPTURE_PATTERN,
            fre::LineCaptureConfiguration::AnchoredWhitespaceLiteralTail,
            fre::SHEBANG_OPERATION_ID,
            12,
            10,
            9,
            12,
            2,
            SHEBANG_INSPECTION_WORK,
            2,
            3,
            2,
            true,
        ),
        LineCapturePlanKind::StringQuotePrefix => (
            STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
            fre::LineCaptureConfiguration::AnchoredAsciiPrefixQuotedTail,
            fre::STRING_QUOTE_PREFIX_OPERATION_ID,
            8,
            6,
            10,
            12,
            0,
            STRING_QUOTE_PREFIX_INSPECTION_WORK,
            1,
            2,
            2,
            true,
        ),
        LineCapturePlanKind::WhitespaceAroundKeywords => (
            WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
            fre::LineCaptureConfiguration::UnicodeWordKeywordSet,
            fre::WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
            16,
            10,
            45,
            20,
            155,
            WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
            2,
            3,
            2,
            true,
        ),
        LineCapturePlanKind::AnchoredAsciiSeparatedFields => (
            ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN,
            fre::LineCaptureConfiguration::AnchoredAsciiSeparatedFields,
            CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN,
            12,
            10,
            19,
            8,
            17,
            ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK,
            3,
            4,
            20,
            false,
        ),
    }
}

fn authenticate_ruff_line_capture_plan(plan: &LineCapturePlan) -> Result<(), ExecutionError> {
    let report = plan.build_report();
    let (
        source,
        configuration,
        operation_id,
        work_per_input_byte,
        unit_work,
        hir_nodes,
        class_ranges,
        literal_bytes,
        inspection_work,
        explicit_captures,
        participating_groups,
        minimum_match_bytes,
        unicode,
    ) = expected_line_capture_identity(report.identity.plan);
    let plan_bytes = core::mem::size_of::<LineCapturePlan>();
    let mut expected_profile = rebar_profile();
    expected_profile.options.unicode = unicode;
    if report.identity.source != source
        || report.identity.profile != expected_profile
        || report.identity.operation.operation_id != operation_id
        || report.identity.operation.configuration != configuration
        || report.identity.operation.work_per_input_byte != work_per_input_byte
        || report.identity.operation.unit_work != unit_work
        || report.identity.operation.minimum_match_bytes != minimum_match_bytes
        || report.identity.operation.participating_groups_per_match != participating_groups
        || report.hir_nodes != hir_nodes
        || report.class_ranges != class_ranges
        || report.literal_bytes != literal_bytes
        || report.inspection_work != inspection_work
        || report.minimum_match_bytes != minimum_match_bytes
        || report.explicit_captures != explicit_captures
        || report.participating_groups_per_match != participating_groups
        || report.allocations != 0
        || report.scratch_bytes != 0
        || report.persistent_bytes != plan_bytes
        || report.peak_bytes != plan_bytes
    {
        return Err(ExecutionError::fault(
            "FRE direct line-capture plan identity mismatch",
        ));
    }
    Ok(())
}

fn ruff_line_capture_run_limits(
    plan: &LineCapturePlan,
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<LineCaptureRunLimits, ExecutionError> {
    authenticate_ruff_line_capture_plan(plan)?;
    let operation = plan.build_report().identity.operation;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE line-capture reducer limit does not fit usize"))?;
    let work = haystack_len
        .checked_mul(operation.work_per_input_byte)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ExecutionError::fault("FRE line-capture lifecycle work overflow"))?;
    let prospective_captures = haystack_len
        .checked_div(operation.minimum_match_bytes)
        .and_then(|matches| matches.checked_mul(operation.participating_groups_per_match))
        .ok_or_else(|| ExecutionError::fault("FRE line-capture lifecycle capture overflow"))?;
    let prospective_reducer_events = haystack_len
        .checked_add(prospective_captures)
        .ok_or_else(|| ExecutionError::fault("FRE line-capture lifecycle event overflow"))?;
    for (resource, required, limit) in [
        ("ExecutionWork", work, limits.fre_aggregate_operation_work),
        (
            "SequentialBytes",
            haystack_len,
            limits.fre_aggregate_sequential_bytes,
        ),
        ("CaptureCount", prospective_captures, reducer_limit),
        ("ReducerEvents", prospective_reducer_events, reducer_limit),
    ] {
        if required > limit {
            return Err(ExecutionError::unsupported(format!(
                "FRE direct line-capture lifecycle resource {resource} requires {required}, limit is {limit}"
            )));
        }
    }
    Ok(LineCaptureRunLimits {
        max_work: limits.fre_aggregate_operation_work,
        max_sequential_bytes: limits.fre_aggregate_sequential_bytes,
        max_capture_count: reducer_limit,
        max_reducer_events: reducer_limit,
    })
}

fn execute_ruff_line_capture_with_limits(
    plan: &LineCapturePlan,
    haystack: &[u8],
    run_limits: LineCaptureRunLimits,
) -> Result<u64, ExecutionError> {
    let report = plan
        .grep_capture_count(haystack, run_limits)
        .map_err(|error| match error {
            LineCaptureRunError::Resource { .. } => ExecutionError::unsupported(format!(
                "FRE direct line-capture reducer refused execution: {error}"
            )),
            LineCaptureRunError::ArithmeticOverflow(_)
            | LineCaptureRunError::AccountingInvariant { .. } => {
                ExecutionError::fault(format!("FRE direct line-capture reducer faulted: {error}"))
            }
        })?;
    if report.identity != plan.build_report().identity
        || report.sequential_bytes != haystack.len()
        || report.actual_input_loads != haystack.len()
        || report.actual_work > report.work
        || report.scratch_bytes != 0
        || report.output_bytes != 0
        || report.capture_count > report.prospective_capture_count
        || report.reducer_events > report.prospective_reducer_events
    {
        return Err(ExecutionError::fault(
            "FRE direct line-capture execution identity or accounting mismatch",
        ));
    }
    u64::try_from(report.capture_count)
        .map_err(|_| ExecutionError::fault("FRE line-capture count does not fit u64"))
}

fn ruff_line_capture_reduction(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<Option<FreReduction>, ExecutionError> {
    if request.patterns.len() != 1 {
        return Ok(None);
    }
    let Some(plan) = ruff_line_capture_plan_one(
        request.patterns[0].as_str(),
        request.unicode,
        request.case_insensitive,
        limits,
    )?
    else {
        return Ok(None);
    };
    let actual = execute_ruff_line_capture_with_limits(
        &plan,
        request.haystack,
        ruff_line_capture_run_limits(&plan, request.haystack.len(), limits)?,
    )?;
    Ok(Some(FreReduction {
        actual,
        plan: plan.build_report().identity.operation.operation_id,
    }))
}

fn anchored_line_capture_plan_one(
    pattern: &str,
    unicode: bool,
    case_insensitive: bool,
    limits: &RunLimits,
) -> Result<Option<AnchoredLineCapturePlan>, ExecutionError> {
    if unicode || case_insensitive {
        return Ok(None);
    }
    let defaults = AnchoredLineCaptureBuildLimits::default();
    let plan = AnchoredLineCaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(false)
        .case_insensitive(false)
        .limits(AnchoredLineCaptureBuildLimits {
            max_inspection_work: limits.fre_capture_scalar_planner_work,
            max_hir_nodes: limits.fre_aggregate_hir_nodes,
            max_stack_items: limits.fre_aggregate_hir_stack_items,
            max_class_ranges: limits.pattern_bytes_per_job,
            max_literal_bytes: limits.pattern_bytes_per_job,
            max_persistent_bytes: limits.fre_aggregate_program_bytes,
            max_peak_bytes: limits.fre_aggregate_peak_bytes,
            ..defaults
        })
        .build();
    let plan = match plan {
        Ok(plan) => plan,
        Err(
            AnchoredLineCaptureBuildError::Syntax(_)
            | AnchoredLineCaptureBuildError::Unsupported(_),
        ) => return Ok(None),
        Err(error @ AnchoredLineCaptureBuildError::Resource { .. }) => {
            return Err(ExecutionError::unsupported(format!(
                "FRE anchored-line capture build refused execution: {error}"
            )));
        }
        Err(
            error @ (AnchoredLineCaptureBuildError::Kernel(_)
            | AnchoredLineCaptureBuildError::ArithmeticOverflow(_)
            | AnchoredLineCaptureBuildError::InternalInvariant(_)),
        ) => {
            return Err(ExecutionError::fault(format!(
                "FRE anchored-line capture build faulted: {error}"
            )));
        }
        Err(error) => {
            return Err(ExecutionError::fault(format!(
                "FRE anchored-line capture build returned an unknown failure: {error}"
            )));
        }
    };
    authenticate_anchored_line_capture_plan(&plan)?;
    Ok(Some(plan))
}

fn authenticate_anchored_line_capture_plan(
    plan: &AnchoredLineCapturePlan,
) -> Result<(), ExecutionError> {
    let report = plan.build_report();
    let mut expected_profile = rebar_profile();
    expected_profile.options.unicode = false;
    expected_profile.options.case_insensitive = false;
    let plan_bytes = core::mem::size_of::<AnchoredLineCapturePlan>();
    if report.identity.profile != expected_profile
        || report.identity.algorithm_version != ANCHORED_LINE_CAPTURE_ALGORITHM_VERSION
        || report.identity.accounting_version != ANCHORED_LINE_CAPTURE_ACCOUNTING_VERSION
        || report.identity.kernel.plan_id != ANCHORED_LINE_CAPTURE_PLAN_ID
        || report.identity.kernel.operation_id != ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID
        || report.identity.kernel.atom_count != report.hir.emitted_atoms
        || report.identity.kernel.explicit_captures != report.explicit_captures
        || report.identity.kernel.groups_per_match != report.groups_per_match
        || report.identity.kernel.minimum_match_bytes != report.minimum_match_bytes
        || report.hir.captures != report.explicit_captures
        || report.explicit_captures == 0
        || report.groups_per_match != report.explicit_captures.saturating_add(1)
        || report.minimum_match_bytes == 0
        || report.hir.emitted_atoms == 0
        || report.hir.hir_nodes == 0
        || report.hir.inspection_work < report.hir.hir_nodes
        || report.kernel.atom_count != report.hir.emitted_atoms
        || report.kernel.explicit_captures != report.explicit_captures
        || report.kernel.minimum_match_bytes != report.minimum_match_bytes
        || report.kernel.allocations != 0
        || report.kernel.scratch_bytes != 0
        || report.kernel.persistent_bytes == 0
        || report.kernel.peak_bytes != report.kernel.persistent_bytes
        || report.kernel.persistent_bytes > report.persistent_bytes
        || report.persistent_bytes != plan_bytes
        || report.peak_bytes != plan_bytes
    {
        return Err(ExecutionError::fault(
            "FRE anchored-line capture plan identity mismatch",
        ));
    }
    Ok(())
}

fn anchored_line_capture_run_limits(
    plan: &AnchoredLineCapturePlan,
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<AnchoredLineCaptureRunLimits, ExecutionError> {
    authenticate_anchored_line_capture_plan(plan)?;
    let report = plan.build_report();
    let work_per_input = report
        .identity
        .kernel
        .atom_count
        .checked_mul(2)
        .and_then(|value| value.checked_add(5))
        .ok_or_else(|| ExecutionError::fault("anchored-line work coefficient overflow"))?;
    let work = haystack_len
        .checked_mul(work_per_input)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ExecutionError::fault("anchored-line work overflow"))?;
    let lines = haystack_len;
    let matches = lines;
    let capture_count = matches
        .checked_mul(report.groups_per_match)
        .ok_or_else(|| ExecutionError::fault("anchored-line capture bound overflow"))?;
    let reducer_events = lines
        .checked_add(capture_count)
        .ok_or_else(|| ExecutionError::fault("anchored-line event bound overflow"))?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("anchored-line reducer limit does not fit usize"))?;
    for (resource, needed, limit) in [
        ("ExecutionWork", work, limits.fre_aggregate_operation_work),
        (
            "SequentialBytes",
            haystack_len,
            limits.fre_aggregate_sequential_bytes,
        ),
        ("CaptureCount", capture_count, reducer_limit),
        ("ReducerEvents", reducer_events, reducer_limit),
        (
            "PeakBytes",
            report.persistent_bytes,
            limits.fre_aggregate_peak_bytes,
        ),
    ] {
        if needed > limit {
            return Err(ExecutionError::unsupported(format!(
                "FRE anchored-line capture lifecycle resource {resource} requires {needed}, limit is {limit}"
            )));
        }
    }
    Ok(AnchoredLineCaptureRunLimits {
        max_input_bytes: haystack_len,
        max_lines: lines,
        max_matches: matches,
        max_capture_count: capture_count,
        max_reducer_events: reducer_events,
        max_work: work,
        max_sequential_bytes: haystack_len,
        max_peak_bytes: report.persistent_bytes,
    })
}

fn execute_anchored_line_capture_with_limits(
    plan: &AnchoredLineCapturePlan,
    haystack: &[u8],
    run_limits: AnchoredLineCaptureRunLimits,
) -> Result<u64, ExecutionError> {
    let result = plan
        .grep_capture_count(haystack, run_limits)
        .map_err(|error| match error {
            AnchoredLineCaptureRunError::Resource { .. } => ExecutionError::unsupported(format!(
                "FRE anchored-line capture reducer refused execution: {error}"
            )),
            AnchoredLineCaptureRunError::ArithmeticOverflow { .. }
            | AnchoredLineCaptureRunError::AccountingInvariant { .. } => ExecutionError::fault(
                format!("FRE anchored-line capture reducer faulted: {error}"),
            ),
            error => ExecutionError::fault(format!(
                "FRE anchored-line capture reducer returned an unknown failure: {error}"
            )),
        })?;
    let report = plan.build_report();
    if result.identity != report.identity.kernel
        || result.capture_count != result.actual.capture_count
        || result.upper_bounds.input_bytes != haystack.len()
        || result.upper_bounds.sequential_bytes != haystack.len()
        || result.upper_bounds.allocations != 0
        || result.upper_bounds.scratch_bytes != 0
        || result.upper_bounds.output_bytes != 0
        || result.actual.input_loads != haystack.len()
        || result.actual.capture_count > result.upper_bounds.capture_count
        || result.actual.reducer_events > result.upper_bounds.reducer_events
        || result.actual.work > result.upper_bounds.work
        || result.actual.reducer_events
            != result
                .actual
                .line_events
                .saturating_add(result.actual.capture_count)
    {
        return Err(ExecutionError::fault(
            "FRE anchored-line capture execution identity or accounting mismatch",
        ));
    }
    u64::try_from(result.capture_count)
        .map_err(|_| ExecutionError::fault("FRE anchored-line capture count does not fit u64"))
}

fn anchored_line_capture_reduction(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<Option<FreReduction>, ExecutionError> {
    if request.patterns.len() != 1 {
        return Ok(None);
    }
    let Some(plan) = anchored_line_capture_plan_one(
        request.patterns[0].as_str(),
        request.unicode,
        request.case_insensitive,
        limits,
    )?
    else {
        return Ok(None);
    };
    let run_limits = anchored_line_capture_run_limits(&plan, request.haystack.len(), limits)?;
    let actual = execute_anchored_line_capture_with_limits(&plan, request.haystack, run_limits)?;
    Ok(Some(FreReduction {
        actual,
        plan: CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN,
    }))
}

fn uniform_capture_scalar_regex(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Option<(AggregateCountRegex, usize)> {
    if request.patterns.len() != 1 || !request.unicode || request.case_insensitive {
        return None;
    }
    let mut build_limits = aggregate_build_limits(limits);
    build_limits.max_unicode_scalar_planner_work = limits.fre_capture_scalar_planner_work;
    let regex = AggregateBuilder::new(request.patterns[0].as_str())
        .profile(rebar_profile())
        .unicode(true)
        .case_insensitive(false)
        .limits(build_limits)
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .ok()?;
    let AggregatePlanIdentity::UnicodeScalar(identity) = regex.build_report().plan_identity else {
        return None;
    };
    if identity.semantics
        != AggregateUnicodeScalarSemantics::UnicodeOnUniformCapturedAlternationRepeatedUtf8False
        || identity.participating_captures_per_match == 0
        || identity.participating_captures_per_match > regex.build_report().captures_erased
    {
        return None;
    }
    Some((regex, identity.participating_captures_per_match))
}

fn execute_uniform_capture_scalar(
    regex: &AggregateCountRegex,
    participating: usize,
    haystack: &[u8],
    grep: bool,
    limits: &RunLimits,
) -> Result<u64, ExecutionError> {
    let line_scan = if grep {
        Some(CaptureSelectorLedger::preflight_lf_scan(
            haystack.len(),
            limits,
        )?)
    } else {
        None
    };
    let mut operation_limits = count_run_limits_with_policy(haystack.len(), regex, limits)?;
    if let Some(line_scan) = line_scan {
        let (remaining_work, _) = line_scan.remaining(limits)?;
        operation_limits.unicode_scalar.max_work =
            operation_limits.unicode_scalar.max_work.min(remaining_work);
    }
    let result = regex.count(haystack, operation_limits).map_err(|error| {
        aggregate_attempt_error(
            &error,
            format!("FRE uniform capture scalar count refused execution: {error}"),
        )
    })?;
    let matches = result.value();
    let participating_with_overall = participating
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("uniform capture participation overflow"))?;
    let participating_with_overall = u64::try_from(participating_with_overall)
        .map_err(|_| ExecutionError::fault("uniform capture participation does not fit u64"))?;
    let actual = matches
        .checked_mul(participating_with_overall)
        .ok_or_else(|| ExecutionError::fault("uniform capture count overflow"))?;

    let all_groups = regex
        .build_report()
        .captures_erased
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("uniform capture group count overflow"))?;
    let all_groups = u64::try_from(all_groups)
        .map_err(|_| ExecutionError::fault("uniform capture group count does not fit u64"))?;
    let group_events = matches
        .checked_mul(all_groups)
        .ok_or_else(|| ExecutionError::fault("uniform capture event count overflow"))?;
    let line_events = if grep {
        u64::try_from(haystack.lines().count())
            .map_err(|_| ExecutionError::fault("grep line count does not fit u64"))?
    } else {
        0
    };
    let reducer_events = group_events
        .checked_add(line_events)
        .ok_or_else(|| ExecutionError::fault("uniform capture reducer event overflow"))?;
    if reducer_events > limits.reducer_steps || actual > limits.reducer_steps {
        return Err(ExecutionError::unsupported(format!(
            "FRE uniform capture reducer needs {reducer_events} events and count {actual}, limit is {}",
            limits.reducer_steps
        )));
    }
    Ok(actual)
}

fn execute_grep_captures(
    regex: &CaptureRegex,
    haystack: &[u8],
    limits: &RunLimits,
) -> Result<u64, ExecutionError> {
    execute_grep_captures_inner(
        active_capture_required_literal_plan(regex),
        regex,
        haystack,
        limits,
    )
    .map(|report| report.count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GrepCaptureExecutionReport {
    count: u64,
    stream_projection: Option<CaptureStreamProjection>,
    line_domains: usize,
    candidate_domains: usize,
    selector_executions: usize,
    consolidated_prefilter: bool,
    prefilter_transitions: usize,
    prefilter_match_events: usize,
    prefilter_match_events_upper_bound: usize,
    prefilter_sequential_bytes: usize,
    selector: CaptureSelectorLedger,
    state_visits: usize,
    history_nodes: usize,
    history_walk: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "whole-input preflight and exact per-domain generic-selector accounting remain one auditable transaction"
)]
fn execute_grep_captures_inner(
    prefilter: Option<&CaptureRequiredLiteralPlan>,
    regex: &CaptureRegex,
    haystack: &[u8],
    limits: &RunLimits,
) -> Result<GrepCaptureExecutionReport, ExecutionError> {
    let (reducer_limit, work_limit) = capture_reducer_budget(limits)?;
    let groups = regex
        .build_report()
        .engine
        .captures
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE capture group count overflow"))?;
    let mut reducer_events = 0_usize;
    let mut count = 0_usize;
    let fallback_prefilter_transitions = haystack
        .len()
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("required-literal input transition overflow"))?;
    let line_partition_prospective = if let Some(prefilter) = prefilter {
        prefilter
            .line_partition_prospective(haystack.len())
            .map_err(|error| {
                ExecutionError::fault(format!(
                    "FRE required-literal line prospective failed: {error}"
                ))
            })?
    } else {
        None
    };
    let consolidated_prefilter = line_partition_prospective.is_some();
    let prefilter_transition_bound = line_partition_prospective
        .map_or(fallback_prefilter_transitions, |prospective| {
            prospective.transitions_upper_bound
        });
    let prefilter_match_events_upper_bound =
        line_partition_prospective.map_or(0, |prospective| prospective.match_events_upper_bound);
    // `ByteSlice::lines` scans the complete haystack for LF delimiters. Bind
    // that work and sequential read, plus the complete optional DFA pass and
    // every possible iterator emission, before constructing either iterator
    // so one-below callers cannot trigger a partial traversal.
    let mut selector = if prefilter.is_some() {
        CaptureSelectorLedger::preflight_lf_and_required_literal(
            haystack.len(),
            prefilter_transition_bound,
            prefilter_match_events_upper_bound,
            limits,
        )?
    } else {
        CaptureSelectorLedger::preflight_lf_scan(haystack.len(), limits)?
    };
    let mut prefilter_transitions = 0_usize;
    let mut prefilter_sequential = 0_usize;
    let mut prefilter_match_events = 0_usize;
    let mut line_matches = if let Some(prefilter) = prefilter {
        let scan = prefilter
            .line_partition_matches(
                haystack,
                CaptureRequiredLiteralRunLimits {
                    max_transitions: prefilter_transition_bound,
                },
            )
            .map_err(|error| {
                ExecutionError::fault(format!(
                    "FRE required-literal whole-input line scan violated its exact bound: {error}"
                ))
            })?;
        match (line_partition_prospective, scan) {
            (Some(prospective), Some(scan)) => {
                let expected_limits = CaptureRequiredLiteralRunLimits {
                    max_transitions: prefilter_transition_bound,
                };
                let expected_build_limits = capture_required_literal_build_limits(limits);
                if scan.identity().plan != prefilter.build_report().identity
                    || scan.identity().build_limits != expected_build_limits
                    || scan.identity().operation
                        != CaptureRequiredLiteralSearchOperation::LinePartitionMatchesV1
                    || scan.identity().run_limits != expected_limits
                    || scan.accounting() != prospective
                {
                    return Err(ExecutionError::fault(
                        "FRE required-literal line scan failed identity/P/A authentication",
                    ));
                }
                let accounting = scan.accounting();
                prefilter_transitions = accounting.transitions_upper_bound;
                prefilter_sequential = accounting.searched_bytes;
                Some(scan.peekable())
            }
            (None, None) => None,
            _ => {
                return Err(ExecutionError::fault(
                    "FRE required-literal construction proof and line scan disagreed",
                ));
            }
        }
    } else {
        None
    };
    let mut state_visits = 0_usize;
    let mut history_nodes = 0_usize;
    let mut history_walk = 0_usize;
    let mut line_domains = 0_usize;
    let mut candidate_domains = 0_usize;
    let mut selector_executions = 0_usize;
    let mut raw_cursor = 0_usize;
    for raw_line in haystack.lines_with_terminator() {
        let line_start = raw_cursor;
        raw_cursor = raw_cursor
            .checked_add(raw_line.len())
            .ok_or_else(|| ExecutionError::fault("capture raw line cursor overflow"))?;
        let line = if let Some(without_lf) = raw_line.strip_suffix(b"\n") {
            without_lf.strip_suffix(b"\r").unwrap_or(without_lf)
        } else {
            raw_line
        };
        let line_end = line_start
            .checked_add(line.len())
            .ok_or_else(|| ExecutionError::fault("capture semantic line end overflow"))?;
        line_domains = checked_aggregate_add(line_domains, 1, "capture line domains")?;
        reducer_events = checked_aggregate_add(reducer_events, 1, "capture line events")?;
        if reducer_events > reducer_limit {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures line events need {reducer_events}, exceeding {reducer_limit}"
            )));
        }
        let candidate = if let Some(matches) = line_matches.as_mut() {
            let mut candidate = false;
            while matches.peek().is_some_and(|&(start, _)| start < raw_cursor) {
                let (start, end) = matches
                    .next()
                    .ok_or_else(|| ExecutionError::fault("peeked line match disappeared"))?;
                prefilter_match_events = checked_aggregate_add(
                    prefilter_match_events,
                    1,
                    "required-literal match events",
                )?;
                if start < line_start || start >= end || end > line_end {
                    return Err(ExecutionError::fault(
                        "FRE required-literal whole-input match escaped its semantic line",
                    ));
                }
                candidate = true;
            }
            candidate
        } else if let Some(prefilter) = prefilter {
            let transitions = line.len().checked_add(1).ok_or_else(|| {
                ExecutionError::fault("required-literal line transition overflow")
            })?;
            let filtered = prefilter
                .is_candidate(
                    line,
                    CaptureRequiredLiteralRunLimits {
                        max_transitions: transitions,
                    },
                )
                .map_err(|error| {
                    ExecutionError::fault(format!(
                        "FRE required-literal prefilter violated its exact line bound: {error}"
                    ))
                })?;
            prefilter_transitions = checked_aggregate_add(
                prefilter_transitions,
                filtered.accounting.transitions_upper_bound,
                "required-literal cumulative transitions",
            )?;
            prefilter_sequential = checked_aggregate_add(
                prefilter_sequential,
                filtered.accounting.searched_bytes,
                "required-literal cumulative sequential bytes",
            )?;
            filtered.candidate
        } else {
            true
        };
        if !candidate {
            continue;
        }
        candidate_domains =
            checked_aggregate_add(candidate_domains, 1, "capture candidate domains")?;
        let event_remaining = reducer_limit
            .checked_sub(reducer_events)
            .ok_or_else(|| ExecutionError::fault("FRE capture event accounting underflow"))?;
        let count_remaining = reducer_limit
            .checked_sub(count)
            .ok_or_else(|| ExecutionError::fault("FRE grep-capture count underflow"))?;
        let (selector_work_remaining, selector_sequential_remaining) =
            selector.remaining(limits)?;
        let state_remaining = work_limit
            .checked_sub(state_visits)
            .ok_or_else(|| ExecutionError::fault("FRE capture state accounting underflow"))?;
        let node_remaining = work_limit
            .checked_sub(history_nodes)
            .ok_or_else(|| ExecutionError::fault("FRE capture node accounting underflow"))?;
        let walk_remaining = work_limit
            .checked_sub(history_walk)
            .ok_or_else(|| ExecutionError::fault("FRE capture walk accounting underflow"))?;
        let run_limits = capture_run_limits(
            regex,
            line.len(),
            regex.build_report().selector.into(),
            selector_work_remaining,
            selector_sequential_remaining,
            event_remaining,
            count_remaining,
            state_remaining,
            node_remaining,
            walk_remaining,
            limits,
        )?;
        let result = regex.count_captures(line, run_limits).map_err(|error| {
            capture_execution_error(
                regex,
                line.len(),
                &run_limits,
                &error,
                format!("FRE grep-capture reducer refused execution: {error}"),
            )
        })?;
        if !authenticates_direct_capture_success(regex, line.len(), &run_limits, &result) {
            return Err(ExecutionError::fault(
                "FRE grep-capture result failed identity/P/A authentication",
            ));
        }
        selector_executions =
            checked_aggregate_add(selector_executions, 1, "capture selector executions")?;
        let group_events = result
            .accounting
            .matches
            .checked_mul(groups)
            .ok_or_else(|| ExecutionError::fault("FRE grep-capture group events overflow"))?;
        reducer_events =
            checked_aggregate_add(reducer_events, group_events, "capture group events")?;
        if reducer_events > reducer_limit {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures events need {reducer_events}, exceeding {reducer_limit}"
            )));
        }
        count = checked_aggregate_add(count, result.accounting.count, "capture count")?;
        let selector_accounting = result.selector_accounting.as_ref().ok_or_else(|| {
            ExecutionError::fault("FRE grep-capture route returned no selector accounting")
        })?;
        selector.charge(
            selector_accounting.work,
            selector_accounting.sequential_bytes_written,
            selector_accounting.sequential_bytes_read,
            limits,
        )?;
        state_visits = checked_aggregate_add(
            state_visits,
            result.accounting.total_state_visits,
            "capture state visits",
        )?;
        history_nodes = checked_aggregate_add(
            history_nodes,
            result.accounting.total_history_nodes,
            "capture history nodes",
        )?;
        history_walk = checked_aggregate_add(
            history_walk,
            result.accounting.total_history_walk,
            "capture history walk",
        )?;
    }
    if raw_cursor != haystack.len() {
        return Err(ExecutionError::fault(
            "FRE capture line iterator did not consume the complete haystack",
        ));
    }
    if let Some(matches) = line_matches.as_mut()
        && matches.next().is_some()
    {
        return Err(ExecutionError::fault(
            "FRE required-literal whole-input match was not assigned to a semantic line",
        ));
    }
    if prefilter.is_some()
        && (prefilter_transitions > prefilter_transition_bound
            || prefilter_match_events > prefilter_match_events_upper_bound
            || prefilter_sequential > haystack.len())
    {
        return Err(ExecutionError::fault(
            "FRE required-literal prefilter exceeded its prospective whole-input bound",
        ));
    }
    if selector_executions != candidate_domains || candidate_domains > line_domains {
        return Err(ExecutionError::fault(
            "FRE grep-capture selector/domain cardinality invariant failed",
        ));
    }
    let count = u64::try_from(count)
        .map_err(|_| ExecutionError::fault("FRE grep-capture count does not fit u64"))?;
    Ok(GrepCaptureExecutionReport {
        count,
        stream_projection: None,
        line_domains,
        candidate_domains,
        selector_executions,
        consolidated_prefilter,
        prefilter_transitions,
        prefilter_match_events,
        prefilter_match_events_upper_bound,
        prefilter_sequential_bytes: prefilter_sequential,
        selector,
        state_visits,
        history_nodes,
        history_walk,
    })
}

fn one_fre_pattern(request: CandidateRequest<'_>) -> Result<&str, ExecutionError> {
    if request.patterns.len() != 1 {
        return Err(ExecutionError::unsupported(format!(
            "current FRE facade has no certified {} operation for multiple patterns; requires exactly one pattern",
            request.model
        )));
    }
    Ok(request.patterns[0].as_str())
}

#[allow(
    clippy::too_many_lines,
    reason = "all aggregate plan quotas remain explicit in one adapter identity boundary"
)]
fn aggregate_build_limits(limits: &RunLimits) -> AggregateBuildLimits {
    let u32_cells = limits
        .fre_aggregate_program_bytes
        .checked_div(core::mem::size_of::<u32>())
        .unwrap_or(0);
    let fixed_absolute_defaults = fre::FixedAbsoluteDomainBuildLimits::default();
    AggregateBuildLimits {
        max_literal_planner_work: limits.fre_literal_planner_work,
        max_unicode_scalar_planner_work: limits.fre_unicode_scalar_planner_work,
        max_word_run_planner_work: limits.fre_unicode_scalar_planner_work,
        max_literal_assertions_planner_work: limits.fre_literal_planner_work,
        max_blocking_delimiter_planner_work: limits.fre_unicode_scalar_planner_work,
        max_token_phrase_planner_work: limits.fre_unicode_scalar_planner_work,
        max_fixed_class_sandwich_planner_work: limits.fre_unicode_scalar_planner_work,
        max_grapheme_scalar_dfa_planner_work: limits.fre_aggregate_compile_work,
        max_bounded_class_sequence_planner_work: limits.fre_unicode_scalar_planner_work,
        max_bounded_separated_fields_planner_work: limits.fre_unicode_scalar_planner_work,
        max_bounded_affix_planner_work: limits.fre_bounded_affix_planner_work,
        max_prefix_class_alternation_planner_work: limits.fre_literal_planner_work,
        max_literal_class_run_literal_planner_work: limits.fre_literal_planner_work,
        max_bounded_literal_pair_planner_work: limits.fre_literal_planner_work,
        max_bounded_context_planner_work: limits.fre_unicode_scalar_planner_work,
        max_fixed_absolute_planner_work: limits.fre_literal_planner_work,
        max_finite_planner_work: u64::try_from(limits.fre_aggregate_compile_work)
            .unwrap_or(u64::MAX),
        exact_literal: LiteralAggregateBuildLimits {
            max_needle_bytes: limits.fre_literal_build_needle_bytes,
            max_build_work: limits.fre_literal_build_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        unicode_scalar: fre::UnicodeScalarAggregateBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: limits.fre_unicode_scalar_build_scratch_bytes,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        word_run: fre::WordRunBuildLimits {
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        literal_assertions: LiteralAssertionsBuildLimits {
            max_literal_bytes: limits.fre_literal_build_needle_bytes,
            max_build_work: usize::try_from(limits.fre_literal_build_work).unwrap_or(usize::MAX),
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        blocking_delimiter: BlockingDelimiterBuildLimits {
            max_delimiter_members: 2,
            max_terminal_members: 256,
            max_middle_bytes: usize::try_from(limits.fre_aggregate_repeat_bound)
                .unwrap_or(usize::MAX),
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        token_phrase: TokenPhraseBuildLimits {
            max_literal_bytes: limits.fre_literal_build_needle_bytes,
            max_build_work: usize::try_from(limits.fre_literal_build_work).unwrap_or(usize::MAX),
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        fixed_class_sandwich: FixedClassSandwichBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_middle_repetitions: limits.fre_aggregate_repeat_bound,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: limits.fre_unicode_scalar_build_scratch_bytes,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        grapheme_scalar_dfa: GraphemeScalarDfaBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_events: limits
                .fre_unicode_scalar_build_source_ranges
                .saturating_mul(2),
            max_segments: limits
                .fre_unicode_scalar_build_source_ranges
                .saturating_mul(2),
            max_sort_comparisons: limits.fre_aggregate_compile_work,
            max_allocations: 2,
            max_event_writes: limits
                .fre_unicode_scalar_build_source_ranges
                .saturating_mul(2),
            max_segment_writes: limits
                .fre_unicode_scalar_build_source_ranges
                .saturating_mul(2),
            max_build_work: limits.fre_aggregate_compile_work,
            max_scratch_bytes: limits.fre_unicode_scalar_build_scratch_bytes,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        bounded_class_sequence: BoundedClassSequenceBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_repeat_bound: limits.fre_aggregate_repeat_bound,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        bounded_separated_fields: BoundedSeparatedFieldsBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_persistent_bytes: limits.fre_unicode_scalar_build_persistent_bytes,
            max_peak_bytes: limits.fre_unicode_scalar_build_peak_bytes,
        },
        prefix_class_alternation: PrefixClassAlternationBuildLimits {
            max_shape_units: limits.pattern_bytes_per_job,
            max_build_work: limits.fre_aggregate_compile_work,
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_aggregate_program_bytes,
            max_peak_bytes: limits.fre_aggregate_peak_bytes,
        },
        literal_class_run_literal: LiteralClassRunLiteralBuildLimits {
            max_literal_bytes: limits.fre_literal_build_needle_bytes,
            max_class_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_class_members: 256,
            max_build_work: limits.fre_aggregate_compile_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        bounded_literal_pair: fre::BoundedLiteralPairBuildLimits {
            max_literal_bytes: limits.fre_literal_build_needle_bytes,
            max_class_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_class_members: 256,
            max_gap_bound: limits.fre_aggregate_repeat_bound,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        bounded_context: fre::BoundedContextBuildLimits {
            max_source_ranges: limits.fre_unicode_scalar_build_source_ranges,
            max_literal_bytes: limits.fre_literal_build_needle_bytes,
            max_repeat_bound: limits.fre_aggregate_repeat_bound,
            max_gap_bound: limits.fre_aggregate_repeat_bound,
            max_build_work: limits.fre_unicode_scalar_build_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        fixed_absolute: fre::FixedAbsoluteDomainBuildLimits {
            max_items: fixed_absolute_defaults
                .max_items
                .min(limits.patterns_per_job),
            max_payload_bytes: fixed_absolute_defaults
                .max_payload_bytes
                .min(limits.fre_literal_build_needle_bytes),
            max_identity_bytes: fixed_absolute_defaults
                .max_identity_bytes
                .min(limits.fre_literal_build_needle_bytes),
            max_copied_bytes: fixed_absolute_defaults
                .max_copied_bytes
                .min(limits.fre_literal_build_needle_bytes),
            max_allocations: fixed_absolute_defaults.max_allocations,
            max_initialized_bytes: fixed_absolute_defaults
                .max_initialized_bytes
                .min(limits.fre_literal_build_needle_bytes),
            max_build_work: fixed_absolute_defaults
                .max_build_work
                .min(limits.fre_literal_build_work),
            max_persistent_bytes: fixed_absolute_defaults
                .max_persistent_bytes
                .min(limits.fre_literal_build_persistent_bytes),
            max_peak_bytes: fixed_absolute_defaults
                .max_peak_bytes
                .min(limits.fre_literal_build_peak_bytes),
        },
        finite_literal: OrderedLiteralAggregateBuildLimits {
            max_patterns: limits.patterns_per_job,
            max_pattern_bytes: limits.pattern_bytes_per_job,
            max_identity_bytes: limits.fre_literal_build_needle_bytes,
            max_trie_states: u32_cells,
            max_dfa_cells: u32_cells,
            max_build_work: limits.fre_literal_build_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        continuation: fre::AggregateCompileLimits {
            max_hir_nodes: limits.fre_aggregate_hir_nodes,
            max_hir_stack_items: limits.fre_aggregate_hir_stack_items,
            max_repeat_bound: limits.fre_aggregate_repeat_bound,
            max_work: limits.fre_aggregate_compile_work,
            max_program_bytes: limits.fre_aggregate_program_bytes,
            ..fre::AggregateCompileLimits::default()
        },
        ..AggregateBuildLimits::default()
    }
}

fn checked_aggregate_add(
    left: usize,
    right: usize,
    dimension: &str,
) -> Result<usize, ExecutionError> {
    left.checked_add(right)
        .ok_or_else(|| ExecutionError::fault(format!("FRE aggregate {dimension} overflow")))
}

fn checked_aggregate_mul(
    left: usize,
    right: usize,
    dimension: &str,
) -> Result<usize, ExecutionError> {
    left.checked_mul(right)
        .ok_or_else(|| ExecutionError::fault(format!("FRE aggregate {dimension} overflow")))
}

fn checked_aggregate_u64_mul(
    left: u64,
    right: u64,
    dimension: &str,
) -> Result<u64, ExecutionError> {
    left.checked_mul(right)
        .ok_or_else(|| ExecutionError::fault(format!("FRE aggregate {dimension} overflow")))
}

#[derive(Clone, Copy)]
struct ContinuationProgramShape {
    states: usize,
    predecessor_edges: usize,
    terminal_frontier_prefix_bytes: usize,
    terminal_frontier_bytes: usize,
    required_literal_sets: usize,
    execution_state_work: usize,
    has_scalar_transitions: bool,
    max_scalar_search_checks: usize,
    requires_utf8_validation: bool,
    required_internal_anchors: usize,
    required_internal_anchor_bytes: usize,
    required_internal_anchor_optional_stages: usize,
    required_internal_anchor_persistent_bytes: usize,
}

impl From<fre::AggregateCompileAccounting> for ContinuationProgramShape {
    fn from(accounting: fre::AggregateCompileAccounting) -> Self {
        Self {
            states: accounting.program_states,
            predecessor_edges: accounting.predecessor_edges,
            terminal_frontier_prefix_bytes: accounting.terminal_frontier_prefix_bytes,
            terminal_frontier_bytes: accounting.terminal_frontier_bytes,
            required_literal_sets: accounting.required_literal_sets,
            execution_state_work: accounting.execution_state_work,
            has_scalar_transitions: accounting.has_scalar_transitions,
            max_scalar_search_checks: accounting.max_scalar_search_checks,
            requires_utf8_validation: accounting.requires_utf8_validation,
            required_internal_anchors: accounting.required_internal_anchors,
            required_internal_anchor_bytes: accounting.required_internal_anchor_bytes,
            required_internal_anchor_optional_stages: accounting
                .required_internal_anchor_optional_stages,
            required_internal_anchor_persistent_bytes: accounting
                .required_internal_anchor_persistent_bytes,
        }
    }
}

fn inactive_continuation_shape() -> ContinuationProgramShape {
    ContinuationProgramShape {
        states: 1,
        predecessor_edges: 0,
        terminal_frontier_prefix_bytes: 0,
        terminal_frontier_bytes: 0,
        required_literal_sets: 0,
        // One Match state is evaluated once and has no outgoing transition.
        execution_state_work: 1,
        has_scalar_transitions: false,
        max_scalar_search_checks: 0,
        requires_utf8_validation: false,
        required_internal_anchors: 0,
        required_internal_anchor_bytes: 0,
        required_internal_anchor_optional_stages: 0,
        required_internal_anchor_persistent_bytes: 0,
    }
}

#[cfg(test)]
fn conservative_continuation_shape(
    states: usize,
) -> Result<ContinuationProgramShape, ExecutionError> {
    // Callers that publish their own exact work limit use this helper only for
    // row/log storage. Three units per state is the non-scalar Thompson
    // maximum: one evaluation and two Split transition checks.
    let execution_state_work = checked_aggregate_mul(states, 3, "state work")?;
    let predecessor_edges = checked_aggregate_mul(states, 2, "predecessor edges")?;
    Ok(ContinuationProgramShape {
        states,
        predecessor_edges,
        terminal_frontier_prefix_bytes: 0,
        terminal_frontier_bytes: 0,
        required_literal_sets: 0,
        execution_state_work,
        has_scalar_transitions: false,
        max_scalar_search_checks: 0,
        requires_utf8_validation: false,
        required_internal_anchors: 0,
        required_internal_anchor_bytes: 0,
        required_internal_anchor_optional_stages: 0,
        required_internal_anchor_persistent_bytes: 0,
    })
}

fn terminal_frontier_resource_upper(
    haystack_len: usize,
    shape: ContinuationProgramShape,
    row_random_access: usize,
) -> Result<Option<(usize, usize)>, ExecutionError> {
    match (
        shape.terminal_frontier_prefix_bytes > 0,
        shape.terminal_frontier_bytes > 0,
    ) {
        (false, false) => return Ok(None),
        (true, true) => {}
        _ => {
            return Err(ExecutionError::fault(
                "FRE terminal-frontier compile accounting is incomplete",
            ));
        }
    }
    let word_bits = usize::try_from(usize::BITS)
        .map_err(|_| ExecutionError::fault("platform word width does not fit usize"))?;
    let candidate_words = shape.states.div_ceil(word_bits);
    let summary_words = candidate_words.div_ceil(word_bits);
    let frontier_state_words = checked_aggregate_mul(shape.states, 4, "frontier state words")?;
    let frontier_words = checked_aggregate_add(
        checked_aggregate_add(
            checked_aggregate_add(frontier_state_words, 1, "frontier offset words")?,
            shape.predecessor_edges,
            "frontier predecessor words",
        )?,
        checked_aggregate_add(candidate_words, summary_words, "frontier bit words")?,
        "frontier words",
    )?;
    let frontier_bytes = checked_aggregate_mul(
        frontier_words,
        core::mem::size_of::<usize>(),
        "frontier bytes",
    )?;
    let prefix_starts = haystack_len
        .checked_sub(shape.terminal_frontier_prefix_bytes)
        .map_or(Ok(0), |remaining| {
            checked_aggregate_add(remaining, 1, "terminal prefix starts")
        })?;
    let prefix_source = checked_aggregate_mul(
        prefix_starts,
        shape.terminal_frontier_prefix_bytes,
        "terminal prefix source visits",
    )?;
    let sweep_source = checked_aggregate_mul(haystack_len, 4, "frontier source bytes")?;
    Ok(Some((
        row_random_access.max(frontier_bytes),
        checked_aggregate_add(prefix_source, sweep_source, "frontier source visits")?,
    )))
}

/// Build every operation limit explicitly from authenticated input size,
/// exact compiled state/search dimensions and the report's named policy
/// quotas. The fixed reverse-row strategy never receives a full-table
/// allowance.
fn required_internal_anchor_operation_limits(
    haystack_len: usize,
    shape: ContinuationProgramShape,
    limits: &RunLimits,
) -> Result<AggregateOperationLimits, ExecutionError> {
    let anchor_bytes = shape.required_internal_anchor_bytes;
    let candidates = haystack_len.checked_div(anchor_bytes).ok_or_else(|| {
        ExecutionError::fault("FRE required internal-anchor route reported an empty anchor")
    })?;
    let anchor_starts = match haystack_len.checked_sub(anchor_bytes) {
        Some(last) => checked_aggregate_add(last, 1, "anchor scan starts")?,
        None => 0,
    };
    let anchor_source = checked_aggregate_mul(anchor_starts, anchor_bytes, "anchor scan source")?;
    let per_candidate = checked_aggregate_add(
        2,
        shape.required_internal_anchor_optional_stages,
        "anchor continuation overhead",
    )?;
    let continuation = checked_aggregate_add(
        haystack_len,
        checked_aggregate_mul(candidates, per_candidate, "anchor continuation work")?,
        "anchor continuation work",
    )?;
    let random_access = checked_aggregate_add(anchor_source, haystack_len, "anchor random source")?;
    let sequential = continuation;
    let source = checked_aggregate_add(random_access, sequential, "anchor source")?;
    let control = checked_aggregate_add(
        anchor_starts,
        checked_aggregate_add(
            checked_aggregate_mul(candidates, 5, "anchor candidate control")?,
            4,
            "anchor fixed control",
        )?,
        "anchor control",
    )?;
    let work = checked_aggregate_add(source, control, "anchor work")?;
    let boundaries = checked_aggregate_add(haystack_len, 1, "boundary count")?;
    let reducer_matches = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let reducer_events = checked_aggregate_mul(reducer_matches, 2, "reducer events")?;
    Ok(AggregateOperationLimits {
        max_boundaries: boundaries,
        max_table_cells: 0,
        max_random_access_bytes: random_access.min(limits.fre_aggregate_random_access_bytes),
        max_scratch_bytes: 0,
        max_log_bytes: 0,
        max_sequential_bytes: sequential.min(limits.fre_aggregate_sequential_bytes),
        max_match_events: candidates.min(reducer_events),
        max_output_matches: candidates.min(reducer_matches),
        max_output_bytes: 0,
        max_span_sum: 0,
        max_peak_bytes: shape
            .required_internal_anchor_persistent_bytes
            .min(limits.fre_aggregate_peak_bytes),
        max_work: work.min(limits.fre_aggregate_operation_work),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContinuationStorageLimits {
    random: usize,
    scratch: usize,
    log: usize,
    sequential: usize,
    peak: usize,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CachedFrontierTransitionLayout {
    symbol: u64,
    next_state: u16,
    result_state: u16,
    occupied: bool,
}

const CACHED_FRONTIERS: usize = 4_096;
const CACHED_TRANSITIONS: usize = 65_536;
const CACHED_TRANSITION_SLOTS: usize = CACHED_TRANSITIONS * 2;

fn cached_frontier_words(program_states: usize) -> Result<usize, ExecutionError> {
    checked_aggregate_add(program_states, 63, "cached-frontier word numerator")?
        .checked_div(64)
        .ok_or_else(|| ExecutionError::fault("FRE cached-frontier word width is zero"))
}

fn cached_frontier_initialization_work(
    program_states: usize,
    boundaries: usize,
) -> Result<usize, ExecutionError> {
    let words = cached_frontier_words(program_states)?;
    let state_words = checked_aggregate_mul(words, CACHED_FRONTIERS, "cached state words")?;
    let candidate_words = checked_aggregate_mul(words, 2, "cached candidate words")?;
    let state_and_hashes = checked_aggregate_add(
        state_words,
        CACHED_FRONTIERS,
        "cached state and hash initialization",
    )?;
    let transitions_and_candidates = checked_aggregate_add(
        CACHED_TRANSITION_SLOTS,
        candidate_words,
        "cached transition and candidate initialization",
    )?;
    checked_aggregate_add(
        checked_aggregate_add(
            boundaries,
            state_and_hashes,
            "cached boundary and state initialization",
        )?,
        checked_aggregate_add(transitions_and_candidates, 6, "cached fixed initialization")?,
        "cached-frontier initialization work",
    )
}

/// Mirror the continuation engine's prospective exact-layout theorem for the
/// bounded Boolean-frontier executor. The capacities are fixed before source
/// inspection: 4,096 frontier images, 65,536 installed transitions in a
/// half-full open-addressed table, and one `u16` image ID or uncached sentinel
/// per boundary. Full caches stop inserting and recompute from checkpoints.
fn cached_frontier_limits(
    program_states: usize,
    boundaries: usize,
    passes: usize,
) -> Result<ContinuationStorageLimits, ExecutionError> {
    let words = cached_frontier_words(program_states)?;
    let state_words =
        checked_aggregate_mul(words, CACHED_FRONTIERS, "cached-frontier state words")?;
    let state_bytes = checked_aggregate_mul(
        state_words,
        core::mem::size_of::<u64>(),
        "cached-frontier state bytes",
    )?;
    let hash_bytes = checked_aggregate_mul(
        CACHED_FRONTIERS,
        core::mem::size_of::<u64>(),
        "cached-frontier hash bytes",
    )?;
    let transition_bytes = checked_aggregate_mul(
        CACHED_TRANSITION_SLOTS,
        core::mem::size_of::<CachedFrontierTransitionLayout>(),
        "cached-frontier transition bytes",
    )?;
    let candidate_words = checked_aggregate_mul(words, 2, "cached-frontier replay row words")?;
    let candidate_bytes = checked_aggregate_mul(
        candidate_words,
        core::mem::size_of::<u64>(),
        "cached-frontier candidate/replay bytes",
    )?;
    let random_bytes = checked_aggregate_add(
        checked_aggregate_add(state_bytes, hash_bytes, "cached-frontier state/hash bytes")?,
        checked_aggregate_add(
            transition_bytes,
            candidate_bytes,
            "cached-frontier transition/candidate bytes",
        )?,
        "cached-frontier random bytes",
    )?;
    let log_bytes = checked_aggregate_mul(
        boundaries,
        core::mem::size_of::<u16>(),
        "cached-frontier log bytes",
    )?;
    let read_passes = checked_aggregate_mul(passes, 3, "cached-frontier read passes")?;
    let sequential_bytes = checked_aggregate_mul(
        log_bytes,
        checked_aggregate_add(read_passes, 1, "cached-frontier total passes")?,
        "cached-frontier sequential bytes",
    )?;
    let peak_bytes = checked_aggregate_add(log_bytes, random_bytes, "cached-frontier peak bytes")?;
    Ok(ContinuationStorageLimits {
        random: random_bytes,
        scratch: random_bytes,
        log: log_bytes,
        sequential: sequential_bytes,
        peak: peak_bytes,
    })
}

fn composed_continuation_storage_limits(
    program_states: usize,
    boundaries: usize,
    source_prefix: usize,
    available_work: usize,
    has_terminal_frontier: bool,
    row: ContinuationStorageLimits,
) -> Result<ContinuationStorageLimits, ExecutionError> {
    if has_terminal_frontier {
        return Ok(row);
    }
    if cached_frontier_initialization_work(program_states, boundaries)? > available_work {
        return Ok(row);
    }
    let cached = cached_frontier_limits(program_states, boundaries, 1)?;
    let cached_sequential = checked_aggregate_add(
        cached.sequential,
        source_prefix,
        "cached-frontier sequential bytes including pre-engine source prefixes",
    )?;
    Ok(ContinuationStorageLimits {
        random: row.random.max(cached.random),
        scratch: row.scratch.max(cached.scratch),
        log: row.log.max(cached.log),
        sequential: row.sequential.max(cached_sequential),
        peak: row.peak.max(cached.peak),
    })
}

#[derive(Clone, Copy)]
struct ContinuationPrefixLimits {
    sequential: usize,
    work: usize,
}

fn continuation_prefix_limits(
    haystack_len: usize,
    shape: ContinuationProgramShape,
) -> Result<ContinuationPrefixLimits, ExecutionError> {
    let prevalidation = if shape.requires_utf8_validation {
        haystack_len
    } else {
        0
    };
    let required_literal_source = if shape.required_literal_sets == 0 {
        0
    } else {
        haystack_len
    };
    let required_literal_comparisons = checked_aggregate_mul(
        required_literal_source,
        shape.required_literal_sets,
        "required-literal comparisons",
    )?;
    let required_literal_work = checked_aggregate_add(
        required_literal_source,
        required_literal_comparisons,
        "required-literal source and comparison work",
    )?;
    Ok(ContinuationPrefixLimits {
        sequential: checked_aggregate_add(
            prevalidation,
            required_literal_source,
            "sequential UTF-8 and required-literal prefixes",
        )?,
        work: checked_aggregate_add(
            prevalidation,
            required_literal_work,
            "UTF-8 and required-literal prefix work",
        )?,
    })
}

fn continuation_operation_limits(
    haystack_len: usize,
    shape: ContinuationProgramShape,
    limits: &RunLimits,
) -> Result<AggregateOperationLimits, ExecutionError> {
    let program_states = shape.states;
    if program_states == 0 {
        return Err(ExecutionError::fault(
            "FRE aggregate compiler reported a zero-state program",
        ));
    }
    if shape.required_internal_anchors == 1 {
        return required_internal_anchor_operation_limits(haystack_len, shape, limits);
    }
    if shape.required_internal_anchors != 0 {
        return Err(ExecutionError::fault(
            "FRE aggregate compiler reported multiple required internal-anchor routes",
        ));
    }
    let boundaries = checked_aggregate_add(haystack_len, 1, "boundary count")?;
    let record_bytes = checked_aggregate_add(program_states, 1, "row decision bits")?.div_ceil(8);
    let row_words = checked_aggregate_mul(program_states, 2, "row words")?;
    let row_bytes = checked_aggregate_mul(row_words, core::mem::size_of::<usize>(), "row bytes")?;
    let row_random_access = checked_aggregate_add(row_bytes, record_bytes, "random-access bytes")?;
    let log_upper = checked_aggregate_mul(record_bytes, boundaries, "row-log bytes")?;
    let row_sequential_upper = checked_aggregate_mul(log_upper, 2, "row sequential bytes")?;
    let terminal_frontier =
        terminal_frontier_resource_upper(haystack_len, shape, row_random_access)?;
    let (random_access_upper, route_source) = terminal_frontier.unwrap_or((row_random_access, 0));
    let prefix = continuation_prefix_limits(haystack_len, shape)?;
    let sequential_upper = checked_aggregate_add(
        checked_aggregate_add(
            row_sequential_upper,
            route_source,
            "row plus frontier sequential bytes",
        )?,
        prefix.sequential,
        "sequential bytes including pre-engine source prefixes",
    )?;
    let row_peak_upper = checked_aggregate_add(log_upper, random_access_upper, "peak bytes")?;
    let row_storage = ContinuationStorageLimits {
        random: random_access_upper,
        scratch: random_access_upper,
        log: log_upper,
        sequential: sequential_upper,
        peak: row_peak_upper,
    };

    // These are the same structural terms enforced by
    // fre-aggregate's Requirements::new. Scalar decoding is shared once per
    // boundary; membership comparisons are already included in the exact
    // state-work census. Sequential replay can revisit every state and adds
    // the largest retained scalar search to its four fixed replay steps.
    let per_boundary_build = checked_aggregate_add(
        shape.execution_state_work,
        usize::from(shape.has_scalar_transitions),
        "per-boundary build work",
    )?;
    let build_work = checked_aggregate_mul(per_boundary_build, boundaries, "row-build work")?;
    let scan_work = checked_aggregate_mul(boundaries, 4, "scan work")?;
    let replay_factor =
        checked_aggregate_add(4, shape.max_scalar_search_checks, "replay work factor")?;
    let state_boundaries =
        checked_aggregate_mul(program_states, boundaries, "state-boundary cells")?;
    let replay_work = checked_aggregate_mul(state_boundaries, replay_factor, "row-replay work")?;
    let engine_work_upper = checked_aggregate_add(
        checked_aggregate_add(build_work, scan_work, "build plus scan work")?,
        replay_work,
        "operation work",
    )?;
    let work_upper = checked_aggregate_add(
        engine_work_upper,
        prefix.work,
        "operation work with prefixes",
    )?;
    let available_work = work_upper.min(limits.fre_aggregate_operation_work);
    let storage = composed_continuation_storage_limits(
        program_states,
        boundaries,
        prefix.sequential,
        available_work,
        terminal_frontier.is_some(),
        row_storage,
    )?;

    let reducer_matches = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let event_upper = checked_aggregate_mul(boundaries, 2, "match events")?;
    let reducer_event_limit =
        checked_aggregate_mul(reducer_matches, 2, "reducer-derived match events")?;

    Ok(AggregateOperationLimits {
        max_boundaries: boundaries,
        max_table_cells: 0,
        max_random_access_bytes: storage.random.min(limits.fre_aggregate_random_access_bytes),
        max_scratch_bytes: storage.scratch.min(limits.fre_aggregate_scratch_bytes),
        max_log_bytes: storage.log.min(limits.fre_aggregate_log_bytes),
        max_sequential_bytes: storage
            .sequential
            .min(limits.fre_aggregate_sequential_bytes),
        max_match_events: event_upper.min(reducer_event_limit),
        max_output_matches: boundaries.min(reducer_matches),
        max_output_bytes: 0,
        max_span_sum: haystack_len,
        max_peak_bytes: storage.peak.min(limits.fre_aggregate_peak_bytes),
        max_work: available_work,
    })
}

fn url_aggregate_operation_limits(
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<AggregateOperationLimits, ExecutionError> {
    let upper = fre::url_aggregate_reduce_upper_bounds(haystack_len).map_err(|error| {
        ExecutionError::fault(format!("FRE URL aggregate upper-bound derivation: {error}"))
    })?;
    let reducer_matches = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(AggregateOperationLimits {
        max_boundaries: upper.boundaries,
        max_table_cells: 0,
        max_random_access_bytes: upper
            .random_access_storage_bytes
            .min(limits.fre_aggregate_random_access_bytes),
        max_scratch_bytes: upper.scratch_bytes.min(limits.fre_aggregate_scratch_bytes),
        max_log_bytes: 0,
        max_sequential_bytes: upper
            .sequential_bytes
            .min(limits.fre_aggregate_sequential_bytes),
        max_match_events: upper.match_events.min(reducer_matches),
        max_output_matches: upper.output_matches.min(reducer_matches),
        max_output_bytes: 0,
        max_span_sum: upper.span_sum,
        max_peak_bytes: upper.peak_bytes.min(limits.fre_aggregate_peak_bytes),
        max_work: limits.fre_aggregate_operation_work,
    })
}

/// Derive the complete two-pass reverse-row limits for a materialized span
/// operation. Every term comes from the authenticated compile shape, input
/// length, HIR minimum width and a named public quota. This is separate from
/// the one-pass count/span-sum derivation so no already-derived field is ever
/// widened by an enclosing replacement reducer.
fn continuation_spans_operation_limits(
    haystack_len: usize,
    shape: ContinuationProgramShape,
    minimum_match_bytes: usize,
    limits: &RunLimits,
) -> Result<AggregateOperationLimits, ExecutionError> {
    const PASSES: usize = 2;
    if shape.states == 0 || minimum_match_bytes == 0 {
        return Err(ExecutionError::fault(
            "FRE continuation spans require nonzero states and minimum width",
        ));
    }
    let boundaries = checked_aggregate_add(haystack_len, 1, "span boundary count")?;
    let record_bytes =
        checked_aggregate_add(shape.states, 1, "span row decision bits")?.div_ceil(8);
    let row_words = checked_aggregate_mul(shape.states, 2, "span row words")?;
    let row_bytes =
        checked_aggregate_mul(row_words, core::mem::size_of::<usize>(), "span row bytes")?;
    let random_access_upper =
        checked_aggregate_add(row_bytes, record_bytes, "span random-access bytes")?;
    let log_upper = checked_aggregate_mul(record_bytes, boundaries, "span row-log bytes")?;
    let sequential_passes = checked_aggregate_add(PASSES, 1, "span sequential passes")?;
    let row_sequential_upper =
        checked_aggregate_mul(log_upper, sequential_passes, "span row sequential bytes")?;
    let prefix = continuation_prefix_limits(haystack_len, shape)?;
    let sequential_upper = checked_aggregate_add(
        row_sequential_upper,
        prefix.sequential,
        "span sequential bytes including pre-engine source prefixes",
    )?;

    let per_boundary_build = checked_aggregate_add(
        shape.execution_state_work,
        usize::from(shape.has_scalar_transitions),
        "span per-boundary build work",
    )?;
    let build_work = checked_aggregate_mul(per_boundary_build, boundaries, "span row-build work")?;
    let scan_work = checked_aggregate_mul(
        checked_aggregate_mul(boundaries, 4, "span scan work per pass")?,
        PASSES,
        "span scan work",
    )?;
    let replay_factor =
        checked_aggregate_add(4, shape.max_scalar_search_checks, "span replay work factor")?;
    let state_boundaries =
        checked_aggregate_mul(shape.states, boundaries, "span state-boundary cells")?;
    let replay_work = checked_aggregate_mul(
        checked_aggregate_mul(state_boundaries, replay_factor, "span replay work per pass")?,
        PASSES,
        "span replay work",
    )?;
    let engine_work_upper = checked_aggregate_add(
        checked_aggregate_add(build_work, scan_work, "span build plus scan work")?,
        replay_work,
        "span operation work",
    )?;
    let work_upper =
        checked_aggregate_add(engine_work_upper, prefix.work, "span work with prefixes")?;

    let reducer_matches = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let structural_matches = haystack_len
        .checked_div(minimum_match_bytes)
        .ok_or_else(|| ExecutionError::fault("FRE continuation span minimum width is zero"))?;
    let output_matches = structural_matches.min(boundaries).min(reducer_matches);
    let output_bytes = checked_aggregate_mul(
        output_matches,
        core::mem::size_of::<fre::AggregateSpan>(),
        "span output bytes",
    )?;
    let event_upper = composite_continuation_match_events(haystack_len)?;
    let reducer_event_limit =
        checked_aggregate_mul(reducer_matches, PASSES, "span reducer-derived match events")?;
    let build_peak =
        checked_aggregate_add(log_upper, random_access_upper, "span build peak bytes")?;
    let replay_peak = checked_aggregate_add(log_upper, output_bytes, "span replay peak bytes")?;
    let peak_upper = build_peak.max(replay_peak);

    Ok(AggregateOperationLimits {
        max_boundaries: boundaries,
        max_table_cells: 0,
        max_random_access_bytes: random_access_upper.min(limits.fre_aggregate_random_access_bytes),
        max_scratch_bytes: random_access_upper.min(limits.fre_aggregate_scratch_bytes),
        max_log_bytes: log_upper.min(limits.fre_aggregate_log_bytes),
        max_sequential_bytes: sequential_upper.min(limits.fre_aggregate_sequential_bytes),
        max_match_events: event_upper.min(reducer_event_limit),
        max_output_matches: output_matches,
        max_output_bytes: output_bytes,
        max_span_sum: haystack_len,
        max_peak_bytes: peak_upper.min(limits.fre_aggregate_peak_bytes),
        max_work: work_upper.min(limits.fre_aggregate_operation_work),
    })
}

/// Derive every literal reducer field from authenticated input, exact selected
/// plan accounting, the shared reducer-event quota and a named literal quota.
/// A quota below the authenticated upper bound remains visible as a typed
/// resource refusal from the selected exact-literal plan.
fn literal_operation_limits(
    haystack_len: usize,
    build: fre::LiteralAggregateBuildAccounting,
    limits: &RunLimits,
) -> Result<LiteralAggregateReduceLimits, ExecutionError> {
    let boundaries = checked_aggregate_add(haystack_len, 1, "literal boundary count")?;
    let linear_terms =
        checked_aggregate_add(haystack_len, build.needle_bytes, "literal linear terms")?;
    let (match_events, reducer_steps) = if build.needle_bytes == 0 {
        (boundaries, 1)
    } else {
        let events = haystack_len
            .checked_div(build.needle_bytes)
            .ok_or_else(|| ExecutionError::fault("nonempty FRE literal needle divided by zero"))?;
        (
            events,
            checked_aggregate_add(events, 1, "literal reducer steps")?,
        )
    };
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE literal event bound does not fit u64"))?;
    let needle = u64::try_from(build.needle_bytes)
        .map_err(|_| ExecutionError::fault("FRE literal needle length does not fit u64"))?;
    let span_sum = checked_aggregate_u64_mul(count, needle, "literal span sum")?;
    let reducer_event_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let reducer_count_limit = limits.reducer_steps;
    let reducer_step_limit = if build.needle_bytes == 0 {
        1
    } else {
        checked_aggregate_add(reducer_event_limit, 1, "literal reducer event steps")?
    };
    let peak_bytes =
        checked_aggregate_add(build.persistent_bytes, 0, "literal operation peak bytes")?;

    Ok(LiteralAggregateReduceLimits {
        max_linear_terms: linear_terms.min(limits.fre_literal_linear_terms),
        max_match_events: match_events
            .min(reducer_event_limit)
            .min(limits.fre_literal_match_events),
        max_count: count.min(reducer_count_limit).min(limits.fre_literal_count),
        max_span_sum: span_sum.min(limits.fre_literal_span_sum),
        max_reducer_steps: reducer_steps
            .min(reducer_step_limit)
            .min(limits.fre_literal_reducer_steps),
        max_scratch_bytes: 0.min(limits.fre_literal_scratch_bytes),
        max_peak_bytes: peak_bytes.min(limits.fre_literal_peak_bytes),
    })
}

fn inactive_literal_operation_limits(limits: &RunLimits) -> LiteralAggregateReduceLimits {
    LiteralAggregateReduceLimits {
        max_linear_terms: limits.fre_literal_linear_terms,
        max_match_events: limits.fre_literal_match_events,
        max_count: limits.fre_literal_count,
        max_span_sum: limits.fre_literal_span_sum,
        max_reducer_steps: limits.fre_literal_reducer_steps,
        max_scratch_bytes: limits.fre_literal_scratch_bytes,
        max_peak_bytes: limits.fre_literal_peak_bytes,
    }
}

fn scalar_binary_search_comparison_bound(mut ranges: usize) -> usize {
    let mut comparisons = 0_usize;
    while ranges != 0 {
        comparisons = comparisons.saturating_add(1);
        ranges /= 2;
    }
    comparisons
}

fn unicode_scalar_operation_limits(
    upper: fre::UnicodeScalarAggregateUpperBounds,
    limits: &RunLimits,
) -> Result<UnicodeScalarAggregateReduceLimits, ExecutionError> {
    let reducer_events = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;

    Ok(UnicodeScalarAggregateReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_decode_byte_checks: upper.decode_byte_checks,
        max_membership_tests: upper.membership_tests,
        max_range_comparisons: upper.range_comparisons,
        max_reducer_steps: upper.reducer_steps.min(reducer_events),
        max_match_events: upper.match_events.min(reducer_events),
        max_count: upper.count.min(limits.reducer_steps),
        max_span_sum: upper.span_sum,
        max_work: upper.work.min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: upper.scratch_bytes,
        max_peak_bytes: upper.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_unicode_scalar_operation_limits() -> UnicodeScalarAggregateReduceLimits {
    UnicodeScalarAggregateReduceLimits::default()
}

fn word_run_operation_limits(
    haystack_len: usize,
    build: fre::WordRunBuildAccounting,
    operation: AggregateOperation,
    limits: &RunLimits,
) -> Result<fre::WordRunReduceLimits, ExecutionError> {
    let event_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let work = checked_aggregate_mul(haystack_len, 10, "word-run event work")?
        .checked_add(8)
        .ok_or_else(|| ExecutionError::fault("FRE word-run work bound overflow"))?;
    let count = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE word-run count bound does not fit u64"))?;
    let span_sum = if operation == AggregateOperation::SpanSum {
        count
    } else {
        0
    };
    Ok(fre::WordRunReduceLimits {
        max_input_bytes: haystack_len,
        max_source_reads: haystack_len,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_unit_events: haystack_len.min(event_limit),
        max_run_events: haystack_len.min(event_limit),
        max_match_events: haystack_len.min(event_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_scratch_bytes: 0,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.persistent_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_word_run_operation_limits() -> fre::WordRunReduceLimits {
    fre::WordRunReduceLimits::default()
}

fn literal_assertions_operation_limits(
    haystack_len: usize,
    build: LiteralAssertionsBuildAccounting,
    operation: AggregateOperation,
    limits: &RunLimits,
) -> Result<LiteralAssertionsReduceLimits, ExecutionError> {
    if build.literal_bytes == 0 {
        return Err(ExecutionError::fault(
            "FRE literal-assertions build retained an empty literal",
        ));
    }
    let candidate_events = haystack_len
        .checked_sub(build.literal_bytes)
        .and_then(|remaining| remaining.checked_add(1))
        .unwrap_or(0);
    let candidate_scan_bytes = candidate_events;
    let literal_comparisons = checked_aggregate_mul(
        candidate_events,
        build.literal_bytes,
        "literal-assertions comparisons",
    )?;
    let assertion_checks = checked_aggregate_mul(candidate_events, 2, "literal-assertions checks")?;
    let boundary_reads = assertion_checks;
    let source_reads = [candidate_scan_bytes, literal_comparisons, boundary_reads]
        .into_iter()
        .try_fold(0_usize, |total, term| {
            checked_aggregate_add(total, term, "literal-assertions source reads")
        })?;
    let match_events = haystack_len
        .checked_div(build.literal_bytes)
        .ok_or_else(|| ExecutionError::fault("literal-assertions match bound divided by zero"))?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("literal-assertions count bound does not fit u64"))?;
    let span_sum = match operation {
        AggregateOperation::Compile | AggregateOperation::Count => 0,
        AggregateOperation::SpanSum => u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("literal-assertions span bound does not fit u64"))?,
        AggregateOperation::Spans => {
            return Err(ExecutionError::fault(
                "literal-assertions plan retained a spans operation",
            ));
        }
    };
    let work = [
        candidate_scan_bytes,
        checked_aggregate_mul(candidate_events, 2, "literal-assertions candidate work")?,
        literal_comparisons,
        checked_aggregate_mul(assertion_checks, 2, "literal-assertions assertion work")?,
        boundary_reads,
        checked_aggregate_mul(match_events, 4, "literal-assertions match work")?,
        8,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "literal-assertions total work")
    })?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(LiteralAssertionsReduceLimits {
        max_input_bytes: haystack_len,
        max_source_reads: source_reads,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_candidate_scan_bytes: candidate_scan_bytes,
        max_literal_comparisons: literal_comparisons,
        max_assertion_checks: assertion_checks,
        max_boundary_reads: boundary_reads,
        max_candidate_events: candidate_events.min(reducer_limit),
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_scratch_bytes: 0,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_literal_assertions_operation_limits() -> LiteralAssertionsReduceLimits {
    LiteralAssertionsReduceLimits::default()
}

fn blocking_delimiter_operation_limits(
    haystack_len: usize,
    build: BlockingDelimiterBuildAccounting,
    operation: AggregateOperation,
    limits: &RunLimits,
) -> Result<BlockingDelimiterReduceLimits, ExecutionError> {
    let delimiter_scan_bytes = haystack_len;
    let delimiter_events = haystack_len;
    let pair_events = haystack_len.saturating_sub(1);
    let terminal_reads = pair_events;
    let source_reads = checked_aggregate_add(
        delimiter_scan_bytes,
        terminal_reads,
        "blocking-delimiter source reads",
    )?;
    let match_events = haystack_len
        .checked_div(3)
        .ok_or_else(|| ExecutionError::fault("blocking-delimiter match bound divided by zero"))?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("blocking-delimiter count bound does not fit u64"))?;
    let span_sum = match operation {
        AggregateOperation::Compile | AggregateOperation::Count => 0,
        AggregateOperation::SpanSum => u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("blocking-delimiter span bound does not fit u64"))?,
        AggregateOperation::Spans => {
            return Err(ExecutionError::fault(
                "blocking-delimiter plan retained a spans operation",
            ));
        }
    };
    let work = [
        delimiter_scan_bytes,
        checked_aggregate_mul(delimiter_events, 2, "blocking-delimiter event work")?,
        checked_aggregate_mul(pair_events, 2, "blocking-delimiter pair work")?,
        terminal_reads,
        checked_aggregate_mul(match_events, 4, "blocking-delimiter match work")?,
        8,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "blocking-delimiter total work")
    })?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(BlockingDelimiterReduceLimits {
        max_input_bytes: haystack_len,
        max_source_reads: source_reads,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_delimiter_scan_bytes: delimiter_scan_bytes,
        max_delimiter_events: delimiter_events.min(reducer_limit),
        max_pair_events: pair_events.min(reducer_limit),
        max_terminal_reads: terminal_reads,
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_scratch_bytes: 0,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_blocking_delimiter_operation_limits() -> BlockingDelimiterReduceLimits {
    BlockingDelimiterReduceLimits::default()
}

fn token_phrase_operation_limits(
    haystack_len: usize,
    build: TokenPhraseBuildAccounting,
    operation: AggregateOperation,
    limits: &RunLimits,
) -> Result<TokenPhraseReduceLimits, ExecutionError> {
    let classifications = haystack_len;
    let source_reads = classifications;
    let literal_comparisons = haystack_len;
    let token_events = haystack_len;
    let minimum_match_bytes = build
        .literal_bytes
        .checked_add(4)
        .ok_or_else(|| ExecutionError::fault("token-phrase minimum match width overflow"))?;
    let match_events = haystack_len
        .checked_div(minimum_match_bytes)
        .ok_or_else(|| ExecutionError::fault("token-phrase match-event bound divided by zero"))?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("token-phrase count bound does not fit u64"))?;
    let span_sum = match operation {
        AggregateOperation::Compile | AggregateOperation::Count => 0,
        AggregateOperation::SpanSum => u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("token-phrase span bound does not fit u64"))?,
        AggregateOperation::Spans => {
            return Err(ExecutionError::fault(
                "token-phrase plan retained a spans operation",
            ));
        }
    };
    let work = [
        checked_aggregate_mul(classifications, 2, "token-phrase classification work")?,
        literal_comparisons,
        checked_aggregate_mul(token_events, 3, "token-phrase token-event work")?,
        checked_aggregate_mul(match_events, 4, "token-phrase match work")?,
        8,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "token-phrase total work")
    })?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(TokenPhraseReduceLimits {
        max_input_bytes: haystack_len,
        max_source_reads: source_reads,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_classifications: classifications,
        max_literal_comparisons: literal_comparisons,
        max_token_events: token_events.min(reducer_limit),
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_scratch_bytes: 0,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_token_phrase_operation_limits() -> TokenPhraseReduceLimits {
    TokenPhraseReduceLimits::default()
}

fn fixed_class_sandwich_operation_limits(
    haystack_len: usize,
    build: fre::FixedClassSandwichBuildAccounting,
    limits: &RunLimits,
) -> Result<FixedClassSandwichReduceLimits, ExecutionError> {
    let decode_factor = match build.semantics {
        fre::FixedClassSandwichSemantics::RustBytesUnicodeOff => 1,
        fre::FixedClassSandwichSemantics::RustBytesUnicodeUtf8False => 4,
    };
    let decode_byte_checks =
        checked_aggregate_mul(haystack_len, decode_factor, "fixed class decode checks")?;
    let membership_tests = checked_aggregate_mul(haystack_len, 3, "fixed class memberships")?;
    let comparisons_per_unit = scalar_binary_search_comparison_bound(build.prefix_ranges)
        .checked_add(scalar_binary_search_comparison_bound(build.middle_ranges))
        .and_then(|value| {
            value.checked_add(scalar_binary_search_comparison_bound(build.suffix_ranges))
        })
        .ok_or_else(|| ExecutionError::fault("FRE fixed class comparison bound overflow"))?;
    let range_comparisons = checked_aggregate_mul(
        haystack_len,
        comparisons_per_unit,
        "fixed class range comparisons",
    )?;
    let reducer_steps = checked_aggregate_add(haystack_len, 1, "fixed class reducer steps")?;
    let match_events = haystack_len
        .checked_div(build.window_units)
        .ok_or_else(|| ExecutionError::fault("FRE fixed class window is zero"))?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE fixed class count bound does not fit u64"))?;
    let span_sum = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE fixed class span bound does not fit u64"))?;
    let work = checked_aggregate_add(
        checked_aggregate_add(
            checked_aggregate_add(
                decode_byte_checks,
                membership_tests,
                "fixed class decode plus membership work",
            )?,
            range_comparisons,
            "fixed class membership comparison work",
        )?,
        reducer_steps,
        "fixed class total structural work",
    )?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(FixedClassSandwichReduceLimits {
        max_input_bytes: haystack_len,
        max_decode_byte_checks: decode_byte_checks,
        max_membership_tests: membership_tests,
        max_range_comparisons: range_comparisons,
        max_reducer_steps: reducer_steps.min(reducer_limit),
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn inactive_fixed_class_sandwich_operation_limits() -> FixedClassSandwichReduceLimits {
    FixedClassSandwichReduceLimits::default()
}

fn literal_class_run_literal_operation_limits(
    upper: fre::LiteralClassRunLiteralUpperBounds,
    limits: &RunLimits,
) -> Result<LiteralClassRunLiteralReduceLimits, ExecutionError> {
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(LiteralClassRunLiteralReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work.min(limits.fre_aggregate_operation_work),
        max_run_events: upper.run_events,
        max_match_events: upper.match_events.min(reducer_limit),
        max_count: upper.count.min(limits.reducer_steps),
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_literal_class_run_literal_operation_limits() -> LiteralClassRunLiteralReduceLimits {
    LiteralClassRunLiteralReduceLimits::default()
}

fn grapheme_scalar_dfa_operation_limits(
    haystack_len: usize,
    build: GraphemeScalarDfaBuildAccounting,
    limits: &RunLimits,
) -> Result<GraphemeScalarDfaReduceLimits, ExecutionError> {
    let decode_byte_checks =
        checked_aggregate_mul(haystack_len, 4, "grapheme scalar decode checks")?;
    let range_comparisons = checked_aggregate_mul(
        haystack_len,
        build.binary_search_comparisons_per_scalar,
        "grapheme scalar range comparisons",
    )?;
    let scanner_steps = checked_aggregate_add(haystack_len, 1, "grapheme scanner terminal")?;
    let role_probes = checked_aggregate_add(haystack_len, 1, "grapheme terminal transition")?;
    let branch_checks = 0;
    let repetition_tests = 0;
    let role_probe_work = checked_aggregate_mul(role_probes, 48, "grapheme transition work")?;
    let work = [
        decode_byte_checks,
        haystack_len,
        range_comparisons,
        scanner_steps,
        role_probe_work,
        branch_checks,
        repetition_tests,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "grapheme total structural work")
    })?;
    let count = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE grapheme count bound does not fit u64"))?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(GraphemeScalarDfaReduceLimits {
        max_input_bytes: haystack_len,
        max_decode_byte_checks: decode_byte_checks,
        max_classifications: haystack_len,
        max_range_comparisons: range_comparisons,
        max_scanner_steps: scanner_steps.min(reducer_limit),
        max_role_probes: role_probes,
        max_branch_checks: branch_checks,
        max_repetition_tests: repetition_tests,
        max_match_events: haystack_len.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: count,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn inactive_grapheme_scalar_dfa_operation_limits() -> GraphemeScalarDfaReduceLimits {
    GraphemeScalarDfaReduceLimits::default()
}

fn bounded_class_sequence_operation_limits(
    haystack_len: usize,
    build: fre::BoundedClassSequenceBuildAccounting,
    limits: &RunLimits,
) -> Result<BoundedClassSequenceReduceLimits, ExecutionError> {
    let work = checked_aggregate_mul(haystack_len, 28, "bounded class-sequence work")?
        .checked_add(8)
        .ok_or_else(|| ExecutionError::fault("FRE bounded class-sequence work overflow"))?;
    let minimum = usize::try_from(build.minimum)
        .map_err(|_| ExecutionError::fault("FRE bounded class-sequence minimum overflow"))?;
    let minimum_match_bytes = minimum.checked_mul(2).ok_or_else(|| {
        ExecutionError::fault("FRE bounded class-sequence minimum width overflow")
    })?;
    let count = u64::try_from(
        haystack_len
            .checked_div(minimum_match_bytes)
            .ok_or_else(|| ExecutionError::fault("FRE bounded class-sequence minimum is zero"))?,
    )
    .map_err(|_| ExecutionError::fault("FRE bounded class-sequence count overflow"))?;
    Ok(BoundedClassSequenceReduceLimits {
        max_input_bytes: haystack_len,
        max_count: count.min(limits.reducer_steps),
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_peak_bytes: build.persistent_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_bounded_class_sequence_operation_limits() -> BoundedClassSequenceReduceLimits {
    BoundedClassSequenceReduceLimits::default()
}

fn bounded_separated_fields_operation_limits(
    haystack_len: usize,
    identity: fre::BoundedSeparatedFieldsOperationIdentity,
    build: fre::BoundedSeparatedFieldsBuildAccounting,
    limits: &RunLimits,
) -> Result<BoundedSeparatedFieldsReduceLimits, ExecutionError> {
    let authenticated_build = identity.build_accounting();
    if build != authenticated_build {
        return Err(ExecutionError::fault(
            "FRE bounded separated-field resource identity mismatch",
        ));
    }
    let fields = usize::try_from(authenticated_build.fields)
        .map_err(|_| ExecutionError::fault("FRE bounded separated-field count overflow"))?;
    let nonfinal = fields
        .checked_sub(1)
        .ok_or_else(|| ExecutionError::fault("FRE bounded separated-field count is below one"))?;
    let separator_scan_width = authenticated_build
        .maximum_field_width
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE bounded separated-field width overflow"))?;
    let separator_checks = checked_aggregate_mul(
        nonfinal,
        separator_scan_width,
        "bounded separated-field separator checks",
    )?;
    let class_checks = checked_aggregate_add(
        checked_aggregate_mul(
            nonfinal,
            identity.exact_field_checks(),
            "bounded separated-field exact checks",
        )?,
        identity.prefix_field_checks(),
        "bounded separated-field class checks",
    )?;
    let sequential_per_candidate = checked_aggregate_add(
        separator_checks,
        class_checks,
        "bounded separated-field sequential accesses per candidate",
    )?;
    let control_checks = checked_aggregate_add(
        checked_aggregate_add(
            checked_aggregate_mul(fields, 3, "bounded separated-field field control")?,
            checked_aggregate_mul(
                authenticated_build.alternatives,
                fields,
                "bounded separated-field alternative control",
            )?,
            "bounded separated-field loop control",
        )?,
        4,
        "bounded separated-field fixed control",
    )?;
    let work_per_candidate = [separator_checks, class_checks, control_checks]
        .into_iter()
        .try_fold(0_usize, |sum, term| {
            checked_aggregate_add(sum, term, "bounded separated-field candidate work")
        })?;
    let work = checked_aggregate_add(
        checked_aggregate_mul(
            haystack_len,
            work_per_candidate,
            "bounded separated-field haystack work",
        )?,
        8,
        "bounded separated-field finalization work",
    )?;
    let sequential_bytes = checked_aggregate_mul(
        haystack_len,
        sequential_per_candidate,
        "bounded separated-field sequential input accesses",
    )?;
    let minimum_match_width = checked_aggregate_add(
        checked_aggregate_mul(
            fields,
            authenticated_build.minimum_field_width,
            "bounded separated-field minimum fields",
        )?,
        nonfinal,
        "bounded separated-field separators",
    )?;
    let count = u64::try_from(
        haystack_len
            .checked_div(minimum_match_width)
            .ok_or_else(|| {
                ExecutionError::fault("FRE bounded separated-field minimum width is zero")
            })?,
    )
    .map_err(|_| ExecutionError::fault("FRE bounded separated-field count overflow"))?;
    Ok(BoundedSeparatedFieldsReduceLimits {
        max_input_bytes: haystack_len,
        max_sequential_bytes: sequential_bytes.min(limits.fre_aggregate_sequential_bytes),
        max_count: count.min(limits.reducer_steps),
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_peak_bytes: authenticated_build
            .persistent_bytes
            .min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_bounded_separated_fields_operation_limits() -> BoundedSeparatedFieldsReduceLimits {
    BoundedSeparatedFieldsReduceLimits::default()
}

fn prefix_class_alternation_operation_limits(
    upper: fre::PrefixClassAlternationUpperBounds,
    limits: &RunLimits,
) -> Result<PrefixClassAlternationReduceLimits, ExecutionError> {
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(PrefixClassAlternationReduceLimits {
        max_work: upper.work.min(limits.fre_aggregate_operation_work),
        max_match_events: upper.match_events.min(reducer_limit),
        max_count: upper.count.min(limits.reducer_steps),
        max_scratch_bytes: upper.scratch_bytes,
        max_peak_bytes: upper.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_prefix_class_alternation_operation_limits() -> PrefixClassAlternationReduceLimits {
    PrefixClassAlternationReduceLimits::default()
}

fn bounded_literal_pair_operation_limits(
    haystack_len: usize,
    build: fre::BoundedLiteralPairBuildAccounting,
    identity: AggregatePlanIdentity,
    operation: AggregateOperation,
    limits: &RunLimits,
) -> Result<fre::BoundedLiteralPairReduceLimits, ExecutionError> {
    let AggregatePlanIdentity::BoundedLiteralPair(identity) = identity else {
        return Err(ExecutionError::fault(
            "FRE bounded literal-pair accounting lacks its typed identity",
        ));
    };
    if !bounded_literal_pair_build_identity_matches(identity.kernel, build) {
        return Err(ExecutionError::fault(
            "FRE bounded literal-pair resource identity mismatch",
        ));
    }
    let candidate_events = haystack_len;
    let maximum_literal = build.left_bytes.max(build.right_bytes);
    let prefix_comparisons = checked_aggregate_mul(
        candidate_events,
        maximum_literal,
        "bounded literal-pair prefix comparisons",
    )?;
    let gap_classifications = checked_aggregate_mul(
        candidate_events,
        usize::try_from(build.gap_max).map_err(|_| {
            ExecutionError::fault("FRE bounded literal-pair gap does not fit usize")
        })?,
        "bounded literal-pair gap classifications",
    )?;
    let suffix_probes = checked_aggregate_mul(
        candidate_events,
        usize::try_from(build.gap_max)
            .ok()
            .and_then(|gap| gap.checked_add(1))
            .ok_or_else(|| ExecutionError::fault("FRE bounded literal-pair probe overflow"))?,
        "bounded literal-pair suffix probes",
    )?;
    let suffix_comparisons = checked_aggregate_mul(
        suffix_probes,
        maximum_literal,
        "bounded literal-pair suffix comparisons",
    )?;
    let source_reads = [
        haystack_len,
        prefix_comparisons,
        gap_classifications,
        suffix_comparisons,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "bounded literal-pair source reads")
    })?;
    let minimum_match = checked_aggregate_add(
        build.left_bytes,
        build.right_bytes,
        "bounded literal-pair minimum match width",
    )?;
    let match_events = haystack_len.checked_div(minimum_match).ok_or_else(|| {
        ExecutionError::fault("FRE bounded literal-pair minimum match width is zero")
    })?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE bounded literal-pair count does not fit u64"))?;
    let span_sum = match operation {
        AggregateOperation::Compile | AggregateOperation::Count => 0,
        AggregateOperation::SpanSum => u64::try_from(haystack_len).map_err(|_| {
            ExecutionError::fault("FRE bounded literal-pair span sum does not fit u64")
        })?,
        AggregateOperation::Spans => {
            return Err(ExecutionError::fault(
                "FRE bounded literal-pair plan retained a spans operation",
            ));
        }
    };
    let work = bounded_literal_pair_work(
        haystack_len,
        candidate_events,
        prefix_comparisons,
        gap_classifications,
        suffix_probes,
        suffix_comparisons,
        match_events,
    )?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(fre::BoundedLiteralPairReduceLimits {
        max_input_bytes: haystack_len,
        max_source_reads: source_reads,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_candidate_events: candidate_events,
        max_suffix_probes: suffix_probes,
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: span_sum,
        max_scratch_bytes: 0,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn bounded_literal_pair_work(
    haystack_len: usize,
    candidate_events: usize,
    prefix_comparisons: usize,
    gap_classifications: usize,
    suffix_probes: usize,
    suffix_comparisons: usize,
    match_events: usize,
) -> Result<usize, ExecutionError> {
    [
        16,
        haystack_len,
        checked_aggregate_mul(candidate_events, 4, "bounded literal-pair candidate work")?,
        checked_aggregate_mul(prefix_comparisons, 2, "bounded literal-pair prefix work")?,
        checked_aggregate_mul(
            gap_classifications,
            2,
            "bounded literal-pair gap classification work",
        )?,
        checked_aggregate_mul(suffix_probes, 3, "bounded literal-pair suffix probe work")?,
        checked_aggregate_mul(
            suffix_comparisons,
            2,
            "bounded literal-pair suffix comparison work",
        )?,
        checked_aggregate_mul(match_events, 8, "bounded literal-pair match work")?,
    ]
    .into_iter()
    .try_fold(0_usize, |total, term| {
        checked_aggregate_add(total, term, "bounded literal-pair total work")
    })
}

fn inactive_bounded_literal_pair_operation_limits() -> fre::BoundedLiteralPairReduceLimits {
    fre::BoundedLiteralPairReduceLimits::default()
}

fn bounded_context_operation_limits(
    operation: AggregateOperation,
    upper: fre::AggregateRetainedFullWindowUpperBounds,
    limits: &RunLimits,
) -> Result<fre::BoundedContextReduceLimits, ExecutionError> {
    let (input_bytes, work, match_events, operation_value, scratch_bytes, peak_bytes) =
        match (operation, upper) {
            (
                AggregateOperation::Compile | AggregateOperation::Count,
                fre::AggregateRetainedFullWindowUpperBounds::BoundedContextCount(upper),
            ) => (
                upper.input_bytes,
                upper.work,
                upper.match_events,
                upper.count,
                upper.scratch_bytes,
                upper.peak_bytes,
            ),
            (
                AggregateOperation::SpanSum,
                fre::AggregateRetainedFullWindowUpperBounds::BoundedContextSpanSum(upper),
            ) => (
                upper.input_bytes,
                upper.work,
                upper.match_events,
                upper.span_sum,
                upper.scratch_bytes,
                upper.peak_bytes,
            ),
            _ => {
                return Err(ExecutionError::fault(
                    "FRE bounded-context retained-owner envelope is absent or transplanted",
                ));
            }
        };
    Ok(fre::BoundedContextReduceLimits {
        max_input_bytes: input_bytes,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_match_events: match_events,
        max_count: operation_value.min(limits.reducer_steps),
        max_scratch_bytes: scratch_bytes.min(limits.fre_aggregate_scratch_bytes),
        max_peak_bytes: peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn inactive_bounded_context_operation_limits() -> fre::BoundedContextReduceLimits {
    fre::BoundedContextReduceLimits::default()
}

fn inactive_fixed_absolute_operation_limits() -> fre::FixedAbsoluteDomainReduceLimits {
    fre::FixedAbsoluteDomainReduceLimits::default()
}

fn inactive_fixed_absolute_residual_limits() -> fre::AggregateFixedAbsoluteDomainResidualLimits {
    fre::AggregateFixedAbsoluteDomainResidualLimits::default()
}

fn fixed_absolute_residual_limits(
    prospective: fre::AggregateFixedAbsoluteDomainResidualProspective,
    limits: &RunLimits,
) -> fre::AggregateFixedAbsoluteDomainResidualLimits {
    fre::AggregateFixedAbsoluteDomainResidualLimits {
        max_work: prospective
            .total_work
            .min(limits.fre_aggregate_operation_work),
        max_allocations: prospective.allocations,
        max_persistent_bytes: prospective
            .persistent_bytes
            .min(limits.fre_aggregate_peak_bytes),
        max_peak_bytes: prospective.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    }
}

fn fixed_absolute_build_contains(
    prospective: fre::FixedAbsoluteDomainBuildProspective,
    actual: fre::FixedAbsoluteDomainBuildActual,
) -> bool {
    actual.items <= prospective.items
        && actual.payload_bytes <= prospective.payload_bytes
        && actual.identity_bytes <= prospective.identity_bytes
        && actual.retained_heap_bytes <= prospective.retained_heap_bytes
        && actual.copied_bytes <= prospective.copied_bytes
        && actual.allocations <= prospective.allocations
        && actual.initialized_bytes <= prospective.initialized_bytes
        && actual.build_work <= prospective.build_work
        && actual.scratch_bytes <= prospective.scratch_bytes
        && actual.persistent_bytes <= prospective.persistent_bytes
        && actual.peak_bytes <= prospective.peak_bytes
}

fn fixed_absolute_operation_limits(
    prospective: fre::FixedAbsoluteDomainProspective,
    identity: fre::AggregateFixedAbsoluteDomainIdentity,
    build: &fre::AggregateFixedAbsoluteDomainBuildAccounting,
    limits: &RunLimits,
) -> Result<fre::FixedAbsoluteDomainReduceLimits, ExecutionError> {
    let descriptor = identity.kernel.descriptor;
    if build.kernel.prospective.descriptor != descriptor
        || !build.kernel.actual.published
        || !fixed_absolute_build_contains(build.kernel.prospective, build.kernel.actual)
        || build.kernel.actual.persistent_bytes != build.kernel.prospective.persistent_bytes
    {
        return Err(ExecutionError::fault(
            "FRE fixed absolute-domain build receipt is not closed",
        ));
    }
    if prospective.allocations != 0 {
        return Err(ExecutionError::fault(
            "FRE fixed absolute-domain prospective unexpectedly allocates",
        ));
    }
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(fre::FixedAbsoluteDomainReduceLimits {
        max_byte_probes: prospective.byte_probes,
        max_branch_checks: prospective.branch_checks,
        max_match_events: prospective.match_events.min(reducer_limit),
        max_count: prospective.count.min(limits.reducer_steps),
        max_span_sum: prospective.span_sum,
        max_reducer_steps: prospective.reducer_steps.min(reducer_limit),
        max_total_work: prospective
            .total_work
            .min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: prospective
            .scratch_bytes
            .min(limits.fre_aggregate_scratch_bytes),
        max_persistent_bytes: prospective
            .persistent_bytes
            .min(limits.fre_aggregate_peak_bytes),
        max_peak_bytes: prospective.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

fn ordered_literal_operation_limits(
    haystack_len: usize,
    build: Option<fre::OrderedLiteralAggregateBuildAccounting>,
    limits: &RunLimits,
) -> Result<OrderedLiteralAggregateReduceLimits, ExecutionError> {
    let boundaries = checked_aggregate_add(haystack_len, 1, "finite literal boundaries")?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let (match_events, ring_initializations) = if let Some(build) = build {
        let events = if build.has_empty_pattern {
            boundaries
        } else {
            let minimum = build.min_nonempty_pattern_bytes.ok_or_else(|| {
                ExecutionError::fault("FRE finite literal plan lacks a nonempty minimum")
            })?;
            haystack_len
                .checked_div(minimum)
                .ok_or_else(|| ExecutionError::fault("FRE finite literal minimum is zero"))?
        };
        let ring = build
            .max_pattern_bytes
            .min(haystack_len)
            .checked_add(1)
            .ok_or_else(|| ExecutionError::fault("FRE finite literal ring overflow"))?;
        (events, ring)
    } else {
        (boundaries, boundaries)
    };
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE finite literal count bound does not fit u64"))?;
    Ok(OrderedLiteralAggregateReduceLimits {
        max_transitions: haystack_len,
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("FRE finite literal span bound does not fit u64"))?,
        max_reducer_steps: boundaries.min(reducer_limit),
        max_ring_initializations: ring_initializations,
        max_total_work: limits.fre_aggregate_operation_work,
        max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn packed_ordered_literal_operation_limits(
    haystack_len: usize,
    build: fre::PackedOrderedLiteralAggregateBuildAccounting,
    limits: &RunLimits,
) -> Result<OrderedLiteralAggregateReduceLimits, ExecutionError> {
    if build.min_pattern_bytes == 0 {
        return Err(ExecutionError::fault(
            "FRE packed finite literal minimum is zero",
        ));
    }
    let match_events = haystack_len
        .checked_div(build.min_pattern_bytes)
        .ok_or_else(|| ExecutionError::fault("FRE packed finite literal minimum is zero"))?;
    let candidate_positions = if haystack_len < build.min_pattern_bytes {
        0
    } else {
        haystack_len
            .checked_sub(build.min_pattern_bytes)
            .and_then(|remaining| remaining.checked_add(1))
            .ok_or_else(|| {
                ExecutionError::fault("FRE packed finite candidate-position bound overflow")
            })?
    };
    let reducer_steps = candidate_positions
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE packed finite reducer-step bound overflow"))?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE packed finite count bound does not fit u64"))?;
    Ok(OrderedLiteralAggregateReduceLimits {
        max_transitions: haystack_len,
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("FRE packed finite span bound does not fit u64"))?,
        max_reducer_steps: reducer_steps.min(reducer_limit),
        max_ring_initializations: 0,
        max_total_work: limits.fre_aggregate_operation_work,
        max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn sparse_ordered_literal_operation_limits(
    haystack_len: usize,
    build: fre::SparseOrderedLiteralAggregateBuildAccounting,
    limits: &RunLimits,
) -> Result<OrderedLiteralAggregateReduceLimits, ExecutionError> {
    let boundaries = checked_aggregate_add(haystack_len, 1, "sparse finite boundaries")?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let match_events = if build.has_empty_pattern {
        boundaries
    } else {
        let minimum = build.min_nonempty_pattern_bytes.ok_or_else(|| {
            ExecutionError::fault("FRE sparse finite plan lacks a nonempty minimum")
        })?;
        haystack_len
            .checked_div(minimum)
            .ok_or_else(|| ExecutionError::fault("FRE sparse finite minimum is zero"))?
    };
    let ring_initializations = build
        .max_pattern_bytes
        .min(haystack_len)
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE sparse finite ring overflow"))?;
    let edge_lookups = checked_aggregate_mul(haystack_len, 2, "sparse edge lookups")?;
    let edge_search_checks = checked_aggregate_mul(
        edge_lookups,
        build.max_edge_search_checks,
        "sparse edge search checks",
    )?;
    let total_work = checked_aggregate_add(
        checked_aggregate_add(
            checked_aggregate_add(
                checked_aggregate_add(
                    haystack_len,
                    edge_lookups,
                    "sparse transitions plus edge lookups",
                )?,
                edge_search_checks,
                "sparse edge comparison work",
            )?,
            haystack_len,
            "sparse failure work",
        )?,
        checked_aggregate_add(
            boundaries,
            ring_initializations,
            "sparse reducer plus ring work",
        )?,
        "sparse finite total work",
    )?;
    let count = u64::try_from(match_events)
        .map_err(|_| ExecutionError::fault("FRE sparse finite count does not fit u64"))?;
    Ok(OrderedLiteralAggregateReduceLimits {
        max_transitions: haystack_len,
        max_match_events: match_events.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: u64::try_from(haystack_len)
            .map_err(|_| ExecutionError::fault("FRE sparse finite span does not fit u64"))?,
        max_reducer_steps: boundaries.min(reducer_limit),
        max_ring_initializations: ring_initializations,
        max_total_work: total_work.min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn guarded_ascii_word_build_accounting_is_closed(
    build: fre::AggregateGuardedAsciiWordBuildAccounting,
) -> bool {
    let prospective = build.dictionary.prospective;
    let Some(actual) = build.dictionary.actual() else {
        return false;
    };
    build.allocations_upper_bound >= prospective.allocations
        && build.allocations_actual >= actual.allocations
        && build.allocations_actual <= build.allocations_upper_bound
        && build.initialized_bytes_upper_bound >= prospective.initialized_bytes
        && build.initialized_bytes_actual >= actual.initialized_bytes
        && build.initialized_bytes_actual <= build.initialized_bytes_upper_bound
        && build.peak_bytes_upper_bound >= prospective.peak_bytes
        && build.peak_bytes_actual_upper_bound >= actual.peak_bytes
        && build.peak_bytes_actual_upper_bound <= build.peak_bytes_upper_bound
}

fn guarded_ascii_word_operation_limits(
    haystack_len: usize,
    build: fre::AggregateGuardedAsciiWordBuildAccounting,
    limits: &RunLimits,
) -> Result<OrderedLiteralAggregateReduceLimits, ExecutionError> {
    if !guarded_ascii_word_build_accounting_is_closed(build) {
        return Err(ExecutionError::fault(
            "FRE guarded dictionary build accounting is not closed",
        ));
    }
    let upper = guarded_ascii_word::published_reduce_upper_bounds(build.dictionary, haystack_len)
        .map_err(|error| {
        ExecutionError::fault(format!(
            "FRE guarded dictionary could not close execution bounds: {error}"
        ))
    })?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    Ok(OrderedLiteralAggregateReduceLimits {
        max_transitions: upper.haystack_bytes,
        max_match_events: upper.candidate_words.min(reducer_limit),
        max_count: upper.matches.min(limits.reducer_steps),
        max_span_sum: upper.span_sum,
        max_reducer_steps: upper.lookup_steps.min(reducer_limit),
        max_ring_initializations: 0,
        max_total_work: upper.total_work.min(limits.fre_aggregate_operation_work),
        max_scratch_bytes: 0,
        max_peak_bytes: upper.peak_bytes.min(limits.fre_aggregate_peak_bytes),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive aggregate-plan dispatch keeps every plan's inactive limits explicit"
)]
fn aggregate_run_limits_with_fixed_absolute(
    haystack_len: usize,
    report: &AggregateBuildReport,
    retained_upper_bounds: Option<fre::AggregateRetainedFullWindowUpperBounds>,
    fixed_absolute_prospective: Option<fre::FixedAbsoluteDomainProspective>,
    fixed_absolute_composite: Option<fre::AggregateFixedAbsoluteDomainResidualProspective>,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    require_closed_bounded_separated_fields_identity(report)?;
    require_closed_fixed_absolute_domain_identity(report)?;
    require_closed_required_internal_anchor_identity(report)?;
    require_closed_url_aggregate_identity(report)?;
    require_closed_construction_attempt(report)?;
    let retained_bounds_required = matches!(
        report.build,
        AggregateBuildAccounting::UnicodeScalar(_)
            | AggregateBuildAccounting::PrefixClassAlternation(_)
            | AggregateBuildAccounting::LiteralClassRunLiteral(_)
            | AggregateBuildAccounting::BoundedContext(_)
    );
    if retained_bounds_required != retained_upper_bounds.is_some() {
        return Err(ExecutionError::fault(
            "FRE retained direct-owner full-window envelope is absent or transplanted",
        ));
    }
    if matches!(
        report.build,
        AggregateBuildAccounting::FixedAbsoluteDomain(_)
    ) != fixed_absolute_prospective.is_some()
    {
        return Err(ExecutionError::fault(
            "FRE fixed absolute-domain artifact/prospective binding is absent or transplanted",
        ));
    }
    let residual_fixed_absolute = fixed_absolute_prospective.is_some_and(|prospective| {
        prospective.disposition == fre::FixedAbsoluteDomainDisposition::PrepublishedContinuation
    });
    if residual_fixed_absolute != fixed_absolute_composite.is_some() {
        return Err(ExecutionError::fault(
            "FRE fixed scalar artifact/composite prospective binding is absent or transplanted",
        ));
    }
    match report.build {
        AggregateBuildAccounting::ExactLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: literal_operation_limits(haystack_len, build, limits)?,
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            // The continuation policy remains present in cache identity even
            // though no continuation engine exists and no fallback is legal.
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::UnicodeScalar(_) => {
            let Some(fre::AggregateRetainedFullWindowUpperBounds::UnicodeScalar(upper)) =
                retained_upper_bounds
            else {
                return Err(ExecutionError::fault(
                    "FRE Unicode scalar retained-owner envelope is absent or transplanted",
                ));
            };
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: unicode_scalar_operation_limits(upper, limits)?,
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::WordRun(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: word_run_operation_limits(haystack_len, build, report.operation, limits)?,
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::LiteralAssertions(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: literal_assertions_operation_limits(
                haystack_len,
                build,
                report.operation,
                limits,
            )?,
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::BlockingDelimiter(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: blocking_delimiter_operation_limits(
                haystack_len,
                build,
                report.operation,
                limits,
            )?,
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::TokenPhrase(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: token_phrase_operation_limits(
                haystack_len,
                build,
                report.operation,
                limits,
            )?,
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::FixedClassSandwich(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: fixed_class_sandwich_operation_limits(
                haystack_len,
                build,
                limits,
            )?,
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::GraphemeScalarDfa(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: grapheme_scalar_dfa_operation_limits(haystack_len, build, limits)?,
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::BoundedClassSequence(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: bounded_class_sequence_operation_limits(
                haystack_len,
                build,
                limits,
            )?,
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::BoundedSeparatedFields(build) => {
            let AggregatePlanIdentity::BoundedSeparatedFields(identity) = report.plan_identity
            else {
                return Err(ExecutionError::fault(
                    "FRE bounded separated-field resource identity is absent",
                ));
            };
            if !report.authenticates_bounded_separated_fields_identity(identity) {
                return Err(ExecutionError::fault(
                    "FRE bounded separated-field resource identity mismatch",
                ));
            }
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: bounded_separated_fields_operation_limits(
                    haystack_len,
                    identity.kernel,
                    build,
                    limits,
                )?,
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::PrefixClassAlternation(_) => {
            let Some(fre::AggregateRetainedFullWindowUpperBounds::PrefixClassAlternation(upper)) =
                retained_upper_bounds
            else {
                return Err(ExecutionError::fault(
                    "FRE prefix/class retained-owner envelope is absent or transplanted",
                ));
            };
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: prefix_class_alternation_operation_limits(upper, limits)?,
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::LiteralClassRunLiteral(_) => {
            let Some(fre::AggregateRetainedFullWindowUpperBounds::LiteralClassRunLiteral(upper)) =
                retained_upper_bounds
            else {
                return Err(ExecutionError::fault(
                    "FRE literal/class-run/literal retained-owner envelope is absent or transplanted",
                ));
            };
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: literal_class_run_literal_operation_limits(
                    upper, limits,
                )?,
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::BoundedLiteralPair(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: bounded_literal_pair_operation_limits(
                haystack_len,
                build,
                report.plan_identity,
                report.operation,
                limits,
            )?,
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::BoundedContext(_) => {
            let upper = retained_upper_bounds.ok_or_else(|| {
                ExecutionError::fault("FRE bounded-context retained-owner envelope is absent")
            })?;
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: bounded_context_operation_limits(report.operation, upper, limits)?,
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::FixedAbsoluteDomain(_) => {
            let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = report.plan_identity else {
                return Err(ExecutionError::fault(
                    "FRE fixed absolute-domain resource identity is absent",
                ));
            };
            let build = report
                .fixed_absolute_domain_build_accounting()
                .ok_or_else(|| {
                    ExecutionError::fault(
                        "FRE fixed absolute-domain full build accounting is not authenticated",
                    )
                })?;
            let continuation = if let Some(compile) = build.residual {
                continuation_operation_limits(
                    haystack_len,
                    ContinuationProgramShape::from(compile),
                    limits,
                )?
            } else {
                continuation_operation_limits(haystack_len, inactive_continuation_shape(), limits)?
            };
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: fixed_absolute_operation_limits(
                    fixed_absolute_prospective.ok_or_else(|| {
                        ExecutionError::fault("FRE fixed absolute-domain prospective is absent")
                    })?,
                    identity,
                    build,
                    limits,
                )?,
                fixed_absolute_residual: fixed_absolute_composite
                    .map_or_else(inactive_fixed_absolute_residual_limits, |prospective| {
                        fixed_absolute_residual_limits(prospective, limits)
                    }),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation,
            })
        }
        AggregateBuildAccounting::FiniteLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, Some(build), limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::PackedFiniteLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: packed_ordered_literal_operation_limits(haystack_len, build, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::SparseFiniteLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            finite_literal: sparse_ordered_literal_operation_limits(haystack_len, build, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::GuardedAsciiWord(build) => {
            let AggregatePlanIdentity::GuardedAsciiWord(identity) = report.plan_identity else {
                return Err(ExecutionError::fault(
                    "FRE guarded ASCII-word resource identity is absent",
                ));
            };
            let operation = match report.operation {
                AggregateOperation::Compile | AggregateOperation::Count => {
                    LiteralAggregateOperation::Count
                }
                AggregateOperation::SpanSum => LiteralAggregateOperation::SpanSum,
                AggregateOperation::Spans => {
                    return Err(ExecutionError::fault(
                        "FRE guarded ASCII-word resource operation is invalid",
                    ));
                }
            };
            if !guarded_ascii_word_plan_identity_matches(report, identity, build, false, operation)
            {
                return Err(ExecutionError::fault(
                    "FRE guarded ASCII-word resource identity mismatch",
                ));
            }
            Ok(AggregateRunLimits {
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: guarded_ascii_word_operation_limits(haystack_len, build, limits)?,
                continuation: continuation_operation_limits(
                    haystack_len,
                    inactive_continuation_shape(),
                    limits,
                )?,
            })
        }
        AggregateBuildAccounting::FixedPredicateWord64(_) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            word_run: inactive_word_run_operation_limits(),
            literal_assertions: inactive_literal_assertions_operation_limits(),
            blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
            token_phrase: inactive_token_phrase_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
            bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            fixed_absolute: inactive_fixed_absolute_operation_limits(),
            fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
            // The facade adapts the existing finite envelope to this
            // allocation-free reducer; no independent quota is introduced.
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::Continuation(compile) => {
            if report.authenticates_url_aggregate_identity()
                && report.continuation_strategy == Some(AggregateStrategy::ReverseSequentialRows)
                && matches!(
                    report.operation,
                    AggregateOperation::Count | AggregateOperation::SpanSum
                )
            {
                let continuation = url_aggregate_operation_limits(haystack_len, limits)?;
                return Ok(AggregateRunLimits {
                    exact_literal: inactive_literal_operation_limits(limits),
                    unicode_scalar: inactive_unicode_scalar_operation_limits(),
                    word_run: inactive_word_run_operation_limits(),
                    literal_assertions: inactive_literal_assertions_operation_limits(),
                    blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                    token_phrase: inactive_token_phrase_operation_limits(),
                    fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                    grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                    bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                    bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                    prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                    literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(
                    ),
                    bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                    bounded_context: inactive_bounded_context_operation_limits(),
                    fixed_absolute: inactive_fixed_absolute_operation_limits(),
                    fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                    finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                    continuation,
                });
            }
            let mut shape = ContinuationProgramShape::from(compile);
            if report.operation != fre::AggregateOperation::Count {
                shape.required_internal_anchors = 0;
                shape.required_internal_anchor_bytes = 0;
                shape.required_internal_anchor_optional_stages = 0;
                shape.required_internal_anchor_persistent_bytes = 0;
            }
            Ok(AggregateRunLimits {
                // Literal policy remains present in cache identity even when HIR
                // eligibility selected the continuation program.
                exact_literal: inactive_literal_operation_limits(limits),
                unicode_scalar: inactive_unicode_scalar_operation_limits(),
                word_run: inactive_word_run_operation_limits(),
                literal_assertions: inactive_literal_assertions_operation_limits(),
                blocking_delimiter: inactive_blocking_delimiter_operation_limits(),
                token_phrase: inactive_token_phrase_operation_limits(),
                fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
                grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
                bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
                bounded_separated_fields: inactive_bounded_separated_fields_operation_limits(),
                prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
                literal_class_run_literal: inactive_literal_class_run_literal_operation_limits(),
                bounded_literal_pair: inactive_bounded_literal_pair_operation_limits(),
                bounded_context: inactive_bounded_context_operation_limits(),
                fixed_absolute: inactive_fixed_absolute_operation_limits(),
                fixed_absolute_residual: inactive_fixed_absolute_residual_limits(),
                finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
                continuation: continuation_operation_limits(haystack_len, shape, limits)?,
            })
        }
    }
}

fn aggregate_run_limits(
    haystack_len: usize,
    report: &AggregateBuildReport,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    aggregate_run_limits_with_fixed_absolute(haystack_len, report, None, None, None, limits)
}

fn finite_plan_identity_matches(
    identity: AggregateFiniteLiteralIdentity,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let (dense_finite_operation, packed_finite_operation, sparse_finite_operation) = match operation
    {
        LiteralAggregateOperation::Count => (
            ORDERED_LITERAL_COUNT_PLAN_ID,
            fre::PACKED_ORDERED_LITERAL_COUNT_PLAN_ID,
            SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
        ),
        LiteralAggregateOperation::SpanSum => (
            ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
            fre::PACKED_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
            SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
        ),
    };
    let expected_semantics = if unicode {
        AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
    } else {
        AggregateFiniteLiteralSemantics::UnicodeOffByteBoundaries
    };
    let representation_matches = (identity.algorithm == ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
        && identity.operation == dense_finite_operation
        && identity.packed_operation_identity.is_none())
        || (identity.algorithm == fre::PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
            && identity.operation == packed_finite_operation
            && identity.packed_operation_identity.is_some_and(|native| {
                native.algorithm_id == fre::PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
                    && native.plan_id == packed_finite_operation
            }))
        || (identity.algorithm == SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
            && identity.operation == sparse_finite_operation
            && identity.packed_operation_identity.is_none());
    identity.semantics == expected_semantics && representation_matches
}

fn exact_literal_plan_identity_matches(
    identity: fre::AggregateExactLiteralIdentity,
    semantics: AggregateExactLiteralSemantics,
    operation: LiteralAggregateOperation,
) -> bool {
    identity.semantics == semantics && identity.kernel.authenticates_operation(operation)
}

fn word_run_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateWordRunIdentity,
    build: fre::WordRunBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let semantic_identity = match identity.semantics {
        fre::AggregateWordRunSemantics::AsciiWordBytes => {
            identity.kernel.plan_id == fre::ASCII_WORD_RUN_PLAN_ID
                && identity.kernel.minimum_scalars > 0
                && identity.kernel.fixed_chunk_bytes.is_none()
                && identity.kernel.canonical_class_words == [0; 4]
                && !identity.kernel.unicode
                && identity.kernel.complete_word_boundaries
                && identity.kernel.invalid_bytes_are_non_word
                && !identity.kernel.arbitrary_bytes_are_classified
        }
        fre::AggregateWordRunSemantics::UnicodeWordScalarsInvalidBytesNonWord => {
            identity.kernel.plan_id == fre::UNICODE_WORD_RUN_PLAN_ID
                && identity.kernel.minimum_scalars > 0
                && identity.kernel.fixed_chunk_bytes.is_none()
                && identity.kernel.canonical_class_words == [0; 4]
                && identity.kernel.unicode
                && identity.kernel.complete_word_boundaries
                && identity.kernel.invalid_bytes_are_non_word
                && !identity.kernel.arbitrary_bytes_are_classified
        }
        fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks => {
            identity.kernel.plan_id == fre::FIXED_CLASS_CHUNKS_PLAN_ID
                && identity.kernel.minimum_scalars == 0
                && identity
                    .kernel
                    .fixed_chunk_bytes
                    .is_some_and(|width| width > 64)
                && identity.kernel.canonical_class_words != [0; 4]
                && !identity.kernel.unicode
                && !identity.kernel.complete_word_boundaries
                && !identity.kernel.invalid_bytes_are_non_word
                && identity.kernel.arbitrary_bytes_are_classified
        }
    };
    let expected_operation_id = match (identity.semantics, operation) {
        (
            fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks,
            LiteralAggregateOperation::Count,
        ) => fre::FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID,
        (
            fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks,
            LiteralAggregateOperation::SpanSum,
        ) => fre::FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID,
        (_, LiteralAggregateOperation::Count) => fre::WORD_RUN_COUNT_OPERATION_ID,
        (_, LiteralAggregateOperation::SpanSum) => fre::WORD_RUN_SPAN_SUM_OPERATION_ID,
    };
    operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::WordRun
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && semantic_identity
        && identity.kernel.operation_id == expected_operation_id
        && identity.kernel.greedy
        && identity.kernel.non_overlapping
        && (unicode || !identity.kernel.unicode)
        && fre::word_run_build_accounting_matches(identity.kernel, build)
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn literal_assertions_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateLiteralAssertionsIdentity,
    build: LiteralAssertionsBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let expected_operation_id = match operation {
        LiteralAggregateOperation::Count => fre::LITERAL_ASSERTIONS_COUNT_OPERATION_ID,
        LiteralAggregateOperation::SpanSum => fre::LITERAL_ASSERTIONS_SPAN_SUM_OPERATION_ID,
    };
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let expected_semantics = if unicode {
        fre::AggregateLiteralAssertionsSemantics::UnicodeOnByteStableLiteral
    } else {
        fre::AggregateLiteralAssertionsSemantics::UnicodeOffByteLiteral
    };
    let profile_matches = matches!(
        &report.syntax_key.profile,
        CompatibilityProfile::RustBytes(profile)
            if profile.options.unicode == unicode
                && profile.options.line_terminator == identity.kernel.line_terminator
    );
    operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::LiteralAssertions
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.semantics == expected_semantics
        && identity.kernel.plan_id == fre::LITERAL_ASSERTIONS_PLAN_ID
        && identity.kernel.operation_id == expected_operation_id
        && identity.kernel.literal_bytes == build.literal_bytes
        && identity.kernel.literal_bytes > 0
        && identity.kernel.topology
            == fre::LiteralAssertionsTopology::StartLineLiteralOrLiteralEndLine
        && identity.kernel.branch_ordered
        && identity.kernel.overlap_complete
        && identity.kernel.non_overlapping
        && profile_matches
        && build.work_upper_bound > 0
        && build.scratch_bytes == 0
        && build.persistent_bytes > build.literal_bytes
        && build.peak_bytes == build.persistent_bytes
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn blocking_delimiter_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateBlockingDelimiterIdentity,
    build: BlockingDelimiterBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let expected_operation_id = match operation {
        LiteralAggregateOperation::Count => fre::BLOCKING_DELIMITER_COUNT_OPERATION_ID,
        LiteralAggregateOperation::SpanSum => fre::BLOCKING_DELIMITER_SPAN_SUM_OPERATION_ID,
    };
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let terminal_members = identity
        .kernel
        .terminal_words
        .into_iter()
        .try_fold(0_usize, |total, word| {
            total.checked_add(usize::try_from(word.count_ones()).ok()?)
        });
    let profile_matches = matches!(
        &report.syntax_key.profile,
        CompatibilityProfile::RustBytes(profile)
            if !profile.options.unicode && !profile.options.case_insensitive
    );
    !unicode
        && operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::BlockingDelimiter
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.semantics
            == fre::AggregateBlockingDelimiterSemantics::UnicodeOffBlockingByteDelimiters
        && identity.kernel.plan_id == fre::BLOCKING_DELIMITER_PLAN_ID
        && identity.kernel.operation_id == expected_operation_id
        && identity.kernel.delimiters[0] < identity.kernel.delimiters[1]
        && !identity.kernel.delimiters.into_iter().any(|delimiter| {
            let word = usize::from(delimiter >> 6);
            let bit = u32::from(delimiter & 63);
            identity.kernel.terminal_words[word] & (1_u64 << bit) != 0
        })
        && identity.kernel.maximum_middle_bytes == build.maximum_middle_bytes
        && identity.kernel.topology
            == fre::BlockingDelimiterTopology::DelimiterComplementBoundedTerminalDelimiter
        && !identity.kernel.unicode
        && identity.kernel.greedy
        && identity.kernel.blocking_delimiter
        && identity.kernel.non_overlapping
        && profile_matches
        && build.delimiter_members == 2
        && terminal_members == Some(build.terminal_members)
        && build.terminal_members > 0
        && build.work_upper_bound > 0
        && build.scratch_bytes == 0
        && build.persistent_bytes > 0
        && build.peak_bytes == build.persistent_bytes
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn token_phrase_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateTokenPhraseIdentity,
    build: TokenPhraseBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let expected_operation_id = match operation {
        LiteralAggregateOperation::Count => fre::TOKEN_PHRASE_COUNT_OPERATION_ID,
        LiteralAggregateOperation::SpanSum => fre::TOKEN_PHRASE_SPAN_SUM_OPERATION_ID,
    };
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let profile_matches = matches!(
        &report.syntax_key.profile,
        CompatibilityProfile::RustBytes(profile)
            if !profile.options.unicode && !profile.options.case_insensitive
    );
    !unicode
        && operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::TokenPhrase
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.semantics == fre::AggregateTokenPhraseSemantics::UnicodeOffAsciiWordSpaceTokens
        && identity.kernel.plan_id == fre::TOKEN_PHRASE_PLAN_ID
        && identity.kernel.operation_id == expected_operation_id
        && identity.kernel.literal_bytes == build.literal_bytes
        && identity.kernel.literal_bytes > 0
        && identity.kernel.topology == fre::TokenPhraseTopology::WordSpaceLiteralSpaceWord
        && !identity.kernel.unicode
        && identity.kernel.greedy
        && identity.kernel.maximal_tokens
        && identity.kernel.non_overlapping
        && profile_matches
        && build.work_upper_bound > 0
        && build.scratch_bytes == 0
        && build.persistent_bytes > build.literal_bytes
        && build.peak_bytes == build.persistent_bytes
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn fixed_predicate_word64_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::FixedPredicateWord64OperationIdentity,
    build: fre::FixedPredicateWord64BuildAccounting,
    operation: LiteralAggregateOperation,
) -> bool {
    let (kernel_operation, operation_id) = match operation {
        LiteralAggregateOperation::Count => (
            FixedPredicateWord64Operation::Count,
            fre::FIXED_PREDICATE_WORD64_COUNT_OPERATION_ID,
        ),
        LiteralAggregateOperation::SpanSum => (
            FixedPredicateWord64Operation::SpanSum,
            fre::FIXED_PREDICATE_WORD64_SPAN_SUM_OPERATION_ID,
        ),
    };
    let facade_operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let unicode_off_profile = matches!(
        &report.syntax_key.profile,
        CompatibilityProfile::RustBytes(profile) if !profile.options.unicode
    );
    let source_ranges_in_range = build.source_ranges > build.positions
        && build.source_ranges <= build.positions.saturating_mul(2);
    let capture_erasure_matches = [2_usize, 3_usize].into_iter().any(|passes| {
        report
            .captures_erased
            .checked_mul(passes)
            .is_some_and(|work| work == report.capture_erasure_work)
    });

    unicode_off_profile
        && facade_operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::FixedPredicateWord64
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.plan_id == fre::FIXED_PREDICATE_WORD64_PLAN_ID
        && identity.operation_id == operation_id
        && identity.operation == kernel_operation
        && identity.semantics == FixedPredicateWord64MatchSemantics::FixedBytePredicates
        && identity.selection == FixedPredicateWord64MatchSelection::LeftmostFirstNonOverlapping
        && identity.width == build.positions
        && (fre::FIXED_PREDICATE_WORD64_MIN_WIDTH..=fre::FIXED_PREDICATE_WORD64_MAX_WIDTH)
            .contains(&build.positions)
        && source_ranges_in_range
        && build.mask_zero_writes == fre::FIXED_PREDICATE_WORD64_MASK_SLOTS
        && build.position_visits == build.positions
        && build.range_inspections == build.source_ranges
        && build.member_writes == build.source_ranges
        && build.work_charged <= build.work_upper_bound
        && build.allocations == 0
        && build.reserves == 0
        && build.temporary_copies == 0
        && build.scratch_bytes == 0
        && build.peak_bytes == build.persistent_bytes
        && capture_erasure_matches
        && report.finite_planner_work > 0
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn guarded_ascii_word_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateGuardedAsciiWordIdentity,
    build: fre::AggregateGuardedAsciiWordBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let dictionary = build.dictionary;
    let prospective = dictionary.prospective;
    let Some(actual) = dictionary.actual() else {
        return false;
    };
    let (report_operation_matches, expected_operation_id) = match operation {
        LiteralAggregateOperation::Count => (
            matches!(
                report.operation,
                AggregateOperation::Compile | AggregateOperation::Count
            ),
            guarded_ascii_word::COUNT_OPERATION_ID,
        ),
        LiteralAggregateOperation::SpanSum => (
            report.operation == AggregateOperation::SpanSum,
            guarded_ascii_word::SPAN_SUM_OPERATION_ID,
        ),
    };
    !unicode
        && report_operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::GuardedAsciiWordDictionary
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.semantics
            == fre::AggregateGuardedAsciiWordSemantics::UnicodeOffMaximalAsciiWords
        && identity.dictionary == guarded_ascii_word::PLAN_ID
        && identity.packing == guarded_ascii_word::PACKING_ID
        && identity.lookup == guarded_ascii_word::LOOKUP_ID
        && identity.fingerprint == guarded_ascii_word::FINGERPRINT_ID
        && identity.operation == expected_operation_id
        && prospective.dimensions.words > 0
        && prospective.dimensions.packed_bytes >= prospective.dimensions.words
        && guarded_ascii_word_build_accounting_is_closed(build)
        && report.retained_capacity_bytes == actual.persistent_bytes
}

fn bounded_separated_fields_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateBoundedSeparatedFieldsIdentity,
    build: fre::BoundedSeparatedFieldsBuildAccounting,
    operation: LiteralAggregateOperation,
) -> bool {
    let kernel = identity.kernel;
    let authenticated_build = kernel.build_accounting();
    let fields_in_range = (2..=fre::BOUNDED_SEPARATED_FIELDS_MAX_FIELDS).contains(&kernel.fields);
    let alternatives = usize::from(kernel.alternatives);
    let alternatives_in_range =
        (1..=fre::BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES).contains(&alternatives);
    let minimum_width = usize::from(kernel.minimum_field_width);
    let maximum_width = usize::from(kernel.maximum_field_width);
    let widths_in_range = minimum_width <= maximum_width
        && (1..=fre::BOUNDED_SEPARATED_FIELDS_MAX_ATOMS).contains(&maximum_width);
    let peak_matches = authenticated_build
        .persistent_bytes
        .checked_add(authenticated_build.scratch_bytes)
        == Some(authenticated_build.peak_bytes);

    operation == LiteralAggregateOperation::Count
        && report.operation == AggregateOperation::Count
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::BoundedSeparatedFields
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && kernel.plan_id == fre::BOUNDED_SEPARATED_FIELDS_PLAN_ID
        && kernel.operation_id == fre::BOUNDED_SEPARATED_FIELDS_COUNT_OPERATION_ID
        && kernel.greedy
        && kernel.non_overlapping
        && report.authenticates_bounded_separated_fields_identity(identity)
        && fields_in_range
        && alternatives_in_range
        && widths_in_range
        && build == authenticated_build
        && kernel.separator == build.separator
        && kernel.fields == build.fields
        && alternatives == build.alternatives
        && minimum_width == build.minimum_field_width
        && maximum_width == build.maximum_field_width
        && authenticated_build.allocations == 0
        && authenticated_build.reserves == 0
        && authenticated_build.temporary_copies == 1
        && kernel.exact_field_checks() == authenticated_build.atoms
        && kernel.prefix_field_checks() >= kernel.exact_field_checks()
        && peak_matches
        && report.retained_capacity_bytes == authenticated_build.persistent_bytes
}

fn literal_class_run_literal_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateLiteralClassRunLiteralIdentity,
    build: LiteralClassRunLiteralBuildAccounting,
    operation: LiteralAggregateOperation,
) -> bool {
    let expected_operation_id = match operation {
        LiteralAggregateOperation::Count => LITERAL_CLASS_RUN_LITERAL_COUNT_OPERATION_ID,
        LiteralAggregateOperation::SpanSum => LITERAL_CLASS_RUN_LITERAL_SPAN_SUM_OPERATION_ID,
    };
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    let literal_bytes_match = identity
        .kernel
        .prefix_bytes
        .checked_add(identity.kernel.suffix_bytes)
        == Some(build.literal_bytes)
        && identity.kernel.prefix_bytes == build.prefix_bytes
        && identity.kernel.suffix_bytes == build.suffix_bytes;
    let class_members = identity
        .kernel
        .class_words
        .into_iter()
        .try_fold(0_usize, |total, word| {
            total.checked_add(usize::try_from(word.count_ones()).ok()?)
        });
    operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::LiteralClassRunLiteral
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.kernel.plan_id == LITERAL_CLASS_RUN_LITERAL_PLAN_ID
        && identity.kernel.operation_id == expected_operation_id
        && !identity.kernel.unicode
        && identity.kernel.greedy
        && identity.kernel.non_overlapping
        && identity.kernel.prefix_bytes > 0
        && identity.kernel.suffix_bytes > 0
        && literal_bytes_match
        && build.class_ranges > 0
        && class_members == Some(build.class_members)
        && build.scratch_bytes == 0
        && build.peak_bytes == build.persistent_bytes
        && report.retained_capacity_bytes == build.persistent_bytes
}

fn bounded_literal_pair_class_facts(class_words: [u64; 4]) -> (usize, usize, usize) {
    let mut ranges = 0_usize;
    let mut members = 0_usize;
    let mut range_word_spans = 0_usize;
    let mut range_start = None;
    let mut previous = false;
    for byte in 0_u16..=u16::from(u8::MAX) {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        let present = class_words[word] & 1_u64.checked_shl(bit).unwrap_or(0) != 0;
        members = members.saturating_add(usize::from(present));
        if present && !previous {
            ranges = ranges.saturating_add(1);
            range_start = Some(byte);
        } else if !present && previous {
            let start = range_start.expect("class range start precedes its end");
            let end = byte.saturating_sub(1);
            let span = (end / 64).saturating_sub(start / 64).saturating_add(1);
            range_word_spans = range_word_spans.saturating_add(usize::from(span));
            range_start = None;
        }
        previous = present;
    }
    if previous {
        let start = range_start.expect("final class range has a start");
        let span = (u16::from(u8::MAX) / 64)
            .saturating_sub(start / 64)
            .saturating_add(1);
        range_word_spans = range_word_spans.saturating_add(usize::from(span));
    }
    (ranges, members, range_word_spans)
}

fn bounded_literal_pair_build_identity_matches(
    kernel: fre::BoundedLiteralPairOperationIdentity,
    build: fre::BoundedLiteralPairBuildAccounting,
) -> bool {
    let (class_ranges, class_members, range_word_spans) =
        bounded_literal_pair_class_facts(kernel.class_words);
    let expected_work = build
        .literal_bytes
        .checked_mul(4)
        .and_then(|work| work.checked_add(32))
        .and_then(|work| {
            class_ranges
                .checked_mul(9)
                .and_then(|term| work.checked_add(term))
        })
        .and_then(|work| {
            range_word_spans
                .checked_mul(4)
                .and_then(|term| work.checked_add(term))
        })
        .and_then(|work| work.checked_add(1));
    kernel
        .left_bytes
        .checked_add(kernel.right_bytes)
        .is_some_and(|literal_bytes| literal_bytes == build.literal_bytes)
        && kernel.left_bytes == build.left_bytes
        && kernel.right_bytes == build.right_bytes
        && kernel.gap_max == build.gap_max
        && kernel.left_bytes > 0
        && kernel.right_bytes > 0
        && kernel.gap_max > 0
        && class_ranges == build.class_ranges
        && class_members == build.class_members
        && class_members > 0
        && expected_work == Some(build.work_upper_bound)
        && build.scratch_bytes == 0
        && build.persistent_bytes > build.literal_bytes
        && build.peak_bytes == build.persistent_bytes
}

fn bounded_literal_pair_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateBoundedLiteralPairIdentity,
    build: fre::BoundedLiteralPairBuildAccounting,
    operation: LiteralAggregateOperation,
) -> bool {
    let expected_operation_id = match operation {
        LiteralAggregateOperation::Count => fre::BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID,
        LiteralAggregateOperation::SpanSum => fre::BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID,
    };
    let operation_matches = matches!(
        (report.operation, operation),
        (
            AggregateOperation::Compile | AggregateOperation::Count,
            LiteralAggregateOperation::Count
        ) | (
            AggregateOperation::SpanSum,
            LiteralAggregateOperation::SpanSum
        )
    );
    operation_matches
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::BoundedLiteralPair
        && report.continuation_strategy.is_none()
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && identity.kernel.plan_id == fre::BOUNDED_LITERAL_PAIR_PLAN_ID
        && identity.kernel.operation_id == expected_operation_id
        && !identity.kernel.unicode
        && identity.kernel.greedy
        && identity.kernel.non_overlapping
        && identity.kernel.topology == fre::BoundedLiteralPairTopology::SwappedLiteralEndpoints
        && bounded_literal_pair_build_identity_matches(identity.kernel, build)
        && report.retained_capacity_bytes == build.persistent_bytes
}

#[allow(
    clippy::too_many_lines,
    reason = "the adapter keeps every fixed-route identity and accounting invariant in one fail-closed audit boundary"
)]
fn fixed_absolute_plan_identity_matches(
    report: &AggregateBuildReport,
    identity: fre::AggregateFixedAbsoluteDomainIdentity,
    build: &fre::AggregateFixedAbsoluteDomainBuildAccounting,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let mut expected_profile = rebar_profile();
    expected_profile.options.unicode = unicode;
    let expected_operation = match operation {
        LiteralAggregateOperation::Count => fre::FixedAbsoluteDomainOperation::Count,
        LiteralAggregateOperation::SpanSum => fre::FixedAbsoluteDomainOperation::SpanSum,
    };
    let kernel = identity.kernel;
    let descriptor = kernel.descriptor.kind();
    let descriptor_closed = matches!(
        (unicode, operation, descriptor),
        (
            false,
            LiteralAggregateOperation::Count,
            fre::FixedAbsoluteDomainDescriptorKind::WholeByteRepeat
                | fre::FixedAbsoluteDomainDescriptorKind::WholeOrderedWords,
        ) | (
            false,
            LiteralAggregateOperation::SpanSum,
            fre::FixedAbsoluteDomainDescriptorKind::EndMaskSequence
                | fre::FixedAbsoluteDomainDescriptorKind::EndOneByteMask
                | fre::FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
                | fre::FixedAbsoluteDomainDescriptorKind::StartOrderedPrefix,
        ) | (
            true,
            LiteralAggregateOperation::Count,
            fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope,
        )
    );
    let scalar = descriptor == fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope;
    let residual_closed = if scalar {
        matches!(
            (
                identity.residual,
                identity.residual_strategy,
                build.residual,
                kernel.residual,
                report.continuation_strategy,
            ),
            (
                Some(fre::AggregateContinuationIdentity {
                    semantics: AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir,
                    ..
                }),
                Some(AggregateStrategy::ReverseSequentialRows),
                Some(_),
                fre::FixedAbsoluteDomainResidual::PrepublishedContinuation,
                Some(AggregateStrategy::ReverseSequentialRows),
            )
        )
    } else {
        identity.residual.is_none()
            && identity.residual_strategy.is_none()
            && build.residual.is_none()
            && kernel.residual == fre::FixedAbsoluteDomainResidual::None
            && report.continuation_strategy.is_none()
    };
    let owner_guard_closed = build.guard_with_owner.prospective.descriptor == kernel.descriptor
        && build.guard_with_owner.actual.published
        && fixed_absolute_build_contains(
            build.guard_with_owner.prospective,
            build.guard_with_owner.actual,
        );
    let composite_closed = if scalar {
        build.residual.is_some()
            && build.actual.published
            && build.actual.work <= build.prospective.work
            && build.actual.allocations <= build.prospective.allocations
            && build.actual.persistent_bytes <= build.prospective.persistent_bytes
            && build.actual.peak_bytes <= build.prospective.peak_bytes
    } else {
        build.residual.is_none()
            && build.actual.work == build.guard_with_owner.actual.build_work
            && build.actual.allocations == build.guard_with_owner.actual.allocations
            && build.actual.persistent_bytes == build.guard_with_owner.actual.persistent_bytes
            && build.actual.peak_bytes == build.guard_with_owner.actual.peak_bytes
    };

    report.operation
        == match operation {
            LiteralAggregateOperation::Count => AggregateOperation::Count,
            LiteralAggregateOperation::SpanSum => AggregateOperation::SpanSum,
        }
        && report.selection == AggregatePlanSelection::Auto
        && report.plan == AggregatePlanKind::FixedAbsoluteDomain
        && report.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
        && report.syntax_key.profile == CompatibilityProfile::RustBytes(expected_profile)
        && report.has_closed_fixed_absolute_domain_identity()
        && report.authenticates_fixed_absolute_domain_identity(identity)
        && kernel.plan_id == fre::FIXED_ABSOLUTE_DOMAIN_PLAN_ID
        && kernel.algorithm_version == fre::FIXED_ABSOLUTE_DOMAIN_ALGORITHM_VERSION
        && kernel.accounting_version == fre::FIXED_ABSOLUTE_DOMAIN_ACCOUNTING_VERSION
        && kernel.operation == expected_operation
        && kernel.operation_id
            == match operation {
                LiteralAggregateOperation::Count => fre::FIXED_ABSOLUTE_DOMAIN_COUNT_OPERATION_ID,
                LiteralAggregateOperation::SpanSum => {
                    fre::FIXED_ABSOLUTE_DOMAIN_SPAN_SUM_OPERATION_ID
                }
            }
        && kernel.original_haystack_anchors
        && kernel.non_overlapping
        && descriptor_closed
        && residual_closed
        && build.kernel.prospective.descriptor == kernel.descriptor
        && build.kernel.actual.published
        && fixed_absolute_build_contains(build.kernel.prospective, build.kernel.actual)
        && owner_guard_closed
        && build.actual.published
        && build.actual.work <= build.prospective.work
        && build.actual.allocations <= build.prospective.allocations
        && build.actual.persistent_bytes <= build.prospective.persistent_bytes
        && build.actual.peak_bytes <= build.prospective.peak_bytes
        && composite_closed
        && report.retained_capacity_bytes == build.actual.persistent_bytes
}

fn require_closed_bounded_separated_fields_identity(
    report: &AggregateBuildReport,
) -> Result<(), ExecutionError> {
    if report.has_closed_bounded_separated_fields_identity() {
        return Ok(());
    }
    Err(ExecutionError::fault(
        "FRE bounded separated-field aggregate identity mismatch: public/private closure is open",
    ))
}

fn require_closed_construction_attempt(
    report: &AggregateBuildReport,
) -> Result<(), ExecutionError> {
    if report.has_closed_construction_attempt() {
        return Ok(());
    }
    Err(ExecutionError::fault(
        "FRE aggregate construction identity mismatch: public/private closure is open",
    ))
}

fn require_closed_fixed_absolute_domain_identity(
    report: &AggregateBuildReport,
) -> Result<(), ExecutionError> {
    if report.has_closed_fixed_absolute_domain_identity() {
        return Ok(());
    }
    Err(ExecutionError::fault(
        "FRE fixed absolute-domain identity mismatch: public/private closure is open",
    ))
}

fn require_closed_required_internal_anchor_identity(
    report: &AggregateBuildReport,
) -> Result<(), ExecutionError> {
    if report.has_closed_required_internal_anchor_identity() {
        return Ok(());
    }
    Err(ExecutionError::fault(
        "FRE required internal-anchor aggregate identity mismatch: public/private closure is open",
    ))
}

fn require_closed_url_aggregate_identity(
    report: &AggregateBuildReport,
) -> Result<(), ExecutionError> {
    if report.has_closed_url_aggregate_identity() {
        return Ok(());
    }
    Err(ExecutionError::fault(
        "FRE URL aggregate identity mismatch: public/private closure is open",
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive identity verifier keeps every supported plan's invariants adjacent"
)]
fn require_unicode_plan_identity(
    report: &AggregateBuildReport,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> Result<(), ExecutionError> {
    require_closed_bounded_separated_fields_identity(report)?;
    require_closed_fixed_absolute_domain_identity(report)?;
    require_closed_required_internal_anchor_identity(report)?;
    require_closed_url_aggregate_identity(report)?;
    require_closed_construction_attempt(report)?;
    if report.plan == AggregatePlanKind::WordRun
        || matches!(report.build, AggregateBuildAccounting::WordRun(_))
        || matches!(report.plan_identity, AggregatePlanIdentity::WordRun(_))
    {
        let (AggregatePlanIdentity::WordRun(identity), AggregateBuildAccounting::WordRun(build)) =
            (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "word-run aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if word_run_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "word-run aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::LiteralAssertions
        || matches!(report.build, AggregateBuildAccounting::LiteralAssertions(_))
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::LiteralAssertions(_)
        )
    {
        let (
            AggregatePlanIdentity::LiteralAssertions(identity),
            AggregateBuildAccounting::LiteralAssertions(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "literal-assertions aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if literal_assertions_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "literal-assertions aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::BlockingDelimiter
        || matches!(report.build, AggregateBuildAccounting::BlockingDelimiter(_))
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::BlockingDelimiter(_)
        )
    {
        let (
            AggregatePlanIdentity::BlockingDelimiter(identity),
            AggregateBuildAccounting::BlockingDelimiter(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "blocking-delimiter aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if blocking_delimiter_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "blocking-delimiter aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::TokenPhrase
        || matches!(report.build, AggregateBuildAccounting::TokenPhrase(_))
        || matches!(report.plan_identity, AggregatePlanIdentity::TokenPhrase(_))
    {
        let (
            AggregatePlanIdentity::TokenPhrase(identity),
            AggregateBuildAccounting::TokenPhrase(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "token-phrase aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if token_phrase_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "token-phrase aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::LiteralClassRunLiteral
        || matches!(
            report.build,
            AggregateBuildAccounting::LiteralClassRunLiteral(_)
        )
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::LiteralClassRunLiteral(_)
        )
    {
        let (
            AggregatePlanIdentity::LiteralClassRunLiteral(identity),
            AggregateBuildAccounting::LiteralClassRunLiteral(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "literal/class-run/literal aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if !unicode
            && literal_class_run_literal_plan_identity_matches(report, identity, build, operation)
        {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "literal/class-run/literal aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::BoundedLiteralPair
        || matches!(
            report.build,
            AggregateBuildAccounting::BoundedLiteralPair(_)
        )
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::BoundedLiteralPair(_)
        )
    {
        let (
            AggregatePlanIdentity::BoundedLiteralPair(identity),
            AggregateBuildAccounting::BoundedLiteralPair(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "bounded literal-pair aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if !unicode
            && bounded_literal_pair_plan_identity_matches(report, identity, build, operation)
        {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "bounded literal-pair aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if let AggregatePlanIdentity::FiniteLiteral(identity) = report.plan_identity {
        let representation_matches = matches!(
            (report.plan, report.build, identity.algorithm),
            (
                AggregatePlanKind::FiniteLiteralDfa,
                AggregateBuildAccounting::FiniteLiteral(_),
                ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
            ) | (
                AggregatePlanKind::PackedFiniteLiteral,
                AggregateBuildAccounting::PackedFiniteLiteral(_),
                fre::PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
            ) | (
                AggregatePlanKind::FiniteLiteralDfa,
                AggregateBuildAccounting::SparseFiniteLiteral(_),
                SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
            )
        );
        if representation_matches && finite_plan_identity_matches(identity, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "finite aggregate semantic identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::FixedPredicateWord64
        || matches!(
            report.build,
            AggregateBuildAccounting::FixedPredicateWord64(_)
        )
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::FixedPredicateWord64(_)
        )
    {
        let (
            AggregatePlanIdentity::FixedPredicateWord64(identity),
            AggregateBuildAccounting::FixedPredicateWord64(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "fixed-predicate Word64 aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if !unicode
            && fixed_predicate_word64_plan_identity_matches(report, identity, build, operation)
        {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "fixed-predicate Word64 aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::GuardedAsciiWordDictionary
        || matches!(report.build, AggregateBuildAccounting::GuardedAsciiWord(_))
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::GuardedAsciiWord(_)
        )
    {
        let (
            AggregatePlanIdentity::GuardedAsciiWord(identity),
            AggregateBuildAccounting::GuardedAsciiWord(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "guarded ASCII-word aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if guarded_ascii_word_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "guarded ASCII-word aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::BoundedSeparatedFields
        || matches!(
            report.build,
            AggregateBuildAccounting::BoundedSeparatedFields(_)
        )
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::BoundedSeparatedFields(_)
        )
    {
        let (
            AggregatePlanIdentity::BoundedSeparatedFields(identity),
            AggregateBuildAccounting::BoundedSeparatedFields(build),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "bounded separated-field aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        if !unicode
            && bounded_separated_fields_plan_identity_matches(report, identity, build, operation)
        {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "bounded separated-field aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if report.plan == AggregatePlanKind::FixedAbsoluteDomain
        || matches!(
            report.build,
            AggregateBuildAccounting::FixedAbsoluteDomain(_)
        )
        || matches!(
            report.plan_identity,
            AggregatePlanIdentity::FixedAbsoluteDomain(_)
        )
    {
        let (
            AggregatePlanIdentity::FixedAbsoluteDomain(identity),
            AggregateBuildAccounting::FixedAbsoluteDomain(_),
        ) = (report.plan_identity, report.build)
        else {
            return Err(ExecutionError::fault(format!(
                "fixed absolute-domain aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        };
        let Some(build) = report.fixed_absolute_domain_build_accounting() else {
            return Err(ExecutionError::fault(format!(
                "fixed absolute-domain aggregate build accounting mismatch for {operation:?}"
            )));
        };
        if fixed_absolute_plan_identity_matches(report, identity, build, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "fixed absolute-domain aggregate identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if !unicode {
        if let AggregatePlanIdentity::ExactLiteral(identity) = report.plan_identity {
            if exact_literal_plan_identity_matches(
                identity,
                AggregateExactLiteralSemantics::UnicodeOffByteBoundaries,
                operation,
            ) {
                return Ok(());
            }
            return Err(ExecutionError::fault(format!(
                "Unicode-off exact-literal aggregate identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        }
        if let AggregatePlanIdentity::GraphemeScalarDfa(_) = report.plan_identity {
            return Err(ExecutionError::fault(format!(
                "grapheme scalar DFA identity is not valid for Unicode-off execution: {:?}",
                report.plan_identity
            )));
        }
        if let AggregatePlanIdentity::BoundedClassSequence(identity) = report.plan_identity {
            if operation == LiteralAggregateOperation::Count
                && identity.plan_id == fre::BOUNDED_CLASS_SEQUENCE_PLAN_ID
                && identity.operation_id == fre::BOUNDED_CLASS_SEQUENCE_COUNT_OPERATION_ID
                && identity.greedy
                && identity.non_overlapping
            {
                return Ok(());
            }
            return Err(ExecutionError::fault(format!(
                "bounded class-sequence aggregate identity mismatch: {:?}",
                report.plan_identity
            )));
        }
        if let AggregatePlanIdentity::FixedClassSandwich(identity) = report.plan_identity {
            let fixed_operation = match operation {
                LiteralAggregateOperation::Count => FixedClassSandwichOperation::Count,
                LiteralAggregateOperation::SpanSum => FixedClassSandwichOperation::SpanSum,
            };
            if identity.semantics == AggregateFixedClassSandwichSemantics::UnicodeOffByteClasses
                && identity.kernel.operation == fixed_operation
            {
                return Ok(());
            }
            return Err(ExecutionError::fault(format!(
                "fixed class aggregate semantic identity mismatch for {fixed_operation:?}: {:?}",
                report.plan_identity
            )));
        }
        if let AggregatePlanIdentity::PrefixClassAlternation(identity) = report.plan_identity {
            if operation == LiteralAggregateOperation::Count
                && matches!(
                    identity.kernel.plan_id,
                    PREFIX_CLASS_ALTERNATION_PLAN_ID | DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID
                )
                && identity.kernel.operation_id == PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID
                && !identity.kernel.unicode
                && identity.kernel.alternatives == 2
                && identity.kernel.non_overlapping
            {
                return Ok(());
            }
            return Err(ExecutionError::fault(format!(
                "prefix/class aggregate semantic identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        }
        if let AggregatePlanIdentity::BoundedContext(identity) = report.plan_identity {
            let operation_id = match operation {
                LiteralAggregateOperation::Count => fre::BOUNDED_CONTEXT_COUNT_OPERATION_ID,
                LiteralAggregateOperation::SpanSum => fre::BOUNDED_CONTEXT_SPAN_SUM_OPERATION_ID,
            };
            if matches!(
                identity.kernel.plan_id,
                fre::BOUNDED_CONTEXT_PLAN_ID | fre::BOUNDED_AFFIX_PLAN_ID
            ) && identity.kernel.operation_id == operation_id
            {
                return Ok(());
            }
            return Err(ExecutionError::fault(format!(
                "bounded-context aggregate semantic identity mismatch for {operation:?}: {:?}",
                report.plan_identity
            )));
        }
        return Ok(());
    }
    if matches!(
        report.plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if exact_literal_plan_identity_matches(
                identity,
                AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal,
                operation,
            )
    ) || matches!(
        report.plan_identity,
        AggregatePlanIdentity::FixedClassSandwich(identity)
            if identity.semantics
                == AggregateFixedClassSandwichSemantics::UnicodeOnScalarClassesUtf8False
                && identity.kernel.operation
                    == match operation {
                        LiteralAggregateOperation::Count => FixedClassSandwichOperation::Count,
                        LiteralAggregateOperation::SpanSum => {
                            FixedClassSandwichOperation::SpanSum
                        }
                    }
    ) || matches!(
        report.plan_identity,
        AggregatePlanIdentity::UnicodeScalar(identity)
            if matches!(
                identity.semantics,
                AggregateUnicodeScalarSemantics::UnicodeOnRootClassUtf8False
                    | AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreGreedyUtf8False
                    | AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreLazyUtf8False
                    | AggregateUnicodeScalarSemantics::UnicodeOnRootClassRepeatedUtf8False
                    | AggregateUnicodeScalarSemantics::UnicodeOnUniformCapturedAlternationRepeatedUtf8False
            )
                && identity.kernel.operation
                    == match operation {
                        LiteralAggregateOperation::Count => UnicodeScalarAggregateOperation::Count,
                        LiteralAggregateOperation::SpanSum => {
                            UnicodeScalarAggregateOperation::SpanSum
                        }
                    }
    ) || matches!(
        report.plan_identity,
        AggregatePlanIdentity::UnicodeScalar(identity)
            if identity.semantics
                == AggregateUnicodeScalarSemantics::UnicodeOnRootClassZeroOrMoreGreedySpanSumUtf8False
                && operation == LiteralAggregateOperation::SpanSum
                && identity.kernel.operation == UnicodeScalarAggregateOperation::SpanSum
    ) || matches!(
        report.plan_identity,
        AggregatePlanIdentity::GraphemeScalarDfa(identity)
            if identity.semantics
                == AggregateGraphemeScalarDfaSemantics::UnicodeOnOrderedScalarGrammarUtf8False
                && operation == LiteralAggregateOperation::Count
                && identity.kernel.operation == GraphemeScalarDfaOperation::Count
    ) || matches!(
        report.plan_identity,
        AggregatePlanIdentity::Continuation(identity)
            if identity.semantics
                == AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
    ) {
        Ok(())
    } else {
        Err(ExecutionError::fault(format!(
            "Unicode aggregate semantic identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )))
    }
}

fn aggregate_engine_error(source: &AggregateEngineError, message: String) -> ExecutionError {
    match source {
        AggregateEngineError::Unsupported(_) | AggregateEngineError::ResourceLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        // Arithmetic, allocation, invalid-program/range and invariant errors
        // are candidate faults. The wildcard also keeps future non-resource
        // error variants from being silently downgraded to unsupported.
        _ => ExecutionError::fault(message),
    }
}

fn fixed_absolute_build_resource_value(
    prospective: fre::FixedAbsoluteDomainBuildProspective,
    resource: fre::FixedAbsoluteDomainBuildResource,
) -> Option<u64> {
    match resource {
        fre::FixedAbsoluteDomainBuildResource::Items => u64::try_from(prospective.items).ok(),
        fre::FixedAbsoluteDomainBuildResource::PayloadBytes => {
            u64::try_from(prospective.payload_bytes).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::IdentityBytes => {
            u64::try_from(prospective.identity_bytes).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::CopiedBytes => {
            u64::try_from(prospective.copied_bytes).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::Allocations => {
            u64::try_from(prospective.allocations).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::InitializedBytes => {
            u64::try_from(prospective.initialized_bytes).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::Work => Some(prospective.build_work),
        fre::FixedAbsoluteDomainBuildResource::PersistentBytes => {
            u64::try_from(prospective.persistent_bytes).ok()
        }
        fre::FixedAbsoluteDomainBuildResource::PeakBytes => {
            u64::try_from(prospective.peak_bytes).ok()
        }
    }
}

fn fixed_absolute_build_resource_refusal_is_closed(
    source: &fre::FixedAbsoluteDomainBuildError,
) -> bool {
    let fre::FixedAbsoluteDomainBuildErrorKind::ResourceLimit {
        resource,
        needed,
        limit,
    } = &source.kind
    else {
        return false;
    };
    let Some(prospective) = source.prospective else {
        return false;
    };
    !source.actual.published
        && source.actual == fre::FixedAbsoluteDomainBuildActual::default()
        && fixed_absolute_build_contains(prospective, source.actual)
        && fixed_absolute_build_resource_value(prospective, *resource) == Some(*needed)
        && needed > limit
}

fn fixed_absolute_build_success_is_closed(
    accounting: fre::FixedAbsoluteDomainBuildAccounting,
) -> bool {
    let prospective = accounting.prospective;
    let actual = accounting.actual;
    actual.published
        && actual.items == prospective.items
        && actual.payload_bytes == prospective.payload_bytes
        && actual.identity_bytes == prospective.identity_bytes
        && actual.retained_heap_bytes == prospective.retained_heap_bytes
        && actual.copied_bytes == prospective.copied_bytes
        && actual.allocations == prospective.allocations
        && actual.initialized_bytes == prospective.initialized_bytes
        && actual.build_work == prospective.build_work
        && actual.scratch_bytes == prospective.scratch_bytes
        && actual.persistent_bytes == prospective.persistent_bytes
        && actual.peak_bytes == prospective.peak_bytes
}

fn fixed_absolute_reduce_resource_value(
    prospective: fre::FixedAbsoluteDomainProspective,
    resource: fre::FixedAbsoluteDomainReduceResource,
) -> Option<u64> {
    match resource {
        fre::FixedAbsoluteDomainReduceResource::ByteProbes => {
            u64::try_from(prospective.byte_probes).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::BranchChecks => {
            u64::try_from(prospective.branch_checks).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::MatchEvents => {
            u64::try_from(prospective.match_events).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::Count => Some(prospective.count),
        fre::FixedAbsoluteDomainReduceResource::SpanSum => Some(prospective.span_sum),
        fre::FixedAbsoluteDomainReduceResource::ReducerSteps => {
            u64::try_from(prospective.reducer_steps).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::TotalWork => {
            u64::try_from(prospective.total_work).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::ScratchBytes => {
            u64::try_from(prospective.scratch_bytes).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::PersistentBytes => {
            u64::try_from(prospective.persistent_bytes).ok()
        }
        fre::FixedAbsoluteDomainReduceResource::PeakBytes => {
            u64::try_from(prospective.peak_bytes).ok()
        }
    }
}

fn fixed_absolute_operation_identity_is_closed(
    identity: fre::FixedAbsoluteDomainOperationIdentity,
) -> bool {
    let descriptor = identity.descriptor.kind();
    let operation_closed = match identity.operation {
        fre::FixedAbsoluteDomainOperation::Count => {
            identity.operation_id == fre::FIXED_ABSOLUTE_DOMAIN_COUNT_OPERATION_ID
                && matches!(
                    descriptor,
                    fre::FixedAbsoluteDomainDescriptorKind::WholeByteRepeat
                        | fre::FixedAbsoluteDomainDescriptorKind::WholeOrderedWords
                        | fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope
                )
        }
        fre::FixedAbsoluteDomainOperation::SpanSum => {
            identity.operation_id == fre::FIXED_ABSOLUTE_DOMAIN_SPAN_SUM_OPERATION_ID
                && matches!(
                    descriptor,
                    fre::FixedAbsoluteDomainDescriptorKind::EndMaskSequence
                        | fre::FixedAbsoluteDomainDescriptorKind::EndOneByteMask
                        | fre::FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
                        | fre::FixedAbsoluteDomainDescriptorKind::StartOrderedPrefix
                )
        }
    };
    let residual_closed =
        if descriptor == fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope {
            identity.residual == fre::FixedAbsoluteDomainResidual::PrepublishedContinuation
        } else {
            identity.residual == fre::FixedAbsoluteDomainResidual::None
        };
    identity.plan_id == fre::FIXED_ABSOLUTE_DOMAIN_PLAN_ID
        && identity.algorithm_version == fre::FIXED_ABSOLUTE_DOMAIN_ALGORITHM_VERSION
        && identity.accounting_version == fre::FIXED_ABSOLUTE_DOMAIN_ACCOUNTING_VERSION
        && identity.original_haystack_anchors
        && identity.non_overlapping
        && operation_closed
        && residual_closed
}

fn fixed_absolute_reduce_resource_refusal_is_closed(
    source: &fre::FixedAbsoluteDomainReduceError,
) -> bool {
    let fre::FixedAbsoluteDomainReduceErrorKind::ResourceLimit {
        resource,
        needed,
        limit,
    } = &source.kind
    else {
        return false;
    };
    let receipt = source.receipt;
    let Some(prospective) = receipt.prospective else {
        return false;
    };
    fixed_absolute_operation_identity_is_closed(receipt.identity)
        && receipt.window.start() == 0
        && receipt.window.end() == receipt.haystack_len
        && receipt.actual == fre::FixedAbsoluteDomainActual::default()
        && receipt.actual.fits(prospective)
        && fixed_absolute_reduce_resource_value(prospective, *resource) == Some(*needed)
        && needed > limit
}

fn fixed_absolute_residual_refusal_is_closed(
    continuation: &fre::AggregateOperationAttemptError,
    composite: &fre::AggregateFixedAbsoluteDomainResidualReceipt,
) -> bool {
    let AggregateEngineError::ResourceLimit {
        required, limit, ..
    } = &continuation.source
    else {
        return false;
    };
    let Some(prospective) = continuation.receipt.prospective else {
        return false;
    };
    let invocation = &continuation.receipt.invocation;
    let guard = composite.guard;
    fixed_absolute_operation_identity_is_closed(guard.identity)
        && composite.contains_actual_with(&continuation.receipt)
        && guard.identity.operation == fre::FixedAbsoluteDomainOperation::Count
        && guard.identity.descriptor.kind()
            == fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope
        && guard.prospective.disposition
            == fre::FixedAbsoluteDomainDisposition::PrepublishedContinuation
        && guard.window.start() == 0
        && guard.window.end() == guard.haystack_len
        && guard.actual.source_accesses == 0
        && guard.actual.allocations == 0
        && guard.actual.fits(guard.prospective)
        && continuation.receipt.identity.operation == fre::AggregateOperationAttemptKind::Count
        && continuation.receipt.identity.operation_id().is_some()
        && invocation.range.start == 0
        && invocation.range.end == invocation.haystack_len
        && invocation.haystack_len == guard.haystack_len
        && prospective.contains(continuation.receipt.actual)
        && required > limit
}

fn fixed_absolute_build_error(
    source: &fre::FixedAbsoluteDomainBuildError,
    message: String,
) -> ExecutionError {
    if fixed_absolute_build_resource_refusal_is_closed(source) {
        ExecutionError::unsupported(message)
    } else {
        ExecutionError::fault(message)
    }
}

fn fixed_absolute_residual_build_resource_value(
    prospective: fre::AggregateFixedAbsoluteDomainResidualBuildProspective,
    resource: fre::AggregateFixedAbsoluteDomainResidualBuildResource,
) -> Option<u64> {
    match resource {
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::Work => Some(prospective.work),
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::Allocations => {
            u64::try_from(prospective.allocations).ok()
        }
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::PersistentBytes => {
            u64::try_from(prospective.persistent_bytes).ok()
        }
        fre::AggregateFixedAbsoluteDomainResidualBuildResource::PeakBytes => {
            u64::try_from(prospective.peak_bytes).ok()
        }
    }
}

fn fixed_absolute_planner_work_is_closed(planner_work: usize) -> bool {
    planner_work > 0 && u32::try_from(planner_work).is_ok()
}

fn fixed_absolute_residual_build_preflight_is_closed(
    operation: AggregateOperation,
    selection: AggregatePlanSelection,
    planner_work: usize,
    resource: fre::AggregateFixedAbsoluteDomainResidualBuildResource,
    needed: u64,
    limit: u64,
    receipt: fre::AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
) -> bool {
    operation == AggregateOperation::Count
        && selection == AggregatePlanSelection::Auto
        && fixed_absolute_planner_work_is_closed(planner_work)
        && receipt.contains_actual()
        && receipt.actual == fre::AggregateFixedAbsoluteDomainResidualBuildActual::default()
        && fixed_absolute_residual_build_resource_value(receipt.prospective, resource)
            == Some(needed)
        && needed > limit
}

fn fixed_absolute_residual_guard_build_error(
    operation: AggregateOperation,
    selection: AggregatePlanSelection,
    planner_work: usize,
    source: &fre::FixedAbsoluteDomainBuildError,
    composite: fre::AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
    message: String,
) -> ExecutionError {
    let closed = operation == AggregateOperation::Count
        && selection == AggregatePlanSelection::Auto
        && fixed_absolute_planner_work_is_closed(planner_work)
        && composite.contains_actual()
        && composite.actual == fre::AggregateFixedAbsoluteDomainResidualBuildActual::default()
        && source.prospective.is_some_and(|prospective| {
            prospective.descriptor.kind()
                == fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope
        })
        && fixed_absolute_build_resource_refusal_is_closed(source);
    if closed {
        ExecutionError::unsupported(message)
    } else {
        ExecutionError::fault(message)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the scalar construction failure closure binds every typed discriminator and immutable P/A receipt explicitly"
)]
fn fixed_absolute_residual_compile_error(
    operation: AggregateOperation,
    selection: AggregatePlanSelection,
    planner_work: usize,
    strategy: AggregateStrategy,
    guard: fre::FixedAbsoluteDomainBuildAccounting,
    source: &fre::AggregateCompileAttemptError,
    composite: fre::AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
    message: String,
) -> ExecutionError {
    let receipt = source.receipt;
    let expected_work = u64::try_from(receipt.actual.work)
        .ok()
        .and_then(|work| guard.actual.build_work.checked_add(work));
    let expected_allocations = receipt
        .actual_allocations
        .and_then(|allocations| guard.actual.allocations.checked_add(allocations));
    let expected_persistent = guard
        .actual
        .persistent_bytes
        .checked_add(receipt.live_construction_bytes);
    let expected_peak = guard
        .actual
        .persistent_bytes
        .checked_add(receipt.actual.construction_peak_bytes)
        .map(|peak| peak.max(guard.actual.peak_bytes));
    let closed = operation == AggregateOperation::Count
        && selection == AggregatePlanSelection::Auto
        && fixed_absolute_planner_work_is_closed(planner_work)
        && strategy == AggregateStrategy::ReverseSequentialRows
        && guard.prospective.descriptor.kind()
            == fre::FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope
        && fixed_absolute_build_success_is_closed(guard)
        && receipt.identity.kind == fre::AggregateCompileAttemptKind::EraseCapturesForWholeMatch
        && receipt.contains_actual()
        && !receipt.published
        && composite.contains_actual()
        && expected_work == Some(composite.actual.work)
        && expected_allocations == Some(composite.actual.allocations)
        && expected_persistent == Some(composite.actual.persistent_bytes)
        && expected_peak == Some(composite.actual.peak_bytes);
    if closed {
        aggregate_engine_error(&source.source, message)
    } else {
        ExecutionError::fault(message)
    }
}

fn literal_build_error(source: &LiteralAggregateBuildError, message: String) -> ExecutionError {
    match source {
        LiteralAggregateBuildError::NeedleLimit { .. }
        | LiteralAggregateBuildError::WorkLimit { .. }
        | LiteralAggregateBuildError::ScratchLimit { .. }
        | LiteralAggregateBuildError::PersistentLimit { .. }
        | LiteralAggregateBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn literal_reduce_error(source: &LiteralAggregateReduceError, message: String) -> ExecutionError {
    match source {
        LiteralAggregateReduceError::LinearTermsLimit { .. }
        | LiteralAggregateReduceError::MatchEventsLimit { .. }
        | LiteralAggregateReduceError::CountLimit { .. }
        | LiteralAggregateReduceError::SpanSumLimit { .. }
        | LiteralAggregateReduceError::ReducerStepsLimit { .. }
        | LiteralAggregateReduceError::ScratchLimit { .. }
        | LiteralAggregateReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn prefix_class_build_error(
    source: &PrefixClassAlternationBuildError,
    message: String,
) -> ExecutionError {
    match source {
        PrefixClassAlternationBuildError::ShapeLimit { .. }
        | PrefixClassAlternationBuildError::WorkLimit { .. }
        | PrefixClassAlternationBuildError::ScratchLimit { .. }
        | PrefixClassAlternationBuildError::PersistentLimit { .. }
        | PrefixClassAlternationBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn prefix_class_reduce_error(
    source: &PrefixClassAlternationReduceError,
    message: String,
) -> ExecutionError {
    match source {
        PrefixClassAlternationReduceError::WorkLimit { .. }
        | PrefixClassAlternationReduceError::MatchEventsLimit { .. }
        | PrefixClassAlternationReduceError::CountLimit { .. }
        | PrefixClassAlternationReduceError::ScratchLimit { .. }
        | PrefixClassAlternationReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn unicode_scalar_build_error(
    source: &UnicodeScalarAggregateBuildError,
    message: String,
) -> ExecutionError {
    match source {
        UnicodeScalarAggregateBuildError::RangeLimit { .. }
        | UnicodeScalarAggregateBuildError::WorkLimit { .. }
        | UnicodeScalarAggregateBuildError::ScratchLimit { .. }
        | UnicodeScalarAggregateBuildError::PersistentLimit { .. }
        | UnicodeScalarAggregateBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn unicode_scalar_reduce_error(
    source: &UnicodeScalarAggregateReduceError,
    message: String,
) -> ExecutionError {
    match source {
        UnicodeScalarAggregateReduceError::InputBytesLimit { .. }
        | UnicodeScalarAggregateReduceError::DecodeByteChecksLimit { .. }
        | UnicodeScalarAggregateReduceError::MembershipTestsLimit { .. }
        | UnicodeScalarAggregateReduceError::RangeComparisonsLimit { .. }
        | UnicodeScalarAggregateReduceError::ReducerStepsLimit { .. }
        | UnicodeScalarAggregateReduceError::MatchEventsLimit { .. }
        | UnicodeScalarAggregateReduceError::CountLimit { .. }
        | UnicodeScalarAggregateReduceError::SpanSumLimit { .. }
        | UnicodeScalarAggregateReduceError::WorkLimit { .. }
        | UnicodeScalarAggregateReduceError::ScratchLimit { .. }
        | UnicodeScalarAggregateReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn fixed_class_sandwich_build_error(
    source: &FixedClassSandwichBuildError,
    message: String,
) -> ExecutionError {
    match source {
        FixedClassSandwichBuildError::MiddleRepetitionLimit { .. }
        | FixedClassSandwichBuildError::RangeLimit { .. }
        | FixedClassSandwichBuildError::WorkLimit { .. }
        | FixedClassSandwichBuildError::ScratchLimit { .. }
        | FixedClassSandwichBuildError::PersistentLimit { .. }
        | FixedClassSandwichBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn fixed_class_sandwich_reduce_error(
    source: &FixedClassSandwichReduceError,
    message: String,
) -> ExecutionError {
    match source {
        FixedClassSandwichReduceError::InputBytesLimit { .. }
        | FixedClassSandwichReduceError::DecodeByteChecksLimit { .. }
        | FixedClassSandwichReduceError::MembershipTestsLimit { .. }
        | FixedClassSandwichReduceError::RangeComparisonsLimit { .. }
        | FixedClassSandwichReduceError::ReducerStepsLimit { .. }
        | FixedClassSandwichReduceError::MatchEventsLimit { .. }
        | FixedClassSandwichReduceError::CountLimit { .. }
        | FixedClassSandwichReduceError::SpanSumLimit { .. }
        | FixedClassSandwichReduceError::WorkLimit { .. }
        | FixedClassSandwichReduceError::ScratchLimit { .. }
        | FixedClassSandwichReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn fixed_predicate_word64_build_error(
    source: &FixedPredicateWord64BuildError,
    message: String,
) -> ExecutionError {
    match source {
        FixedPredicateWord64BuildError::PositionLimit { .. }
        | FixedPredicateWord64BuildError::SourceRangesLimit { .. }
        | FixedPredicateWord64BuildError::WorkLimit { .. }
        | FixedPredicateWord64BuildError::ScratchLimit { .. }
        | FixedPredicateWord64BuildError::PersistentLimit { .. }
        | FixedPredicateWord64BuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn fixed_predicate_word64_reduce_error(
    source: &FixedPredicateWord64ReduceError,
    message: String,
) -> ExecutionError {
    match source {
        FixedPredicateWord64ReduceError::InputLimit { .. }
        | FixedPredicateWord64ReduceError::TransitionsLimit { .. }
        | FixedPredicateWord64ReduceError::MatchEventsLimit { .. }
        | FixedPredicateWord64ReduceError::CountLimit { .. }
        | FixedPredicateWord64ReduceError::SpanSumLimit { .. }
        | FixedPredicateWord64ReduceError::ReducerStepsLimit { .. }
        | FixedPredicateWord64ReduceError::WorkLimit { .. }
        | FixedPredicateWord64ReduceError::ScratchLimit { .. }
        | FixedPredicateWord64ReduceError::PersistentLimit { .. }
        | FixedPredicateWord64ReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn grapheme_scalar_dfa_build_error(
    source: &GraphemeScalarDfaBuildError,
    message: String,
) -> ExecutionError {
    match source {
        GraphemeScalarDfaBuildError::RangeLimit { .. }
        | GraphemeScalarDfaBuildError::EventLimit { .. }
        | GraphemeScalarDfaBuildError::SegmentLimit { .. }
        | GraphemeScalarDfaBuildError::SortComparisonsLimit { .. }
        | GraphemeScalarDfaBuildError::AllocationLimit { .. }
        | GraphemeScalarDfaBuildError::EventWritesLimit { .. }
        | GraphemeScalarDfaBuildError::SegmentWritesLimit { .. }
        | GraphemeScalarDfaBuildError::WorkLimit { .. }
        | GraphemeScalarDfaBuildError::ScratchLimit { .. }
        | GraphemeScalarDfaBuildError::PersistentLimit { .. }
        | GraphemeScalarDfaBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn grapheme_scalar_dfa_reduce_error(
    source: &GraphemeScalarDfaReduceError,
    message: String,
) -> ExecutionError {
    match source {
        GraphemeScalarDfaReduceError::InputBytesLimit { .. }
        | GraphemeScalarDfaReduceError::DecodeByteChecksLimit { .. }
        | GraphemeScalarDfaReduceError::ClassificationsLimit { .. }
        | GraphemeScalarDfaReduceError::RangeComparisonsLimit { .. }
        | GraphemeScalarDfaReduceError::ScannerStepsLimit { .. }
        | GraphemeScalarDfaReduceError::RoleProbesLimit { .. }
        | GraphemeScalarDfaReduceError::BranchChecksLimit { .. }
        | GraphemeScalarDfaReduceError::RepetitionTestsLimit { .. }
        | GraphemeScalarDfaReduceError::MatchEventsLimit { .. }
        | GraphemeScalarDfaReduceError::CountLimit { .. }
        | GraphemeScalarDfaReduceError::SpanSumLimit { .. }
        | GraphemeScalarDfaReduceError::WorkLimit { .. }
        | GraphemeScalarDfaReduceError::ScratchLimit { .. }
        | GraphemeScalarDfaReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn bounded_class_sequence_build_error(
    source: &BoundedClassSequenceBuildError,
    message: String,
) -> ExecutionError {
    match source {
        BoundedClassSequenceBuildError::RepeatLimit { .. }
        | BoundedClassSequenceBuildError::RangeLimit { .. }
        | BoundedClassSequenceBuildError::WorkLimit { .. }
        | BoundedClassSequenceBuildError::PersistentLimit { .. }
        | BoundedClassSequenceBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn bounded_separated_fields_build_error(
    source: &BoundedSeparatedFieldsBuildError,
    message: String,
) -> ExecutionError {
    match source {
        BoundedSeparatedFieldsBuildError::RangeLimit { .. }
        | BoundedSeparatedFieldsBuildError::WorkLimit { .. }
        | BoundedSeparatedFieldsBuildError::PersistentLimit { .. }
        | BoundedSeparatedFieldsBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn bounded_context_build_error(
    source: &fre::BoundedContextBuildError,
    message: String,
) -> ExecutionError {
    match source {
        fre::BoundedContextBuildError::RepeatLimit { .. }
        | fre::BoundedContextBuildError::GapLimit { .. }
        | fre::BoundedContextBuildError::RangeLimit { .. }
        | fre::BoundedContextBuildError::LiteralLimit { .. }
        | fre::BoundedContextBuildError::WorkLimit { .. }
        | fre::BoundedContextBuildError::ScratchLimit { .. }
        | fre::BoundedContextBuildError::PersistentLimit { .. }
        | fre::BoundedContextBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn literal_class_run_literal_build_error(
    source: &LiteralClassRunLiteralBuildError,
    message: String,
) -> ExecutionError {
    match source {
        LiteralClassRunLiteralBuildError::LiteralBytesLimit { .. }
        | LiteralClassRunLiteralBuildError::ClassRangesLimit { .. }
        | LiteralClassRunLiteralBuildError::ClassMembersLimit { .. }
        | LiteralClassRunLiteralBuildError::WorkLimit { .. }
        | LiteralClassRunLiteralBuildError::ScratchLimit { .. }
        | LiteralClassRunLiteralBuildError::PersistentLimit { .. }
        | LiteralClassRunLiteralBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn bounded_literal_pair_build_error(
    source: &fre::BoundedLiteralPairBuildError,
    message: String,
) -> ExecutionError {
    match source {
        fre::BoundedLiteralPairBuildError::LiteralBytesLimit { .. }
        | fre::BoundedLiteralPairBuildError::ClassRangesLimit { .. }
        | fre::BoundedLiteralPairBuildError::ClassMembersLimit { .. }
        | fre::BoundedLiteralPairBuildError::GapLimit { .. }
        | fre::BoundedLiteralPairBuildError::WorkLimit { .. }
        | fre::BoundedLiteralPairBuildError::ScratchLimit { .. }
        | fre::BoundedLiteralPairBuildError::PersistentLimit { .. }
        | fre::BoundedLiteralPairBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn bounded_class_sequence_reduce_error(
    source: &BoundedClassSequenceReduceError,
    message: String,
) -> ExecutionError {
    match source {
        BoundedClassSequenceReduceError::InputLimit { .. }
        | BoundedClassSequenceReduceError::CountLimit { .. }
        | BoundedClassSequenceReduceError::WorkLimit { .. }
        | BoundedClassSequenceReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn bounded_separated_fields_reduce_error(
    source: &BoundedSeparatedFieldsReduceError,
    message: String,
) -> ExecutionError {
    match source {
        BoundedSeparatedFieldsReduceError::InputLimit { .. }
        | BoundedSeparatedFieldsReduceError::SequentialLimit { .. }
        | BoundedSeparatedFieldsReduceError::CountLimit { .. }
        | BoundedSeparatedFieldsReduceError::WorkLimit { .. }
        | BoundedSeparatedFieldsReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn bounded_context_reduce_error(
    source: &fre::BoundedContextReduceError,
    message: String,
) -> ExecutionError {
    match source {
        fre::BoundedContextReduceError::InputLimit { .. }
        | fre::BoundedContextReduceError::WorkLimit { .. }
        | fre::BoundedContextReduceError::MatchEventsLimit { .. }
        | fre::BoundedContextReduceError::CountLimit { .. }
        | fre::BoundedContextReduceError::SpanSumLimit { .. }
        | fre::BoundedContextReduceError::ScratchLimit { .. }
        | fre::BoundedContextReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn literal_class_run_literal_reduce_error(
    source: &LiteralClassRunLiteralReduceError,
    message: String,
) -> ExecutionError {
    match source {
        LiteralClassRunLiteralReduceError::InputBytesLimit { .. }
        | LiteralClassRunLiteralReduceError::SourceReadsLimit { .. }
        | LiteralClassRunLiteralReduceError::WorkLimit { .. }
        | LiteralClassRunLiteralReduceError::RunEventsLimit { .. }
        | LiteralClassRunLiteralReduceError::MatchEventsLimit { .. }
        | LiteralClassRunLiteralReduceError::CountLimit { .. }
        | LiteralClassRunLiteralReduceError::SpanSumLimit { .. }
        | LiteralClassRunLiteralReduceError::ScratchLimit { .. }
        | LiteralClassRunLiteralReduceError::PersistentLimit { .. }
        | LiteralClassRunLiteralReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn bounded_literal_pair_reduce_error(
    source: &fre::BoundedLiteralPairReduceError,
    message: String,
) -> ExecutionError {
    match source {
        fre::BoundedLiteralPairReduceError::InputBytesLimit { .. }
        | fre::BoundedLiteralPairReduceError::SourceReadsLimit { .. }
        | fre::BoundedLiteralPairReduceError::WorkLimit { .. }
        | fre::BoundedLiteralPairReduceError::CandidateEventsLimit { .. }
        | fre::BoundedLiteralPairReduceError::SuffixProbesLimit { .. }
        | fre::BoundedLiteralPairReduceError::MatchEventsLimit { .. }
        | fre::BoundedLiteralPairReduceError::CountLimit { .. }
        | fre::BoundedLiteralPairReduceError::SpanSumLimit { .. }
        | fre::BoundedLiteralPairReduceError::ScratchLimit { .. }
        | fre::BoundedLiteralPairReduceError::PersistentLimit { .. }
        | fre::BoundedLiteralPairReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn sparse_ordered_literal_build_error(
    source: &SparseOrderedLiteralAggregateBuildError,
    message: String,
) -> ExecutionError {
    match source {
        SparseOrderedLiteralAggregateBuildError::PatternLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::PatternBytesLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::IdentityBytesLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::TrieStatesLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::SparseEdgesLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::WorkLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::ScratchLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::PersistentLimit { .. }
        | SparseOrderedLiteralAggregateBuildError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn packed_ordered_literal_build_error(
    source: &fre::PackedOrderedLiteralAggregateBuildError,
    message: String,
) -> ExecutionError {
    match source {
        fre::PackedOrderedLiteralAggregateBuildError::PatternLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::PatternBytesLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::TotalPatternBytesLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::IdentityLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::WorkLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::BuildPeakLimit { .. }
        | fre::PackedOrderedLiteralAggregateBuildError::PersistentLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn sparse_ordered_literal_reduce_error(
    source: &SparseOrderedLiteralAggregateReduceError,
    message: String,
) -> ExecutionError {
    match source {
        SparseOrderedLiteralAggregateReduceError::TransitionLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::EdgeLookupLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::EdgeSearchChecksLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::FailureStepsLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::MatchEventsLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::CountLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::SpanSumLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::ReducerStepsLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::RingInitializationLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::TotalWorkLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::ScratchLimit { .. }
        | SparseOrderedLiteralAggregateReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn packed_ordered_literal_reduce_error(
    source: &fre::PackedOrderedLiteralAggregateReduceError,
    message: String,
) -> ExecutionError {
    match source {
        fre::PackedOrderedLiteralAggregateReduceError::WorkLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::MatchEventsLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::CountLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::SpanSumLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::ReducerStepsLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::ScratchLimit { .. }
        | fre::PackedOrderedLiteralAggregateReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn word_run_reduce_error(source: &fre::WordRunReduceError, message: String) -> ExecutionError {
    match source {
        fre::WordRunReduceError::InputBytesLimit { .. }
        | fre::WordRunReduceError::SourceReadsLimit { .. }
        | fre::WordRunReduceError::WorkLimit { .. }
        | fre::WordRunReduceError::UnitEventsLimit { .. }
        | fre::WordRunReduceError::RunEventsLimit { .. }
        | fre::WordRunReduceError::MatchEventsLimit { .. }
        | fre::WordRunReduceError::CountLimit { .. }
        | fre::WordRunReduceError::SpanSumLimit { .. }
        | fre::WordRunReduceError::ScratchLimit { .. }
        | fre::WordRunReduceError::PersistentLimit { .. }
        | fre::WordRunReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        fre::WordRunReduceError::ArithmeticOverflow { .. }
        | fre::WordRunReduceError::AccountingInvariant { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn word_run_build_error(source: &fre::WordRunBuildError, message: String) -> ExecutionError {
    match source {
        fre::WordRunBuildError::WorkLimit { .. }
        | fre::WordRunBuildError::ScratchLimit { .. }
        | fre::WordRunBuildError::PersistentLimit { .. }
        | fre::WordRunBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn literal_assertions_build_error(
    source: &LiteralAssertionsBuildError,
    message: String,
) -> ExecutionError {
    match source {
        LiteralAssertionsBuildError::LiteralBytesLimit { .. }
        | LiteralAssertionsBuildError::WorkLimit { .. }
        | LiteralAssertionsBuildError::ScratchLimit { .. }
        | LiteralAssertionsBuildError::PersistentLimit { .. }
        | LiteralAssertionsBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        LiteralAssertionsBuildError::EmptyLiteral
        | LiteralAssertionsBuildError::AllocationFailed { .. }
        | LiteralAssertionsBuildError::ArithmeticOverflow { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn literal_assertions_reduce_error(
    source: &LiteralAssertionsReduceError,
    message: String,
) -> ExecutionError {
    match source {
        LiteralAssertionsReduceError::InputBytesLimit { .. }
        | LiteralAssertionsReduceError::SourceReadsLimit { .. }
        | LiteralAssertionsReduceError::WorkLimit { .. }
        | LiteralAssertionsReduceError::CandidateScanBytesLimit { .. }
        | LiteralAssertionsReduceError::LiteralComparisonsLimit { .. }
        | LiteralAssertionsReduceError::AssertionChecksLimit { .. }
        | LiteralAssertionsReduceError::BoundaryReadsLimit { .. }
        | LiteralAssertionsReduceError::CandidateEventsLimit { .. }
        | LiteralAssertionsReduceError::MatchEventsLimit { .. }
        | LiteralAssertionsReduceError::CountLimit { .. }
        | LiteralAssertionsReduceError::SpanSumLimit { .. }
        | LiteralAssertionsReduceError::ScratchLimit { .. }
        | LiteralAssertionsReduceError::PersistentLimit { .. }
        | LiteralAssertionsReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        LiteralAssertionsReduceError::ArithmeticOverflow { .. }
        | LiteralAssertionsReduceError::AccountingInvariant { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn blocking_delimiter_build_error(
    source: &BlockingDelimiterBuildError,
    message: String,
) -> ExecutionError {
    match source {
        BlockingDelimiterBuildError::DelimiterMembersLimit { .. }
        | BlockingDelimiterBuildError::TerminalMembersLimit { .. }
        | BlockingDelimiterBuildError::MiddleBytesLimit { .. }
        | BlockingDelimiterBuildError::WorkLimit { .. }
        | BlockingDelimiterBuildError::ScratchLimit { .. }
        | BlockingDelimiterBuildError::PersistentLimit { .. }
        | BlockingDelimiterBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        BlockingDelimiterBuildError::NonCanonicalDelimiters
        | BlockingDelimiterBuildError::EmptyTerminalClass
        | BlockingDelimiterBuildError::TerminalContainsDelimiter { .. }
        | BlockingDelimiterBuildError::ArithmeticOverflow { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn blocking_delimiter_reduce_error(
    source: &BlockingDelimiterReduceError,
    message: String,
) -> ExecutionError {
    match source {
        BlockingDelimiterReduceError::InputBytesLimit { .. }
        | BlockingDelimiterReduceError::SourceReadsLimit { .. }
        | BlockingDelimiterReduceError::WorkLimit { .. }
        | BlockingDelimiterReduceError::DelimiterScanBytesLimit { .. }
        | BlockingDelimiterReduceError::DelimiterEventsLimit { .. }
        | BlockingDelimiterReduceError::PairEventsLimit { .. }
        | BlockingDelimiterReduceError::TerminalReadsLimit { .. }
        | BlockingDelimiterReduceError::MatchEventsLimit { .. }
        | BlockingDelimiterReduceError::CountLimit { .. }
        | BlockingDelimiterReduceError::SpanSumLimit { .. }
        | BlockingDelimiterReduceError::ScratchLimit { .. }
        | BlockingDelimiterReduceError::PersistentLimit { .. }
        | BlockingDelimiterReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        BlockingDelimiterReduceError::ArithmeticOverflow { .. }
        | BlockingDelimiterReduceError::AccountingInvariant { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn token_phrase_build_error(source: &TokenPhraseBuildError, message: String) -> ExecutionError {
    match source {
        TokenPhraseBuildError::LiteralBytesLimit { .. }
        | TokenPhraseBuildError::WorkLimit { .. }
        | TokenPhraseBuildError::ScratchLimit { .. }
        | TokenPhraseBuildError::PersistentLimit { .. }
        | TokenPhraseBuildError::PeakLimit { .. } => ExecutionError::unsupported(message),
        TokenPhraseBuildError::EmptyLiteral
        | TokenPhraseBuildError::NonWordLiteral { .. }
        | TokenPhraseBuildError::AllocationFailed { .. }
        | TokenPhraseBuildError::ArithmeticOverflow { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn token_phrase_reduce_error(source: &TokenPhraseReduceError, message: String) -> ExecutionError {
    match source {
        TokenPhraseReduceError::InputBytesLimit { .. }
        | TokenPhraseReduceError::SourceReadsLimit { .. }
        | TokenPhraseReduceError::WorkLimit { .. }
        | TokenPhraseReduceError::ClassificationsLimit { .. }
        | TokenPhraseReduceError::LiteralComparisonsLimit { .. }
        | TokenPhraseReduceError::TokenEventsLimit { .. }
        | TokenPhraseReduceError::MatchEventsLimit { .. }
        | TokenPhraseReduceError::CountLimit { .. }
        | TokenPhraseReduceError::SpanSumLimit { .. }
        | TokenPhraseReduceError::ScratchLimit { .. }
        | TokenPhraseReduceError::PersistentLimit { .. }
        | TokenPhraseReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
        TokenPhraseReduceError::ArithmeticOverflow { .. }
        | TokenPhraseReduceError::AccountingInvariant { .. }
        | _ => ExecutionError::fault(message),
    }
}

fn aggregate_execution_error(source: &AggregateExecutionSource, message: String) -> ExecutionError {
    match source {
        AggregateExecutionSource::UnicodeScalar(source) => {
            unicode_scalar_reduce_error(source, message)
        }
        AggregateExecutionSource::WordRun(source) => word_run_reduce_error(source, message),
        AggregateExecutionSource::LiteralAssertions(source) => {
            literal_assertions_reduce_error(source, message)
        }
        AggregateExecutionSource::BlockingDelimiter(source) => {
            blocking_delimiter_reduce_error(source, message)
        }
        AggregateExecutionSource::TokenPhrase(source) => token_phrase_reduce_error(source, message),
        AggregateExecutionSource::FixedClassSandwich(source) => {
            fixed_class_sandwich_reduce_error(source, message)
        }
        AggregateExecutionSource::GraphemeScalarDfa(source) => {
            grapheme_scalar_dfa_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedClassSequence(source) => {
            bounded_class_sequence_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedSeparatedFields(source) => {
            bounded_separated_fields_reduce_error(source, message)
        }
        AggregateExecutionSource::PrefixClassAlternation(source) => {
            prefix_class_reduce_error(source, message)
        }
        AggregateExecutionSource::LiteralClassRunLiteral(source) => {
            literal_class_run_literal_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedLiteralPair(source) => {
            bounded_literal_pair_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedContext(source) => {
            bounded_context_reduce_error(source, message)
        }
        // Exact-literal resource refusals are unsupported only when the full
        // construction-owned direct attempt closes. A detached source cannot
        // carry that proof and must fail closed.
        AggregateExecutionSource::ExactLiteral(_)
        | AggregateExecutionSource::FixedAbsoluteDomain
        | AggregateExecutionSource::FixedAbsoluteDomainResidual
        | AggregateExecutionSource::InternalInvariant(_) => ExecutionError::fault(message),
        AggregateExecutionSource::FiniteLiteral(source) => {
            ordered_literal_many_reduce_error(source, message)
        }
        AggregateExecutionSource::PackedFiniteLiteral(source) => {
            packed_ordered_literal_reduce_error(source, message)
        }
        AggregateExecutionSource::SparseFiniteLiteral(source) => {
            sparse_ordered_literal_reduce_error(source, message)
        }
        AggregateExecutionSource::GuardedAsciiWord(source) => match source.kind {
            guarded_ascii_word::ReduceErrorKind::ResourceLimit { .. } => {
                ExecutionError::unsupported(message)
            }
            guarded_ascii_word::ReduceErrorKind::ArithmeticOverflow { .. }
            | guarded_ascii_word::ReduceErrorKind::InternalInvariant { .. } => {
                ExecutionError::fault(message)
            }
        },
        AggregateExecutionSource::FixedPredicateWord64(source) => {
            fixed_predicate_word64_reduce_error(source, message)
        }
        AggregateExecutionSource::Continuation(source) => aggregate_engine_error(source, message),
    }
}

fn aggregate_attempt_error(
    error: &fre::AggregateExecutionError,
    message: String,
) -> ExecutionError {
    match &error.source {
        AggregateExecutionSource::ExactLiteral(source) => {
            if error.has_closed_direct_attempt() {
                literal_reduce_error(source, message)
            } else {
                ExecutionError::fault(message)
            }
        }
        AggregateExecutionSource::FixedAbsoluteDomain => {
            let Some(attempt) = error.identity.as_fixed_absolute_domain_attempt() else {
                return ExecutionError::fault(message);
            };
            let Some(owner) = error.identity.as_fixed_absolute_domain() else {
                return ExecutionError::fault(message);
            };
            let Some(receipt) = error.fixed_absolute_domain_receipt() else {
                return ExecutionError::fault(message);
            };
            let Some(source) = receipt.guard_error() else {
                return ExecutionError::fault(message);
            };
            if error.has_closed_fixed_attempt()
                && std::ptr::eq(attempt.owner_identity(), owner)
                && std::ptr::eq(attempt.receipt(), receipt)
                && source.receipt.identity == owner.plan_identity.kernel
                && fixed_absolute_reduce_resource_refusal_is_closed(source)
            {
                ExecutionError::unsupported(message)
            } else {
                ExecutionError::fault(message)
            }
        }
        AggregateExecutionSource::FixedAbsoluteDomainResidual => {
            let Some(attempt) = error.identity.as_fixed_absolute_domain_attempt() else {
                return ExecutionError::fault(message);
            };
            let Some(owner) = error.identity.as_fixed_absolute_domain() else {
                return ExecutionError::fault(message);
            };
            let Some(receipt) = error.fixed_absolute_domain_receipt() else {
                return ExecutionError::fault(message);
            };
            let Some((continuation, composite)) = receipt.residual_error() else {
                return ExecutionError::fault(message);
            };
            if error.has_closed_fixed_attempt()
                && std::ptr::eq(attempt.owner_identity(), owner)
                && std::ptr::eq(attempt.receipt(), receipt)
                && composite.guard.identity == owner.plan_identity.kernel
                && fixed_absolute_residual_refusal_is_closed(continuation, composite)
            {
                aggregate_engine_error(&continuation.source, message)
            } else {
                ExecutionError::fault(message)
            }
        }
        _ if error.identity.as_cache_identity().is_some() => {
            aggregate_execution_error(&error.source, message)
        }
        _ => ExecutionError::fault(message),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the adapter exhaustively classifies every typed aggregate construction terminal at one fail-closed boundary"
)]
fn aggregate_build_error(error: &AggregateBuildError) -> ExecutionError {
    let message = format!("FRE aggregate build refused input: {error}");
    match &error {
        AggregateBuildError::Syntax { .. }
        | AggregateBuildError::LiteralPlannerWorkLimit { .. }
        | AggregateBuildError::UnicodeScalarPlannerWorkLimit { .. }
        | AggregateBuildError::WordRunPlannerWorkLimit { .. }
        | AggregateBuildError::LiteralAssertionsPlannerWorkLimit { .. }
        | AggregateBuildError::BlockingDelimiterPlannerWorkLimit { .. }
        | AggregateBuildError::TokenPhrasePlannerWorkLimit { .. }
        | AggregateBuildError::FixedClassSandwichPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedAffixPlannerWorkLimit { .. }
        | AggregateBuildError::GraphemeScalarDfaPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedClassSequencePlannerWorkLimit { .. }
        | AggregateBuildError::BoundedSeparatedFieldsPlannerWorkLimit { .. }
        | AggregateBuildError::PrefixClassAlternationPlannerWorkLimit { .. }
        | AggregateBuildError::LiteralClassRunLiteralPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedLiteralPairPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedContextPlannerWorkLimit { .. }
        | AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit { .. }
        | AggregateBuildError::FinitePlannerWorkLimit { .. }
        | AggregateBuildError::FinitePlannerAllocationFailed { .. }
        | AggregateBuildError::ExactLiteralIneligible { .. } => {
            ExecutionError::unsupported(message)
        }
        AggregateBuildError::ExactLiteralBuild { source, .. } => {
            literal_build_error(source, message)
        }
        AggregateBuildError::UnicodeScalarBuild { source, .. } => {
            unicode_scalar_build_error(source, message)
        }
        AggregateBuildError::WordRunBuild { source, .. } => word_run_build_error(source, message),
        AggregateBuildError::LiteralAssertionsBuild { source, .. } => {
            literal_assertions_build_error(source, message)
        }
        AggregateBuildError::BlockingDelimiterBuild { source, .. } => {
            blocking_delimiter_build_error(source, message)
        }
        AggregateBuildError::TokenPhraseBuild { source, .. } => {
            token_phrase_build_error(source, message)
        }
        AggregateBuildError::FixedClassSandwichBuild { source, .. } => {
            fixed_class_sandwich_build_error(source, message)
        }
        AggregateBuildError::GraphemeScalarDfaBuild { source, .. } => {
            grapheme_scalar_dfa_build_error(source, message)
        }
        AggregateBuildError::BoundedClassSequenceBuild { source, .. } => {
            bounded_class_sequence_build_error(source, message)
        }
        AggregateBuildError::BoundedSeparatedFieldsBuild { source, .. } => {
            bounded_separated_fields_build_error(source, message)
        }
        AggregateBuildError::PrefixClassAlternationBuild { source, .. } => {
            prefix_class_build_error(source, message)
        }
        AggregateBuildError::LiteralClassRunLiteralBuild { source, .. } => {
            literal_class_run_literal_build_error(source, message)
        }
        AggregateBuildError::BoundedLiteralPairBuild { source, .. } => {
            bounded_literal_pair_build_error(source, message)
        }
        AggregateBuildError::BoundedContextBuild { source, .. } => {
            bounded_context_build_error(source, message)
        }
        AggregateBuildError::FixedAbsoluteDomainBuild {
            planner_work,
            source,
            ..
        } => {
            if fixed_absolute_planner_work_is_closed(*planner_work) {
                fixed_absolute_build_error(source, message)
            } else {
                ExecutionError::fault(message)
            }
        }
        AggregateBuildError::FixedAbsoluteDomainResidualGuardBuild {
            operation,
            selection,
            planner_work,
            source,
            composite,
        } => fixed_absolute_residual_guard_build_error(
            *operation,
            *selection,
            *planner_work,
            source,
            *composite,
            message,
        ),
        AggregateBuildError::FixedAbsoluteDomainResidualPreflight {
            operation,
            selection,
            planner_work,
            resource,
            needed,
            limit,
            receipt,
            ..
        } => {
            if fixed_absolute_residual_build_preflight_is_closed(
                *operation,
                *selection,
                *planner_work,
                *resource,
                *needed,
                *limit,
                *receipt,
            ) {
                ExecutionError::unsupported(message)
            } else {
                ExecutionError::fault(message)
            }
        }
        AggregateBuildError::FixedAbsoluteDomainResidualCompile {
            operation,
            selection,
            planner_work,
            strategy,
            guard,
            source,
            composite,
        } => fixed_absolute_residual_compile_error(
            *operation,
            *selection,
            *planner_work,
            *strategy,
            *guard,
            source,
            *composite,
            message,
        ),
        AggregateBuildError::FiniteLiteralBuild { source, .. } => {
            ordered_literal_many_build_error(source, message)
        }
        AggregateBuildError::PackedFiniteLiteralBuild { source, .. } => {
            packed_ordered_literal_build_error(source, message)
        }
        AggregateBuildError::SparseFiniteLiteralBuild { source, .. } => {
            sparse_ordered_literal_build_error(source, message)
        }
        AggregateBuildError::FixedPredicateWord64Build { source, .. } => {
            fixed_predicate_word64_build_error(source, message)
        }
        AggregateBuildError::ContinuationCompile { source, .. } => {
            aggregate_engine_error(source, message)
        }
        // Facade invariants and every future non-refusal variant are faults.
        _ => ExecutionError::fault(message),
    }
}

fn fre_aggregate_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if request.patterns.len() != 1 {
        return fre_aggregate_many_count(request, limits);
    }
    if let Some(reduction) = canonical_case_fold::try_count(request, limits)? {
        return Ok(reduction);
    }
    let pattern = one_fre_pattern(request)?;
    let regex = AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_build_limits(limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| aggregate_build_error(&error))?;
    require_unicode_plan_identity(
        regex.build_report(),
        request.unicode,
        LiteralAggregateOperation::Count,
    )?;
    let operation_limits = count_run_limits_with_policy(request.haystack.len(), &regex, limits)?;
    let operation_limits = &operation_limits;
    let actual = regex
        .count_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate count refused execution: {error}");
            aggregate_attempt_error(&error, message)
        })?;
    let plan = aggregate_single_plan_label("count", regex.build_report());
    Ok(FreReduction { actual, plan })
}

fn fre_aggregate_span_sum(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    if request.patterns.len() != 1 {
        return fre_aggregate_many_span_sum(request, limits);
    }
    let pattern = one_fre_pattern(request)?;
    let regex = AggregateBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_build_limits(limits))
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_span_sum()
        .map_err(|error| aggregate_build_error(&error))?;
    require_unicode_plan_identity(
        regex.build_report(),
        request.unicode,
        LiteralAggregateOperation::SpanSum,
    )?;
    let operation_limits = span_sum_run_limits_with_policy(request.haystack.len(), &regex, limits)?;
    let operation_limits = &operation_limits;
    let actual = regex
        .span_sum_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate span-sum refused execution: {error}");
            aggregate_attempt_error(&error, message)
        })?;
    let plan = aggregate_single_plan_label("count-spans", regex.build_report());
    Ok(FreReduction { actual, plan })
}

fn aggregate_many_build_limits(limits: &RunLimits) -> AggregateManyBuildLimits {
    let u32_cells = limits
        .fre_aggregate_program_bytes
        .checked_div(core::mem::size_of::<u32>())
        .unwrap_or(0);
    AggregateManyBuildLimits {
        max_patterns: limits.patterns_per_job,
        max_pattern_bytes: limits.pattern_bytes_per_job,
        max_composition_work: u64::try_from(limits.fre_aggregate_compile_work).unwrap_or(u64::MAX),
        max_composition_scratch_bytes: limits.fre_aggregate_scratch_bytes,
        max_report_capacity_bytes: limits.fre_aggregate_program_bytes,
        max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
        ordered_literal: OrderedLiteralAggregateBuildLimits {
            max_patterns: limits.patterns_per_job,
            max_pattern_bytes: limits.pattern_bytes_per_job,
            max_identity_bytes: limits.fre_literal_build_needle_bytes,
            max_trie_states: u32_cells,
            max_dfa_cells: u32_cells,
            max_build_work: limits.fre_literal_build_work,
            max_scratch_bytes: limits.fre_literal_build_scratch_bytes,
            max_persistent_bytes: limits.fre_literal_build_persistent_bytes,
            max_peak_bytes: limits.fre_literal_build_peak_bytes,
        },
        continuation: fre::AggregateCompileLimits {
            max_hir_nodes: limits.fre_aggregate_hir_nodes,
            max_hir_stack_items: limits.fre_aggregate_hir_stack_items,
            max_repeat_bound: limits.fre_aggregate_repeat_bound,
            max_work: limits.fre_aggregate_compile_work,
            max_program_bytes: limits.fre_aggregate_program_bytes,
            ..fre::AggregateCompileLimits::default()
        },
        ..AggregateManyBuildLimits::default()
    }
}

fn require_aggregate_many_identity(
    request: CandidateRequest<'_>,
    report: &AggregateManyBuildReport,
    operation: AggregateManyOperation,
) -> Result<(), ExecutionError> {
    require_aggregate_many_report_identity(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        report,
        operation,
    )
}

fn require_aggregate_many_report_identity(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    report: &AggregateManyBuildReport,
    operation: AggregateManyOperation,
) -> Result<(), ExecutionError> {
    let mut expected_profile = rebar_profile();
    expected_profile.options.unicode = unicode;
    expected_profile.options.case_insensitive = case_insensitive;
    if report.profile != expected_profile || report.operation != operation {
        return Err(ExecutionError::fault(
            "FRE ordered build-many profile/operation identity mismatch",
        ));
    }
    match operation {
        AggregateManyOperation::CaptureCount => {
            if report.capture_semantics
                != Some(AggregateManyCaptureSemantics::UniformSingleWholeMatchCaptureNonempty)
                || report.participating_captures_per_match != Some(1)
            {
                return Err(ExecutionError::fault(
                    "FRE ordered build-many capture participation identity mismatch",
                ));
            }
        }
        AggregateManyOperation::Compile
        | AggregateManyOperation::Count
        | AggregateManyOperation::SpanSum
        | AggregateManyOperation::Spans => {
            if report.capture_semantics.is_some()
                || report.participating_captures_per_match.is_some()
            {
                return Err(ExecutionError::fault(
                    "FRE non-capture build-many plan retained capture participation identity",
                ));
            }
        }
    }
    if report.patterns.len() != patterns.len() {
        return Err(ExecutionError::fault(
            "FRE ordered build-many pattern identity count mismatch",
        ));
    }
    for (ordinal, (pattern_report, source)) in report.patterns.iter().zip(patterns).enumerate() {
        if pattern_report.ordinal != ordinal
            || pattern_report.syntax_key.pattern.as_bytes() != source.as_bytes()
            || pattern_report.syntax_key.profile
                != CompatibilityProfile::RustBytes(expected_profile.clone())
        {
            return Err(ExecutionError::fault(format!(
                "FRE ordered build-many pattern {ordinal} identity mismatch"
            )));
        }
    }
    let literal_semantics = match report.plan_identity {
        AggregateManyPlanIdentity::OrderedLiteral { semantics, .. } => Some(semantics),
        AggregateManyPlanIdentity::Continuation(_) => None,
    };
    if unicode
        && literal_semantics != Some(AggregateManyLiteralSemantics::UnicodeOnNonemptyUtf8Literals)
    {
        return Err(ExecutionError::fault(
            "FRE Unicode ordered build-many literal proof identity mismatch",
        ));
    }
    if !unicode
        && literal_semantics.is_some_and(|semantics| {
            semantics != AggregateManyLiteralSemantics::UnicodeOffByteBoundaries
        })
    {
        return Err(ExecutionError::fault(
            "FRE byte ordered build-many literal proof identity mismatch",
        ));
    }
    Ok(())
}

fn aggregate_many_run_limits(
    haystack_len: usize,
    report: &fre::AggregateManyBuildReport,
    limits: &RunLimits,
) -> Result<AggregateManyRunLimits, ExecutionError> {
    let boundaries = checked_aggregate_add(haystack_len, 1, "build-many boundaries")?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let ordered_literal = match report.build {
        AggregateManyBuildAccounting::OrderedLiteral(build) => {
            let match_events = if build.has_empty_pattern {
                boundaries
            } else {
                let minimum = build.min_nonempty_pattern_bytes.ok_or_else(|| {
                    ExecutionError::fault("FRE ordered literal plan lacks a nonempty minimum")
                })?;
                haystack_len
                    .checked_div(minimum)
                    .ok_or_else(|| ExecutionError::fault("FRE ordered literal minimum is zero"))?
            };
            let count = u64::try_from(match_events).map_err(|_| {
                ExecutionError::fault("FRE ordered literal count bound does not fit u64")
            })?;
            let ring = build
                .max_pattern_bytes
                .min(haystack_len)
                .checked_add(1)
                .ok_or_else(|| ExecutionError::fault("FRE ordered literal ring overflow"))?;
            OrderedLiteralAggregateReduceLimits {
                max_transitions: haystack_len,
                max_match_events: match_events.min(reducer_limit),
                max_count: count.min(limits.reducer_steps),
                max_span_sum: u64::try_from(haystack_len).map_err(|_| {
                    ExecutionError::fault("FRE ordered literal span bound does not fit u64")
                })?,
                max_reducer_steps: boundaries.min(reducer_limit),
                max_ring_initializations: ring,
                max_total_work: limits.fre_aggregate_operation_work,
                max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
                max_peak_bytes: limits.fre_aggregate_peak_bytes,
            }
        }
        AggregateManyBuildAccounting::Continuation(_) => OrderedLiteralAggregateReduceLimits {
            max_transitions: haystack_len,
            max_match_events: boundaries.min(reducer_limit),
            max_count: limits.reducer_steps,
            max_span_sum: u64::try_from(haystack_len).map_err(|_| {
                ExecutionError::fault("FRE inactive ordered span bound does not fit u64")
            })?,
            max_reducer_steps: boundaries.min(reducer_limit),
            max_ring_initializations: boundaries,
            max_total_work: limits.fre_aggregate_operation_work,
            max_scratch_bytes: limits.fre_aggregate_scratch_bytes,
            max_peak_bytes: limits.fre_aggregate_peak_bytes,
        },
    };
    let continuation_shape = match report.build {
        AggregateManyBuildAccounting::Continuation(compile) => compile.into(),
        AggregateManyBuildAccounting::OrderedLiteral(_) => inactive_continuation_shape(),
    };
    Ok(AggregateManyRunLimits {
        ordered_literal,
        continuation: continuation_operation_limits(haystack_len, continuation_shape, limits)?,
    })
}

fn ordered_literal_many_build_error(
    source: &OrderedLiteralAggregateBuildError,
    message: String,
) -> ExecutionError {
    match source {
        OrderedLiteralAggregateBuildError::EmptyPatternSet
        | OrderedLiteralAggregateBuildError::PatternLimit { .. }
        | OrderedLiteralAggregateBuildError::PatternBytesLimit { .. }
        | OrderedLiteralAggregateBuildError::IdentityBytesLimit { .. }
        | OrderedLiteralAggregateBuildError::TrieStatesLimit { .. }
        | OrderedLiteralAggregateBuildError::DfaCellsLimit { .. }
        | OrderedLiteralAggregateBuildError::WorkLimit { .. }
        | OrderedLiteralAggregateBuildError::ScratchLimit { .. }
        | OrderedLiteralAggregateBuildError::PersistentLimit { .. }
        | OrderedLiteralAggregateBuildError::PeakLimit { .. }
        | OrderedLiteralAggregateBuildError::RepresentationLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn ordered_literal_many_reduce_error(
    source: &OrderedLiteralAggregateReduceError,
    message: String,
) -> ExecutionError {
    match source {
        OrderedLiteralAggregateReduceError::TransitionLimit { .. }
        | OrderedLiteralAggregateReduceError::MatchEventsLimit { .. }
        | OrderedLiteralAggregateReduceError::CountLimit { .. }
        | OrderedLiteralAggregateReduceError::SpanSumLimit { .. }
        | OrderedLiteralAggregateReduceError::ReducerStepsLimit { .. }
        | OrderedLiteralAggregateReduceError::RingInitializationLimit { .. }
        | OrderedLiteralAggregateReduceError::TotalWorkLimit { .. }
        | OrderedLiteralAggregateReduceError::ScratchLimit { .. }
        | OrderedLiteralAggregateReduceError::PeakLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn aggregate_many_build_error(error: &AggregateManyBuildError) -> ExecutionError {
    let message = format!("FRE ordered build-many refused input: {error}");
    match error {
        AggregateManyBuildError::UnsupportedOutput { .. }
        | AggregateManyBuildError::EmptyPatternSet
        | AggregateManyBuildError::PatternLimit { .. }
        | AggregateManyBuildError::PatternBytesLimit { .. }
        | AggregateManyBuildError::CompositionWorkLimit { .. }
        | AggregateManyBuildError::CompositionScratchLimit { .. }
        | AggregateManyBuildError::ReportCapacityLimit { .. }
        | AggregateManyBuildError::PersistentLimit { .. }
        | AggregateManyBuildError::Syntax { .. }
        | AggregateManyBuildError::UnicodeNonLiteral { .. }
        | AggregateManyBuildError::CaptureIneligible { .. } => ExecutionError::unsupported(message),
        AggregateManyBuildError::OrderedLiteralBuild { source, .. } => {
            ordered_literal_many_build_error(source, message)
        }
        AggregateManyBuildError::ContinuationCompile { source, .. } => {
            aggregate_engine_error(source, message)
        }
        _ => ExecutionError::fault(message),
    }
}

fn aggregate_many_execution_error(
    source: &AggregateManyExecutionSource,
    message: String,
) -> ExecutionError {
    match source {
        AggregateManyExecutionSource::OrderedLiteral(source) => {
            ordered_literal_many_reduce_error(source, message)
        }
        AggregateManyExecutionSource::Continuation(source) => {
            aggregate_engine_error(source, message)
        }
        AggregateManyExecutionSource::CaptureEventsLimit { .. }
        | AggregateManyExecutionSource::CaptureCountLimit { .. } => {
            ExecutionError::unsupported(message)
        }
        AggregateManyExecutionSource::ArithmeticOverflow { .. }
        | AggregateManyExecutionSource::InternalInvariant(_) => ExecutionError::fault(message),
    }
}

fn fre_aggregate_many_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = aggregate_many_builder_with_limits(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        limits,
    )
    .build_count()
    .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(request, regex.build_report(), AggregateManyOperation::Count)?;
    let operation_limits =
        aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let actual = regex
        .count_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message =
                format!("FRE ordered build-many value-only count refused execution: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "aggregate-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "aggregate-many-continuation-program",
    };
    Ok(FreReduction { actual, plan })
}

fn fre_aggregate_many_capture_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex: AggregateManyCaptureCountRegex = aggregate_many_builder_with_limits(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        limits,
    )
    .build_capture_count()
    .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(
        request,
        regex.build_report(),
        AggregateManyOperation::CaptureCount,
    )?;
    let selector = aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let operation_limits = AggregateManyCaptureRunLimits {
        selector,
        max_capture_events: limits.reducer_steps,
        max_capture_count: limits.reducer_steps,
    };
    let actual = regex
        .count_captures_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message =
                format!("FRE ordered build-many capture count refused execution: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "capture-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "capture-many-continuation-program",
    };
    Ok(FreReduction { actual, plan })
}

fn fre_aggregate_many_compile(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = aggregate_many_builder_with_limits(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        limits,
    )
    .build_compile()
    .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(
        request,
        regex.build_report(),
        AggregateManyOperation::Compile,
    )?;
    let operation_limits =
        aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let result = regex
        .verify_count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE ordered compile-many refused verification: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "compile-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "compile-many-continuation-program",
    };
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
}

fn fre_aggregate_many_span_sum(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = aggregate_many_builder_with_limits(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        limits,
    )
    .build_span_sum()
    .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(
        request,
        regex.build_report(),
        AggregateManyOperation::SpanSum,
    )?;
    let operation_limits =
        aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let actual = regex
        .span_sum_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message =
                format!("FRE ordered build-many value-only span-sum refused execution: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "aggregate-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "aggregate-many-continuation-program",
    };
    Ok(FreReduction { actual, plan })
}

enum TimedFreAggregate {
    Count {
        regex: AggregateCountRegex,
        limits: AggregateRunLimits,
    },
    SpanSum {
        regex: AggregateSpanSumRegex,
        limits: AggregateRunLimits,
    },
}

impl TimedFreAggregate {
    fn build(job: &Job, loaded: &LoadedJob, limits: &RunLimits) -> Result<Self, CompareError> {
        let pattern = loaded.patterns.as_slice();
        let [pattern] = pattern else {
            return Err(CompareError::new(format!(
                "{} exact-plan timing job does not have one pattern",
                job.id
            )));
        };
        let builder = || {
            AggregateBuilder::new(pattern)
                .profile(rebar_profile())
                .unicode(job.regex.unicode)
                .case_insensitive(job.regex.case_insensitive)
                .limits(aggregate_build_limits(limits))
                .plan_selection(AggregatePlanSelection::Auto)
                .strategy(AggregateStrategy::ReverseSequentialRows)
        };
        match job.model.as_str() {
            "count" => {
                let regex = builder().build_count().map_err(|error| {
                    CompareError::new(format!("{} FRE timing build: {error}", job.id))
                })?;
                if regex.build_report().plan != AggregatePlanKind::ExactLiteral {
                    return Err(CompareError::new(format!(
                        "{} no longer selects the exact-literal count plan",
                        job.id
                    )));
                }
                require_unicode_plan_identity(
                    regex.build_report(),
                    job.regex.unicode,
                    LiteralAggregateOperation::Count,
                )
                .map_err(|error| {
                    CompareError::new(format!(
                        "{} FRE timing semantic identity: {}",
                        job.id, error.message
                    ))
                })?;
                let operation_limits =
                    aggregate_run_limits(loaded.haystack.len(), regex.build_report(), limits)
                        .map_err(|error| {
                            CompareError::new(format!(
                                "{} FRE timing limit derivation: {}",
                                job.id, error.message
                            ))
                        })?;
                Ok(Self::Count {
                    regex,
                    limits: operation_limits,
                })
            }
            "count-spans" => {
                let regex = builder().build_span_sum().map_err(|error| {
                    CompareError::new(format!("{} FRE timing build: {error}", job.id))
                })?;
                if regex.build_report().plan != AggregatePlanKind::ExactLiteral {
                    return Err(CompareError::new(format!(
                        "{} no longer selects the exact-literal span-sum plan",
                        job.id
                    )));
                }
                require_unicode_plan_identity(
                    regex.build_report(),
                    job.regex.unicode,
                    LiteralAggregateOperation::SpanSum,
                )
                .map_err(|error| {
                    CompareError::new(format!(
                        "{} FRE timing semantic identity: {}",
                        job.id, error.message
                    ))
                })?;
                let operation_limits =
                    aggregate_run_limits(loaded.haystack.len(), regex.build_report(), limits)
                        .map_err(|error| {
                            CompareError::new(format!(
                                "{} FRE timing limit derivation: {}",
                                job.id, error.message
                            ))
                        })?;
                Ok(Self::SpanSum {
                    regex,
                    limits: operation_limits,
                })
            }
            model => Err(CompareError::new(format!(
                "{} exact-plan timing model {model} is not aggregate",
                job.id
            ))),
        }
    }

    fn execute(
        &self,
        haystack: &[u8],
        boundary: LiteralAggregateTimingBoundary,
    ) -> Result<u64, ExecutionError> {
        match self {
            Self::Count { regex, limits }
                if matches!(boundary, LiteralAggregateTimingBoundary::FullReport) =>
            {
                let result = regex.count(haystack, limits).map_err(|error| {
                    aggregate_attempt_error(
                        &error,
                        format!("FRE timed count refused execution: {error}"),
                    )
                })?;
                let value = result.value();
                // Make the complete public result/report observable. This is
                // intentionally inside the documented facade timing boundary.
                std::hint::black_box(&result);
                Ok(value)
            }
            Self::SpanSum { regex, limits }
                if matches!(boundary, LiteralAggregateTimingBoundary::FullReport) =>
            {
                let result = regex.span_sum(haystack, limits).map_err(|error| {
                    aggregate_attempt_error(
                        &error,
                        format!("FRE timed span-sum refused execution: {error}"),
                    )
                })?;
                let value = result.value();
                std::hint::black_box(&result);
                Ok(value)
            }
            Self::Count { regex, limits } => regex.count_value(haystack, limits).map_err(|error| {
                aggregate_attempt_error(
                    &error,
                    format!("FRE timed value-only count refused execution: {error}"),
                )
            }),
            Self::SpanSum { regex, limits } => {
                regex.span_sum_value(haystack, limits).map_err(|error| {
                    aggregate_attempt_error(
                        &error,
                        format!("FRE timed value-only span-sum refused execution: {error}"),
                    )
                })
            }
        }
    }
}

fn timed_rust_aggregate(
    job: &Job,
    regex: &Regex,
    haystack: &[u8],
    limits: &RunLimits,
) -> Result<u64, ExecutionError> {
    match job.model.as_str() {
        "count" => count_matches(regex, haystack, limits.reducer_steps),
        "count-spans" => count_spans(regex, haystack, limits.reducer_steps),
        model => Err(ExecutionError::fault(format!(
            "timed Rust aggregate does not implement {model}"
        ))),
    }
}

fn timed_operation_sample(
    iterations: usize,
    expected: u64,
    mut execute: impl FnMut() -> Result<u64, ExecutionError>,
) -> Result<u64, ExecutionError> {
    let start = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..iterations {
        let actual = std::hint::black_box(execute()?);
        if actual != expected {
            return Err(ExecutionError::fault(format!(
                "timed reducer returned {actual}, expected {expected}"
            )));
        }
        checksum = checksum.wrapping_add(actual);
    }
    std::hint::black_box(checksum);
    let total = start.elapsed().as_nanos();
    let iterations = u128::try_from(iterations)
        .map_err(|_| ExecutionError::fault("timing iteration count does not fit u128"))?;
    let per_iteration = total
        .checked_div(iterations)
        .ok_or_else(|| ExecutionError::fault("timing iteration count is zero"))?;
    u64::try_from(per_iteration.max(1))
        .map_err(|_| ExecutionError::fault("timed nanoseconds per iteration do not fit u64"))
}

fn median(values: &[u64]) -> u64 {
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    ordered[ordered.len() / 2]
}

#[allow(
    clippy::too_many_arguments,
    reason = "the timing row keeps authenticated job inputs and explicit sampling policy together"
)]
fn time_literal_aggregate_job(
    job: &Job,
    loaded: &LoadedJob,
    limits: &RunLimits,
    samples_per_engine: usize,
    target_bytes_per_sample: usize,
    max_iterations_per_sample: usize,
    boundary: LiteralAggregateTimingBoundary,
) -> Result<LiteralAggregateTimingJob, CompareError> {
    let fre = TimedFreAggregate::build(job, loaded, limits)?;
    let rust = rust_compile(job, &loaded.patterns).map_err(|error| {
        CompareError::new(format!("{} Rust timing build: {}", job.id, error.message))
    })?;
    let haystack = loaded.haystack.as_ref();
    let expected = job.expected.count;
    let fre_warm = fre.execute(haystack, boundary).map_err(|error| {
        CompareError::new(format!("{} FRE timing warmup: {}", job.id, error.message))
    })?;
    let rust_warm = timed_rust_aggregate(job, &rust, haystack, limits).map_err(|error| {
        CompareError::new(format!("{} Rust timing warmup: {}", job.id, error.message))
    })?;
    if fre_warm != expected || rust_warm != expected {
        return Err(CompareError::new(format!(
            "{} timing warmup differs: expected {expected}, FRE {fre_warm}, Rust {rust_warm}",
            job.id
        )));
    }

    let iterations = target_bytes_per_sample
        .div_ceil(haystack.len().max(1))
        .clamp(1, max_iterations_per_sample);
    let mut fre_samples = Vec::new();
    let mut rust_samples = Vec::new();
    fre_samples
        .try_reserve_exact(samples_per_engine)
        .map_err(|error| CompareError::new(format!("reserve FRE timing samples: {error}")))?;
    rust_samples
        .try_reserve_exact(samples_per_engine)
        .map_err(|error| CompareError::new(format!("reserve Rust timing samples: {error}")))?;

    for sample in 0..samples_per_engine {
        let time_fre = || {
            timed_operation_sample(iterations, expected, || fre.execute(haystack, boundary))
                .map_err(|error| {
                    CompareError::new(format!("{} FRE timing sample: {}", job.id, error.message))
                })
        };
        let time_rust = || {
            timed_operation_sample(iterations, expected, || {
                timed_rust_aggregate(job, &rust, haystack, limits)
            })
            .map_err(|error| {
                CompareError::new(format!("{} Rust timing sample: {}", job.id, error.message))
            })
        };
        if sample.is_multiple_of(2) {
            fre_samples.push(time_fre()?);
            rust_samples.push(time_rust()?);
        } else {
            rust_samples.push(time_rust()?);
            fre_samples.push(time_fre()?);
        }
    }
    let fre_median = median(&fre_samples);
    let rust_median = median(&rust_samples);
    let ratio_numerator = u128::from(rust_median)
        .checked_mul(1_000_000)
        .ok_or_else(|| CompareError::new("literal timing ratio overflow"))?;
    let ratio = ratio_numerator
        .checked_div(u128::from(fre_median))
        .ok_or_else(|| CompareError::new("literal timing FRE median is zero"))?;
    let ratio = u64::try_from(ratio)
        .map_err(|_| CompareError::new("literal timing ratio does not fit u64"))?;
    Ok(LiteralAggregateTimingJob {
        job_id: job.id.clone(),
        model: job.model.clone(),
        haystack_bytes: haystack.len(),
        expected,
        iterations_per_sample: iterations,
        fre_ns_per_iteration: fre_samples,
        rust_ns_per_iteration: rust_samples,
        fre_median_ns: fre_median,
        rust_median_ns: rust_median,
        rust_over_fre_millionths: ratio,
    })
}

fn fre_grep(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let pattern = one_fre_pattern(request)?;
    if request.case_insensitive {
        return Err(ExecutionError::unsupported(
            "current FRE facade has no case-insensitive builder option",
        ));
    }
    let regex = PortableBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .build()
        .map_err(|error| {
            ExecutionError::unsupported(format!("FRE build refused input: {error}"))
        })?;
    let search_limits = SearchLimits {
        max_work: limits.fre_search_work,
        max_scratch_bytes: limits.fre_scratch_bytes,
    };
    let mut session = regex
        .search_session(SearchSessionLimits {
            max_setup_work: limits.fre_search_work,
            max_scratch_bytes: limits.fre_scratch_bytes,
        })
        .map_err(|error| {
            ExecutionError::unsupported(format!("FRE search session refused: {error}"))
        })?;
    let mut count = 0u64;
    let mut events = 0u64;
    for line in request.haystack.lines() {
        charge(&mut events, 1, limits.reducer_steps, "FRE grep line events")?;
        let (matched, _) = session
            .is_match(line, search_limits)
            .map_err(|error| ExecutionError::unsupported(format!("FRE search refused: {error}")))?;
        if matched {
            count = count
                .checked_add(1)
                .ok_or_else(|| ExecutionError::fault("FRE grep reducer overflow"))?;
        }
    }
    Ok(FreReduction {
        actual: count,
        plan: "portable-single-search",
    })
}

fn candidate_reducer(
    adapter: &dyn CandidateAdapter,
    job: &Job,
    loaded: &LoadedJob,
    limits: &RunLimits,
) -> Result<AdapterReduction, ExecutionError> {
    let request = CandidateRequest {
        job_id: &job.id,
        model: &job.model,
        patterns: &loaded.patterns,
        haystack: &loaded.haystack,
        unicode: job.regex.unicode,
        case_insensitive: job.regex.case_insensitive,
    };
    match adapter.execute(request, limits) {
        CandidateOutcome::Executed(actual) => Ok(AdapterReduction::unplanned(actual)),
        CandidateOutcome::ExecutedWithPlan { actual, plan } => Ok(AdapterReduction {
            actual,
            plan: Some(plan),
        }),
        CandidateOutcome::Unsupported(reason) => Err(ExecutionError::unsupported(reason)),
        CandidateOutcome::Unresolved(reason) => Err(ExecutionError {
            status: Status::Unresolved,
            message: reason,
        }),
        CandidateOutcome::Fault(reason) => Err(ExecutionError::fault(reason)),
    }
}

fn regex_redux(job: &Job, haystack: &[u8], limits: &RunLimits) -> Result<u64, ExecutionError> {
    let text = std::str::from_utf8(haystack)
        .map_err(|error| ExecutionError::fault(format!("regex-redux haystack UTF-8: {error}")))?;
    let mut sequence = text.to_string();
    let input_length = sequence.len();
    let flatten = rust_compile_one(job, r">[^\n]*\n|\n")?;
    sequence = replace_all(&sequence, "", &flatten, limits.reducer_steps)?;
    let clean_length = sequence.len();
    let variants = [
        r"agggtaaa|tttaccct",
        r"[cgt]gggtaaa|tttaccc[acg]",
        r"a[act]ggtaaa|tttacc[agt]t",
        r"ag[act]gtaaa|tttac[agt]ct",
        r"agg[act]taaa|ttta[agt]cct",
        r"aggg[acg]aaa|ttt[cgt]ccct",
        r"agggt[cgt]aa|tt[acg]accct",
        r"agggta[cgt]a|t[acg]taccct",
        r"agggtaa[cgt]|[acg]ttaccct",
    ];
    let mut report = String::new();
    for variant in variants {
        let regex = rust_compile_one(job, variant)?;
        let count = count_matches(&regex, sequence.as_bytes(), limits.reducer_steps)?;
        writeln!(&mut report, "{variant} {count}")
            .map_err(|error| ExecutionError::fault(format!("format regex-redux: {error}")))?;
    }
    let substitutions = [
        (r"tHa[Nt]", "<4>"),
        (r"aND|caN|Ha[DS]|WaS", "<3>"),
        (r"a[NSt]|BY", "<2>"),
        (r"<[^>]*>", "|"),
        (r"\|[^|][^|]*\|", "-"),
    ];
    for (pattern, replacement) in substitutions {
        let regex = rust_compile_one(job, pattern)?;
        sequence = replace_all(&sequence, replacement, &regex, limits.reducer_steps)?;
    }
    writeln!(
        &mut report,
        "\n{input_length}\n{clean_length}\n{}",
        sequence.len()
    )
    .map_err(|error| ExecutionError::fault(format!("format regex-redux: {error}")))?;
    let expected_report = "agggtaaa|tttaccct 6\n[cgt]gggtaaa|tttaccc[acg] 26\na[act]ggtaaa|tttacc[agt]t 86\nag[act]gtaaa|tttac[agt]ct 58\nagg[act]taaa|ttta[agt]cct 113\naggg[acg]aaa|ttt[cgt]ccct 31\nagggt[cgt]aa|tt[acg]accct 31\nagggta[cgt]a|t[acg]taccct 32\nagggtaa[cgt]|[acg]ttaccct 43\n\n1016745\n1000000\n547899\n";
    if report != expected_report {
        return Err(ExecutionError::fault(
            "regex-redux complete canonical report differs",
        ));
    }
    u64::try_from(sequence.len())
        .map_err(|_| ExecutionError::fault("regex-redux length does not fit u64"))
}

fn rust_compile_one(job: &Job, pattern: &str) -> Result<Regex, ExecutionError> {
    rust_compile(job, &[pattern.to_string()])
}

fn replace_all(
    text: &str,
    replacement: &str,
    regex: &Regex,
    limit: u64,
) -> Result<String, ExecutionError> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    let mut events = 0u64;
    loop {
        let Some(matched) = regex.find(rest.as_bytes()) else {
            break;
        };
        charge(&mut events, 1, limit, "regex-redux replacement events")?;
        if matched.end() == 0 {
            return Err(ExecutionError::fault("regex-redux matched empty text"));
        }
        output.push_str(&rest[..matched.start()]);
        output.push_str(replacement);
        rest = &rest[matched.end()..];
    }
    output.push_str(rest);
    Ok(output)
}

fn validate_manifest(
    manifest: &Manifest,
    checkout: &Path,
    limits: &RunLimits,
) -> Result<(), CompareError> {
    if manifest.schema != rebar_expand::SCHEMA {
        return Err(CompareError::new(format!(
            "unsupported manifest schema {}",
            manifest.schema
        )));
    }
    if manifest.source.revision != AUDITED_REBAR_REVISION {
        return Err(CompareError::new(format!(
            "unsupported Rebar revision {}",
            manifest.source.revision
        )));
    }
    if !manifest.source.tracked_worktree_clean {
        return Err(CompareError::new(
            "expanded manifest was not generated from a clean tracked worktree",
        ));
    }
    if manifest.jobs.len() > limits.jobs || manifest.jobs.len() != manifest.scope.job_count {
        return Err(CompareError::new(
            "manifest job count is inconsistent or over limit",
        ));
    }
    let head = command_stdout(
        Command::new("git")
            .arg("-C")
            .arg(checkout)
            .args(["rev-parse", "HEAD"]),
    )?;
    if head.trim() != manifest.source.revision {
        return Err(CompareError::new(format!(
            "checkout revision {} differs from manifest {}",
            head.trim(),
            manifest.source.revision
        )));
    }
    let tracked_status = command_stdout(Command::new("git").arg("-C").arg(checkout).args([
        "status",
        "--short",
        "--untracked-files=no",
    ]))?;
    if !tracked_status.trim().is_empty() {
        return Err(CompareError::new(
            "pinned Rebar checkout has tracked modifications",
        ));
    }
    let mut required = BTreeMap::<&str, (&str, usize)>::new();
    for job in &manifest.jobs {
        if !matches!(job.engine.as_str(), "rust/regex" | "re2") {
            return Err(CompareError::new(format!(
                "unexpected target engine {}",
                job.engine
            )));
        }
        if !matches!(
            job.model.as_str(),
            "compile"
                | "count"
                | "count-spans"
                | "count-captures"
                | "grep"
                | "grep-captures"
                | "regex-redux"
        ) {
            return Err(CompareError::new(format!("unexpected model {}", job.model)));
        }
        for source in &job.required_files {
            match required.insert(&source.path, (&source.sha256, source.bytes)) {
                Some(previous) if previous != (&source.sha256, source.bytes) => {
                    return Err(CompareError::new(format!(
                        "conflicting source identity for {}",
                        source.path
                    )));
                }
                _ => {}
            }
        }
    }
    for adapter in &manifest.adapters {
        for source in &adapter.evidence {
            required.insert(&source.path, (&source.sha256, source.bytes));
        }
    }
    for (relative, (digest, length)) in required {
        let path = safe_join(checkout, relative)?;
        let bytes = read_limited(&path, limits.haystack_bytes)?;
        verify_bytes(&bytes, length, digest, "required source")?;
    }
    validate_rust_adapter_identity(manifest)
}

fn validate_rust_adapter_identity(manifest: &Manifest) -> Result<(), CompareError> {
    let adapter = manifest
        .adapters
        .iter()
        .find(|adapter| adapter.engine == "rust/regex")
        .ok_or_else(|| CompareError::new("manifest lacks Rust regex adapter"))?;
    let regex_config = "regex = { version = \"=1.12.4\", default-features = true (implicit because key is omitted), features = [\"logging\", \"perf-dfa-full\"] }";
    let automata_config = "regex-automata = \"=0.4.14\"";
    if !adapter
        .dependency_configuration
        .iter()
        .any(|line| line == regex_config)
        || !adapter
            .dependency_configuration
            .iter()
            .any(|line| line == automata_config)
    {
        return Err(CompareError::new(
            "manifest Rust adapter dependency configuration differs",
        ));
    }
    Ok(())
}

fn adapter_identities(
    manifest: &Manifest,
    rust_runner: Option<&Path>,
    re2_runner: Option<&Path>,
    candidate: Option<&dyn CandidateAdapter>,
) -> Result<Vec<AdapterIdentity>, CompareError> {
    let (rust_availability, rust_digest) = if let Some(path) = rust_runner {
        let version = command_stdout(Command::new(path).arg("--version"))?;
        if version.trim() != RUST_REGEX_VERSION {
            return Err(CompareError::new(format!(
                "Rebar Rust runner version {} is not {RUST_REGEX_VERSION}",
                version.trim()
            )));
        }
        (
            "in-process exact dependency configuration; pinned upstream KLV runner version verified"
                .to_string(),
            Some(file_sha256(path)?),
        )
    } else {
        (
            "in-process exact dependency configuration; upstream KLV runtime not supplied"
                .to_string(),
            None,
        )
    };
    let re2 = manifest
        .adapters
        .iter()
        .find(|adapter| adapter.engine == "re2")
        .ok_or_else(|| CompareError::new("manifest lacks RE2 adapter"))?;
    let (re2_availability, re2_digest) = if let Some(path) = re2_runner {
        let version = command_stdout(Command::new(path).arg("--version"))?;
        if version.trim() != RE2_VERSION {
            return Err(CompareError::new(format!(
                "Rebar RE2 runner version {} is not {RE2_VERSION}",
                version.trim()
            )));
        }
        (
            "exact pinned Rebar runtime supplied; every RE2 job executes through KLV".to_string(),
            Some(file_sha256(path)?),
        )
    } else {
        (
            "unresolved: exact Rebar RE2 runtime not supplied".to_string(),
            None,
        )
    };
    let mut identities = Vec::new();
    if let Some(candidate) = candidate {
        if matches!(candidate.adapter(), RUST_ADAPTER | RE2_ADAPTER) {
            return Err(CompareError::new(
                "candidate adapter ID collides with a reference adapter",
            ));
        }
        let identity = candidate.identity();
        if identity.adapter != candidate.adapter() {
            return Err(CompareError::new(
                "candidate identity and receipt adapter IDs differ",
            ));
        }
        identities.push(identity);
    }
    identities.extend([
        AdapterIdentity {
            adapter: RE2_ADAPTER.to_string(),
            identity: format!(
                "re2={RE2_VERSION}; re2_revision=972a15cedd008d846f1a39b2e88ce48d7f166cbd; abseil=20250814.1@d38452e1ee03523a208362186fd42248ff2609f6; pinned Rebar adapter with {} evidence files",
                re2.evidence.len()
            ),
            availability: re2_availability,
            runtime_sha256: re2_digest,
        },
        AdapterIdentity {
            adapter: RUST_ADAPTER.to_string(),
            identity: rebar_profile().identity_string(),
            availability: rust_availability,
            runtime_sha256: rust_digest,
        },
    ]);
    identities.sort_by(|left, right| left.adapter.cmp(&right.adapter));
    Ok(identities)
}

fn coverage(receipts: &[Receipt]) -> Result<Coverage, CompareError> {
    let mut result = Coverage::default();
    for receipt in receipts {
        increment_nested(
            &mut result.by_adapter_status,
            &receipt.adapter,
            receipt.status,
        )?;
        increment_nested(&mut result.by_model_status, &receipt.model, receipt.status)?;
        result.total = result
            .total
            .checked_add(1)
            .ok_or_else(|| CompareError::new("coverage total overflow"))?;
    }
    Ok(result)
}

fn increment_nested(
    map: &mut BTreeMap<String, BTreeMap<Status, usize>>,
    outer: &str,
    status: Status,
) -> Result<(), CompareError> {
    let value = map
        .entry(outer.to_string())
        .or_default()
        .entry(status)
        .or_default();
    *value = value
        .checked_add(1)
        .ok_or_else(|| CompareError::new("coverage count overflow"))?;
    Ok(())
}

const DIFFERENTIAL_JOBS: [&str; 9] = [
    "test/model/compile@rust/regex",
    "test/model/count@rust/regex",
    "test/model/count-spans@rust/regex",
    "test/model/count-captures@rust/regex",
    "test/model/grep@rust/regex",
    "test/model/grep-captures@rust/regex",
    "imported/regex-redux/regex-redux@rust/regex",
    "opt/reverse-suffix/unsound-leftmost-first@rust/regex",
    "opt/reverse-suffix/unsound-start-literal-order-mismatch@rust/regex",
];

fn run_klv_differentials(
    manifest: &Manifest,
    loader: &mut Loader<'_>,
    runner: &Path,
    limits: &RunLimits,
    receipts: &[Receipt],
) -> Result<Vec<KlvDifferential>, CompareError> {
    let version = command_stdout(Command::new(runner).arg("--version"))?;
    if version.trim() != RUST_REGEX_VERSION {
        return Err(CompareError::new("upstream KLV runner version mismatch"));
    }
    let mut output = Vec::new();
    for id in DIFFERENTIAL_JOBS {
        let job = manifest
            .jobs
            .iter()
            .find(|job| job.id == id)
            .ok_or_else(|| CompareError::new(format!("missing differential job {id}")))?;
        let loaded_job = loader.load(job)?;
        let local = receipts
            .iter()
            .find(|receipt| receipt.job_id == id && receipt.adapter == RUST_ADAPTER)
            .and_then(|receipt| receipt.actual);
        let upstream = run_upstream_klv(runner, job, &loaded_job)?;
        let (status, reason) = if local == Some(upstream) {
            (Status::Pass, None)
        } else {
            (
                Status::Fail,
                Some(format!(
                    "local reducer {local:?} differs from upstream {upstream}"
                )),
            )
        };
        if upstream > limits.reducer_steps && job.model != "count-spans" {
            return Err(CompareError::new(
                "upstream differential exceeds reducer limit",
            ));
        }
        output.push(KlvDifferential {
            job_id: id.to_string(),
            model: job.model.clone(),
            local,
            upstream: Some(upstream),
            status,
            reason,
        });
    }
    Ok(output)
}

fn run_upstream_klv(runner: &Path, job: &Job, loaded: &LoadedJob) -> Result<u64, CompareError> {
    let klv = encode_klv(job, loaded)?;
    let mut child = Command::new(runner)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CompareError::new(format!("spawn upstream KLV runner: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| CompareError::new("upstream KLV stdin unavailable"))?
        .write_all(&klv)
        .map_err(|error| CompareError::new(format!("write upstream KLV: {error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| CompareError::new(format!("wait for upstream KLV: {error}")))?;
    if !output.status.success() {
        return Err(CompareError::new(format!(
            "upstream KLV failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| CompareError::new(format!("upstream stdout UTF-8: {error}")))?;
    let first = stdout
        .lines()
        .next()
        .ok_or_else(|| CompareError::new("upstream KLV produced no sample"))?;
    let (_, count) = first
        .split_once(',')
        .ok_or_else(|| CompareError::new("upstream sample lacks comma"))?;
    count
        .parse::<u64>()
        .map_err(|error| CompareError::new(format!("parse upstream reducer: {error}")))
}

fn encode_klv(job: &Job, loaded: &LoadedJob) -> Result<Vec<u8>, CompareError> {
    let mut output = Vec::new();
    klv_field(&mut output, "name", job.benchmark.as_bytes())?;
    klv_field(&mut output, "model", job.model.as_bytes())?;
    klv_field(
        &mut output,
        "case-insensitive",
        job.regex.case_insensitive.to_string().as_bytes(),
    )?;
    klv_field(
        &mut output,
        "unicode",
        job.regex.unicode.to_string().as_bytes(),
    )?;
    klv_field(&mut output, "max-iters", b"1")?;
    klv_field(&mut output, "max-warmup-iters", b"0")?;
    klv_field(&mut output, "max-time", b"3000000000")?;
    klv_field(&mut output, "max-warmup-time", b"0")?;
    for pattern in &loaded.patterns {
        klv_field(&mut output, "pattern", pattern.as_bytes())?;
    }
    klv_field(&mut output, "haystack", &loaded.haystack)?;
    Ok(output)
}

fn klv_field(output: &mut Vec<u8>, key: &str, value: &[u8]) -> Result<(), CompareError> {
    write!(output, "{key}:{}:", value.len())
        .map_err(|error| CompareError::new(format!("format KLV: {error}")))?;
    output
        .write_all(value)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|error| CompareError::new(format!("write KLV: {error}")))
}

fn reconstruct_patterns(
    checkout: &Path,
    bench: &toml::Value,
    expanded: &ExpandedRegex,
    limit: usize,
) -> Result<Vec<String>, CompareError> {
    let table = bench
        .as_table()
        .ok_or_else(|| CompareError::new("bench entry is not a table"))?;
    let regex = table
        .get("regex")
        .ok_or_else(|| CompareError::new("definition regex is missing"))?;
    let mut patterns;
    let mut file_source = false;
    match regex {
        toml::Value::String(pattern) => patterns = vec![pattern.clone()],
        toml::Value::Array(values) => patterns = string_array(values, "inline regex")?,
        toml::Value::Table(regex_table) => {
            if let Some(path) = regex_table.get("path").and_then(toml::Value::as_str) {
                let source = safe_join(&checkout.join("benchmarks/regexes"), path)?;
                let bytes = read_limited(&source, limit)?;
                verify_bytes(
                    &bytes,
                    expanded.source.bytes,
                    &expanded.source.sha256,
                    "raw regex source",
                )?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|error| CompareError::new(format!("regex source UTF-8: {error}")))?;
                patterns = match expanded.transforms.per_line.as_str() {
                    "none" => vec![text.trim().to_string()],
                    "alternate" | "pattern" => text.lines().map(str::to_string).collect(),
                    other => {
                        return Err(CompareError::new(format!(
                            "unknown per-line transform {other}"
                        )));
                    }
                };
                file_source = true;
            } else if let Some(value) = regex_table.get("patterns") {
                patterns = match value {
                    toml::Value::String(pattern) => vec![pattern.clone()],
                    toml::Value::Array(values) => string_array(values, "regex patterns")?,
                    _ => return Err(CompareError::new("regex patterns has invalid shape")),
                };
            } else {
                return Err(CompareError::new("regex table lacks path or patterns"));
            }
        }
        _ => return Err(CompareError::new("definition regex has invalid shape")),
    }
    if !file_source {
        let encoded = encode_pattern_sequence(&patterns)?;
        verify_bytes(
            &encoded,
            expanded.source.bytes,
            &expanded.source.sha256,
            "raw inline pattern sequence",
        )?;
    }
    for pattern in &mut patterns {
        if expanded.transforms.literal {
            *pattern = regex_lite::escape(pattern);
        }
        if let Some(prefix) = &expanded.transforms.prepend {
            pattern.insert_str(0, prefix);
        }
        if let Some(suffix) = &expanded.transforms.append {
            pattern.push_str(suffix);
        }
        if pattern.len() > limit {
            return Err(CompareError::new("transformed pattern exceeds limit"));
        }
    }
    if file_source && expanded.transforms.per_line == "alternate" {
        for pattern in &mut patterns {
            *pattern = format!("(?:{pattern})");
        }
        patterns = vec![patterns.join("|")];
    }
    Ok(patterns)
}

fn encode_pattern_sequence(patterns: &[String]) -> Result<Vec<u8>, CompareError> {
    let mut output = Vec::new();
    for pattern in patterns {
        let length = u64::try_from(pattern.len())
            .map_err(|_| CompareError::new("pattern length does not fit u64"))?;
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(pattern.as_bytes());
    }
    Ok(output)
}

fn string_array(values: &[toml::Value], what: &str) -> Result<Vec<String>, CompareError> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| CompareError::new(format!("{what} contains a non-string")))
        })
        .collect()
}

fn inline_haystack(bench: &toml::Value) -> Result<Vec<u8>, CompareError> {
    let haystack = bench
        .get("haystack")
        .ok_or_else(|| CompareError::new("definition haystack is missing"))?;
    match haystack {
        toml::Value::String(contents) => Ok(contents.as_bytes().to_vec()),
        toml::Value::Table(table) => table
            .get("contents")
            .and_then(toml::Value::as_str)
            .map(|contents| contents.as_bytes().to_vec())
            .ok_or_else(|| CompareError::new("inline haystack table lacks contents")),
        _ => Err(CompareError::new("definition haystack has invalid shape")),
    }
}

fn transform_haystack(
    raw: &[u8],
    options: &HaystackTransforms,
    limit: usize,
) -> Result<Vec<u8>, CompareError> {
    let mut bytes = if options.utf8_lossy {
        String::from_utf8_lossy(raw).into_owned().into_bytes()
    } else {
        raw.to_vec()
    };
    check_length(bytes.len(), limit, "lossy haystack")?;
    if options.trim {
        bytes = bytes.trim_with(char::is_whitespace).to_vec();
    }
    bytes = match (options.line_start, options.line_end) {
        (None, None) => bytes,
        (Some(start), None) => bstr::concat(bytes.lines_with_terminator().skip(start)),
        (None, Some(end)) => bstr::concat(bytes.lines_with_terminator().take(end)),
        (Some(start), Some(end)) => {
            bstr::concat(bytes.lines_with_terminator().take(end).skip(start))
        }
    };
    if let Some(repeat) = options.repeat {
        let length = bytes
            .len()
            .checked_mul(repeat)
            .ok_or_else(|| CompareError::new("haystack repeat overflow"))?;
        check_length(length, limit, "repeated haystack")?;
        bytes = bytes.repeat(repeat);
    }
    let prefix = options.prepend.as_deref().unwrap_or("").as_bytes();
    let suffix = options.append.as_deref().unwrap_or("").as_bytes();
    let final_length = bytes
        .len()
        .checked_add(prefix.len())
        .and_then(|length| length.checked_add(suffix.len()))
        .ok_or_else(|| CompareError::new("haystack affix overflow"))?;
    check_length(final_length, limit, "affixed haystack")?;
    if !prefix.is_empty() {
        bytes.splice(0..0, prefix.iter().copied());
    }
    bytes.extend_from_slice(suffix);
    Ok(bytes)
}

fn definition_count(
    table: &toml::map::Map<String, toml::Value>,
    engine: &str,
) -> Result<(u64, String), CompareError> {
    let value = table
        .get("count")
        .ok_or_else(|| CompareError::new("definition count is missing"))?;
    if let Some(count) = value.as_integer() {
        let count =
            u64::try_from(count).map_err(|_| CompareError::new("definition count is negative"))?;
        return Ok((count, "scalar-for-all-engines".to_string()));
    }
    let entries = value
        .as_array()
        .ok_or_else(|| CompareError::new("definition count has invalid shape"))?;
    for entry in entries {
        let entry = entry
            .as_table()
            .ok_or_else(|| CompareError::new("count entry is not a table"))?;
        let expression = entry
            .get("engine")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CompareError::new("count entry lacks engine"))?;
        let anchored = format!("^(?:{expression})$");
        let regex = regex_lite::Regex::new(&anchored)
            .map_err(|error| CompareError::new(format!("count engine regex: {error}")))?;
        if regex.is_match(engine) {
            let count = entry
                .get("count")
                .and_then(toml::Value::as_integer)
                .ok_or_else(|| CompareError::new("count entry lacks integer count"))?;
            let count =
                u64::try_from(count).map_err(|_| CompareError::new("count entry is negative"))?;
            return Ok((count, format!("first-matching-engine-regex:{expression}")));
        }
    }
    Err(CompareError::new(format!(
        "no expected count rule matches {engine}"
    )))
}

fn definition_group(relative: &str) -> Result<String, CompareError> {
    let path = Path::new(relative);
    let prefix = Path::new("benchmarks/definitions");
    let stripped = path
        .strip_prefix(prefix)
        .map_err(|_| CompareError::new("definition path is outside definitions"))?;
    let mut group = stripped.to_path_buf();
    group.set_extension("");
    group
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or_else(|| CompareError::new("definition group is not UTF-8"))
}

fn compare_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    expected: &str,
) -> Result<(), CompareError> {
    let actual = table
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| CompareError::new(format!("definition {key} is missing")))?;
    if actual != expected {
        return Err(CompareError::new(format!(
            "definition {key} {actual} differs from {expected}"
        )));
    }
    Ok(())
}

fn verify_sidecar_hash(manifest: &Path, actual: &str) -> Result<(), CompareError> {
    let path = manifest.with_extension("sha256");
    let expected = fs::read_to_string(&path)
        .map_err(|error| CompareError::new(format!("read {}: {error}", path.display())))?;
    let digest = expected
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| CompareError::new("manifest hash sidecar is empty"))?;
    if digest != actual {
        return Err(CompareError::new(format!(
            "manifest hash {actual} differs from sidecar {digest}"
        )));
    }
    Ok(())
}

fn verify_bytes(
    bytes: &[u8],
    expected_length: usize,
    expected_hash: &str,
    what: &str,
) -> Result<(), CompareError> {
    if bytes.len() != expected_length {
        return Err(CompareError::new(format!(
            "{what} length {} differs from {expected_length}",
            bytes.len()
        )));
    }
    let actual = sha256(bytes);
    if actual != expected_hash {
        return Err(CompareError::new(format!(
            "{what} SHA-256 {actual} differs from {expected_hash}"
        )));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, CompareError> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CompareError::new(format!(
            "unsafe relative path {}",
            relative.display()
        )));
    }
    Ok(root.join(relative))
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, CompareError> {
    let metadata = fs::metadata(path)
        .map_err(|error| CompareError::new(format!("stat {}: {error}", path.display())))?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| CompareError::new(format!("{} is too large", path.display())))?;
    check_length(length, limit, &path.display().to_string())?;
    fs::read(path).map_err(|error| CompareError::new(format!("read {}: {error}", path.display())))
}

fn file_sha256(path: &Path) -> Result<String, CompareError> {
    let bytes = read_limited(path, 512 * 1_048_576)?;
    Ok(sha256(&bytes))
}

fn check_length(length: usize, limit: usize, what: &str) -> Result<(), CompareError> {
    if length > limit {
        return Err(CompareError::new(format!(
            "{what} length {length} exceeds {limit}"
        )));
    }
    Ok(())
}

fn command_stdout(command: &mut Command) -> Result<String, CompareError> {
    let output = command
        .output()
        .map_err(|error| CompareError::new(format!("run command: {error}")))?;
    if !output.status.success() {
        return Err(CompareError::new(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| CompareError::new(format!("command stdout is not UTF-8: {error}")))
}

/// Serialize a report as stable compact JSON followed by one newline.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn report_bytes(report: &Report) -> Result<Vec<u8>, CompareError> {
    let mut bytes = serde_json::to_vec(report)
        .map_err(|error| CompareError::new(format!("serialize report: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre::AggregateResource;

    #[test]
    fn current_fre_regex_redux_composite_semantics_and_inventory() {
        let limits = RunLimits::default();
        let result = run_fre_composite(
            b">header\r\n\nagggtaaatHaN",
            &REGEX_REDUX_STAGES,
            &limits,
            composite_limits(&limits).expect("composite limits"),
        )
        .expect("synthetic regex-redux program");
        assert_eq!(result.input_length, 22);
        assert_eq!(result.clean_length, 12);
        assert_eq!(result.counts[0], 1);
        assert_eq!(result.final_bytes, b"agggtaaa|");
        assert_eq!(result.accounting.stages, 15);
        assert_eq!(result.accounting.pattern_bytes, 283);
        assert_eq!(result.accounting.replacement_bytes, 11);
        assert_eq!(result.report.len(), result.accounting.report_bytes);
        assert!(result.accounting.build_work > 0);
        assert!(result.accounting.execution_work > 0);
    }

    #[test]
    fn current_fre_regex_redux_stage_order_is_semantic() {
        let limits = RunLimits::default();
        let caps = composite_limits(&limits).expect("composite limits");
        let ordered = run_fre_composite(b"tHaN", &REGEX_REDUX_STAGES, &limits, caps)
            .expect("ordered program");
        assert_eq!(ordered.final_bytes, b"|");

        let mut reversed = REGEX_REDUX_STAGES;
        reversed.swap(10, 13);
        let reordered =
            run_fre_composite(b"tHaN", &reversed, &limits, caps).expect("reordered program");
        assert_eq!(reordered.final_bytes, b"tH<2>");
    }

    #[test]
    fn current_fre_regex_redux_report_is_bound_to_the_executed_stage_program() {
        let run_limits = RunLimits::default();
        let limits = composite_limits(&run_limits).expect("composite limits");

        let mut changed_pattern = REGEX_REDUX_STAGES;
        changed_pattern[1] = CompositeStage::Count {
            pattern: "a|b",
            output: 0,
        };
        let changed = run_fre_composite(b"aaa", &changed_pattern, &run_limits, limits)
            .expect("changed count label program");
        assert!(changed.report.starts_with("a|b 3\n"), "{}", changed.report);
        assert!(!changed.report.starts_with("agggtaaa|tttaccct"));

        let changed_identity =
            CompositeProgram::authenticate(&changed_pattern).expect("changed program identity");
        let changed_prospective = composite_prospective(3, &changed_identity, &run_limits)
            .expect("changed report preflight");
        let canonical_identity = CompositeProgram::authenticate(&REGEX_REDUX_STAGES)
            .expect("canonical program identity");
        let canonical_prospective = composite_prospective(3, &canonical_identity, &run_limits)
            .expect("canonical report preflight");
        assert_ne!(
            changed_prospective.report_bytes,
            canonical_prospective.report_bytes
        );
        let exact_report = CompositeLimits {
            report_bytes: changed_prospective.report_bytes,
            ..limits
        };
        run_fre_composite(b"aaa", &changed_pattern, &run_limits, exact_report)
            .expect("changed report at exact preflight bound");
        let error = run_fre_composite(
            b"aaa",
            &changed_pattern,
            &run_limits,
            CompositeLimits {
                report_bytes: changed_prospective
                    .report_bytes
                    .checked_sub(1)
                    .expect("report bound"),
                ..limits
            },
        )
        .expect_err("one below changed report preflight");
        assert_eq!(error.status, Status::Unsupported);

        let mut swapped_slots = REGEX_REDUX_STAGES;
        swapped_slots[1] = CompositeStage::Count {
            pattern: REGEX_REDUX_VARIANTS[0],
            output: 1,
        };
        swapped_slots[2] = CompositeStage::Count {
            pattern: REGEX_REDUX_VARIANTS[1],
            output: 0,
        };
        let swapped = run_fre_composite(b"agggtaaa", &swapped_slots, &run_limits, limits)
            .expect("swapped count slots");
        let mut lines = swapped.report.lines();
        assert_eq!(lines.next(), Some("[cgt]gggtaaa|tttaccc[acg] 0"));
        assert_eq!(lines.next(), Some("agggtaaa|tttaccct 1"));
    }

    #[test]
    fn current_fre_regex_redux_rejects_malformed_stage_programs_before_input_work() {
        let run_limits = RunLimits::default();
        let limits = composite_limits(&run_limits).expect("composite limits");
        let mut duplicate = REGEX_REDUX_STAGES;
        duplicate[2] = CompositeStage::Count {
            pattern: REGEX_REDUX_VARIANTS[1],
            output: 0,
        };
        let mut out_of_range = REGEX_REDUX_STAGES;
        out_of_range[1] = CompositeStage::Count {
            pattern: REGEX_REDUX_VARIANTS[0],
            output: REGEX_REDUX_COUNT_SLOTS,
        };
        let mut missing = REGEX_REDUX_STAGES;
        missing[1] = REGEX_REDUX_STAGES[10];
        for stages in [&duplicate[..], &out_of_range[..], &missing[..]] {
            let error = run_fre_composite(b"\xff", stages, &run_limits, limits)
                .expect_err("malformed stage program");
            assert_eq!(error.status, Status::Fault);
            assert!(
                error.message.contains("count output") || error.message.contains("stage program"),
                "{}",
                error.message
            );
            assert!(!error.message.contains("UTF-8"));
        }
    }

    #[test]
    fn current_fre_regex_redux_metadata_limits_are_exact() {
        let limits = RunLimits::default();
        let default_caps = composite_limits(&limits).expect("composite limits");
        let input = b">h\n\nagggtaaa";
        let exact = CompositeLimits {
            stages: 15,
            pattern_bytes: 283,
            replacement_bytes: 11,
            input_bytes: input.len(),
            ..default_caps
        };
        run_fre_composite(input, &REGEX_REDUX_STAGES, &limits, exact)
            .expect("exact metadata limits");

        for one_below in [
            CompositeLimits {
                stages: 14,
                ..exact
            },
            CompositeLimits {
                pattern_bytes: 282,
                ..exact
            },
            CompositeLimits {
                replacement_bytes: 10,
                ..exact
            },
            CompositeLimits {
                input_bytes: input.len() - 1,
                ..exact
            },
        ] {
            let error = run_fre_composite(input, &REGEX_REDUX_STAGES, &limits, one_below)
                .expect_err("one-below metadata limit");
            assert_eq!(error.status, Status::Unsupported);
        }
    }

    #[test]
    fn current_fre_regex_redux_dispatch_ignores_job_id_but_binds_model_shape() {
        let limits = RunLimits::default();
        let patterns = Vec::new();
        let request = |job_id| CandidateRequest {
            job_id,
            model: "regex-redux",
            patterns: &patterns,
            haystack: b"tHaN",
            unicode: false,
            case_insensitive: false,
        };
        let first = fre_regex_redux(request("unrelated/a"), &limits).expect("first synthetic ID");
        let second = fre_regex_redux(request("unrelated/b"), &limits).expect("second synthetic ID");
        assert_eq!(first.actual, second.actual);
        assert_eq!(first.actual, 1);

        let external = vec!["a".to_string()];
        let error = fre_regex_redux(
            CandidateRequest {
                job_id: "unrelated/c",
                model: "regex-redux",
                patterns: &external,
                haystack: b"tHaN",
                unicode: false,
                case_insensitive: false,
            },
            &limits,
        )
        .expect_err("external patterns are not model input");
        assert_eq!(error.status, Status::Unsupported);
    }

    #[test]
    fn current_fre_regex_redux_invalid_utf8_fails_before_publication() {
        let limits = RunLimits::default();
        let error = run_fre_composite(
            b"\xff",
            &REGEX_REDUX_STAGES,
            &limits,
            composite_limits(&limits).expect("composite limits"),
        )
        .expect_err("invalid UTF-8");
        assert_eq!(error.status, Status::Fault);
        assert!(error.message.contains("UTF-8"));
    }

    #[test]
    fn current_fre_regex_redux_declared_minima_are_pinned_nonnullable_hir() {
        for stage in REGEX_REDUX_STAGES {
            let CompositeStage::ReplaceAllLiteral {
                pattern,
                minimum_match_bytes,
                ..
            } = stage
            else {
                continue;
            };
            let mut builder = regex_syntax::ParserBuilder::new();
            builder.unicode(false).utf8(false);
            let hir = builder
                .build()
                .parse(pattern)
                .expect("pinned replacement HIR");
            assert_eq!(hir.properties().minimum_len(), Some(minimum_match_bytes));
            assert!(minimum_match_bytes > 0);
        }

        let run_limits = RunLimits::default();
        let canonical_program =
            CompositeProgram::authenticate(&REGEX_REDUX_STAGES).expect("canonical program");
        let canonical_envelope = composite_prospective(3, &canonical_program, &run_limits)
            .expect("canonical declaration-independent envelope");

        let mut changed_declaration = REGEX_REDUX_STAGES;
        changed_declaration[10] = CompositeStage::ReplaceAllLiteral {
            pattern: r"tHa[Nt]",
            replacement: b"<4>",
            minimum_match_bytes: 1,
            records_clean_length: false,
        };
        let changed_program = CompositeProgram::authenticate(&changed_declaration)
            .expect("changed-declaration program shape");
        assert_eq!(
            composite_prospective(3, &changed_program, &run_limits)
                .expect("changed declaration-independent envelope"),
            canonical_envelope,
            "a caller-declared minimum influenced the whole-program envelope"
        );
    }

    #[test]
    fn current_fre_regex_redux_nullable_replacement_cannot_influence_the_envelope() {
        let run_limits = RunLimits::default();
        let canonical_program =
            CompositeProgram::authenticate(&REGEX_REDUX_STAGES).expect("canonical program");
        let canonical_envelope = composite_prospective(3, &canonical_program, &run_limits)
            .expect("canonical declaration-independent envelope");
        let mut nullable = REGEX_REDUX_STAGES;
        nullable[0] = CompositeStage::ReplaceAllLiteral {
            pattern: "a*",
            replacement: b"",
            minimum_match_bytes: 1,
            records_clean_length: true,
        };
        let nullable_program =
            CompositeProgram::authenticate(&nullable).expect("nullable program shape");
        let nullable_envelope = composite_prospective(3, &nullable_program, &run_limits)
            .expect("nullable-safe whole-program envelope");
        assert_eq!(
            nullable_envelope.sequence_bytes,
            canonical_envelope.sequence_bytes
        );
        assert_eq!(
            nullable_envelope.replacement_output_bytes,
            canonical_envelope.replacement_output_bytes
        );
        assert_eq!(
            nullable_envelope.match_events,
            canonical_envelope.match_events
        );
        assert_eq!(
            nullable_envelope.span_visits,
            canonical_envelope.span_visits
        );
        assert_eq!(
            nullable_envelope.copied_bytes,
            canonical_envelope.copied_bytes
        );
        assert_eq!(
            nullable_envelope.allocation_bytes,
            canonical_envelope.allocation_bytes
        );
        let error = run_fre_composite(
            b"aaa",
            &nullable,
            &run_limits,
            composite_limits(&run_limits).expect("composite limits"),
        )
        .expect_err("false nonzero nullable replacement declaration");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error.message.contains("authenticated nonzero HIR minimum"),
            "{}",
            error.message
        );
    }

    #[test]
    fn current_fre_regex_redux_rejects_wrong_minimum_and_nullable_count_before_limits() {
        let run_limits = RunLimits::default();
        let canonical_program =
            CompositeProgram::authenticate(&REGEX_REDUX_STAGES).expect("canonical program");
        let canonical_envelope = composite_prospective(3, &canonical_program, &run_limits)
            .expect("canonical declaration-independent envelope");
        let mut wrong_nonzero = REGEX_REDUX_STAGES;
        wrong_nonzero[10] = CompositeStage::ReplaceAllLiteral {
            pattern: r"tHa[Nt]",
            replacement: b"x",
            minimum_match_bytes: 3,
            records_clean_length: false,
        };
        let error = run_fre_composite(
            b"tHaN",
            &wrong_nonzero,
            &run_limits,
            composite_limits(&run_limits).expect("composite limits"),
        )
        .expect_err("wrong nonzero replacement minimum");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error.message.contains("authenticated nonzero HIR minimum"),
            "{}",
            error.message
        );

        let mut nullable_count = REGEX_REDUX_STAGES;
        nullable_count[1] = CompositeStage::Count {
            pattern: "a*",
            output: 0,
        };
        let nullable_count_program =
            CompositeProgram::authenticate(&nullable_count).expect("nullable count program shape");
        let nullable_count_envelope =
            composite_prospective(3, &nullable_count_program, &run_limits)
                .expect("nullable-safe count envelope");
        assert_eq!(
            nullable_count_envelope.match_events, canonical_envelope.match_events,
            "count HIR nullability influenced the N-plus-one envelope"
        );
        let error = run_fre_composite(
            b"aaa",
            &nullable_count,
            &run_limits,
            composite_limits(&run_limits).expect("composite limits"),
        )
        .expect_err("nullable count stage");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error.message.contains("authenticated nonzero HIR minimum"),
            "{}",
            error.message
        );
    }

    #[test]
    fn current_fre_regex_redux_count_preflight_uses_n_plus_one_boundaries() {
        assert_eq!(composite_count_match_events(0).expect("empty boundary"), 1);
        assert_eq!(composite_count_match_events(3).expect("four boundaries"), 4);

        let run_limits = RunLimits::default();
        let program =
            CompositeProgram::authenticate(&REGEX_REDUX_STAGES).expect("stage program identity");
        let prospective =
            composite_prospective(0, &program, &run_limits).expect("empty prospective ledger");
        let count_events = REGEX_REDUX_COUNT_SLOTS
            .checked_mul(composite_count_match_events(0).expect("empty count boundary"))
            .expect("count-event contribution");
        assert_eq!(count_events, 9);
        // Replacement stages add their own declaration-independent N+1
        // envelope; the count contribution remains exactly nine.
        assert_eq!(prospective.match_events, 223);
        let error = enforce_composite_prospective(
            0,
            &program,
            prospective,
            CompositeLimits {
                match_events: u64::try_from(
                    prospective
                        .match_events
                        .checked_sub(1)
                        .expect("positive match-event envelope"),
                )
                .expect("match-event envelope fits u64"),
                ..composite_limits(&run_limits).expect("composite limits")
            },
        )
        .expect_err("one below the empty-input N-plus-one program envelope");
        assert_eq!(error.status, Status::Unsupported);
        assert!(error.message.contains("match events"));
    }

    #[test]
    fn current_fre_regex_redux_replacement_limits_never_widen_the_component() {
        let build = AggregateBuilder::new(r"tHa[Nt]")
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .plan_selection(AggregatePlanSelection::Auto)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .expect("replacement selector build");
        let minimum = build
            .minimum_match_bytes()
            .expect("authenticated nonzero minimum");
        assert_eq!(minimum, 4);

        for (bytes, matches) in [(3_usize, 0_usize), (4, 1), (8, 2)] {
            let component = composite_replacement_component_limits(
                bytes,
                build.build_report(),
                minimum,
                &RunLimits::default(),
            )
            .expect("authenticated component limits");
            let wrapped = composite_replacement_run_limits(
                bytes,
                build.build_report(),
                minimum,
                &RunLimits::default(),
            )
            .expect("composite wrapper limits");
            assert_eq!(wrapped, component, "wrapper widened a field at N={bytes}");
            assert_eq!(wrapped.continuation.max_output_matches, matches);
            assert_eq!(
                wrapped.continuation.max_output_bytes,
                matches * core::mem::size_of::<fre::AggregateSpan>()
            );
        }

        let low_quotas = RunLimits {
            reducer_steps: 0,
            fre_aggregate_random_access_bytes: 3,
            fre_aggregate_scratch_bytes: 2,
            fre_aggregate_log_bytes: 1,
            fre_aggregate_sequential_bytes: 5,
            fre_aggregate_peak_bytes: 1,
            fre_aggregate_operation_work: 7,
            ..RunLimits::default()
        };
        let component =
            composite_replacement_component_limits(4, build.build_report(), minimum, &low_quotas)
                .expect("low-quota component limits");
        let wrapped =
            composite_replacement_run_limits(4, build.build_report(), minimum, &low_quotas)
                .expect("low-quota wrapper limits");
        assert_eq!(wrapped, component);
        assert_eq!(wrapped.continuation.max_output_matches, 0);
        assert!(wrapped.continuation.max_random_access_bytes <= 3);
        assert!(wrapped.continuation.max_scratch_bytes <= 2);
        assert!(wrapped.continuation.max_log_bytes <= 1);
        assert!(wrapped.continuation.max_sequential_bytes <= 5);
        assert!(wrapped.continuation.max_peak_bytes <= 1);
        assert!(wrapped.continuation.max_work <= 7);
    }

    #[test]
    fn current_fre_regex_redux_doubling_overflow_is_typed_and_fail_closed() {
        let error = composite_limits(&RunLimits {
            reducer_steps: u64::MAX,
            ..RunLimits::default()
        })
        .expect_err("reducer-step doubling overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(error.message.contains("reducer step doubling overflow"));

        let error = composite_replacement_span_visits(usize::MAX)
            .expect_err("replacement span-visit doubling overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(error.message.contains("replacement span visits overflow"));

        let error = composite_continuation_match_events(usize::MAX / 2)
            .expect_err("continuation boundary doubling overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("continuation match-event ceiling overflow")
        );

        let error = composite_continuation_match_events(usize::MAX)
            .expect_err("continuation N-plus-one boundary overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(error.message.contains("span boundaries overflow"));

        let error = composite_replacement_match_events(usize::MAX)
            .expect_err("replacement N-plus-one boundary overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("replacement match boundaries overflow")
        );

        let error = composite_count_match_events(usize::MAX)
            .expect_err("count N-plus-one boundary overflow");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("count match-event boundaries overflow")
        );
    }

    #[test]
    fn current_fre_regex_redux_counts_match_pinned_rust_independently() {
        let limits = RunLimits::default();
        let input = b"xxagggtaaayytttaccctagggtaaa";
        let result = run_fre_composite(
            input,
            &REGEX_REDUX_STAGES,
            &limits,
            composite_limits(&limits).expect("composite limits"),
        )
        .expect("generated DNA composite");
        for (index, pattern) in REGEX_REDUX_VARIANTS.iter().enumerate() {
            let reference = rust_compile_options(&[(*pattern).to_string()], false, false)
                .expect("pinned Rust variant");
            let expected =
                count_matches(&reference, input, u64::MAX).expect("pinned Rust variant count");
            assert_eq!(result.counts[index], expected, "{pattern}");
        }
    }

    #[test]
    fn current_fre_regex_redux_preserves_gaps_adjacency_and_literal_bytes() {
        let limits = RunLimits::default();
        let caps = composite_limits(&limits).expect("composite limits");
        let adjacent = run_fre_composite(
            b"prefix tHaNtHaN suffix",
            &REGEX_REDUX_STAGES,
            &limits,
            caps,
        )
        .expect("adjacent replacements");
        assert_eq!(adjacent.final_bytes, b"prefix || suffix");

        let mut literal = REGEX_REDUX_STAGES;
        literal[10] = CompositeStage::ReplaceAllLiteral {
            pattern: r"tHa[Nt]",
            replacement: b"$x",
            minimum_match_bytes: 4,
            records_clean_length: false,
        };
        let literal_result =
            run_fre_composite(b"tHaN", &literal, &limits, caps).expect("literal dollar bytes");
        assert_eq!(literal_result.final_bytes, b"$x");
    }

    fn exact_regex_redux_limits(input: &[u8], run_limits: &RunLimits) -> CompositeLimits {
        let program =
            CompositeProgram::authenticate(&REGEX_REDUX_STAGES).expect("stage program identity");
        let prospective = composite_prospective(input.len(), &program, run_limits)
            .expect("prospective composite accounting");
        let mut exact = composite_limits(run_limits).expect("composite limits");
        exact.stages = REGEX_REDUX_STAGES.len();
        exact.pattern_bytes = prospective.pattern_bytes;
        exact.replacement_bytes = prospective.replacement_bytes;
        exact.input_bytes = input.len();
        exact.intermediate_bytes = prospective.sequence_bytes;
        exact.initial_requested_bytes = input.len();
        exact.replacement_requested_bytes = prospective.replacement_output_bytes;
        exact.build_work = prospective.declared_build_work;
        exact.execution_work = prospective.declared_execution_work;
        exact.match_events =
            composite_u64(prospective.match_events, "test events").expect("events");
        exact.span_visits = composite_u64(prospective.span_visits, "test spans").expect("spans");
        exact.copied_bytes =
            composite_u64(prospective.copied_bytes, "test copied").expect("copied");
        exact.allocation_bytes =
            composite_u64(prospective.allocation_bytes, "test allocation").expect("allocation");
        exact.prospective_owned_peak_bytes = prospective.owned_peak_bytes;
        exact.report_bytes = prospective.report_bytes;
        assert_eq!(exact.pattern_bytes, 283);
        assert_eq!(exact.replacement_bytes, 11);
        exact
    }

    fn regex_redux_prospective_one_below(exact: CompositeLimits) -> [CompositeLimits; 9] {
        [
            CompositeLimits {
                build_work: exact.build_work.checked_sub(1).expect("build work"),
                ..exact
            },
            CompositeLimits {
                execution_work: exact.execution_work.checked_sub(1).expect("execution work"),
                ..exact
            },
            CompositeLimits {
                match_events: exact.match_events.checked_sub(1).expect("events"),
                ..exact
            },
            CompositeLimits {
                span_visits: exact.span_visits.checked_sub(1).expect("span visits"),
                ..exact
            },
            CompositeLimits {
                copied_bytes: exact.copied_bytes.checked_sub(1).expect("copied bytes"),
                ..exact
            },
            CompositeLimits {
                allocation_bytes: exact
                    .allocation_bytes
                    .checked_sub(1)
                    .expect("allocation bytes"),
                ..exact
            },
            CompositeLimits {
                intermediate_bytes: exact
                    .intermediate_bytes
                    .checked_sub(1)
                    .expect("intermediate bytes"),
                ..exact
            },
            CompositeLimits {
                prospective_owned_peak_bytes: exact
                    .prospective_owned_peak_bytes
                    .checked_sub(1)
                    .expect("prospective owned peak bytes"),
                ..exact
            },
            CompositeLimits {
                report_bytes: exact.report_bytes.checked_sub(1).expect("report bytes"),
                ..exact
            },
        ]
    }

    fn assert_regex_redux_component_build_peak(
        report: &AggregateBuildReport,
        current_sequence_capacity: usize,
        run_limits: &RunLimits,
    ) {
        let independent_peak = match report.build {
            AggregateBuildAccounting::FiniteLiteral(build) => {
                assert_eq!(
                    build.persistent_bytes.checked_add(build.scratch_bytes),
                    Some(build.peak_bytes)
                );
                build.peak_bytes
            }
            AggregateBuildAccounting::PackedFiniteLiteral(build) => {
                assert!(build.build_peak_upper_bound >= build.persistent_bytes);
                build.build_peak_upper_bound
            }
            AggregateBuildAccounting::SparseFiniteLiteral(build) => {
                assert!(build.peak_bytes >= build.persistent_bytes);
                assert!(build.peak_bytes >= build.scratch_bytes);
                build.peak_bytes
            }
            AggregateBuildAccounting::Continuation(build) => {
                assert!(build.construction_peak_bytes > build.program_bytes);
                build.construction_peak_bytes
            }
            other => panic!("unexpected regex-redux component build: {other:?}"),
        };
        assert_eq!(
            composite_component_build_peak(report).expect("authenticated component build peak"),
            independent_peak
        );
        let exact_peak = current_sequence_capacity
            .checked_add(independent_peak)
            .expect("component plus live sequence peak");
        let mut exact_limits = composite_limits(run_limits).expect("composite limits");
        exact_limits.owned_peak_bytes = exact_peak;
        let mut exact_accounting = CompositeAccounting {
            current_sequence_capacity_bytes: current_sequence_capacity,
            ..CompositeAccounting::default()
        };
        charge_composite_build(&mut exact_accounting, report, exact_limits)
            .expect("independently derived exact component build peak");
        assert_eq!(exact_accounting.owned_peak_bytes, exact_peak);

        let mut one_below = exact_limits;
        one_below.owned_peak_bytes = exact_peak.checked_sub(1).expect("one-below peak");
        let mut refused_accounting = CompositeAccounting {
            current_sequence_capacity_bytes: current_sequence_capacity,
            ..CompositeAccounting::default()
        };
        let refusal = charge_composite_build(&mut refused_accounting, report, one_below)
            .expect_err("one below independent component build peak");
        assert_eq!(refusal.status, Status::Unsupported);
        assert!(refusal.message.contains("owned peak bytes"));
    }

    fn assert_regex_redux_all_component_build_peaks(run_limits: &RunLimits) {
        let build_limits = aggregate_build_limits(run_limits);
        let dense = AggregateBuilder::new(REGEX_REDUX_VARIANTS[0])
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(build_limits)
            .plan_selection(AggregatePlanSelection::Auto)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .expect("dense regex-redux count component");
        assert_regex_redux_component_build_peak(dense.build_report(), 17, run_limits);

        let mut sparse_pattern = String::from("(?:");
        for index in 0..32 {
            if index != 0 {
                sparse_pattern.push('|');
            }
            write!(&mut sparse_pattern, "p{index:03}").expect("write sparse arm");
        }
        sparse_pattern.push(')');
        let mut sparse_limits = build_limits;
        sparse_limits.finite_literal.max_dfa_cells = 32 * 4;
        let sparse = AggregateBuilder::new(sparse_pattern)
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(sparse_limits)
            .plan_selection(AggregatePlanSelection::Auto)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .expect("sparse regex-redux count control");
        assert!(matches!(
            sparse.build_report().build,
            AggregateBuildAccounting::SparseFiniteLiteral(_)
        ));
        assert_regex_redux_component_build_peak(sparse.build_report(), 23, run_limits);

        let replacement = AggregateBuilder::new(r">[^\n]*\n|\n")
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(build_limits)
            .plan_selection(AggregatePlanSelection::Auto)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .expect("continuation regex-redux replacement component");
        assert_regex_redux_component_build_peak(replacement.build_report(), 29, run_limits);
    }

    #[test]
    fn current_fre_regex_redux_composite_resource_limits_are_exact() {
        let run_limits = RunLimits::default();
        let input = b"tHaN";
        assert_regex_redux_all_component_build_peaks(&run_limits);

        let exact = exact_regex_redux_limits(input, &run_limits);
        let probe = run_fre_composite(input, &REGEX_REDUX_STAGES, &run_limits, exact)
            .expect("all exact prospective composite limits");
        for limited in regex_redux_prospective_one_below(exact) {
            let error = run_fre_composite(input, &REGEX_REDUX_STAGES, &run_limits, limited)
                .expect_err("one below a prospective composite limit");
            assert_eq!(error.status, Status::Unsupported);
        }
        let error = run_fre_composite(
            input,
            &REGEX_REDUX_STAGES,
            &run_limits,
            CompositeLimits {
                initial_requested_bytes: exact
                    .initial_requested_bytes
                    .checked_sub(1)
                    .expect("initial requested bytes"),
                ..exact
            },
        )
        .expect_err("one below initial requested bytes");
        assert_eq!(error.status, Status::Unsupported);
        assert!(error.message.contains("initial requested bytes"));
        for index in 0..REGEX_REDUX_REPLACEMENT_STAGES {
            let mut limited = exact;
            limited.replacement_requested_bytes[index] = limited.replacement_requested_bytes[index]
                .checked_sub(1)
                .expect("replacement requested bytes");
            let error = run_fre_composite(input, &REGEX_REDUX_STAGES, &run_limits, limited)
                .expect_err("one below replacement requested bytes");
            assert_eq!(error.status, Status::Unsupported);
            assert!(error.message.contains("replacement requested bytes"));
        }

        let mut observed_exact = exact;
        observed_exact.initial_capacity_bytes = probe.accounting.initial_capacity_bytes;
        observed_exact.replacement_capacity_bytes = probe.accounting.replacement_capacity_bytes;
        observed_exact.report_capacity_bytes = probe.accounting.report_capacity_bytes;
        observed_exact.capacity_bytes = probe.accounting.capacity_bytes;
        observed_exact.owned_peak_bytes = probe.accounting.owned_peak_bytes;
        let exact_result =
            run_fre_composite(input, &REGEX_REDUX_STAGES, &run_limits, observed_exact)
                .expect("observed capacities at exact limits");
        assert_eq!(exact_result.accounting, probe.accounting);

        let mut observed_one_below = Vec::new();
        observed_one_below.push((
            CompositeLimits {
                initial_capacity_bytes: observed_exact
                    .initial_capacity_bytes
                    .checked_sub(1)
                    .expect("initial capacity"),
                ..observed_exact
            },
            "initial capacity bytes",
        ));
        for index in 0..REGEX_REDUX_REPLACEMENT_STAGES {
            let mut limited = observed_exact;
            limited.replacement_capacity_bytes[index] = limited.replacement_capacity_bytes[index]
                .checked_sub(1)
                .expect("replacement capacity");
            observed_one_below.push((limited, "replacement capacity"));
        }
        observed_one_below.push((
            CompositeLimits {
                report_capacity_bytes: observed_exact
                    .report_capacity_bytes
                    .checked_sub(1)
                    .expect("report capacity"),
                ..observed_exact
            },
            "report capacity bytes",
        ));
        observed_one_below.push((
            CompositeLimits {
                capacity_bytes: observed_exact
                    .capacity_bytes
                    .checked_sub(1)
                    .expect("cumulative capacity"),
                ..observed_exact
            },
            "observed capacity bytes",
        ));
        observed_one_below.push((
            CompositeLimits {
                owned_peak_bytes: observed_exact
                    .owned_peak_bytes
                    .checked_sub(1)
                    .expect("owned peak"),
                ..observed_exact
            },
            "owned peak bytes",
        ));
        for (limited, dimension) in observed_one_below {
            let error = run_fre_composite(input, &REGEX_REDUX_STAGES, &run_limits, limited)
                .expect_err("one below an observed capacity limit");
            assert_eq!(error.status, Status::Unsupported);
            assert!(error.message.contains(dimension), "{}", error.message);
        }
    }

    #[test]
    fn current_fre_regex_redux_authenticated_hard_canary() {
        const HAYSTACK: &[u8] = b">header\r\n\nagggtaaatHaN";
        assert_eq!(HAYSTACK.len(), 22);
        assert_eq!(
            sha256(HAYSTACK),
            "115675a932c8c9c8d29abafd60eb9d35aacfdf5f8bafe42e08b903785fc213bc"
        );
        CompositeProgram::authenticate(&REGEX_REDUX_STAGES)
            .expect("authenticated regex-redux stage program");
        let limits = RunLimits::default();
        let result = run_fre_composite(
            HAYSTACK,
            &REGEX_REDUX_STAGES,
            &limits,
            composite_limits(&limits).expect("composite limits"),
        )
        .expect("bounded authenticated regex-redux hard canary");
        assert_eq!(result.counts, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(result.input_length, 22);
        assert_eq!(result.clean_length, 12);
        assert_eq!(result.final_bytes, b"agggtaaa|");
        assert_eq!(result.report.len(), 253);
        assert_eq!(
            sha256(result.report.as_bytes()),
            "da311207a189c0805481e5a7b3c09a79a369a124807a59f968ef1fd447f823cc"
        );
        assert_eq!(
            result.report,
            "agggtaaa|tttaccct 1\n[cgt]gggtaaa|tttaccc[acg] 0\na[act]ggtaaa|tttacc[agt]t 0\nag[act]gtaaa|tttac[agt]ct 0\nagg[act]taaa|ttta[agt]cct 0\naggg[acg]aaa|ttt[cgt]ccct 0\nagggt[cgt]aa|tt[acg]accct 0\nagggta[cgt]a|t[acg]taccct 0\nagggtaa[cgt]|[acg]ttaccct 0\n\n22\n12\n9\n"
        );
    }

    const PROGRAM_STATE_SENTINEL_MANIFEST_SHA256: &str =
        "09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43";

    #[derive(Clone, Copy)]
    enum ProgramStateSentinelDisposition {
        Pass { plan: &'static str },
        ExecutionWorkUnsupported,
    }

    #[derive(Clone, Copy)]
    struct ProgramStateSentinelExpectation {
        id: &'static str,
        model: &'static str,
        expected: u64,
        case_insensitive: bool,
        disposition: ProgramStateSentinelDisposition,
    }

    const PROGRAM_STATE_SENTINEL_EXPECTATIONS: [ProgramStateSentinelExpectation; 9] = [
        ProgramStateSentinelExpectation {
            id: "curated/03-date/compile-unicode@rust/regex",
            model: "compile",
            expected: 5,
            case_insensitive: true,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "compile-aggregate-continuation-program",
            },
        },
        ProgramStateSentinelExpectation {
            id: "curated/03-date/unicode@rust/regex",
            model: "count-spans",
            expected: 111_841,
            case_insensitive: true,
            disposition: ProgramStateSentinelDisposition::ExecutionWorkUnsupported,
        },
        ProgramStateSentinelExpectation {
            id: "curated/08-words/long-russian@rust/regex",
            model: "count-spans",
            expected: 5_481,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "aggregate-continuation-program",
            },
        },
        ProgramStateSentinelExpectation {
            id: "dictionary/compile/english-10@rust/regex",
            model: "compile",
            expected: 1,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "compile-aggregate-finite-literal-sparse",
            },
        },
        ProgramStateSentinelExpectation {
            id: "dictionary/search/english-10@rust/regex",
            model: "count-spans",
            expected: 690,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "aggregate-finite-literal-sparse",
            },
        },
        ProgramStateSentinelExpectation {
            id: "hyperscan/fixed-length-words-unicode-nosom@rust/regex",
            model: "count",
            expected: 120,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::ExecutionWorkUnsupported,
        },
        ProgramStateSentinelExpectation {
            id: "unicode/compile/huge-character-class@rust/regex",
            model: "compile",
            expected: 1,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "compile-aggregate-continuation-program",
            },
        },
        ProgramStateSentinelExpectation {
            id: "unicode/word/boundary-long-russian@rust/regex",
            model: "count-spans",
            expected: 21_332,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::ExecutionWorkUnsupported,
        },
        ProgramStateSentinelExpectation {
            id: "wild/bibleref/compile@rust/regex",
            model: "compile",
            expected: 3,
            case_insensitive: false,
            disposition: ProgramStateSentinelDisposition::Pass {
                plan: "compile-aggregate-continuation-program",
            },
        },
    ];

    fn program_state_sentinel_expectation(id: &str) -> Option<ProgramStateSentinelExpectation> {
        PROGRAM_STATE_SENTINEL_EXPECTATIONS
            .iter()
            .copied()
            .find(|expectation| expectation.id == id)
    }

    fn assert_program_state_sentinel_receipt(
        receipt: &Receipt,
        expectation: ProgramStateSentinelExpectation,
    ) {
        assert_eq!(receipt.job_id, expectation.id);
        assert_eq!(receipt.model, expectation.model);
        assert_eq!(receipt.expected, expectation.expected);
        assert!(receipt.input.unicode);
        assert_eq!(receipt.input.case_insensitive, expectation.case_insensitive);
        match expectation.disposition {
            ProgramStateSentinelDisposition::Pass { plan } => {
                assert_eq!(receipt.status, Status::Pass, "{}", receipt.job_id);
                assert_eq!(
                    receipt.actual,
                    Some(expectation.expected),
                    "{}",
                    receipt.job_id
                );
                assert_eq!(
                    receipt.candidate_plan.as_deref(),
                    Some(plan),
                    "{}",
                    receipt.job_id
                );
                assert_eq!(receipt.reason, None, "{}", receipt.job_id);
            }
            ProgramStateSentinelDisposition::ExecutionWorkUnsupported => {
                assert_eq!(receipt.status, Status::Unsupported, "{}", receipt.job_id);
                assert_eq!(receipt.actual, None, "{}", receipt.job_id);
                assert_eq!(receipt.candidate_plan, None, "{}", receipt.job_id);
                let reason = receipt
                    .reason
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} has no refusal reason", receipt.job_id));
                assert!(
                    reason.contains("aggregate resource ExecutionWork requires")
                        && reason.contains("limit is 536870912"),
                    "{} returned the wrong refusal: {reason}",
                    receipt.job_id
                );
                assert!(
                    !reason.contains("ProgramStates"),
                    "{}: {reason}",
                    receipt.job_id
                );
            }
        }
    }

    fn fn_predicate_direct_receipt(
        haystack: &[u8],
        limits: &RunLimits,
    ) -> fre::LineCaptureRunReport {
        let plan = LineCaptureBuilder::new(ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN)
            .profile(rebar_profile())
            .unicode(false)
            .build()
            .expect("exact allocation-free separated-fields plan");
        let reducer_limit = usize::try_from(limits.reducer_steps).expect("reducer limit usize");
        let report = plan
            .grep_capture_count(
                haystack,
                LineCaptureRunLimits {
                    max_work: limits.fre_aggregate_operation_work,
                    max_sequential_bytes: limits.fre_aggregate_sequential_bytes,
                    max_capture_count: reducer_limit,
                    max_reducer_events: reducer_limit,
                },
            )
            .expect("direct fn-predicate resource receipt");
        assert_eq!(haystack.len(), 7_384_531);
        assert_eq!(report.work, 88_614_373);
        assert_eq!(report.actual_work, 81_447_534);
        assert_eq!(report.actual_input_loads, haystack.len());
        assert_eq!(report.prospective_matches, 369_226);
        assert_eq!(report.prospective_capture_count, 1_476_904);
        assert_eq!(report.prospective_reducer_events, 8_861_435);
        assert_eq!((report.lines, report.matches), (239_963, 229));
        assert_eq!(
            (report.capture_count, report.reducer_events),
            (916, 240_879)
        );
        assert_eq!((report.scratch_bytes, report.output_bytes), (0, 0));
        report
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_program_state_frontier_nine_row_sentinel() {
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode exact expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let candidate = CurrentFreAdapter;
        let mut remaining: BTreeSet<&str> = PROGRAM_STATE_SENTINEL_EXPECTATIONS
            .iter()
            .map(|expectation| expectation.id)
            .collect();
        assert_eq!(remaining.len(), PROGRAM_STATE_SENTINEL_EXPECTATIONS.len());
        let mut receipts = Vec::with_capacity(PROGRAM_STATE_SENTINEL_EXPECTATIONS.len());
        for job in &manifest.jobs {
            let Some(expectation) = program_state_sentinel_expectation(&job.id) else {
                continue;
            };
            assert!(
                remaining.remove(job.id.as_str()),
                "duplicate sentinel job {}",
                job.id
            );
            assert_eq!(job.engine, "rust/regex", "{}", job.id);
            assert_eq!(job.model, expectation.model, "{}", job.id);
            assert_eq!(job.expected.count, expectation.expected, "{}", job.id);
            assert!(job.regex.unicode, "{}", job.id);
            assert_eq!(
                job.regex.case_insensitive, expectation.case_insensitive,
                "{}",
                job.id
            );
            let input = loader.load(job);
            let receipt = execute_receipt(job, candidate.adapter(), &input, &limits, |loaded| {
                candidate_reducer(&candidate, job, loaded, &limits)
            });
            assert_program_state_sentinel_receipt(&receipt, expectation);
            receipts.push(receipt);
        }
        assert!(remaining.is_empty(), "missing sentinel jobs: {remaining:?}");
        assert_eq!(receipts.len(), PROGRAM_STATE_SENTINEL_EXPECTATIONS.len());
        receipts.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        let actual_ids: Vec<&str> = receipts
            .iter()
            .map(|receipt| receipt.job_id.as_str())
            .collect();
        let mut expected_ids: Vec<&str> = PROGRAM_STATE_SENTINEL_EXPECTATIONS
            .iter()
            .map(|expectation| expectation.id)
            .collect();
        expected_ids.sort_unstable();
        assert_eq!(
            actual_ids, expected_ids,
            "sentinel selected an inexact row set"
        );
        let receipt_bytes = serde_json::to_vec(&receipts).expect("serialize sentinel receipts");
        println!(
            "program-state-nine-row-sentinel manifest_sha256={manifest_hash} receipts_sha256={} rows={}",
            sha256(&receipt_bytes),
            receipts.len()
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_parol_veryl_ordered_root_capture_many_real_row_canary() {
        const JOB_ID: &str = "wild/parol-veryl/unicode@rust/regex";
        const PATTERN_SHA256: &str =
            "67e843247dab802f1b298e8ecb7180581ee8ec71b9d13aaac57d5817f649adfe";
        const HAYSTACK_SHA256: &str =
            "adf5fcdfb6071e5470b77a45b33826ccf6a0cb8709e5157697d5a9838a4e0b81";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact Parol/Veryl hard row");
        assert!(matching.next().is_none(), "duplicate Parol/Veryl row");
        assert_eq!(job.model, "count-captures");
        assert!(job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 124_800);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated Parol/Veryl row");
        assert_eq!(input.patterns.len(), 1);
        assert_eq!(input.patterns[0].len(), 1_509);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 150_600);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let regex = capture_regex_one(&input.patterns[0], true, false, &limits)
            .expect("build authenticated Parol/Veryl capture plan");
        assert_eq!(
            regex.build_report().plan_identity.plan,
            CapturePlanKind::OrderedRootCaptureManyCount
        );
        let proof = regex
            .build_report()
            .ordered_root_capture_many
            .expect("authenticated ordered-root proof");
        assert_eq!(proof.root_arms, 88);
        assert_eq!(proof.root_arms, regex.build_report().engine.captures);
        assert_eq!(proof.participating_captures, 1);
        assert_eq!(proof.groups_per_match, 2);
        let run_limits = capture_count_run_limits(&regex, input.haystack.len(), &limits)
            .expect("derive authenticated capture limits");
        let report = regex
            .count_captures(&input.haystack, run_limits)
            .expect("authenticated ordered-root Count");
        assert!(report.has_closed_count_attempt());
        assert_eq!(report.accounting.count, 124_800);
        assert_eq!(
            report.accounting.count,
            usize::try_from(job.expected.count).expect("expected count fits usize")
        );

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE ordered-root capture-many result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some(CURRENT_FRE_CAPTURE_ORDERED_ROOT_COUNT_PLAN)
        );
        println!(
            "parol-veryl-ordered-root-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} arms={} plan={}",
            candidate.actual,
            proof.root_arms,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_rust_functions_direct_capture_real_row_canary() {
        const JOB_ID: &str = "opt/prefilter/rust-functions@rust/regex";
        const PATTERN_SHA256: &str =
            "7b4393482afc22bece95e43688b5ecceb1e2ec5cd62369cc27cea25dc5f4461b";
        const HAYSTACK_SHA256: &str =
            "7d43cc8dfd053b083b809bd7ce7d4a074f2fd24a6b7ec38908b3966f3324fa36";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact Rust-functions row");
        assert!(matching.next().is_none(), "duplicate Rust-functions row");
        assert_eq!(job.model, "count-captures");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 948);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated Rust-functions row");
        assert_eq!(input.patterns, [r"fn is_(\w+)|fn as_(\w+)".to_string()]);
        assert_eq!(input.patterns[0].len(), 23);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 7_384_531);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let regex = capture_regex_one(&input.patterns[0], false, false, &limits)
            .expect("build authenticated Rust-functions capture plan");
        assert_eq!(
            regex.build_report().plan_identity.plan,
            CapturePlanKind::UniformPrefixClassParticipation
        );
        assert!(
            regex
                .build_report()
                .plan_identity
                .prefix_class_participation
                .is_some()
        );
        let run_limits = capture_count_run_limits(&regex, input.haystack.len(), &limits)
            .expect("derive authenticated direct-capture limits");
        let retained = regex
            .retained_prefix_class_participation_prospective(input.haystack.len())
            .expect("derive retained direct-capture envelope")
            .expect("direct Rust-functions owner");
        assert_eq!(
            run_limits
                .prefix_class_participation
                .max_greedy_extension_reads,
            retained.greedy_extension_reads
        );
        let report = regex
            .count_captures(&input.haystack, run_limits)
            .expect("authenticated direct capture Count");
        assert!(report.has_closed_count_attempt());
        assert!(report.selector_receipt.is_none());
        assert!(report.prefix_class_participation.is_some());
        assert!(report.prefix_class_participation_receipt.is_some());
        assert!(authenticates_direct_capture_success(
            &regex,
            input.haystack.len(),
            &run_limits,
            &report
        ));
        assert_eq!(report.accounting.count, 948);
        assert_eq!(
            report.accounting.count,
            usize::try_from(job.expected.count).expect("expected count fits usize")
        );

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE direct Rust-functions result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some(CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN)
        );
        println!(
            "rust-functions-direct-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} plan={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_quotes_bounded_terminal_class_real_row_canary() {
        const JOB_ID: &str = "imported/leipzig/quotes-bounded@rust/regex";
        const PATTERN_SHA256: &str =
            "68764d7810d256b15dbb4ee7a6a7d7d282bce027da056b4c77a04ae9f9f05c78";
        const HAYSTACK_SHA256: &str =
            "f2aa28234e7a8212c9e009fa9c67d1960d2d063d076765de46b0faed5fe44ad8";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact quotes-bounded hard row");
        assert!(matching.next().is_none(), "duplicate quotes-bounded row");
        assert_eq!(job.model, "count");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 8_886);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated quotes-bounded row");
        assert_eq!(input.patterns.len(), 1);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 16_013_977);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE bounded terminal-class result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some("aggregate-blocking-delimiter-v1")
        );
        println!(
            "quotes-bounded-terminal-class-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} plan={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_token_phrase_real_rows_canary() {
        const CASES: [(&str, &str, u64, usize, &str); 5] = [
            (
                "unicode/word/around-holmes-english@rust/regex",
                "0704ded7fbd59d6eb343f82f9551b310ae8d33aa5592ba806b2725ac4f1bb9ad",
                27,
                613_357,
                "07ff024bdc05f6c2b4bc0b5b768a332a18a616261fcbd16b41e953df1c7fa7ff",
            ),
            (
                "imported/sherlock/before-after-holmes@rust/regex",
                "b529539ea7718c8fdfd31b0505e3722f2284c5cd2cbb04384c267a1b0fefecb0",
                2_593,
                594_933,
                "242ec73a70f0a03dcbe007e32038e7deeaee004aaec9a09a07fa322743440fa8",
            ),
            (
                "imported/rsc/reallyreallyreallyhard0-1k@rust/regex",
                "b529539ea7718c8fdfd31b0505e3722f2284c5cd2cbb04384c267a1b0fefecb0",
                20,
                1_043,
                "3db73c34587a8f69d2e1d4f05df40fc31563e13c5009e765cc56fd7b6f36c828",
            ),
            (
                "imported/rsc/reallyreallyreallyhard0-32k@rust/regex",
                "b529539ea7718c8fdfd31b0505e3722f2284c5cd2cbb04384c267a1b0fefecb0",
                20,
                32_787,
                "c93a7679bd93a0ee51df77d8e2ede03f73b22a699abff777b00dbd6537147baa",
            ),
            (
                "imported/rsc/reallyreallyreallyhard0-1mb@rust/regex",
                "b529539ea7718c8fdfd31b0505e3722f2284c5cd2cbb04384c267a1b0fefecb0",
                44,
                1_048_595,
                "88546c284fe02c16c231036f1c7552ca216aef08513c99941803550c29626568",
            ),
        ];
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);

        for (job_id, pattern_hash, expected, haystack_bytes, haystack_hash) in CASES {
            let mut matching = manifest.jobs.iter().filter(|job| job.id == job_id);
            let job = matching.next().expect("exact token-phrase row");
            assert!(matching.next().is_none(), "duplicate token-phrase row");
            assert_eq!(job.model, "count-spans");
            assert!(!job.regex.unicode);
            assert!(!job.regex.case_insensitive);
            assert_eq!(job.expected.count, expected);

            let input = loader
                .load(job)
                .expect("load authenticated token-phrase row");
            assert_eq!(input.patterns.len(), 1);
            assert_eq!(sha256(input.patterns[0].as_bytes()), pattern_hash);
            assert_eq!(input.haystack.len(), haystack_bytes);
            assert_eq!(sha256(&input.haystack), haystack_hash);

            let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
            assert_eq!(rust, job.expected.count);
            let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
                .expect("FRE token-phrase result");
            assert_eq!(candidate.actual, rust);
            assert_eq!(candidate.plan.as_deref(), Some("aggregate-token-phrase-v1"));
            println!(
                "token-phrase-canary manifest_sha256={manifest_hash} job={job_id} rust={rust} fre={} plan={}",
                candidate.actual,
                candidate.plan.as_deref().expect("candidate plan")
            );
        }
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_mariomka_uri_required_internal_anchor_real_row_canary() {
        const JOB_ID: &str = "imported/mariomka/uri@rust/regex";
        const PATTERN_SHA256: &str =
            "59aa370e8ffdb480c2f5bbfcff37061da270773771f9d1c9a7a91eb2ab5d04f7";
        const HAYSTACK_SHA256: &str =
            "7b7f70c9ca999b2bede85b7ed8e37c9193edced196f4aed29651e37ef4f8e979";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact mariomka URI hard row");
        assert!(matching.next().is_none(), "duplicate mariomka URI row");
        assert_eq!(job.model, "count");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 5_301);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated mariomka URI row");
        assert_eq!(input.patterns.len(), 1);
        assert_eq!(input.patterns[0].len(), 51);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 6_839_410);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let qualified = AggregateBuilder::new(&input.patterns[0])
            .profile(rebar_profile())
            .unicode(false)
            .limits(aggregate_build_limits(&limits))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .expect("build authenticated URI required-anchor plan");
        let report = qualified.build_report();
        assert!(report.authenticates_required_internal_anchor_identity());
        let AggregateBuildAccounting::Continuation(compile) = report.build else {
            panic!("authenticated URI must use continuation accounting");
        };
        assert_eq!(compile.required_internal_anchors, 1);
        assert_eq!(compile.required_internal_anchor_bytes, 3);
        assert_eq!(compile.required_internal_anchor_optional_stages, 2);

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE required internal-anchor result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some("aggregate-continuation-program")
        );
        println!(
            "mariomka-uri-required-anchor-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} plan={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_rustsec_both_slashes_terminal_frontier_canary() {
        const JOB_ID: &str = "wild/rustsec-cargo-audit/both-slashes@rust/regex";
        const PATTERN_SHA256: &str =
            "a303f14a4fb17aff87505e48b619e8c7d23252ee596fbe51ed15ca80541bed19";
        const HAYSTACK_SHA256: &str =
            "4ef156371199b3ddac1bf584e0e52b1828279af82e4ea864b4d9c816adb5db40";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact rustsec both-slashes row");
        assert!(matching.next().is_none(), "duplicate rustsec row");
        assert_eq!(job.model, "count-captures");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 471);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader.load(job).expect("load authenticated rustsec row");
        assert_eq!(input.patterns.len(), 1);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 5_266_960);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE terminal-frontier result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some("capture-linear-selector-uniform-participation")
        );
        println!(
            "rustsec-both-slashes-terminal-frontier-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} plan={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated three-row canary keeps corpus identity, route proof, exact work, and semantic parity in one audit boundary"
    )]
    fn authenticated_rustsec_three_row_bounded_capture_routes_canary() {
        struct Case {
            job_id: &'static str,
            pattern_sha256: &'static str,
            haystack_sha256: &'static str,
            haystack_bytes: usize,
            expected: u64,
            route: fre::AggregateOperationPhysicalRoute,
            selector_work: usize,
        }
        const CASES: [Case; 3] = [
            Case {
                job_id: "wild/rustsec-cargo-audit/original-unix@rust/regex",
                pattern_sha256: "06edd4d491861350d45e366072f015f1228cdc280e1bd86ac7a522b586c4637b",
                haystack_sha256: "4ef156371199b3ddac1bf584e0e52b1828279af82e4ea864b4d9c816adb5db40",
                haystack_bytes: 5_266_960,
                expected: 471,
                route: fre::AggregateOperationPhysicalRoute::RequiredSuffixRows,
                selector_work: 23_129_890,
            },
            Case {
                job_id: "wild/rustsec-cargo-audit/original-windows@rust/regex",
                pattern_sha256: "483e1e7639635ae8643c81307688e573e8cdb3021a161ddf392a029a53c2df1a",
                haystack_sha256: "ab5595a4f7a6b918cece0e7e22ebc883ead6163948571419a1dd5cd3c7f37972",
                haystack_bytes: 4_644_864,
                expected: 462,
                route: fre::AggregateOperationPhysicalRoute::RequiredSuffixRows,
                selector_work: 24_820_280,
            },
            Case {
                job_id: "wild/rustsec-cargo-audit/both-alternate@rust/regex",
                pattern_sha256: "38550f6dc85c967348ff9aee3acd6ba9300ca3142604cdb6d4e620899258977f",
                haystack_sha256: "4ef156371199b3ddac1bf584e0e52b1828279af82e4ea864b4d9c816adb5db40",
                haystack_bytes: 5_266_960,
                expected: 471,
                route: fre::AggregateOperationPhysicalRoute::Candidate,
                selector_work: 16_091_646,
            },
        ];

        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        for case in CASES {
            let mut matching = manifest.jobs.iter().filter(|job| job.id == case.job_id);
            let job = matching.next().expect("exact rustsec row");
            assert!(matching.next().is_none(), "duplicate rustsec row");
            assert_eq!(job.model, "count-captures");
            assert!(!job.regex.unicode);
            assert!(!job.regex.case_insensitive);
            assert_eq!(job.expected.count, case.expected);

            let input = loader.load(job).expect("load authenticated rustsec row");
            assert_eq!(input.patterns.len(), 1);
            assert_eq!(sha256(input.patterns[0].as_bytes()), case.pattern_sha256);
            assert_eq!(input.haystack.len(), case.haystack_bytes);
            assert_eq!(sha256(&input.haystack), case.haystack_sha256);

            let regex = capture_regex_one(&input.patterns[0], false, false, &limits)
                .expect("build authenticated capture reducer");
            assert_eq!(
                regex.build_report().plan_identity.plan,
                CapturePlanKind::LinearSelectorUniformParticipation
            );
            let run_limits = capture_count_run_limits(&regex, input.haystack.len(), &limits)
                .expect("derive authenticated capture limits");
            let identity = regex.cache_identity(run_limits);
            let seal = identity
                .count_seal
                .as_ref()
                .expect("positive uniform capture Count seal");
            assert_eq!(
                seal.route_identity().selector_route.physical_route,
                case.route
            );

            let report = regex
                .count_captures(&input.haystack, run_limits)
                .expect("bounded rustsec capture Count");
            assert!(report.has_closed_count_attempt());
            assert_eq!(
                u64::try_from(report.accounting.count).expect("capture count fits u64"),
                case.expected
            );
            assert_eq!(report.accounting.matches * 3, report.accounting.count);
            let selector = report
                .selector_receipt
                .as_ref()
                .expect("receipt-bearing selector route");
            assert_eq!(selector.identity.physical_route, Some(case.route));
            assert_eq!(selector.actual.work, case.selector_work);
            assert!(selector.actual.work < limits.fre_aggregate_operation_work);

            let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
            assert_eq!(rust, case.expected);
            let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
                .expect("FRE bounded capture result");
            assert_eq!(candidate.actual, rust);
            assert_eq!(
                candidate.plan.as_deref(),
                Some(CURRENT_FRE_CAPTURE_UNIFORM_PLAN)
            );
            println!(
                "rustsec-bounded-capture-canary manifest_sha256={manifest_hash} job={} rust={rust} fre={} route={:?} work={}",
                case.job_id, candidate.actual, case.route, selector.actual.work,
            );
        }
    }

    const CONTINUATION_FAMILY_SCREEN_JOB_IDS: [&str; 7] = [
        "curated/03-date/ascii@rust/regex",
        "curated/03-date/unicode@rust/regex",
        "curated/13-noseyparker/single@rust/regex",
        "curated/13-noseyparker/multi@rust/regex",
        "imported/leipzig/quotes-bounded@rust/regex",
        "imported/mariomka/uri@rust/regex",
        "wild/url/search@rust/regex",
    ];

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_continuation_family_seven_row_screen() {
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        assert_eq!(limits.fre_aggregate_operation_work, 536_870_912);
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let candidate = CurrentFreAdapter;
        let mut remaining: BTreeSet<&str> =
            CONTINUATION_FAMILY_SCREEN_JOB_IDS.into_iter().collect();
        let mut receipts = Vec::with_capacity(CONTINUATION_FAMILY_SCREEN_JOB_IDS.len());
        for job in &manifest.jobs {
            if !remaining.remove(job.id.as_str()) {
                continue;
            }
            let input = loader.load(job);
            let receipt = execute_receipt(job, candidate.adapter(), &input, &limits, |loaded| {
                candidate_reducer(&candidate, job, loaded, &limits)
            });
            assert!(
                matches!(receipt.status, Status::Pass | Status::Unsupported),
                "{} returned {:?}: {:?}",
                receipt.job_id,
                receipt.status,
                receipt.reason
            );
            println!(
                "continuation-family-screen job={} status={:?} actual={} plan={} reason={}",
                receipt.job_id,
                receipt.status,
                receipt
                    .actual
                    .map_or_else(|| "-".to_string(), |actual| actual.to_string()),
                receipt.candidate_plan.as_deref().unwrap_or("-"),
                receipt.reason.as_deref().unwrap_or("-"),
            );
            receipts.push(receipt);
        }
        assert!(remaining.is_empty(), "missing family rows: {remaining:?}");
        assert_eq!(receipts.len(), CONTINUATION_FAMILY_SCREEN_JOB_IDS.len());
        receipts.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        let receipt_bytes = serde_json::to_vec(&receipts).expect("serialize family receipts");
        println!(
            "continuation-family-screen manifest_sha256={manifest_hash} receipts_sha256={} rows={}",
            sha256(&receipt_bytes),
            receipts.len()
        );
    }

    fn retained_ruff_lifecycle(
        haystack_len: usize,
        limits: RunLimits,
    ) -> CurrentFreCaptureLifecycle {
        current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
            true,
            false,
            haystack_len,
            limits,
        )
        .expect("exact retained Ruff lifecycle")
    }

    fn assert_retained_ruff_first_and_steady(haystack: &[u8], expected: u64, limits: RunLimits) {
        let mut lifecycle = retained_ruff_lifecycle(haystack.len(), limits);
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN);
        assert_eq!(
            lifecycle.execute(haystack).expect("first lifecycle"),
            expected
        );
        assert_eq!(
            lifecycle.execute(haystack).expect("steady lifecycle"),
            expected
        );
    }

    fn exact_ruff_lifecycle_limits(haystack_len: usize) -> (RunLimits, usize, usize, usize) {
        let work = haystack_len
            .checked_mul(12)
            .and_then(|value| value.checked_add(1))
            .expect("small exact work");
        let sequential = haystack_len;
        let prospective_captures = haystack_len
            .checked_div(2)
            .and_then(|matches| matches.checked_mul(3))
            .expect("small capture bound");
        let reducer_events = haystack_len
            .checked_add(prospective_captures)
            .expect("small reducer bound");
        (
            RunLimits {
                fre_capture_scalar_planner_work: SPACE_AROUND_OPERATOR_INSPECTION_WORK,
                fre_aggregate_operation_work: work,
                fre_aggregate_sequential_bytes: sequential,
                reducer_steps: u64::try_from(reducer_events).expect("reducer u64"),
                ..RunLimits::default()
            },
            work,
            sequential,
            reducer_events,
        )
    }

    fn assert_ruff_lifecycle_preflight_refusal(
        haystack_len: usize,
        resource: &str,
        required: usize,
        limits: RunLimits,
    ) {
        let error = current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
            true,
            false,
            haystack_len,
            limits,
        )
        .expect_err("one-below resource must refuse before retaining the lifecycle")
        .to_string();
        assert!(
            error.contains(resource),
            "unexpected {resource} error: {error}"
        );
        assert!(error.contains(&required.to_string()));
        assert!(
            error.contains(
                &required
                    .checked_sub(1)
                    .expect("positive resource")
                    .to_string()
            )
        );
    }

    fn print_ruff_hard_canary_receipt(
        manifest_hash: &str,
        job_id: &str,
        rust: u64,
        candidate: &AdapterReduction,
        build: &fre::LineCaptureBuildReport,
        direct: &fre::LineCaptureRunReport,
    ) {
        println!(
            "ruff-space-operator-canary manifest_sha256={manifest_hash} job={job_id} rust={rust} fre={} plan={} construction_allocations={} construction_scratch={} construction_persistent={} construction_peak={} prospective_work={} prospective_loads={} actual_loads={} prospective_matches={} actual_matches={} prospective_captures={} actual_captures={} prospective_lines={} actual_lines={} prospective_events={} actual_events={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan"),
            build.allocations,
            build.scratch_bytes,
            build.persistent_bytes,
            build.peak_bytes,
            direct.work,
            direct.sequential_bytes,
            direct.actual_input_loads,
            direct.prospective_matches,
            direct.matches,
            direct.prospective_capture_count,
            direct.capture_count,
            direct.prospective_line_events,
            direct.lines,
            direct.prospective_reducer_events,
            direct.reducer_events,
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_ruff_space_operator_real_row_canary() {
        const JOB_ID: &str = "wild/ruff/space-around-operator@rust/regex";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact Ruff hard row");
        assert!(matching.next().is_none(), "duplicate Ruff hard row");
        assert_eq!(job.model, "grep-captures");
        assert!(job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 1_224_378);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader.load(job).expect("load authenticated Ruff hard row");
        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let direct_plan = LineCaptureBuilder::new(SPACE_AROUND_OPERATOR_CAPTURE_PATTERN)
            .profile(rebar_profile())
            .build()
            .expect("exact allocation-free direct plan");
        let build = direct_plan.build_report();
        assert_eq!((build.allocations, build.scratch_bytes), (0, 0));
        let plan_bytes = core::mem::size_of::<fre::LineCapturePlan>();
        assert_eq!(
            (build.persistent_bytes, build.peak_bytes),
            (plan_bytes, plan_bytes)
        );
        let reducer_limit = usize::try_from(limits.reducer_steps).expect("reducer limit usize");
        let direct = direct_plan
            .grep_capture_count(
                &input.haystack,
                LineCaptureRunLimits {
                    max_work: limits.fre_aggregate_operation_work,
                    max_sequential_bytes: limits.fre_aggregate_sequential_bytes,
                    max_capture_count: reducer_limit,
                    max_reducer_events: reducer_limit,
                },
            )
            .expect("direct hard-row resource receipt");
        assert_eq!(input.haystack.len(), 32_514_526);
        assert_eq!(direct.work, 390_174_313);
        assert_eq!(direct.sequential_bytes, 32_514_526);
        assert_eq!(direct.actual_input_loads, 32_514_526);
        assert_eq!(direct.prospective_matches, 16_257_263);
        assert_eq!(direct.prospective_capture_count, 48_771_789);
        assert_eq!(direct.prospective_line_events, 32_514_526);
        assert_eq!(direct.prospective_reducer_events, 81_286_315);
        assert_eq!(direct.matches, 408_126);
        assert_eq!(direct.lines, 890_906);
        assert_eq!(direct.reducer_events, 2_115_284);
        assert_eq!(
            u64::try_from(direct.capture_count).expect("capture u64"),
            rust
        );
        assert!(direct.capture_count <= direct.prospective_capture_count);
        assert!(direct.reducer_events <= direct.prospective_reducer_events);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE direct hard-row result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some(CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN)
        );
        assert_retained_ruff_first_and_steady(
            &input.haystack,
            rust,
            RunLimits {
                fre_capture_scalar_planner_work: SPACE_AROUND_OPERATOR_INSPECTION_WORK,
                fre_aggregate_operation_work: direct.work,
                fre_aggregate_sequential_bytes: direct.sequential_bytes,
                reducer_steps: u64::try_from(direct.prospective_reducer_events)
                    .expect("reducer events u64"),
                ..RunLimits::default()
            },
        );
        print_ruff_hard_canary_receipt(&manifest_hash, JOB_ID, rust, &candidate, build, &direct);
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_fn_predicate_real_row_canary() {
        const JOB_ID: &str = "opt/onepass/fn-predicate@rust/regex";
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact fn-predicate row");
        assert!(matching.next().is_none(), "duplicate fn-predicate row");
        assert_eq!(job.model, "grep-captures");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 916);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated fn-predicate row");
        assert_eq!(
            input.patterns,
            [ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN.to_string()]
        );
        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust semantic result");
        assert_eq!(rust, job.expected.count);
        let direct = fn_predicate_direct_receipt(&input.haystack, &limits);

        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE fn-predicate facade result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some(CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN)
        );
        let mut lifecycle = current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN,
            false,
            false,
            input.haystack.len(),
            RunLimits {
                fre_capture_scalar_planner_work: ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK,
                fre_aggregate_operation_work: direct.work,
                fre_aggregate_sequential_bytes: direct.sequential_bytes,
                reducer_steps: u64::try_from(direct.prospective_reducer_events)
                    .expect("reducer events u64"),
                ..RunLimits::default()
            },
        )
        .expect("retained fn-predicate lifecycle");
        assert_eq!(
            lifecycle.plan(),
            CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN
        );
        assert_eq!(lifecycle.execute(&input.haystack).expect("first"), rust);
        assert_eq!(lifecycle.execute(&input.haystack).expect("steady"), rust);
        println!(
            "fn-predicate-canary manifest_sha256={manifest_hash} job={JOB_ID} rust={rust} fre={} plan={} work={} actual_work={} bytes={} loads={} matches={} captures={} lines={} events={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan"),
            direct.work,
            direct.actual_work,
            direct.sequential_bytes,
            direct.actual_input_loads,
            direct.matches,
            direct.capture_count,
            direct.lines,
            direct.reducer_events,
        );
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_fn_predicate_nearest_controls_screen() {
        const ROWS: [(&str, u64); 5] = [
            ("opt/onepass/fn-predicate@rust/regex", 916),
            ("opt/onepass/first-three-words-english@rust/regex", 35_128),
            ("opt/onepass/first-three-words-russian@rust/regex", 19_224),
            ("opt/onepass/word-boundary-english@rust/regex", 579),
            ("opt/onepass/word-boundary-russian@rust/regex", 873),
        ];
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let mut seen = BTreeSet::new();
        for job in manifest
            .jobs
            .iter()
            .filter(|job| ROWS.iter().any(|(expected_id, _)| job.id == *expected_id))
        {
            let expected = ROWS
                .iter()
                .find_map(|(id, count)| (job.id == *id).then_some(*count))
                .expect("selected exact row");
            assert!(seen.insert(job.id.as_str()), "duplicate row {}", job.id);
            assert_eq!(job.expected.count, expected, "{}", job.id);
            let input = loader.load(job).expect("load exact onepass control");
            let rust = rust_reducer(job, &input, &limits).expect("pinned Rust control result");
            let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
                .expect("FRE onepass control result");
            assert_eq!(rust, expected, "{}", job.id);
            assert_eq!(candidate.actual, expected, "{}", job.id);
            let plan = candidate.plan.as_deref().expect("executed plan");
            if job.id == ROWS[0].0 {
                assert_eq!(plan, CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN);
            } else {
                assert_ne!(plan, CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN);
            }
            println!(
                "fn-predicate-control-screen manifest_sha256={manifest_hash} job={} unicode={} expected={expected} rust={rust} fre={} plan={plan}",
                job.id, job.regex.unicode, candidate.actual,
            );
        }
        assert_eq!(seen.len(), ROWS.len());
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    #[allow(
        clippy::too_many_lines,
        reason = "one authenticated transaction binds all five tracker points, both controls, and first/steady reuse"
    )]
    fn authenticated_p128_capture_stream_d_rows_canary() {
        const ROWS: [(&str, u64, &[&str]); 3] = [
            (
                "opt/onepass/first-three-words-russian@rust/regex",
                19_224,
                &["316b893df6c697251fef808a", "1392d2f25572eccf26134456"],
            ),
            (
                "opt/onepass/word-boundary-russian@rust/regex",
                873,
                &["f43803891f368402e52a2440", "c514b04dc3b7ff886f56f4d8"],
            ),
            (
                "wild/bibleref/short@rust/regex",
                30,
                &["43fa59817f1c44d92040848e"],
            ),
        ];
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let mut seen = BTreeSet::new();
        for (job_id, expected, point_ids) in ROWS {
            let mut matching = manifest.jobs.iter().filter(|job| job.id == job_id);
            let job = matching.next().expect("exact D row");
            assert!(matching.next().is_none(), "duplicate D row {job_id}");
            assert!(seen.insert(job_id), "duplicate D fixture {job_id}");
            assert_eq!(job.expected.count, expected, "{job_id}");
            assert!(job.regex.unicode, "{job_id}");
            assert!(!job.regex.case_insensitive, "{job_id}");
            let input = loader.load(job).expect("load exact D row");
            let rust = rust_reducer(job, &input, &limits).expect("pinned Rust D result");
            let candidate =
                candidate_reducer(&CurrentFreAdapter, job, &input, &limits).expect("FRE D result");
            assert_eq!(rust, expected, "{job_id}");
            assert_eq!(candidate.actual, expected, "{job_id}");
            assert_eq!(job.model, "grep-captures", "{job_id}");
            let regex = capture_grep_regex_one(
                input.patterns.first().expect("one D pattern"),
                job.regex.unicode,
                job.regex.case_insensitive,
                &limits,
            )
            .expect("D grep artifact");
            assert_eq!(
                candidate.plan.as_deref(),
                Some(capture_grep_plan_label(&regex)),
                "{job_id}"
            );
            let mut lifecycle = current_fre_rebar_capture_lifecycle(
                &job.model,
                input.patterns.first().expect("one D pattern"),
                job.regex.unicode,
                job.regex.case_insensitive,
                input.haystack.len(),
            )
            .expect("retained D lifecycle");
            assert_eq!(
                lifecycle.plan(),
                CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN,
                "{job_id}"
            );
            assert_eq!(
                lifecycle
                    .execute(&input.haystack)
                    .expect("first D operation"),
                expected,
                "{job_id}"
            );
            assert_eq!(
                lifecycle
                    .execute(&input.haystack)
                    .expect("steady D operation"),
                expected,
                "{job_id}"
            );
            let report = execute_grep_captures_inner(None, &regex, &input.haystack, &limits)
                .expect("D generic line receipt");
            assert_eq!(report.stream_projection, None);
            assert_eq!(report.selector_executions, report.candidate_domains);
            assert_eq!(report.count, expected);
            println!(
                "p128-capture-stream-d-canary manifest_sha256={manifest_hash} job={job_id} points={} expected={expected} rust={rust} fre={} plan={}",
                point_ids.join(","),
                candidate.actual,
                candidate.plan.as_deref().expect("D plan"),
            );
        }
        assert_eq!(seen.len(), ROWS.len());
    }

    #[derive(Clone, Copy)]
    struct RuffRealRow {
        id: &'static str,
        pattern: &'static str,
        plan: &'static str,
        matches: usize,
        captures: usize,
        events: usize,
    }

    fn assert_authenticated_remaining_ruff_row(
        row: RuffRealRow,
        job: &Job,
        input: &LoadedJob,
        limits: &RunLimits,
    ) {
        assert_eq!(job.model, "grep-captures", "{}", row.id);
        assert!(job.regex.unicode, "{}", row.id);
        assert!(!job.regex.case_insensitive, "{}", row.id);
        assert_eq!(input.patterns, [row.pattern.to_string()], "{}", row.id);
        assert_eq!(
            job.expected.count,
            u64::try_from(row.captures).expect("fixture capture count fits u64"),
            "{}",
            row.id
        );
        let rust = rust_reducer(job, input, limits).expect("pinned Rust remaining Ruff row");
        assert_eq!(rust, job.expected.count, "{}", row.id);

        let plan = LineCaptureBuilder::new(row.pattern)
            .profile(rebar_profile())
            .build()
            .expect("exact remaining Ruff plan");
        let reducer_limit = usize::try_from(limits.reducer_steps).expect("reducer limit usize");
        let direct = plan
            .grep_capture_count(
                &input.haystack,
                LineCaptureRunLimits {
                    max_work: limits.fre_aggregate_operation_work,
                    max_sequential_bytes: limits.fre_aggregate_sequential_bytes,
                    max_capture_count: reducer_limit,
                    max_reducer_events: reducer_limit,
                },
            )
            .expect("remaining Ruff direct resource receipt");
        assert_eq!(input.haystack.len(), 32_514_526, "{}", row.id);
        assert_eq!(
            direct.actual_input_loads,
            input.haystack.len(),
            "{}",
            row.id
        );
        assert!(direct.actual_work <= direct.work, "{}", row.id);
        assert_eq!(direct.matches, row.matches, "{}", row.id);
        assert_eq!(direct.capture_count, row.captures, "{}", row.id);
        assert_eq!(direct.lines, 890_906, "{}", row.id);
        assert_eq!(direct.reducer_events, row.events, "{}", row.id);

        let candidate = candidate_reducer(&CurrentFreAdapter, job, input, limits)
            .expect("remaining Ruff facade reduction");
        assert_eq!(candidate.actual, rust, "{}", row.id);
        assert_eq!(candidate.plan.as_deref(), Some(row.plan), "{}", row.id);
        let mut lifecycle = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            row.pattern,
            true,
            false,
            input.haystack.len(),
        )
        .expect("remaining Ruff retained lifecycle");
        assert_eq!(lifecycle.plan(), row.plan, "{}", row.id);
        assert_eq!(lifecycle.execute(&input.haystack).expect("first"), rust);
        assert_eq!(lifecycle.execute(&input.haystack).expect("steady"), rust);
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_remaining_ruff_three_row_real_canary() {
        let rows = [
            RuffRealRow {
                id: "wild/ruff/shebang@rust/regex",
                pattern: SHEBANG_CAPTURE_PATTERN,
                plan: CURRENT_FRE_CAPTURE_SHEBANG_PLAN,
                matches: 94,
                captures: 282,
                events: 891_188,
            },
            RuffRealRow {
                id: "wild/ruff/string-quote-prefix@rust/regex",
                pattern: STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
                plan: CURRENT_FRE_CAPTURE_STRING_QUOTE_PLAN,
                matches: 1_486,
                captures: 2_972,
                events: 893_878,
            },
            RuffRealRow {
                id: "wild/ruff/whitespace-around-keywords@rust/regex",
                pattern: WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
                plan: CURRENT_FRE_CAPTURE_KEYWORDS_PLAN,
                matches: 437_494,
                captures: 1_312_482,
                events: 2_203_388,
            },
        ];
        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).expect("decode manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        let root = manifest_path.parent().expect("manifest parent");
        let mut loader = Loader::new(root, &checkout, &limits);
        for row in rows {
            let mut matches = manifest.jobs.iter().filter(|job| job.id == row.id);
            let job = matches.next().expect("exact remaining Ruff row");
            assert!(matches.next().is_none(), "duplicate {}", row.id);
            let input = loader.load(job).expect("load remaining Ruff row");
            assert_authenticated_remaining_ruff_row(row, job, &input, &limits);
        }
        println!("ruff-remaining-three-canary manifest_sha256={manifest_hash} rows=3");
    }

    fn synthetic_job(model: &str, expected: u64) -> Job {
        serde_json::from_value(serde_json::json!({
            "id": format!("test/{model}@rust/regex"),
            "benchmark": format!("test/{model}"),
            "engine": "rust/regex",
            "model": model,
            "provenance": {"definition_file":"benchmarks/definitions/test.toml","bench_index":0,"definition_file_sha256":"x"},
            "regex": {"patterns":[],"case_insensitive":false,"unicode":false,"source":{"kind":"inline","path":null,"encoding":"u64le-length-prefixed-utf8-pattern-sequence","sha256":"x","bytes":0},"transforms":{"literal":false,"per_line":"none","prepend":null,"append":null}},
            "haystack": {"sha256":"x","bytes":0,"valid_utf8":true,"source":{"kind":"inline","path":null,"encoding":"inline-utf8","sha256":"x","bytes":0},"transforms":{"utf8_lossy":false,"trim":false,"line_start":null,"line_end":null,"repeat":null,"prepend":null,"append":null}},
            "expected":{"count":expected,"selected_by":"scalar-for-all-engines","reducer_contract":format!("model:{model}")},
            "measurement":{"max_iters":1,"max_warmup_iters":0,"max_time_ns":1,"max_warmup_time_ns":0,"timeout_ns":1,"stop_rule":"test","overrides":"test"},
            "required_files":[],
            "availability":{"static_inputs":"test","engine_runtime":"test","semantic_execution":"test"}
        }))
        .expect("valid synthetic job")
    }

    fn compile_for(model: &str, pattern: &str) -> Regex {
        let job = synthetic_job(model, 0);
        rust_compile(&job, &[pattern.to_string()]).expect("compile fixture")
    }

    #[test]
    fn exact_rebar_model_reducers_cover_empty_and_crlf_semantics() {
        let empty = compile_for("count", "");
        assert_eq!(count_matches(&empty, b"a", 10).expect("count"), 2);
        let spans = compile_for("count-spans", "a+");
        assert_eq!(count_spans(&spans, b"aa a", 10).expect("spans"), 3);
        let lines = compile_for("grep", r"^x$");
        assert_eq!(grep(&lines, b"x\r\ny\nx\n", 10).expect("grep"), 2);
        let captures = compile_for("count-captures", r"(a)(b)?");
        assert_eq!(
            count_captures(&captures, b"a ab", 100).expect("captures"),
            5
        );
    }

    #[test]
    fn fre_capture_reducers_cover_optional_repeated_and_line_models() {
        let limits = RunLimits::default();
        let count_patterns = vec![r"(a)(b)?".to_string()];
        let count = fre_reducer(
            CandidateRequest {
                job_id: "test/capture-count",
                model: "count-captures",
                patterns: &count_patterns,
                haystack: b"a ab",
                unicode: false,
                case_insensitive: false,
            },
            &limits,
        )
        .expect("FRE capture count");
        assert_eq!(count.actual, 5);
        assert_eq!(count.plan, CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN);

        let grep_patterns = vec![r"([a-z][a-z])([a-z])([\r\n])?".to_string()];
        let grep = fre_reducer(
            CandidateRequest {
                job_id: "test/capture-grep",
                model: "grep-captures",
                patterns: &grep_patterns,
                haystack: b"foo foo\r\nZ\r\nfoo\r\nfoo",
                unicode: false,
                case_insensitive: false,
            },
            &limits,
        )
        .expect("FRE grep capture count");
        assert_eq!(grep.actual, 12);
        assert_eq!(grep.plan, CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);

        for invalid in [Vec::new(), vec!["(a)".to_string(), "(b)".to_string()]] {
            let error = fre_reducer(
                CandidateRequest {
                    job_id: "test/capture-grep-pattern-cardinality",
                    model: "grep-captures",
                    patterns: &invalid,
                    haystack: b"ab",
                    unicode: false,
                    case_insensitive: false,
                },
                &limits,
            )
            .expect_err("grep-captures requires exactly one pattern");
            assert_eq!(error.status, Status::Unsupported);
            assert!(error.message.contains("requires exactly one pattern"));
        }
    }

    #[test]
    fn generic_anchored_line_capture_routes_target_and_preserves_controls() {
        const PATTERN: &str = r"^ *(\w+) +(\w+) +(\w+)";
        let limits = RunLimits::default();
        let haystack = b"one two three\n".repeat(8_782);
        let patterns = vec![PATTERN.to_string()];
        let reduction = fre_reducer(
            CandidateRequest {
                job_id: "test/generic-anchored-line-capture",
                model: "grep-captures",
                patterns: &patterns,
                haystack: &haystack,
                unicode: false,
                case_insensitive: false,
            },
            &limits,
        )
        .expect("generic anchored-line reduction");
        assert_eq!(reduction.actual, 35_128);
        assert_eq!(reduction.plan, CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN);

        let mut lifecycle = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            PATTERN,
            false,
            false,
            haystack.len(),
        )
        .expect("generic anchored-line lifecycle");
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN);
        assert_eq!(lifecycle.execute(&haystack).expect("first"), 35_128);
        assert_eq!(lifecycle.execute(&haystack).expect("steady"), 35_128);

        let neighbor_haystack = b"aaa bbb\n x y\r\nno\n";
        let neighbor_patterns = vec![r"^ *([a-z]+) +([a-z]+)".to_string()];
        let neighbor = fre_reducer(
            CandidateRequest {
                job_id: "test/generic-anchored-line-neighbor",
                model: "grep-captures",
                patterns: &neighbor_patterns,
                haystack: neighbor_haystack,
                unicode: false,
                case_insensitive: false,
            },
            &limits,
        )
        .expect("supported non-benchmark neighbor");
        assert_eq!(neighbor.actual, 6);
        assert_eq!(neighbor.plan, CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN);

        let ambiguous_haystack = b"aaa\n";
        let mut control = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            r"^(a+)a",
            false,
            false,
            ambiguous_haystack.len(),
        )
        .expect("ambiguous boundary retains incumbent lifecycle");
        assert_ne!(control.plan(), CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN);
        assert_eq!(
            control
                .execute(ambiguous_haystack)
                .expect("incumbent ambiguous-boundary execution"),
            2
        );
    }

    #[test]
    fn noqa_grep_capture_routes_preserve_three_exact_identities() {
        let limits = RunLimits::default();
        let haystack = b"# noqa\n# noqa: A1, B2\r\nnoise # NOQA\n";
        let fixtures = [
            (
                r"(\s*)((?:# [Nn][Oo][Qq][Aa])(?::\s?(([A-Z]+[0-9]+(?:[,\s]+)?)+))?)",
                false,
                11,
                fre::NOQA_ASCII_LEADING_PLAN_ID,
            ),
            (
                r"(?:# [Nn][Oo][Qq][Aa])(?::\s?(([A-Z]+[0-9]+(?:[,\s]+)?)+))?",
                false,
                5,
                fre::NOQA_ASCII_NO_LEADING_PLAN_ID,
            ),
            (
                r"(?P<spaces>\s*)(?P<noqa>(?i:# noqa)(?::\s?(?P<codes>([A-Z]+[0-9]+(?:[,\s]+)?)+))?)",
                true,
                11,
                fre::NOQA_UNICODE_LEADING_PLAN_ID,
            ),
        ];
        for (pattern, unicode, expected, expected_plan) in fixtures {
            let patterns = vec![pattern.to_string()];
            let reduction = fre_reducer(
                CandidateRequest {
                    job_id: "test/noqa-grep-capture",
                    model: "grep-captures",
                    patterns: &patterns,
                    haystack,
                    unicode,
                    case_insensitive: false,
                },
                &limits,
            )
            .expect("exact noqa route executes");
            assert_eq!(reduction.actual, expected);
            assert_eq!(reduction.plan, expected_plan);

            let mut lifecycle = current_fre_rebar_capture_lifecycle(
                "grep-captures",
                pattern,
                unicode,
                false,
                haystack.len(),
            )
            .expect("exact noqa lifecycle builds");
            assert_eq!(lifecycle.plan(), expected_plan);
            assert_eq!(
                lifecycle.execute(haystack).expect("first operation"),
                expected
            );
            assert_eq!(
                lifecycle.execute(haystack).expect("steady operation"),
                expected
            );
            assert!(
                ruff_line_capture_plan_one(pattern, unicode, false, &RunLimits::default(),)
                    .expect("NOQA shape is not a Ruff resource failure")
                    .is_none()
            );
        }
        for pattern in [
            SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
            SHEBANG_CAPTURE_PATTERN,
            STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
            WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
        ] {
            assert!(
                noqa_grep_capture_regex_one(pattern, true, false, &RunLimits::default(),)
                    .expect("Ruff shape is not a NOQA resource failure")
                    .is_none()
            );
        }
    }

    fn exact_configured_ruff_limits(
        haystack_len: usize,
        work_rate: usize,
        groups: usize,
        inspection: usize,
    ) -> (RunLimits, usize, usize) {
        let work = haystack_len
            .checked_mul(work_rate)
            .and_then(|value| value.checked_add(1))
            .expect("small configured Ruff work");
        let captures = haystack_len
            .checked_div(2)
            .and_then(|matches| matches.checked_mul(groups))
            .expect("small configured Ruff capture bound");
        let reducer_events = haystack_len
            .checked_add(captures)
            .expect("small configured Ruff reducer bound");
        (
            RunLimits {
                fre_capture_scalar_planner_work: inspection,
                fre_aggregate_operation_work: work,
                fre_aggregate_sequential_bytes: haystack_len,
                reducer_steps: u64::try_from(reducer_events).expect("reducer u64"),
                ..RunLimits::default()
            },
            work,
            reducer_events,
        )
    }

    #[test]
    fn configured_ruff_lifecycles_are_exact_first_steady_and_bounded() {
        let cases = [
            (
                SHEBANG_CAPTURE_PATTERN,
                fre::SHEBANG_OPERATION_ID,
                SHEBANG_INSPECTION_WORK,
                12,
                3,
                b" #!python\n#!x\nno\n".as_slice(),
            ),
            (
                STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
                fre::STRING_QUOTE_PREFIX_OPERATION_ID,
                STRING_QUOTE_PREFIX_INSPECTION_WORK,
                8,
                2,
                b"r'raw'\nUR\"x\"\nno\n".as_slice(),
            ),
            (
                WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
                fre::WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
                WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
                16,
                3,
                b" if else\nxif _if\ntry\r\n".as_slice(),
            ),
        ];
        for (pattern, plan, inspection, rate, groups, haystack) in cases {
            let upstream = rust_compile_options(&[pattern.to_string()], true, false)
                .expect("pinned Rust configured Ruff pattern");
            let expected =
                grep_captures(&upstream, haystack, u64::MAX).expect("Rust configured Ruff result");
            let (limits, work, reducer_events) =
                exact_configured_ruff_limits(haystack.len(), rate, groups, inspection);
            let mut lifecycle = current_fre_rebar_capture_lifecycle_with_limits(
                "grep-captures",
                pattern,
                true,
                false,
                haystack.len(),
                limits.clone(),
            )
            .expect("configured Ruff lifecycle");
            assert_eq!(lifecycle.plan(), plan);
            assert_eq!(lifecycle.execute(haystack).expect("first"), expected);
            assert_eq!(lifecycle.execute(haystack).expect("steady"), expected);

            for (resource, one_below) in [
                (
                    "ExecutionWork",
                    RunLimits {
                        fre_aggregate_operation_work: work.checked_sub(1).expect("positive work"),
                        ..limits.clone()
                    },
                ),
                (
                    "SequentialBytes",
                    RunLimits {
                        fre_aggregate_sequential_bytes: haystack
                            .len()
                            .checked_sub(1)
                            .expect("nonempty haystack"),
                        ..limits.clone()
                    },
                ),
                (
                    "ReducerEvents",
                    RunLimits {
                        reducer_steps: u64::try_from(
                            reducer_events.checked_sub(1).expect("positive events"),
                        )
                        .expect("reducer u64"),
                        ..limits.clone()
                    },
                ),
            ] {
                let error = current_fre_rebar_capture_lifecycle_with_limits(
                    "grep-captures",
                    pattern,
                    true,
                    false,
                    haystack.len(),
                    one_below,
                )
                .expect_err("one-below must refuse before execution")
                .to_string();
                assert!(error.contains(resource), "unexpected error: {error}");
            }
        }
    }

    #[test]
    fn fn_predicate_line_capture_lifecycle_is_exact_first_steady_and_bounded() {
        let pattern = ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN;
        let haystack = b"fn is_a(x) -> bool {";
        let upstream = rust_compile_options(&[pattern.to_string()], false, false)
            .expect("pinned Rust Unicode-off separated-fields pattern");
        let expected =
            grep_captures(&upstream, haystack, u64::MAX).expect("Rust separated-fields result");
        assert_eq!(expected, 4);
        let exact = RunLimits {
            fre_capture_scalar_planner_work: ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK,
            fre_aggregate_operation_work: 241,
            fre_aggregate_sequential_bytes: 20,
            reducer_steps: 24,
            ..RunLimits::default()
        };
        let mut lifecycle = current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            pattern,
            false,
            false,
            haystack.len(),
            exact.clone(),
        )
        .expect("exact Unicode-off separated-fields lifecycle");
        assert_eq!(
            lifecycle.plan(),
            CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN
        );
        assert!(!lifecycle.unicode());
        assert!(!lifecycle.case_insensitive());
        assert_eq!(lifecycle.execute(haystack).expect("first"), expected);
        assert_eq!(lifecycle.execute(haystack).expect("steady"), expected);

        for (resource, one_below) in [
            (
                "inspection requires 44",
                RunLimits {
                    fre_capture_scalar_planner_work: ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK
                        - 1,
                    ..exact.clone()
                },
            ),
            (
                "ExecutionWork",
                RunLimits {
                    fre_aggregate_operation_work: 240,
                    ..exact.clone()
                },
            ),
            (
                "SequentialBytes",
                RunLimits {
                    fre_aggregate_sequential_bytes: 19,
                    ..exact.clone()
                },
            ),
            (
                "CaptureCount",
                RunLimits {
                    reducer_steps: 3,
                    ..exact.clone()
                },
            ),
            (
                "ReducerEvents",
                RunLimits {
                    reducer_steps: 23,
                    ..exact.clone()
                },
            ),
        ] {
            let error = current_fre_rebar_capture_lifecycle_with_limits(
                "grep-captures",
                pattern,
                false,
                false,
                haystack.len(),
                one_below,
            )
            .expect_err("one-below must refuse before execution")
            .to_string();
            assert!(error.contains(resource), "unexpected error: {error}");
        }
    }

    #[test]
    fn ruff_capture_lifecycle_is_retained_exact_and_bounded() {
        let haystack = b"x+\n\xFF++\r\nx + ";
        let upstream = rust_compile_options(
            &[SPACE_AROUND_OPERATOR_CAPTURE_PATTERN.to_string()],
            true,
            false,
        )
        .expect("pinned Rust Ruff pattern");
        let expected = grep_captures(&upstream, haystack, u64::MAX).expect("Rust Ruff result");
        let (exact_limits, work, sequential, reducer_events) =
            exact_ruff_lifecycle_limits(haystack.len());
        let mut lifecycle = retained_ruff_lifecycle(haystack.len(), exact_limits.clone());
        assert_eq!(lifecycle.model(), "grep-captures");
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN);
        assert!(is_current_fre_capture_route(
            lifecycle.model(),
            lifecycle.plan()
        ));
        assert_eq!(
            lifecycle.execute(haystack).expect("first operation"),
            expected
        );
        assert_eq!(
            lifecycle.execute(haystack).expect("steady operation"),
            expected
        );
        assert!(lifecycle.execute(b"x+").is_err());

        let planner_error = current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
            true,
            false,
            haystack.len(),
            RunLimits {
                fre_capture_scalar_planner_work: SPACE_AROUND_OPERATOR_INSPECTION_WORK
                    .checked_sub(1)
                    .expect("positive inspection work"),
                ..exact_limits.clone()
            },
        )
        .expect_err("one-below inspection must refuse construction");
        let planner_error = planner_error.to_string();
        assert!(planner_error.contains("requires 54 work"));
        assert!(planner_error.contains("limit is 53"));

        for (resource, required, limits) in [
            (
                "ExecutionWork",
                work,
                RunLimits {
                    fre_aggregate_operation_work: work.checked_sub(1).expect("positive work"),
                    ..exact_limits.clone()
                },
            ),
            (
                "SequentialBytes",
                sequential,
                RunLimits {
                    fre_aggregate_sequential_bytes: sequential
                        .checked_sub(1)
                        .expect("nonempty input"),
                    ..exact_limits.clone()
                },
            ),
            (
                "ReducerEvents",
                reducer_events,
                RunLimits {
                    reducer_steps: u64::try_from(
                        reducer_events
                            .checked_sub(1)
                            .expect("positive reducer bound"),
                    )
                    .expect("reducer u64"),
                    ..exact_limits.clone()
                },
            ),
        ] {
            assert_ruff_lifecycle_preflight_refusal(haystack.len(), resource, required, limits);
        }
    }

    #[test]
    fn capture_lifecycle_reuses_one_authenticated_artifact_across_boundaries() {
        let mut count =
            current_fre_rebar_capture_lifecycle("count-captures", r"(a)(b)?", false, false, 4)
                .expect("count-captures lifecycle");
        assert_eq!(count.model(), "count-captures");
        assert_eq!(
            count.plan(),
            CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN
        );
        assert_eq!(count.execute(b"a ab").expect("first count operation"), 5);
        assert_eq!(count.execute(b"a ab").expect("steady count operation"), 5);
        assert!(count.execute(b"a").is_err());

        let haystack = b"foo foo\r\nZ\r\nfoo\r\nfoo";
        let mut grep = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            r"([a-z][a-z])([a-z])([\r\n])?",
            false,
            false,
            haystack.len(),
        )
        .expect("grep-captures lifecycle");
        assert_eq!(grep.model(), "grep-captures");
        assert_eq!(grep.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
        assert_eq!(grep.execute(haystack).expect("first grep operation"), 12);
        assert_eq!(grep.execute(haystack).expect("steady grep operation"), 12);

        assert!(current_fre_rebar_capture_lifecycle("count", "a", false, false, 1).is_err());
        let mut unicode =
            current_fre_rebar_capture_lifecycle("count-captures", r"(\pL)", true, false, 3)
                .expect("Unicode count-captures lifecycle");
        assert_eq!(unicode.model(), "count-captures");
        assert_eq!(unicode.plan(), CURRENT_FRE_CAPTURE_UNIFORM_PLAN);
        assert_eq!(
            unicode.execute("雪".as_bytes()).expect("Unicode capture"),
            2
        );
    }

    #[test]
    fn direct_capture_limits_project_retained_simd_physical_reads() {
        let prospective = fre::PrefixClassUniformParticipationProspective {
            haystack_bytes: 10,
            shape_units: 3,
            minimum_match_bytes: 4,
            first_finder_bytes: 10,
            second_finder_bytes: 10,
            first_finder_candidates: 10,
            second_finder_candidates: 10,
            prefix_candidates: 20,
            start_arbitrations: 40,
            first_class_probes: 20,
            greedy_extension_reads: 180,
            results: 2,
            capture_count: 4,
            capture_events: 6,
            work: 300,
            operation_allocations: 0,
            operation_bytes: 0,
            scratch_bytes: 0,
            persistent_bytes: 64,
            peak_bytes: 64,
        };
        let projected = project_direct_capture_run_limits(
            Some(prospective),
            prospective.haystack_bytes,
            250,
            20,
            5,
            3,
            &RunLimits::default(),
        )
        .expect("project retained dispatched envelope");
        assert_eq!(projected.max_greedy_extension_reads, 180);
        assert_eq!(projected.max_work, 250);
        assert_eq!(projected.max_capture_count, 3);
        assert_eq!(projected.max_capture_events, 5);
        assert_eq!(projected.max_first_finder_bytes, 10);
        assert_eq!(projected.max_second_finder_bytes, 10);

        let sequential_one_below = project_direct_capture_run_limits(
            Some(prospective),
            prospective.haystack_bytes,
            usize::MAX,
            19,
            usize::MAX,
            usize::MAX,
            &RunLimits::default(),
        )
        .expect("project one-below sequential policy");
        assert_eq!(sequential_one_below.max_first_finder_bytes, 0);
        assert_eq!(sequential_one_below.max_second_finder_bytes, 0);
    }

    #[test]
    fn rust_functions_direct_capture_lifecycle_is_eager_and_stable() {
        let pattern = r"fn is_(\w+)|fn as_(\w+)";
        let first = b"fn is_alpha fn as_beta ";
        let mutated = b"fn as_9 fn is_Z fn is_\xff";
        let reference = rust_compile_options(&[pattern.to_string()], false, false)
            .expect("Rust-functions reference build");
        let mut lifecycle = current_fre_rebar_capture_lifecycle(
            "count-captures",
            pattern,
            false,
            false,
            mutated.len(),
        )
        .expect("Rust-functions direct lifecycle");
        assert_eq!(lifecycle.model(), "count-captures");
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN);
        assert!(is_current_fre_capture_route(
            lifecycle.model(),
            lifecycle.plan()
        ));
        assert_eq!(
            lifecycle.execute(first).expect("first public operation"),
            count_captures(&reference, first, u64::MAX).expect("Rust-functions reference first"),
        );
        assert_eq!(
            lifecycle
                .execute(mutated)
                .expect("mutated steady public operation"),
            count_captures(&reference, mutated, u64::MAX).expect("Rust-functions reference steady"),
        );
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_PREFIX_CLASS_PLAN);
    }

    #[test]
    fn rust_functions_direct_receipts_fail_closed_in_adapter() {
        let pattern = r"fn is_(\w+)|fn as_(\w+)";
        let haystack = b"fn is_alpha fn as_beta";
        let adapter_limits = RunLimits::default();
        let regex = capture_regex_one(pattern, false, false, &adapter_limits)
            .expect("direct capture artifact");
        let run_limits = capture_count_run_limits(&regex, haystack.len(), &adapter_limits)
            .expect("direct run limits");
        let retained = regex
            .retained_prefix_class_participation_prospective(haystack.len())
            .expect("direct retained envelope")
            .expect("direct artifact");
        assert_eq!(
            run_limits
                .prefix_class_participation
                .max_greedy_extension_reads,
            retained.greedy_extension_reads
        );
        assert_eq!(
            run_limits.prefix_class_participation.max_work,
            retained.work
        );
        let result = regex
            .count_captures(haystack, run_limits)
            .expect("direct capture result");
        assert!(authenticates_direct_capture_success(
            &regex,
            haystack.len(),
            &run_limits,
            &result
        ));
        let mut forged_success = result.clone();
        forged_success
            .prefix_class_participation_receipt
            .as_mut()
            .expect("direct success receipt")
            .actual_allocations = 1;
        assert!(!authenticates_direct_capture_success(
            &regex,
            haystack.len(),
            &run_limits,
            &forged_success
        ));

        let prospective = result
            .prefix_class_participation
            .expect("direct success accounting")
            .prospective;
        assert_eq!(prospective, retained);
        let mut greedy_one_below = run_limits;
        greedy_one_below
            .prefix_class_participation
            .max_greedy_extension_reads = prospective.greedy_extension_reads - 1;
        let greedy_terminal = regex
            .count_captures(haystack, greedy_one_below)
            .expect_err("direct greedy-extension one-below");
        assert!(matches!(
            greedy_terminal.source,
            fre::CaptureExecutionSource::PrefixClassParticipation(
                fre::PrefixClassUniformParticipationError::GreedyExtensionReadsLimit {
                    needed,
                    limit,
                }
            ) if needed == prospective.greedy_extension_reads
                && limit == prospective.greedy_extension_reads - 1
        ));
        assert!(authenticates_direct_capture_error(
            &regex,
            haystack.len(),
            &greedy_one_below,
            &greedy_terminal
        ));
        let mut one_below = run_limits;
        one_below.prefix_class_participation.max_work = prospective.work - 1;
        let terminal = regex
            .count_captures(haystack, one_below)
            .expect_err("direct one-below");
        assert!(authenticates_direct_capture_error(
            &regex,
            haystack.len(),
            &one_below,
            &terminal
        ));
        assert_eq!(
            capture_execution_error(
                &regex,
                haystack.len(),
                &one_below,
                &terminal,
                "valid direct refusal".to_string(),
            )
            .status,
            Status::Unsupported
        );
        let mut forged_terminal = terminal;
        forged_terminal
            .prefix_class_participation_receipt
            .as_mut()
            .expect("direct terminal receipt")
            .prospective = None;
        assert!(!authenticates_direct_capture_error(
            &regex,
            haystack.len(),
            &one_below,
            &forged_terminal
        ));
        assert_eq!(
            capture_execution_error(
                &regex,
                haystack.len(),
                &one_below,
                &forged_terminal,
                "forged direct refusal".to_string(),
            )
            .status,
            Status::Fault
        );
    }

    #[test]
    fn required_literal_capture_lifecycle_is_single_build_exact_and_bounded() {
        const AWS: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|"))+"#;
        let haystack = b"miss\n\xFF no key\n\"AKIAIOSFODNN7EXAMPLE\" \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
        let upstream = rust_compile_options(&[AWS.to_string()], false, false)
            .expect("pinned Rust AWS pattern");
        let expected =
            grep_captures(&upstream, haystack, u64::MAX).expect("Rust AWS grep-captures");
        assert_eq!(expected, 9);
        let mut lifecycle =
            current_fre_rebar_capture_lifecycle("grep-captures", AWS, false, false, haystack.len())
                .expect("required-literal lifecycle");
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
        assert!(is_current_fre_capture_route(
            lifecycle.model(),
            lifecycle.plan()
        ));
        assert_eq!(lifecycle.execute(haystack).expect("first"), expected);
        assert_eq!(lifecycle.execute(haystack).expect("steady"), expected);

        let accounting_regex = capture_grep_regex_one(AWS, false, false, &RunLimits::default())
            .expect("required-literal accounting fixture");
        let accounting_prefilter = active_capture_required_literal_plan(&accounting_regex)
            .expect("AWS required-literal proof");
        for miss in [b"".as_slice(), b"xx\n".as_slice()] {
            let prospective = accounting_prefilter
                .line_partition_prospective(miss.len())
                .expect("small line prospective")
                .expect("AWS literals contain no line terminators");
            let work = miss
                .len()
                .checked_add(prospective.transitions_upper_bound)
                .and_then(|value| value.checked_add(prospective.match_events_upper_bound))
                .expect("small prefilter work");
            let sequential = miss.len().checked_mul(2).expect("small sequential");
            let exact = RunLimits {
                fre_aggregate_operation_work: work,
                fre_aggregate_sequential_bytes: sequential,
                ..RunLimits::default()
            };
            let mut lifecycle = current_fre_rebar_capture_lifecycle_with_limits(
                "grep-captures",
                AWS,
                false,
                false,
                miss.len(),
                exact.clone(),
            )
            .expect("exact required-literal lifecycle");
            assert_eq!(lifecycle.execute(miss).expect("exact miss"), 0);

            let work_one_below = RunLimits {
                fre_aggregate_operation_work: work
                    .checked_sub(1)
                    .expect("required initial transition"),
                ..exact.clone()
            };
            assert!(
                current_fre_rebar_capture_lifecycle_with_limits(
                    "grep-captures",
                    AWS,
                    false,
                    false,
                    miss.len(),
                    work_one_below,
                )
                .expect("one-below work lifecycle builds")
                .execute(miss)
                .expect_err("one-below work must refuse")
                .to_string()
                .contains("required-literal scans require")
            );
            if sequential > 0 {
                let sequential_one_below = RunLimits {
                    fre_aggregate_sequential_bytes: sequential - 1,
                    ..exact
                };
                assert!(
                    current_fre_rebar_capture_lifecycle_with_limits(
                        "grep-captures",
                        AWS,
                        false,
                        false,
                        miss.len(),
                        sequential_one_below,
                    )
                    .expect("one-below sequential lifecycle builds")
                    .execute(miss)
                    .expect_err("one-below sequential must refuse")
                    .to_string()
                    .contains("sequential bytes")
                );
            }
        }
    }

    #[test]
    fn required_literal_activation_uses_only_the_effective_antichain() {
        let haystack = b"AB\nXAB\nCD\nmiss";
        for pattern in ["(?:(AB)|(AB))", "(?:(AB)|(XAB))"] {
            let upstream = rust_compile_options(&[pattern.to_string()], false, false)
                .expect("pinned Rust redundant capture pattern");
            let expected =
                grep_captures(&upstream, haystack, u64::MAX).expect("Rust redundant grep-captures");
            let mut lifecycle = current_fre_rebar_capture_lifecycle(
                "grep-captures",
                pattern,
                false,
                false,
                haystack.len(),
            )
            .expect("redundant any-literal set falls back to capture route");
            assert_ne!(lifecycle.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
            assert_eq!(
                lifecycle.execute(haystack).expect("fallback execution"),
                expected
            );
        }

        let distinct = "(?:(AB)|(CD))";
        let upstream = rust_compile_options(&[distinct.to_string()], false, false)
            .expect("pinned Rust distinct capture pattern");
        let expected =
            grep_captures(&upstream, haystack, u64::MAX).expect("Rust distinct grep-captures");
        let mut active = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            distinct,
            false,
            false,
            haystack.len(),
        )
        .expect("distinct effective antichain lifecycle");
        assert_eq!(active.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
        assert_eq!(
            active.execute(haystack).expect("prefilter execution"),
            expected
        );

        let refused_limits = RunLimits {
            fre_literal_build_needle_bytes: 3,
            ..RunLimits::default()
        };
        let mut fallback = current_fre_rebar_capture_lifecycle_with_limits(
            "grep-captures",
            distinct,
            false,
            false,
            haystack.len(),
            refused_limits,
        )
        .expect("optional effective-set refusal preserves capture lifecycle");
        assert_ne!(fallback.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
        assert_eq!(
            fallback
                .execute(haystack)
                .expect("resource fallback execution"),
            expected
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven test authenticates line semantics, selector cardinality, and exact cumulative boundaries together"
    )]
    fn required_literal_line_stream_preserves_domains_priority_and_accounting() {
        const PATTERN: &str = r"(?:(ABC)|(AB)(C)|(XY))";
        let defaults = RunLimits::default();
        let regex = capture_grep_regex_one(PATTERN, false, false, &defaults)
            .expect("generic variable-participation capture fixture");
        let prefilter = active_capture_required_literal_plan(&regex)
            .expect("fixture has a same-HIR required-literal proof");
        assert_eq!(
            capture_plan_label(&regex),
            CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN
        );
        let upstream = rust_compile_options(&[PATTERN.to_string()], false, false)
            .expect("pinned Rust source-priority fixture");
        let cases: &[(&[u8], usize, usize, usize)] = &[
            (b"", 0, 0, 0),
            (b"\n", 0, 1, 0),
            (b"\n\n", 0, 2, 0),
            (b"ABC\n", 1, 1, 1),
            (b"ABC\r\n", 1, 1, 1),
            (b"ABC\n\n", 1, 2, 1),
            (b"A\nBC", 0, 2, 0),
            (b"\xFFABC\r\nA\xFFB\nXY\x80", 2, 3, 2),
            (b"ABCABC", 1, 1, 2),
        ];
        for &(haystack, candidate_domains, line_domains, match_events) in cases {
            let expected =
                grep_captures(&upstream, haystack, u64::MAX).expect("Rust grep-captures");
            let first = execute_grep_captures_inner(Some(prefilter), &regex, haystack, &defaults)
                .expect("first consolidated line execution");
            let steady = execute_grep_captures_inner(Some(prefilter), &regex, haystack, &defaults)
                .expect("steady consolidated line execution");
            assert_eq!(first, steady, "retained execution changed for {haystack:?}");
            assert_eq!(first.count, expected, "semantic mismatch for {haystack:?}");
            assert_eq!(first.line_domains, line_domains, "{haystack:?}");
            assert_eq!(first.candidate_domains, candidate_domains, "{haystack:?}");
            assert_eq!(
                first.selector_executions, candidate_domains,
                "one selector execution is required per surviving domain: {haystack:?}"
            );
            assert!(first.consolidated_prefilter, "{haystack:?}");
            let prospective = prefilter
                .line_partition_prospective(haystack.len())
                .unwrap()
                .unwrap();
            assert_eq!(
                first.prefilter_transitions,
                prospective.transitions_upper_bound
            );
            assert_eq!(first.prefilter_match_events, match_events);
            assert_eq!(
                first.prefilter_match_events_upper_bound,
                prospective.match_events_upper_bound
            );
            assert_eq!(first.prefilter_sequential_bytes, haystack.len());
        }
        assert_eq!(
            execute_grep_captures_inner(Some(prefilter), &regex, b"ABC", &defaults)
                .unwrap()
                .count,
            2,
            "leftmost first arm contributes only overall plus its one capture"
        );
        assert_eq!(
            execute_grep_captures_inner(Some(prefilter), &regex, b"ABCABC", &defaults)
                .unwrap()
                .count,
            4,
            "multiple matches in one line still use one selector operation"
        );

        let miss = b"miss\n";
        let prospective = prefilter
            .line_partition_prospective(miss.len())
            .unwrap()
            .unwrap();
        let exact_work = miss
            .len()
            .checked_add(prospective.transitions_upper_bound)
            .and_then(|work| work.checked_add(prospective.match_events_upper_bound))
            .unwrap();
        let exact = RunLimits {
            fre_aggregate_operation_work: exact_work,
            fre_aggregate_sequential_bytes: miss.len() * 2,
            ..RunLimits::default()
        };
        let exact_report =
            execute_grep_captures_inner(Some(prefilter), &regex, miss, &exact).unwrap();
        assert_eq!(exact_report.count, 0);
        assert_eq!(exact_report.selector_executions, 0);
        assert_eq!(
            exact_report.selector.work,
            exact.fre_aggregate_operation_work
        );
        assert_eq!(
            exact_report.selector.sequential_bytes,
            exact.fre_aggregate_sequential_bytes
        );
        let one_below = RunLimits {
            fre_aggregate_operation_work: exact.fre_aggregate_operation_work - 1,
            ..exact
        };
        let refusal =
            execute_grep_captures_inner(Some(prefilter), &regex, miss, &one_below).unwrap_err();
        assert_eq!(refusal.status, Status::Unsupported);
        assert!(refusal.message.contains("required-literal scans require"));
    }

    #[test]
    fn required_literal_line_stream_keeps_delimiter_sensitive_fallback() {
        const PATTERN: &str = r"(?:(AB\r)|(BC))";
        let limits = RunLimits::default();
        let regex = capture_grep_regex_one(PATTERN, false, false, &limits)
            .expect("delimiter-sensitive required-literal fixture");
        let prefilter =
            active_capture_required_literal_plan(&regex).expect("required-literal proof");
        let haystack = b"ABC\r\nmiss\nBC";
        assert!(
            prefilter
                .line_partition_matches(haystack, CaptureRequiredLiteralRunLimits::default(),)
                .unwrap()
                .is_none(),
            "terminator-bearing literals must retain independent line searches"
        );
        let upstream = rust_compile_options(&[PATTERN.to_string()], false, false)
            .expect("pinned Rust delimiter-sensitive fixture");
        let expected = grep_captures(&upstream, haystack, u64::MAX).expect("Rust grep-captures");
        let report =
            execute_grep_captures_inner(Some(prefilter), &regex, haystack, &limits).unwrap();
        assert_eq!(report.count, expected);
        assert!(!report.consolidated_prefilter);
        assert_eq!(report.line_domains, 3);
        assert_eq!(report.candidate_domains, 2);
        assert_eq!(report.selector_executions, 2);
        assert_eq!(report.prefilter_match_events, 0);
        assert_eq!(report.prefilter_match_events_upper_bound, 0);
    }

    #[test]
    #[ignore = "requires the exact expanded Rebar corpus and pinned clean Rebar checkout"]
    fn authenticated_aws_keys_full_real_row_canary() {
        const JOB_ID: &str = "curated/09-aws-keys/full@rust/regex";
        const PATTERN_SHA256: &str =
            "280d3fd784adec2abe6d59663f2676aa97a0b239135d761522e2d7e008ffe24d";
        const HAYSTACK_SHA256: &str =
            "140a09e1134154c3222186d21ace797cf3ffaa1ed317480064e3faffd4fe85b6";
        const AWS: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|"))+"#;

        let manifest_path = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_MANIFEST")
                .expect("FRE_TEST_REBAR_MANIFEST must name the exact manifest.json"),
        );
        let checkout = PathBuf::from(
            std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
                .expect("FRE_TEST_REBAR_CHECKOUT must name the pinned clean Rebar checkout"),
        );
        let manifest_bytes = read_limited(&manifest_path, 64 * 1_048_576)
            .expect("read exact expanded Rebar manifest");
        let manifest_hash = sha256(&manifest_bytes);
        assert_eq!(manifest_hash, PROGRAM_STATE_SENTINEL_MANIFEST_SHA256);
        verify_sidecar_hash(&manifest_path, &manifest_hash)
            .expect("authenticate expanded Rebar manifest sidecar");
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).expect("decode expanded Rebar manifest");
        let limits = RunLimits::default();
        validate_manifest(&manifest, &checkout, &limits)
            .expect("authenticate manifest and pinned clean Rebar checkout");
        assert_eq!(manifest.source.revision, AUDITED_REBAR_REVISION);

        let mut matching = manifest.jobs.iter().filter(|job| job.id == JOB_ID);
        let job = matching.next().expect("exact AWS keys full row");
        assert!(matching.next().is_none(), "duplicate AWS keys full row");
        assert_eq!(job.engine, "rust/regex");
        assert_eq!(job.model, "grep-captures");
        assert!(!job.regex.unicode);
        assert!(!job.regex.case_insensitive);
        assert_eq!(job.expected.count, 0);
        assert_eq!(job.regex.patterns.len(), 1);
        assert_eq!(job.regex.patterns[0].bytes, AWS.len());
        assert_eq!(job.regex.patterns[0].sha256, PATTERN_SHA256);
        assert_eq!(job.haystack.bytes, 32_514_634);
        assert_eq!(job.haystack.sha256, HAYSTACK_SHA256);

        let manifest_root = manifest_path.parent().expect("manifest has a parent");
        let mut loader = Loader::new(manifest_root, &checkout, &limits);
        let input = loader
            .load(job)
            .expect("load authenticated AWS keys full row");
        assert_eq!(input.patterns, [AWS.to_string()]);
        assert_eq!(sha256(input.patterns[0].as_bytes()), PATTERN_SHA256);
        assert_eq!(input.haystack.len(), 32_514_634);
        assert_eq!(sha256(&input.haystack), HAYSTACK_SHA256);

        let rust = rust_reducer(job, &input, &limits).expect("pinned Rust AWS result");
        assert_eq!(rust, 0);
        let candidate = candidate_reducer(&CurrentFreAdapter, job, &input, &limits)
            .expect("FRE AWS required-literal result");
        assert_eq!(candidate.actual, rust);
        assert_eq!(
            candidate.plan.as_deref(),
            Some(CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN)
        );

        let mut lifecycle = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            AWS,
            false,
            false,
            input.haystack.len(),
        )
        .expect("retained AWS required-literal lifecycle");
        assert_eq!(lifecycle.plan(), CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN);
        assert_eq!(lifecycle.execute(&input.haystack).expect("first"), rust);
        assert_eq!(lifecycle.execute(&input.haystack).expect("steady"), rust);
        println!(
            "aws-keys-full-canary manifest_sha256={manifest_hash} job={JOB_ID} pattern_sha256={PATTERN_SHA256} haystack_sha256={HAYSTACK_SHA256} rust={rust} fre={} plan={}",
            candidate.actual,
            candidate.plan.as_deref().expect("candidate plan")
        );
    }

    #[test]
    fn grep_capture_selector_ledgers_are_cumulative_across_lines() {
        let limits = RunLimits {
            fre_aggregate_operation_work: 10,
            fre_aggregate_sequential_bytes: 20,
            ..RunLimits::default()
        };

        let mut work = CaptureSelectorLedger::default();
        assert_eq!(work.remaining(&limits).expect("initial ledger"), (10, 20));
        work.charge(6, 5, 4, &limits).expect("first line");
        assert_eq!(work.remaining(&limits).expect("remaining ledger"), (4, 11));
        assert_eq!(
            work.charge(5, 0, 0, &limits).unwrap_err().status,
            Status::Fault
        );

        let mut sequential = CaptureSelectorLedger::default();
        sequential
            .charge(1, 8, 9, &limits)
            .expect("first sequential line");
        assert_eq!(
            sequential.charge(1, 2, 2, &limits).unwrap_err().status,
            Status::Fault
        );
    }

    #[test]
    fn grep_capture_lf_scan_is_preflighted_and_scales() {
        for bytes in [0, 1, 4_096] {
            let limits = RunLimits {
                fre_aggregate_operation_work: bytes,
                fre_aggregate_sequential_bytes: bytes,
                ..RunLimits::default()
            };
            let ledger = CaptureSelectorLedger::preflight_lf_scan(bytes, &limits)
                .expect("exact LF scan budget");
            assert_eq!(ledger.work, bytes);
            assert_eq!(ledger.sequential_bytes, bytes);
            assert_eq!(ledger.remaining(&limits).unwrap(), (0, 0));
        }

        let bytes = 4_096;
        let work_one_below = RunLimits {
            fre_aggregate_operation_work: bytes - 1,
            fre_aggregate_sequential_bytes: bytes,
            ..RunLimits::default()
        };
        let work = CaptureSelectorLedger::preflight_lf_scan(bytes, &work_one_below).unwrap_err();
        assert_eq!(work.status, Status::Unsupported);
        assert!(work.message.contains("requires 4096 work, limit is 4095"));
        let sequential_one_below = RunLimits {
            fre_aggregate_operation_work: bytes,
            fre_aggregate_sequential_bytes: bytes - 1,
            ..RunLimits::default()
        };
        let sequential =
            CaptureSelectorLedger::preflight_lf_scan(bytes, &sequential_one_below).unwrap_err();
        assert_eq!(sequential.status, Status::Unsupported);
        assert!(
            sequential
                .message
                .contains("requires 4096 sequential bytes, limit is 4095")
        );

        let regex = capture_regex_one("(a)", false, false, &RunLimits::default())
            .expect("uniform capture fixture");
        let layouts: [&[u8]; 2] = [b"aaaaaaaa", b"a\na\na\na\n"];
        assert_eq!(layouts[0].len(), layouts[1].len());
        assert_eq!(
            execute_grep_captures(&regex, layouts[0], &RunLimits::default()).unwrap(),
            16
        );
        assert_eq!(
            execute_grep_captures(&regex, layouts[1], &RunLimits::default()).unwrap(),
            8
        );
        for haystack in layouts {
            let work_one_below = RunLimits {
                fre_aggregate_operation_work: haystack.len() - 1,
                fre_aggregate_sequential_bytes: haystack.len(),
                ..RunLimits::default()
            };
            let work = execute_grep_captures(&regex, haystack, &work_one_below).unwrap_err();
            assert_eq!(work.status, Status::Unsupported);
            assert!(work.message.contains("LF scan requires 8 work, limit is 7"));
            let sequential_one_below = RunLimits {
                fre_aggregate_operation_work: haystack.len(),
                fre_aggregate_sequential_bytes: haystack.len() - 1,
                ..RunLimits::default()
            };
            let sequential =
                execute_grep_captures(&regex, haystack, &sequential_one_below).unwrap_err();
            assert_eq!(sequential.status, Status::Unsupported);
            assert!(
                sequential
                    .message
                    .contains("LF scan requires 8 sequential bytes, limit is 7")
            );
        }
    }

    #[test]
    fn fused_capture_stream_is_operation_specific_and_reused() {
        let limits = RunLimits::default();
        let pattern = r"(\p{L}+)";
        let haystack = "ab\r\nЖж\ncd".as_bytes();
        let regex =
            capture_grep_regex_one(pattern, true, false, &limits).expect("capture stream fixture");
        assert_eq!(
            regex.build_report().plan_identity.plan,
            CapturePlanKind::LinearSelectorUniformParticipation
        );
        assert_eq!(capture_plan_label(&regex), CURRENT_FRE_CAPTURE_UNIFORM_PLAN);
        assert_eq!(
            capture_grep_plan_label(&regex),
            CURRENT_FRE_CAPTURE_UNIFORM_PLAN
        );

        let run_limits =
            capture_count_run_limits(&regex, haystack.len(), &limits).expect("stream limits");
        let report = execute_grep_captures_inner(None, &regex, haystack, &limits)
            .expect("one-shot generic capture fallback");
        assert_eq!(report.count, 6);
        assert_eq!(report.stream_projection, None);
        assert_eq!(report.line_domains, 3);
        assert_eq!(report.candidate_domains, 3);
        assert_eq!(report.selector_executions, 3);
        assert!(
            regex
                .line_stream_prospective(haystack.len(), run_limits)
                .expect("stream prospective")
                .is_some()
        );

        let mut count = current_fre_rebar_capture_lifecycle(
            "count-captures",
            pattern,
            true,
            false,
            haystack.len(),
        )
        .expect("ordinary Count lifecycle");
        assert_eq!(count.plan(), CURRENT_FRE_CAPTURE_UNIFORM_PLAN);
        assert_eq!(count.execute(haystack).expect("ordinary Count"), 6);

        let mut grep = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            pattern,
            true,
            false,
            haystack.len(),
        )
        .expect("stream lifecycle");
        assert_eq!(grep.plan(), CURRENT_FRE_CAPTURE_STREAM_PARTICIPATION_PLAN);
        assert_eq!(grep.execute(haystack).expect("first stream operation"), 6);
        assert_eq!(grep.execute(haystack).expect("steady stream operation"), 6);
    }

    #[test]
    fn scalar_capture_grep_lf_scan_shares_one_work_cap() {
        let defaults = RunLimits::default();
        let patterns = [r"(\p{L}{14})|(\p{L}{13})|(\p{L}{12})|(\p{L}{11})|(\p{L}{10})|(\p{L}{9})|(\p{L}{8})|(\p{L}{7})|(\p{L}{6})|(\p{L}{5})".to_string()];
        let fixture = b"aaaaaaaaaaaaaa";
        let selected = fre_reducer(
            CandidateRequest {
                job_id: "test/scalar-grep-plan",
                model: "grep-captures",
                patterns: &patterns,
                haystack: fixture,
                unicode: true,
                case_insensitive: false,
            },
            &defaults,
        )
        .expect("scalar capture plan");
        assert_eq!(selected.plan, CURRENT_FRE_CAPTURE_SCALAR_PLAN);
        let (regex, participating) = uniform_capture_scalar_regex(
            CandidateRequest {
                job_id: "test/scalar-grep-line-preflight",
                model: "grep-captures",
                patterns: &patterns,
                haystack: fixture,
                unicode: true,
                case_insensitive: false,
            },
            &defaults,
        )
        .expect("scalar capture fixture");
        assert_eq!(participating, 1);
        let upstream =
            rust_compile_options(&patterns, true, false).expect("upstream scalar capture fixture");

        for bytes in [64, 128, 256] {
            let no_lines = vec![b'a'; bytes];
            let many_lines = (0..bytes)
                .map(|index| if index.is_multiple_of(2) { b'a' } else { b'\n' })
                .collect::<Vec<_>>();
            let structural_work = count_run_limits_with_policy(bytes, &regex, &defaults)
                .unwrap()
                .unicode_scalar
                .max_work;
            let exact_work = structural_work.checked_add(bytes).unwrap();
            for haystack in [&no_lines, &many_lines] {
                let exact = RunLimits {
                    fre_aggregate_operation_work: exact_work,
                    fre_aggregate_sequential_bytes: bytes,
                    ..RunLimits::default()
                };
                let expected = grep_captures(&upstream, haystack, u64::MAX)
                    .expect("upstream grep-captures result");
                assert_eq!(
                    execute_uniform_capture_scalar(&regex, participating, haystack, true, &exact,)
                        .unwrap(),
                    expected
                );

                let work_one_below = RunLimits {
                    fre_aggregate_operation_work: exact_work - 1,
                    ..exact.clone()
                };
                let work = execute_uniform_capture_scalar(
                    &regex,
                    participating,
                    haystack,
                    true,
                    &work_one_below,
                )
                .unwrap_err();
                assert_eq!(work.status, Status::Unsupported, "{work:?}");

                let sequential_one_below = RunLimits {
                    fre_aggregate_sequential_bytes: bytes - 1,
                    ..exact.clone()
                };
                let sequential = execute_uniform_capture_scalar(
                    &regex,
                    participating,
                    haystack,
                    true,
                    &sequential_one_below,
                )
                .unwrap_err();
                assert_eq!(sequential.status, Status::Unsupported, "{sequential:?}");
            }
        }
    }

    #[test]
    fn transformed_haystack_recipe_is_ordered_and_bounded() {
        let options = HaystackTransforms {
            utf8_lossy: false,
            trim: true,
            line_start: Some(1),
            line_end: Some(2),
            repeat: Some(2),
            prepend: Some("<".to_string()),
            append: Some(">".to_string()),
        };
        assert_eq!(
            transform_haystack(b"  a\nb\nc  ", &options, 100).expect("transform"),
            b"<b\nb\n>"
        );
        assert!(transform_haystack(b"abc", &options, 2).is_err());
    }

    #[test]
    fn klv_encoding_has_exact_rebar_field_order() {
        let job = synthetic_job("count", 1);
        let loaded = LoadedJob {
            patterns: vec!["a".to_string()],
            haystack: Arc::from(&b"a"[..]),
        };
        let encoded = encode_klv(&job, &loaded).expect("KLV");
        assert!(encoded.starts_with(b"name:10:test/count\nmodel:5:count\n"));
        assert!(encoded.ends_with(b"pattern:1:a\nhaystack:1:a\n"));
    }

    #[test]
    fn status_coverage_is_deterministic() {
        let job = synthetic_job("count", 1);
        let receipts = vec![
            receipt(&job, "a", Status::Pass, Some(1), None),
            receipt(&job, "b", Status::Unsupported, None, Some("no".to_string())),
        ];
        let first = coverage(&receipts).expect("coverage");
        let second = coverage(&receipts).expect("coverage");
        assert_eq!(first, second);
        assert_eq!(first.total, 2);
    }

    #[test]
    fn pattern_sequence_uses_u64_little_endian_lengths() {
        let encoded = encode_pattern_sequence(&["ab".to_string()]).expect("encode");
        assert_eq!(&encoded[..8], &2u64.to_le_bytes());
        assert_eq!(&encoded[8..], b"ab");
    }

    #[test]
    fn report_serialization_and_path_admission_are_deterministic() {
        let report = Report {
            schema: REPORT_SCHEMA.to_string(),
            input_schema: "fixture".to_string(),
            manifest_sha256: "00".to_string(),
            rebar_revision: "fixture".to_string(),
            adapters: Vec::new(),
            coverage: Coverage::default(),
            receipts_sha256: sha256(b"[]"),
            receipts: Vec::new(),
            klv_differentials: Vec::new(),
        };
        assert_eq!(
            report_bytes(&report).expect("serialize once"),
            report_bytes(&report).expect("serialize twice")
        );
        assert!(safe_join(Path::new("root"), "../escape").is_err());
        assert!(safe_join(Path::new("root"), "/absolute").is_err());
        assert_eq!(
            safe_join(Path::new("root"), "blobs/item").expect("safe path"),
            Path::new("root/blobs/item")
        );
    }

    fn current_fre(
        model: &str,
        patterns: &[String],
        haystack: &[u8],
        unicode: bool,
        case_insensitive: bool,
        limits: &RunLimits,
    ) -> CandidateOutcome {
        CurrentFreAdapter.execute(
            CandidateRequest {
                job_id: "synthetic/current-fre",
                model,
                patterns,
                haystack,
                unicode,
                case_insensitive,
            },
            limits,
        )
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "test helper deliberately consumes temporary adapter outcomes"
    )]
    fn assert_current_fre_execution(outcome: CandidateOutcome, expected: u64, plan: &str) {
        assert_eq!(
            outcome,
            CandidateOutcome::ExecutedWithPlan {
                actual: expected,
                plan: plan.to_string(),
            }
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven test closes all seven fixed-domain route contracts"
    )]
    fn current_fre_fixed_absolute_adapter_covers_all_seven_generic_routes() {
        struct Case {
            model: &'static str,
            pattern: &'static str,
            haystack: Vec<u8>,
            unicode: bool,
            expected: u64,
        }

        let cases = [
            Case {
                model: "count-spans",
                pattern: "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$",
                haystack: b"XABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec(),
                unicode: false,
                expected: 27,
            },
            Case {
                model: "count-spans",
                pattern: r"\w$",
                haystack: b"a".to_vec(),
                unicode: false,
                expected: 1,
            },
            Case {
                model: "count-spans",
                pattern: r"[a-z]*XYZ$",
                haystack: b"!abcXYZ".to_vec(),
                unicode: false,
                expected: 6,
            },
            Case {
                model: "count",
                pattern: r"^a{2,5}$",
                haystack: b"aaaa".to_vec(),
                unicode: false,
                expected: 1,
            },
            Case {
                model: "count",
                pattern: r"^((aaa)|(aa))$",
                haystack: b"aaa".to_vec(),
                unicode: false,
                expected: 1,
            },
            Case {
                model: "count-spans",
                pattern: r"^zbc(d|e)",
                haystack: b"zbcd-tail".to_vec(),
                unicode: false,
                expected: 4,
            },
            Case {
                model: "count",
                pattern: r"^.{249}$",
                haystack: vec![b'a'; 249],
                unicode: true,
                expected: 1,
            },
        ];

        for case in cases {
            let patterns = [case.pattern.to_string()];
            assert_current_fre_execution(
                current_fre(
                    case.model,
                    &patterns,
                    &case.haystack,
                    case.unicode,
                    false,
                    &RunLimits::default(),
                ),
                case.expected,
                "aggregate-fixed-absolute-domain",
            );
            let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
                case.model,
                &patterns,
                case.unicode,
                false,
                case.haystack.len(),
            )
            .expect("fixed absolute-domain lifecycle builds");
            assert_eq!(lifecycle.plan(), "aggregate-fixed-absolute-domain");
            if case.pattern == r"^.{249}$" {
                let CurrentFreAggregateOperationInner::CountSingle(regex, limits) =
                    &lifecycle.inner
                else {
                    panic!("scalar fixed-domain lifecycle is not single-pattern Count")
                };
                let guard = regex
                    .fixed_absolute_domain_full_window_prospective(case.haystack.len())
                    .expect("scalar guard query")
                    .expect("scalar guard prospective");
                assert_eq!(
                    guard.disposition,
                    fre::FixedAbsoluteDomainDisposition::PrepublishedContinuation
                );
                let composite = regex
                    .fixed_absolute_domain_full_window_composite_prospective(case.haystack.len())
                    .expect("scalar composite query")
                    .expect("scalar composite prospective");
                assert_eq!(
                    limits.fixed_absolute_residual,
                    fre::AggregateFixedAbsoluteDomainResidualLimits {
                        max_work: composite.total_work,
                        max_allocations: composite.allocations,
                        max_persistent_bytes: composite.persistent_bytes,
                        max_peak_bytes: composite.peak_bytes,
                    }
                );
                let execution = regex
                    .count(&case.haystack, *limits)
                    .expect("scalar residual execution");
                let fre::AggregateExecutionDetails::FixedAbsoluteDomain(
                    fre::AggregateFixedAbsoluteDomainExecutionDetails::Residual {
                        composite: receipt,
                        ..
                    },
                ) = execution.report().details()
                else {
                    panic!("in-envelope scalar execution lacks residual receipt")
                };
                assert_eq!(receipt.prospective, composite);
                assert!(receipt.contains_actual());
            }
            assert_eq!(
                lifecycle.execute(&case.haystack).expect("first"),
                case.expected
            );
            assert_eq!(
                lifecycle.execute(&case.haystack).expect("steady"),
                case.expected
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one authenticated table keeps the exact thirteen imported Rebar shapes and lifecycle checks together"
    )]
    fn current_fre_fixed_absolute_adapter_covers_thirteen_target_lifecycle_shapes() {
        struct Case {
            id: &'static str,
            model: &'static str,
            pattern: &'static str,
            haystack: Vec<u8>,
            unicode: bool,
            expected: u64,
        }

        fn endpoint(length: usize, suffix: &[u8]) -> Vec<u8> {
            let mut haystack = vec![b'!'; length];
            haystack[length - suffix.len()..].copy_from_slice(suffix);
            haystack
        }

        fn assert_exact_limits(
            limits: &fre::AggregateRunLimits,
            prospective: fre::FixedAbsoluteDomainProspective,
        ) {
            assert_eq!(
                limits.fixed_absolute,
                fre::FixedAbsoluteDomainReduceLimits {
                    max_byte_probes: prospective.byte_probes,
                    max_branch_checks: prospective.branch_checks,
                    max_match_events: prospective.match_events,
                    max_count: prospective.count,
                    max_span_sum: prospective.span_sum,
                    max_reducer_steps: prospective.reducer_steps,
                    max_total_work: prospective.total_work,
                    max_scratch_bytes: prospective.scratch_bytes,
                    max_persistent_bytes: prospective.persistent_bytes,
                    max_peak_bytes: prospective.peak_bytes,
                }
            );
        }

        fn assert_guard(
            details: &fre::AggregateExecutionDetails,
            prospective: fre::FixedAbsoluteDomainProspective,
            composite_prospective: Option<fre::AggregateFixedAbsoluteDomainResidualProspective>,
            limits: &fre::AggregateRunLimits,
            haystack_len: usize,
        ) {
            let fre::AggregateExecutionDetails::FixedAbsoluteDomain(details) = details else {
                panic!("fixed absolute-domain lifecycle lacks fixed execution details")
            };
            match details {
                fre::AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard } => {
                    assert!(composite_prospective.is_none());
                    assert_eq!(
                        limits.fixed_absolute_residual,
                        fre::AggregateFixedAbsoluteDomainResidualLimits::default()
                    );
                    assert_eq!(guard.prospective, prospective);
                    assert!(guard.actual.fits(prospective));
                    assert_eq!(guard.window.start(), 0);
                    assert_eq!(guard.window.end(), haystack_len);
                    assert_eq!(guard.haystack_len, haystack_len);
                }
                fre::AggregateFixedAbsoluteDomainExecutionDetails::Residual { composite } => {
                    assert_eq!(
                        prospective.disposition,
                        fre::FixedAbsoluteDomainDisposition::PrepublishedContinuation
                    );
                    assert_eq!(composite_prospective, Some(composite.prospective));
                    assert!(composite.contains_actual());
                    assert_eq!(
                        limits.fixed_absolute_residual,
                        fre::AggregateFixedAbsoluteDomainResidualLimits {
                            max_work: composite.prospective.total_work,
                            max_allocations: composite.prospective.allocations,
                            max_persistent_bytes: composite.prospective.persistent_bytes,
                            max_peak_bytes: composite.prospective.peak_bytes,
                        }
                    );
                }
            }
        }

        const MEDIUM: &str = "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$";
        const EASY_19: &str = "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$";
        let cases = vec![
            Case {
                id: "imported/rsc/medium-1mb@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: MEDIUM,
                haystack: endpoint(1_048_603, b"XABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                unicode: false,
                expected: 27,
            },
            Case {
                id: "imported/rsc/medium-1mb@rust/regex::first-public-operation",
                model: "count-spans",
                pattern: MEDIUM,
                haystack: endpoint(1_048_603, b"XABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                unicode: false,
                expected: 27,
            },
            Case {
                id: "imported/rsc/easy1-1mb@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: EASY_19,
                haystack: endpoint(1_048_595, b"AABCCCDEEEFGGHHHIJJ"),
                unicode: false,
                expected: 19,
            },
            Case {
                id: "imported/rsc/easy1-1mb@rust/regex::first-public-operation",
                model: "count-spans",
                pattern: EASY_19,
                haystack: endpoint(1_048_595, b"AABCCCDEEEFGGHHHIJJ"),
                unicode: false,
                expected: 19,
            },
            Case {
                id: "opt/reverse-anchored/word-end@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: r"\w$",
                haystack: endpoint(1_000_001, b"X"),
                unicode: false,
                expected: 1,
            },
            Case {
                id: "imported/rsc/medium-32k@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: MEDIUM,
                haystack: endpoint(32_795, b"XABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                unicode: false,
                expected: 27,
            },
            Case {
                id: "imported/rsc/easy1-32k@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: EASY_19,
                haystack: endpoint(32_787, b"AABCCCDEEEFGGHHHIJJ"),
                unicode: false,
                expected: 19,
            },
            Case {
                id: "imported/rsc/medium-1k@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: MEDIUM,
                haystack: endpoint(1_051, b"XABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                unicode: false,
                expected: 27,
            },
            Case {
                id: "imported/rsc/easy1-1k@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: EASY_19,
                haystack: endpoint(1_043, b"AABCCCDEEEFGGHHHIJJ"),
                unicode: false,
                expected: 19,
            },
            Case {
                id: "opt/fixed-length/go33484-1@rust/regex::steady-public-operation",
                model: "count",
                pattern: r"^a{2,5}$",
                haystack: vec![b'a'; 10_000],
                unicode: false,
                expected: 0,
            },
            Case {
                id: "opt/fixed-length/go33484-2@rust/regex::steady-public-operation",
                model: "count",
                pattern: r"^((aaa)|(aa))$",
                haystack: vec![b'a'; 10_000],
                unicode: false,
                expected: 0,
            },
            Case {
                id: "opt/fixed-length/go33484-3@rust/regex::steady-public-operation",
                model: "count",
                pattern: r"^.{249}$",
                haystack: vec![b'a'; 1_000],
                unicode: true,
                expected: 0,
            },
            Case {
                id: "imported/rsc/anchored-literal-long-non-match@rust/regex::steady-public-operation",
                model: "count-spans",
                pattern: r"^zbc(d|e)",
                haystack: (b'a'..=b'z').cycle().take(390).collect(),
                unicode: false,
                expected: 0,
            },
        ];

        assert_eq!(cases.len(), 13);
        for case in cases {
            let patterns = [case.pattern.to_string()];
            assert_current_fre_execution(
                current_fre(
                    case.model,
                    &patterns,
                    &case.haystack,
                    case.unicode,
                    false,
                    &RunLimits::default(),
                ),
                case.expected,
                "aggregate-fixed-absolute-domain",
            );
            let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
                case.model,
                &patterns,
                case.unicode,
                false,
                case.haystack.len(),
            )
            .unwrap_or_else(|error| panic!("{} lifecycle build: {error}", case.id));
            assert_eq!(
                lifecycle.plan(),
                "aggregate-fixed-absolute-domain",
                "{}",
                case.id
            );
            match &lifecycle.inner {
                CurrentFreAggregateOperationInner::CountSingle(regex, limits) => {
                    assert_eq!(case.model, "count", "{}", case.id);
                    assert_eq!(
                        current_fre_rebar_count_run_limits(case.haystack.len(), regex)
                            .unwrap_or_else(|error| {
                                panic!("{} non-raw runner limits: {error}", case.id)
                            }),
                        *limits,
                        "{}",
                        case.id
                    );
                    let prospective = regex
                        .fixed_absolute_domain_full_window_prospective(case.haystack.len())
                        .unwrap_or_else(|error| panic!("{} prospective: {error}", case.id))
                        .unwrap_or_else(|| panic!("{} missing prospective", case.id));
                    let composite_prospective = regex
                        .fixed_absolute_domain_full_window_composite_prospective(
                            case.haystack.len(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("{} composite prospective: {error}", case.id)
                        });
                    assert_exact_limits(limits, prospective);
                    let identity = regex.cache_identity(*limits);
                    let first = regex
                        .count(&case.haystack, *limits)
                        .unwrap_or_else(|error| panic!("{} first: {error}", case.id));
                    let steady = regex
                        .count(&case.haystack, *limits)
                        .unwrap_or_else(|error| panic!("{} steady: {error}", case.id));
                    assert_eq!(first.value(), case.expected, "{}", case.id);
                    assert_eq!(steady.value(), case.expected, "{}", case.id);
                    assert_eq!(first.report().identity(), &identity, "{}", case.id);
                    assert_eq!(steady.report(), first.report(), "{}", case.id);
                    assert!(std::sync::Arc::ptr_eq(
                        &identity.syntax_key,
                        &first.report().identity().syntax_key
                    ));
                    assert_guard(
                        first.report().details(),
                        prospective,
                        composite_prospective,
                        limits,
                        case.haystack.len(),
                    );
                }
                CurrentFreAggregateOperationInner::SpanSumSingle(regex, limits) => {
                    assert_eq!(case.model, "count-spans", "{}", case.id);
                    assert_eq!(
                        current_fre_rebar_span_sum_run_limits(case.haystack.len(), regex)
                            .unwrap_or_else(|error| {
                                panic!("{} non-raw runner limits: {error}", case.id)
                            }),
                        *limits,
                        "{}",
                        case.id
                    );
                    let prospective = regex
                        .fixed_absolute_domain_full_window_prospective(case.haystack.len())
                        .unwrap_or_else(|error| panic!("{} prospective: {error}", case.id))
                        .unwrap_or_else(|| panic!("{} missing prospective", case.id));
                    let composite_prospective = regex
                        .fixed_absolute_domain_full_window_composite_prospective(
                            case.haystack.len(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("{} composite prospective: {error}", case.id)
                        });
                    assert_exact_limits(limits, prospective);
                    let identity = regex.cache_identity(*limits);
                    let first = regex
                        .span_sum(&case.haystack, *limits)
                        .unwrap_or_else(|error| panic!("{} first: {error}", case.id));
                    let steady = regex
                        .span_sum(&case.haystack, *limits)
                        .unwrap_or_else(|error| panic!("{} steady: {error}", case.id));
                    assert_eq!(first.value(), case.expected, "{}", case.id);
                    assert_eq!(steady.value(), case.expected, "{}", case.id);
                    assert_eq!(first.report().identity(), &identity, "{}", case.id);
                    assert_eq!(steady.report(), first.report(), "{}", case.id);
                    assert!(std::sync::Arc::ptr_eq(
                        &identity.syntax_key,
                        &first.report().identity().syntax_key
                    ));
                    assert_guard(
                        first.report().details(),
                        prospective,
                        composite_prospective,
                        limits,
                        case.haystack.len(),
                    );
                }
                CurrentFreAggregateOperationInner::CountMany(_, _)
                | CurrentFreAggregateOperationInner::SpanSumMany(_, _) => {
                    panic!(
                        "{} unexpectedly selected a multi-pattern lifecycle",
                        case.id
                    )
                }
            }
            assert_eq!(
                lifecycle
                    .execute(&case.haystack)
                    .unwrap_or_else(|error| panic!("{} runner first: {error}", case.id)),
                case.expected,
                "{}",
                case.id
            );
            assert_eq!(
                lifecycle
                    .execute(&case.haystack)
                    .unwrap_or_else(|error| panic!("{} runner steady: {error}", case.id)),
                case.expected,
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn current_fre_bounded_affix_receipt_label_binds_kernel_route() {
        let pattern = r"\s[A-Za-z]{0,12}ing\s".to_string();
        let haystack = b" ing  walking\t";
        assert_current_fre_execution(
            current_fre(
                "count",
                std::slice::from_ref(&pattern),
                haystack,
                false,
                false,
                &RunLimits::default(),
            ),
            2,
            "aggregate-bounded-affix",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &[pattern],
                haystack,
                false,
                false,
                &RunLimits::default(),
            ),
            14,
            "aggregate-bounded-affix",
        );
    }

    #[test]
    fn current_fre_space_operator_capture_stream_binds_exact_limits_and_plan() {
        assert!(
            CurrentFreAdapter
                .identity()
                .identity
                .contains("four exact-HIR allocation-free Ruff line-stream configurations")
        );
        let patterns = [SPACE_AROUND_OPERATOR_CAPTURE_PATTERN.to_string()];
        let haystack = b"x+\n\xFF++\r\nx + ";
        let upstream = rust_compile_options(&patterns, true, false).expect("upstream pattern");
        let expected = grep_captures(&upstream, haystack, u64::MAX).expect("upstream result");
        assert_eq!(expected, 9);
        assert_current_fre_execution(
            current_fre(
                "grep-captures",
                &patterns,
                haystack,
                true,
                false,
                &RunLimits::default(),
            ),
            expected,
            CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN,
        );

        let work_one_below = RunLimits {
            fre_aggregate_operation_work: 12 * haystack.len(),
            ..RunLimits::default()
        };
        assert!(matches!(
            current_fre(
                "grep-captures",
                &patterns,
                haystack,
                true,
                false,
                &work_one_below,
            ),
            CandidateOutcome::Unsupported(reason)
                if reason.contains("ExecutionWork")
                    && reason.contains(&format!("requires {}", 12 * haystack.len() + 1))
        ));
        let sequential_one_below = RunLimits {
            fre_aggregate_sequential_bytes: haystack.len() - 1,
            ..RunLimits::default()
        };
        assert!(matches!(
            current_fre(
                "grep-captures",
                &patterns,
                haystack,
                true,
                false,
                &sequential_one_below,
            ),
            CandidateOutcome::Unsupported(reason)
                if reason.contains("SequentialBytes")
                    && reason.contains(&format!("requires {}", haystack.len()))
        ));
    }

    // rebar-row:imported/mariomka/ip@rust/regex
    #[test]
    fn current_fre_bounded_separated_ip_receipt_and_hard_limits_are_exact() {
        const PATTERN: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])";
        assert_current_fre_execution(
            current_fre(
                "count",
                &[PATTERN.to_string()],
                b"10.20.30.40 xx 255.255.255.255",
                false,
                false,
                &RunLimits::default(),
            ),
            2,
            "aggregate-bounded-separated-fields",
        );

        let regex = AggregateBuilder::new(PATTERN)
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .build_count()
            .expect("assigned IP row builds");
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::BoundedSeparatedFields
        );
        let AggregateBuildAccounting::BoundedSeparatedFields(build) = regex.build_report().build
        else {
            panic!("assigned IP row retained another build receipt")
        };
        let AggregatePlanIdentity::BoundedSeparatedFields(identity) =
            regex.build_report().plan_identity
        else {
            panic!("assigned IP row retained another operation identity")
        };
        let derived = bounded_separated_fields_operation_limits(
            6_839_410,
            identity.kernel,
            build,
            &RunLimits::default(),
        )
        .expect("hard dimensions fit");
        assert_eq!(derived.max_input_bytes, 6_839_410);
        assert_eq!(derived.max_sequential_bytes, 341_970_500);
        assert_eq!(derived.max_work, 533_473_988);
        assert!(derived.max_work < RunLimits::default().fre_aggregate_operation_work);
        let one_below = bounded_separated_fields_operation_limits(
            6_839_410,
            identity.kernel,
            build,
            &RunLimits {
                fre_aggregate_operation_work: 533_473_987,
                ..RunLimits::default()
            },
        )
        .expect("capped dimensions fit");
        assert_eq!(one_below.max_work, 533_473_987);
        let one_below = bounded_separated_fields_operation_limits(
            6_839_410,
            identity.kernel,
            build,
            &RunLimits {
                fre_aggregate_sequential_bytes: 341_970_499,
                ..RunLimits::default()
            },
        )
        .expect("capped sequential dimensions fit");
        assert_eq!(one_below.max_sequential_bytes, 341_970_499);
    }

    fn assert_bounded_separated_identity_fault(result: Result<(), ExecutionError>) {
        let error = result.expect_err("forged bounded separated-field identity must fail");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("bounded separated-field aggregate identity mismatch"),
            "unexpected identity error: {error:?}"
        );
    }

    fn assert_aggregate_construction_identity_fault(result: Result<(), ExecutionError>) {
        let error = result.expect_err("forged whole-construction identity must fail");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("aggregate construction identity mismatch"),
            "unexpected construction identity error: {error:?}"
        );
    }

    fn assert_bounded_separated_closure_faults(report: &AggregateBuildReport) {
        assert!(!report.has_closed_bounded_separated_fields_identity());
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            report,
            false,
            LiteralAggregateOperation::Count,
        ));
        let error = aggregate_run_limits(usize::MAX, report, &RunLimits::default())
            .expect_err("open closure must fail before limit derivation");
        assert_eq!(error.status, Status::Fault);
        assert!(error.message.contains("public/private closure is open"));

        let error = current_fre_rebar_validate_aggregate_identity(report, false, "count")
            .expect_err("public identity wrapper must reject an open closure")
            .to_string();
        assert!(error.contains("public/private closure is open"));
        let error = current_fre_rebar_aggregate_run_limits(usize::MAX, report)
            .expect_err("public limit wrapper must reject before arithmetic")
            .to_string();
        assert!(error.contains("public/private closure is open"));
    }

    fn exact_literal_control_report() -> AggregateBuildReport {
        AggregateBuilder::new("x")
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .build_count()
            .expect("control literal builds")
            .build_report()
            .clone()
    }

    fn reject_bounded_separated_kernel<F>(base: &AggregateBuildReport, mutate: F)
    where
        F: FnOnce(&mut fre::BoundedSeparatedFieldsOperationIdentity),
    {
        let mut report = base.clone();
        let AggregatePlanIdentity::BoundedSeparatedFields(identity) = &mut report.plan_identity
        else {
            panic!("test report lost bounded separated-field identity")
        };
        mutate(&mut identity.kernel);
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
    }

    fn reject_bounded_separated_build<F>(base: &AggregateBuildReport, mutate: F)
    where
        F: FnOnce(&mut fre::BoundedSeparatedFieldsBuildAccounting),
    {
        let mut report = base.clone();
        let AggregateBuildAccounting::BoundedSeparatedFields(build) = &mut report.build else {
            panic!("test report lost bounded separated-field build accounting")
        };
        mutate(build);
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
        let error = aggregate_run_limits(31, &report, &RunLimits::default())
            .expect_err("forged build receipt must fail before limit derivation");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("bounded separated-field aggregate identity mismatch"),
            "unexpected resource identity error: {error:?}"
        );
    }

    fn reject_bounded_separated_report<F>(base: &AggregateBuildReport, mutate: F)
    where
        F: FnOnce(&mut AggregateBuildReport),
    {
        let mut report = base.clone();
        mutate(&mut report);
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
    }

    fn reject_aggregate_construction_report<F>(base: &AggregateBuildReport, mutate: F)
    where
        F: FnOnce(&mut AggregateBuildReport),
    {
        let mut report = base.clone();
        mutate(&mut report);
        assert_aggregate_construction_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
        let error = aggregate_run_limits(31, &report, &RunLimits::default())
            .expect_err("forged whole-construction identity must fail before limit derivation");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("aggregate construction identity mismatch"),
            "unexpected construction limit error: {error:?}"
        );
    }

    fn reject_bounded_separated_coherent_forgery<F>(base: &AggregateBuildReport, mutate: F)
    where
        F: FnOnce(
            &mut fre::BoundedSeparatedFieldsOperationIdentity,
            &mut fre::BoundedSeparatedFieldsBuildAccounting,
            &mut usize,
        ),
    {
        let mut report = base.clone();
        let AggregatePlanIdentity::BoundedSeparatedFields(identity) = &mut report.plan_identity
        else {
            panic!("test report lost bounded separated-field identity")
        };
        let AggregateBuildAccounting::BoundedSeparatedFields(build) = &mut report.build else {
            panic!("test report lost bounded separated-field build accounting")
        };
        mutate(
            &mut identity.kernel,
            build,
            &mut report.retained_capacity_bytes,
        );
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
        let error = aggregate_run_limits(31, &report, &RunLimits::default())
            .expect_err("coherent forgery must fail before limit derivation");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("bounded separated-field aggregate identity mismatch"),
            "unexpected coherent-forgery error: {error:?}"
        );
    }

    fn assert_bounded_separated_authentic_resource_receipt(base: &AggregateBuildReport) {
        let AggregateBuildAccounting::BoundedSeparatedFields(build) = base.build else {
            panic!("authentic report lost bounded separated-field build accounting")
        };
        let AggregatePlanIdentity::BoundedSeparatedFields(identity) = base.plan_identity else {
            panic!("authentic report lost bounded separated-field operation identity")
        };
        assert_eq!(
            build,
            fre::BoundedSeparatedFieldsBuildAccounting {
                alternatives: 3,
                atoms: 9,
                optional_atoms: 1,
                source_ranges: 9,
                fields: 4,
                separator: b'.',
                minimum_field_width: 2,
                maximum_field_width: 3,
                structural_work: 320,
                range_inspections: 9,
                bitmap_zero_writes: 164,
                bitmap_word_writes: 9,
                separator_comparisons: 9,
                work_bound: 392,
                allocations: 0,
                reserves: 0,
                temporary_copies: 1,
                scratch_bytes: build.scratch_bytes,
                persistent_bytes: build.persistent_bytes,
                peak_bytes: build.peak_bytes,
            }
        );
        assert_eq!(
            build.persistent_bytes.checked_add(build.scratch_bytes),
            Some(build.peak_bytes)
        );
        assert_eq!(identity.kernel.build_accounting(), build);
        assert_eq!(identity.kernel.exact_field_checks(), 9);
        assert_eq!(identity.kernel.prefix_field_checks(), 11);
    }

    fn reject_bounded_separated_kernel_forgeries(base: &AggregateBuildReport) {
        reject_bounded_separated_kernel(base, |kernel| kernel.plan_id = "forged-plan");
        reject_bounded_separated_kernel(base, |kernel| kernel.operation_id = "forged-operation");
        reject_bounded_separated_kernel(base, |kernel| kernel.separator = b'/');
        for fields in [3, 1, 9] {
            reject_bounded_separated_kernel(base, move |kernel| kernel.fields = fields);
        }
        for alternatives in [2, 0, 9] {
            reject_bounded_separated_kernel(base, move |kernel| {
                kernel.alternatives = alternatives;
            });
        }
        for minimum in [1, 4] {
            reject_bounded_separated_kernel(base, move |kernel| {
                kernel.minimum_field_width = minimum;
            });
        }
        for maximum in [4, 0, 5] {
            reject_bounded_separated_kernel(base, move |kernel| {
                kernel.maximum_field_width = maximum;
            });
        }
        reject_bounded_separated_kernel(base, |kernel| kernel.greedy = false);
        reject_bounded_separated_kernel(base, |kernel| kernel.non_overlapping = false);
    }

    fn reject_bounded_separated_build_forgeries(base: &AggregateBuildReport) {
        reject_bounded_separated_build(base, |build| build.separator = b'/');
        reject_bounded_separated_build(base, |build| build.fields = 3);
        reject_bounded_separated_build(base, |build| build.alternatives = 2);
        reject_bounded_separated_build(base, |build| build.atoms = 8);
        reject_bounded_separated_build(base, |build| build.optional_atoms = 0);
        reject_bounded_separated_build(base, |build| build.source_ranges = 8);
        reject_bounded_separated_build(base, |build| build.minimum_field_width = 1);
        reject_bounded_separated_build(base, |build| build.maximum_field_width = 4);
        reject_bounded_separated_build(base, |build| build.structural_work = 319);
        reject_bounded_separated_build(base, |build| build.range_inspections = 8);
        reject_bounded_separated_build(base, |build| build.bitmap_zero_writes = 163);
        reject_bounded_separated_build(base, |build| build.bitmap_word_writes = 8);
        reject_bounded_separated_build(base, |build| build.separator_comparisons = 8);
        reject_bounded_separated_build(base, |build| build.work_bound = 391);
        reject_bounded_separated_build(base, |build| build.allocations = 1);
        reject_bounded_separated_build(base, |build| build.reserves = 1);
        reject_bounded_separated_build(base, |build| build.temporary_copies = 0);
        reject_bounded_separated_build(base, |build| {
            build.scratch_bytes = build.scratch_bytes.checked_sub(1).unwrap();
        });
        reject_bounded_separated_build(base, |build| {
            build.persistent_bytes = build.persistent_bytes.checked_sub(1).unwrap();
        });
        reject_bounded_separated_build(base, |build| {
            build.peak_bytes = build.peak_bytes.checked_sub(1).unwrap();
        });
    }

    fn reject_bounded_separated_coherent_forgeries(base: &AggregateBuildReport) {
        reject_bounded_separated_coherent_forgery(base, |kernel, build, _| {
            kernel.separator = b'/';
            build.separator = b'/';
        });
        reject_bounded_separated_coherent_forgery(base, |kernel, build, _| {
            kernel.fields = 3;
            build.fields = 3;
        });
        reject_bounded_separated_coherent_forgery(base, |kernel, build, _| {
            kernel.alternatives = 2;
            build.alternatives = 2;
        });
        reject_bounded_separated_coherent_forgery(base, |kernel, build, _| {
            kernel.minimum_field_width = 1;
            build.minimum_field_width = 1;
        });
        reject_bounded_separated_coherent_forgery(base, |kernel, build, _| {
            kernel.maximum_field_width = 4;
            build.maximum_field_width = 4;
        });
        reject_bounded_separated_coherent_forgery(base, |_, build, _| {
            build.atoms = 8;
            build.bitmap_zero_writes = 160;
            build.separator_comparisons = 8;
            build.work_bound = 391;
        });
        reject_bounded_separated_coherent_forgery(base, |_, build, _| {
            build.source_ranges = 8;
            build.range_inspections = 8;
            build.bitmap_word_writes = 8;
            build.work_bound = 385;
        });
        reject_bounded_separated_coherent_forgery(base, |_, build, _| {
            build.structural_work = 319;
            build.work_bound = 391;
        });
        reject_bounded_separated_coherent_forgery(base, |_, build, _| {
            build.scratch_bytes = build.scratch_bytes.checked_sub(1).unwrap();
            build.peak_bytes = build.peak_bytes.checked_sub(1).unwrap();
        });
        reject_bounded_separated_coherent_forgery(base, |_, build, retained| {
            build.persistent_bytes = build.persistent_bytes.checked_sub(1).unwrap();
            build.peak_bytes = build.peak_bytes.checked_sub(1).unwrap();
            *retained = retained.checked_sub(1).unwrap();
        });
    }

    fn reject_bounded_separated_report_forgeries(base: &AggregateBuildReport) {
        let other = exact_literal_control_report();
        reject_bounded_separated_report(base, |report| report.plan = other.plan);
        reject_bounded_separated_report(base, |report| report.build = other.build);
        reject_bounded_separated_report(base, |report| {
            report.plan_identity = other.plan_identity;
        });
        reject_bounded_separated_report(base, |report| {
            report.retained_capacity_bytes = report.retained_capacity_bytes.saturating_add(1);
        });
        reject_aggregate_construction_report(base, |report| {
            report.selection = AggregatePlanSelection::ForceContinuation;
        });
        reject_aggregate_construction_report(base, |report| {
            report.continuation_strategy = Some(AggregateStrategy::ReverseSequentialRows);
        });
        reject_aggregate_construction_report(base, |report| {
            report.operation = AggregateOperation::SpanSum;
        });
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            base,
            false,
            LiteralAggregateOperation::SpanSum,
        ));
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            base,
            true,
            LiteralAggregateOperation::Count,
        ));
    }

    fn reject_bounded_separated_whole_certificate_splice(base: &AggregateBuildReport) {
        let smaller = AggregateBuilder::new(
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01][0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01][0-9][0-9])",
        )
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .build_count()
            .expect("smaller bounded separated-field control builds")
            .build_report()
            .clone();
        assert_eq!(smaller.plan, AggregatePlanKind::BoundedSeparatedFields);
        assert_ne!(base.syntax_key, smaller.syntax_key);

        let mut report = base.clone();
        report.plan_identity = smaller.plan_identity;
        report.build = smaller.build;
        report.retained_capacity_bytes = smaller.retained_capacity_bytes;
        assert_bounded_separated_identity_fault(require_unicode_plan_identity(
            &report,
            false,
            LiteralAggregateOperation::Count,
        ));
        let error = aggregate_run_limits(31, &report, &RunLimits::default())
            .expect_err("whole-certificate splice must fail before limit derivation");
        assert_eq!(error.status, Status::Fault);
        assert!(
            error
                .message
                .contains("bounded separated-field aggregate identity mismatch"),
            "unexpected whole-certificate splice error: {error:?}"
        );
    }

    fn reject_bounded_separated_cross_family_closure(base: &AggregateBuildReport) {
        let exact = exact_literal_control_report();
        assert!(base.has_closed_bounded_separated_fields_identity());
        assert!(exact.has_closed_bounded_separated_fields_identity());
        require_unicode_plan_identity(&exact, false, LiteralAggregateOperation::Count)
            .expect("authentic exact-literal identity remains closed");
        aggregate_run_limits(31, &exact, &RunLimits::default())
            .expect("authentic exact-literal limits remain derivable");
        current_fre_rebar_validate_aggregate_identity(&exact, false, "count")
            .expect("public identity wrapper accepts the exact-literal control");
        current_fre_rebar_aggregate_run_limits(31, &exact)
            .expect("public limit wrapper accepts the exact-literal control");

        let mut three_field = base.clone();
        three_field.plan = exact.plan;
        three_field.build = exact.build;
        three_field.plan_identity = exact.plan_identity;
        assert_bounded_separated_closure_faults(&three_field);

        let mut whole_public_certificate = base.clone();
        whole_public_certificate.syntax_key = exact.syntax_key.clone();
        whole_public_certificate.admission = exact.admission;
        whole_public_certificate.syntax = exact.syntax.clone();
        whole_public_certificate.plan = exact.plan;
        whole_public_certificate.build = exact.build;
        whole_public_certificate.plan_identity = exact.plan_identity;
        whole_public_certificate.retained_capacity_bytes = exact.retained_capacity_bytes;
        assert_bounded_separated_closure_faults(&whole_public_certificate);

        let mut reverse_missing_seal = exact;
        reverse_missing_seal.plan = base.plan;
        reverse_missing_seal.build = base.build;
        reverse_missing_seal.plan_identity = base.plan_identity;
        assert_bounded_separated_closure_faults(&reverse_missing_seal);

        let mut reverse_matching_public_certificate = reverse_missing_seal;
        reverse_matching_public_certificate.retained_capacity_bytes = base.retained_capacity_bytes;
        assert_bounded_separated_closure_faults(&reverse_matching_public_certificate);
    }

    #[test]
    fn current_fre_bounded_separated_identity_is_fail_closed() {
        const PATTERN: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])";

        let regex = AggregateBuilder::new(PATTERN)
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .build_count()
            .expect("assigned IP row builds");
        let base = regex.build_report().clone();
        assert!(base.has_closed_bounded_separated_fields_identity());
        require_unicode_plan_identity(&base, false, LiteralAggregateOperation::Count)
            .expect("authentic bounded separated-field identity");
        assert_bounded_separated_authentic_resource_receipt(&base);
        reject_bounded_separated_kernel_forgeries(&base);
        reject_bounded_separated_build_forgeries(&base);
        reject_bounded_separated_coherent_forgeries(&base);
        reject_bounded_separated_report_forgeries(&base);
        reject_bounded_separated_whole_certificate_splice(&base);
        reject_bounded_separated_cross_family_closure(&base);
    }

    // rebar-row:imported/mariomka/ip@rust/regex
    #[test]
    #[ignore = "requires FRE_BOUNDED_SEPARATED_FIELDS_HARD_CORPUS"]
    fn current_fre_bounded_separated_ip_hard_no_clock_canary() {
        const PATTERN: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])";
        let path = std::env::var_os("FRE_BOUNDED_SEPARATED_FIELDS_HARD_CORPUS")
            .expect("FRE_BOUNDED_SEPARATED_FIELDS_HARD_CORPUS names the authenticated corpus");
        let haystack = fs::read(path).expect("hard corpus is readable");
        assert_eq!(haystack.len(), 6_839_410);
        assert_eq!(
            sha256(&haystack),
            "7b7f70c9ca999b2bede85b7ed8e37c9193edced196f4aed29651e37ef4f8e979"
        );
        let patterns = [PATTERN.to_string()];
        for limits in [
            RunLimits::default(),
            RunLimits {
                fre_aggregate_operation_work: 533_473_988,
                ..RunLimits::default()
            },
            RunLimits {
                fre_aggregate_sequential_bytes: 341_970_500,
                ..RunLimits::default()
            },
        ] {
            assert_current_fre_execution(
                current_fre("count", &patterns, &haystack, false, false, &limits),
                5,
                "aggregate-bounded-separated-fields",
            );
        }
        let refusal = current_fre(
            "count",
            &patterns,
            &haystack,
            false,
            false,
            &RunLimits {
                fre_aggregate_operation_work: 533_473_987,
                ..RunLimits::default()
            },
        );
        assert!(
            matches!(refusal, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("WorkLimit")
                    && reason.contains("533473988")
                    && reason.contains("533473987")),
            "one-below hard work must be a typed refusal: {refusal:?}"
        );
        let refusal = current_fre(
            "count",
            &patterns,
            &haystack,
            false,
            false,
            &RunLimits {
                fre_aggregate_sequential_bytes: 341_970_499,
                ..RunLimits::default()
            },
        );
        assert!(
            matches!(refusal, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("SequentialLimit")
                    && reason.contains("341970500")
                    && reason.contains("341970499")),
            "one-below hard sequential input access must be a typed refusal: {refusal:?}"
        );
    }
    #[test]
    #[ignore = "requires FRE_TEST_URL_PATTERN to name the authenticated Rebar URL pattern"]
    #[allow(
        clippy::too_many_lines,
        reason = "one authenticated URL transaction covers route gating, exported bounds, and typed one-below refusals"
    )]
    fn current_fre_url_identity_and_route_label_are_fail_closed() {
        let path = std::env::var_os("FRE_TEST_URL_PATTERN")
            .expect("FRE_TEST_URL_PATTERN must name wild/url.txt");
        let source = std::fs::read_to_string(path).unwrap();
        let source = source.trim_end();

        let count = current_fre_rebar_aggregate_builder(source, false, true)
            .build_count()
            .unwrap();
        let count_report = count.build_report();
        assert!(count_report.has_closed_url_aggregate_identity());
        assert!(count_report.authenticates_url_aggregate_identity());
        current_fre_rebar_validate_aggregate_identity(count_report, false, "count").unwrap();
        assert_eq!(
            aggregate_single_plan_label("count", count_report),
            "aggregate-url"
        );

        let span_sum = current_fre_rebar_aggregate_builder(source, false, true)
            .build_span_sum()
            .unwrap();
        let span_sum_report = span_sum.build_report();
        assert!(span_sum_report.has_closed_url_aggregate_identity());
        assert_eq!(
            aggregate_single_plan_label("count-spans", span_sum_report),
            "aggregate-url"
        );

        let compile = current_fre_rebar_aggregate_builder(source, false, true)
            .build_compile()
            .unwrap();
        assert_eq!(
            aggregate_single_plan_label("compile", compile.build_report()),
            "compile-aggregate-url"
        );

        let dormant = current_fre_rebar_aggregate_builder(source, false, true)
            .strategy(AggregateStrategy::FullTable)
            .build_span_sum()
            .unwrap();
        assert!(dormant.build_report().has_closed_url_aggregate_identity());
        assert!(
            dormant
                .build_report()
                .authenticates_url_aggregate_identity()
        );
        assert_eq!(
            aggregate_single_plan_label("count-spans", dormant.build_report()),
            "aggregate-continuation-program"
        );

        let mut long_segment = vec![b'a'; 600 * 1_024];
        long_segment.extend_from_slice(b".com");
        let upper = fre::url_aggregate_reduce_upper_bounds(long_segment.len()).unwrap();
        let policy = RunLimits::default();
        let count_limits = aggregate_run_limits(long_segment.len(), count_report, &policy).unwrap();
        let sum_limits =
            aggregate_run_limits(long_segment.len(), span_sum_report, &policy).unwrap();
        let specialized = url_aggregate_operation_limits(long_segment.len(), &policy).unwrap();
        assert_eq!(count_limits.continuation, specialized);
        assert_eq!(sum_limits.continuation, specialized);

        let AggregateBuildAccounting::Continuation(count_compile) = count_report.build else {
            panic!("URL count must retain continuation compile accounting");
        };
        let generic = continuation_operation_limits(
            long_segment.len(),
            ContinuationProgramShape::from(count_compile),
            &policy,
        )
        .unwrap();
        assert!(
            generic.max_random_access_bytes < specialized.max_random_access_bytes,
            "generic continuation storage {} must not authorize URL workspace {}",
            generic.max_random_access_bytes,
            specialized.max_random_access_bytes
        );

        let dormant_limits =
            aggregate_run_limits(long_segment.len(), dormant.build_report(), &policy).unwrap();
        let AggregateBuildAccounting::Continuation(dormant_compile) = dormant.build_report().build
        else {
            panic!("dormant URL plan must retain continuation compile accounting");
        };
        let mut dormant_shape = ContinuationProgramShape::from(dormant_compile);
        dormant_shape.required_internal_anchors = 0;
        dormant_shape.required_internal_anchor_bytes = 0;
        dormant_shape.required_internal_anchor_optional_stages = 0;
        dormant_shape.required_internal_anchor_persistent_bytes = 0;
        assert_eq!(
            dormant_limits.continuation,
            continuation_operation_limits(long_segment.len(), dormant_shape, &policy).unwrap()
        );
        assert_ne!(dormant_limits.continuation, specialized);

        let compile_limits =
            aggregate_run_limits(long_segment.len(), compile.build_report(), &policy).unwrap();
        let AggregateBuildAccounting::Continuation(compile_accounting) =
            compile.build_report().build
        else {
            panic!("URL compile route must retain continuation compile accounting");
        };
        let mut compile_shape = ContinuationProgramShape::from(compile_accounting);
        compile_shape.required_internal_anchors = 0;
        compile_shape.required_internal_anchor_bytes = 0;
        compile_shape.required_internal_anchor_optional_stages = 0;
        compile_shape.required_internal_anchor_persistent_bytes = 0;
        assert_eq!(
            compile_limits.continuation,
            continuation_operation_limits(long_segment.len(), compile_shape, &policy).unwrap()
        );
        assert_ne!(compile_limits.continuation, specialized);

        let result = count.count(&long_segment, count_limits).unwrap();
        let AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } = result.report().details()
        else {
            panic!("URL count must publish continuation execution details");
        };
        assert_eq!(
            certificate.random_access_bytes,
            upper.random_access_storage_bytes
        );
        assert_eq!(certificate.scratch_bytes, upper.scratch_bytes);
        assert_eq!(certificate.peak_bytes, upper.peak_bytes);
        assert_eq!(certificate.sequential_bytes_bound, upper.sequential_bytes);
        assert_eq!(
            accounting.random_access_peak_bytes,
            upper.random_access_storage_bytes
        );
        assert_eq!(accounting.scratch_peak_bytes, upper.scratch_bytes);
        assert_eq!(accounting.peak_bytes, upper.peak_bytes);
        assert_eq!(accounting.sequential_bytes_read, upper.sequential_bytes);

        let mut generic_limits = count_limits;
        generic_limits.continuation = generic;
        let error = count.count(&long_segment, generic_limits).unwrap_err();
        assert!(matches!(
            error.source,
            AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
                resource: AggregateResource::RandomAccessBytes,
                ..
            })
        ));

        for (resource, one_below) in [
            (
                AggregateResource::RandomAccessBytes,
                AggregateOperationLimits {
                    max_random_access_bytes: upper.random_access_storage_bytes - 1,
                    ..specialized
                },
            ),
            (
                AggregateResource::ScratchBytes,
                AggregateOperationLimits {
                    max_scratch_bytes: upper.scratch_bytes - 1,
                    ..specialized
                },
            ),
            (
                AggregateResource::PeakBytes,
                AggregateOperationLimits {
                    max_peak_bytes: upper.peak_bytes - 1,
                    ..specialized
                },
            ),
            (
                AggregateResource::SequentialBytes,
                AggregateOperationLimits {
                    max_sequential_bytes: upper.sequential_bytes - 1,
                    ..specialized
                },
            ),
        ] {
            let mut limits = count_limits;
            limits.continuation = one_below;
            let error = count.count(&long_segment, limits).unwrap_err();
            assert!(matches!(
                error.source,
                AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
                    resource: actual,
                    required,
                    limit,
                }) if actual == resource && required == limit + 1
            ));
        }

        for field in 0..5 {
            let mut forged = count_report.clone();
            let AggregateBuildAccounting::Continuation(ref mut accounting) = forged.build else {
                panic!("URL route must retain continuation accounting");
            };
            match field {
                0 => accounting.url_aggregate_plans += 1,
                1 => accounting.url_aggregate_tlds += 1,
                2 => accounting.url_aggregate_tld_bytes += 1,
                3 => accounting.url_aggregate_build_work += 1,
                4 => accounting.url_aggregate_persistent_bytes += 1,
                _ => unreachable!(),
            }
            assert!(!forged.has_closed_url_aggregate_identity());
            assert!(!forged.authenticates_url_aggregate_identity());
            assert!(
                current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err()
            );
            assert!(aggregate_run_limits(128, &forged, &RunLimits::default()).is_err());
        }

        let mut capacity_forgery = count_report.clone();
        capacity_forgery.retained_capacity_bytes += 1;
        assert!(!capacity_forgery.has_closed_url_aggregate_identity());

        let mut semantics_forgery = count_report.clone();
        let AggregatePlanIdentity::Continuation(ref mut identity) = semantics_forgery.plan_identity
        else {
            panic!("URL route must retain a continuation identity");
        };
        identity.semantics = AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir;
        assert!(!semantics_forgery.has_closed_url_aggregate_identity());

        let absent = current_fre_rebar_aggregate_builder("abc", false, false)
            .build_count()
            .unwrap();
        assert!(absent.build_report().has_closed_url_aggregate_identity());
        assert!(!absent.build_report().authenticates_url_aggregate_identity());
        let absent_continuation = current_fre_rebar_aggregate_builder("a.*b", false, false)
            .build_count()
            .unwrap();
        assert!(matches!(
            absent_continuation.build_report().build,
            AggregateBuildAccounting::Continuation(_)
        ));
        assert!(
            absent_continuation
                .build_report()
                .has_closed_url_aggregate_identity()
        );
        assert!(
            !absent_continuation
                .build_report()
                .authenticates_url_aggregate_identity()
        );
    }

    #[test]
    fn current_fre_adapter_identity_describes_every_composed_route() {
        let identity = CurrentFreAdapter.identity();
        assert_eq!(
            identity.adapter,
            "fre-current-aggregate-capture-v42-fused-capture-stream-v1-persistent-capture-participation-quotient-v1-anchored-line-capture-v1-bounded-affix-span-sum-v1-terminal-class-frontier-v1-unicode-casefold-suffix-domain-v2-required-literal-line-partition-v1-noqa-v1-portable-word-run-v2-aggregate-word-run-v1-literal-assertions-v1-blocking-delimiter-v1-token-phrase-v1-unicode-scalar-run-v4-capture-scalar-alternation-v1-line-space-operator-v2-line-configured-ruff-three-v1-line-ascii-separated-fields-v1-finite-dfa-v2-packed-v2-sparse-v1-guarded-ascii-word-v1-fixed-predicate-word64-v1-fixed-class-sandwich-v1-literal-class-run-literal-v1-bounded-literal-pair-v1-grapheme-scalar-dfa-v2-bounded-class-sequence-v1-bounded-separated-fields-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-capture-count-v3-ordered-root-count-v1-continuation-accounting-v4-uniform-prefix-class-participation-v2-required-internal-anchor-v3-structural-quota-v8-regex-redux-composite-v2-url-aggregate-v1-fixed-absolute-domain-v1-terminal-greedy-class-v1-grep-stream-v1-k0-search-session-v1"
        );
        assert!(identity.identity.contains("direct Unicode scalar-class"));
        assert!(
            identity
                .identity
                .contains("canonical terminal Unicode scalars")
        );
        assert!(
            identity
                .availability
                .contains("canonical terminal-scalar encodings")
        );
        assert!(identity.identity.contains("fixed class-sandwich"));
        assert!(identity.identity.contains("finite-packed-v2"));
        assert!(identity.availability.contains("bounded packed scanner"));
        assert!(
            identity
                .identity
                .contains("guarded finite ASCII-word dictionary")
        );
        assert!(identity.identity.contains("ASCII fixed-predicate Word64"));
        assert!(identity.identity.contains("positive-Unicode-word"));
        assert!(
            identity
                .availability
                .contains("finite nonempty ASCII-word bodies")
        );
        assert!(identity.identity.contains("aggregate-word-run-v1"));
        assert!(identity.identity.contains("anchored-line-capture-v1"));
        assert!(identity.identity.contains("bounded-affix-span-sum-v1"));
        assert!(identity.identity.contains("literal-class-run-literal-v1"));
        assert!(identity.identity.contains("bounded-literal-pair-v1"));
        assert!(
            identity
                .identity
                .contains("one checked whole-input literal stream")
        );
        assert!(
            identity
                .availability
                .contains("independent checked per-line fallback")
        );
        assert!(
            identity
                .identity
                .contains("exact-span persistent tagged-history replay")
        );
        assert!(identity.identity.contains("fused-capture-stream-v1"));
        assert!(
            identity
                .availability
                .contains("caller-owned authenticated whole-input LF/CRLF stream")
        );
    }

    #[test]
    fn current_fre_fixed_predicate_word64_covers_rebar_count_sum_compile_and_accounting() {
        let limits = RunLimits::default();
        let pattern = "Sherlock Holmes";
        let patterns = vec![pattern.to_string()];
        let haystack = b"Sherlock Holmes|SHERLOCK HOLMES|sherlock holmes|Sherlock Xolmes";

        let count = current_fre_rebar_aggregate_builder(pattern, false, true)
            .build_count()
            .expect("ASCII case-fold sequence count plan");
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64
        );
        current_fre_rebar_validate_aggregate_identity(count.build_report(), false, "count")
            .expect("closed Unicode-off Word64 identity");
        let AggregateBuildAccounting::FixedPredicateWord64(build) = count.build_report().build
        else {
            panic!("expected fixed-predicate Word64 build accounting");
        };
        assert_eq!(build.positions, 15);
        assert_eq!(build.source_ranges, 29);
        assert_eq!(
            build.mask_zero_writes,
            fre::FIXED_PREDICATE_WORD64_MASK_SLOTS
        );
        assert!(build.work_charged <= build.work_upper_bound);
        assert_eq!(build.allocations, 0);
        assert_eq!(build.scratch_bytes, 0);
        assert_eq!(build.peak_bytes, build.persistent_bytes);

        let count_limits =
            current_fre_rebar_aggregate_run_limits(haystack.len(), count.build_report())
                .expect("finite-envelope Word64 limits");
        let counted = count
            .count(haystack, count_limits)
            .expect("audited Word64 count");
        assert_eq!(counted.value(), 3);
        let AggregateExecutionDetails::FixedPredicateWord64(accounting) =
            counted.report().details()
        else {
            panic!("expected fixed-predicate Word64 execution accounting");
        };
        assert_eq!(accounting.actual.count, 3);
        assert_eq!(accounting.actual.matched_bytes, 45);
        assert!(accounting.actual.transitions <= accounting.upper_bounds.transitions);
        assert!(accounting.actual.match_events <= accounting.upper_bounds.match_events);
        assert!(accounting.actual.work_charged <= accounting.upper_bounds.work);
        assert!(accounting.actual.peak_bytes <= accounting.upper_bounds.peak_bytes);

        assert_current_fre_execution(
            current_fre("count", &patterns, haystack, false, true, &limits),
            3,
            "aggregate-fixed-predicate-word64",
        );
        assert_current_fre_execution(
            current_fre("count-spans", &patterns, haystack, false, true, &limits),
            45,
            "aggregate-fixed-predicate-word64",
        );
        assert_current_fre_execution(
            current_fre("compile", &patterns, haystack, false, true, &limits),
            3,
            "compile-aggregate-fixed-predicate-word64",
        );

        let captured = current_fre_rebar_aggregate_builder("((Sherlock Holmes))", false, true)
            .build_count()
            .expect("captured Rebar-cap Word64 retry plan");
        assert_eq!(captured.build_report().captures_erased, 2);
        assert_eq!(captured.build_report().capture_erasure_work, 6);
        current_fre_rebar_validate_aggregate_identity(captured.build_report(), false, "count")
            .expect("closed captured post-dense-retry identity");
        let captured_limits =
            current_fre_rebar_aggregate_run_limits(haystack.len(), captured.build_report())
                .expect("captured Word64 run limits");
        assert_eq!(
            captured
                .count_value(haystack, captured_limits)
                .expect("captured Word64 count"),
            3
        );

        let unicode = current_fre_rebar_aggregate_builder(pattern, true, true)
            .build_count()
            .expect("Unicode case-fold control remains supported");
        assert_ne!(
            unicode.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64
        );
    }

    #[test]
    fn current_fre_exact_literal_identity_accepts_only_authenticated_owners() {
        for semantics in [
            AggregateExactLiteralSemantics::UnicodeOffByteBoundaries,
            AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal,
        ] {
            for operation in [
                LiteralAggregateOperation::Count,
                LiteralAggregateOperation::SpanSum,
            ] {
                for kernel in [
                    fre::LiteralAggregateOperationIdentity::for_operation(operation),
                    fre::LiteralAggregateOperationIdentity::for_dispatched_operation(operation),
                ] {
                    assert!(exact_literal_plan_identity_matches(
                        fre::AggregateExactLiteralIdentity { semantics, kernel },
                        semantics,
                        operation,
                    ));
                }

                let mut forged =
                    fre::LiteralAggregateOperationIdentity::for_dispatched_operation(operation);
                forged.plan_id = "forged-exact-literal-owner";
                assert!(!exact_literal_plan_identity_matches(
                    fre::AggregateExactLiteralIdentity {
                        semantics,
                        kernel: forged,
                    },
                    semantics,
                    operation,
                ));
                let other_semantics = match semantics {
                    AggregateExactLiteralSemantics::UnicodeOffByteBoundaries => {
                        AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
                    }
                    AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal => {
                        AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
                    }
                };
                assert!(!exact_literal_plan_identity_matches(
                    fre::AggregateExactLiteralIdentity {
                        semantics: other_semantics,
                        kernel: fre::LiteralAggregateOperationIdentity::for_dispatched_operation(
                            operation,
                        ),
                    },
                    semantics,
                    operation,
                ));
                let other_operation = match operation {
                    LiteralAggregateOperation::Count => LiteralAggregateOperation::SpanSum,
                    LiteralAggregateOperation::SpanSum => LiteralAggregateOperation::Count,
                };
                assert!(!exact_literal_plan_identity_matches(
                    fre::AggregateExactLiteralIdentity {
                        semantics,
                        kernel: fre::LiteralAggregateOperationIdentity::for_dispatched_operation(
                            other_operation,
                        ),
                    },
                    semantics,
                    operation,
                ));
            }
        }
    }

    #[test]
    fn current_fre_word_run_build_accounting_is_plan_owned_and_operation_complete() {
        for (pattern, unicode, expected_semantics) in [
            (
                r"\b\w{12,}\b",
                false,
                fre::AggregateWordRunSemantics::AsciiWordBytes,
            ),
            (
                r"\b\w{12,}\b",
                true,
                fre::AggregateWordRunSemantics::UnicodeWordScalarsInvalidBytesNonWord,
            ),
            (
                r"[0-9A-Za-z_]{256}",
                false,
                fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks,
            ),
        ] {
            for operation in [
                LiteralAggregateOperation::Count,
                LiteralAggregateOperation::SpanSum,
            ] {
                let builder = current_fre_rebar_aggregate_builder(pattern, unicode, false);
                let report = match operation {
                    LiteralAggregateOperation::Count => builder
                        .build_count()
                        .expect("word-run count build")
                        .build_report()
                        .clone(),
                    LiteralAggregateOperation::SpanSum => builder
                        .build_span_sum()
                        .expect("word-run span-sum build")
                        .build_report()
                        .clone(),
                };
                let model = match operation {
                    LiteralAggregateOperation::Count => "count",
                    LiteralAggregateOperation::SpanSum => "count-spans",
                };
                current_fre_rebar_validate_aggregate_identity(&report, unicode, model)
                    .expect("exact word-run identity");
                let (
                    AggregatePlanIdentity::WordRun(identity),
                    AggregateBuildAccounting::WordRun(build),
                ) = (report.plan_identity, report.build)
                else {
                    panic!("word-run test retained another plan or build receipt");
                };
                assert_eq!(identity.semantics, expected_semantics);
                assert!(fre::word_run_build_accounting_matches(
                    identity.kernel,
                    build
                ));

                for field in 0..4 {
                    let mut forged = report.clone();
                    let AggregateBuildAccounting::WordRun(build) = &mut forged.build else {
                        unreachable!("word-run build receipt checked above");
                    };
                    match field {
                        0 => {
                            build.work_upper_bound = build
                                .work_upper_bound
                                .checked_sub(1)
                                .expect("word-run build work is positive");
                        }
                        1 => {
                            build.scratch_bytes = build
                                .scratch_bytes
                                .checked_add(1)
                                .expect("test scratch mutation fits");
                        }
                        2 => {
                            build.persistent_bytes = build
                                .persistent_bytes
                                .checked_sub(1)
                                .expect("word-run persistent storage is positive");
                        }
                        3 => {
                            build.peak_bytes = build
                                .peak_bytes
                                .checked_sub(1)
                                .expect("word-run peak storage is positive");
                        }
                        _ => unreachable!(),
                    }
                    assert!(
                        current_fre_rebar_validate_aggregate_identity(&forged, unicode, model)
                            .is_err()
                    );
                }

                let mut wrong_plan = report;
                let AggregatePlanIdentity::WordRun(identity) = &mut wrong_plan.plan_identity else {
                    unreachable!("word-run identity checked above");
                };
                identity.kernel.plan_id = "forged-word-run-plan";
                assert!(
                    current_fre_rebar_validate_aggregate_identity(&wrong_plan, unicode, model)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn current_fre_composition_keeps_unicode_capture_and_build_many_reachable() {
        let limits = RunLimits::default();
        assert_current_fre_execution(
            current_fre(
                "count",
                &[r"\pL".to_string()],
                "A雪1δ".as_bytes(),
                true,
                false,
                &limits,
            ),
            3,
            "aggregate-unicode-scalar-class",
        );
        for (model, expected) in [("count", 2), ("count-spans", 8)] {
            assert_current_fre_execution(
                current_fre(
                    model,
                    &[r"[A-Za-zα-ω]{2,4}".to_string()],
                    "ab αβγ x".as_bytes(),
                    true,
                    false,
                    &limits,
                ),
                expected,
                "aggregate-unicode-scalar-class",
            );
        }
        assert_current_fre_execution(
            current_fre(
                "count-captures",
                &[r"(a)(b)?".to_string()],
                b"a ab",
                false,
                false,
                &limits,
            ),
            5,
            CURRENT_FRE_CAPTURE_PARTICIPATION_QUOTIENT_PLAN,
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &["ab".to_string(), "a".to_string()],
                b"ab",
                false,
                false,
                &limits,
            ),
            2,
            "aggregate-many-ordered-literal",
        );
        assert_current_fre_execution(
            current_fre(
                "count",
                &[r"(?:cat|dog)".to_string()],
                b"cat x dog",
                false,
                false,
                &limits,
            ),
            2,
            "aggregate-finite-literal-packed-v2",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &[r"(?:cat|dog)".to_string()],
                b"cat x dog",
                false,
                false,
                &limits,
            ),
            6,
            "aggregate-finite-literal-packed-v2",
        );

        assert_current_fre_execution(
            current_fre(
                "count-captures",
                &[r"(\pL)".to_string()],
                "雪".as_bytes(),
                true,
                false,
                &limits,
            ),
            2,
            "capture-linear-selector-uniform-participation",
        );
    }

    #[test]
    fn current_fre_packed_finite_route_has_exact_labels_identity_and_limits() {
        let pattern = r"(?:cat|dog)";
        let haystack = b"catdogxxxx";

        let count = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_count()
            .expect("packed finite count plan");
        let count_report = count.build_report();
        assert_eq!(count_report.plan, AggregatePlanKind::PackedFiniteLiteral);
        let AggregateBuildAccounting::PackedFiniteLiteral(build) = count_report.build else {
            panic!("packed finite count plan lost packed build accounting");
        };
        assert_eq!(build.min_pattern_bytes, 3);
        current_fre_rebar_validate_aggregate_identity(count_report, false, "count")
            .expect("packed finite count identity");
        assert_eq!(
            aggregate_single_plan_label("count", count_report),
            "aggregate-finite-literal-packed-v2"
        );

        let count_limits = current_fre_rebar_aggregate_run_limits(haystack.len(), count_report)
            .expect("packed finite count limits");
        assert_eq!(count_limits.finite_literal.max_match_events, 3);
        assert_eq!(count_limits.finite_literal.max_reducer_steps, 9);
        let one_below = aggregate_run_limits(
            haystack.len(),
            count_report,
            &RunLimits {
                reducer_steps: 8,
                ..RunLimits::default()
            },
        )
        .expect("one-below packed finite count limits");
        assert_eq!(one_below.finite_literal.max_reducer_steps, 8);
        let refusal = count
            .count(haystack, one_below)
            .expect_err("one below packed candidate steps");
        assert!(matches!(
            refusal.source,
            AggregateExecutionSource::PackedFiniteLiteral(
                fre::PackedOrderedLiteralAggregateReduceError::ReducerStepsLimit {
                    needed: 9,
                    limit: 8,
                }
            )
        ));
        let counted = count
            .count(haystack, count_limits)
            .expect("packed finite count");
        assert_eq!(counted.value(), 2);
        let AggregateExecutionDetails::PackedFiniteLiteral {
            operation_identity,
            upper_bounds,
            actual,
        } = counted.report().details()
        else {
            panic!("packed finite count lost packed execution details");
        };
        let AggregatePlanIdentity::FiniteLiteral(count_identity) = count_report.plan_identity
        else {
            panic!("packed finite count lost finite build identity");
        };
        assert_eq!(
            count_identity.packed_operation_identity,
            Some(*operation_identity)
        );
        assert_eq!(upper_bounds.candidate_positions, 8);
        assert_eq!(upper_bounds.reducer_steps, 9);
        assert_eq!(actual.classified_positions, 8);
        assert!(actual.candidate_events <= upper_bounds.candidate_positions);
        assert!(actual.pattern_checks <= upper_bounds.pattern_checks);
        assert_eq!(actual.source_byte_reads, upper_bounds.source_byte_reads);
        assert!(actual.work <= upper_bounds.work);

        let span_sum = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_span_sum()
            .expect("packed finite span-sum plan");
        current_fre_rebar_validate_aggregate_identity(
            span_sum.build_report(),
            false,
            "count-spans",
        )
        .expect("packed finite span-sum identity");
        assert_eq!(
            aggregate_single_plan_label("count-spans", span_sum.build_report()),
            "aggregate-finite-literal-packed-v2"
        );
        let span_limits = current_fre_rebar_span_sum_run_limits(haystack.len(), &span_sum)
            .expect("packed finite span-sum limits");
        let spanned = span_sum
            .span_sum(haystack, span_limits)
            .expect("packed finite span sum");
        assert_eq!(spanned.value(), 6);
        assert!(matches!(
            spanned.report().details(),
            AggregateExecutionDetails::PackedFiniteLiteral { .. }
        ));

        let compile = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_compile()
            .expect("packed finite compile plan");
        current_fre_rebar_validate_aggregate_identity(compile.build_report(), false, "compile")
            .expect("packed finite compile identity");
        assert_eq!(
            aggregate_single_plan_label("compile", compile.build_report()),
            "compile-aggregate-finite-literal-packed-v2"
        );

        let mut forged = count_report.clone();
        forged.plan = AggregatePlanKind::FiniteLiteralDfa;
        assert!(current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err());
        assert!(current_fre_rebar_aggregate_run_limits(haystack.len(), &forged).is_err());
    }

    #[test]
    fn current_fre_guarded_ascii_word_count_and_span_sum_route() {
        let limits = RunLimits::default();
        for (model, expected) in [("count", 3), ("count-spans", 11)] {
            assert_current_fre_execution(
                current_fre(
                    model,
                    &[r"\b(?:as|break|Self)\b".to_string()],
                    b"as break Self other",
                    false,
                    false,
                    &limits,
                ),
                expected,
                "aggregate-guarded-ascii-word",
            );
        }
    }

    #[test]
    fn current_fre_guarded_ascii_word_receipts_fail_closed_under_forgery() {
        let report = AggregateBuilder::new(r"\b(?:as|break|Self)\b")
            .profile(rebar_profile())
            .unicode(false)
            .case_insensitive(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .build_count()
            .unwrap()
            .build_report()
            .clone();
        current_fre_rebar_validate_aggregate_identity(&report, false, "count").unwrap();

        let mut forged = report.clone();
        let AggregateBuildAccounting::GuardedAsciiWord(build) = &mut forged.build else {
            panic!("guarded test report lost build accounting");
        };
        build.allocations_upper_bound = 0;
        build.allocations_actual = 0;
        build.initialized_bytes_upper_bound = 0;
        build.initialized_bytes_actual = 0;
        build.peak_bytes_upper_bound = 0;
        build.peak_bytes_actual_upper_bound = 0;
        assert!(current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err());
        assert!(current_fre_rebar_aggregate_run_limits(64, &forged).is_err());

        let mut forged = report.clone();
        let AggregateBuildAccounting::GuardedAsciiWord(build) = &mut forged.build else {
            panic!("guarded test report lost build accounting");
        };
        build.dictionary.prospective.source_len_calls = 0;
        assert!(current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err());
        assert!(current_fre_rebar_aggregate_run_limits(64, &forged).is_err());

        let mut forged = report;
        forged.retained_capacity_bytes = 0;
        assert!(current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err());
        assert!(current_fre_rebar_aggregate_run_limits(64, &forged).is_err());
    }

    #[test]
    fn current_fre_span_sum_greedy_star_uses_direct_scalar_reduction() {
        let limits = RunLimits::default();
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &[".*".to_string()],
                b"ab\n\xFFcd",
                true,
                false,
                &limits,
            ),
            4,
            "aggregate-unicode-scalar-class",
        );
    }

    #[test]
    fn current_fre_unicode_finite_literals_use_the_packed_scanner() {
        let limits = RunLimits::default();
        let haystack = "--∞--✓--∞--".as_bytes();
        assert_current_fre_execution(
            current_fre(
                "count",
                &["∞|✓".to_string()],
                haystack,
                true,
                false,
                &limits,
            ),
            3,
            "aggregate-finite-literal-packed-v2",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &["∞|✓".to_string()],
                haystack,
                true,
                false,
                &limits,
            ),
            9,
            "aggregate-finite-literal-packed-v2",
        );
    }

    #[test]
    fn canonical_unicode_word_boundary_rows_retain_support() {
        let patterns = [r"\b".to_string()];
        let limits = RunLimits::default();
        for (job_id, haystack) in [
            (
                "test/unicode/word-boundary/unicode-alphabetic@rust/regex",
                "δ".as_bytes(),
            ),
            (
                "test/unicode/word-boundary/unicode-connector-punctuation@rust/regex",
                "⁀".as_bytes(),
            ),
            (
                "test/unicode/word-boundary/unicode-decimal-number@rust/regex",
                "᠕".as_bytes(),
            ),
            (
                "test/unicode/word-boundary/unicode-join-control@rust/regex",
                "\u{200D}".as_bytes(),
            ),
            (
                "test/unicode/word-boundary/unicode-mark@rust/regex",
                "\u{0322}".as_bytes(),
            ),
        ] {
            let outcome = CurrentFreAdapter.execute(
                CandidateRequest {
                    job_id,
                    model: "count",
                    patterns: &patterns,
                    haystack,
                    unicode: true,
                    case_insensitive: false,
                },
                &limits,
            );
            assert_eq!(
                outcome,
                CandidateOutcome::ExecutedWithPlan {
                    actual: 2,
                    plan: "aggregate-continuation-program".to_string(),
                },
                "canonical row {job_id}"
            );
        }
    }

    #[test]
    fn compile_lifecycle_labels_sparse_finite_representation_exactly() {
        let words = (0..32)
            .map(|index| format!("p{index:03}"))
            .collect::<Vec<_>>();
        let pattern = format!("(?:{})", words.join("|"));
        let mut limits = AggregateBuildLimits::default();
        limits.finite_literal.max_dfa_cells = 32 * 4;
        let regex = AggregateBuilder::new(&pattern)
            .profile(rebar_profile())
            .unicode(false)
            .limits(limits)
            .build_compile()
            .unwrap();
        assert!(matches!(
            regex.build_report().build,
            AggregateBuildAccounting::SparseFiniteLiteral(_)
        ));
        let artifact = CurrentFreAggregateCompileArtifact {
            inner: CurrentFreAggregateCompileArtifactInner::Single(regex),
        };
        let lifecycle = CurrentFreAggregateCompileLifecycle {
            patterns: vec![pattern],
            unicode: false,
            case_insensitive: false,
            haystack_len: 0,
        };
        assert_eq!(
            artifact.plan(&lifecycle).unwrap(),
            "compile-aggregate-finite-literal-sparse"
        );
    }

    #[test]
    #[ignore = "requires the sealed Rebar Veryl KLV pattern and haystack payloads"]
    fn sealed_veryl_klv_uses_value_only_build_many_rebar_routes() {
        let pattern_path = std::env::var("FRE_QUALIFICATION_VERYL_PATTERNS")
            .expect("qualification must bind the sealed Veryl pattern path");
        let haystack_path = std::env::var("FRE_QUALIFICATION_VERYL_HAYSTACK")
            .expect("qualification must bind the sealed Veryl haystack path");
        let pattern_text = std::fs::read_to_string(pattern_path).unwrap();
        let patterns = pattern_text.lines().map(str::to_owned).collect::<Vec<_>>();
        let haystack = std::fs::read(haystack_path).unwrap();
        assert_eq!(88, patterns.len());
        assert_eq!(150_600, haystack.len());

        let limits = RunLimits::default();
        for (model, expected, plan) in [
            ("count", 62_400, "aggregate-many-continuation-program"),
            (
                "count-spans",
                150_600,
                "aggregate-many-continuation-program",
            ),
            (
                "count-captures",
                124_800,
                "capture-many-continuation-program",
            ),
        ] {
            assert_current_fre_execution(
                current_fre(model, &patterns, &haystack, false, false, &limits),
                expected,
                plan,
            );
        }
    }

    #[test]
    fn current_fre_one_pattern_aggregate_models_cover_adversarial_semantics() {
        let limits = RunLimits::default();
        let late = vec![r"(?:a+b|a)".to_string()];
        assert_current_fre_execution(
            current_fre("count", &late, b"aaaa", false, false, &limits),
            4,
            "aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre("count", &late, b"aaaab", false, false, &limits),
            1,
            "aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre("count-spans", &late, b"aaaa", false, false, &limits),
            4,
            "aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre("count-spans", &late, b"aaaab", false, false, &limits),
            5,
            "aggregate-continuation-program",
        );

        let empty = vec![String::new()];
        assert_current_fre_execution(
            current_fre("count", &empty, b"ab", false, false, &limits),
            3,
            "aggregate-exact-literal",
        );
        assert_current_fre_execution(
            current_fre("count-spans", &empty, b"ab", false, false, &limits),
            0,
            "aggregate-exact-literal",
        );
        let nullable = vec![r"(?:(?:|a){1,2}?b?)*".to_string()];
        let reference = compile_for("count", &nullable[0]);
        let expected = count_matches(&reference, b"aab", 100).unwrap();
        assert_current_fre_execution(
            current_fre("count", &nullable, b"aab", false, false, &limits),
            expected,
            "aggregate-continuation-program",
        );

        let absolute = vec![r"\Afoo\z".to_string()];
        assert_current_fre_execution(
            current_fre("count", &absolute, b"xxfoo", false, false, &limits),
            0,
            "aggregate-continuation-program",
        );
        let end = vec![r"foo\z".to_string()];
        assert_current_fre_execution(
            current_fre("count", &end, b"xxfoo", false, false, &limits),
            1,
            "aggregate-continuation-program",
        );
        let assertion_cases: [(&str, &[u8], u64, u64); 2] = [
            (r"\b[a-z]+\b", b"_alpha beta!gamma42 \xFFdelta", 2, 9),
            (r"(?m:sherlock$)", b"sherlock\nnot\nsherlock", 2, 16),
        ];
        for (pattern, haystack, count, span_sum) in assertion_cases {
            let patterns = [pattern.to_string()];
            assert_current_fre_execution(
                current_fre("count", &patterns, haystack, false, false, &limits),
                count,
                "aggregate-continuation-program",
            );
            assert_current_fre_execution(
                current_fre("count-spans", &patterns, haystack, false, false, &limits),
                span_sum,
                "aggregate-continuation-program",
            );
        }
        let captured = vec![r"(?P<outer>(?P<inner>a))".to_string()];
        assert_current_fre_execution(
            current_fre("count", &captured, b"baab", false, false, &limits),
            2,
            "aggregate-exact-literal",
        );
        let folded = vec!["sherlock".to_string()];
        assert_current_fre_execution(
            current_fre("count", &folded, b"SHERLOCK sherlock", false, true, &limits),
            2,
            "aggregate-finite-literal-dfa",
        );

        // These are canonical leftmost-first results. The pinned Rust meta
        // adapter's reverse-suffix optimization incorrectly returns 2; exact
        // report generation deliberately retains those reference failures.
        for (pattern, plan) in [
            (r".abb|b", "aggregate-finite-literal-dfa"),
            (r"(?:[A-Za-z]ab)?b", "aggregate-continuation-program"),
        ] {
            assert_current_fre_execution(
                current_fre(
                    "count",
                    &[pattern.to_string()],
                    b"zabb",
                    false,
                    false,
                    &limits,
                ),
                1,
                plan,
            );
        }
    }

    #[test]
    fn current_fre_grep_reuses_k0_workspace_across_lines() {
        let patterns = vec![r"\b[0-9A-Za-z_]{2,}\b".to_string()];
        assert_current_fre_execution(
            current_fre(
                "grep",
                &patterns,
                b"--\nalpha\n-\nxy\n\xFF\n",
                false,
                false,
                &RunLimits::default(),
            ),
            2,
            "portable-single-search",
        );
        let unicode_lines = format!("short\n{}\n{}\n", "α".repeat(25), "β".repeat(24));
        assert_current_fre_execution(
            current_fre(
                "grep",
                &[r"\b\w{25,}\b".to_string()],
                unicode_lines.as_bytes(),
                true,
                false,
                &RunLimits::default(),
            ),
            1,
            "portable-single-search",
        );
        assert_current_fre_execution(
            current_fre(
                "grep",
                &[r"^[ \t\f]*#.*?coding[:=][ \t]*utf-?8".to_string()],
                b"# coding: utf-8\nx # coding: utf-8\n\xFF\n",
                true,
                false,
                &RunLimits::default(),
            ),
            1,
            "portable-single-search",
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the single/ordered compile routing and refusal matrix shares one identity setup"
    )]
    fn current_fre_compile_constructs_fresh_single_and_ordered_many_artifacts() {
        let limits = RunLimits::default();
        assert_current_fre_execution(
            current_fre(
                "compile",
                &["aba".to_string()],
                b"abaaba",
                false,
                false,
                &limits,
            ),
            2,
            "compile-aggregate-exact-literal",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &[r"(?:a+b|a)".to_string()],
                b"aaaab",
                false,
                false,
                &limits,
            ),
            1,
            "compile-aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &[r"(?P<word>[a-z]+)".to_string()],
                b"Ab C",
                false,
                true,
                &limits,
            ),
            2,
            "compile-aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &["雪+".to_string()],
                "雪雪".as_bytes(),
                true,
                false,
                &limits,
            ),
            1,
            "compile-aggregate-continuation-program",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &[r"\pL".to_string()],
                "雪".as_bytes(),
                true,
                false,
                &limits,
            ),
            1,
            "compile-aggregate-unicode-scalar-class",
        );

        assert_current_fre_execution(
            current_fre(
                "compile",
                &["ab".to_string(), "a".to_string()],
                b"ab a",
                false,
                false,
                &limits,
            ),
            2,
            "compile-many-ordered-literal",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &[r"a+".to_string(), "a".to_string()],
                b"aa",
                false,
                false,
                &limits,
            ),
            1,
            "compile-many-continuation-program",
        );

        let unicode_profile_refusal = current_fre(
            "compile",
            &["snow".to_string(), r"\w+".to_string()],
            "snow 雪".as_bytes(),
            true,
            false,
            &limits,
        );
        assert!(
            matches!(unicode_profile_refusal, CandidateOutcome::Unsupported(ref reason) if reason.contains("Unicode ordered build-many pattern 1")),
            "unexpected Unicode compile-many outcome: {unicode_profile_refusal:?}"
        );

        let mut bounded = limits;
        bounded.patterns_per_job = 1;
        let resource_refusal = current_fre(
            "compile",
            &["a".to_string(), "(".to_string()],
            b"a",
            false,
            false,
            &bounded,
        );
        assert!(
            matches!(resource_refusal, CandidateOutcome::Unsupported(ref reason) if reason.contains("needs 2 patterns, limit is 1")),
            "unexpected compile-many resource outcome: {resource_refusal:?}"
        );

        let wrong_profile_patterns = vec!["snow".to_string(), "雪".to_string()];
        let wrong_profile = AggregateManyBuilder::new(&wrong_profile_patterns)
            .profile(rebar_profile())
            .unicode(false)
            .build_compile()
            .unwrap();
        let profile_request = CandidateRequest {
            job_id: "synthetic/compile-many-profile-mismatch",
            model: "compile",
            patterns: &wrong_profile_patterns,
            haystack: "snow雪".as_bytes(),
            unicode: true,
            case_insensitive: false,
        };
        let mismatch = require_aggregate_many_identity(
            profile_request,
            wrong_profile.build_report(),
            AggregateManyOperation::Compile,
        )
        .unwrap_err();
        assert_eq!(Status::Fault, mismatch.status);
        assert!(
            mismatch
                .message
                .contains("profile/operation identity mismatch")
        );

        assert_current_fre_execution(
            current_fre(
                "compile",
                &[r"[A-Za-z0-9_-]{20,1024}".to_string(), "never".to_string()],
                b"TWITTER_API_KEY",
                false,
                false,
                &RunLimits::default(),
            ),
            0,
            "compile-many-continuation-program",
        );
    }

    #[test]
    fn rust_reference_lifecycles_separate_fresh_compile_from_same_artifact_operations() {
        let patterns = vec![r"(a)(b)?".to_string()];
        let haystack = b"ab a\nzz\nab\n";
        let compile =
            rust_regex_reference_compile_lifecycle(&patterns, false, false, haystack.len())
                .expect("Rust reference compile lifecycle");
        let first_artifact = compile.construct().expect("first fresh Rust artifact");
        assert_eq!(
            first_artifact
                .verify(&compile, haystack)
                .expect("first compile verification"),
            3
        );
        let second_artifact = compile.construct().expect("second fresh Rust artifact");
        assert_eq!(
            second_artifact
                .verify(&compile, haystack)
                .expect("second compile verification"),
            3
        );
        assert!(second_artifact.verify(&compile, b"ab").is_err());

        for (model, expected) in [
            ("count", 3),
            ("count-spans", 5),
            ("count-captures", 8),
            ("grep", 2),
            ("grep-captures", 8),
        ] {
            let lifecycle = rust_regex_reference_operation_lifecycle(
                model,
                &patterns,
                false,
                false,
                haystack.len(),
            )
            .expect("Rust reference operation lifecycle");
            assert_eq!(lifecycle.model(), model);
            assert_eq!(
                lifecycle.execute(haystack).expect("first operation"),
                expected
            );
            assert_eq!(
                lifecycle.execute(haystack).expect("steady operation"),
                expected
            );
            assert!(lifecycle.execute(b"ab").is_err());
        }

        let unicode_patterns = vec![r"\pL+".to_string()];
        let unicode = rust_regex_reference_operation_lifecycle(
            "count",
            &unicode_patterns,
            true,
            true,
            "雪 SNOW".len(),
        )
        .expect("Unicode case-insensitive reference lifecycle");
        assert_eq!(
            unicode
                .execute("雪 SNOW".as_bytes())
                .expect("Unicode reference operation"),
            2
        );

        assert!(rust_regex_reference_compile_lifecycle(&[], false, false, 0).is_err());
        assert!(
            rust_regex_reference_operation_lifecycle(
                "compile",
                &patterns,
                false,
                false,
                haystack.len(),
            )
            .is_err()
        );
        assert!(
            rust_regex_reference_operation_lifecycle("count", &["(".to_string()], false, false, 0,)
                .is_err()
        );
    }

    #[test]
    fn aggregate_lifecycles_separate_construction_from_same_artifact_operations() {
        let haystack = b"aba aba";
        let single_patterns = vec!["aba".to_string()];
        let compile = current_fre_rebar_aggregate_compile_lifecycle(
            &single_patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("single compile lifecycle");
        let first_artifact = compile.construct().expect("first fresh compile artifact");
        assert_eq!(
            first_artifact.plan(&compile).expect("single compile plan"),
            "compile-aggregate-exact-literal"
        );
        assert_eq!(
            first_artifact
                .verify(&compile, haystack)
                .expect("single compile verification"),
            2
        );
        let second_artifact = compile.construct().expect("second fresh compile artifact");
        assert_eq!(
            second_artifact
                .verify(&compile, haystack)
                .expect("second compile verification"),
            2
        );
        assert!(second_artifact.verify(&compile, b"aba").is_err());

        let continuation_patterns = vec!["a+".to_string(), "b+".to_string()];
        let continuation_haystack = b"aa bbb";
        let compile_many = current_fre_rebar_aggregate_compile_lifecycle(
            &continuation_patterns,
            false,
            false,
            continuation_haystack.len(),
        )
        .expect("compile-many lifecycle");
        let artifact = compile_many.construct().expect("compile-many artifact");
        assert_eq!(
            artifact.plan(&compile_many).expect("compile-many plan"),
            "compile-many-continuation-program"
        );
        assert_eq!(
            artifact
                .verify(&compile_many, continuation_haystack)
                .expect("compile-many verification"),
            2
        );

        let count = current_fre_rebar_aggregate_operation_lifecycle(
            "count",
            &continuation_patterns,
            false,
            false,
            continuation_haystack.len(),
        )
        .expect("count-many lifecycle");
        assert_eq!(count.model(), "count");
        assert_eq!(count.plan(), "aggregate-many-continuation-program");
        assert_eq!(
            count
                .execute(continuation_haystack)
                .expect("first count operation"),
            2
        );
        assert_eq!(
            count
                .execute(continuation_haystack)
                .expect("steady count operation"),
            2
        );
        assert!(count.execute(b"aa").is_err());

        let span_sum = current_fre_rebar_aggregate_operation_lifecycle(
            "count-spans",
            &single_patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("single span-sum lifecycle");
        assert_eq!(span_sum.model(), "count-spans");
        assert_eq!(span_sum.plan(), "aggregate-exact-literal");
        assert_eq!(span_sum.execute(haystack).expect("span-sum operation"), 6);
        assert!(current_fre_rebar_aggregate_compile_lifecycle(&[], false, false, 0).is_err());
        assert!(
            current_fre_rebar_aggregate_operation_lifecycle(
                "compile",
                &single_patterns,
                false,
                false,
                haystack.len(),
            )
            .is_err()
        );
    }

    #[test]
    fn current_fre_ordered_build_many_preserves_priority_and_operation_output() {
        let limits = RunLimits::default();
        let longer_first = vec![r"a+".to_string(), "a".to_string()];
        let shorter_first = vec!["a".to_string(), r"a+".to_string()];
        assert_current_fre_execution(
            current_fre("count", &longer_first, b"aa", false, false, &limits),
            1,
            "aggregate-many-continuation-program",
        );
        assert_current_fre_execution(
            current_fre("count", &shorter_first, b"aa", false, false, &limits),
            2,
            "aggregate-many-continuation-program",
        );

        let literal_priority = vec!["ab".to_string(), "a".to_string()];
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &literal_priority,
                b"ab",
                false,
                false,
                &limits,
            ),
            2,
            "aggregate-many-ordered-literal",
        );
        let unicode_literals = vec!["snow".to_string(), "雪".to_string()];
        assert_current_fre_execution(
            current_fre(
                "count",
                &unicode_literals,
                "雪snow".as_bytes(),
                true,
                false,
                &limits,
            ),
            2,
            "aggregate-many-ordered-literal",
        );
    }

    #[test]
    fn current_fre_uniform_build_many_captures_keep_priority_limits_and_identity() {
        let limits = RunLimits::default();
        for (patterns, haystack, expected, plan) in [
            (
                vec!["(a+)".to_string(), "(a)".to_string()],
                b"aa".as_slice(),
                2,
                "capture-many-continuation-program",
            ),
            (
                vec!["(a)".to_string(), "(a+)".to_string()],
                b"aa".as_slice(),
                4,
                "capture-many-continuation-program",
            ),
            (
                vec!["(ab)".to_string(), "(a)".to_string()],
                b"ab".as_slice(),
                2,
                "capture-many-ordered-literal",
            ),
        ] {
            assert_current_fre_execution(
                current_fre("count-captures", &patterns, haystack, false, false, &limits),
                expected,
                plan,
            );
        }

        let captures = current_fre(
            "count-captures",
            &["(a)".to_string(), "b".to_string()],
            b"ab",
            false,
            false,
            &limits,
        );
        assert!(
            matches!(captures, CandidateOutcome::Unsupported(ref reason) if reason.contains("lacks the uniform whole-match proof")),
            "mixed capture participation must remain typed unsupported: {captures:?}"
        );

        let mut bounded = limits;
        bounded.reducer_steps = 1;
        let capture_limit = current_fre(
            "count-captures",
            &["(a+)".to_string(), "(a)".to_string()],
            b"aa",
            false,
            false,
            &bounded,
        );
        assert!(
            matches!(capture_limit, CandidateOutcome::Unsupported(ref reason) if reason.contains("CaptureEventsLimit")),
            "capture reducer limit must remain typed unsupported: {capture_limit:?}"
        );

        let identity_patterns = vec!["(a+)".to_string(), "(a)".to_string()];
        let capture_plan = AggregateManyBuilder::new(&identity_patterns)
            .profile(rebar_profile())
            .unicode(false)
            .build_capture_count()
            .unwrap();
        require_aggregate_many_report_identity(
            &identity_patterns,
            false,
            false,
            capture_plan.build_report(),
            AggregateManyOperation::CaptureCount,
        )
        .unwrap();
        let mut malformed_report = capture_plan.build_report().clone();
        malformed_report.participating_captures_per_match = None;
        let identity_error = require_aggregate_many_report_identity(
            &identity_patterns,
            false,
            false,
            &malformed_report,
            AggregateManyOperation::CaptureCount,
        )
        .unwrap_err();
        assert_eq!(Status::Fault, identity_error.status);
        assert!(
            identity_error
                .message
                .contains("capture participation identity mismatch")
        );
    }

    #[test]
    fn current_fre_admits_byte_stable_hir_and_direct_root_unicode_classes() {
        let limits = RunLimits::default();
        let empty = current_fre("count", &[String::new()], b"a", true, false, &limits);
        assert_current_fre_execution(empty, 2, "aggregate-continuation-program");
        assert_current_fre_execution(
            current_fre("count", &["a|b".to_string()], b"baab", true, false, &limits),
            4,
            "aggregate-finite-literal-dfa",
        );
        assert_current_fre_execution(
            current_fre("count", &["a".to_string()], b"baab", true, false, &limits),
            2,
            "aggregate-exact-literal",
        );
        let folded = current_fre(
            "count",
            &["рус".to_string()],
            "a русский".as_bytes(),
            true,
            true,
            &limits,
        );
        assert_current_fre_execution(folded, 1, "aggregate-finite-literal-packed-v2");
        assert_current_fre_execution(
            current_fre(
                "count",
                &[r"\pL".to_string()],
                "a русский".as_bytes(),
                true,
                false,
                &limits,
            ),
            8,
            "aggregate-unicode-scalar-class",
        );

        assert_current_fre_execution(
            current_fre(
                "count",
                &["(?s:.)".to_string()],
                b"a\xFF\xE9\x9B\xAA\n\x80",
                true,
                false,
                &limits,
            ),
            3,
            "aggregate-unicode-scalar-class",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &[r"\pL".to_string()],
                "A雪1δ".as_bytes(),
                true,
                false,
                &limits,
            ),
            6,
            "aggregate-unicode-scalar-class",
        );

        let build_many = vec!["(".to_string(), "a".to_string()];
        let outcome = current_fre("count", &build_many, b"a", false, false, &limits);
        assert!(
            matches!(outcome, CandidateOutcome::Unsupported(ref reason) if reason.contains("pattern 0 syntax failed")),
            "the invalid first pattern must be a typed syntax refusal: {outcome:?}"
        );

        let mut literal_starved = limits.clone();
        literal_starved.fre_literal_linear_terms = 0;
        let outcome = current_fre(
            "count",
            &["a".to_string()],
            b"a",
            false,
            false,
            &literal_starved,
        );
        assert!(
            matches!(outcome, CandidateOutcome::Unsupported(ref reason) if reason.contains("linear terms")),
            "literal resource admission must remain unsupported: {outcome:?}"
        );

        let mut continuation_starved = limits;
        continuation_starved.fre_aggregate_operation_work = 0;
        let outcome = current_fre(
            "count",
            &["a+".to_string()],
            b"a",
            false,
            false,
            &continuation_starved,
        );
        assert!(
            matches!(outcome, CandidateOutcome::Unsupported(ref reason) if reason.contains("ExecutionWork")),
            "continuation resource admission must remain unsupported: {outcome:?}"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "both Rebar value reducers share one exact observed-work admission fixture"
    )]
    fn current_fre_single_value_reducers_use_exact_continuation_work() {
        let pattern = r"(?:|a+|z{64}[q-r])";
        let patterns = [pattern.to_string()];
        let haystack = [b'a', 0xFF, b'a'];
        let baseline_limits = RunLimits::default();

        let count = AggregateBuilder::new(pattern)
            .profile(rebar_profile())
            .unicode(false)
            .limits(aggregate_build_limits(&baseline_limits))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );
        let AggregateBuildAccounting::Continuation(compile) = count.build_report().build else {
            panic!("expected continuation compile accounting");
        };
        assert!(!compile.requires_utf8_validation);
        let run_limits =
            aggregate_run_limits(haystack.len(), count.build_report(), &baseline_limits).unwrap();
        let record_bytes = (compile.program_states + 1).div_ceil(8);
        let prior_sequential = record_bytes * (haystack.len() + 1) * 2;
        assert_eq!(
            run_limits.continuation.max_sequential_bytes,
            prior_sequential
        );
        let audited = count.count(&haystack, run_limits).unwrap();
        let fre::AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } = audited.report().details()
        else {
            panic!("expected continuation count details");
        };
        assert!(accounting.work < certificate.work_bound);

        let mut exact = baseline_limits.clone();
        exact.fre_aggregate_operation_work = accounting.work;
        assert_current_fre_execution(
            current_fre("count", &patterns, &haystack, false, false, &exact),
            4,
            "aggregate-continuation-program",
        );
        exact.fre_aggregate_operation_work -= 1;
        let refused = current_fre("count", &patterns, &haystack, false, false, &exact);
        assert!(
            matches!(refused, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("ExecutionWork")
                    && reason.contains(&format!("requires {}", accounting.work))
                    && reason.contains(&format!("limit is {}", accounting.work - 1))),
            "one-below observed count work must remain typed unsupported: {refused:?}"
        );

        let span_sum = AggregateBuilder::new(pattern)
            .profile(rebar_profile())
            .unicode(false)
            .limits(aggregate_build_limits(&baseline_limits))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_span_sum()
            .unwrap();
        let run_limits =
            aggregate_run_limits(haystack.len(), span_sum.build_report(), &baseline_limits)
                .unwrap();
        let audited = span_sum.span_sum(&haystack, run_limits).unwrap();
        let fre::AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } = audited.report().details()
        else {
            panic!("expected continuation span-sum details");
        };
        assert!(accounting.work < certificate.work_bound);

        exact = baseline_limits;
        exact.fre_aggregate_operation_work = accounting.work;
        assert_current_fre_execution(
            current_fre("count-spans", &patterns, &haystack, false, false, &exact),
            0,
            "aggregate-continuation-program",
        );
        exact.fre_aggregate_operation_work -= 1;
        let refused = current_fre("count-spans", &patterns, &haystack, false, false, &exact);
        assert!(
            matches!(refused, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("ExecutionWork")
                    && reason.contains(&format!("requires {}", accounting.work))
                    && reason.contains(&format!("limit is {}", accounting.work - 1))),
            "one-below observed span-sum work must remain typed unsupported: {refused:?}"
        );
    }

    #[test]
    fn unicode_word_prevalidation_exact_limits_execute_and_one_below_refuses() {
        let pattern = r"\b";
        let patterns = [pattern.to_string()];
        let haystack = "δ".as_bytes();
        let baseline = RunLimits::default();
        let regex = AggregateBuilder::new(pattern)
            .profile(rebar_profile())
            .unicode(true)
            .limits(aggregate_build_limits(&baseline))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .unwrap();
        let AggregateBuildAccounting::Continuation(compile) = regex.build_report().build else {
            panic!("Unicode word boundary did not select continuation");
        };
        assert!(compile.requires_utf8_validation);

        let run_limits =
            aggregate_run_limits(haystack.len(), regex.build_report(), &baseline).unwrap();
        let sequential = run_limits.continuation.max_sequential_bytes;
        let audited = regex.count(haystack, run_limits).unwrap();
        let fre::AggregateExecutionDetails::Continuation { accounting, .. } =
            audited.report().details()
        else {
            panic!("expected continuation execution details");
        };
        assert_eq!(accounting.utf8_validation_work, haystack.len());

        let exact = RunLimits {
            fre_aggregate_operation_work: accounting.work,
            fre_aggregate_sequential_bytes: sequential,
            ..RunLimits::default()
        };
        assert_current_fre_execution(
            current_fre("count", &patterns, haystack, true, false, &exact),
            2,
            "aggregate-continuation-program",
        );

        let work_one_below = RunLimits {
            fre_aggregate_operation_work: accounting.work - 1,
            ..exact.clone()
        };
        let work = current_fre("count", &patterns, haystack, true, false, &work_one_below);
        assert!(
            matches!(work, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("ExecutionWork")
                    && reason.contains(&format!("requires {}", accounting.work))
                    && reason.contains(&format!("limit is {}", accounting.work - 1))),
            "one-below Unicode validation work must be typed unsupported: {work:?}"
        );

        let sequential_one_below = RunLimits {
            fre_aggregate_sequential_bytes: sequential - 1,
            ..exact
        };
        let sequential_refusal = current_fre(
            "count",
            &patterns,
            haystack,
            true,
            false,
            &sequential_one_below,
        );
        let CandidateOutcome::Unsupported(reason) = sequential_refusal else {
            panic!(
                "one-below Unicode validation bytes must be typed unsupported: {sequential_refusal:?}"
            );
        };
        assert!(
            reason.contains("SequentialBytes"),
            "expected a typed sequential-byte refusal in {reason:?}"
        );
    }

    #[test]
    fn rebar_span_sum_dense_prefix_absent_suffix_fits_derived_limits() {
        // Exact shape and input construction from
        // opt/reverse-inner/no-quadratic-forward. The lifecycle derives the
        // same public-operation limit that the Rebar runner enforces.
        let patterns = [r".efghijklmnopq[a-z]+[A-Z]".to_string()];
        let haystack = b"bcdefghijklmnopq".repeat(500);
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            "count-spans",
            &patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("candidate span-sum lifecycle");
        assert_eq!(lifecycle.plan(), "aggregate-continuation-program");
        assert_eq!(lifecycle.execute(&haystack).expect("first span sum"), 0);
        assert_eq!(lifecycle.execute(&haystack).expect("steady span sum"), 0);
    }

    #[test]
    fn rebar_span_sum_required_literal_miss_fits_derived_limits() {
        let haystack = b"bcdefghijklmnopq".repeat(500);
        for pattern in [r"[A-Z][a-z]+.efghijklmnopq", r".[a-z]+[A-Z]efghijklmnopq"] {
            let patterns = [pattern.to_string()];
            let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
                "count-spans",
                &patterns,
                false,
                false,
                haystack.len(),
            )
            .expect("required-literal span-sum lifecycle");
            assert_eq!(lifecycle.plan(), "aggregate-continuation-program");
            assert_eq!(lifecycle.execute(&haystack).expect("first span sum"), 0);
            assert_eq!(lifecycle.execute(&haystack).expect("steady span sum"), 0);
        }
    }

    #[test]
    fn current_fre_fixed_class_sandwich_covers_count_span_sum_and_compile() {
        let limits = RunLimits::default();
        let byte_pattern = vec![r"[a-q][^u-z]{13}x".to_string()];
        let mut byte_haystack = Vec::from(b"--".as_slice());
        byte_haystack.push(b'a');
        byte_haystack.extend(core::iter::repeat_n(b'p', 13));
        byte_haystack.push(b'x');
        byte_haystack.extend_from_slice(b"--auuuuuuuuuuuuux");
        assert_current_fre_execution(
            current_fre(
                "count",
                &byte_pattern,
                &byte_haystack,
                false,
                false,
                &limits,
            ),
            1,
            "aggregate-fixed-class-sandwich",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &byte_pattern,
                &byte_haystack,
                false,
                false,
                &limits,
            ),
            15,
            "aggregate-fixed-class-sandwich",
        );
        assert_current_fre_execution(
            current_fre(
                "compile",
                &byte_pattern,
                &byte_haystack,
                false,
                false,
                &limits,
            ),
            1,
            "compile-aggregate-fixed-class-sandwich",
        );

        let unicode_pattern = vec![r"[a-q][^u-z]{3}[x\xE0-\xFF]".to_string()];
        let unicode_haystack = "aöööà--a雪δéx".as_bytes();
        assert_current_fre_execution(
            current_fre(
                "count",
                &unicode_pattern,
                unicode_haystack,
                true,
                false,
                &limits,
            ),
            2,
            "aggregate-fixed-class-sandwich",
        );
        assert_current_fre_execution(
            current_fre(
                "count-spans",
                &unicode_pattern,
                unicode_haystack,
                true,
                false,
                &limits,
            ),
            18,
            "aggregate-fixed-class-sandwich",
        );
    }

    #[test]
    fn exact_literal_build_and_run_limits_map_every_named_quota() {
        let mut run = RunLimits {
            fre_literal_planner_work: 1,
            fre_literal_build_needle_bytes: 2,
            fre_literal_build_work: 3,
            fre_literal_build_scratch_bytes: 4,
            fre_literal_build_persistent_bytes: 5,
            fre_literal_build_peak_bytes: 6,
            ..RunLimits::default()
        };
        let build_limits = aggregate_build_limits(&run);
        assert_eq!(build_limits.max_literal_planner_work, 1);
        assert_eq!(build_limits.exact_literal.max_needle_bytes, 2);
        assert_eq!(build_limits.exact_literal.max_build_work, 3);
        assert_eq!(build_limits.exact_literal.max_scratch_bytes, 4);
        assert_eq!(build_limits.exact_literal.max_persistent_bytes, 5);
        assert_eq!(build_limits.exact_literal.max_peak_bytes, 6);

        let build = fre::LiteralAggregateBuildAccounting {
            needle_bytes: 2,
            temporary_capacity_bytes: 2,
            work_upper_bound: 2,
            scratch_bytes: 2,
            persistent_bytes: 10,
            peak_bytes: 12,
        };
        let derived = literal_operation_limits(10, build, &RunLimits::default()).unwrap();
        assert_eq!(derived.max_linear_terms, 12);
        assert_eq!(derived.max_match_events, 5);
        assert_eq!(derived.max_count, 5);
        assert_eq!(derived.max_span_sum, 10);
        assert_eq!(derived.max_reducer_steps, 6);
        assert_eq!(derived.max_scratch_bytes, 0);
        assert_eq!(derived.max_peak_bytes, 10);

        run.fre_literal_linear_terms = 1;
        run.fre_literal_match_events = 2;
        run.fre_literal_count = 3;
        run.fre_literal_span_sum = 4;
        run.fre_literal_reducer_steps = 5;
        run.fre_literal_scratch_bytes = 6;
        run.fre_literal_peak_bytes = 7;
        let capped = literal_operation_limits(10, build, &run).unwrap();
        assert_eq!(capped.max_linear_terms, 1);
        assert_eq!(capped.max_match_events, 2);
        assert_eq!(capped.max_count, 3);
        assert_eq!(capped.max_span_sum, 4);
        assert_eq!(capped.max_reducer_steps, 5);
        // The selected kernel's authenticated operation scratch upper bound is
        // zero, so a larger policy quota is represented by the tight bound.
        assert_eq!(capped.max_scratch_bytes, 0);
        assert_eq!(capped.max_peak_bytes, 7);
    }

    #[test]
    fn exact_literal_receipt_invariants_and_actual_escape_are_faults_without_fallback() {
        for source in [
            LiteralAggregateReduceError::ReceiptInvariant {
                detail: "injected receipt invariant",
            },
            LiteralAggregateReduceError::ActualEscapedProspective {
                dimension: "match events",
                actual: 2,
                prospective: 1,
            },
        ] {
            let error = literal_reduce_error(&source, source.to_string());
            assert_eq!(error.status, Status::Fault);
            assert_ne!(error.status, Status::Unsupported);
        }
    }

    #[test]
    fn exact_literal_resource_refusal_requires_a_closed_direct_attempt() {
        let regex = AggregateBuilder::new("needle")
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count()
            .expect("exact-literal count");
        let haystack = b"needle";

        let mut linear_limits = AggregateRunLimits::default();
        linear_limits.exact_literal.max_linear_terms = 0;
        let linear_refusal = regex
            .count(haystack, linear_limits)
            .expect_err("linear-term refusal");
        assert!(linear_refusal.has_closed_direct_attempt());
        assert!(matches!(
            linear_refusal.source,
            AggregateExecutionSource::ExactLiteral(
                LiteralAggregateReduceError::LinearTermsLimit { .. }
            )
        ));
        let classified =
            aggregate_attempt_error(&linear_refusal, "valid exact refusal".to_string());
        assert_eq!(classified.status, Status::Unsupported);

        let mut event_limits = AggregateRunLimits::default();
        event_limits.exact_literal.max_match_events = 0;
        let event_refusal = regex
            .count(haystack, event_limits)
            .expect_err("match-event refusal");
        assert!(event_refusal.has_closed_direct_attempt());
        assert!(matches!(
            event_refusal.source,
            AggregateExecutionSource::ExactLiteral(
                LiteralAggregateReduceError::MatchEventsLimit { .. }
            )
        ));

        let mut nested_receipt_splice = linear_refusal.clone();
        nested_receipt_splice.identity = event_refusal.identity.clone();
        assert!(!nested_receipt_splice.has_closed_direct_attempt());
        let classified =
            aggregate_attempt_error(&nested_receipt_splice, "spliced receipt".to_string());
        assert_eq!(classified.status, Status::Fault);

        let mut source_splice = linear_refusal.clone();
        source_splice.source = event_refusal.source.clone();
        assert!(!source_splice.has_closed_direct_attempt());
        let classified = aggregate_attempt_error(&source_splice, "spliced source".to_string());
        assert_eq!(classified.status, Status::Fault);

        let mut identity_splice = linear_refusal;
        let cache = identity_splice
            .identity
            .as_cache_identity()
            .expect("exact direct cache")
            .clone();
        identity_splice.identity =
            fre::AggregateExecutionAttemptIdentity::Incumbent(Box::new(cache));
        assert!(!identity_splice.has_closed_direct_attempt());
        let classified = aggregate_attempt_error(&identity_splice, "spliced identity".to_string());
        assert_eq!(classified.status, Status::Fault);
    }

    #[test]
    fn continuation_build_limits_map_every_named_structural_quota() {
        let run = RunLimits {
            fre_aggregate_compile_work: 11,
            fre_aggregate_hir_nodes: 12,
            fre_aggregate_hir_stack_items: 13,
            fre_aggregate_repeat_bound: 14,
            fre_aggregate_program_bytes: 15,
            ..RunLimits::default()
        };
        let continuation = aggregate_build_limits(&run).continuation;
        assert_eq!(continuation.max_work, 11);
        assert_eq!(continuation.max_hir_nodes, 12);
        assert_eq!(continuation.max_hir_stack_items, 13);
        assert_eq!(continuation.max_repeat_bound, 14);
        assert_eq!(continuation.max_program_bytes, 15);

        let many_continuation = aggregate_many_build_limits(&run).continuation;
        assert_eq!(many_continuation.max_work, 11);
        assert_eq!(many_continuation.max_hir_nodes, 12);
        assert_eq!(many_continuation.max_hir_stack_items, 13);
        assert_eq!(many_continuation.max_repeat_bound, 14);
        assert_eq!(many_continuation.max_program_bytes, 15);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mapping gate keeps direct cardinality, selector ceilings, and exact refusal behavior together"
    )]
    fn capture_limits_preserve_facade_cardinality_and_selector_ceilings() {
        // This scalar-planner-disabled path is a versioned exact construction
        // boundary, but its golden is derived from retained layout rather than
        // copied from an error string. The ten `\p{L}` classes each have 677
        // scalar ranges. Repetitions 5..=14 materialize 95 scalar states. The
        // composed report supplies the final instruction count; every
        // instruction owns two `usize` certificate entries. Fixed storage is
        // rederived below from the
        // terminal-frontier seed, minimum-width proof, start-domain proof,
        // required-literal proof, and both complete inline theorem slots.
        const ALTERNATIVES: usize = 10;
        const SCALAR_RANGES_PER_CLASS: usize = 677;
        const SCALAR_STATES: usize = (5 + 14) * ALTERNATIVES / 2;
        const SCALAR_RANGE_BYTES: usize = 2 * core::mem::size_of::<u32>();
        const COMPOSED_PROGRAM_STATES: usize = 390;
        const PINNED_INSTRUCTION_BYTES: usize = 56;
        const CERTIFICATE_ENTRIES_PER_STATE: usize = 2;
        const TERMINAL_FRONTIER_SEED_BYTES: usize = 56;
        const MINIMUM_MATCH_PROOF_BYTES: usize = core::mem::size_of::<Option<usize>>();
        const START_DOMAIN_PROOF_BYTES: usize = 1;
        const COMPLETE_REQUIRED_LITERAL_PROOF_BYTES: usize = 80;
        const COMPLETE_STATE_BYTE_SLOT_BYTES: usize = 208;
        const COMPLETE_ORDERED_BOUNDED_SPAN_SUM_SLOT_BYTES: usize = 144;
        const DEFAULT_SELECTOR_PROGRAM_BYTES: usize = 32 * 1_048_576;
        const ONE_STATE_ENVELOPE_BYTES: usize = PINNED_INSTRUCTION_BYTES
            + CERTIFICATE_ENTRIES_PER_STATE * core::mem::size_of::<usize>();
        const SCALAR_STORAGE_BYTES: usize =
            SCALAR_STATES * SCALAR_RANGES_PER_CLASS * SCALAR_RANGE_BYTES;
        const FIXED_PROOF_BYTES: usize =
            TERMINAL_FRONTIER_SEED_BYTES + MINIMUM_MATCH_PROOF_BYTES + START_DOMAIN_PROOF_BYTES;

        let run = RunLimits {
            pattern_bytes_per_job: 31,
            fre_aggregate_compile_work: 17,
            fre_aggregate_program_bytes: 19,
            fre_aggregate_peak_bytes: 37,
            fre_capture_selector_program_bytes: 23,
            fre_literal_planner_work: 29,
            ..RunLimits::default()
        };
        let defaults = CaptureBuildLimits::default();
        assert_eq!(
            defaults.selector.max_program_bytes,
            DEFAULT_SELECTOR_PROGRAM_BYTES
        );
        assert_eq!(
            RunLimits::default().fre_capture_selector_program_bytes,
            DEFAULT_SELECTOR_PROGRAM_BYTES
        );
        let mapped = capture_build_limits(&run);
        assert_eq!(mapped.max_hir_work, 17);
        assert_eq!(mapped.engine.max_compile_work, 17);
        assert_eq!(mapped.engine.max_program_bytes, 19);
        assert_eq!(mapped.engine.max_captures, 1_024);
        assert_eq!(
            mapped.selector.max_program_states,
            defaults.selector.max_program_states
        );
        assert_eq!(
            mapped.selector.max_temporary_states,
            defaults.selector.max_temporary_states
        );
        assert_eq!(mapped.selector.max_work, 17);
        assert_eq!(mapped.selector.max_program_bytes, 23);
        assert_eq!(mapped.max_prefix_class_participation_planner_work, 29);
        assert_eq!(mapped.prefix_class_participation.max_shape_units, 31);
        assert_eq!(mapped.prefix_class_participation.max_build_work, 17);
        assert_eq!(mapped.prefix_class_participation.max_scratch_bytes, 0);
        assert_eq!(mapped.prefix_class_participation.max_persistent_bytes, 19);
        assert_eq!(mapped.prefix_class_participation.max_peak_bytes, 37);
        assert_eq!(mapped.prefix_class_participation.max_allocations, 3);
        assert_eq!(
            mapped.prefix_class_participation.max_copied_prefix_bytes,
            31
        );
        assert_eq!(
            mapped
                .prefix_class_participation
                .max_finder_preprocess_input_bytes,
            31
        );
        assert_eq!(
            mapped
                .prefix_class_participation
                .max_initialized_bitmap_bytes,
            64
        );
        assert_eq!(
            mapped
                .prefix_class_participation
                .max_retained_capacity_bytes,
            19
        );

        let pattern = "(a)".repeat(65);
        let patterns = [pattern];
        let haystack = [b'a'; 65];
        assert_current_fre_execution(
            current_fre(
                "count-captures",
                &patterns,
                &haystack,
                false,
                false,
                &RunLimits::default(),
            ),
            66,
            "capture-linear-selector-uniform-participation",
        );

        let overlapping = r"(\p{L}{14})|(\p{L}{13})|(\p{L}{12})|(\p{L}{11})|(\p{L}{10})|(\p{L}{9})|(\p{L}{8})|(\p{L}{7})|(\p{L}{6})|(\p{L}{5})";
        assert_current_fre_execution(
            current_fre(
                "count-captures",
                &[overlapping.to_string()],
                "abcdefghijklmn абвгдежзийклмн".as_bytes(),
                true,
                false,
                &RunLimits::default(),
            ),
            4,
            CURRENT_FRE_CAPTURE_SCALAR_PLAN,
        );
        assert_current_fre_execution(
            current_fre(
                "grep-captures",
                &[overlapping.to_string()],
                "abcdefghijklmn абвгдежзийклмн\nabcde".as_bytes(),
                true,
                false,
                &RunLimits::default(),
            ),
            6,
            CURRENT_FRE_CAPTURE_SCALAR_PLAN,
        );

        assert_eq!(SCALAR_STATES, 95);
        assert_eq!(SCALAR_RANGE_BYTES, 8);
        assert_eq!(ONE_STATE_ENVELOPE_BYTES, 72);
        assert_eq!(SCALAR_STORAGE_BYTES, 514_520);
        assert_eq!(FIXED_PROOF_BYTES, 73);

        let default_fallback =
            capture_regex_one(overlapping, true, false, &RunLimits::default()).unwrap();
        let default_report = default_fallback.build_report();
        assert_eq!(
            default_report.selector.required_literal_proof_bytes,
            COMPLETE_REQUIRED_LITERAL_PROOF_BYTES
        );
        assert_eq!(
            default_report.selector.state_byte_span_sum_persistent_bytes,
            COMPLETE_STATE_BYTE_SLOT_BYTES
        );
        assert_eq!(
            default_report
                .selector
                .ordered_bounded_span_sum_persistent_bytes,
            COMPLETE_ORDERED_BOUNDED_SPAN_SUM_SLOT_BYTES
        );
        assert_eq!(
            default_report.selector.class_ranges,
            ALTERNATIVES * SCALAR_RANGES_PER_CLASS
        );
        assert_eq!(
            default_report.selector.program_states,
            COMPOSED_PROGRAM_STATES
        );
        assert_eq!(default_report.selector.state_byte_span_sum_plans, 0);
        assert_eq!(default_report.selector.ordered_bounded_span_sum_plans, 0);
        assert_eq!(
            default_report.selector.minimum_match_bytes_proof_bytes,
            MINIMUM_MATCH_PROOF_BYTES
        );
        assert_eq!(
            usize::from(default_report.selector.start_domain_proof_bytes),
            START_DOMAIN_PROOF_BYTES
        );
        let required_suffix_storage = default_report.selector.required_suffix_bytes
            + default_report.selector.required_suffixes * core::mem::size_of::<usize>();
        let retained_components = required_suffix_storage
            + FIXED_PROOF_BYTES
            + default_report.selector.required_literal_proof_bytes
            + default_report
                .selector
                .required_internal_anchor_persistent_bytes
            + default_report.selector.url_aggregate_persistent_bytes
            + default_report.selector.candidate_bytes
            + default_report.selector.state_byte_span_sum_persistent_bytes
            + default_report
                .selector
                .ordered_bounded_span_sum_persistent_bytes;
        let full_program_bytes = default_report.selector.program_states * ONE_STATE_ENVELOPE_BYTES
            + SCALAR_STORAGE_BYTES
            + retained_components;
        let incremental_program_bytes = full_program_bytes - ONE_STATE_ENVELOPE_BYTES;
        let incremental_one_below = incremental_program_bytes - 1;
        let full_one_below = full_program_bytes - 1;
        assert_eq!(retained_components, 505);
        assert_eq!(incremental_program_bytes, 543_033);
        assert_eq!(full_program_bytes, 543_105);
        assert_eq!(default_report.selector.program_bytes, full_program_bytes);

        let limits_at = |max_program_bytes| RunLimits {
            fre_capture_scalar_planner_work: 0,
            fre_capture_selector_program_bytes: max_program_bytes,
            ..RunLimits::default()
        };
        let refusal_at = |max_program_bytes| {
            let outcome = current_fre(
                "count-captures",
                &[overlapping.to_string()],
                b"abcdefghijklmn",
                true,
                false,
                &limits_at(max_program_bytes),
            );
            match outcome {
                CandidateOutcome::Unsupported(reason) => reason,
                other => {
                    panic!("capture selector byte quota {max_program_bytes} must refuse: {other:?}")
                }
            }
        };

        let one_below = refusal_at(incremental_one_below);
        let incremental_one_below_message = format!(
            "ProgramBytes requires {incremental_program_bytes}, limit is {incremental_one_below}"
        );
        assert!(
            one_below.contains(&incremental_one_below_message),
            "complete inline slot must move the protected incremental boundary: {one_below}"
        );
        let incremental_exact = refusal_at(incremental_program_bytes);
        let incremental_exact_message = format!(
            "ProgramBytes requires {full_program_bytes}, limit is {incremental_program_bytes}"
        );
        assert!(
            incremental_exact.contains(&incremental_exact_message),
            "exact incremental admission must advance to the full retained boundary: \
             {incremental_exact}"
        );
        let full_one_below_refusal = refusal_at(full_one_below);
        let full_one_below_message =
            format!("ProgramBytes requires {full_program_bytes}, limit is {full_one_below}");
        assert!(
            full_one_below_refusal.contains(&full_one_below_message),
            "full selector ProgramBytes must retain its own one-below refusal: \
             {full_one_below_refusal}"
        );

        let exact_limits = limits_at(full_program_bytes);
        let exact_fallback = capture_regex_one(overlapping, true, false, &exact_limits).unwrap();
        assert_eq!(
            exact_fallback.build_report().selector,
            default_report.selector
        );
        assert_eq!(
            exact_fallback.build_report().plan_identity,
            default_report.plan_identity
        );
        assert_current_fre_execution(
            current_fre(
                "count-captures",
                &[overlapping.to_string()],
                b"abcdefghijklmn",
                true,
                false,
                &exact_limits,
            ),
            2,
            CURRENT_FRE_CAPTURE_ORDERED_ROOT_COUNT_PLAN,
        );
    }

    #[test]
    fn continuation_structural_quotas_refuse_before_plan_publication() {
        let build = |pattern: &str, run: &RunLimits| {
            AggregateBuilder::new(pattern)
                .profile(rebar_profile())
                .unicode(false)
                .case_insensitive(false)
                .limits(aggregate_build_limits(run))
                .plan_selection(AggregatePlanSelection::ForceContinuation)
                .strategy(AggregateStrategy::ReverseSequentialRows)
                .build_count()
                .unwrap_err()
                .to_string()
        };
        let build_many = |pattern: &str, run: &RunLimits| {
            let patterns = vec![pattern.to_string(), "never".to_string()];
            AggregateManyBuilder::new(&patterns)
                .profile(rebar_profile())
                .unicode(false)
                .case_insensitive(false)
                .limits(aggregate_many_build_limits(run))
                .strategy(AggregateStrategy::ReverseSequentialRows)
                .build_count()
                .unwrap_err()
                .to_string()
        };

        let nodes = RunLimits {
            fre_aggregate_hir_nodes: 0,
            ..RunLimits::default()
        };
        assert!(build("a.*b", &nodes).contains("HirNodes"));
        assert!(build_many("a.*b", &nodes).contains("HirNodes"));

        let stack = RunLimits {
            fre_aggregate_hir_stack_items: 0,
            ..RunLimits::default()
        };
        assert!(build("a.*b", &stack).contains("HirStackItems"));
        assert!(build_many("a.*b", &stack).contains("HirStackItems"));

        let repetition = RunLimits {
            fre_aggregate_repeat_bound: 1,
            ..RunLimits::default()
        };
        assert!(build("a{2}", &repetition).contains("RepeatBound"));
        assert!(build_many("a{2}", &repetition).contains("RepeatBound"));
    }

    #[test]
    fn legacy_run_limits_default_new_continuation_structural_quotas() {
        let mut legacy = serde_json::to_value(RunLimits::default()).unwrap();
        let object = legacy.as_object_mut().unwrap();
        for field in [
            "fre_aggregate_hir_nodes",
            "fre_aggregate_hir_stack_items",
            "fre_aggregate_repeat_bound",
        ] {
            assert!(object.remove(field).is_some());
        }
        let decoded: RunLimits = serde_json::from_value(legacy).unwrap();
        let defaults = RunLimits::default();
        assert_eq!(
            decoded.fre_aggregate_hir_nodes,
            defaults.fre_aggregate_hir_nodes
        );
        assert_eq!(
            decoded.fre_aggregate_hir_stack_items,
            defaults.fre_aggregate_hir_stack_items
        );
        assert_eq!(
            decoded.fre_aggregate_repeat_bound,
            defaults.fre_aggregate_repeat_bound
        );
    }

    #[test]
    fn unicode_scalar_build_limits_map_every_named_quota() {
        let run = RunLimits {
            fre_aggregate_compile_work: 19,
            fre_unicode_scalar_planner_work: 7,
            fre_unicode_scalar_build_source_ranges: 8,
            fre_unicode_scalar_build_work: 9,
            fre_unicode_scalar_build_scratch_bytes: 10,
            fre_unicode_scalar_build_persistent_bytes: 11,
            fre_unicode_scalar_build_peak_bytes: 12,
            ..RunLimits::default()
        };
        let build_limits = aggregate_build_limits(&run);
        assert_eq!(build_limits.max_unicode_scalar_planner_work, 7);
        assert_eq!(build_limits.max_grapheme_scalar_dfa_planner_work, 19);
        assert_eq!(build_limits.max_bounded_separated_fields_planner_work, 7);
        assert_eq!(build_limits.unicode_scalar.max_source_ranges, 8);
        assert_eq!(build_limits.unicode_scalar.max_build_work, 9);
        assert_eq!(build_limits.unicode_scalar.max_scratch_bytes, 10);
        assert_eq!(build_limits.unicode_scalar.max_persistent_bytes, 11);
        assert_eq!(build_limits.unicode_scalar.max_peak_bytes, 12);
        assert_eq!(build_limits.bounded_separated_fields.max_source_ranges, 8);
        assert_eq!(build_limits.bounded_separated_fields.max_build_work, 9);
        assert_eq!(
            build_limits.bounded_separated_fields.max_persistent_bytes,
            11
        );
        assert_eq!(build_limits.bounded_separated_fields.max_peak_bytes, 12);

        let defaults = aggregate_build_limits(&RunLimits::default());
        assert_eq!(defaults.max_unicode_scalar_planner_work, 4_096);
        assert_eq!(
            defaults.max_grapheme_scalar_dfa_planner_work,
            RunLimits::default().fre_aggregate_compile_work
        );
        assert_eq!(
            defaults.max_unicode_scalar_planner_work,
            fre::AggregateBuildLimits::default().max_unicode_scalar_planner_work
        );
        assert_eq!(
            defaults.unicode_scalar,
            fre::UnicodeScalarAggregateBuildLimits::default()
        );
    }

    #[test]
    fn legacy_run_limits_default_new_unicode_scalar_quotas() {
        let mut legacy = serde_json::to_value(RunLimits::default()).unwrap();
        let object = legacy.as_object_mut().unwrap();
        for field in [
            "fre_unicode_scalar_planner_work",
            "fre_unicode_scalar_build_source_ranges",
            "fre_unicode_scalar_build_work",
            "fre_unicode_scalar_build_scratch_bytes",
            "fre_unicode_scalar_build_persistent_bytes",
            "fre_unicode_scalar_build_peak_bytes",
        ] {
            assert!(object.remove(field).is_some());
        }
        let decoded: RunLimits = serde_json::from_value(legacy).unwrap();
        let defaults = RunLimits::default();
        assert_eq!(
            decoded.fre_unicode_scalar_planner_work,
            defaults.fre_unicode_scalar_planner_work
        );
        assert_eq!(
            decoded.fre_unicode_scalar_build_source_ranges,
            defaults.fre_unicode_scalar_build_source_ranges
        );
        assert_eq!(
            decoded.fre_unicode_scalar_build_work,
            defaults.fre_unicode_scalar_build_work
        );
        assert_eq!(
            decoded.fre_unicode_scalar_build_scratch_bytes,
            defaults.fre_unicode_scalar_build_scratch_bytes
        );
        assert_eq!(
            decoded.fre_unicode_scalar_build_persistent_bytes,
            defaults.fre_unicode_scalar_build_persistent_bytes
        );
        assert_eq!(
            decoded.fre_unicode_scalar_build_peak_bytes,
            defaults.fre_unicode_scalar_build_peak_bytes
        );
    }

    #[test]
    fn unicode_scalar_run_limits_project_the_retained_owner_envelope() {
        let upper = fre::UnicodeScalarAggregateUpperBounds {
            input_bytes: 10,
            ascii_block_classifications: 0,
            ascii_block_classification_bytes: 0,
            ascii_block_lookahead_bytes: 0,
            decode_byte_checks: 40,
            membership_tests: 10,
            range_comparisons: 30,
            binary_search_comparisons_per_scalar: 3,
            reducer_steps: 0,
            match_events: 10,
            count: 10,
            span_sum: 10,
            work: 80,
            scratch_bytes: 0,
            persistent_bytes: 123,
            peak_bytes: 123,
        };
        let derived = unicode_scalar_operation_limits(upper, &RunLimits::default()).unwrap();
        assert_eq!(derived.max_input_bytes, 10);
        assert_eq!(derived.max_decode_byte_checks, 40);
        assert_eq!(derived.max_membership_tests, 10);
        // Five retained ranges need at most three binary-search comparisons
        // per decoded scalar. The byte length is a safe upper bound on the
        // number of decoded scalars, including invalid one-byte advances.
        assert_eq!(derived.max_range_comparisons, 30);
        assert_eq!(derived.max_reducer_steps, 0);
        assert_eq!(derived.max_match_events, 10);
        assert_eq!(derived.max_count, 10);
        assert_eq!(derived.max_span_sum, 10);
        assert_eq!(derived.max_work, 80);
        assert_eq!(derived.max_scratch_bytes, 0);
        assert_eq!(derived.max_peak_bytes, 123);

        let run_upper = fre::UnicodeScalarAggregateUpperBounds {
            range_comparisons: 50,
            binary_search_comparisons_per_scalar: 5,
            reducer_steps: 11,
            work: 111,
            ..upper
        };
        let run = unicode_scalar_operation_limits(run_upper, &RunLimits::default()).unwrap();
        // Run plans may probe the cached non-ASCII range and its monotone
        // successor before falling back to the bounded binary search.
        assert_eq!(run.max_range_comparisons, 50);
        assert_eq!(run.max_reducer_steps, 11);
        assert_eq!(run.max_work, 111);

        let capped = unicode_scalar_operation_limits(
            run_upper,
            &RunLimits {
                reducer_steps: 4,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(capped.max_match_events, 4);
        assert_eq!(capped.max_count, 4);
        assert_eq!(capped.max_reducer_steps, 4);
        assert_eq!(capped.max_range_comparisons, 50);
        assert_eq!(capped.max_work, 111);
    }

    #[test]
    fn bounded_context_run_limits_bind_the_retained_owner_operation() {
        let count = fre::BoundedContextUpperBounds {
            input_bytes: 10,
            literal_bytes: 2,
            interval_records: 3,
            interval_bytes: 24,
            inspections: 20,
            branches: 30,
            comparisons: 40,
            state_writes: 50,
            work: 140,
            match_events: 4,
            count: 4,
            scratch_bytes: 24,
            persistent_bytes: 16,
            peak_bytes: 40,
        };
        let span_sum = fre::BoundedContextSpanSumUpperBounds {
            input_bytes: 10,
            literal_bytes: 2,
            interval_records: 3,
            interval_bytes: 24,
            inspections: 20,
            branches: 30,
            comparisons: 40,
            state_writes: 50,
            work: 140,
            match_events: 4,
            span_sum: 20,
            scratch_bytes: 24,
            persistent_bytes: 16,
            peak_bytes: 40,
        };
        let defaults = RunLimits::default();

        for operation in [AggregateOperation::Compile, AggregateOperation::Count] {
            let derived = bounded_context_operation_limits(
                operation,
                fre::AggregateRetainedFullWindowUpperBounds::BoundedContextCount(count),
                &defaults,
            )
            .expect("compile/count retain the count envelope");
            assert_eq!(derived.max_count, count.count);
        }
        let derived = bounded_context_operation_limits(
            AggregateOperation::SpanSum,
            fre::AggregateRetainedFullWindowUpperBounds::BoundedContextSpanSum(span_sum),
            &defaults,
        )
        .expect("span-sum retains the span-sum envelope");
        assert_eq!(derived.max_count, span_sum.span_sum);

        assert!(
            bounded_context_operation_limits(
                AggregateOperation::SpanSum,
                fre::AggregateRetainedFullWindowUpperBounds::BoundedContextCount(count),
                &defaults,
            )
            .is_err()
        );
        assert!(
            bounded_context_operation_limits(
                AggregateOperation::Count,
                fre::AggregateRetainedFullWindowUpperBounds::BoundedContextSpanSum(span_sum),
                &defaults,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one retained-artifact matrix binds every repaired direct family to its executable limits"
    )]
    fn retained_direct_owner_limits_project_actual_selected_artifacts() {
        let defaults = RunLimits::default();

        let prefix_haystack = b"abcz--xy7";
        let prefix = current_fre_rebar_aggregate_builder(r"ab[a-z]+|xy[0-9]+", false, false)
            .build_count()
            .expect("prefix/class count artifact");
        assert_eq!(
            prefix.build_report().plan,
            AggregatePlanKind::PrefixClassAlternation
        );
        let Some(fre::AggregateRetainedFullWindowUpperBounds::PrefixClassAlternation(prefix_upper)) =
            prefix
                .retained_full_window_upper_bounds(prefix_haystack.len())
                .expect("prefix/class retained envelope")
        else {
            panic!("prefix/class artifact lost its retained envelope");
        };
        let prefix_limits =
            current_fre_rebar_count_run_limits(prefix_haystack.len(), &prefix).unwrap();
        assert_eq!(
            prefix_limits.prefix_class_alternation.max_work,
            prefix_upper.work
        );
        assert_eq!(
            prefix.count_value(prefix_haystack, prefix_limits).unwrap(),
            2
        );
        assert!(
            current_fre_rebar_aggregate_run_limits(prefix_haystack.len(), prefix.build_report())
                .is_err()
        );
        let prefix_one_below = count_run_limits_with_policy(
            prefix_haystack.len(),
            &prefix,
            &RunLimits {
                fre_aggregate_operation_work: prefix_upper.work - 1,
                ..defaults.clone()
            },
        )
        .unwrap();
        assert!(
            prefix
                .count_value(prefix_haystack, prefix_one_below)
                .is_err()
        );

        let literal_haystack = b"Sherlock Holmes--Sherlock\tHolmes";
        let literal = current_fre_rebar_aggregate_builder(r"Sherlock\s+Holmes", false, false)
            .build_count()
            .expect("literal/class-run/literal count artifact");
        assert_eq!(
            literal.build_report().plan,
            AggregatePlanKind::LiteralClassRunLiteral
        );
        let Some(fre::AggregateRetainedFullWindowUpperBounds::LiteralClassRunLiteral(
            literal_upper,
        )) = literal
            .retained_full_window_upper_bounds(literal_haystack.len())
            .expect("literal/class-run/literal retained envelope")
        else {
            panic!("literal/class-run/literal artifact lost its retained envelope");
        };
        let literal_limits =
            current_fre_rebar_count_run_limits(literal_haystack.len(), &literal).unwrap();
        assert_eq!(
            literal_limits.literal_class_run_literal.max_source_reads,
            literal_upper.source_reads
        );
        assert_eq!(
            literal
                .count_value(literal_haystack, literal_limits)
                .unwrap(),
            2
        );
        let literal_one_below = count_run_limits_with_policy(
            literal_haystack.len(),
            &literal,
            &RunLimits {
                fre_aggregate_operation_work: literal_upper.work - 1,
                ..defaults.clone()
            },
        )
        .unwrap();
        assert!(
            literal
                .count_value(literal_haystack, literal_one_below)
                .is_err()
        );

        let literal_span = current_fre_rebar_aggregate_builder(r"Sherlock\s+Holmes", false, false)
            .build_span_sum()
            .expect("literal/class-run/literal span-sum artifact");
        let Some(fre::AggregateRetainedFullWindowUpperBounds::LiteralClassRunLiteral(
            literal_span_upper,
        )) = literal_span
            .retained_full_window_upper_bounds(literal_haystack.len())
            .expect("literal/class-run/literal span-sum retained envelope")
        else {
            panic!("literal/class-run/literal span-sum artifact lost its retained envelope");
        };
        let literal_span_limits =
            current_fre_rebar_span_sum_run_limits(literal_haystack.len(), &literal_span).unwrap();
        assert_eq!(
            literal_span_limits.literal_class_run_literal.max_span_sum,
            literal_span_upper.span_sum
        );
        assert_eq!(
            literal_span
                .span_sum_value(literal_haystack, literal_span_limits)
                .unwrap(),
            30
        );

        let bounded_haystack = b" ing  walking\t thing\n";
        let bounded = current_fre_rebar_aggregate_builder(r"\s[A-Za-z]{0,12}ing\s", false, false)
            .build_count()
            .expect("bounded-context count artifact");
        assert_eq!(
            bounded.build_report().plan,
            AggregatePlanKind::BoundedContext
        );
        let Some(fre::AggregateRetainedFullWindowUpperBounds::BoundedContextCount(bounded_upper)) =
            bounded
                .retained_full_window_upper_bounds(bounded_haystack.len())
                .expect("bounded-context retained envelope")
        else {
            panic!("bounded-context artifact lost its retained envelope");
        };
        let bounded_limits =
            current_fre_rebar_count_run_limits(bounded_haystack.len(), &bounded).unwrap();
        assert_eq!(bounded_limits.bounded_context.max_work, bounded_upper.work);
        assert_eq!(
            bounded
                .count_value(bounded_haystack, bounded_limits)
                .unwrap(),
            3
        );
        let bounded_one_below = count_run_limits_with_policy(
            bounded_haystack.len(),
            &bounded,
            &RunLimits {
                fre_aggregate_operation_work: bounded_upper.work - 1,
                ..defaults.clone()
            },
        )
        .unwrap();
        assert!(
            bounded
                .count_value(bounded_haystack, bounded_one_below)
                .is_err()
        );

        let bounded_span =
            current_fre_rebar_aggregate_builder(r"\s[A-Za-z]{0,12}ing\s", false, false)
                .build_span_sum()
                .expect("bounded-context span-sum artifact");
        let Some(fre::AggregateRetainedFullWindowUpperBounds::BoundedContextSpanSum(
            bounded_span_upper,
        )) = bounded_span
            .retained_full_window_upper_bounds(bounded_haystack.len())
            .expect("bounded-context span-sum retained envelope")
        else {
            panic!("bounded-context span-sum artifact lost its retained envelope");
        };
        let bounded_span_limits =
            current_fre_rebar_span_sum_run_limits(bounded_haystack.len(), &bounded_span).unwrap();
        assert_eq!(
            bounded_span_limits.bounded_context.max_count,
            bounded_span_upper.span_sum
        );
        assert_eq!(
            bounded_span
                .span_sum_value(bounded_haystack, bounded_span_limits)
                .unwrap(),
            21
        );
    }

    #[test]
    fn aggregate_operation_limits_are_fully_derived_and_quota_capped() {
        let mut run = RunLimits::default();
        let derived =
            continuation_operation_limits(10, conservative_continuation_shape(5).unwrap(), &run)
                .unwrap();
        let cached_frontier = cached_frontier_limits(5, 11, 1).unwrap();
        assert_eq!(cached_frontier.random, 2_162_704);
        assert_eq!(cached_frontier.scratch, 2_162_704);
        assert_eq!(cached_frontier.log, 22);
        assert_eq!(cached_frontier.sequential, 88);
        assert_eq!(cached_frontier.peak, 2_162_726);
        assert!(cached_frontier_initialization_work(5, 11).unwrap() > derived.max_work);
        assert_eq!(derived.max_boundaries, 11);
        assert_eq!(derived.max_table_cells, 0);
        assert_eq!(derived.max_random_access_bytes, 81);
        assert_eq!(derived.max_scratch_bytes, 81);
        assert_eq!(derived.max_log_bytes, 11);
        assert_eq!(derived.max_sequential_bytes, 22);
        assert_eq!(derived.max_match_events, 22);
        assert_eq!(derived.max_output_matches, 11);
        assert_eq!(derived.max_output_bytes, 0);
        assert_eq!(derived.max_span_sum, 10);
        assert_eq!(derived.max_peak_bytes, 92);
        assert_eq!(derived.max_work, 429);

        let unicode = continuation_operation_limits(
            10,
            ContinuationProgramShape {
                requires_utf8_validation: true,
                ..conservative_continuation_shape(5).unwrap()
            },
            &run,
        )
        .unwrap();
        assert_eq!(unicode.max_sequential_bytes, 32);

        let one_below = continuation_operation_limits(
            10,
            conservative_continuation_shape(5).unwrap(),
            &RunLimits {
                fre_aggregate_sequential_bytes: derived.max_sequential_bytes - 1,
                fre_aggregate_operation_work: derived.max_work - 1,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            one_below.max_sequential_bytes,
            derived.max_sequential_bytes - 1
        );
        assert_eq!(one_below.max_work, derived.max_work - 1);

        let row_one_below = continuation_operation_limits(
            10,
            conservative_continuation_shape(5).unwrap(),
            &RunLimits {
                fre_aggregate_random_access_bytes: derived.max_random_access_bytes - 1,
                fre_aggregate_scratch_bytes: derived.max_scratch_bytes - 1,
                fre_aggregate_peak_bytes: derived.max_peak_bytes - 1,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            row_one_below.max_random_access_bytes,
            derived.max_random_access_bytes - 1
        );
        assert_eq!(
            row_one_below.max_scratch_bytes,
            derived.max_scratch_bytes - 1
        );
        assert_eq!(row_one_below.max_peak_bytes, derived.max_peak_bytes - 1);

        run.fre_aggregate_random_access_bytes = 7;
        run.fre_aggregate_scratch_bytes = 6;
        run.fre_aggregate_log_bytes = 5;
        run.fre_aggregate_sequential_bytes = 4;
        run.fre_aggregate_peak_bytes = 3;
        run.fre_aggregate_operation_work = 2;
        let capped =
            continuation_operation_limits(10, conservative_continuation_shape(5).unwrap(), &run)
                .unwrap();
        assert_eq!(capped.max_random_access_bytes, 7);
        assert_eq!(capped.max_scratch_bytes, 6);
        assert_eq!(capped.max_log_bytes, 5);
        assert_eq!(capped.max_sequential_bytes, 4);
        assert_eq!(capped.max_peak_bytes, 3);
        assert_eq!(capped.max_work, 2);
    }

    #[test]
    fn continuation_required_literal_prefix_limits_are_fully_derived() {
        let run = RunLimits::default();
        let baseline_shape = conservative_continuation_shape(5).unwrap();
        let required_literal_shape = ContinuationProgramShape {
            required_literal_sets: 2,
            ..baseline_shape
        };
        let baseline = continuation_operation_limits(10, baseline_shape, &run).unwrap();
        let required = continuation_operation_limits(10, required_literal_shape, &run).unwrap();
        // The pre-engine proof reads the source once and compares every byte
        // against both retained sets: N sequential units and N * (sets + 1)
        // work units, independently of the incumbent continuation envelope.
        assert_eq!(
            required.max_sequential_bytes,
            baseline.max_sequential_bytes + 10
        );
        assert_eq!(required.max_work, baseline.max_work + 30);

        let span_baseline =
            continuation_spans_operation_limits(10, baseline_shape, 1, &run).unwrap();
        let span_required =
            continuation_spans_operation_limits(10, required_literal_shape, 1, &run).unwrap();
        assert_eq!(
            span_required.max_sequential_bytes,
            span_baseline.max_sequential_bytes + 10
        );
        assert_eq!(span_required.max_work, span_baseline.max_work + 30);
    }

    #[test]
    fn url_aggregate_operation_limits_are_exported_and_quota_capped() {
        let input_bytes = 4_100;
        let upper = fre::url_aggregate_reduce_upper_bounds(input_bytes)
            .expect("URL input-only upper bound");
        let derived = url_aggregate_operation_limits(input_bytes, &RunLimits::default())
            .expect("URL adapter limits");
        assert_eq!(derived.max_boundaries, upper.boundaries);
        assert_eq!(derived.max_table_cells, 0);
        assert_eq!(
            derived.max_random_access_bytes,
            upper.random_access_storage_bytes
        );
        assert_eq!(derived.max_scratch_bytes, upper.scratch_bytes);
        assert_eq!(derived.max_log_bytes, 0);
        assert_eq!(derived.max_sequential_bytes, upper.sequential_bytes);
        assert_eq!(derived.max_match_events, upper.match_events);
        assert_eq!(derived.max_output_matches, upper.output_matches);
        assert_eq!(derived.max_output_bytes, 0);
        assert_eq!(derived.max_span_sum, upper.span_sum);
        assert_eq!(derived.max_peak_bytes, upper.peak_bytes);
        assert_eq!(
            derived.max_work,
            RunLimits::default().fre_aggregate_operation_work
        );

        let capped = url_aggregate_operation_limits(
            input_bytes,
            &RunLimits {
                reducer_steps: u64::try_from(upper.boundaries - 1).unwrap(),
                fre_aggregate_random_access_bytes: upper.random_access_storage_bytes - 1,
                fre_aggregate_scratch_bytes: upper.scratch_bytes - 2,
                fre_aggregate_sequential_bytes: upper.sequential_bytes - 3,
                fre_aggregate_peak_bytes: upper.peak_bytes - 4,
                fre_aggregate_operation_work: 17,
                ..RunLimits::default()
            },
        )
        .expect("URL named quotas cap independently");
        assert_eq!(
            capped.max_random_access_bytes,
            upper.random_access_storage_bytes - 1
        );
        assert_eq!(capped.max_scratch_bytes, upper.scratch_bytes - 2);
        assert_eq!(capped.max_sequential_bytes, upper.sequential_bytes - 3);
        assert_eq!(capped.max_peak_bytes, upper.peak_bytes - 4);
        assert_eq!(capped.max_match_events, upper.boundaries - 1);
        assert_eq!(capped.max_output_matches, upper.boundaries - 1);
        assert_eq!(capped.max_work, 17);
        assert_eq!(capped.max_boundaries, upper.boundaries);
        assert_eq!(capped.max_span_sum, upper.span_sum);
    }

    #[test]
    fn cached_storage_is_derived_only_when_fixed_initialization_fits_work() {
        let cache_shape = conservative_continuation_shape(65).unwrap();
        let cache_derived =
            continuation_operation_limits(1_000, cache_shape, &RunLimits::default()).unwrap();
        let cache_storage = cached_frontier_limits(65, 1_001, 1).unwrap();
        let cache_initialization = cached_frontier_initialization_work(65, 1_001).unwrap();
        assert!(cache_initialization <= cache_derived.max_work);
        assert_eq!(cache_derived.max_random_access_bytes, cache_storage.random);
        assert_eq!(cache_derived.max_scratch_bytes, cache_storage.scratch);
        assert_eq!(cache_derived.max_log_bytes, 9_009);
        assert_eq!(cache_derived.max_sequential_bytes, 18_018);
        assert_eq!(cache_derived.max_peak_bytes, cache_storage.peak);

        let cache_ineligible = continuation_operation_limits(
            1_000,
            cache_shape,
            &RunLimits {
                fre_aggregate_operation_work: cache_initialization - 1,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(cache_ineligible.max_random_access_bytes, 1_049);
        assert_eq!(cache_ineligible.max_scratch_bytes, 1_049);
        assert_eq!(cache_ineligible.max_log_bytes, 9_009);
        assert_eq!(cache_ineligible.max_sequential_bytes, 18_018);
        assert_eq!(cache_ineligible.max_peak_bytes, 10_058);
    }

    #[test]
    fn required_anchor_limits_split_random_and_sequential_and_never_widen_quotas() {
        let shape = ContinuationProgramShape {
            states: 9,
            predecessor_edges: 0,
            terminal_frontier_prefix_bytes: 0,
            terminal_frontier_bytes: 0,
            required_literal_sets: 0,
            execution_state_work: 27,
            has_scalar_transitions: false,
            max_scalar_search_checks: 0,
            requires_utf8_validation: false,
            required_internal_anchors: 1,
            required_internal_anchor_bytes: 3,
            required_internal_anchor_optional_stages: 2,
            required_internal_anchor_persistent_bytes: 128,
        };
        let derived = required_internal_anchor_operation_limits(10, shape, &RunLimits::default())
            .expect("derive required-anchor limits");
        assert_eq!(derived.max_boundaries, 11);
        assert_eq!(derived.max_table_cells, 0);
        assert_eq!(derived.max_random_access_bytes, 34);
        assert_eq!(derived.max_sequential_bytes, 22);
        assert_eq!(derived.max_scratch_bytes, 0);
        assert_eq!(derived.max_log_bytes, 0);
        assert_eq!(derived.max_output_bytes, 0);
        assert_eq!(
            derived.max_random_access_bytes + derived.max_sequential_bytes,
            56
        );
        assert_eq!(derived.max_peak_bytes, 128);
        assert_eq!(derived.max_work, 83);
        assert_eq!(derived.max_span_sum, 0);

        let capped = required_internal_anchor_operation_limits(
            10,
            shape,
            &RunLimits {
                reducer_steps: 2,
                fre_aggregate_random_access_bytes: 7,
                fre_aggregate_sequential_bytes: 6,
                fre_aggregate_peak_bytes: 5,
                fre_aggregate_operation_work: 4,
                ..RunLimits::default()
            },
        )
        .expect("derive capped required-anchor limits");
        assert_eq!(capped.max_random_access_bytes, 7);
        assert_eq!(capped.max_sequential_bytes, 6);
        assert_eq!(capped.max_match_events, 3);
        assert_eq!(capped.max_output_matches, 2);
        assert_eq!(capped.max_peak_bytes, 5);
        assert_eq!(capped.max_work, 4);
        assert_eq!(capped.max_table_cells, 0);
        assert_eq!(capped.max_scratch_bytes, 0);
        assert_eq!(capped.max_log_bytes, 0);
        assert_eq!(capped.max_output_bytes, 0);
    }

    fn assert_required_anchor_report_rejected(report: &AggregateBuildReport) {
        assert!(!report.has_closed_required_internal_anchor_identity());
        assert!(require_closed_required_internal_anchor_identity(report).is_err());
        assert!(aggregate_run_limits(128, report, &RunLimits::default()).is_err());
    }

    #[test]
    fn required_anchor_public_private_identity_is_fail_closed() {
        let regex = AggregateBuilder::new(r"[\w]+://[^/\s?#]+[^\s?#]+(?:\?[^\s#]*)?(?:#[^\s]*)?")
            .profile(rebar_profile())
            .unicode(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .unwrap();
        let report = regex.build_report();
        assert!(report.authenticates_required_internal_anchor_identity());
        require_closed_required_internal_anchor_identity(report).unwrap();
        aggregate_run_limits(128, report, &RunLimits::default()).unwrap();

        for field in 0..6 {
            let mut forged = report.clone();
            let AggregateBuildAccounting::Continuation(ref mut compile) = forged.build else {
                panic!("URI must retain continuation accounting");
            };
            match field {
                0 => compile.required_internal_anchors += 1,
                1 => compile.required_internal_anchor_bytes += 1,
                2 => compile.required_internal_anchor_optional_stages += 1,
                3 => compile.required_internal_anchor_build_work += 1,
                4 => compile.required_internal_anchor_build_work_upper_bound += 1,
                5 => compile.required_internal_anchor_persistent_bytes += 1,
                _ => unreachable!(),
            }
            assert_required_anchor_report_rejected(&forged);
        }
        let mut retained = report.clone();
        retained.retained_capacity_bytes += 1;
        assert_required_anchor_report_rejected(&retained);

        let other = AggregateBuilder::new(r"a+Xb+[ab]+")
            .profile(rebar_profile())
            .unicode(false)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .unwrap();
        let mut program = report.clone();
        program.plan_identity = other.build_report().plan_identity;
        assert_required_anchor_report_rejected(&program);
        let mut transplanted = report.clone();
        transplanted.build = other.build_report().build;
        transplanted.plan_identity = other.build_report().plan_identity;
        transplanted.retained_capacity_bytes = other.build_report().retained_capacity_bytes;
        assert_required_anchor_report_rejected(&transplanted);
    }

    #[test]
    fn terminal_frontier_derivation_stays_within_existing_policy_components() {
        let policy = RunLimits {
            fre_aggregate_random_access_bytes: 71,
            fre_aggregate_scratch_bytes: 67,
            fre_aggregate_log_bytes: 61,
            fre_aggregate_sequential_bytes: 59,
            fre_aggregate_peak_bytes: 53,
            fre_aggregate_operation_work: 47,
            ..RunLimits::default()
        };
        let derived = continuation_operation_limits(
            10,
            ContinuationProgramShape {
                predecessor_edges: 10,
                terminal_frontier_prefix_bytes: 5,
                terminal_frontier_bytes: 2,
                ..conservative_continuation_shape(5).unwrap()
            },
            &policy,
        )
        .unwrap();
        assert!(derived.max_random_access_bytes <= policy.fre_aggregate_random_access_bytes);
        assert!(derived.max_scratch_bytes <= policy.fre_aggregate_scratch_bytes);
        assert!(derived.max_log_bytes <= policy.fre_aggregate_log_bytes);
        assert!(derived.max_sequential_bytes <= policy.fre_aggregate_sequential_bytes);
        assert!(derived.max_peak_bytes <= policy.fre_aggregate_peak_bytes);
        assert!(derived.max_work <= policy.fre_aggregate_operation_work);
    }

    #[test]
    fn capture_run_limits_retain_exact_terminal_frontier_shape() {
        let regex = CaptureBuilder::new(
            r"cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)[\\/]",
        )
        .unicode(false)
        .build()
        .unwrap();
        let shape = ContinuationProgramShape::from(regex.build_report().selector);
        assert_eq!(shape.terminal_frontier_prefix_bytes, 5);
        assert_eq!(shape.terminal_frontier_bytes, 2);
        let limits = RunLimits::default();
        let exact = continuation_operation_limits(1_024, shape, &limits).unwrap();
        let record_bytes = (shape.states + 1).div_ceil(8);
        let row_random_access = shape.states * 2 * core::mem::size_of::<usize>() + record_bytes;
        let (terminal_random_access, _) =
            terminal_frontier_resource_upper(1_024, shape, row_random_access)
                .unwrap()
                .unwrap();
        assert_eq!(
            exact.max_random_access_bytes,
            terminal_random_access.min(limits.fre_aggregate_random_access_bytes)
        );
        assert!(
            exact.max_random_access_bytes
                < cached_frontier_limits(shape.states, 1_025, 1)
                    .unwrap()
                    .random
        );
        let capture = capture_count_run_limits(&regex, 1_024, &limits).unwrap();
        assert_eq!(
            capture.selector.max_random_access_bytes,
            exact.max_random_access_bytes
        );
        assert_eq!(capture.selector.max_scratch_bytes, exact.max_scratch_bytes);
    }

    #[test]
    fn aggregate_operation_limits_include_scalar_search_and_shared_decode() {
        let shape = ContinuationProgramShape {
            states: 5,
            predecessor_edges: 4,
            terminal_frontier_prefix_bytes: 0,
            terminal_frontier_bytes: 0,
            required_literal_sets: 0,
            execution_state_work: 11,
            has_scalar_transitions: true,
            max_scalar_search_checks: 10,
            requires_utf8_validation: false,
            required_internal_anchors: 0,
            required_internal_anchor_bytes: 0,
            required_internal_anchor_optional_stages: 0,
            required_internal_anchor_persistent_bytes: 0,
        };
        let derived = continuation_operation_limits(10, shape, &RunLimits::default()).unwrap();
        // 11 boundaries: (11 state work + one shared decode) * 11 to build
        // rows, 4 * 11 to scan, and 5 * 11 * (4 + 10) to replay.
        assert_eq!(derived.max_work, 946);

        let capped = continuation_operation_limits(
            10,
            shape,
            &RunLimits {
                fre_aggregate_operation_work: 945,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(capped.max_work, 945);
    }

    #[test]
    fn continuation_limits_include_authenticated_utf8_prevalidation() {
        let regex = AggregateBuilder::new(r"\b")
            .profile(rebar_profile())
            .unicode(true)
            .limits(aggregate_build_limits(&RunLimits::default()))
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .unwrap();
        let AggregateBuildAccounting::Continuation(compile) = regex.build_report().build else {
            panic!("forced continuation returned another plan");
        };
        let shape = ContinuationProgramShape::from(compile);
        assert!(shape.requires_utf8_validation);

        let bytes = 10;
        let exact = continuation_operation_limits(bytes, shape, &RunLimits::default()).unwrap();
        let without_prevalidation = continuation_operation_limits(
            bytes,
            ContinuationProgramShape {
                requires_utf8_validation: false,
                ..shape
            },
            &RunLimits::default(),
        )
        .unwrap();
        assert_eq!(
            exact.max_sequential_bytes,
            without_prevalidation.max_sequential_bytes + bytes
        );
        assert_eq!(exact.max_work, without_prevalidation.max_work + bytes);

        let one_below = continuation_operation_limits(
            bytes,
            shape,
            &RunLimits {
                fre_aggregate_sequential_bytes: exact.max_sequential_bytes - 1,
                fre_aggregate_operation_work: exact.max_work - 1,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            one_below.max_sequential_bytes,
            exact.max_sequential_bytes - 1
        );
        assert_eq!(one_below.max_work, exact.max_work - 1);
    }

    #[test]
    fn sparse_finite_operation_limits_include_every_search_and_reducer_term() {
        let build = fre::SparseOrderedLiteralAggregateBuildAccounting {
            patterns: 3,
            pattern_bytes: 30,
            identity_bytes: 62,
            identity_capacity_bytes: 62,
            trie_states_upper_bound: 31,
            trie_states_actual: 20,
            sparse_edges_upper_bound: 30,
            sparse_edges_actual: 19,
            build_work: 200,
            max_pattern_bytes: 24,
            min_nonempty_pattern_bytes: Some(1),
            has_empty_pattern: false,
            max_edge_search_checks: 6,
            scratch_bytes: 400,
            persistent_bytes: 500,
            peak_bytes: 900,
        };
        let derived =
            sparse_ordered_literal_operation_limits(10, build, &RunLimits::default()).unwrap();
        assert_eq!(derived.max_transitions, 10);
        assert_eq!(derived.max_match_events, 10);
        assert_eq!(derived.max_reducer_steps, 11);
        assert_eq!(derived.max_ring_initializations, 11);
        // 10 transitions + 20 lookups + 120 comparisons + 10 failures
        // + 11 reducer positions + 11 ring initializations.
        assert_eq!(derived.max_total_work, 182);

        let capped = sparse_ordered_literal_operation_limits(
            10,
            build,
            &RunLimits {
                fre_aggregate_operation_work: 181,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(capped.max_total_work, 181);
    }

    #[test]
    fn finite_identity_requires_matching_dense_packed_or_sparse_algorithm_operation_pair() {
        let identity = |algorithm, operation| AggregateFiniteLiteralIdentity {
            semantics: AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words,
            algorithm,
            operation,
            packed_operation_identity: None,
        };
        assert!(finite_plan_identity_matches(
            identity(
                ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(finite_plan_identity_matches(
            identity(
                SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        let packed_count = current_fre_rebar_aggregate_builder("ab|cd", true, false)
            .build_count()
            .expect("packed count identity fixture");
        let AggregatePlanIdentity::FiniteLiteral(packed_count_identity) =
            packed_count.build_report().plan_identity
        else {
            panic!("packed count identity fixture selected another plan");
        };
        assert!(finite_plan_identity_matches(
            packed_count_identity,
            true,
            LiteralAggregateOperation::Count,
        ));
        let packed_span_sum = current_fre_rebar_aggregate_builder("ab|cd", true, false)
            .build_span_sum()
            .expect("packed span-sum identity fixture");
        let AggregatePlanIdentity::FiniteLiteral(packed_span_sum_identity) =
            packed_span_sum.build_report().plan_identity
        else {
            panic!("packed span-sum identity fixture selected another plan");
        };
        assert!(finite_plan_identity_matches(
            packed_span_sum_identity,
            true,
            LiteralAggregateOperation::SpanSum,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                fre::PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                fre::PACKED_ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
            ),
            true,
            LiteralAggregateOperation::Count,
        ));
        assert!(!finite_plan_identity_matches(
            identity(
                SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
            ),
            false,
            LiteralAggregateOperation::Count,
        ));
    }

    #[test]
    fn aggregate_error_classification_separates_resource_refusal_from_faults() {
        let resource = aggregate_engine_error(
            &AggregateEngineError::ResourceLimit {
                resource: AggregateResource::ExecutionWork,
                required: 2,
                limit: 1,
            },
            "resource".to_string(),
        );
        assert_eq!(resource.status, Status::Unsupported);
        let arithmetic = aggregate_engine_error(
            &AggregateEngineError::ArithmeticOverflow {
                resource: AggregateResource::ExecutionWork,
            },
            "arithmetic".to_string(),
        );
        assert_eq!(arithmetic.status, Status::Fault);
        let invariant = aggregate_engine_error(
            &AggregateEngineError::InternalInvariant("fixture"),
            "invariant".to_string(),
        );
        assert_eq!(invariant.status, Status::Fault);

        let literal_resource = literal_reduce_error(
            &LiteralAggregateReduceError::CountLimit {
                needed: 2,
                limit: 1,
            },
            "literal resource".to_string(),
        );
        assert_eq!(literal_resource.status, Status::Unsupported);
        let literal_arithmetic = literal_reduce_error(
            &LiteralAggregateReduceError::ArithmeticOverflow {
                computation: "fixture",
            },
            "literal arithmetic".to_string(),
        );
        assert_eq!(literal_arithmetic.status, Status::Fault);

        let sparse_build_resource = sparse_ordered_literal_build_error(
            &SparseOrderedLiteralAggregateBuildError::SparseEdgesLimit {
                needed: 2,
                limit: 1,
            },
            "sparse build resource".to_string(),
        );
        assert_eq!(sparse_build_resource.status, Status::Unsupported);
        let sparse_build_fault = sparse_ordered_literal_build_error(
            &SparseOrderedLiteralAggregateBuildError::ArithmeticOverflow {
                computation: "fixture",
            },
            "sparse build arithmetic".to_string(),
        );
        assert_eq!(sparse_build_fault.status, Status::Fault);
        let sparse_reduce_resource = sparse_ordered_literal_reduce_error(
            &SparseOrderedLiteralAggregateReduceError::EdgeSearchChecksLimit {
                needed: 2,
                limit: 1,
            },
            "sparse reduce resource".to_string(),
        );
        assert_eq!(sparse_reduce_resource.status, Status::Unsupported);
        let sparse_reduce_fault = sparse_ordered_literal_reduce_error(
            &SparseOrderedLiteralAggregateReduceError::InternalInvariant { detail: "fixture" },
            "sparse reduce invariant".to_string(),
        );
        assert_eq!(sparse_reduce_fault.status, Status::Fault);

        let packed_build_resource = packed_ordered_literal_build_error(
            &fre::PackedOrderedLiteralAggregateBuildError::WorkLimit {
                needed: 2,
                limit: 1,
            },
            "packed build resource".to_string(),
        );
        assert_eq!(packed_build_resource.status, Status::Unsupported);
        let packed_build_fault = packed_ordered_literal_build_error(
            &fre::PackedOrderedLiteralAggregateBuildError::ArithmeticOverflow {
                computation: "fixture",
            },
            "packed build arithmetic".to_string(),
        );
        assert_eq!(packed_build_fault.status, Status::Fault);
        let packed_reduce_resource = packed_ordered_literal_reduce_error(
            &fre::PackedOrderedLiteralAggregateReduceError::ReducerStepsLimit {
                needed: 2,
                limit: 1,
            },
            "packed reduce resource".to_string(),
        );
        assert_eq!(packed_reduce_resource.status, Status::Unsupported);
        let packed_reduce_fault = packed_ordered_literal_reduce_error(
            &fre::PackedOrderedLiteralAggregateReduceError::InternalInvariant { detail: "fixture" },
            "packed reduce invariant".to_string(),
        );
        assert_eq!(packed_reduce_fault.status, Status::Fault);
    }
}
