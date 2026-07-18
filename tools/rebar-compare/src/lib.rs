//! Exact semantic comparator and receipt generator for FRE qualification.
//!
//! This crate deliberately separates input authentication, reference adapter
//! execution and candidate adapter execution. A missing runtime, an unsupported
//! candidate operation and a wrong answer are distinct receipt states.

#![forbid(unsafe_code)]

use std::{
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
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuildReport,
    AggregateBuilder, AggregateCompileRegex, AggregateContinuationSemantics, AggregateCountRegex,
    AggregateEngineError, AggregateExactLiteralSemantics, AggregateExecutionSource,
    AggregateFiniteLiteralIdentity, AggregateFiniteLiteralSemantics,
    AggregateFixedClassSandwichSemantics, AggregateGraphemeScalarDfaSemantics,
    AggregateManyBuildAccounting, AggregateManyBuildError, AggregateManyBuildLimits,
    AggregateManyBuildReport, AggregateManyBuilder, AggregateManyCaptureCountRegex,
    AggregateManyCaptureRunLimits, AggregateManyCaptureSemantics, AggregateManyCompileRegex,
    AggregateManyCountRegex, AggregateManyExecutionSource, AggregateManyLiteralSemantics,
    AggregateManyOperation, AggregateManyPlanIdentity, AggregateManyPlanKind,
    AggregateManyRunLimits, AggregateManySpanSumRegex, AggregateOperation,
    AggregateOperationLimits, AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection,
    AggregateRunLimits, AggregateSpanSumRegex, AggregateStrategy, AggregateUnicodeScalarSemantics,
    BoundedClassSequenceBuildError, BoundedClassSequenceBuildLimits,
    BoundedClassSequenceReduceError, BoundedClassSequenceReduceLimits, CaptureAggregateLimits,
    CaptureBuildError, CaptureBuildLimits, CaptureBuilder, CaptureExecutionSource,
    CaptureOperation, CapturePlanKind, CaptureRegex, CaptureRunLimits, CaptureSearchError,
    CaptureSearchLimits, CompatibilityProfile, FixedClassSandwichBuildError,
    FixedClassSandwichBuildLimits, FixedClassSandwichOperation, FixedClassSandwichReduceError,
    FixedClassSandwichReduceLimits, GraphemeScalarDfaBuildAccounting, GraphemeScalarDfaBuildError,
    GraphemeScalarDfaBuildLimits, GraphemeScalarDfaOperation, GraphemeScalarDfaReduceError,
    GraphemeScalarDfaReduceLimits, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateOperation, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    NoqaBuildError, NoqaBuildLimits, NoqaGrepCaptureBuilder, NoqaGrepCaptureRegex, NoqaRunError,
    NoqaRunLimits, ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, ORDERED_LITERAL_COUNT_PLAN_ID,
    ORDERED_LITERAL_SPAN_SUM_PLAN_ID, OrderedLiteralAggregateBuildError,
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID,
    PREFIX_CLASS_ALTERNATION_PLAN_ID, PortableBuilder, PrefixClassAlternationBuildError,
    PrefixClassAlternationBuildLimits, PrefixClassAlternationReduceError,
    PrefixClassAlternationReduceLimits, RustProfile, SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID, SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID, SearchLimits,
    SearchSessionLimits, SparseOrderedLiteralAggregateBuildError,
    SparseOrderedLiteralAggregateReduceError, UnicodeScalarAggregateBuildError,
    UnicodeScalarAggregateOperation, UnicodeScalarAggregateReduceError,
    UnicodeScalarAggregateReduceLimits,
};
use rebar_expand::{ExpandedRegex, HaystackTransforms, Job, Manifest, PatternBlob};
use regex_automata::{Input, meta::Regex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod canonical_case_fold;
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
/// Stable plan label for capture-erased selection with proved participation.
pub const CURRENT_FRE_CAPTURE_UNIFORM_PLAN: &str = "capture-linear-selector-uniform-participation";
/// Stable plan label for the proved uniform captured scalar-alternation path.
pub const CURRENT_FRE_CAPTURE_SCALAR_PLAN: &str = "capture-uniform-alternation-unicode-scalar";

fn is_current_fre_capture_plan(plan: &str) -> bool {
    matches!(
        plan,
        CURRENT_FRE_CAPTURE_PLAN
            | CURRENT_FRE_CAPTURE_UNIFORM_PLAN
            | CURRENT_FRE_CAPTURE_SCALAR_PLAN
            | fre::NOQA_ASCII_LEADING_PLAN_ID
            | fre::NOQA_ASCII_NO_LEADING_PLAN_ID
            | fre::NOQA_UNICODE_LEADING_PLAN_ID
    )
}

const RUST_ADAPTER: &str = "rebar-rust-regex-1.12.4";
const RE2_ADAPTER: &str = "rebar-re2-2025-11-05";
const FRE_ADAPTER: &str = "fre-current-aggregate-capture-v19-noqa-v1-portable-word-run-v2-unicode-scalar-run-v4-capture-scalar-alternation-v1-finite-dfa-v2-sparse-v1-fixed-class-sandwich-v1-grapheme-scalar-dfa-v1-bounded-class-sequence-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-structural-quota-v8";
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
        AdapterIdentity {
            adapter: FRE_ADAPTER.to_string(),
            identity: format!(
                "{}; fre Rust-bytes facade: PortableRegex grep with absolute/LF-line/ASCII-word/positive-Unicode-word assertions and a linear canonical Unicode word-run plan plus construction-selected one-pattern compile/count/span-sum and ordered build-many compile/count/span-sum/uniform-capture-count; exact literal, direct Unicode scalar-class/counted-run, bounded fixed class-sandwich, ordered grapheme scalar DFA, linear bounded compound byte-class sequence count, shared finite-language dense/sparse automaton, full-Unicode variable-width canonical case-fold alternatives, fixed-class/bounded-gap literal context count, ordered literal, or reverse-sequential-rows continuation; compact canonical scalar ranges; grep-capture participation additionally recognizes three exact literal-anchored noqa HIRs with separate ASCII-leading, ASCII-no-leading, and Unicode-leading identities and allocation-free prospective whole-haystack bounds; other capture participation uses a uniform whole-match proof, a proved uniform captured Unicode-scalar alternation, whole-operation capture-erased span selection with a structural fixed-participation proof, or exact-span persistent tagged-history replay",
                profile.identity_string()
            ),
            availability: "one-pattern compile/count/count-spans auto-select exact canonical literals, canonical nonempty root Unicode scalar classes and greedy/lazy non-nullable root scalar repetitions, span-sum also admits greedy nullable unbounded root scalar repetition by erasing its zero-length matches, exact PREFIX MIDDLE{N} SUFFIX byte/scalar class sandwiches, Unicode-off count for greedy bounded repetitions of pairwise-disjoint HEAD BODY+ TRAIL* byte-class units, Unicode-off fixed-class/bounded-gap literal contexts, a bounded finite-language shared dense or sparse reversed automaton (including nonempty valid-UTF8 Unicode words), a full-Unicode variable-width canonical case-fold alternative count plan, or a bounded continuation program; the direct scalar and fixed-class plans decode valid UTF-8 once and advance one byte over invalid encoding; the direct scalar plan keeps counted and lower-bounded repetition symbolic and supports count/span-sum without materializing matches; fixed-class reduction uses bounded N+2 circular state without a continuation log; bounded compound class count uses three inline byte masks and constant execution state; bounded-context count uses monotone suffix intervals and one non-overlapping unbordered-literal stream in O(N+Q); the finite-language plan preserves leftmost-first HIR order and empty-match progress while using either dense shared transitions or sorted sparse edges with bounded failure links; Unicode-on finite execution rejects empty words and invalid UTF-8 words before selection; Unicode-on continuation admits compact canonical-scalar transitions with bounded UTF-8 decoding plus positive Unicode word boundaries on valid UTF-8, while local Unicode-off raw bytes remain byte-oriented and malformed word-boundary input plus remaining Unicode-word/CRLF assertions stay typed refusals; ordered build-many compile/count/count-spans preserve leftmost-first input priority, use the ordered literal plan for eligible sets, and otherwise use the Unicode-off bounded continuation while retaining every pattern's syntax/profile identity; ordered build-many count-captures additionally requires every nonempty pattern to have exactly one root capture, then reduces ordered matches to the implicit whole-match group plus that uniformly participating capture; one-pattern grep-captures first admits only three exact literal-anchored noqa HIRs under route-specific prospective O(N) work and sequential-byte bounds with zero dynamic scratch; other one-pattern count-captures/grep-captures normalize a proved descending uniform captured Unicode-scalar alternation to one bounded scalar run, use a complete reverse-row selector without tagged replay when the same HIR traversal proves fixed capture participation, and otherwise retain exact-span tagged-history replay; compile constructs a fresh complete artifact before untimed verification; portable grep construction-selects a linear canonical \\b\\w{m,}\\b Unicode scalar-run plan and otherwise executes bounded compact canonical-scalar transitions plus absolute/LF-line/ASCII-word and positive Unicode-word assertions; invalid UTF-8 is non-word context for positive Unicode boundaries, while CRLF and remaining Unicode-word looks stay typed refusals; general capture-record/span outputs and all other inputs are unsupported"
                .to_string(),
            runtime_sha256,
        }
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
                let limits =
                    current_fre_rebar_aggregate_run_limits(haystack.len(), regex.build_report())?;
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
            CurrentFreAggregateOperationInner::CountSingle(regex, limits) => regex
                .count_value(haystack, limits)
                .map_err(|error| CompareError::new(format!("FRE count lifecycle: {error}"))),
            CurrentFreAggregateOperationInner::CountMany(regex, limits) => regex
                .count_value(haystack, *limits)
                .map_err(|error| CompareError::new(format!("FRE count-many lifecycle: {error}"))),
            CurrentFreAggregateOperationInner::SpanSumSingle(regex, limits) => regex
                .span_sum_value(haystack, limits)
                .map_err(|error| CompareError::new(format!("FRE span-sum lifecycle: {error}"))),
            CurrentFreAggregateOperationInner::SpanSumMany(regex, limits) => {
                regex.span_sum_value(haystack, *limits).map_err(|error| {
                    CompareError::new(format!("FRE span-sum-many lifecycle: {error}"))
                })
            }
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
        let limits = current_fre_rebar_aggregate_run_limits(haystack_len, regex.build_report())?;
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
        let limits = current_fre_rebar_aggregate_run_limits(haystack_len, regex.build_report())?;
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

fn aggregate_single_plan_label(model: &str, report: &AggregateBuildReport) -> &'static str {
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
    let sparse = matches!(
        report.build,
        AggregateBuildAccounting::SparseFiniteLiteral(_)
    );
    match (model, report.plan, sparse) {
        ("compile", AggregatePlanKind::ExactLiteral, _) => "compile-aggregate-exact-literal",
        ("compile", AggregatePlanKind::UnicodeScalarClass, _) => {
            "compile-aggregate-unicode-scalar-class"
        }
        ("compile", AggregatePlanKind::FixedClassSandwich, _) => {
            "compile-aggregate-fixed-class-sandwich"
        }
        ("compile", AggregatePlanKind::GraphemeScalarDfa, _) => {
            "compile-aggregate-grapheme-scalar-dfa"
        }
        ("compile", AggregatePlanKind::BoundedClassSequence, _) => {
            "compile-aggregate-bounded-class-sequence"
        }
        ("compile", AggregatePlanKind::PrefixClassAlternation, _) => {
            "compile-aggregate-prefix-class-alternation"
        }
        ("compile", AggregatePlanKind::BoundedContext, _) => "compile-aggregate-bounded-context",
        ("compile", AggregatePlanKind::FiniteLiteralDfa, true) => {
            "compile-aggregate-finite-literal-sparse"
        }
        ("compile", AggregatePlanKind::FiniteLiteralDfa, false) => {
            "compile-aggregate-finite-literal-dfa"
        }
        ("compile", AggregatePlanKind::ContinuationProgram, _) => {
            "compile-aggregate-continuation-program"
        }
        (_, AggregatePlanKind::ExactLiteral, _) => "aggregate-exact-literal",
        (_, AggregatePlanKind::UnicodeScalarClass, _) => "aggregate-unicode-scalar-class",
        (_, AggregatePlanKind::FixedClassSandwich, _) => "aggregate-fixed-class-sandwich",
        (_, AggregatePlanKind::GraphemeScalarDfa, _) => "aggregate-grapheme-scalar-dfa",
        (_, AggregatePlanKind::BoundedClassSequence, _) => "aggregate-bounded-class-sequence",
        (_, AggregatePlanKind::PrefixClassAlternation, _) => "aggregate-prefix-class-alternation",
        (_, AggregatePlanKind::BoundedContext, _) => "aggregate-bounded-context",
        (_, AggregatePlanKind::FiniteLiteralDfa, true) => "aggregate-finite-literal-sparse",
        (_, AggregatePlanKind::FiniteLiteralDfa, false) => "aggregate-finite-literal-dfa",
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

#[derive(Clone, Debug)]
enum CurrentFreCapturePreparation {
    Count(Box<CaptureRunLimits>),
    Grep,
}

#[derive(Clone, Debug)]
enum CurrentFreCaptureRegex {
    General(Box<CaptureRegex>),
    Noqa(Box<NoqaGrepCaptureRegex>),
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
#[derive(Clone, Debug)]
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
        match &self.regex {
            CurrentFreCaptureRegex::General(regex) => capture_plan_label(regex),
            CurrentFreCaptureRegex::Noqa(regex) => regex.build_report().plan_identity.plan_id,
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
    pub fn execute(&self, haystack: &[u8]) -> Result<u64, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "capture lifecycle haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let result = match (&self.regex, &self.preparation) {
            (
                CurrentFreCaptureRegex::General(regex),
                CurrentFreCapturePreparation::Count(run_limits),
            ) => execute_count_captures_with_limits(regex, haystack, **run_limits),
            (CurrentFreCaptureRegex::General(regex), CurrentFreCapturePreparation::Grep) => {
                execute_grep_captures(regex, haystack, &self.limits)
            }
            (CurrentFreCaptureRegex::Noqa(regex), CurrentFreCapturePreparation::Grep) => {
                execute_noqa_grep_captures(regex, haystack, &self.limits)
            }
            (CurrentFreCaptureRegex::Noqa(_), CurrentFreCapturePreparation::Count(_)) => {
                return Err(CompareError::new(
                    "noqa grep-only artifact reached count-captures lifecycle",
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
    let model = CurrentFreCaptureModel::parse(model)?;
    let limits = RunLimits::default();
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
            let regex = if let Some(regex) =
                noqa_grep_capture_regex_one(pattern, unicode, case_insensitive, &limits)
                    .map_err(|error| CompareError::new(error.message))?
            {
                CurrentFreCaptureRegex::Noqa(Box::new(regex))
            } else {
                CurrentFreCaptureRegex::General(Box::new(
                    capture_regex_one(pattern, unicode, case_insensitive, &limits)
                        .map_err(|error| CompareError::new(error.message))?,
                ))
            };
            (regex, CurrentFreCapturePreparation::Grep)
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

/// Derive the exact whole-operation limits used by the authenticated
/// current-FRE Rebar adapter for one already-published aggregate plan.
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
struct FreReduction {
    actual: u64,
    plan: &'static str,
}

fn fre_reducer(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    match request.model {
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
    let operation_limits =
        aggregate_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let operation_limits = &operation_limits;
    let result = regex
        .verify_count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE compiled artifact failed untimed verification: {error}");
            aggregate_execution_error(&error.source, message)
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
        | CaptureBuildError::Syntax(_) => ExecutionError::unsupported(message),
        _ => ExecutionError::fault(message),
    }
}

fn capture_execution_error(source: &CaptureExecutionSource, message: String) -> ExecutionError {
    match source {
        CaptureExecutionSource::Selector(source) => aggregate_engine_error(source, message),
        CaptureExecutionSource::History(CaptureSearchError::Resource { .. }) => {
            ExecutionError::unsupported(message)
        }
        CaptureExecutionSource::History(_) | CaptureExecutionSource::InternalInvariant(_) => {
            ExecutionError::fault(message)
        }
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
    let regex = CaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .limits(capture_build_limits(limits))
        .build()
        .map_err(|error| capture_build_error(&error))?;
    let identity = &regex.build_report().plan_identity;
    if identity.operation != CaptureOperation::CountParticipatingNonempty
        || !matches!(
            identity.plan,
            CapturePlanKind::LinearSelectorUniformParticipation
                | CapturePlanKind::LinearSelectorPersistentHistory
        )
    {
        return Err(ExecutionError::fault(
            "FRE capture builder returned an unexpected plan identity",
        ));
    }
    Ok(regex)
}

fn capture_plan_label(regex: &CaptureRegex) -> &'static str {
    match regex.build_report().plan_identity.plan {
        CapturePlanKind::LinearSelectorUniformParticipation => CURRENT_FRE_CAPTURE_UNIFORM_PLAN,
        CapturePlanKind::LinearSelectorPersistentHistory => CURRENT_FRE_CAPTURE_PLAN,
    }
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
        ..defaults
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "independent capture reducer ledgers remain explicit at each line invocation"
)]
fn capture_run_limits(
    haystack_len: usize,
    selector_states: usize,
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
    let mut selector = continuation_operation_limits(
        haystack_len,
        conservative_continuation_shape(selector_states)?,
        limits,
    )?;
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
        },
        selector,
        max_combined_peak_bytes: limits.fre_aggregate_peak_bytes,
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
    execute_count_captures_with_limits(regex, haystack, run_limits)
}

fn capture_count_run_limits(
    regex: &CaptureRegex,
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<CaptureRunLimits, ExecutionError> {
    let (reducer, work) = capture_reducer_budget(limits)?;
    capture_run_limits(
        haystack_len,
        regex.build_report().selector.program_states,
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
    run_limits: CaptureRunLimits,
) -> Result<u64, ExecutionError> {
    let result = regex
        .count_captures(haystack, run_limits)
        .map_err(|error| {
            capture_execution_error(
                &error.source,
                format!("FRE capture reducer refused execution: {error}"),
            )
        })?;
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
    if let Some((regex, participating)) = uniform_capture_scalar_regex(request, limits) {
        let actual =
            execute_uniform_capture_scalar(&regex, participating, request.haystack, true, limits)?;
        return Ok(FreReduction {
            actual,
            plan: CURRENT_FRE_CAPTURE_SCALAR_PLAN,
        });
    }
    let regex = capture_regex(request, limits)?;
    let plan = capture_plan_label(&regex);
    let actual = execute_grep_captures(&regex, request.haystack, limits)?;
    Ok(FreReduction { actual, plan })
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
        Err(error @ NoqaBuildError::WorkLimit { .. }) => Err(ExecutionError::unsupported(format!(
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
    let mut operation_limits = aggregate_run_limits(haystack.len(), regex.build_report(), limits)?;
    if let Some(line_scan) = line_scan {
        let (remaining_work, _) = line_scan.remaining(limits)?;
        operation_limits.unicode_scalar.max_work =
            operation_limits.unicode_scalar.max_work.min(remaining_work);
    }
    let result = regex.count(haystack, operation_limits).map_err(|error| {
        aggregate_execution_error(
            &error.source,
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
    let (reducer_limit, work_limit) = capture_reducer_budget(limits)?;
    let groups = regex
        .build_report()
        .engine
        .captures
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE capture group count overflow"))?;
    let mut reducer_events = 0_usize;
    let mut count = 0_usize;
    // `ByteSlice::lines` scans the complete haystack for LF delimiters. Bind
    // that work and sequential read before constructing the iterator so a
    // one-below caller cannot trigger an uncharged partial traversal.
    let mut selector = CaptureSelectorLedger::preflight_lf_scan(haystack.len(), limits)?;
    let mut state_visits = 0_usize;
    let mut history_nodes = 0_usize;
    let mut history_walk = 0_usize;
    for line in haystack.lines() {
        reducer_events = checked_aggregate_add(reducer_events, 1, "capture line events")?;
        if reducer_events > reducer_limit {
            return Err(ExecutionError::unsupported(format!(
                "FRE grep-captures line events need {reducer_events}, exceeding {reducer_limit}"
            )));
        }
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
            line.len(),
            regex.build_report().selector.program_states,
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
                &error.source,
                format!("FRE grep-capture reducer refused execution: {error}"),
            )
        })?;
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
        selector.charge(
            result.selector_accounting.work,
            result.selector_accounting.sequential_bytes_written,
            result.selector_accounting.sequential_bytes_read,
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
    u64::try_from(count)
        .map_err(|_| ExecutionError::fault("FRE grep-capture count does not fit u64"))
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
    AggregateBuildLimits {
        max_literal_planner_work: limits.fre_literal_planner_work,
        max_unicode_scalar_planner_work: limits.fre_unicode_scalar_planner_work,
        max_fixed_class_sandwich_planner_work: limits.fre_unicode_scalar_planner_work,
        max_grapheme_scalar_dfa_planner_work: limits.fre_aggregate_compile_work,
        max_bounded_class_sequence_planner_work: limits.fre_unicode_scalar_planner_work,
        max_bounded_affix_planner_work: limits.fre_bounded_affix_planner_work,
        max_prefix_class_alternation_planner_work: limits.fre_literal_planner_work,
        max_bounded_context_planner_work: limits.fre_unicode_scalar_planner_work,
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
        prefix_class_alternation: PrefixClassAlternationBuildLimits {
            max_shape_units: limits.pattern_bytes_per_job,
            max_build_work: limits.fre_aggregate_compile_work,
            max_scratch_bytes: 0,
            max_persistent_bytes: limits.fre_aggregate_program_bytes,
            max_peak_bytes: limits.fre_aggregate_peak_bytes,
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
    execution_state_work: usize,
    has_scalar_transitions: bool,
    max_scalar_search_checks: usize,
    requires_utf8_validation: bool,
}

impl From<fre::AggregateCompileAccounting> for ContinuationProgramShape {
    fn from(accounting: fre::AggregateCompileAccounting) -> Self {
        Self {
            states: accounting.program_states,
            execution_state_work: accounting.execution_state_work,
            has_scalar_transitions: accounting.has_scalar_transitions,
            max_scalar_search_checks: accounting.max_scalar_search_checks,
            requires_utf8_validation: accounting.requires_utf8_validation,
        }
    }
}

fn inactive_continuation_shape() -> ContinuationProgramShape {
    ContinuationProgramShape {
        states: 1,
        // One Match state is evaluated once and has no outgoing transition.
        execution_state_work: 1,
        has_scalar_transitions: false,
        max_scalar_search_checks: 0,
        requires_utf8_validation: false,
    }
}

fn conservative_continuation_shape(
    states: usize,
) -> Result<ContinuationProgramShape, ExecutionError> {
    // Callers that publish their own exact work limit use this helper only for
    // row/log storage. Three units per state is the non-scalar Thompson
    // maximum: one evaluation and two Split transition checks.
    let execution_state_work = checked_aggregate_mul(states, 3, "state work")?;
    Ok(ContinuationProgramShape {
        states,
        execution_state_work,
        has_scalar_transitions: false,
        max_scalar_search_checks: 0,
        requires_utf8_validation: false,
    })
}

/// Build every operation limit explicitly from authenticated input size,
/// exact compiled state/search dimensions and the report's named policy
/// quotas. The fixed reverse-row strategy never receives a full-table
/// allowance.
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
    let boundaries = checked_aggregate_add(haystack_len, 1, "boundary count")?;
    let record_bytes = checked_aggregate_add(program_states, 1, "row decision bits")?.div_ceil(8);
    let row_words = checked_aggregate_mul(program_states, 2, "row words")?;
    let row_bytes = checked_aggregate_mul(row_words, core::mem::size_of::<usize>(), "row bytes")?;
    let random_access_upper =
        checked_aggregate_add(row_bytes, record_bytes, "random-access bytes")?;
    let log_upper = checked_aggregate_mul(record_bytes, boundaries, "row-log bytes")?;
    let row_sequential_upper = checked_aggregate_mul(log_upper, 2, "row sequential bytes")?;
    let prevalidation = if shape.requires_utf8_validation {
        haystack_len
    } else {
        0
    };
    let sequential_upper = checked_aggregate_add(
        row_sequential_upper,
        prevalidation,
        "sequential bytes including UTF-8 prevalidation",
    )?;
    let peak_upper = checked_aggregate_add(log_upper, random_access_upper, "peak bytes")?;

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
        prevalidation,
        "operation work including UTF-8 prevalidation",
    )?;

    let reducer_matches = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let event_upper = checked_aggregate_mul(boundaries, 2, "match events")?;
    let reducer_event_limit =
        checked_aggregate_mul(reducer_matches, 2, "reducer-derived match events")?;

    Ok(AggregateOperationLimits {
        max_boundaries: boundaries,
        max_table_cells: 0,
        max_random_access_bytes: random_access_upper.min(limits.fre_aggregate_random_access_bytes),
        max_scratch_bytes: random_access_upper.min(limits.fre_aggregate_scratch_bytes),
        max_log_bytes: log_upper.min(limits.fre_aggregate_log_bytes),
        max_sequential_bytes: sequential_upper.min(limits.fre_aggregate_sequential_bytes),
        max_match_events: event_upper.min(reducer_event_limit),
        max_output_matches: boundaries.min(reducer_matches),
        max_output_bytes: 0,
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
    haystack_len: usize,
    build: fre::UnicodeScalarAggregateBuildAccounting,
    limits: &RunLimits,
) -> Result<UnicodeScalarAggregateReduceLimits, ExecutionError> {
    let decode_byte_checks = checked_aggregate_mul(haystack_len, 4, "scalar decode checks")?;
    let comparisons_per_scalar =
        scalar_binary_search_comparison_bound(build.retained_non_ascii_ranges)
            .checked_add(
                usize::from(build.repetition.is_run() && build.retained_non_ascii_ranges != 0)
                    .checked_mul(2)
                    .ok_or_else(|| {
                        ExecutionError::fault("FRE cached scalar comparison bound overflow")
                    })?,
            )
            .ok_or_else(|| ExecutionError::fault("FRE cached scalar comparison bound overflow"))?;
    let range_comparisons = checked_aggregate_mul(
        haystack_len,
        comparisons_per_scalar,
        "scalar range comparisons",
    )?;
    let reducer_steps = if build.repetition.is_run() {
        checked_aggregate_add(haystack_len, 1, "scalar run reducer steps")?
    } else {
        0
    };
    // This is the kernel's structural bound: byte examinations, membership
    // tests and range comparisons. It is deliberately not described as an
    // executed-CPU-instruction count.
    let structural_work = checked_aggregate_add(
        checked_aggregate_add(
            decode_byte_checks,
            haystack_len,
            "scalar decode plus membership work",
        )?,
        range_comparisons,
        "scalar total work",
    )?;
    let structural_work = checked_aggregate_add(
        structural_work,
        reducer_steps,
        "scalar work plus run reduction",
    )?;
    let count = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE scalar count bound does not fit u64"))?;
    let reducer_events = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;

    Ok(UnicodeScalarAggregateReduceLimits {
        max_input_bytes: haystack_len,
        max_decode_byte_checks: decode_byte_checks,
        max_membership_tests: haystack_len,
        max_range_comparisons: range_comparisons,
        max_reducer_steps: reducer_steps.min(reducer_events),
        max_match_events: haystack_len.min(reducer_events),
        max_count: count.min(limits.reducer_steps),
        max_span_sum: count,
        max_work: structural_work,
        max_scratch_bytes: 0,
        max_peak_bytes: build.persistent_bytes,
    })
}

fn inactive_unicode_scalar_operation_limits() -> UnicodeScalarAggregateReduceLimits {
    UnicodeScalarAggregateReduceLimits::default()
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
    let role_probes = checked_aggregate_mul(haystack_len, 16, "grapheme role probes")?;
    let branch_checks = checked_aggregate_add(
        checked_aggregate_mul(haystack_len, 24, "grapheme branch checks")?,
        1,
        "grapheme terminal branch",
    )?;
    let repetition_tests = checked_aggregate_add(
        checked_aggregate_mul(haystack_len, 8, "grapheme repetition tests")?,
        1,
        "grapheme terminal repetition",
    )?;
    let role_probe_work = checked_aggregate_mul(role_probes, 4, "grapheme role probe work")?;
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
fn prefix_class_alternation_operation_limits(
    haystack_len: usize,
    build: fre::PrefixClassAlternationBuildAccounting,
    limits: &RunLimits,
) -> Result<PrefixClassAlternationReduceLimits, ExecutionError> {
    let work = checked_aggregate_add(
        checked_aggregate_mul(haystack_len, 16, "prefix/class haystack work")?,
        checked_aggregate_add(
            checked_aggregate_mul(build.shape_units, 8, "prefix/class shape work")?,
            64,
            "prefix/class fixed work",
        )?,
        "prefix/class total work",
    )?;
    let reducer_limit = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;
    let count = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE prefix/class count bound does not fit u64"))?;
    Ok(PrefixClassAlternationReduceLimits {
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_match_events: haystack_len.min(reducer_limit),
        max_count: count.min(limits.reducer_steps),
        max_scratch_bytes: 0,
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn inactive_prefix_class_alternation_operation_limits() -> PrefixClassAlternationReduceLimits {
    PrefixClassAlternationReduceLimits::default()
}

fn bounded_context_operation_limits(
    haystack_len: usize,
    build: fre::BoundedContextBuildAccounting,
    identity: AggregatePlanIdentity,
    limits: &RunLimits,
) -> Result<fre::BoundedContextReduceLimits, ExecutionError> {
    let tail = usize::try_from(build.tail_width)
        .map_err(|_| ExecutionError::fault("FRE bounded-context tail width does not fit usize"))?;
    let interval_records = haystack_len
        .checked_div(
            tail.checked_add(1)
                .ok_or_else(|| ExecutionError::fault("FRE bounded-context tail overflow"))?,
        )
        .ok_or_else(|| ExecutionError::fault("FRE bounded-context interval denominator is zero"))?;
    let interval_bytes =
        checked_aggregate_mul(interval_records, 12, "bounded-context interval bytes")?;
    let work = checked_aggregate_add(
        checked_aggregate_add(
            checked_aggregate_mul(haystack_len, 21, "bounded-context input work")?,
            checked_aggregate_mul(build.literal_bytes, 11, "bounded-context literal work")?,
            "bounded-context input plus literal work",
        )?,
        checked_aggregate_add(
            checked_aggregate_mul(interval_bytes, 3, "bounded-context interval work")?,
            40,
            "bounded-context interval plus fixed work",
        )?,
        "bounded-context total work",
    )?;
    let AggregatePlanIdentity::BoundedContext(identity) = identity else {
        return Err(ExecutionError::fault(
            "FRE bounded-context accounting lacks bounded-context identity",
        ));
    };
    let minimum_match = if identity.kernel.plan_id == fre::BOUNDED_AFFIX_PLAN_ID {
        usize::try_from(build.prefix_width)
            .ok()
            .and_then(|value| value.checked_add(build.literal_bytes))
            .and_then(|value| {
                usize::try_from(build.tail_width)
                    .ok()
                    .and_then(|tail| value.checked_add(tail))
            })
    } else if identity.kernel.plan_id == fre::BOUNDED_CONTEXT_PLAN_ID {
        usize::try_from(build.prefix_width)
            .ok()
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(build.literal_bytes))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| {
                usize::try_from(build.tail_width)
                    .ok()
                    .and_then(|tail| value.checked_add(tail))
            })
    } else {
        return Err(ExecutionError::fault(
            "FRE bounded-context accounting has unknown kernel identity",
        ));
    }
    .ok_or_else(|| ExecutionError::fault("FRE bounded-context minimum match overflow"))?;
    let match_events = haystack_len
        .checked_div(minimum_match)
        .ok_or_else(|| ExecutionError::fault("FRE bounded-context minimum match is zero"))?;
    Ok(fre::BoundedContextReduceLimits {
        max_input_bytes: haystack_len,
        max_work: work.min(limits.fre_aggregate_operation_work),
        max_match_events: match_events,
        max_count: u64::try_from(match_events)
            .map_err(|_| ExecutionError::fault("FRE bounded-context count does not fit u64"))?
            .min(limits.reducer_steps),
        max_scratch_bytes: interval_bytes.min(limits.fre_aggregate_scratch_bytes),
        max_peak_bytes: limits.fre_aggregate_peak_bytes,
    })
}

fn inactive_bounded_context_operation_limits() -> fre::BoundedContextReduceLimits {
    fre::BoundedContextReduceLimits::default()
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

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive aggregate-plan dispatch keeps every plan's inactive limits explicit"
)]
fn aggregate_run_limits(
    haystack_len: usize,
    report: &AggregateBuildReport,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    match report.build {
        AggregateBuildAccounting::ExactLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: literal_operation_limits(haystack_len, build, limits)?,
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            // The continuation policy remains present in cache identity even
            // though no continuation engine exists and no fallback is legal.
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::UnicodeScalar(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: unicode_scalar_operation_limits(haystack_len, build, limits)?,
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
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
            fixed_class_sandwich: fixed_class_sandwich_operation_limits(
                haystack_len,
                build,
                limits,
            )?,
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
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
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: grapheme_scalar_dfa_operation_limits(haystack_len, build, limits)?,
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
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
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: bounded_class_sequence_operation_limits(
                haystack_len,
                build,
                limits,
            )?,
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::PrefixClassAlternation(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: prefix_class_alternation_operation_limits(
                haystack_len,
                build,
                limits,
            )?,
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::BoundedContext(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: bounded_context_operation_limits(
                haystack_len,
                build,
                report.plan_identity,
                limits,
            )?,
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::FiniteLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, Some(build), limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::SparseFiniteLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: sparse_ordered_literal_operation_limits(haystack_len, build, limits)?,
            continuation: continuation_operation_limits(
                haystack_len,
                inactive_continuation_shape(),
                limits,
            )?,
        }),
        AggregateBuildAccounting::Continuation(compile) => Ok(AggregateRunLimits {
            // Literal policy remains present in cache identity even when HIR
            // eligibility selected the continuation program.
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            fixed_class_sandwich: inactive_fixed_class_sandwich_operation_limits(),
            grapheme_scalar_dfa: inactive_grapheme_scalar_dfa_operation_limits(),
            bounded_class_sequence: inactive_bounded_class_sequence_operation_limits(),
            prefix_class_alternation: inactive_prefix_class_alternation_operation_limits(),
            bounded_context: inactive_bounded_context_operation_limits(),
            finite_literal: ordered_literal_operation_limits(haystack_len, None, limits)?,
            continuation: continuation_operation_limits(haystack_len, compile.into(), limits)?,
        }),
    }
}

fn finite_plan_identity_matches(
    identity: AggregateFiniteLiteralIdentity,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> bool {
    let (dense_finite_operation, sparse_finite_operation) = match operation {
        LiteralAggregateOperation::Count => (
            ORDERED_LITERAL_COUNT_PLAN_ID,
            SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
        ),
        LiteralAggregateOperation::SpanSum => (
            ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
            SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
        ),
    };
    let expected_semantics = if unicode {
        AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
    } else {
        AggregateFiniteLiteralSemantics::UnicodeOffByteBoundaries
    };
    let representation_matches = (identity.algorithm == ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
        && identity.operation == dense_finite_operation)
        || (identity.algorithm == SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
            && identity.operation == sparse_finite_operation);
    identity.semantics == expected_semantics && representation_matches
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
    if let AggregatePlanIdentity::FiniteLiteral(identity) = report.plan_identity {
        if finite_plan_identity_matches(identity, unicode, operation) {
            return Ok(());
        }
        return Err(ExecutionError::fault(format!(
            "finite aggregate semantic identity mismatch for {operation:?}: {:?}",
            report.plan_identity
        )));
    }
    if !unicode {
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
                && identity.kernel.plan_id == PREFIX_CLASS_ALTERNATION_PLAN_ID
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
            if operation == LiteralAggregateOperation::Count
                && matches!(
                    identity.kernel.plan_id,
                    fre::BOUNDED_CONTEXT_PLAN_ID | fre::BOUNDED_AFFIX_PLAN_ID
                )
                && identity.kernel.operation_id == fre::BOUNDED_CONTEXT_COUNT_OPERATION_ID
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
            if identity.semantics
                == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
                && identity.kernel.operation == operation
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

fn bounded_context_reduce_error(
    source: &fre::BoundedContextReduceError,
    message: String,
) -> ExecutionError {
    match source {
        fre::BoundedContextReduceError::InputLimit { .. }
        | fre::BoundedContextReduceError::WorkLimit { .. }
        | fre::BoundedContextReduceError::MatchEventsLimit { .. }
        | fre::BoundedContextReduceError::CountLimit { .. }
        | fre::BoundedContextReduceError::ScratchLimit { .. }
        | fre::BoundedContextReduceError::PeakLimit { .. } => ExecutionError::unsupported(message),
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

fn aggregate_execution_error(source: &AggregateExecutionSource, message: String) -> ExecutionError {
    match source {
        AggregateExecutionSource::ExactLiteral(source) => literal_reduce_error(source, message),
        AggregateExecutionSource::UnicodeScalar(source) => {
            unicode_scalar_reduce_error(source, message)
        }
        AggregateExecutionSource::FixedClassSandwich(source) => {
            fixed_class_sandwich_reduce_error(source, message)
        }
        AggregateExecutionSource::GraphemeScalarDfa(source) => {
            grapheme_scalar_dfa_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedClassSequence(source) => {
            bounded_class_sequence_reduce_error(source, message)
        }
        AggregateExecutionSource::PrefixClassAlternation(source) => {
            prefix_class_reduce_error(source, message)
        }
        AggregateExecutionSource::BoundedContext(source) => {
            bounded_context_reduce_error(source, message)
        }
        AggregateExecutionSource::FiniteLiteral(source) => {
            ordered_literal_many_reduce_error(source, message)
        }
        AggregateExecutionSource::SparseFiniteLiteral(source) => {
            sparse_ordered_literal_reduce_error(source, message)
        }
        AggregateExecutionSource::Continuation(source) => aggregate_engine_error(source, message),
        AggregateExecutionSource::InternalInvariant(_) => ExecutionError::fault(message),
    }
}

fn aggregate_build_error(error: &AggregateBuildError) -> ExecutionError {
    let message = format!("FRE aggregate build refused input: {error}");
    match &error {
        AggregateBuildError::Syntax { .. }
        | AggregateBuildError::LiteralPlannerWorkLimit { .. }
        | AggregateBuildError::UnicodeScalarPlannerWorkLimit { .. }
        | AggregateBuildError::FixedClassSandwichPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedAffixPlannerWorkLimit { .. }
        | AggregateBuildError::GraphemeScalarDfaPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedClassSequencePlannerWorkLimit { .. }
        | AggregateBuildError::PrefixClassAlternationPlannerWorkLimit { .. }
        | AggregateBuildError::BoundedContextPlannerWorkLimit { .. }
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
        AggregateBuildError::FixedClassSandwichBuild { source, .. } => {
            fixed_class_sandwich_build_error(source, message)
        }
        AggregateBuildError::GraphemeScalarDfaBuild { source, .. } => {
            grapheme_scalar_dfa_build_error(source, message)
        }
        AggregateBuildError::BoundedClassSequenceBuild { source, .. } => {
            bounded_class_sequence_build_error(source, message)
        }
        AggregateBuildError::PrefixClassAlternationBuild { source, .. } => {
            prefix_class_build_error(source, message)
        }
        AggregateBuildError::BoundedContextBuild { source, .. } => {
            bounded_context_build_error(source, message)
        }
        AggregateBuildError::FiniteLiteralBuild { source, .. } => {
            ordered_literal_many_build_error(source, message)
        }
        AggregateBuildError::SparseFiniteLiteralBuild { source, .. } => {
            sparse_ordered_literal_build_error(source, message)
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
    let operation_limits =
        aggregate_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let operation_limits = &operation_limits;
    let actual = regex
        .count_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate count refused execution: {error}");
            aggregate_execution_error(&error.source, message)
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
    let operation_limits =
        aggregate_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let operation_limits = &operation_limits;
    let actual = regex
        .span_sum_value(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate span-sum refused execution: {error}");
            aggregate_execution_error(&error.source, message)
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
                    aggregate_execution_error(
                        &error.source,
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
                    aggregate_execution_error(
                        &error.source,
                        format!("FRE timed span-sum refused execution: {error}"),
                    )
                })?;
                let value = result.value();
                std::hint::black_box(&result);
                Ok(value)
            }
            Self::Count { regex, limits } => regex.count_value(haystack, limits).map_err(|error| {
                aggregate_execution_error(
                    &error.source,
                    format!("FRE timed value-only count refused execution: {error}"),
                )
            }),
            Self::SpanSum { regex, limits } => {
                regex.span_sum_value(haystack, limits).map_err(|error| {
                    aggregate_execution_error(
                        &error.source,
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
        assert_eq!(count.plan, "capture-linear-selector-persistent-history");

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
        assert_eq!(grep.plan, "capture-linear-selector-persistent-history");
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

            let lifecycle = current_fre_rebar_capture_lifecycle(
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
        }
    }

    #[test]
    fn capture_lifecycle_reuses_one_authenticated_artifact_across_boundaries() {
        let count =
            current_fre_rebar_capture_lifecycle("count-captures", r"(a)(b)?", false, false, 4)
                .expect("count-captures lifecycle");
        assert_eq!(count.model(), "count-captures");
        assert_eq!(count.plan(), CURRENT_FRE_CAPTURE_PLAN);
        assert_eq!(count.execute(b"a ab").expect("first count operation"), 5);
        assert_eq!(count.execute(b"a ab").expect("steady count operation"), 5);
        assert!(count.execute(b"a").is_err());

        let haystack = b"foo foo\r\nZ\r\nfoo\r\nfoo";
        let grep = current_fre_rebar_capture_lifecycle(
            "grep-captures",
            r"([a-z][a-z])([a-z])([\r\n])?",
            false,
            false,
            haystack.len(),
        )
        .expect("grep-captures lifecycle");
        assert_eq!(grep.model(), "grep-captures");
        assert_eq!(grep.plan(), CURRENT_FRE_CAPTURE_PLAN);
        assert_eq!(grep.execute(haystack).expect("first grep operation"), 12);
        assert_eq!(grep.execute(haystack).expect("steady grep operation"), 12);

        assert!(current_fre_rebar_capture_lifecycle("count", "a", false, false, 1).is_err());
        let unicode =
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
            let structural_work = aggregate_run_limits(bytes, regex.build_report(), &defaults)
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
                assert_eq!(work.status, Status::Unsupported);

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
                assert_eq!(sequential.status, Status::Unsupported);
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
    fn current_fre_bounded_affix_receipt_label_binds_kernel_route() {
        assert_current_fre_execution(
            current_fre(
                "count",
                &[r"\s[A-Za-z]{0,12}ing\s".to_string()],
                b" ing  walking\t",
                false,
                false,
                &RunLimits::default(),
            ),
            2,
            "aggregate-bounded-affix",
        );
    }

    #[test]
    fn current_fre_composition_keeps_unicode_capture_and_build_many_reachable() {
        let limits = RunLimits::default();
        let identity = CurrentFreAdapter.identity();
        assert_eq!(
            identity.adapter,
            "fre-current-aggregate-capture-v19-noqa-v1-portable-word-run-v2-unicode-scalar-run-v4-capture-scalar-alternation-v1-finite-dfa-v2-sparse-v1-fixed-class-sandwich-v1-grapheme-scalar-dfa-v1-bounded-class-sequence-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-structural-quota-v8"
        );
        assert!(identity.identity.contains("direct Unicode scalar-class"));
        assert!(identity.identity.contains("fixed class-sandwich"));
        assert!(identity.identity.contains("positive-Unicode-word"));
        assert!(
            identity
                .identity
                .contains("exact-span persistent tagged-history replay")
        );

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
            "capture-linear-selector-persistent-history",
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
            "aggregate-finite-literal-dfa",
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
            "aggregate-finite-literal-dfa",
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
    fn current_fre_unicode_finite_literals_use_the_shared_dfa() {
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
            "aggregate-finite-literal-dfa",
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
            "aggregate-finite-literal-dfa",
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
        assert_current_fre_execution(folded, 1, "aggregate-finite-literal-dfa");
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
        } = &audited.report().details
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
        } = &audited.report().details
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
            &audited.report().details
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
    fn capture_limits_preserve_facade_cardinality_and_selector_ceilings() {
        let run = RunLimits {
            fre_aggregate_compile_work: 17,
            fre_aggregate_program_bytes: 19,
            fre_capture_selector_program_bytes: 23,
            ..RunLimits::default()
        };
        let defaults = CaptureBuildLimits::default();
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

        let selector_starved = RunLimits {
            fre_capture_scalar_planner_work: 0,
            fre_capture_selector_program_bytes: 549_431,
            ..RunLimits::default()
        };
        let refusal = current_fre(
            "count-captures",
            &[overlapping.to_string()],
            b"abcdefghijklmn",
            true,
            false,
            &selector_starved,
        );
        assert!(
            matches!(refusal, CandidateOutcome::Unsupported(ref reason)
                if reason.contains("ProgramBytes requires 549432, limit is 549431")),
            "capture selector byte quota must remain a typed refusal: {refusal:?}"
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
        assert_eq!(build_limits.unicode_scalar.max_source_ranges, 8);
        assert_eq!(build_limits.unicode_scalar.max_build_work, 9);
        assert_eq!(build_limits.unicode_scalar.max_scratch_bytes, 10);
        assert_eq!(build_limits.unicode_scalar.max_persistent_bytes, 11);
        assert_eq!(build_limits.unicode_scalar.max_peak_bytes, 12);

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
    fn unicode_scalar_run_limits_are_derived_from_input_and_retained_ranges() {
        let build = fre::UnicodeScalarAggregateBuildAccounting {
            source_ranges: 9,
            retained_non_ascii_ranges: 5,
            ascii_scalars: 17,
            repetition: fre::UnicodeScalarAggregateRepetition::ExactlyOne,
            range_payload_bytes: 40,
            work: 26,
            temporary_capacity_bytes: 72,
            scratch_bytes: 72,
            persistent_bytes: 123,
            peak_bytes: 195,
        };
        let derived = unicode_scalar_operation_limits(10, build, &RunLimits::default()).unwrap();
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

        let run_build = fre::UnicodeScalarAggregateBuildAccounting {
            repetition: fre::UnicodeScalarAggregateRepetition::OneOrMoreGreedy,
            ..build
        };
        let run = unicode_scalar_operation_limits(10, run_build, &RunLimits::default()).unwrap();
        // Run plans may probe the cached non-ASCII range and its monotone
        // successor before falling back to the bounded binary search.
        assert_eq!(run.max_range_comparisons, 50);
        assert_eq!(run.max_reducer_steps, 11);
        assert_eq!(run.max_work, 111);

        let capped = unicode_scalar_operation_limits(
            10,
            run_build,
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
    fn aggregate_operation_limits_are_fully_derived_and_quota_capped() {
        let mut run = RunLimits::default();
        let derived =
            continuation_operation_limits(10, conservative_continuation_shape(5).unwrap(), &run)
                .unwrap();
        let row_words = 5usize.checked_mul(2).unwrap();
        let row_bytes = row_words
            .checked_mul(core::mem::size_of::<usize>())
            .unwrap();
        let random = row_bytes.checked_add(1).unwrap();
        assert_eq!(derived.max_boundaries, 11);
        assert_eq!(derived.max_table_cells, 0);
        assert_eq!(derived.max_random_access_bytes, random);
        assert_eq!(derived.max_scratch_bytes, random);
        assert_eq!(derived.max_log_bytes, 11);
        assert_eq!(derived.max_sequential_bytes, 22);
        assert_eq!(derived.max_match_events, 22);
        assert_eq!(derived.max_output_matches, 11);
        assert_eq!(derived.max_output_bytes, 0);
        assert_eq!(derived.max_span_sum, 10);
        assert_eq!(derived.max_peak_bytes, random.checked_add(11).unwrap());
        assert_eq!(derived.max_work, 429);

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
    fn aggregate_operation_limits_include_scalar_search_and_shared_decode() {
        let shape = ContinuationProgramShape {
            states: 5,
            execution_state_work: 11,
            has_scalar_transitions: true,
            max_scalar_search_checks: 10,
            requires_utf8_validation: false,
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
    fn finite_identity_requires_matching_dense_or_sparse_algorithm_operation_pair() {
        let identity = |algorithm, operation| AggregateFiniteLiteralIdentity {
            semantics: AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words,
            algorithm,
            operation,
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
    }
}
