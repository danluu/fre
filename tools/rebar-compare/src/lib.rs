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
    AggregateBuilder, AggregateContinuationSemantics, AggregateCountRegex, AggregateEngineError,
    AggregateExactLiteralSemantics, AggregateExecutionSource, AggregateManyBuildAccounting,
    AggregateManyBuildError, AggregateManyBuildLimits, AggregateManyBuildReport,
    AggregateManyBuilder, AggregateManyExecutionSource, AggregateManyLiteralSemantics,
    AggregateManyOperation, AggregateManyPlanIdentity, AggregateManyPlanKind,
    AggregateManyRunLimits, AggregateOperation, AggregateOperationLimits, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateSpanSumRegex,
    AggregateStrategy, AggregateUnicodeScalarSemantics, CaptureAggregateLimits, CaptureBuildError,
    CaptureBuildLimits, CaptureBuilder, CaptureExecutionSource, CaptureRegex, CaptureRunLimits,
    CaptureSearchError, CaptureSearchLimits, CompatibilityProfile, LiteralAggregateBuildError,
    LiteralAggregateBuildLimits, LiteralAggregateOperation, LiteralAggregateReduceError,
    LiteralAggregateReduceLimits, OrderedLiteralAggregateBuildError,
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, PortableBuilder, RustProfile, SearchLimits,
    SearchSessionLimits, UnicodeScalarAggregateBuildError, UnicodeScalarAggregateOperation,
    UnicodeScalarAggregateReduceError, UnicodeScalarAggregateReduceLimits,
};
use rebar_expand::{ExpandedRegex, HaystackTransforms, Job, Manifest, PatternBlob};
use regex_automata::{Input, meta::Regex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

const RUST_ADAPTER: &str = "rebar-rust-regex-1.12.4";
const RE2_ADAPTER: &str = "rebar-re2-2025-11-05";
const FRE_ADAPTER: &str = "fre-current-aggregate-capture-v10-portable-word-run-v1";
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
    /// Maximum retained continuation-program capacity for one aggregate plan.
    pub fre_aggregate_program_bytes: usize,
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
            fre_aggregate_program_bytes: 16 * 1_048_576,
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
        AdapterIdentity {
            adapter: FRE_ADAPTER.to_string(),
            identity: format!(
                "{}; fre Rust-bytes facade: PortableRegex grep with absolute/LF-line/ASCII-word/positive-Unicode-word assertions and a linear canonical Unicode word-run plan plus construction-selected one-pattern compile/count/span-sum and ordered build-many compile/count/span-sum; exact literal, direct Unicode scalar-class, ordered literal, or reverse-sequential-rows continuation; compact canonical scalar ranges; whole-operation capture-erased span selection plus exact-span persistent tagged-history replay for capture reducers",
                profile.identity_string()
            ),
            availability: "one-pattern compile/count/count-spans auto-select exact canonical literals, canonical nonempty root Unicode scalar classes, or a bounded continuation program; the direct scalar plan decodes valid UTF-8 once, advances one byte over invalid encoding, and supports count/span-sum without materializing matches; Unicode-on continuation admits canonical scalar classes as bounded UTF-8 paths plus positive Unicode word boundaries on valid UTF-8, while local Unicode-off raw bytes remain byte-oriented and malformed word-boundary input plus remaining Unicode-word/CRLF assertions stay typed refusals; ordered build-many compile/count/count-spans preserve leftmost-first input priority, use the ordered literal plan for eligible sets, and otherwise use the Unicode-off bounded continuation while retaining every pattern's syntax/profile identity; count-captures/grep-captures use a complete reverse-row selector and replay tagged histories only over its disjoint nonempty spans, while refusing capture Unicode mode and unsupported looks; compile constructs a fresh complete artifact before untimed verification; portable grep construction-selects a linear canonical \\b\\w{m,}\\b Unicode scalar-run plan and otherwise executes bounded canonical UTF-8 scalar-class paths plus absolute/LF-line/ASCII-word and positive Unicode-word assertions; invalid UTF-8 is non-word context for positive Unicode boundaries, while CRLF and remaining Unicode-word looks stay typed refusals; general capture-record/span outputs and all other inputs are unsupported"
                .to_string(),
            runtime_sha256: None,
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
    fn new(message: impl Into<String>) -> Self {
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
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(NFA_SIZE_LIMIT));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(job.regex.unicode)
        .case_insensitive(job.regex.case_insensitive);
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
    let result = regex
        .verify_count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE compiled artifact failed untimed verification: {error}");
            aggregate_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregatePlanKind::ExactLiteral => "compile-aggregate-exact-literal",
        AggregatePlanKind::UnicodeScalarClass => "compile-aggregate-unicode-scalar-class",
        AggregatePlanKind::ContinuationProgram => "compile-aggregate-continuation-program",
    };
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
    let engine_limits = fre::CaptureEngineBuildLimits {
        max_compile_work: limits.fre_aggregate_compile_work,
        max_program_bytes: limits.fre_aggregate_program_bytes,
        ..fre::CaptureEngineBuildLimits::default()
    };
    CaptureBuilder::new(pattern)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(CaptureBuildLimits {
            max_hir_work: limits.fre_aggregate_compile_work,
            engine: engine_limits,
            selector: fre::AggregateCompileLimits {
                max_work: limits.fre_aggregate_compile_work,
                max_program_bytes: limits.fre_aggregate_program_bytes,
                ..fre::AggregateCompileLimits::default()
            },
            ..CaptureBuildLimits::default()
        })
        .build()
        .map_err(|error| capture_build_error(&error))
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
    let mut selector = continuation_operation_limits(haystack_len, selector_states, limits)?;
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
    let regex = capture_regex(request, limits)?;
    let (reducer, work) = capture_reducer_budget(limits)?;
    let run_limits = capture_run_limits(
        request.haystack.len(),
        regex.build_report().selector.program_states,
        work,
        limits.fre_aggregate_sequential_bytes,
        reducer,
        reducer,
        work,
        work,
        work,
        limits,
    )?;
    let result = regex
        .count_captures(request.haystack, run_limits)
        .map_err(|error| {
            capture_execution_error(
                &error.source,
                format!("FRE capture reducer refused execution: {error}"),
            )
        })?;
    let actual = u64::try_from(result.accounting.count)
        .map_err(|_| ExecutionError::fault("FRE capture count does not fit u64"))?;
    Ok(FreReduction {
        actual,
        plan: "capture-linear-selector-persistent-history",
    })
}

fn fre_grep_captures(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = capture_regex(request, limits)?;
    let (reducer_limit, work_limit) = capture_reducer_budget(limits)?;
    let groups = regex
        .build_report()
        .engine
        .captures
        .checked_add(1)
        .ok_or_else(|| ExecutionError::fault("FRE capture group count overflow"))?;
    let mut reducer_events = 0_usize;
    let mut count = 0_usize;
    let mut selector = CaptureSelectorLedger::default();
    let mut state_visits = 0_usize;
    let mut history_nodes = 0_usize;
    let mut history_walk = 0_usize;
    for line in request.haystack.lines() {
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
    let actual = u64::try_from(count)
        .map_err(|_| ExecutionError::fault("FRE grep-capture count does not fit u64"))?;
    Ok(FreReduction {
        actual,
        plan: "capture-linear-selector-persistent-history",
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

fn aggregate_build_limits(limits: &RunLimits) -> AggregateBuildLimits {
    AggregateBuildLimits {
        max_literal_planner_work: limits.fre_literal_planner_work,
        max_unicode_scalar_planner_work: limits.fre_unicode_scalar_planner_work,
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
        continuation: fre::AggregateCompileLimits {
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

/// Build every operation limit explicitly from authenticated input size,
/// exact compiled state count and the report's named policy quotas. The fixed
/// reverse-row strategy never receives a full-table allowance.
fn continuation_operation_limits(
    haystack_len: usize,
    program_states: usize,
    limits: &RunLimits,
) -> Result<AggregateOperationLimits, ExecutionError> {
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
    let sequential_upper = checked_aggregate_mul(log_upper, 2, "sequential bytes")?;
    let peak_upper = checked_aggregate_add(log_upper, random_access_upper, "peak bytes")?;

    // A state contributes at most one evaluation plus two transition checks
    // per boundary. Reverse-row replay adds at most four state steps per
    // boundary, and the scan contributes four boundary steps.
    let state_boundaries =
        checked_aggregate_mul(program_states, boundaries, "state-boundary cells")?;
    let state_work = checked_aggregate_mul(state_boundaries, 7, "state work")?;
    let scan_work = checked_aggregate_mul(boundaries, 4, "scan work")?;
    let work_upper = checked_aggregate_add(state_work, scan_work, "operation work")?;

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
        scalar_binary_search_comparison_bound(build.retained_non_ascii_ranges);
    let range_comparisons = checked_aggregate_mul(
        haystack_len,
        comparisons_per_scalar,
        "scalar range comparisons",
    )?;
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
    let count = u64::try_from(haystack_len)
        .map_err(|_| ExecutionError::fault("FRE scalar count bound does not fit u64"))?;
    let reducer_events = usize::try_from(limits.reducer_steps)
        .map_err(|_| ExecutionError::fault("FRE reducer limit does not fit usize"))?;

    Ok(UnicodeScalarAggregateReduceLimits {
        max_input_bytes: haystack_len,
        max_decode_byte_checks: decode_byte_checks,
        max_membership_tests: haystack_len,
        max_range_comparisons: range_comparisons,
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

fn aggregate_run_limits(
    haystack_len: usize,
    report: &AggregateBuildReport,
    limits: &RunLimits,
) -> Result<AggregateRunLimits, ExecutionError> {
    match report.build {
        AggregateBuildAccounting::ExactLiteral(build) => Ok(AggregateRunLimits {
            exact_literal: literal_operation_limits(haystack_len, build, limits)?,
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            // The continuation policy remains present in cache identity even
            // though no continuation engine exists and no fallback is legal.
            continuation: continuation_operation_limits(haystack_len, 1, limits)?,
        }),
        AggregateBuildAccounting::UnicodeScalar(build) => Ok(AggregateRunLimits {
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: unicode_scalar_operation_limits(haystack_len, build, limits)?,
            continuation: continuation_operation_limits(haystack_len, 1, limits)?,
        }),
        AggregateBuildAccounting::Continuation(compile) => Ok(AggregateRunLimits {
            // Literal policy remains present in cache identity even when HIR
            // eligibility selected the continuation program.
            exact_literal: inactive_literal_operation_limits(limits),
            unicode_scalar: inactive_unicode_scalar_operation_limits(),
            continuation: continuation_operation_limits(
                haystack_len,
                compile.program_states,
                limits,
            )?,
        }),
    }
}

fn require_unicode_plan_identity(
    report: &AggregateBuildReport,
    unicode: bool,
    operation: LiteralAggregateOperation,
) -> Result<(), ExecutionError> {
    if !unicode {
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
        AggregatePlanIdentity::UnicodeScalar(identity)
            if identity.semantics
                == AggregateUnicodeScalarSemantics::UnicodeOnRootClassUtf8False
                && identity.kernel.operation
                    == match operation {
                        LiteralAggregateOperation::Count => UnicodeScalarAggregateOperation::Count,
                        LiteralAggregateOperation::SpanSum => {
                            UnicodeScalarAggregateOperation::SpanSum
                        }
                    }
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

fn aggregate_execution_error(source: &AggregateExecutionSource, message: String) -> ExecutionError {
    match source {
        AggregateExecutionSource::ExactLiteral(source) => literal_reduce_error(source, message),
        AggregateExecutionSource::UnicodeScalar(source) => {
            unicode_scalar_reduce_error(source, message)
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
        | AggregateBuildError::ExactLiteralIneligible { .. } => {
            ExecutionError::unsupported(message)
        }
        AggregateBuildError::ExactLiteralBuild { source, .. } => {
            literal_build_error(source, message)
        }
        AggregateBuildError::UnicodeScalarBuild { source, .. } => {
            unicode_scalar_build_error(source, message)
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
    let result = regex
        .count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate count refused execution: {error}");
            aggregate_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregatePlanKind::ExactLiteral => "aggregate-exact-literal",
        AggregatePlanKind::UnicodeScalarClass => "aggregate-unicode-scalar-class",
        AggregatePlanKind::ContinuationProgram => "aggregate-continuation-program",
    };
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
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
    let result = regex
        .span_sum(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE aggregate span-sum refused execution: {error}");
            aggregate_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregatePlanKind::ExactLiteral => "aggregate-exact-literal",
        AggregatePlanKind::UnicodeScalarClass => "aggregate-unicode-scalar-class",
        AggregatePlanKind::ContinuationProgram => "aggregate-continuation-program",
    };
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
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
    let mut expected_profile = rebar_profile();
    expected_profile.options.unicode = request.unicode;
    expected_profile.options.case_insensitive = request.case_insensitive;
    if report.profile != expected_profile || report.operation != operation {
        return Err(ExecutionError::fault(
            "FRE ordered build-many profile/operation identity mismatch",
        ));
    }
    if report.patterns.len() != request.patterns.len() {
        return Err(ExecutionError::fault(
            "FRE ordered build-many pattern identity count mismatch",
        ));
    }
    for (ordinal, (pattern_report, source)) in
        report.patterns.iter().zip(request.patterns).enumerate()
    {
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
    if request.unicode
        && literal_semantics != Some(AggregateManyLiteralSemantics::UnicodeOnNonemptyUtf8Literals)
    {
        return Err(ExecutionError::fault(
            "FRE Unicode ordered build-many literal proof identity mismatch",
        ));
    }
    if !request.unicode
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
    let program_states = match report.build {
        AggregateManyBuildAccounting::Continuation(compile) => compile.program_states,
        AggregateManyBuildAccounting::OrderedLiteral(_) => 1,
    };
    Ok(AggregateManyRunLimits {
        ordered_literal,
        continuation: continuation_operation_limits(haystack_len, program_states, limits)?,
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
        | AggregateManyBuildError::UnicodeNonLiteral { .. } => ExecutionError::unsupported(message),
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
        AggregateManyExecutionSource::InternalInvariant(_) => ExecutionError::fault(message),
    }
}

fn fre_aggregate_many_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = AggregateManyBuilder::new(request.patterns)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_many_build_limits(limits))
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(request, regex.build_report(), AggregateManyOperation::Count)?;
    let operation_limits =
        aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let result = regex
        .count(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE ordered build-many count refused execution: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "aggregate-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "aggregate-many-continuation-program",
    };
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
}

fn fre_aggregate_many_compile(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<FreReduction, ExecutionError> {
    let regex = AggregateManyBuilder::new(request.patterns)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_many_build_limits(limits))
        .strategy(AggregateStrategy::ReverseSequentialRows)
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
    let regex = AggregateManyBuilder::new(request.patterns)
        .profile(rebar_profile())
        .unicode(request.unicode)
        .case_insensitive(request.case_insensitive)
        .limits(aggregate_many_build_limits(limits))
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_span_sum()
        .map_err(|error| aggregate_many_build_error(&error))?;
    require_aggregate_many_identity(
        request,
        regex.build_report(),
        AggregateManyOperation::SpanSum,
    )?;
    let operation_limits =
        aggregate_many_run_limits(request.haystack.len(), regex.build_report(), limits)?;
    let result = regex
        .span_sum(request.haystack, operation_limits)
        .map_err(|error| {
            let message = format!("FRE ordered build-many span-sum refused execution: {error}");
            aggregate_many_execution_error(&error.source, message)
        })?;
    let plan = match regex.build_report().plan {
        AggregateManyPlanKind::OrderedLiteral => "aggregate-many-ordered-literal",
        AggregateManyPlanKind::ContinuationProgram => "aggregate-many-continuation-program",
    };
    Ok(FreReduction {
        actual: result.value(),
        plan,
    })
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
                let result = regex.count(haystack, *limits).map_err(|error| {
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
                let result = regex.span_sum(haystack, *limits).map_err(|error| {
                    aggregate_execution_error(
                        &error.source,
                        format!("FRE timed span-sum refused execution: {error}"),
                    )
                })?;
                let value = result.value();
                std::hint::black_box(&result);
                Ok(value)
            }
            Self::Count { regex, limits } => {
                regex.count_value(haystack, *limits).map_err(|error| {
                    aggregate_execution_error(
                        &error.source,
                        format!("FRE timed value-only count refused execution: {error}"),
                    )
                })
            }
            Self::SpanSum { regex, limits } => {
                regex.span_sum_value(haystack, *limits).map_err(|error| {
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
        assert!(work.charge(5, 0, 0, &limits).is_err());

        let mut sequential = CaptureSelectorLedger::default();
        sequential
            .charge(1, 8, 9, &limits)
            .expect("first sequential line");
        assert!(sequential.charge(1, 2, 2, &limits).is_err());
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
    fn current_fre_composition_keeps_unicode_capture_and_build_many_reachable() {
        let limits = RunLimits::default();
        let identity = CurrentFreAdapter.identity();
        assert_eq!(
            identity.adapter,
            "fre-current-aggregate-capture-v10-portable-word-run-v1"
        );
        assert!(identity.identity.contains("direct Unicode scalar-class"));
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

        let unicode_capture = current_fre(
            "count-captures",
            &[r"(\pL)".to_string()],
            "雪".as_bytes(),
            true,
            false,
            &limits,
        );
        assert!(
            matches!(unicode_capture, CandidateOutcome::Unsupported(ref reason) if reason.contains("Unicode")),
            "Unicode capture must remain a typed refusal: {unicode_capture:?}"
        );
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
            "aggregate-continuation-program",
        );

        // These are canonical leftmost-first results. The pinned Rust meta
        // adapter's reverse-suffix optimization incorrectly returns 2; exact
        // report generation deliberately retains those reference failures.
        for pattern in [r".abb|b", r"(?:[A-Za-z]ab)?b"] {
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
                "aggregate-continuation-program",
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

        let nosey_repeat = current_fre(
            "compile",
            &[r"[A-Za-z0-9_-]{20,1024}".to_string(), "never".to_string()],
            b"TWITTER_API_KEY",
            false,
            false,
            &RunLimits::default(),
        );
        assert!(
            matches!(nosey_repeat, CandidateOutcome::Unsupported(ref reason) if reason.contains("RepeatBound")),
            "compile-many must retain the frozen repeat cap: {nosey_repeat:?}"
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

        let captures = current_fre(
            "count-captures",
            &["(a)".to_string(), "b".to_string()],
            b"ab",
            false,
            false,
            &limits,
        );
        assert!(
            matches!(captures, CandidateOutcome::Unsupported(ref reason) if reason.contains("no certified count-captures operation")),
            "capture output must remain typed unsupported: {captures:?}"
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
            "aggregate-continuation-program",
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
        assert_current_fre_execution(folded, 1, "aggregate-continuation-program");
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
    fn unicode_scalar_build_limits_map_every_named_quota() {
        let run = RunLimits {
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
        assert_eq!(build_limits.unicode_scalar.max_source_ranges, 8);
        assert_eq!(build_limits.unicode_scalar.max_build_work, 9);
        assert_eq!(build_limits.unicode_scalar.max_scratch_bytes, 10);
        assert_eq!(build_limits.unicode_scalar.max_persistent_bytes, 11);
        assert_eq!(build_limits.unicode_scalar.max_peak_bytes, 12);

        let defaults = aggregate_build_limits(&RunLimits::default());
        assert_eq!(defaults.max_unicode_scalar_planner_work, 4_096);
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
        assert_eq!(derived.max_match_events, 10);
        assert_eq!(derived.max_count, 10);
        assert_eq!(derived.max_span_sum, 10);
        assert_eq!(derived.max_work, 80);
        assert_eq!(derived.max_scratch_bytes, 0);
        assert_eq!(derived.max_peak_bytes, 123);

        let capped = unicode_scalar_operation_limits(
            10,
            build,
            &RunLimits {
                reducer_steps: 4,
                ..RunLimits::default()
            },
        )
        .unwrap();
        assert_eq!(capped.max_match_events, 4);
        assert_eq!(capped.max_count, 4);
        assert_eq!(capped.max_range_comparisons, 30);
        assert_eq!(capped.max_work, 80);
    }

    #[test]
    fn aggregate_operation_limits_are_fully_derived_and_quota_capped() {
        let mut run = RunLimits::default();
        let derived = continuation_operation_limits(10, 5, &run).unwrap();
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

        run.fre_aggregate_random_access_bytes = 7;
        run.fre_aggregate_scratch_bytes = 6;
        run.fre_aggregate_log_bytes = 5;
        run.fre_aggregate_sequential_bytes = 4;
        run.fre_aggregate_peak_bytes = 3;
        run.fre_aggregate_operation_work = 2;
        let capped = continuation_operation_limits(10, 5, &run).unwrap();
        assert_eq!(capped.max_random_access_bytes, 7);
        assert_eq!(capped.max_scratch_bytes, 6);
        assert_eq!(capped.max_log_bytes, 5);
        assert_eq!(capped.max_sequential_bytes, 4);
        assert_eq!(capped.max_peak_bytes, 3);
        assert_eq!(capped.max_work, 2);
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
    }
}
