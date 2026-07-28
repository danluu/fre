//! KLV runner for timing the public FRE facade with Rebar's operation models.
//!
//! This deliberately implements models, not benchmark names. Construction is
//! outside the timer for `grep`; `compile` times a fresh complete artifact and
//! performs semantic verification only after the sample duration is captured.
//! Capture models require an explicit first/steady boundary and emit a
//! self-identifying canonical raw-observation record instead of legacy CSV.

use std::{
    env,
    error::Error,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

#[cfg(test)]
use bstr::ByteSlice;
#[cfg(test)]
use fre::PortableRegex;
use fre::{
    AggregateBuildAccounting, AggregateBuildReport, AggregateBuilder, AggregateManyBuildReport,
    AggregateManyBuilder, AggregateManyCaptureCountRegex, AggregateManyCaptureRunLimits,
    AggregateManyPlanKind, AggregatePlanIdentity, AggregatePlanKind, BOUNDED_AFFIX_PLAN_ID,
    PlanKind, SearchLimits, SimdDispatchContext, simd_dispatch_profile,
};
use rebar_compare::{
    AUDITED_REBAR_REVISION, CandidateAdapter, CandidateOutcome, CandidateRequest, CompareError,
    CurrentFreAdapter, CurrentFreAggregateCompileArtifact, CurrentFreAggregateCompileLifecycle,
    CurrentFreAggregateOperationLifecycle, CurrentFreGrepSession,
    CurrentFreHotByteOperationLifecycle, InputReceipt, REPORT_SCHEMA, RunLimits,
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_compile_lifecycle,
    current_fre_rebar_aggregate_many_builder, current_fre_rebar_aggregate_many_run_limits,
    current_fre_rebar_aggregate_operation_lifecycle, current_fre_rebar_capture_lifecycle,
    current_fre_rebar_compile_run_limits, current_fre_rebar_count_run_limits,
    current_fre_rebar_grep_session, current_fre_rebar_hot_byte_operation_lifecycle,
    current_fre_rebar_portable_builder, current_fre_rebar_search_limits,
    current_fre_rebar_span_sum_run_limits, current_fre_rebar_validate_aggregate_identity,
    current_fre_rebar_validate_aggregate_many_identity,
    performance_contract::{
        CaptureLifecycleBoundary, CaptureLifecycleObservationIdentity,
        CaptureLifecycleRawObservation, PerformanceCandidateObservationIdentity,
        PerformanceRawObservation, capture_lifecycle_observation_bytes,
        performance_raw_observation_bytes, produce_capture_lifecycle_observation,
        produce_performance_candidate_observation,
        validate_performance_candidate_observation_request,
    },
};
use sha2::{Digest, Sha256};

type DynError = Box<dyn Error + Send + Sync + 'static>;

const RUNNER_SCHEMA: &str = "fre.rebar.klv-runner.v1";
const MAX_KLV_BYTES: u64 = 64 * 1_048_576;

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed CLI keeps parsing, identity checks and dispatch in one auditable boundary"
)]
fn main() -> Result<(), DynError> {
    let mut expectations = Expectations::default();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--quiet" | "-q" => {
                return Err("formal FRE timing samples cannot suppress stdout".into());
            }
            "--version" => {
                let canonical_sha =
                    bound_env("FRE_CANONICAL_SHA", option_env!("FRE_CANONICAL_SHA"))?;
                let canonical_tree =
                    bound_env("FRE_CANONICAL_TREE", option_env!("FRE_CANONICAL_TREE"))?;
                let engine_sha = bound_env("FRE_ENGINE_SHA", option_env!("FRE_ENGINE_SHA"))?;
                let engine_tree = bound_env("FRE_ENGINE_TREE", option_env!("FRE_ENGINE_TREE"))?;
                let runner_sha = bound_env("FRE_RUNNER_SHA", option_env!("FRE_RUNNER_SHA"))?;
                let runner_tree = bound_env("FRE_RUNNER_TREE", option_env!("FRE_RUNNER_TREE"))?;
                let lock = bound_env("FRE_LOCK_SHA256", option_env!("FRE_LOCK_SHA256"))?;
                let profile = bound_env("FRE_BUILD_PROFILE", option_env!("FRE_BUILD_PROFILE"))?;
                let toolchain = bound_env("FRE_TOOLCHAIN", option_env!("FRE_TOOLCHAIN"))?;
                let target = bound_env("FRE_TARGET", option_env!("FRE_TARGET"))?;
                let simd_capabilities = SimdDispatchContext::capture().capabilities();
                println!(
                    "{RUNNER_SCHEMA} protocol=stratified-v1 adapter=fre-current-aggregate-capture-v44-fused-capture-stream-v1-persistent-capture-participation-quotient-v1-anchored-line-capture-v1-bounded-affix-span-sum-v1-terminal-class-frontier-v1-unicode-casefold-suffix-domain-v2-required-literal-line-partition-v1-noqa-v1-portable-word-run-v2-aggregate-word-run-v1-literal-assertions-v1-blocking-delimiter-v1-token-phrase-v2-unicode-scalar-run-v4-capture-scalar-alternation-v1-line-space-operator-v2-line-configured-ruff-three-v1-line-ascii-separated-fields-v1-finite-dfa-v2-packed-v2-sparse-v1-guarded-ascii-word-v1-guarded-unicode-word-ranked-anchor-v1-fixed-predicate-word64-v1-fixed-class-sandwich-v1-literal-class-run-literal-v2-reverse-inner-v1-bounded-literal-pair-v1-grapheme-scalar-dfa-v2-bounded-class-sequence-v1-bounded-separated-fields-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-capture-count-v3-ordered-root-count-v1-continuation-accounting-v6-state-byte-literal-anchor-v1-repeated-lazy-delimiter-v1-required-literal-simd-v1-uniform-prefix-class-participation-v2-required-internal-anchor-v3-structural-quota-v8-regex-redux-composite-v2-url-aggregate-v1-fixed-absolute-domain-v1-terminal-greedy-class-v1-grep-stream-v1-k0-search-session-v1 report={REPORT_SCHEMA} aggregate-explain=44 aggregate-many-explain=3 aggregate-many=compile+count+count-spans+count-captures performance-raw=all-supported facade-explain=1 rebar={AUDITED_REBAR_REVISION} package={} canonical-sha={canonical_sha} canonical-tree={canonical_tree} engine-sha={engine_sha} engine-tree={engine_tree} runner-sha={runner_sha} runner-tree={runner_tree} lock={lock} profile={profile} toolchain={toolchain} target={target} simd-dispatch={} simd-architecture={:?} simd-feature-bits={:032x}",
                    env!("CARGO_PKG_VERSION"),
                    simd_dispatch_profile().name(),
                    simd_capabilities.architecture(),
                    simd_capabilities.usable().bits(),
                );
                return Ok(());
            }
            "--expect-model" => {
                expectations.model = Some(next_argument(&mut arguments, "--expect-model")?);
            }
            "--expect-benchmark" => {
                expectations.benchmark = Some(next_argument(&mut arguments, "--expect-benchmark")?);
            }
            "--expect-plan" => {
                expectations.plan = Some(next_argument(&mut arguments, "--expect-plan")?);
            }
            "--expect-runtime" => {
                expectations.runtime = Some(next_argument(&mut arguments, "--expect-runtime")?);
            }
            "--expect-count" => {
                expectations.count = Some(
                    next_argument(&mut arguments, "--expect-count")?
                        .parse::<u64>()
                        .map_err(|error| format!("invalid --expect-count: {error}"))?,
                );
            }
            "--expect-job-id" => {
                expectations.job_id = Some(next_argument(&mut arguments, "--expect-job-id")?);
            }
            "--expect-contract-id" => {
                expectations.contract_id =
                    Some(next_argument(&mut arguments, "--expect-contract-id")?);
            }
            "--expect-canonical-sha" => {
                expectations.canonical_sha =
                    Some(next_argument(&mut arguments, "--expect-canonical-sha")?);
            }
            "--expect-canonical-tree" => {
                expectations.canonical_tree =
                    Some(next_argument(&mut arguments, "--expect-canonical-tree")?);
            }
            "--expect-semantic-receipts" => {
                expectations.semantic_receipts =
                    Some(next_argument(&mut arguments, "--expect-semantic-receipts")?);
            }
            "--expect-boundary" => {
                expectations.boundary = Some(next_argument(&mut arguments, "--expect-boundary")?);
            }
            "--expect-process-token" => {
                expectations.process_token =
                    Some(next_argument(&mut arguments, "--expect-process-token")?);
            }
            "--expect-comparator" => {
                expectations.comparator =
                    Some(next_argument(&mut arguments, "--expect-comparator")?);
            }
            "--forced-compiler" => {
                expectations.forced_compiler =
                    Some(next_argument(&mut arguments, "--forced-compiler")?);
            }
            "--performance-raw" => {
                expectations.performance_raw = true;
            }
            "--help" | "-h" => {
                return Err(
                    "usage: fre_rebar_runner --expect-benchmark NAME --expect-model MODEL --expect-plan PLAN [--forced-compiler ID] [--expect-runtime ID] --expect-count N [capture: --expect-job-id ID --expect-contract-id ID --expect-canonical-sha OID --expect-canonical-tree OID --expect-semantic-receipts SHA256 --expect-boundary first-public-operation|steady-public-operation --expect-process-token SHA256] [aggregate all-model: --performance-raw plus the identity fields and --expect-comparator ID] | --version"
                        .into(),
                );
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }

    let mut input = Vec::new();
    io::stdin()
        .take(MAX_KLV_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > MAX_KLV_BYTES) {
        return Err(format!("FRE KLV input exceeds {MAX_KLV_BYTES} bytes").into());
    }
    let benchmark = Benchmark::parse(&input)?;
    let expected_benchmark = expectations
        .benchmark
        .as_deref()
        .ok_or("formal FRE timing requires --expect-benchmark")?;
    let expected_model = expectations
        .model
        .as_deref()
        .ok_or("formal FRE timing requires --expect-model")?;
    let _ = expectations
        .plan
        .as_deref()
        .ok_or("formal FRE timing requires --expect-plan")?;
    let _ = expectations
        .count
        .ok_or("formal FRE timing requires --expect-count")?;
    require_optional("model", Some(expected_model), &benchmark.model)?;
    require_optional("benchmark", Some(expected_benchmark), &benchmark.name)?;
    if expectations.forced_compiler.is_some()
        && !matches!(benchmark.model.as_str(), "count" | "count-spans")
    {
        return Err("forced hot-byte compiler supports only count and count-spans".into());
    }
    if expectations.performance_raw {
        require_performance_raw_metadata(&benchmark.model, &expectations)?;
        let observation = model_performance_raw(&benchmark, &expectations)?;
        let bytes = performance_raw_observation_bytes(&observation)?;
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    if benchmark.model == "regex-redux"
        || (benchmark.model == "count-captures" && benchmark.patterns.len() > 1)
    {
        return Err(format!(
            "FRE model {:?} with {} patterns requires --performance-raw",
            benchmark.model,
            benchmark.patterns.len()
        )
        .into());
    }
    require_runtime_expectation(&benchmark.model, expectations.runtime.as_deref())?;
    require_capture_metadata(&benchmark.model, &expectations)?;
    if matches!(benchmark.model.as_str(), "count-captures" | "grep-captures") {
        let observation = model_captures(&benchmark, &expectations)?;
        let bytes = capture_lifecycle_observation_bytes(&observation)?;
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
    }
    let samples = match benchmark.model.as_str() {
        "compile" => model_compile(&benchmark, &expectations)?,
        "count" => model_count(&benchmark, &expectations)?,
        "count-spans" => model_count_spans(&benchmark, &expectations)?,
        "grep" => model_grep(&benchmark, &expectations)?,
        model => return Err(format!("unsupported FRE Rebar model {model:?}").into()),
    };
    if let Some((expected, sample)) = expectations.count.and_then(|expected| {
        samples
            .iter()
            .find(|sample| sample.count != expected)
            .map(|sample| (expected, sample))
    }) {
        return Err(format!(
            "FRE sample count {} differs from expected {expected}",
            sample.count
        )
        .into());
    }
    let mut output = io::stdout().lock();
    for sample in samples {
        writeln!(output, "{},{}", sample.duration.as_nanos(), sample.count)?;
    }
    Ok(())
}

fn bound_env<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str, DynError> {
    value
        .filter(|value| !value.is_empty() && *value != "unbound")
        .ok_or_else(|| format!("runner build provenance {name} is unbound").into())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Expectations {
    benchmark: Option<String>,
    model: Option<String>,
    plan: Option<String>,
    runtime: Option<String>,
    count: Option<u64>,
    job_id: Option<String>,
    contract_id: Option<String>,
    canonical_sha: Option<String>,
    canonical_tree: Option<String>,
    semantic_receipts: Option<String>,
    boundary: Option<String>,
    process_token: Option<String>,
    comparator: Option<String>,
    forced_compiler: Option<String>,
    performance_raw: bool,
}

fn next_argument(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, DynError> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn require_optional(label: &str, expected: Option<&str>, actual: &str) -> Result<(), DynError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(
            format!("FRE {label} identity {actual:?} differs from expected {expected:?}").into(),
        );
    }
    Ok(())
}

fn require_runtime_expectation(model: &str, runtime: Option<&str>) -> Result<(), DynError> {
    match (model, runtime) {
        ("grep", None) => Err("formal FRE grep timing requires --expect-runtime".into()),
        ("grep", Some(_)) | (_, None) => Ok(()),
        (_, Some(_)) => Err("formal non-grep timing rejects --expect-runtime".into()),
    }
}

fn require_capture_metadata(model: &str, expectations: &Expectations) -> Result<(), DynError> {
    if expectations.comparator.is_some() {
        return Err("--expect-comparator requires --performance-raw".into());
    }
    let fields = [
        expectations.job_id.as_deref(),
        expectations.contract_id.as_deref(),
        expectations.canonical_sha.as_deref(),
        expectations.canonical_tree.as_deref(),
        expectations.semantic_receipts.as_deref(),
        expectations.boundary.as_deref(),
        expectations.process_token.as_deref(),
    ];
    let supplied = fields.iter().filter(|value| value.is_some()).count();
    if matches!(model, "count-captures" | "grep-captures") {
        if supplied != fields.len() {
            return Err(
                "formal capture timing requires every authenticated identity and boundary field"
                    .into(),
            );
        }
    } else if supplied != 0 {
        return Err("formal non-capture timing rejects capture identity or boundary fields".into());
    }
    Ok(())
}

fn require_performance_raw_metadata(
    model: &str,
    expectations: &Expectations,
) -> Result<(), DynError> {
    if !matches!(
        model,
        "compile"
            | "count"
            | "count-spans"
            | "grep"
            | "count-captures"
            | "grep-captures"
            | "regex-redux"
    ) {
        return Err(
            format!("all-model raw mode does not yet implement FRE model {model:?}").into(),
        );
    }
    if model != "grep" && expectations.runtime.is_some() {
        return Err("all-model raw non-grep timing rejects --expect-runtime".into());
    }
    let fields = [
        expectations.job_id.as_deref(),
        expectations.contract_id.as_deref(),
        expectations.canonical_sha.as_deref(),
        expectations.canonical_tree.as_deref(),
        expectations.semantic_receipts.as_deref(),
        expectations.boundary.as_deref(),
        expectations.process_token.as_deref(),
        expectations.comparator.as_deref(),
    ];
    if fields.iter().any(Option::is_none) {
        return Err(
            "all-model raw mode requires every identity, boundary, token, and comparator field"
                .into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Benchmark {
    name: String,
    model: String,
    patterns: Vec<String>,
    case_insensitive: bool,
    unicode: bool,
    haystack: Vec<u8>,
    max_iters: u64,
    max_warmup_iters: u64,
    max_time: Duration,
    max_warmup_time: Duration,
}

impl Benchmark {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "delimiter positions prove the two one-byte slice advances are in bounds"
    )]
    fn parse(mut input: &[u8]) -> Result<Self, DynError> {
        let mut name = None;
        let mut model = None;
        let mut patterns = Vec::new();
        let mut case_insensitive = None;
        let mut unicode = None;
        let mut haystack = None;
        let mut max_iters = None;
        let mut max_warmup_iters = None;
        let mut max_time = None;
        let mut max_warmup_time = None;

        while !input.is_empty() {
            let key_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or("KLV field has no key delimiter")?;
            let key = std::str::from_utf8(&input[..key_end])?;
            input = &input[key_end + 1..];
            let length_end = input
                .iter()
                .position(|&byte| byte == b':')
                .ok_or("KLV field has no length delimiter")?;
            let length = std::str::from_utf8(&input[..length_end])?.parse::<usize>()?;
            input = &input[length_end + 1..];
            let value_end = length.checked_add(1).ok_or("KLV field length overflow")?;
            if input.len() < value_end || input[length] != b'\n' {
                return Err("KLV field is truncated or lacks its trailing newline".into());
            }
            let value = &input[..length];
            input = &input[value_end..];

            match key {
                "name" => set_once(&mut name, text(value, key)?.to_owned(), key)?,
                "model" => set_once(&mut model, text(value, key)?.to_owned(), key)?,
                "pattern" => patterns.push(text(value, key)?.to_owned()),
                "case-insensitive" => {
                    set_once(&mut case_insensitive, parse_bool(value, key)?, key)?;
                }
                "unicode" => set_once(&mut unicode, parse_bool(value, key)?, key)?,
                "haystack" => set_once(&mut haystack, value.to_vec(), key)?,
                "max-iters" => set_once(&mut max_iters, parse_u64(value, key)?, key)?,
                "max-warmup-iters" => {
                    set_once(&mut max_warmup_iters, parse_u64(value, key)?, key)?;
                }
                "max-time" => set_once(
                    &mut max_time,
                    Duration::from_nanos(parse_u64(value, key)?),
                    key,
                )?,
                "max-warmup-time" => set_once(
                    &mut max_warmup_time,
                    Duration::from_nanos(parse_u64(value, key)?),
                    key,
                )?,
                unknown => return Err(format!("unrecognized KLV key {unknown:?}").into()),
            }
        }

        let benchmark = Self {
            name: required(name, "name")?,
            model: required(model, "model")?,
            patterns,
            case_insensitive: required(case_insensitive, "case-insensitive")?,
            unicode: required(unicode, "unicode")?,
            haystack: required(haystack, "haystack")?,
            max_iters: required(max_iters, "max-iters")?,
            max_warmup_iters: required(max_warmup_iters, "max-warmup-iters")?,
            max_time: required(max_time, "max-time")?,
            max_warmup_time: required(max_warmup_time, "max-warmup-time")?,
        };
        if benchmark.max_iters != 1 || benchmark.max_warmup_iters != 0 {
            return Err("formal FRE timing requires max-iters=1 and max-warmup-iters=0".into());
        }
        match (benchmark.model.as_str(), benchmark.patterns.len()) {
            ("regex-redux", 0) => {}
            ("regex-redux", count) => {
                return Err(format!(
                    "FRE KLV regex-redux requires no external patterns, got {count}"
                )
                .into());
            }
            (_, 0) => return Err("FRE KLV runner requires at least one pattern".into()),
            ("compile" | "count" | "count-spans" | "count-captures", _) | (_, 1) => {}
            (model, count) => {
                return Err(
                    format!("FRE KLV model {model:?} requires one pattern, got {count}").into(),
                );
            }
        }
        Ok(benchmark)
    }

    fn pattern(&self) -> &str {
        &self.patterns[0]
    }
}

fn text<'a>(value: &'a [u8], key: &str) -> Result<&'a str, DynError> {
    std::str::from_utf8(value).map_err(|error| format!("{key} is not UTF-8: {error}").into())
}

fn parse_bool(value: &[u8], key: &str) -> Result<bool, DynError> {
    match text(value, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("{key} has invalid boolean value {other:?}").into()),
    }
}

fn parse_u64(value: &[u8], key: &str) -> Result<u64, DynError> {
    text(value, key)?
        .parse::<u64>()
        .map_err(|error| format!("{key} has invalid integer value: {error}").into())
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), DynError> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate scalar KLV key {key:?}").into());
    }
    Ok(())
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, DynError> {
    value.ok_or_else(|| format!("missing required KLV key {key:?}").into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Sample {
    duration: Duration,
    count: u64,
}

fn run<T>(
    benchmark: &Benchmark,
    mut operation: impl FnMut() -> Result<T, DynError>,
    mut count: impl FnMut(T) -> Result<u64, DynError>,
) -> Result<Vec<Sample>, DynError> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let value = operation()?;
        let _ = count(value)?;
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let mut samples = Vec::new();
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let value = operation()?;
        let duration = sample_start.elapsed();
        let count = count(value)?;
        samples.push(Sample { duration, count });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn aggregate_builder(benchmark: &Benchmark) -> AggregateBuilder {
    current_fre_rebar_aggregate_builder(
        benchmark.pattern(),
        benchmark.unicode,
        benchmark.case_insensitive,
    )
}

fn aggregate_many_builder(benchmark: &Benchmark) -> AggregateManyBuilder<'_> {
    current_fre_rebar_aggregate_many_builder(
        &benchmark.patterns,
        benchmark.unicode,
        benchmark.case_insensitive,
    )
}

fn specialized_aggregate_plan(model: &str, report: &AggregateBuildReport) -> Option<&'static str> {
    if matches!(
        report.plan_identity,
        fre::AggregatePlanIdentity::WordRun(identity)
            if identity.semantics
                == fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks
    ) {
        return Some(if model == "compile" {
            "compile-aggregate-fixed-class-chunks-v1"
        } else {
            "aggregate-fixed-class-chunks-v1"
        });
    }
    if matches!(
        report.plan_identity,
        AggregatePlanIdentity::BoundedContext(identity)
            if identity.kernel.plan_id == BOUNDED_AFFIX_PLAN_ID
    ) {
        return Some(if model == "compile" {
            "compile-aggregate-bounded-affix"
        } else {
            "aggregate-bounded-affix"
        });
    }
    None
}

fn aggregate_plan(model: &str, report: &AggregateBuildReport) -> &'static str {
    if let Some(plan) = specialized_aggregate_plan(model, report) {
        return plan;
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
        ("compile", AggregatePlanKind::TokenPhrase, _) => "compile-aggregate-token-phrase-v2",
        ("compile", AggregatePlanKind::FixedClassSandwich, _) => {
            "compile-aggregate-fixed-class-sandwich"
        }
        ("compile", AggregatePlanKind::LiteralClassRunLiteral, _) => {
            "compile-aggregate-literal-class-run-literal-v2"
        }
        ("compile", AggregatePlanKind::ReverseInner, _) => "compile-aggregate-reverse-inner-v1",
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
        ("compile", AggregatePlanKind::GuardedUnicodeWordLiteralSet, _) => {
            "compile-aggregate-guarded-unicode-word"
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
        (_, AggregatePlanKind::TokenPhrase, _) => "aggregate-token-phrase-v2",
        (_, AggregatePlanKind::FixedClassSandwich, _) => "aggregate-fixed-class-sandwich",
        (_, AggregatePlanKind::LiteralClassRunLiteral, _) => {
            "aggregate-literal-class-run-literal-v2"
        }
        (_, AggregatePlanKind::ReverseInner, _) => "aggregate-reverse-inner-v1",
        (_, AggregatePlanKind::BoundedLiteralPair, _) => "aggregate-bounded-literal-pair-v1",
        (_, AggregatePlanKind::GraphemeScalarDfa, _) => "aggregate-grapheme-scalar-dfa",
        (_, AggregatePlanKind::BoundedClassSequence, _) => "aggregate-bounded-class-sequence",
        (_, AggregatePlanKind::BoundedSeparatedFields, _) => "aggregate-bounded-separated-fields",
        (_, AggregatePlanKind::PrefixClassAlternation, _) => "aggregate-prefix-class-alternation",
        (_, AggregatePlanKind::BoundedContext, _) => "aggregate-bounded-context",
        (_, AggregatePlanKind::FixedAbsoluteDomain, _) => "aggregate-fixed-absolute-domain",
        (_, AggregatePlanKind::FiniteLiteralDfa, true) => "aggregate-finite-literal-sparse",
        (_, AggregatePlanKind::FiniteLiteralDfa, false) => "aggregate-finite-literal-dfa",
        (_, AggregatePlanKind::PackedFiniteLiteral, _) => "aggregate-finite-literal-packed-v2",
        (_, AggregatePlanKind::GuardedAsciiWordDictionary, _) => "aggregate-guarded-ascii-word",
        (_, AggregatePlanKind::GuardedUnicodeWordLiteralSet, _) => {
            "aggregate-guarded-unicode-word"
        }
        (_, AggregatePlanKind::FixedPredicateWord64, _) => "aggregate-fixed-predicate-word64",
        (_, AggregatePlanKind::ContinuationProgram, _) => "aggregate-continuation-program",
    }
}

fn aggregate_many_plan(model: &str, report: &AggregateManyBuildReport) -> &'static str {
    match (model, report.plan) {
        ("compile", AggregateManyPlanKind::OrderedLiteral) => "compile-many-ordered-literal",
        ("compile", AggregateManyPlanKind::ContinuationProgram) => {
            "compile-many-continuation-program"
        }
        ("count-captures", AggregateManyPlanKind::OrderedLiteral) => "capture-many-ordered-literal",
        ("count-captures", AggregateManyPlanKind::ContinuationProgram) => {
            "capture-many-continuation-program"
        }
        (_, AggregateManyPlanKind::OrderedLiteral) => "aggregate-many-ordered-literal",
        (_, AggregateManyPlanKind::ContinuationProgram) => "aggregate-many-continuation-program",
    }
}

fn require_aggregate_plan(
    model: &str,
    report: &AggregateBuildReport,
    unicode: bool,
    expectations: &Expectations,
) -> Result<(), DynError> {
    current_fre_rebar_validate_aggregate_identity(report, unicode, model)?;
    require_optional(
        "plan",
        expectations.plan.as_deref(),
        aggregate_plan(model, report),
    )
}

fn require_aggregate_many_plan(
    benchmark: &Benchmark,
    model: &str,
    report: &AggregateManyBuildReport,
    expectations: &Expectations,
) -> Result<(), DynError> {
    current_fre_rebar_validate_aggregate_many_identity(
        &benchmark.patterns,
        report,
        benchmark.unicode,
        benchmark.case_insensitive,
        model,
    )?;
    require_optional(
        "plan",
        expectations.plan.as_deref(),
        aggregate_many_plan(model, report),
    )
}

fn model_compile(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    if benchmark.patterns.len() > 1 {
        return model_compile_many(benchmark, expectations);
    }
    let haystack = benchmark.haystack.as_slice();
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let artifact = aggregate_builder(benchmark).build_compile()?;
        require_aggregate_plan(
            "compile",
            artifact.build_report(),
            benchmark.unicode,
            expectations,
        )?;
        let limits = current_fre_rebar_compile_run_limits(haystack.len(), &artifact)?;
        let limits = &limits;
        let _ = artifact.verify_count(haystack, limits)?;
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let mut samples = Vec::new();
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        // Rebar's reference compile model includes builder/configuration
        // creation in every fresh construction sample, so FRE does too.
        let sample_start = Instant::now();
        let artifact = aggregate_builder(benchmark).build_compile()?;
        let duration = sample_start.elapsed();
        require_aggregate_plan(
            "compile",
            artifact.build_report(),
            benchmark.unicode,
            expectations,
        )?;
        let limits = current_fre_rebar_compile_run_limits(haystack.len(), &artifact)?;
        let limits = &limits;
        let count = artifact.verify_count(haystack, limits)?.value();
        samples.push(Sample { duration, count });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn model_compile_many(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    let haystack = benchmark.haystack.as_slice();
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let artifact = aggregate_many_builder(benchmark).build_compile()?;
        require_aggregate_many_plan(benchmark, "compile", artifact.build_report(), expectations)?;
        let limits =
            current_fre_rebar_aggregate_many_run_limits(haystack.len(), artifact.build_report())?;
        let _ = artifact.verify_count(haystack, limits)?;
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let mut samples = Vec::new();
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let artifact = aggregate_many_builder(benchmark).build_compile()?;
        let duration = sample_start.elapsed();
        require_aggregate_many_plan(benchmark, "compile", artifact.build_report(), expectations)?;
        let limits =
            current_fre_rebar_aggregate_many_run_limits(haystack.len(), artifact.build_report())?;
        let count = artifact.verify_count(haystack, limits)?.value();
        samples.push(Sample { duration, count });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn model_count(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    if expectations.forced_compiler.is_some() {
        return model_hot_byte_operation(benchmark, expectations);
    }
    if benchmark.patterns.len() > 1 {
        return model_count_many(benchmark, expectations);
    }
    let regex = aggregate_builder(benchmark).build_count()?;
    require_aggregate_plan(
        "count",
        regex.build_report(),
        benchmark.unicode,
        expectations,
    )?;
    let limits = current_fre_rebar_count_run_limits(benchmark.haystack.len(), &regex)?;
    let limits = &limits;
    run(
        benchmark,
        || {
            regex
                .count_value(&benchmark.haystack, limits)
                .map_err(Into::into)
        },
        Ok,
    )
}

fn model_count_many(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    let regex = aggregate_many_builder(benchmark).build_count()?;
    require_aggregate_many_plan(benchmark, "count", regex.build_report(), expectations)?;
    let limits = current_fre_rebar_aggregate_many_run_limits(
        benchmark.haystack.len(),
        regex.build_report(),
    )?;
    run(
        benchmark,
        || {
            regex
                .count_value(&benchmark.haystack, limits)
                .map_err(Into::into)
        },
        Ok,
    )
}

fn model_count_spans(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    if expectations.forced_compiler.is_some() {
        return model_hot_byte_operation(benchmark, expectations);
    }
    if benchmark.patterns.len() > 1 {
        return model_count_spans_many(benchmark, expectations);
    }
    let regex = aggregate_builder(benchmark).build_span_sum()?;
    require_aggregate_plan(
        "count-spans",
        regex.build_report(),
        benchmark.unicode,
        expectations,
    )?;
    let limits = current_fre_rebar_span_sum_run_limits(benchmark.haystack.len(), &regex)?;
    let limits = &limits;
    run(
        benchmark,
        || {
            regex
                .span_sum_value(&benchmark.haystack, limits)
                .map_err(Into::into)
        },
        Ok,
    )
}

fn model_hot_byte_operation(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    let compiler_id = expectations
        .forced_compiler
        .as_deref()
        .ok_or("hot-byte operation requires an explicit compiler ID")?;
    let lifecycle = current_fre_rebar_hot_byte_operation_lifecycle(
        compiler_id,
        &benchmark.model,
        &benchmark.patterns,
        benchmark.unicode,
        benchmark.case_insensitive,
        benchmark.haystack.len(),
    )?;
    require_optional("plan", expectations.plan.as_deref(), lifecycle.plan())?;
    run(
        benchmark,
        || lifecycle.execute(&benchmark.haystack).map_err(Into::into),
        Ok,
    )
}

fn model_count_spans_many(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
    let regex = aggregate_many_builder(benchmark).build_span_sum()?;
    require_aggregate_many_plan(benchmark, "count-spans", regex.build_report(), expectations)?;
    let limits = current_fre_rebar_aggregate_many_run_limits(
        benchmark.haystack.len(),
        regex.build_report(),
    )?;
    run(
        benchmark,
        || {
            regex
                .span_sum_value(&benchmark.haystack, limits)
                .map_err(Into::into)
        },
        Ok,
    )
}

fn model_performance_raw(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<PerformanceRawObservation, DynError> {
    if expectations.forced_compiler.is_some() {
        return match benchmark.model.as_str() {
            "count" | "count-spans" => model_hot_byte_operation_performance_raw_with_measurement(
                benchmark,
                expectations,
                |lifecycle, haystack| {
                    let start = Instant::now();
                    let actual = lifecycle.execute(haystack)?;
                    Ok((start.elapsed(), actual))
                },
            ),
            model => Err(format!(
                "forced hot-byte compiler rejects performance-raw model {model:?}"
            )
            .into()),
        };
    }
    match benchmark.model.as_str() {
        "compile" => {
            model_compile_performance_raw_with_measurement(benchmark, expectations, |lifecycle| {
                let start = Instant::now();
                let artifact = lifecycle.construct()?;
                Ok((start.elapsed(), artifact))
            })
        }
        "count" | "count-spans" => model_operation_performance_raw_with_measurement(
            benchmark,
            expectations,
            |lifecycle, haystack| {
                let start = Instant::now();
                let actual = lifecycle.execute(haystack)?;
                Ok((start.elapsed(), actual))
            },
        ),
        "grep" => model_grep_performance_raw_with_measurement(
            benchmark,
            expectations,
            |session, haystack, limits| {
                let start = Instant::now();
                let actual = execute_grep_session(session, haystack, limits)?;
                Ok((start.elapsed(), actual))
            },
        ),
        "count-captures" if benchmark.patterns.len() > 1 => {
            model_many_capture_performance_raw_with_measurement(
                benchmark,
                expectations,
                |regex, haystack, limits| {
                    let start = Instant::now();
                    let actual = regex
                        .count_captures_value(haystack, limits)
                        .map_err(|error| {
                            CompareError::new(format!(
                                "FRE aggregate-many capture lifecycle execution: {error}"
                            ))
                        })?;
                    Ok((start.elapsed(), actual))
                },
            )
        }
        "count-captures" | "grep-captures" => model_capture_performance_raw_with_measurement(
            benchmark,
            expectations,
            |lifecycle, haystack| {
                let start = Instant::now();
                let actual = lifecycle.execute(haystack)?;
                Ok((start.elapsed(), actual))
            },
        ),
        "regex-redux" => model_regex_redux_performance_raw_with_measurement(
            benchmark,
            expectations,
            |request, limits| {
                let start = Instant::now();
                let outcome = CurrentFreAdapter.execute(request, limits);
                Ok((start.elapsed(), outcome))
            },
        ),
        model => Err(format!("all-model raw candidate route rejects model {model:?}").into()),
    }
}

fn model_hot_byte_operation_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(&CurrentFreHotByteOperationLifecycle, &[u8]) -> Result<(Duration, u64), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let compiler_id = expectations
        .forced_compiler
        .as_deref()
        .ok_or("hot-byte performance lifecycle requires an explicit compiler ID")?;
    let expected_plan = identity.candidate_plan.clone();
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        let lifecycle = current_fre_rebar_hot_byte_operation_lifecycle(
            compiler_id,
            &benchmark.model,
            &benchmark.patterns,
            benchmark.unicode,
            benchmark.case_insensitive,
            benchmark.haystack.len(),
        )?;
        require_performance_plan(&expected_plan, lifecycle.plan())?;
        if steady {
            let primed = lifecycle.execute(&benchmark.haystack)?;
            if primed != identity.expected {
                return Err(CompareError::new(format!(
                    "hot-byte lifecycle prime returned {primed}, expected {}",
                    identity.expected
                )));
            }
        }
        measure(&lifecycle, &benchmark.haystack)
    })
    .map_err(Into::into)
}

fn model_compile_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        &CurrentFreAggregateCompileLifecycle,
    ) -> Result<(Duration, CurrentFreAggregateCompileArtifact), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let lifecycle = current_fre_rebar_aggregate_compile_lifecycle(
        &benchmark.patterns,
        benchmark.unicode,
        benchmark.case_insensitive,
        benchmark.haystack.len(),
    )?;
    let expected_plan = identity.candidate_plan.clone();
    let allocator_warm = identity.boundary == "allocator-warm-public-compile";
    produce_performance_candidate_observation(&identity, || {
        if allocator_warm {
            let warm = lifecycle.construct()?;
            require_performance_plan(&expected_plan, warm.plan(&lifecycle)?)?;
            drop(warm);
        }
        let (elapsed, artifact) = measure(&lifecycle)?;
        require_performance_plan(&expected_plan, artifact.plan(&lifecycle)?)?;
        let actual = artifact.verify(&lifecycle, &benchmark.haystack)?;
        Ok((elapsed, actual))
    })
    .map_err(Into::into)
}

fn model_operation_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        &CurrentFreAggregateOperationLifecycle,
        &[u8],
    ) -> Result<(Duration, u64), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let expected_plan = identity.candidate_plan.clone();
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            &benchmark.model,
            &benchmark.patterns,
            benchmark.unicode,
            benchmark.case_insensitive,
            benchmark.haystack.len(),
        )?;
        require_performance_plan(&expected_plan, lifecycle.plan())?;
        if steady {
            let primed = lifecycle.execute(&benchmark.haystack)?;
            if primed != identity.expected {
                return Err(CompareError::new(format!(
                    "aggregate lifecycle prime returned {primed}, expected {}",
                    identity.expected
                )));
            }
        }
        measure(&lifecycle, &benchmark.haystack)
    })
    .map_err(Into::into)
}

fn model_capture_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        &mut rebar_compare::CurrentFreCaptureLifecycle,
        &[u8],
    ) -> Result<(Duration, u64), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let expected_plan = identity.candidate_plan.clone();
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        let mut lifecycle = current_fre_rebar_capture_lifecycle(
            &benchmark.model,
            benchmark.pattern(),
            benchmark.unicode,
            benchmark.case_insensitive,
            benchmark.haystack.len(),
        )?;
        require_performance_plan(&expected_plan, lifecycle.plan())?;
        if steady {
            let primed = lifecycle.execute(&benchmark.haystack)?;
            if primed != identity.expected {
                return Err(CompareError::new(format!(
                    "capture lifecycle prime returned {primed}, expected {}",
                    identity.expected
                )));
            }
        }
        measure(&mut lifecycle, &benchmark.haystack)
    })
    .map_err(Into::into)
}

fn model_many_capture_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        &AggregateManyCaptureCountRegex,
        &[u8],
        AggregateManyCaptureRunLimits,
    ) -> Result<(Duration, u64), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let expected_plan = identity.candidate_plan.clone();
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        let regex = aggregate_many_builder(benchmark)
            .build_capture_count()
            .map_err(|error| {
                CompareError::new(format!(
                    "FRE aggregate-many capture lifecycle build: {error}"
                ))
            })?;
        current_fre_rebar_validate_aggregate_many_identity(
            &benchmark.patterns,
            regex.build_report(),
            benchmark.unicode,
            benchmark.case_insensitive,
            "count-captures",
        )?;
        require_performance_plan(
            &expected_plan,
            aggregate_many_plan("count-captures", regex.build_report()),
        )?;
        let selector = current_fre_rebar_aggregate_many_run_limits(
            benchmark.haystack.len(),
            regex.build_report(),
        )?;
        let limits = AggregateManyCaptureRunLimits {
            selector,
            ..AggregateManyCaptureRunLimits::default()
        };
        if steady {
            let primed = regex
                .count_captures_value(&benchmark.haystack, limits)
                .map_err(|error| {
                    CompareError::new(format!(
                        "FRE aggregate-many capture lifecycle prime: {error}"
                    ))
                })?;
            if primed != identity.expected {
                return Err(CompareError::new(format!(
                    "aggregate-many capture lifecycle prime returned {primed}, expected {}",
                    identity.expected
                )));
            }
        }
        measure(&regex, &benchmark.haystack, limits)
    })
    .map_err(Into::into)
}

fn model_regex_redux_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        CandidateRequest<'_>,
        &RunLimits,
    ) -> Result<(Duration, CandidateOutcome), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let expected_plan = identity.candidate_plan.clone();
    let request = CandidateRequest {
        job_id: &identity.job_id,
        model: &benchmark.model,
        patterns: &benchmark.patterns,
        haystack: &benchmark.haystack,
        unicode: benchmark.unicode,
        case_insensitive: benchmark.case_insensitive,
    };
    let limits = RunLimits::default();
    produce_performance_candidate_observation(&identity, || {
        let (elapsed, outcome) = measure(request, &limits)?;
        let (actual, plan) = match outcome {
            CandidateOutcome::ExecutedWithPlan { actual, plan } => (actual, plan),
            CandidateOutcome::Executed(actual) => {
                return Err(CompareError::new(format!(
                    "FRE regex-redux lifecycle returned unplanned reducer {actual}"
                )));
            }
            CandidateOutcome::Unsupported(reason) => {
                return Err(CompareError::new(format!(
                    "FRE regex-redux lifecycle was unsupported: {reason}"
                )));
            }
            CandidateOutcome::Unresolved(reason) => {
                return Err(CompareError::new(format!(
                    "FRE regex-redux lifecycle was unresolved: {reason}"
                )));
            }
            CandidateOutcome::Fault(reason) => {
                return Err(CompareError::new(format!(
                    "FRE regex-redux lifecycle faulted: {reason}"
                )));
            }
        };
        require_performance_plan(&expected_plan, &plan)?;
        Ok((elapsed, actual))
    })
    .map_err(Into::into)
}

fn model_grep_performance_raw_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce(
        &mut CurrentFreGrepSession<'_>,
        &[u8],
        SearchLimits,
    ) -> Result<(Duration, u64), CompareError>,
{
    let mut identity = performance_candidate_identity(benchmark, expectations)?;
    validate_performance_candidate_observation_request(&identity)?;
    let expected_plan = identity.candidate_plan.clone();
    let regex = current_fre_rebar_portable_builder(
        benchmark.pattern(),
        benchmark.unicode,
        benchmark.case_insensitive,
    )?
    .build()
    .map_err(|error| CompareError::new(format!("FRE grep lifecycle build: {error}")))?;
    require_performance_plan(&expected_plan, "portable-single-search")?;
    let selected_runtime = regex.runtime_implementation_id().to_string();
    if let Some(expected_runtime) = expectations.runtime.as_deref() {
        require_performance_runtime(expected_runtime, &selected_runtime)?;
    }
    require_grep_runtime_plan(&selected_runtime, regex.build_report().plan)?;
    identity.candidate_runtime = Some(selected_runtime.clone());
    let limits = current_fre_rebar_search_limits();
    let mut session = current_fre_rebar_grep_session(&regex, benchmark.haystack.len())?;
    require_performance_runtime(&selected_runtime, session.runtime_implementation_id())?;
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        if steady {
            let primed = execute_grep_session(&mut session, &benchmark.haystack, limits)?;
            if primed != identity.expected {
                return Err(CompareError::new(format!(
                    "grep lifecycle prime returned {primed}, expected {}",
                    identity.expected
                )));
            }
        }
        measure(&mut session, &benchmark.haystack, limits)
    })
    .map_err(Into::into)
}

fn execute_grep_session(
    session: &mut CurrentFreGrepSession<'_>,
    haystack: &[u8],
    _limits: SearchLimits,
) -> Result<u64, CompareError> {
    session.execute(haystack)
}

fn require_performance_plan(expected: &str, actual: &str) -> Result<(), CompareError> {
    if expected != actual {
        return Err(CompareError::new(format!(
            "FRE performance plan {actual:?} differs from expected {expected:?}"
        )));
    }
    Ok(())
}

fn require_performance_runtime(expected: &str, actual: &str) -> Result<(), CompareError> {
    if expected != actual {
        return Err(CompareError::new(format!(
            "FRE performance runtime {actual:?} differs from expected {expected:?}"
        )));
    }
    Ok(())
}

fn performance_candidate_identity(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<PerformanceCandidateObservationIdentity, DynError> {
    Ok(PerformanceCandidateObservationIdentity {
        contract_id: required(expectations.contract_id.clone(), "--expect-contract-id")?,
        canonical_commit: required(expectations.canonical_sha.clone(), "--expect-canonical-sha")?,
        canonical_tree: required(
            expectations.canonical_tree.clone(),
            "--expect-canonical-tree",
        )?,
        semantic_receipts_sha256: required(
            expectations.semantic_receipts.clone(),
            "--expect-semantic-receipts",
        )?,
        job_id: required(expectations.job_id.clone(), "--expect-job-id")?,
        benchmark: benchmark.name.clone(),
        model: benchmark.model.clone(),
        boundary: required(expectations.boundary.clone(), "--expect-boundary")?,
        comparator: required(expectations.comparator.clone(), "--expect-comparator")?,
        candidate_plan: required(expectations.plan.clone(), "--expect-plan")?,
        candidate_runtime: expectations.runtime.clone(),
        input: InputReceipt {
            pattern_sha256: benchmark
                .patterns
                .iter()
                .map(|pattern| sha256(pattern.as_bytes()))
                .collect(),
            haystack_sha256: sha256(&benchmark.haystack),
            haystack_bytes: benchmark.haystack.len(),
            unicode: benchmark.unicode,
            case_insensitive: benchmark.case_insensitive,
        },
        expected: required(expectations.count, "--expect-count")?,
        process_token_sha256: required(
            expectations.process_token.clone(),
            "--expect-process-token",
        )?,
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capture_lifecycle(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<rebar_compare::CurrentFreCaptureLifecycle, DynError> {
    let lifecycle = current_fre_rebar_capture_lifecycle(
        &benchmark.model,
        benchmark.pattern(),
        benchmark.unicode,
        benchmark.case_insensitive,
        benchmark.haystack.len(),
    )?;
    require_optional("plan", expectations.plan.as_deref(), lifecycle.plan())?;
    Ok(lifecycle)
}

fn model_captures(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<CaptureLifecycleRawObservation, DynError> {
    model_captures_with_measurement(benchmark, expectations, |operation, haystack| {
        let start = Instant::now();
        let actual = operation.execute(haystack)?;
        Ok((start.elapsed(), actual))
    })
}

fn model_captures_with_measurement<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    measure: F,
) -> Result<CaptureLifecycleRawObservation, DynError>
where
    F: FnOnce(
        &mut rebar_compare::CurrentFreCaptureLifecycle,
        &[u8],
    ) -> Result<(Duration, u64), CompareError>,
{
    let boundary = CaptureLifecycleBoundary::parse(
        expectations
            .boundary
            .as_deref()
            .ok_or("capture boundary is absent")?,
    )?;
    let identity = CaptureLifecycleObservationIdentity {
        contract_id: expectations
            .contract_id
            .clone()
            .ok_or("capture contract ID is absent")?,
        canonical_commit: expectations
            .canonical_sha
            .clone()
            .ok_or("capture canonical SHA is absent")?,
        canonical_tree: expectations
            .canonical_tree
            .clone()
            .ok_or("capture canonical tree is absent")?,
        semantic_receipts_sha256: expectations
            .semantic_receipts
            .clone()
            .ok_or("capture semantic receipt digest is absent")?,
        job_id: expectations
            .job_id
            .clone()
            .ok_or("capture job ID is absent")?,
        benchmark: benchmark.name.clone(),
        expected: expectations
            .count
            .ok_or("capture expected count is absent")?,
        process_token_sha256: expectations
            .process_token
            .clone()
            .ok_or("capture process token is absent")?,
    };
    let mut lifecycle = capture_lifecycle(benchmark, expectations)?;
    produce_capture_lifecycle_observation(
        &identity,
        &mut lifecycle,
        benchmark.pattern(),
        &benchmark.haystack,
        boundary,
        measure,
    )
    .map_err(Into::into)
}

fn model_grep(benchmark: &Benchmark, expectations: &Expectations) -> Result<Vec<Sample>, DynError> {
    let regex = current_fre_rebar_portable_builder(
        benchmark.pattern(),
        benchmark.unicode,
        benchmark.case_insensitive,
    )?
    .build()?;
    require_optional(
        "plan",
        expectations.plan.as_deref(),
        "portable-single-search",
    )?;
    require_optional(
        "runtime",
        expectations.runtime.as_deref(),
        regex.runtime_implementation_id(),
    )?;
    require_grep_runtime_plan(regex.runtime_implementation_id(), regex.build_report().plan)?;
    let haystack = benchmark.haystack.as_slice();
    let limits = current_fre_rebar_search_limits();
    let mut session = current_fre_rebar_grep_session(&regex, haystack.len())?;
    run(
        benchmark,
        || execute_grep_session(&mut session, haystack, limits).map_err(Into::into),
        Ok,
    )
}

fn require_grep_runtime_plan(runtime: &str, plan: PlanKind) -> Result<(), CompareError> {
    match (runtime, plan) {
        ("exact-literal", PlanKind::ExactLiteral)
        | ("k0", PlanKind::K0)
        | ("ascii-word-run-linear-v1" | "unicode-word-run-linear-v1", PlanKind::UnicodeWordRun) => {
            Ok(())
        }
        _ => Err(CompareError::new(format!(
            "grep runtime {runtime:?} and selected plan {plan:?} are not an authenticated pair"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebar_compare::performance_contract::PerformanceLifecyclePreparation;
    use std::{collections::BTreeSet, process::Command};

    fn field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
        write!(output, "{key}:{}:", value.len()).unwrap();
        output.extend_from_slice(value);
        output.push(b'\n');
    }

    fn valid_klv() -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", b"test/model/grep");
        field(&mut output, "model", b"grep");
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"false");
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", b"a:b");
        field(&mut output, "haystack", b"a:b\n\xFF");
        output
    }

    #[derive(Clone, Copy)]
    struct LineCaptureFixture {
        name: &'static str,
        pattern: &'static str,
        haystack: &'static [u8],
        expected: u64,
        plan: &'static str,
        unicode: bool,
    }

    fn line_capture_fixtures() -> [LineCaptureFixture; 5] {
        [
            LineCaptureFixture {
                name: "wild/ruff/space-around-operator",
                pattern: fre::SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
                haystack: b"x+\n\xFF++\r\nx + ",
                expected: 9,
                plan: rebar_compare::CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN,
                unicode: true,
            },
            LineCaptureFixture {
                name: "wild/ruff/shebang",
                pattern: fre::SHEBANG_CAPTURE_PATTERN,
                haystack: b"#!x\nx#!\n \t#!z",
                expected: 6,
                plan: fre::SHEBANG_OPERATION_ID,
                unicode: true,
            },
            LineCaptureFixture {
                name: "wild/ruff/string-quote-prefix",
                pattern: fre::STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
                haystack: b"''\nr\"x\"\nno\n",
                expected: 4,
                plan: fre::STRING_QUOTE_PREFIX_OPERATION_ID,
                unicode: true,
            },
            LineCaptureFixture {
                name: "wild/ruff/whitespace-around-keywords",
                pattern: fre::WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
                haystack: b"if else\nif_\n",
                expected: 6,
                plan: fre::WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
                unicode: true,
            },
            LineCaptureFixture {
                name: "opt/onepass/fn-predicate",
                pattern: fre::ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN,
                haystack: b"fn is_a(x) -> bool {\r\nno\n",
                expected: 4,
                plan: rebar_compare::CURRENT_FRE_CAPTURE_ASCII_SEPARATED_FIELDS_PLAN,
                unicode: false,
            },
        ]
    }

    fn line_capture_klv(fixture: LineCaptureFixture) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", fixture.name.as_bytes());
        field(&mut output, "model", b"grep-captures");
        field(&mut output, "case-insensitive", b"false");
        field(
            &mut output,
            "unicode",
            if fixture.unicode { b"true" } else { b"false" },
        );
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", fixture.pattern.as_bytes());
        field(&mut output, "haystack", fixture.haystack);
        output
    }

    fn aws_required_literal_klv() -> Vec<u8> {
        const PATTERN: &str = r#"(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-7]{16}))('|"))+"#;
        const HAYSTACK: &[u8] =
            b"miss\n\xFF no key\n\"AKIAIOSFODNN7EXAMPLE\" \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";

        let mut output = Vec::new();
        field(&mut output, "name", b"curated/09-aws-keys/full");
        field(&mut output, "model", b"grep-captures");
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"false");
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", PATTERN.as_bytes());
        field(&mut output, "haystack", HAYSTACK);
        output
    }

    fn multi_klv(model: &str) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", b"test/model/multi");
        field(&mut output, "model", model.as_bytes());
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"false");
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", b"cat");
        field(&mut output, "pattern", b"dog");
        field(&mut output, "haystack", b"cat dog cat");
        output
    }

    fn zero_pattern_klv(model: &str) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", b"test/model/zero-pattern");
        field(&mut output, "model", model.as_bytes());
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"false");
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "haystack", b"tHaN");
        output
    }

    fn capture_benchmark(model: &str, pattern: &str, haystack: &[u8]) -> Benchmark {
        Benchmark {
            name: format!("test/model/{model}"),
            model: model.to_string(),
            patterns: vec![pattern.to_string()],
            case_insensitive: false,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_nanos(1),
            max_warmup_time: Duration::ZERO,
        }
    }

    fn capture_expectations(boundary: &str, expected: u64) -> Expectations {
        Expectations {
            plan: Some("capture-linear-selector-participation-quotient-v1".to_string()),
            count: Some(expected),
            job_id: Some("fixture/capture@rust/regex".to_string()),
            contract_id: Some("fixture-contract-v1".to_string()),
            canonical_sha: Some("a".repeat(40)),
            canonical_tree: Some("b".repeat(40)),
            semantic_receipts: Some("c".repeat(64)),
            boundary: Some(boundary.to_string()),
            process_token: Some("d".repeat(64)),
            ..Expectations::default()
        }
    }

    fn performance_expectations(boundary: &str, plan: &str, expected: u64) -> Expectations {
        Expectations {
            plan: Some(plan.to_string()),
            count: Some(expected),
            job_id: Some("fixture/aggregate@rust/regex".to_string()),
            contract_id: Some("fixture-performance-contract-v1".to_string()),
            canonical_sha: Some("a".repeat(40)),
            canonical_tree: Some("b".repeat(40)),
            semantic_receipts: Some("c".repeat(64)),
            boundary: Some(boundary.to_string()),
            process_token: Some("d".repeat(64)),
            comparator: Some("rust-regex-1.12.4".to_string()),
            performance_raw: true,
            ..Expectations::default()
        }
    }

    fn hot_byte_benchmark(model: &str) -> Benchmark {
        Benchmark {
            name: format!("test/model/hot-byte/{model}"),
            model: model.to_string(),
            patterns: vec![r"[ab]{16}".to_string()],
            case_insensitive: false,
            unicode: false,
            haystack: vec![b'a'; 32],
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_nanos(1),
            max_warmup_time: Duration::ZERO,
        }
    }

    #[test]
    fn parses_arbitrary_haystack_and_delimiters_in_values() {
        let benchmark = Benchmark::parse(&valid_klv()).unwrap();
        assert_eq!(benchmark.name, "test/model/grep");
        assert_eq!(benchmark.pattern(), "a:b");
        assert_eq!(benchmark.haystack, b"a:b\n\xFF");
        assert_eq!(benchmark.max_iters, 1);
    }

    #[test]
    fn parses_model_specific_pattern_cardinality() {
        for model in ["compile", "count", "count-spans", "count-captures"] {
            let benchmark = Benchmark::parse(&multi_klv(model)).expect("aggregate multi KLV");
            assert_eq!(benchmark.patterns, ["cat", "dog"]);
        }
        for model in ["grep", "grep-captures"] {
            assert!(Benchmark::parse(&multi_klv(model)).is_err());
        }
        let regex_redux =
            Benchmark::parse(&zero_pattern_klv("regex-redux")).expect("regex-redux KLV");
        assert!(regex_redux.patterns.is_empty());
        assert!(Benchmark::parse(&zero_pattern_klv("count")).is_err());
        assert!(Benchmark::parse(&multi_klv("regex-redux")).is_err());
    }

    #[test]
    fn multi_pattern_lifecycles_bind_order_and_plan_without_timing() {
        let benchmark = Benchmark::parse(&multi_klv("count")).expect("multi count KLV");
        let expected = Expectations {
            plan: Some("aggregate-many-ordered-literal".to_string()),
            ..Expectations::default()
        };
        let count = aggregate_many_builder(&benchmark)
            .build_count()
            .expect("multi count artifact");
        require_aggregate_many_plan(&benchmark, "count", count.build_report(), &expected)
            .expect("multi count identity");
        let count_limits = current_fre_rebar_aggregate_many_run_limits(
            benchmark.haystack.len(),
            count.build_report(),
        )
        .expect("multi count limits");
        assert_eq!(
            count
                .count_value(&benchmark.haystack, count_limits)
                .expect("multi count execution"),
            3
        );

        let spans = aggregate_many_builder(&benchmark)
            .build_span_sum()
            .expect("multi span-sum artifact");
        require_aggregate_many_plan(&benchmark, "count-spans", spans.build_report(), &expected)
            .expect("multi span-sum identity");
        let span_limits = current_fre_rebar_aggregate_many_run_limits(
            benchmark.haystack.len(),
            spans.build_report(),
        )
        .expect("multi span-sum limits");
        assert_eq!(
            spans
                .span_sum_value(&benchmark.haystack, span_limits)
                .expect("multi span-sum execution"),
            9
        );

        let compile = aggregate_many_builder(&benchmark)
            .build_compile()
            .expect("multi compile artifact");
        let compile_expected = Expectations {
            plan: Some("compile-many-ordered-literal".to_string()),
            ..Expectations::default()
        };
        require_aggregate_many_plan(
            &benchmark,
            "compile",
            compile.build_report(),
            &compile_expected,
        )
        .expect("multi compile identity");
        let compile_limits = current_fre_rebar_aggregate_many_run_limits(
            benchmark.haystack.len(),
            compile.build_report(),
        )
        .expect("multi compile limits");
        assert_eq!(
            compile
                .verify_count(&benchmark.haystack, compile_limits)
                .expect("multi compile verification")
                .value(),
            3
        );

        let mut wrong_order = benchmark.patterns.clone();
        wrong_order.reverse();
        assert!(
            current_fre_rebar_validate_aggregate_many_identity(
                &wrong_order,
                count.build_report(),
                false,
                false,
                "count",
            )
            .is_err()
        );

        let continuation = Benchmark {
            patterns: vec!["a+".to_string(), "b+".to_string()],
            haystack: b"aa bbb".to_vec(),
            ..benchmark
        };
        let continuation_count = aggregate_many_builder(&continuation)
            .build_count()
            .expect("multi continuation artifact");
        let continuation_expected = Expectations {
            plan: Some("aggregate-many-continuation-program".to_string()),
            ..Expectations::default()
        };
        require_aggregate_many_plan(
            &continuation,
            "count",
            continuation_count.build_report(),
            &continuation_expected,
        )
        .expect("multi continuation identity");
        let continuation_limits = current_fre_rebar_aggregate_many_run_limits(
            continuation.haystack.len(),
            continuation_count.build_report(),
        )
        .expect("multi continuation limits");
        assert_eq!(
            continuation_count
                .count_value(&continuation.haystack, continuation_limits)
                .expect("multi continuation execution"),
            2
        );

        let continuation_compile = aggregate_many_builder(&continuation)
            .build_compile()
            .expect("multi continuation compile artifact");
        let continuation_compile_expected = Expectations {
            plan: Some("compile-many-continuation-program".to_string()),
            ..Expectations::default()
        };
        require_aggregate_many_plan(
            &continuation,
            "compile",
            continuation_compile.build_report(),
            &continuation_compile_expected,
        )
        .expect("multi continuation compile identity");
        let continuation_compile_limits = current_fre_rebar_aggregate_many_run_limits(
            continuation.haystack.len(),
            continuation_compile.build_report(),
        )
        .expect("multi continuation compile limits");
        assert_eq!(
            continuation_compile
                .verify_count(&continuation.haystack, continuation_compile_limits)
                .expect("multi continuation compile verification")
                .value(),
            2
        );

        let unicode = Benchmark {
            patterns: vec!["Δ".to_string(), "β".to_string()],
            unicode: true,
            haystack: "Δ β Δ".as_bytes().to_vec(),
            ..continuation
        };
        let unicode_count = aggregate_many_builder(&unicode)
            .build_count()
            .expect("Unicode ordered-many count artifact");
        require_aggregate_many_plan(&unicode, "count", unicode_count.build_report(), &expected)
            .expect("Unicode ordered-many count identity");
        let unicode_limits = current_fre_rebar_aggregate_many_run_limits(
            unicode.haystack.len(),
            unicode_count.build_report(),
        )
        .expect("Unicode ordered-many limits");
        assert_eq!(
            unicode_count
                .count_value(&unicode.haystack, unicode_limits)
                .expect("Unicode ordered-many execution"),
            3
        );
    }

    #[test]
    fn aggregate_raw_mode_emits_exact_compile_and_operation_lifecycles() {
        let compile_benchmark = Benchmark::parse(&multi_klv("compile")).expect("multi compile KLV");
        for (boundary, preparation) in [
            (
                "cold-public-compile",
                PerformanceLifecyclePreparation::ColdProcess,
            ),
            (
                "allocator-warm-public-compile",
                PerformanceLifecyclePreparation::AllocatorInitialized,
            ),
        ] {
            let expectations =
                performance_expectations(boundary, "compile-many-ordered-literal", 3);
            require_performance_raw_metadata("compile", &expectations)
                .expect("complete aggregate raw metadata");
            let measured = std::cell::Cell::new(0_u8);
            let observation = model_compile_performance_raw_with_measurement(
                &compile_benchmark,
                &expectations,
                |lifecycle| {
                    measured.set(measured.get() + 1);
                    Ok((Duration::from_nanos(31), lifecycle.construct()?))
                },
            )
            .expect("fixed compile raw arm");
            assert_eq!(measured.get(), 1);
            assert_eq!(observation.preparation, preparation);
            assert_eq!(observation.priming_operations, 0);
            assert_eq!(observation.elapsed_ns, 31);
            assert_eq!(observation.actual, 3);
            assert_eq!(
                observation.candidate_plan.as_deref(),
                Some("compile-many-ordered-literal")
            );
            assert_eq!(
                observation.input.pattern_sha256,
                vec![sha256(b"cat"), sha256(b"dog")]
            );
            assert_eq!(observation.input.haystack_sha256, sha256(b"cat dog cat"));
        }

        let count_benchmark = Benchmark::parse(&multi_klv("count")).expect("multi count KLV");
        let steady_expectations = performance_expectations(
            "steady-public-operation",
            "aggregate-many-ordered-literal",
            3,
        );
        let measured = std::cell::Cell::new(0_u8);
        let steady = model_operation_performance_raw_with_measurement(
            &count_benchmark,
            &steady_expectations,
            |lifecycle, haystack| {
                measured.set(measured.get() + 1);
                Ok((Duration::from_nanos(37), lifecycle.execute(haystack)?))
            },
        )
        .expect("fixed steady-operation raw arm");
        assert_eq!(measured.get(), 1);
        assert_eq!(
            steady.preparation,
            PerformanceLifecyclePreparation::PrimedArtifact
        );
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.elapsed_ns, 37);
        assert_eq!(steady.actual, 3);

        let first_expectations = performance_expectations(
            "first-public-operation",
            "aggregate-many-ordered-literal",
            3,
        );
        let first = model_operation_performance_raw_with_measurement(
            &count_benchmark,
            &first_expectations,
            |lifecycle, haystack| Ok((Duration::from_nanos(41), lifecycle.execute(haystack)?)),
        )
        .expect("fixed first-operation raw arm");
        assert_eq!(
            first.preparation,
            PerformanceLifecyclePreparation::BuiltArtifact
        );
        assert_eq!(first.priming_operations, 0);

        let mut wrong_plan = first_expectations;
        wrong_plan.plan = Some("aggregate-many-continuation-program".to_string());
        let ran = std::cell::Cell::new(false);
        assert!(
            model_operation_performance_raw_with_measurement(
                &count_benchmark,
                &wrong_plan,
                |lifecycle, haystack| {
                    ran.set(true);
                    Ok((Duration::from_nanos(1), lifecycle.execute(haystack)?))
                },
            )
            .is_err()
        );
        assert!(!ran.get(), "wrong operation plan reached measurement");
    }

    #[test]
    fn explicit_hot_byte_compiler_reaches_semantic_and_performance_raw_paths() {
        let compiler_id = rebar_compare::p128_forced_registry::P128ForcedCompiler::HotBytePrograms
            .id()
            .to_string();
        for (model, expected) in [("count", 2_u64), ("count-spans", 32_u64)] {
            let benchmark = hot_byte_benchmark(model);
            let semantic = Expectations {
                plan: Some(rebar_compare::CURRENT_FRE_HOT_BYTE_PROGRAM_PLAN.to_string()),
                count: Some(expected),
                forced_compiler: Some(compiler_id.clone()),
                ..Expectations::default()
            };
            let samples = if model == "count" {
                model_count(&benchmark, &semantic)
            } else {
                model_count_spans(&benchmark, &semantic)
            }
            .expect("forced semantic runner path");
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].count, expected);

            let mut raw = performance_expectations(
                "steady-public-operation",
                rebar_compare::CURRENT_FRE_HOT_BYTE_PROGRAM_PLAN,
                expected,
            );
            raw.forced_compiler = Some(compiler_id.clone());
            let measured = std::cell::Cell::new(0_u8);
            let observation = model_hot_byte_operation_performance_raw_with_measurement(
                &benchmark,
                &raw,
                |lifecycle, haystack| {
                    measured.set(measured.get() + 1);
                    Ok((Duration::from_nanos(47), lifecycle.execute(haystack)?))
                },
            )
            .expect("forced performance-raw runner path");
            assert_eq!(measured.get(), 1);
            assert_eq!(observation.priming_operations, 1);
            assert_eq!(observation.elapsed_ns, 47);
            assert_eq!(observation.actual, expected);
            assert_eq!(
                observation.candidate_plan.as_deref(),
                Some(rebar_compare::CURRENT_FRE_HOT_BYTE_PROGRAM_PLAN)
            );
        }
    }

    #[test]
    fn explicit_hot_byte_compiler_refuses_wrong_id_scope_and_missing_classifier_pre_source() {
        let compiler_id =
            rebar_compare::p128_forced_registry::P128ForcedCompiler::HotBytePrograms.id();
        let pattern = vec![r"[ab]{16}".to_string()];
        assert!(
            current_fre_rebar_hot_byte_operation_lifecycle(
                "fre.forced.unknown.v1",
                "count",
                &pattern,
                false,
                false,
                32,
            )
            .is_err()
        );
        assert!(
            current_fre_rebar_hot_byte_operation_lifecycle(
                compiler_id,
                "count",
                &[r"[ab]+".to_string()],
                false,
                false,
                32,
            )
            .is_err()
        );
        assert!(
            current_fre_rebar_hot_byte_operation_lifecycle(
                compiler_id,
                "count",
                &["abcdefghijklmnop".to_string()],
                false,
                false,
                32,
            )
            .is_err()
        );
        assert!(
            current_fre_rebar_hot_byte_operation_lifecycle(
                compiler_id,
                "count",
                &pattern,
                true,
                false,
                32,
            )
            .is_err()
        );
        assert!(
            current_fre_rebar_hot_byte_operation_lifecycle(
                compiler_id,
                "count",
                &[r"[ab]{16}".to_string(), r"[cd]{16}".to_string()],
                false,
                false,
                32,
            )
            .is_err()
        );
    }

    #[test]
    fn aggregate_raw_mode_requires_explicit_complete_metadata() {
        let complete =
            performance_expectations("first-public-operation", "aggregate-exact-literal", 1);
        require_performance_raw_metadata("count", &complete).expect("complete metadata");
        let mut grep = complete.clone();
        grep.plan = Some("portable-single-search".to_string());
        require_performance_raw_metadata("grep", &grep)
            .expect("trusted raw grep may derive its runtime");
        grep.runtime = Some("unicode-word-run-linear-v1".to_string());
        require_performance_raw_metadata("grep", &grep)
            .expect("raw grep may additionally check an expected runtime");
        let mut non_grep_runtime = complete.clone();
        non_grep_runtime.runtime = Some("k0".to_string());
        assert!(require_performance_raw_metadata("count", &non_grep_runtime).is_err());
        assert!(require_capture_metadata("count", &complete).is_err());
        let mut missing = complete;
        missing.comparator = None;
        assert!(require_performance_raw_metadata("count", &missing).is_err());
    }

    #[test]
    fn aggregate_many_capture_raw_mode_preserves_first_and_steady_lifecycles() {
        let benchmark = Benchmark {
            name: "test/model/multi-count-captures".to_string(),
            model: "count-captures".to_string(),
            patterns: vec!["(a+)".to_string(), "(a)".to_string()],
            case_insensitive: false,
            unicode: false,
            haystack: b"aa".to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_nanos(1),
            max_warmup_time: Duration::ZERO,
        };
        for (boundary, preparation, priming_operations, elapsed) in [
            (
                "first-public-operation",
                PerformanceLifecyclePreparation::BuiltArtifact,
                0,
                47,
            ),
            (
                "steady-public-operation",
                PerformanceLifecyclePreparation::PrimedArtifact,
                1,
                49,
            ),
        ] {
            let expectations =
                performance_expectations(boundary, "capture-many-continuation-program", 2);
            let measured = std::cell::Cell::new(0_u8);
            let observation = model_many_capture_performance_raw_with_measurement(
                &benchmark,
                &expectations,
                |regex, haystack, limits| {
                    measured.set(measured.get() + 1);
                    let actual = regex
                        .count_captures_value(haystack, limits)
                        .map_err(|error| CompareError::new(error.to_string()))?;
                    Ok((Duration::from_nanos(elapsed), actual))
                },
            )
            .expect("aggregate-many capture raw arm");
            assert_eq!(measured.get(), 1);
            assert_eq!(observation.preparation, preparation);
            assert_eq!(observation.priming_operations, priming_operations);
            assert_eq!(observation.elapsed_ns, elapsed);
            assert_eq!(observation.actual, 2);
            assert_eq!(
                observation.candidate_plan.as_deref(),
                Some("capture-many-continuation-program")
            );
            assert_eq!(
                observation.input.pattern_sha256,
                vec![sha256(b"(a+)"), sha256(b"(a)")]
            );
        }

        let wrong_plan =
            performance_expectations("first-public-operation", "capture-many-ordered-literal", 2);
        let measured = std::cell::Cell::new(false);
        assert!(
            model_many_capture_performance_raw_with_measurement(
                &benchmark,
                &wrong_plan,
                |regex, haystack, limits| {
                    measured.set(true);
                    let actual = regex
                        .count_captures_value(haystack, limits)
                        .map_err(|error| CompareError::new(error.to_string()))?;
                    Ok((Duration::from_nanos(1), actual))
                },
            )
            .is_err()
        );
        assert!(
            !measured.get(),
            "wrong capture-many plan reached measurement"
        );
    }

    #[test]
    fn regex_redux_raw_mode_times_one_complete_generic_composite() {
        let benchmark =
            Benchmark::parse(&zero_pattern_klv("regex-redux")).expect("regex-redux KLV");
        let expectations = performance_expectations(
            "complete-regex-redux",
            "regex-redux-sequential-composite-v1",
            1,
        );
        require_performance_raw_metadata("regex-redux", &expectations)
            .expect("regex-redux raw metadata");
        let measured = std::cell::Cell::new(0_u8);
        let observation = model_regex_redux_performance_raw_with_measurement(
            &benchmark,
            &expectations,
            |request, limits| {
                measured.set(measured.get() + 1);
                Ok((
                    Duration::from_nanos(53),
                    CurrentFreAdapter.execute(request, limits),
                ))
            },
        )
        .expect("regex-redux raw arm");
        assert_eq!(measured.get(), 1);
        assert_eq!(
            observation.preparation,
            PerformanceLifecyclePreparation::CompositeFresh
        );
        assert_eq!(observation.priming_operations, 0);
        assert_eq!(observation.measured_operations, 1);
        assert_eq!(observation.elapsed_ns, 53);
        assert_eq!(observation.actual, 1);
        assert!(observation.input.pattern_sha256.is_empty());
        assert_eq!(observation.input.haystack_sha256, sha256(b"tHaN"));

        let wrong_plan =
            performance_expectations("complete-regex-redux", "regex-redux-composite-alias", 1);
        let measured = std::cell::Cell::new(false);
        assert!(
            model_regex_redux_performance_raw_with_measurement(
                &benchmark,
                &wrong_plan,
                |request, limits| {
                    measured.set(true);
                    Ok((
                        Duration::from_nanos(1),
                        CurrentFreAdapter.execute(request, limits),
                    ))
                },
            )
            .is_err()
        );
        assert!(
            measured.get(),
            "regex-redux plan is authenticated from the measured composite"
        );
    }

    #[test]
    fn capture_raw_mode_emits_first_and_steady_all_model_arms() {
        let count_benchmark = capture_benchmark("count-captures", r"(a)(b)?", b"a ab");
        let first_expectations = performance_expectations(
            "first-public-operation",
            "capture-linear-selector-participation-quotient-v1",
            5,
        );
        require_performance_raw_metadata("count-captures", &first_expectations)
            .expect("capture raw metadata");
        let first = model_capture_performance_raw_with_measurement(
            &count_benchmark,
            &first_expectations,
            |lifecycle, haystack| Ok((Duration::from_nanos(43), lifecycle.execute(haystack)?)),
        )
        .expect("capture first-operation raw arm");
        assert_eq!(first.model, "count-captures");
        assert_eq!(
            first.preparation,
            PerformanceLifecyclePreparation::BuiltArtifact
        );
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.elapsed_ns, 43);
        assert_eq!(first.actual, 5);
        assert_eq!(
            first.input.pattern_sha256,
            vec![sha256(r"(a)(b)?".as_bytes())]
        );

        let grep_benchmark = capture_benchmark(
            "grep-captures",
            r"([a-z][a-z])([a-z])([\r\n])?",
            b"foo foo\r\nZ\r\nfoo\r\nfoo",
        );
        let steady_expectations = performance_expectations(
            "steady-public-operation",
            rebar_compare::CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN,
            12,
        );
        let steady = model_capture_performance_raw_with_measurement(
            &grep_benchmark,
            &steady_expectations,
            |lifecycle, haystack| Ok((Duration::from_nanos(47), lifecycle.execute(haystack)?)),
        )
        .expect("capture steady-operation raw arm");
        assert_eq!(steady.model, "grep-captures");
        assert_eq!(
            steady.preparation,
            PerformanceLifecyclePreparation::PrimedArtifact
        );
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.actual, 12);

        let mut wrong_plan = first_expectations;
        wrong_plan.plan = Some("aggregate-exact-literal".to_string());
        let ran = std::cell::Cell::new(false);
        assert!(
            model_capture_performance_raw_with_measurement(
                &count_benchmark,
                &wrong_plan,
                |lifecycle, haystack| {
                    ran.set(true);
                    Ok((Duration::from_nanos(1), lifecycle.execute(haystack)?))
                },
            )
            .is_err()
        );
        assert!(!ran.get(), "wrong capture plan reached measurement");
    }

    #[test]
    fn grep_raw_mode_binds_runtime_and_reuses_one_session_for_steady_operation() {
        let benchmark = Benchmark {
            name: "grep/long-words-unicode".to_string(),
            model: "grep".to_string(),
            patterns: vec![r"\b\w{25,}\b".to_string()],
            case_insensitive: false,
            unicode: true,
            haystack: b"abcdefghijklmnopqrstuvwxyz\nshort\n".to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_nanos(1),
            max_warmup_time: Duration::ZERO,
        };
        let mut first_expectations =
            performance_expectations("first-public-operation", "portable-single-search", 1);
        first_expectations.runtime = Some("unicode-word-run-linear-v1".to_string());
        let first = model_grep_performance_raw_with_measurement(
            &benchmark,
            &first_expectations,
            |session, haystack, limits| {
                Ok((
                    Duration::from_nanos(53),
                    execute_grep_session(session, haystack, limits)?,
                ))
            },
        )
        .expect("grep first-operation raw arm");
        assert_eq!(
            first.preparation,
            PerformanceLifecyclePreparation::BuiltArtifact
        );
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.actual, 1);
        assert_eq!(
            first.candidate_runtime.as_deref(),
            Some("unicode-word-run-linear-v1")
        );

        let mut steady_expectations = first_expectations.clone();
        steady_expectations.boundary = Some("steady-public-operation".to_string());
        let measured = std::cell::Cell::new(0_u8);
        let steady = model_grep_performance_raw_with_measurement(
            &benchmark,
            &steady_expectations,
            |session, haystack, limits| {
                measured.set(measured.get() + 1);
                Ok((
                    Duration::from_nanos(59),
                    execute_grep_session(session, haystack, limits)?,
                ))
            },
        )
        .expect("grep steady-operation raw arm");
        assert_eq!(measured.get(), 1);
        assert_eq!(
            steady.preparation,
            PerformanceLifecyclePreparation::PrimedArtifact
        );
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.actual, 1);

        let mut derived_runtime = first_expectations.clone();
        derived_runtime.runtime = None;
        let derived = model_grep_performance_raw_with_measurement(
            &benchmark,
            &derived_runtime,
            |session, haystack, limits| {
                Ok((
                    Duration::from_nanos(61),
                    execute_grep_session(session, haystack, limits)?,
                ))
            },
        )
        .expect("trusted grep construction derives its runtime");
        assert_eq!(
            derived.candidate_runtime.as_deref(),
            Some("unicode-word-run-linear-v1")
        );

        let mut malformed_metadata = derived_runtime;
        malformed_metadata.canonical_sha = Some("malformed".to_string());
        let mut malformed_pattern = benchmark.clone();
        malformed_pattern.patterns = vec!["(".to_string()];
        let ran = std::cell::Cell::new(false);
        let error = model_grep_performance_raw_with_measurement(
            &malformed_pattern,
            &malformed_metadata,
            |session, haystack, limits| {
                ran.set(true);
                Ok((
                    Duration::from_nanos(1),
                    execute_grep_session(session, haystack, limits)?,
                ))
            },
        )
        .expect_err("malformed identity fails before constructing an invalid pattern");
        assert!(
            error
                .to_string()
                .contains("performance tested-source commit")
        );
        assert!(!ran.get(), "malformed identity reached measurement");

        let mut wrong_runtime = first_expectations;
        wrong_runtime.runtime = Some("k0".to_string());
        let ran = std::cell::Cell::new(false);
        assert!(
            model_grep_performance_raw_with_measurement(
                &benchmark,
                &wrong_runtime,
                |session, haystack, limits| {
                    ran.set(true);
                    Ok((
                        Duration::from_nanos(1),
                        execute_grep_session(session, haystack, limits)?,
                    ))
                },
            )
            .is_err()
        );
        assert!(!ran.get(), "wrong grep runtime reached measurement");
    }

    #[test]
    fn grep_runner_selects_the_reviewed_route_for_each_runtime() {
        let limits = current_fre_rebar_search_limits();

        let literal = PortableRegex::new("ab").expect("exact literal");
        let literal_source = b"xxab\r\nmiss\nab";
        let mut literal_session = current_fre_rebar_grep_session(&literal, literal_source.len())
            .expect("whole-input literal session");
        assert!(!literal_session.has_reusable_k0_workspace());
        assert!(!literal_session.has_required_literal_prefilter());
        assert_eq!(
            execute_grep_session(&mut literal_session, literal_source, limits)
                .expect("whole-input literal count"),
            2
        );

        let k0 = PortableRegex::new("a.*b").expect("K0 regex");
        assert_eq!(k0.build_report().plan, PlanKind::K0);
        let k0_source = b"axb\r\nmiss\nab";
        let mut k0_session = current_fre_rebar_grep_session(&k0, k0_source.len())
            .expect("retained per-line K0 search session");
        assert!(k0_session.has_reusable_k0_workspace());
        assert!(!k0_session.has_required_literal_prefilter());
        assert_eq!(
            execute_grep_session(&mut k0_session, k0_source, limits).expect("per-line K0 count"),
            2
        );

        let finite = PortableRegex::new("a|ab").expect("finite language");
        assert!(matches!(
            finite.build_report().plan,
            PlanKind::PackedLiteralSet | PlanKind::LiteralSetDfa
        ));
        let finite_source = b"ab\nmiss\na";
        let mut fallback = current_fre_rebar_grep_session(&finite, finite_source.len())
            .expect("pre-source fallback session");
        assert!(!fallback.has_reusable_k0_workspace());
        assert!(!fallback.has_required_literal_prefilter());
        assert_eq!(
            execute_grep_session(&mut fallback, finite_source, limits).expect("fallback count"),
            2
        );
    }

    struct ExactGrepPointCase {
        benchmark: &'static str,
        first_point: &'static str,
        steady_point: &'static str,
        expected: u64,
        pattern_sha256: &'static str,
        haystack_sha256: &'static str,
    }

    const EXACT_GREP_POINT_CASES: &[ExactGrepPointCase] = &[
        ExactGrepPointCase {
            benchmark: "wild/ruff/unnecessary-coding-comment",
            first_point: "5025d66d740709c9cc31a829",
            steady_point: "0711993ed41d68476c302313",
            expected: 16,
            pattern_sha256: "84e0cc3593d33caadf1514b2a9812333cec9688400c213294aac9f13871dc131",
            haystack_sha256: "1aaf33e0e5d90f0b350c5e04c3817c6c12b9e1ee0cecf2433c8ee6a7bae176d2",
        },
        ExactGrepPointCase {
            benchmark: "opt/accelerate/whole-line",
            first_point: "4daf5f136f93b62bf0335b7a",
            steady_point: "39505cf71e565d453ecd1ed9",
            expected: 239_963,
            pattern_sha256: "5b22f7373a0d958dc8e60e039ebdfbb1244ca8c46453d8935ce31bcd4d9d7847",
            haystack_sha256: "7d43cc8dfd053b083b809bd7ce7d4a074f2fd24a6b7ec38908b3966f3324fa36",
        },
        ExactGrepPointCase {
            benchmark: "curated/09-aws-keys/quick",
            first_point: "910af6338454ed8b0f039d04",
            steady_point: "4479a56ac44660257a1de34d",
            expected: 0,
            pattern_sha256: "acff6bfb9eb90b7a486e98c7b0c20a48ca9e59b581207b4f4838f05fd8767d96",
            haystack_sha256: "140a09e1134154c3222186d21ace797cf3ffaa1ed317480064e3faffd4fe85b6",
        },
        ExactGrepPointCase {
            benchmark: "imported/lh3lh3-reb/uri",
            first_point: "eaf2d4518dbbe36e62732cc5",
            steady_point: "5a8094207291c4e128cff9ba",
            expected: 17_549,
            pattern_sha256: "b64702455770fd570e7233b5810d725e62d291d33d1746c1cbc6d10e7c302e95",
            haystack_sha256: "e58320cfc01a0f0f0ae0b263a1c84406bae21449f8128c8fda83c22b85ee536d",
        },
        ExactGrepPointCase {
            benchmark: "imported/lh3lh3-reb/email",
            first_point: "855a8558e5a8294439d1625a",
            steady_point: "e2abbbfb6e2789c2ce0afda8",
            expected: 15_057,
            pattern_sha256: "6cc0e2ec3a0f3b344987f88881ff21d0d5b2e9cff30b09d27a2bde5ce099b76d",
            haystack_sha256: "e58320cfc01a0f0f0ae0b263a1c84406bae21449f8128c8fda83c22b85ee536d",
        },
        ExactGrepPointCase {
            benchmark: "imported/lh3lh3-reb/uri-or-email",
            first_point: "87ddbaeadf448b8f9137fde7",
            steady_point: "cd47a59f57a84fc2b839c986",
            expected: 32_539,
            pattern_sha256: "05c2ad9d4d1d7a6eb3d2a15ffdaa482c43b8dcc5874025ab5549ae1e33e2f633",
            haystack_sha256: "e58320cfc01a0f0f0ae0b263a1c84406bae21449f8128c8fda83c22b85ee536d",
        },
        ExactGrepPointCase {
            benchmark: "imported/lh3lh3-reb/date",
            first_point: "cc7337b681e74e0a46b8407f",
            steady_point: "9796b5afbd23ba1f087a26a7",
            expected: 668,
            pattern_sha256: "3970711d148533bf7588cde3f7f0a3299cff950f2a86263d7db7057d42858a45",
            haystack_sha256: "e58320cfc01a0f0f0ae0b263a1c84406bae21449f8128c8fda83c22b85ee536d",
        },
    ];

    fn exact_rebar_klv(benchmark: &str) -> Vec<u8> {
        let rebar = env::var_os("FRE_REBAR_BIN")
            .expect("FRE_REBAR_BIN must name the pinned Rebar executable");
        let definitions = env::var_os("FRE_REBAR_BENCH_DIR")
            .expect("FRE_REBAR_BENCH_DIR must name the pinned benchmark directory");
        let output = Command::new(rebar)
            .args(["klv", "--max-iters", "1", "--max-warmup-iters", "0"])
            .args(["--max-time", "1ns", "--max-warmup-time", "0ns"])
            .arg("--dir")
            .arg(definitions)
            .arg(benchmark)
            .output()
            .expect("run pinned Rebar KLV generator");
        assert!(
            output.status.success(),
            "Rebar KLV generation failed for {benchmark}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    #[ignore = "requires FRE_REBAR_BIN and FRE_REBAR_BENCH_DIR for the pinned expanded checkout"]
    fn exact_14_grep_points_use_one_reusable_k0_search_session_without_a_clock() {
        let mut point_ids = BTreeSet::new();
        for case in EXACT_GREP_POINT_CASES {
            assert!(point_ids.insert(case.first_point));
            assert!(point_ids.insert(case.steady_point));
            let benchmark =
                Benchmark::parse(&exact_rebar_klv(case.benchmark)).expect("parse exact Rebar KLV");
            assert_eq!(benchmark.name, case.benchmark);
            assert_eq!(benchmark.model, "grep");
            assert_eq!(benchmark.patterns.len(), 1);
            assert_eq!(sha256(benchmark.pattern().as_bytes()), case.pattern_sha256);
            assert_eq!(sha256(&benchmark.haystack), case.haystack_sha256);

            let regex = current_fre_rebar_portable_builder(
                benchmark.pattern(),
                benchmark.unicode,
                benchmark.case_insensitive,
            )
            .expect("portable builder")
            .build()
            .expect("portable regex");
            assert_eq!(regex.build_report().plan, PlanKind::K0);
            assert_eq!(regex.runtime_implementation_id(), "k0");
            let limits = current_fre_rebar_search_limits();
            let mut session = current_fre_rebar_grep_session(&regex, benchmark.haystack.len())
                .expect("retained per-line K0 search session");
            assert!(session.has_reusable_k0_workspace());

            let repeated = benchmark
                .haystack
                .lines()
                .map(|line| {
                    regex
                        .is_match(line, limits)
                        .expect("current per-line reference")
                        .0
                })
                .filter(|matched| *matched)
                .count();
            assert_eq!(u64::try_from(repeated).expect("line count"), case.expected);

            let first = execute_grep_session(&mut session, &benchmark.haystack, limits)
                .expect("first public operation");
            assert_eq!(first, case.expected, "first point {}", case.first_point);
            let steady = execute_grep_session(&mut session, &benchmark.haystack, limits)
                .expect("steady public operation");
            assert_eq!(steady, case.expected, "steady point {}", case.steady_point);
        }
        assert_eq!(point_ids.len(), 14);
    }

    #[test]
    fn authenticates_each_timed_grep_runtime_against_its_plan() {
        assert!(require_grep_runtime_plan("exact-literal", PlanKind::ExactLiteral).is_ok());
        assert!(require_grep_runtime_plan("k0", PlanKind::K0).is_ok());
        assert!(
            require_grep_runtime_plan("ascii-word-run-linear-v1", PlanKind::UnicodeWordRun,)
                .is_ok()
        );
        assert!(
            require_grep_runtime_plan("unicode-word-run-linear-v1", PlanKind::UnicodeWordRun,)
                .is_ok()
        );
        assert!(require_grep_runtime_plan("exact-literal", PlanKind::K0).is_err());
        assert!(require_grep_runtime_plan("k0", PlanKind::UnicodeWordRun).is_err());
        assert!(require_grep_runtime_plan("ascii-word-run-linear-v1", PlanKind::K0).is_err());
        assert!(require_grep_runtime_plan("unicode-word-run-linear-v1", PlanKind::K0).is_err());
    }

    #[test]
    fn requires_runtime_identity_for_grep_without_freezing_it_to_k0() {
        assert!(require_runtime_expectation("grep", Some("exact-literal")).is_ok());
        assert!(require_runtime_expectation("grep", Some("k0")).is_ok());
        assert!(require_runtime_expectation("grep", Some("ascii-word-run-linear-v1")).is_ok());
        assert!(require_runtime_expectation("grep", Some("unicode-word-run-linear-v1")).is_ok());
        assert!(require_runtime_expectation("grep", None).is_err());
        assert!(require_runtime_expectation("count", Some("k0")).is_err());
        assert!(require_runtime_expectation("count", None).is_ok());
        assert!(require_runtime_expectation("count-captures", None).is_ok());
        assert!(require_runtime_expectation("grep-captures", None).is_ok());
        assert!(require_runtime_expectation("grep-captures", Some("k0")).is_err());
    }

    #[test]
    fn line_capture_formal_klv_binds_each_plan_to_first_steady_and_performance_capture_paths() {
        for fixture in line_capture_fixtures() {
            let benchmark =
                Benchmark::parse(&line_capture_klv(fixture)).expect("exact line-capture KLV");
            assert_eq!(benchmark.name, fixture.name);
            assert_eq!(benchmark.model, "grep-captures");
            assert_eq!(benchmark.unicode, fixture.unicode);
            assert!(!benchmark.case_insensitive);
            assert_eq!(benchmark.pattern(), fixture.pattern);

            let mut first_expectations =
                capture_expectations("first-public-operation", fixture.expected);
            first_expectations.plan = Some(fixture.plan.to_string());
            let first = model_captures_with_measurement(
                &benchmark,
                &first_expectations,
                |operation, haystack| Ok((Duration::from_nanos(29), operation.execute(haystack)?)),
            )
            .expect("formal Ruff first operation");
            assert_eq!(first.priming_operations, 0);
            assert_eq!(first.actual, fixture.expected);
            assert_eq!(first.candidate_plan, fixture.plan);

            let mut steady_expectations = first_expectations.clone();
            steady_expectations.boundary = Some("steady-public-operation".to_string());
            let steady = model_captures_with_measurement(
                &benchmark,
                &steady_expectations,
                |operation, haystack| Ok((Duration::from_nanos(31), operation.execute(haystack)?)),
            )
            .expect("formal Ruff steady operation");
            assert_eq!(steady.priming_operations, 1);
            assert_eq!(steady.actual, fixture.expected);

            let performance = model_capture_performance_raw_with_measurement(
                &benchmark,
                &performance_expectations(
                    "steady-public-operation",
                    fixture.plan,
                    fixture.expected,
                ),
                |operation, haystack| Ok((Duration::from_nanos(37), operation.execute(haystack)?)),
            )
            .expect("formal Ruff performance-raw operation");
            assert_eq!(performance.priming_operations, 1);
            assert_eq!(performance.actual, fixture.expected);
            assert_eq!(performance.candidate_plan.as_deref(), Some(fixture.plan));

            let mut wrong_plan = first_expectations;
            wrong_plan.plan = Some(format!("{}-alias", fixture.plan));
            let measured = std::cell::Cell::new(false);
            assert!(
                model_captures_with_measurement(&benchmark, &wrong_plan, |operation, haystack| {
                    measured.set(true);
                    Ok((Duration::from_nanos(1), operation.execute(haystack)?))
                })
                .is_err()
            );
            assert!(!measured.get(), "wrong Ruff plan reached measurement");
        }
    }

    #[test]
    fn aws_required_literal_formal_klv_binds_first_and_steady_lifecycle() {
        let benchmark =
            Benchmark::parse(&aws_required_literal_klv()).expect("exact AWS required-literal KLV");
        assert_eq!(benchmark.name, "curated/09-aws-keys/full");
        assert_eq!(benchmark.model, "grep-captures");
        assert!(!benchmark.unicode);
        assert!(!benchmark.case_insensitive);

        let mut first_expectations = capture_expectations("first-public-operation", 9);
        first_expectations.plan =
            Some(rebar_compare::CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN.to_string());
        let first = model_captures_with_measurement(
            &benchmark,
            &first_expectations,
            |operation, haystack| Ok((Duration::from_nanos(41), operation.execute(haystack)?)),
        )
        .expect("formal AWS first operation");
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.actual, 9);
        assert_eq!(
            first.candidate_plan,
            rebar_compare::CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN
        );

        let mut steady_expectations = first_expectations;
        steady_expectations.boundary = Some("steady-public-operation".to_string());
        let steady = model_captures_with_measurement(
            &benchmark,
            &steady_expectations,
            |operation, haystack| Ok((Duration::from_nanos(43), operation.execute(haystack)?)),
        )
        .expect("formal AWS steady operation");
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.actual, 9);
        assert_eq!(
            steady.candidate_plan,
            rebar_compare::CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN
        );
    }

    #[test]
    fn capture_models_bind_plan_and_preserve_first_and_steady_semantics() {
        let count_benchmark = capture_benchmark("count-captures", r"(a)(b)?", b"a ab");
        let first_expectations = capture_expectations("first-public-operation", 5);
        require_capture_metadata("count-captures", &first_expectations)
            .expect("complete capture metadata");
        let first = model_captures_with_measurement(
            &count_benchmark,
            &first_expectations,
            |operation, haystack| Ok((Duration::from_nanos(17), operation.execute(haystack)?)),
        )
        .expect("first raw capture observation");
        assert_eq!(
            first.boundary,
            CaptureLifecycleBoundary::FirstPublicOperation
        );
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.elapsed_ns, 17);
        assert_eq!(first.actual, 5);

        let steady_expectations = capture_expectations("steady-public-operation", 5);
        let steady = model_captures_with_measurement(
            &count_benchmark,
            &steady_expectations,
            |operation, haystack| Ok((Duration::from_nanos(19), operation.execute(haystack)?)),
        )
        .expect("steady raw capture observation");
        assert_eq!(
            steady.boundary,
            CaptureLifecycleBoundary::SteadyPublicOperation
        );
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.elapsed_ns, 19);

        let grep_benchmark = capture_benchmark(
            "grep-captures",
            r"([a-z][a-z])([a-z])([\r\n])?",
            b"foo foo\r\nZ\r\nfoo\r\nfoo",
        );
        let mut grep_expectations = capture_expectations("steady-public-operation", 12);
        grep_expectations.plan =
            Some(rebar_compare::CURRENT_FRE_CAPTURE_REQUIRED_LITERAL_PLAN.to_string());
        let grep = model_captures_with_measurement(
            &grep_benchmark,
            &grep_expectations,
            |operation, haystack| Ok((Duration::from_nanos(23), operation.execute(haystack)?)),
        )
        .expect("grep raw capture observation");
        assert_eq!(grep.model, "grep-captures");
        assert_eq!(grep.actual, 12);
        assert_eq!(grep.priming_operations, 1);

        let wrong_plan = Expectations {
            plan: Some("aggregate-exact-literal".to_string()),
            ..Expectations::default()
        };
        assert!(capture_lifecycle(&count_benchmark, &wrong_plan).is_err());
        assert!(require_capture_metadata("count-captures", &wrong_plan).is_err());
        assert!(require_capture_metadata("count", &first_expectations).is_err());
    }

    #[test]
    fn rejects_duplicate_scalar_and_truncation() {
        let mut duplicate = valid_klv();
        field(&mut duplicate, "unicode", b"true");
        assert!(Benchmark::parse(&duplicate).is_err());

        let mut truncated = valid_klv();
        truncated.pop();
        assert!(Benchmark::parse(&truncated).is_err());
    }

    #[test]
    fn rejects_nonformal_iteration_policy() {
        let mut nonformal = valid_klv();
        let needle = b"max-iters:1:1\n";
        let replacement = b"max-iters:1:2\n";
        let start = nonformal
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        nonformal.splice(start..start + needle.len(), replacement.iter().copied());
        assert!(Benchmark::parse(&nonformal).is_err());
    }

    #[test]
    fn authenticates_direct_unicode_scalar_plan_names() {
        let benchmark = Benchmark {
            name: "test/unicode-scalar".to_owned(),
            model: "count".to_owned(),
            patterns: vec![r"\pL".to_owned()],
            case_insensitive: false,
            unicode: true,
            haystack: "aΔ".as_bytes().to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        };
        let count = aggregate_builder(&benchmark)
            .build_count()
            .expect("Unicode scalar count plan");
        assert_eq!(
            aggregate_plan("count", count.build_report()),
            "aggregate-unicode-scalar-class"
        );
        current_fre_rebar_validate_aggregate_identity(count.build_report(), true, "count")
            .expect("Unicode scalar count identity");

        let span_sum = aggregate_builder(&benchmark)
            .build_span_sum()
            .expect("Unicode scalar span-sum plan");
        assert_eq!(
            aggregate_plan("count-spans", span_sum.build_report()),
            "aggregate-unicode-scalar-class"
        );
        current_fre_rebar_validate_aggregate_identity(span_sum.build_report(), true, "count-spans")
            .expect("Unicode scalar span-sum identity");

        let compile = aggregate_builder(&benchmark)
            .build_compile()
            .expect("Unicode scalar compile plan");
        assert_eq!(
            aggregate_plan("compile", compile.build_report()),
            "compile-aggregate-unicode-scalar-class"
        );
        current_fre_rebar_validate_aggregate_identity(compile.build_report(), true, "compile")
            .expect("Unicode scalar compile identity");
    }

    #[test]
    fn authenticates_packed_finite_plan_names() {
        let benchmark = Benchmark {
            name: "test/packed-finite".to_owned(),
            model: "count".to_owned(),
            patterns: vec![r"(?:cat|dog)".to_owned()],
            case_insensitive: false,
            unicode: false,
            haystack: b"cat x dog".to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        };

        let count = aggregate_builder(&benchmark)
            .build_count()
            .expect("packed finite count plan");
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::PackedFiniteLiteral
        );
        assert!(matches!(
            count.build_report().build,
            AggregateBuildAccounting::PackedFiniteLiteral(_)
        ));
        assert_eq!(
            aggregate_plan("count", count.build_report()),
            "aggregate-finite-literal-packed-v2"
        );
        current_fre_rebar_validate_aggregate_identity(count.build_report(), false, "count")
            .expect("packed finite count identity");

        let span_sum = aggregate_builder(&benchmark)
            .build_span_sum()
            .expect("packed finite span-sum plan");
        assert_eq!(
            aggregate_plan("count-spans", span_sum.build_report()),
            "aggregate-finite-literal-packed-v2"
        );
        current_fre_rebar_validate_aggregate_identity(
            span_sum.build_report(),
            false,
            "count-spans",
        )
        .expect("packed finite span-sum identity");

        let compile = aggregate_builder(&benchmark)
            .build_compile()
            .expect("packed finite compile plan");
        assert_eq!(
            aggregate_plan("compile", compile.build_report()),
            "compile-aggregate-finite-literal-packed-v2"
        );
        current_fre_rebar_validate_aggregate_identity(compile.build_report(), false, "compile")
            .expect("packed finite compile identity");
    }

    #[test]
    fn bounded_affix_count_spans_uses_the_formal_adapter_plan_name() {
        let benchmark = Benchmark {
            name: "test/bounded-affix-span-sum".to_owned(),
            model: "count-spans".to_owned(),
            patterns: vec![r"\s[A-Za-z]{0,12}ing\s".to_owned()],
            case_insensitive: false,
            unicode: false,
            haystack: b" ing  walking\t".to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        };
        let span_sum = aggregate_builder(&benchmark)
            .build_span_sum()
            .expect("bounded-affix span-sum plan");
        assert_eq!(
            aggregate_plan("count-spans", span_sum.build_report()),
            "aggregate-bounded-affix"
        );
        current_fre_rebar_validate_aggregate_identity(
            span_sum.build_report(),
            false,
            "count-spans",
        )
        .expect("bounded-affix span-sum identity");
        require_aggregate_plan(
            "count-spans",
            span_sum.build_report(),
            false,
            &Expectations {
                plan: Some("aggregate-bounded-affix".to_owned()),
                ..Expectations::default()
            },
        )
        .expect("formal expected plan");
    }
}
