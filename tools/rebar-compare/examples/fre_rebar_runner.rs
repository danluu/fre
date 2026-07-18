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

use bstr::ByteSlice;
use fre::{
    AggregateBuildAccounting, AggregateBuildReport, AggregateBuilder, AggregateManyBuildReport,
    AggregateManyBuilder, AggregateManyPlanKind, AggregatePlanKind, PlanKind,
    PortableSearchSession, SearchLimits, SearchSessionLimits,
};
use rebar_compare::{
    AUDITED_REBAR_REVISION, CompareError, CurrentFreAggregateCompileArtifact,
    CurrentFreAggregateCompileLifecycle, CurrentFreAggregateOperationLifecycle, InputReceipt,
    REPORT_SCHEMA, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_compile_lifecycle, current_fre_rebar_aggregate_many_builder,
    current_fre_rebar_aggregate_many_run_limits, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_aggregate_run_limits, current_fre_rebar_capture_lifecycle,
    current_fre_rebar_portable_builder, current_fre_rebar_search_limits,
    current_fre_rebar_validate_aggregate_identity,
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
                println!(
                    "{RUNNER_SCHEMA} protocol=stratified-v1 adapter=fre-current-aggregate-capture-v20-noqa-v1-portable-word-run-v2-unicode-scalar-run-v4-capture-scalar-alternation-v1-line-space-operator-v2-line-configured-ruff-three-v1-finite-dfa-v2-sparse-v1-fixed-class-sandwich-v1-grapheme-scalar-dfa-v1-bounded-class-sequence-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-structural-quota-v8 report={REPORT_SCHEMA} aggregate-explain=19 aggregate-many-explain=3 aggregate-many=compile+count+count-spans+count-captures performance-raw=all-supported facade-explain=1 rebar={AUDITED_REBAR_REVISION} package={} canonical-sha={canonical_sha} canonical-tree={canonical_tree} engine-sha={engine_sha} engine-tree={engine_tree} runner-sha={runner_sha} runner-tree={runner_tree} lock={lock} profile={profile} toolchain={toolchain} target={target}",
                    env!("CARGO_PKG_VERSION"),
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
            "--performance-raw" => {
                expectations.performance_raw = true;
            }
            "--help" | "-h" => {
                return Err(
                    "usage: fre_rebar_runner --expect-benchmark NAME --expect-model MODEL --expect-plan PLAN [--expect-runtime ID] --expect-count N [capture: --expect-job-id ID --expect-contract-id ID --expect-canonical-sha OID --expect-canonical-tree OID --expect-semantic-receipts SHA256 --expect-boundary first-public-operation|steady-public-operation --expect-process-token SHA256] [aggregate all-model: --performance-raw plus the identity fields and --expect-comparator ID] | --version"
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
    if expectations.performance_raw {
        require_performance_raw_metadata(&benchmark.model, &expectations)?;
        let observation = model_performance_raw(&benchmark, &expectations)?;
        let bytes = performance_raw_observation_bytes(&observation)?;
        io::stdout().lock().write_all(&bytes)?;
        return Ok(());
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
    if let Some(expected) = expectations.count
        && let Some(sample) = samples.iter().find(|sample| sample.count != expected)
    {
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
        "compile" | "count" | "count-spans" | "grep" | "count-captures" | "grep-captures"
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
        if benchmark.patterns.is_empty() {
            return Err("FRE KLV runner requires at least one pattern".into());
        }
        if benchmark.patterns.len() != 1
            && !matches!(
                benchmark.model.as_str(),
                "compile" | "count" | "count-spans"
            )
        {
            return Err(format!(
                "FRE KLV model {:?} requires one pattern, got {}",
                benchmark.model,
                benchmark.patterns.len()
            )
            .into());
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

fn aggregate_plan(model: &str, report: &AggregateBuildReport) -> &'static str {
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

fn aggregate_many_plan(model: &str, report: &AggregateManyBuildReport) -> &'static str {
    match (model, report.plan) {
        ("compile", AggregateManyPlanKind::OrderedLiteral) => "compile-many-ordered-literal",
        ("compile", AggregateManyPlanKind::ContinuationProgram) => {
            "compile-many-continuation-program"
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
        let limits =
            current_fre_rebar_aggregate_run_limits(haystack.len(), artifact.build_report())?;
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
        let limits =
            current_fre_rebar_aggregate_run_limits(haystack.len(), artifact.build_report())?;
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
    let limits =
        current_fre_rebar_aggregate_run_limits(benchmark.haystack.len(), regex.build_report())?;
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
    let limits =
        current_fre_rebar_aggregate_run_limits(benchmark.haystack.len(), regex.build_report())?;
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
        "count-captures" | "grep-captures" => model_capture_performance_raw_with_measurement(
            benchmark,
            expectations,
            |lifecycle, haystack| {
                let start = Instant::now();
                let actual = lifecycle.execute(haystack)?;
                Ok((start.elapsed(), actual))
            },
        ),
        model => Err(format!("all-model raw candidate route rejects model {model:?}").into()),
    }
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
        &rebar_compare::CurrentFreCaptureLifecycle,
        &[u8],
    ) -> Result<(Duration, u64), CompareError>,
{
    let identity = performance_candidate_identity(benchmark, expectations)?;
    let expected_plan = identity.candidate_plan.clone();
    let steady = identity.boundary == "steady-public-operation";
    produce_performance_candidate_observation(&identity, || {
        let lifecycle = current_fre_rebar_capture_lifecycle(
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
        measure(&lifecycle, &benchmark.haystack)
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
        &mut PortableSearchSession<'_>,
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
    let mut session = regex
        .search_session(SearchSessionLimits {
            max_setup_work: limits.max_work,
            max_scratch_bytes: limits.max_scratch_bytes,
        })
        .map_err(|error| CompareError::new(format!("FRE grep session build: {error}")))?;
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
    session: &mut PortableSearchSession<'_>,
    haystack: &[u8],
    limits: SearchLimits,
) -> Result<u64, CompareError> {
    let mut count = 0_u64;
    for line in haystack.lines() {
        if session
            .is_match(line, limits)
            .map_err(|error| CompareError::new(format!("FRE grep lifecycle search: {error}")))?
            .0
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| CompareError::new("FRE grep lifecycle count overflow"))?;
        }
    }
    Ok(count)
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
        &rebar_compare::CurrentFreCaptureLifecycle,
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
    let lifecycle = capture_lifecycle(benchmark, expectations)?;
    produce_capture_lifecycle_observation(
        &identity,
        &lifecycle,
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
    let mut session = regex.search_session(SearchSessionLimits {
        max_setup_work: limits.max_work,
        max_scratch_bytes: limits.max_scratch_bytes,
    })?;
    run(
        benchmark,
        || {
            let mut count = 0_u64;
            for line in haystack.lines() {
                if session.is_match(line, limits)?.0 {
                    count = count.checked_add(1).ok_or("grep count overflow")?;
                }
            }
            Ok(count)
        },
        Ok,
    )
}

fn require_grep_runtime_plan(runtime: &str, plan: PlanKind) -> Result<(), CompareError> {
    match (runtime, plan) {
        ("k0", PlanKind::K0)
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
    struct RuffCaptureFixture {
        name: &'static str,
        pattern: &'static str,
        haystack: &'static [u8],
        expected: u64,
        plan: &'static str,
    }

    fn ruff_capture_fixtures() -> [RuffCaptureFixture; 4] {
        [
            RuffCaptureFixture {
                name: "wild/ruff/space-around-operator",
                pattern: fre::SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
                haystack: b"x+\n\xFF++\r\nx + ",
                expected: 9,
                plan: rebar_compare::CURRENT_FRE_CAPTURE_SPACE_OPERATOR_PLAN,
            },
            RuffCaptureFixture {
                name: "wild/ruff/shebang",
                pattern: fre::SHEBANG_CAPTURE_PATTERN,
                haystack: b"#!x\nx#!\n \t#!z",
                expected: 6,
                plan: fre::SHEBANG_OPERATION_ID,
            },
            RuffCaptureFixture {
                name: "wild/ruff/string-quote-prefix",
                pattern: fre::STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
                haystack: b"''\nr\"x\"\nno\n",
                expected: 4,
                plan: fre::STRING_QUOTE_PREFIX_OPERATION_ID,
            },
            RuffCaptureFixture {
                name: "wild/ruff/whitespace-around-keywords",
                pattern: fre::WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN,
                haystack: b"if else\nif_\n",
                expected: 6,
                plan: fre::WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
            },
        ]
    }

    fn ruff_capture_klv(fixture: RuffCaptureFixture) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, "name", fixture.name.as_bytes());
        field(&mut output, "model", b"grep-captures");
        field(&mut output, "case-insensitive", b"false");
        field(&mut output, "unicode", b"true");
        field(&mut output, "max-iters", b"1");
        field(&mut output, "max-warmup-iters", b"0");
        field(&mut output, "max-time", b"1000");
        field(&mut output, "max-warmup-time", b"100");
        field(&mut output, "pattern", fixture.pattern.as_bytes());
        field(&mut output, "haystack", fixture.haystack);
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
            plan: Some("capture-linear-selector-persistent-history".to_string()),
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

    #[test]
    fn parses_arbitrary_haystack_and_delimiters_in_values() {
        let benchmark = Benchmark::parse(&valid_klv()).unwrap();
        assert_eq!(benchmark.name, "test/model/grep");
        assert_eq!(benchmark.pattern(), "a:b");
        assert_eq!(benchmark.haystack, b"a:b\n\xFF");
        assert_eq!(benchmark.max_iters, 1);
    }

    #[test]
    fn parses_multiple_patterns_only_for_aggregate_models() {
        for model in ["compile", "count", "count-spans"] {
            let benchmark = Benchmark::parse(&multi_klv(model)).expect("aggregate multi KLV");
            assert_eq!(benchmark.patterns, ["cat", "dog"]);
        }
        for model in ["grep", "count-captures", "grep-captures"] {
            assert!(Benchmark::parse(&multi_klv(model)).is_err());
        }
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
    fn capture_raw_mode_emits_first_and_steady_all_model_arms() {
        let count_benchmark = capture_benchmark("count-captures", r"(a)(b)?", b"a ab");
        let first_expectations = performance_expectations(
            "first-public-operation",
            "capture-linear-selector-persistent-history",
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
            "capture-linear-selector-persistent-history",
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
    fn authenticates_each_timed_grep_runtime_against_its_plan() {
        assert!(require_grep_runtime_plan("k0", PlanKind::K0).is_ok());
        assert!(
            require_grep_runtime_plan("ascii-word-run-linear-v1", PlanKind::UnicodeWordRun,)
                .is_ok()
        );
        assert!(
            require_grep_runtime_plan("unicode-word-run-linear-v1", PlanKind::UnicodeWordRun,)
                .is_ok()
        );
        assert!(require_grep_runtime_plan("k0", PlanKind::UnicodeWordRun).is_err());
        assert!(require_grep_runtime_plan("ascii-word-run-linear-v1", PlanKind::K0).is_err());
        assert!(require_grep_runtime_plan("unicode-word-run-linear-v1", PlanKind::K0).is_err());
    }

    #[test]
    fn requires_runtime_identity_for_grep_without_freezing_it_to_k0() {
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
    fn ruff_formal_klv_binds_each_plan_to_first_steady_and_performance_capture_paths() {
        for fixture in ruff_capture_fixtures() {
            let benchmark = Benchmark::parse(&ruff_capture_klv(fixture)).expect("exact Ruff KLV");
            assert_eq!(benchmark.name, fixture.name);
            assert_eq!(benchmark.model, "grep-captures");
            assert!(benchmark.unicode);
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
        let grep_expectations = capture_expectations("steady-public-operation", 12);
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
}
