//! KLV runner for timing the public FRE facade with Rebar's operation models.
//!
//! This deliberately implements models, not benchmark names. Construction is
//! outside the timer for `grep`; `compile` times a fresh complete artifact and
//! performs semantic verification only after the sample duration is captured.

use std::{
    env,
    error::Error,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use fre::{
    AggregateBuildReport, AggregateBuilder, AggregatePlanKind, PlanKind, SearchSessionLimits,
};
use rebar_compare::{
    AUDITED_REBAR_REVISION, REPORT_SCHEMA, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_run_limits, current_fre_rebar_portable_builder,
    current_fre_rebar_search_limits, current_fre_rebar_validate_aggregate_identity,
};

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
                    "{RUNNER_SCHEMA} protocol=stratified-v1 adapter=fre-current-aggregate-capture-v13-portable-word-run-v2-unicode-scalar-run-v2-finite-dfa-v1-aggregate-word-run-v1 report={REPORT_SCHEMA} aggregate-explain=11 facade-explain=1 rebar={AUDITED_REBAR_REVISION} package={} canonical-sha={canonical_sha} canonical-tree={canonical_tree} engine-sha={engine_sha} engine-tree={engine_tree} runner-sha={runner_sha} runner-tree={runner_tree} lock={lock} profile={profile} toolchain={toolchain} target={target}",
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
            "--help" | "-h" => {
                return Err(
                    "usage: fre_rebar_runner --expect-benchmark NAME --expect-model MODEL --expect-plan PLAN [--expect-runtime k0] --expect-count N | --version"
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
    require_runtime_expectation(&benchmark.model, expectations.runtime.as_deref())?;
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
        if benchmark.patterns.len() != 1 {
            return Err(format!(
                "FRE KLV runner requires one pattern, got {}",
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

fn aggregate_plan(model: &str, report: &AggregateBuildReport) -> &'static str {
    match (model, report.plan) {
        ("compile", AggregatePlanKind::ExactLiteral) => "compile-aggregate-exact-literal",
        ("compile", AggregatePlanKind::UnicodeScalarClass) => {
            "compile-aggregate-unicode-scalar-class"
        }
        ("compile", AggregatePlanKind::FiniteLiteralDfa) => "compile-aggregate-finite-literal-dfa",
        ("compile", AggregatePlanKind::WordRun) => "compile-aggregate-word-run",
        ("compile", AggregatePlanKind::ContinuationProgram) => {
            "compile-aggregate-continuation-program"
        }
        (_, AggregatePlanKind::ExactLiteral) => "aggregate-exact-literal",
        (_, AggregatePlanKind::UnicodeScalarClass) => "aggregate-unicode-scalar-class",
        (_, AggregatePlanKind::FiniteLiteralDfa) => "aggregate-finite-literal-dfa",
        (_, AggregatePlanKind::WordRun) => "aggregate-word-run",
        (_, AggregatePlanKind::ContinuationProgram) => "aggregate-continuation-program",
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

fn model_compile(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
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

fn model_count(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
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

fn model_count_spans(
    benchmark: &Benchmark,
    expectations: &Expectations,
) -> Result<Vec<Sample>, DynError> {
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

fn require_grep_runtime_plan(runtime: &str, plan: PlanKind) -> Result<(), DynError> {
    match (runtime, plan) {
        ("k0", PlanKind::K0)
        | ("ascii-word-run-linear-v1" | "unicode-word-run-linear-v1", PlanKind::UnicodeWordRun) => {
            Ok(())
        }
        _ => Err(format!(
            "grep runtime {runtime:?} and selected plan {plan:?} are not an authenticated pair"
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parses_arbitrary_haystack_and_delimiters_in_values() {
        let benchmark = Benchmark::parse(&valid_klv()).unwrap();
        assert_eq!(benchmark.name, "test/model/grep");
        assert_eq!(benchmark.pattern(), "a:b");
        assert_eq!(benchmark.haystack, b"a:b\n\xFF");
        assert_eq!(benchmark.max_iters, 1);
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
