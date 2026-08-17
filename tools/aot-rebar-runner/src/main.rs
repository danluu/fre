//! Statically linked, job-specialized adapter for public Rebar operation models.

#![warn(unsafe_code)]

use std::{
    env,
    error::Error,
    hint::black_box,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use fre_aot_rebar_runner::shared;
use fre_aot_regex::CompiledRegex;
use fre_aot_regex_runtime::{
    DEFAULT_GREP_COUNT_WORKSPACE_BYTES, DEFAULT_START_FILTER_SETUP_WORK,
    FreAotRegexExclusiveHandleV1, FreAotRegexPrepareConfigV2, PREPARE_CONFIG_V2_VERSION,
    STATUS_SUCCESS, fre_aot_regex_runtime_destroy_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v2,
};
use regex_automata::meta::Regex;

#[allow(
    unsafe_code,
    unreachable_pub,
    reason = "generated declarations are the exact statically linked AOT C ABI boundary"
)]
mod linked {
    include!(concat!(env!("OUT_DIR"), "/linked_artifact.rs"));
}

type DynError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Arguments {
    quiet: bool,
    version: bool,
    provenance: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Sample {
    duration: Duration,
    value: u64,
}

#[derive(Debug)]
struct ExclusiveSession {
    handle: FreAotRegexExclusiveHandleV1,
}

impl ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "preparation is the audited exclusive-handle C ABI boundary"
    )]
    fn prepare(model: shared::Model) -> Result<Self, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        let operation_flags = model.prepare_operation_flags();
        if operation_flags != linked::PREPARE_OPERATION_FLAGS {
            return Err("runtime model preparation differs from linked artifact".to_owned());
        }
        let config = FreAotRegexPrepareConfigV2::new(operation_flags);
        // SAFETY: the linked immutable program has the exact generated extent;
        // `config` is initialized and readable, while `handle` is aligned,
        // writable, and disjoint from both readable inputs.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v2(
                linked::program_ptr(),
                linked::PROGRAM_LEN,
                &config,
                &raw mut handle,
            )
        };
        if status != STATUS_SUCCESS || handle.is_invalid() {
            return Err(format!(
                "prepare exclusive AOT handle returned status {status}"
            ));
        }
        Ok(Self { handle })
    }

    #[allow(
        unsafe_code,
        reason = "the exact generated reducer call is the audited timed C ABI boundary"
    )]
    fn reduce(&mut self, haystack: &[u8]) -> Result<u64, String> {
        let mut value = u64::MAX;
        // SAFETY: this object uniquely owns the live exclusive handle; the
        // haystack and aligned scalar output remain disjoint and live for the
        // complete call.
        let status = unsafe {
            linked::reduce(
                self.handle,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut value,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "identity-suffixed reducer {:?} returned status {status}",
                linked::REDUCER_SYMBOL
            ));
        }
        Ok(value)
    }

    #[allow(
        unsafe_code,
        reason = "explicit destruction is the audited exclusive-handle C ABI boundary"
    )]
    fn destroy(mut self) -> Result<(), String> {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: `handle` is the one live exclusively owned value and no call
        // overlaps this explicit terminal destruction.
        let status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "destroy exclusive AOT handle returned status {status}"
            ));
        }
        Ok(())
    }
}

impl Drop for ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "Drop is the terminal fallback for the uniquely owned exclusive handle"
    )]
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: Drop owns the only live handle and is the final fallback
        // when explicit checked destruction did not already consume it.
        let _ = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
    }
}

fn main() -> Result<(), DynError> {
    let arguments = parse_arguments()?;
    if arguments.version {
        if linked::CONFIGURED {
            println!("{}+{}", env!("CARGO_PKG_VERSION"), linked::ADAPTER);
        } else {
            println!("{}+general-aot-unconfigured", env!("CARGO_PKG_VERSION"));
        }
        return Ok(());
    }
    if arguments.provenance {
        print_provenance();
        return Ok(());
    }
    if !linked::CONFIGURED {
        return Err(format!(
            "runner is unconfigured; rebuild with FRE_AOT_REBAR_KLV=/absolute/public/job.klv"
        )
        .into());
    }

    let mut input = Vec::new();
    io::stdin()
        .take(shared::MAX_KLV_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > shared::MAX_KLV_BYTES) {
        return Err(format!("KLV input exceeds {} bytes", shared::MAX_KLV_BYTES).into());
    }
    let benchmark = shared::Benchmark::parse(&input)?;
    authenticate_benchmark(&benchmark)?;
    let target =
        shared::target_from_parts(linked::TARGET_ARCH, linked::TARGET_OS, linked::FEATURE_BITS)?;
    let mut session = ExclusiveSession::prepare(benchmark.model)?;
    let samples = if benchmark.model == shared::Model::Compile {
        run_compile(&benchmark, target, &mut session)?
    } else {
        run_operation(&benchmark, &mut session)?
    };
    session.destroy()?;
    let expected = rust_oracle(&benchmark)?;
    for sample in &samples {
        require_expected(sample.value, expected)?;
    }

    if !arguments.quiet {
        let mut stdout = io::stdout().lock();
        for sample in samples {
            writeln!(stdout, "{},{}", sample.duration.as_nanos(), sample.value)?;
        }
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, DynError> {
    let mut parsed = Arguments::default();
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--quiet" | "-q" => parsed.quiet = true,
            "--version" => parsed.version = true,
            "--provenance" => parsed.provenance = true,
            "--help" | "-h" => {
                return Err(
                    "usage: fre-aot-rebar-runner [--quiet | --version | --provenance]".into(),
                );
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }
    if parsed.version && parsed.provenance {
        return Err("--version and --provenance are mutually exclusive".into());
    }
    Ok(parsed)
}

fn print_provenance() {
    println!(
        "schema=fre.aot.rebar-runner.v1 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} prepare_config_version={} prepare_operation_flags={:016x} prepare_scope=runtime-handle-state object_descriptor_setup=lazy-if-native-fused max_start_filter_setup_work={} max_grep_count_workspace_bytes={} program_sha256={} object_sha256={} program_symbol={} reducer_symbol={} required_runtime_symbols={} boundary=runtime-klv-warmup-schedule required_comparators=rust-regex-1.12.4,fre-current-runtime",
        linked::CONFIGURED,
        linked::ADAPTER,
        linked::EXPECTED_MODEL,
        linked::EXPECTED_NAME,
        linked::SOURCE_COMMIT,
        linked::SOURCE_TREE,
        linked::TARGET_ARCH,
        linked::TARGET_OS,
        linked::FEATURE_BITS,
        linked::COMPILER_VERSION,
        linked::OPTIMIZER_VERSION,
        linked::ENGINE,
        linked::AGGREGATE_STRATEGY,
        PREPARE_CONFIG_V2_VERSION,
        linked::PREPARE_OPERATION_FLAGS,
        DEFAULT_START_FILTER_SETUP_WORK,
        DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
        hex(&linked::PROGRAM_SHA256),
        hex(&linked::OBJECT_SHA256),
        linked::PROGRAM_SYMBOL,
        linked::REDUCER_SYMBOL,
        linked::REQUIRED_RUNTIME_SYMBOLS,
    );
}

fn authenticate_benchmark(benchmark: &shared::Benchmark) -> Result<(), String> {
    let expected_model = shared::Model::parse(linked::EXPECTED_MODEL)?;
    let expected = shared::Benchmark {
        name: linked::EXPECTED_NAME.to_owned(),
        model: expected_model,
        patterns: vec![linked::EXPECTED_PATTERN.to_owned()],
        case_insensitive: linked::EXPECTED_CASE_INSENSITIVE,
        unicode: linked::EXPECTED_UNICODE,
        haystack: Vec::new(),
        max_iters: 1,
        max_warmup_iters: 0,
        max_time: Duration::ZERO,
        max_warmup_time: Duration::ZERO,
    };
    if benchmark.same_compilation_identity(&expected) {
        Ok(())
    } else {
        Err("runtime KLV compilation identity differs from linked AOT artifact".to_owned())
    }
}

fn run_operation(
    benchmark: &shared::Benchmark,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let actual = session.reduce(black_box(&benchmark.haystack))?;
        black_box(actual);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let actual = session.reduce(black_box(&benchmark.haystack))?;
        let duration = sample_start.elapsed();
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn run_compile(
    benchmark: &shared::Benchmark,
    target: fre_aot_regex::Target,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let artifact = shared::compile_benchmark(benchmark, target)?;
        validate_compiled_artifact(&artifact)?;
        black_box(session.reduce(&benchmark.haystack)?);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let artifact = shared::compile_benchmark(black_box(benchmark), target)?;
        let duration = sample_start.elapsed();
        validate_compiled_artifact(&artifact)?;
        let actual = session.reduce(&benchmark.haystack)?;
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn validate_compiled_artifact(artifact: &CompiledRegex) -> Result<(), String> {
    if artifact.object() != linked::OBJECT_BYTES
        || artifact.receipt().program_sha256 != linked::PROGRAM_SHA256
        || artifact.receipt().object_sha256 != linked::OBJECT_SHA256
    {
        return Err(
            "timed compilation differs from the exact statically linked verification artifact"
                .to_owned(),
        );
    }
    Ok(())
}

fn rust_oracle(benchmark: &shared::Benchmark) -> Result<u64, String> {
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(104_857_600));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(benchmark.unicode)
        .case_insensitive(benchmark.case_insensitive);
    let regex = Regex::builder()
        .configure(config)
        .syntax(syntax)
        .build_many(&benchmark.patterns)
        .map_err(|error| format!("Rust Rebar oracle compilation failed: {error}"))?;
    match benchmark.model {
        shared::Model::Compile | shared::Model::Count => {
            u64::try_from(regex.find_iter(&benchmark.haystack).count())
                .map_err(|_| "Rust Rebar Count oracle overflow".to_owned())
        }
        shared::Model::SpanSum => {
            regex
                .find_iter(&benchmark.haystack)
                .try_fold(0_u64, |sum, matched| {
                    let width = u64::try_from(matched.end().saturating_sub(matched.start()))
                        .map_err(|_| "Rust Rebar span width overflow".to_owned())?;
                    sum.checked_add(width)
                        .ok_or_else(|| "Rust Rebar SpanSum oracle overflow".to_owned())
                })
        }
        shared::Model::GrepCount => benchmark.haystack.lines().try_fold(0_u64, |count, line| {
            if regex.is_match(line) {
                count
                    .checked_add(1)
                    .ok_or_else(|| "Rust Rebar GrepCount oracle overflow".to_owned())
            } else {
                Ok(count)
            }
        }),
    }
}

fn require_expected(actual: u64, expected: u64) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "linked AOT reducer returned {actual}, Rust Rebar oracle returned {expected}"
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benchmark(model: shared::Model, haystack: &[u8]) -> shared::Benchmark {
        shared::Benchmark {
            name: "test/model/aot".to_owned(),
            model,
            patterns: vec!["a+".to_owned()],
            case_insensitive: false,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        }
    }

    #[test]
    fn independent_oracle_covers_all_current_scalar_models() {
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Compile, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Count, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::SpanSum, b"baa x aaa")).unwrap(),
            5
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::GrepCount, b"aa\r\nno\na")).unwrap(),
            2
        );
    }

    #[test]
    fn provenance_hex_is_fixed_width() {
        assert_eq!(hex(&[0, 1, 0xfe, 0xff]), "0001feff");
    }
}
