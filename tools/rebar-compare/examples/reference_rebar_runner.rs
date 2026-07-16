//! Fresh-process Rust-regex/RE2 reference-arm adapter for the all-model gate.
//!
//! The pinned Rebar runners own the clock. For allocator-warm/steady phases,
//! this wrapper requests two visible iterations, verifies both reducers,
//! discards the first duration, and publishes the second. Compile constructs
//! and drops a distinct regex per iteration; every other admitted model uses
//! one regex retained across both iterations. This wrapper authenticates that
//! runner, validates the exact KLV lifecycle policy, and emits one canonical
//! reference raw arm.

use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use rebar_compare::{
    CompareError, InputReceipt,
    performance_contract::{
        PerformanceRawObservation, PerformanceReferenceObservationIdentity,
        performance_raw_observation_bytes, produce_performance_reference_observation,
    },
};
use sha2::{Digest, Sha256};

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;

const RUNNER_SCHEMA: &str = "fre.rebar.reference-runner.v1";
const MAX_KLV_BYTES: u64 = 64 * 1_048_576;
const MAX_RUNNER_BYTES: u64 = 256 * 1_048_576;
const MAX_CHILD_OUTPUT_BYTES: u64 = 4_096;
const RUST_RUNNER_SHA256: &str = "8ef7a4a47264c584c02432a70f7e917c1aab2639451f0ba42da0ef04041951fc";
const RE2_RUNNER_SHA256: &str = "42a53794bc7a1a911484b84dd239b625e7241c8aca41b28d677ca76686266d4b";
static PRIVATE_COPY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed CLI keeps duplicate rejection and every authenticated identity flag in one auditable dispatch"
)]
fn main() -> Result<(), DynError> {
    let all_arguments = env::args().skip(1).collect::<Vec<_>>();
    if all_arguments.as_slice() == ["--version"] {
        println!("{RUNNER_SCHEMA} protocol=performance-raw-v2 rust-regex=1.12.4 re2=2025-11-05");
        return Ok(());
    }
    let mut expectations = Expectations::default();
    let mut arguments = all_arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" => {
                return Err("--version must be the sole argument".into());
            }
            "--reference-runner" => {
                set_once(
                    &mut expectations.runner,
                    PathBuf::from(next_argument(&mut arguments, "--reference-runner")?),
                    "--reference-runner",
                )?;
            }
            "--expect-reference-runner-sha256" => {
                set_once(
                    &mut expectations.runner_sha256,
                    next_argument(&mut arguments, "--expect-reference-runner-sha256")?,
                    "--expect-reference-runner-sha256",
                )?;
            }
            "--expect-comparator" => {
                set_once(
                    &mut expectations.comparator,
                    next_argument(&mut arguments, "--expect-comparator")?,
                    "--expect-comparator",
                )?;
            }
            "--expect-benchmark" => {
                set_once(
                    &mut expectations.benchmark,
                    next_argument(&mut arguments, "--expect-benchmark")?,
                    "--expect-benchmark",
                )?;
            }
            "--expect-model" => {
                set_once(
                    &mut expectations.model,
                    next_argument(&mut arguments, "--expect-model")?,
                    "--expect-model",
                )?;
            }
            "--expect-count" => {
                let count = next_argument(&mut arguments, "--expect-count")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --expect-count: {error}"))?;
                set_once(&mut expectations.count, count, "--expect-count")?;
            }
            "--expect-job-id" => {
                set_once(
                    &mut expectations.job_id,
                    next_argument(&mut arguments, "--expect-job-id")?,
                    "--expect-job-id",
                )?;
            }
            "--expect-contract-id" => {
                set_once(
                    &mut expectations.contract_id,
                    next_argument(&mut arguments, "--expect-contract-id")?,
                    "--expect-contract-id",
                )?;
            }
            "--expect-canonical-sha" => {
                set_once(
                    &mut expectations.canonical_sha,
                    next_argument(&mut arguments, "--expect-canonical-sha")?,
                    "--expect-canonical-sha",
                )?;
            }
            "--expect-canonical-tree" => {
                set_once(
                    &mut expectations.canonical_tree,
                    next_argument(&mut arguments, "--expect-canonical-tree")?,
                    "--expect-canonical-tree",
                )?;
            }
            "--expect-semantic-receipts" => {
                set_once(
                    &mut expectations.semantic_receipts,
                    next_argument(&mut arguments, "--expect-semantic-receipts")?,
                    "--expect-semantic-receipts",
                )?;
            }
            "--expect-boundary" => {
                set_once(
                    &mut expectations.boundary,
                    next_argument(&mut arguments, "--expect-boundary")?,
                    "--expect-boundary",
                )?;
            }
            "--expect-process-token" => {
                set_once(
                    &mut expectations.process_token,
                    next_argument(&mut arguments, "--expect-process-token")?,
                    "--expect-process-token",
                )?;
            }
            "--quiet" | "-q" => {
                return Err("formal reference timing cannot suppress stdout".into());
            }
            "--help" | "-h" => {
                return Err("usage: reference_rebar_runner --reference-runner PATH --expect-reference-runner-sha256 SHA256 --expect-comparator rust-regex-1.12.4|re2-2025-11-05 --expect-benchmark NAME --expect-model MODEL --expect-count N --expect-job-id ID --expect-contract-id ID --expect-canonical-sha OID --expect-canonical-tree OID --expect-semantic-receipts SHA256 --expect-boundary BOUNDARY --expect-process-token SHA256".into());
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }

    let mut input = Vec::new();
    io::stdin()
        .take(MAX_KLV_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > MAX_KLV_BYTES) {
        return Err(format!("reference KLV input exceeds {MAX_KLV_BYTES} bytes").into());
    }
    let benchmark = Benchmark::parse(&input)?;
    let expected = required(expectations.count, "--expect-count")?;
    let boundary = required_ref(expectations.boundary.as_deref(), "--expect-boundary")?;
    let policy = benchmark.execution_policy(boundary)?;
    let observation = model_reference_raw_with_sample(&benchmark, &expectations, || {
        let runner = AuthenticatedReferenceRunner::open(&expectations)?;
        let outcome = runner.sample(&input, expected, policy);
        runner.finish(outcome)
    })?;
    io::stdout()
        .lock()
        .write_all(&performance_raw_observation_bytes(&observation)?)?;
    Ok(())
}

fn next_argument(
    arguments: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, DynError> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Expectations {
    runner: Option<PathBuf>,
    runner_sha256: Option<String>,
    comparator: Option<String>,
    benchmark: Option<String>,
    model: Option<String>,
    count: Option<u64>,
    job_id: Option<String>,
    contract_id: Option<String>,
    canonical_sha: Option<String>,
    canonical_tree: Option<String>,
    semantic_receipts: Option<String>,
    boundary: Option<String>,
    process_token: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceComparator {
    RustRegex,
    Re2,
}

impl ReferenceComparator {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "rust-regex-1.12.4" => Ok(Self::RustRegex),
            "re2-2025-11-05" => Ok(Self::Re2),
            other => Err(format!("unrecognized reference comparator {other:?}").into()),
        }
    }

    const fn version(self) -> &'static str {
        match self {
            Self::RustRegex => "1.12.4",
            Self::Re2 => "2025-11-05",
        }
    }

    const fn runner_sha256(self) -> &'static str {
        match self {
            Self::RustRegex => RUST_RUNNER_SHA256,
            Self::Re2 => RE2_RUNNER_SHA256,
        }
    }
}

#[derive(Debug)]
struct AuthenticatedReferenceRunner {
    executable: PrivateExecutable,
    sha256: String,
}

impl AuthenticatedReferenceRunner {
    fn open(expectations: &Expectations) -> Result<Self, CompareError> {
        let comparator = expectations
            .comparator
            .as_deref()
            .ok_or_else(|| CompareError::new("--expect-comparator is absent"))?;
        let comparator = ReferenceComparator::parse(comparator)
            .map_err(|error| CompareError::new(error.to_string()))?;
        let expected_sha256 = expectations
            .runner_sha256
            .as_deref()
            .ok_or_else(|| CompareError::new("--expect-reference-runner-sha256 is absent"))?;
        require_digest(expected_sha256, "reference runner SHA-256")?;
        require_comparator_digest(comparator, expected_sha256)?;
        let supplied = expectations
            .runner
            .as_deref()
            .ok_or_else(|| CompareError::new("--reference-runner is absent"))?;
        let source = fs::canonicalize(supplied).map_err(|error| {
            CompareError::new(format!(
                "canonicalize reference runner {}: {error}",
                supplied.display()
            ))
        })?;
        let bytes = read_bounded_regular_file(&source)?;
        let actual = sha256(&bytes);
        if actual != expected_sha256 {
            return Err(CompareError::new(format!(
                "reference runner digest {actual} differs from {expected_sha256}"
            )));
        }
        let executable = PrivateExecutable::create(&bytes)?;
        executable.validate()?;
        if file_sha256(executable.path())? != actual {
            return Err(CompareError::new(
                "private reference executable differs before version authentication",
            ));
        }
        let output = Command::new(executable.path())
            .env_clear()
            .arg("--version")
            .output()
            .map_err(|error| CompareError::new(format!("run reference --version: {error}")))?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(CompareError::new(
                "reference runner --version failed or wrote stderr",
            ));
        }
        let version = exact_output_line(&output.stdout, "reference runner --version")?;
        if version != comparator.version() {
            return Err(CompareError::new(format!(
                "reference runner version {version:?} differs from {:?}",
                comparator.version()
            )));
        }
        Ok(Self {
            executable,
            sha256: actual,
        })
    }

    fn sample(
        &self,
        input: &[u8],
        expected: u64,
        policy: ReferenceExecutionPolicy,
    ) -> Result<(Duration, u64), CompareError> {
        self.executable.validate()?;
        if file_sha256(self.executable.path())? != self.sha256 {
            return Err(CompareError::new(
                "reference runner changed before producing a sample",
            ));
        }
        let mut child = Command::new(self.executable.path())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| CompareError::new(format!("spawn reference runner: {error}")))?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| CompareError::new("reference runner stdin is absent"))
            .and_then(|mut stdin| {
                stdin
                    .write_all(input)
                    .map_err(|error| CompareError::new(format!("write reference KLV: {error}")))
            });
        if let Err(error) = write_result {
            terminate_child(&mut child);
            return Err(error);
        }
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return Err(CompareError::new("reference runner stdout is absent"));
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(&mut child);
            return Err(CompareError::new("reference runner stderr is absent"));
        };
        let stdout_reader = spawn_bounded_pipe_reader(stdout, "reference runner stdout");
        let stderr_reader = spawn_bounded_pipe_reader(stderr, "reference runner stderr");
        let status = match child.wait() {
            Ok(status) => status,
            Err(error) => {
                terminate_child(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CompareError::new(format!(
                    "wait for reference runner: {error}"
                )));
            }
        };
        let stdout = join_pipe_reader(stdout_reader, "reference runner stdout")?;
        let stderr = join_pipe_reader(stderr_reader, "reference runner stderr")?;
        if !status.success() || !stderr.is_empty() {
            return Err(CompareError::new(format!(
                "reference runner failed or wrote stderr: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        let published = select_verified_sample(&stdout, expected, policy)?;
        self.executable.validate()?;
        let after = file_sha256(self.executable.path())?;
        if after != self.sha256 {
            return Err(CompareError::new(
                "reference runner changed while producing a sample",
            ));
        }
        Ok(published)
    }

    fn finish<T>(mut self, outcome: Result<T, CompareError>) -> Result<T, CompareError> {
        let cleanup = self.executable.cleanup();
        match (outcome, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }
}

fn model_reference_raw_with_sample<F>(
    benchmark: &Benchmark,
    expectations: &Expectations,
    sample: F,
) -> Result<PerformanceRawObservation, DynError>
where
    F: FnOnce() -> Result<(Duration, u64), CompareError>,
{
    require_equal(
        "benchmark",
        required_ref(expectations.benchmark.as_deref(), "--expect-benchmark")?,
        &benchmark.name,
    )?;
    require_equal(
        "model",
        required_ref(expectations.model.as_deref(), "--expect-model")?,
        &benchmark.model,
    )?;
    let comparator_text = required_ref(expectations.comparator.as_deref(), "--expect-comparator")?;
    let comparator = ReferenceComparator::parse(comparator_text)?;
    if comparator == ReferenceComparator::Re2 && benchmark.patterns.len() != 1 {
        return Err("the pinned RE2 reference runner requires exactly one pattern".into());
    }
    let boundary = required_ref(expectations.boundary.as_deref(), "--expect-boundary")?;
    let _ = benchmark.execution_policy(boundary)?;
    let identity = PerformanceReferenceObservationIdentity {
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
        boundary: boundary.to_string(),
        comparator: comparator_text.to_string(),
        input: benchmark.input_receipt(),
        expected: required(expectations.count, "--expect-count")?,
        process_token_sha256: required(
            expectations.process_token.clone(),
            "--expect-process-token",
        )?,
    };
    produce_performance_reference_observation(&identity, sample).map_err(Into::into)
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
    max_time_ns: u64,
    max_warmup_time_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReferenceExecutionPolicy {
    sample_count: usize,
    publish_index: usize,
}

impl Benchmark {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "delimiter positions prove the two one-byte slice advances are in bounds"
    )]
    fn parse(mut input: &[u8]) -> Result<Self, DynError> {
        let original = input;
        let mut name = None;
        let mut model = None;
        let mut patterns = Vec::new();
        let mut case_insensitive = None;
        let mut unicode = None;
        let mut haystack = None;
        let mut max_iters = None;
        let mut max_warmup_iters = None;
        let mut max_time_ns = None;
        let mut max_warmup_time_ns = None;
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
                "max-time" => set_once(&mut max_time_ns, parse_u64(value, key)?, key)?,
                "max-warmup-time" => {
                    set_once(&mut max_warmup_time_ns, parse_u64(value, key)?, key)?;
                }
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
            max_time_ns: required(max_time_ns, "max-time")?,
            max_warmup_time_ns: required(max_warmup_time_ns, "max-warmup-time")?,
        };
        if benchmark.patterns.is_empty() {
            return Err("reference KLV requires at least one pattern".into());
        }
        if benchmark.patterns.len() != 1
            && !matches!(
                benchmark.model.as_str(),
                "compile" | "count" | "count-spans"
            )
        {
            return Err(format!(
                "reference model {:?} requires one pattern, got {}",
                benchmark.model,
                benchmark.patterns.len()
            )
            .into());
        }
        if benchmark.canonical_bytes() != original {
            return Err("reference KLV is not in canonical Rebar field order and encoding".into());
        }
        Ok(benchmark)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        append_klv_field(&mut output, "name", self.name.as_bytes());
        append_klv_field(&mut output, "model", self.model.as_bytes());
        append_klv_field(
            &mut output,
            "case-insensitive",
            self.case_insensitive.to_string().as_bytes(),
        );
        append_klv_field(&mut output, "unicode", self.unicode.to_string().as_bytes());
        append_klv_field(
            &mut output,
            "max-iters",
            self.max_iters.to_string().as_bytes(),
        );
        append_klv_field(
            &mut output,
            "max-warmup-iters",
            self.max_warmup_iters.to_string().as_bytes(),
        );
        append_klv_field(
            &mut output,
            "max-time",
            self.max_time_ns.to_string().as_bytes(),
        );
        append_klv_field(
            &mut output,
            "max-warmup-time",
            self.max_warmup_time_ns.to_string().as_bytes(),
        );
        for pattern in &self.patterns {
            append_klv_field(&mut output, "pattern", pattern.as_bytes());
        }
        append_klv_field(&mut output, "haystack", &self.haystack);
        output
    }

    fn execution_policy(&self, boundary: &str) -> Result<ReferenceExecutionPolicy, DynError> {
        let needs_verified_predecessor = match (self.model.as_str(), boundary) {
            ("compile", "cold-public-compile")
            | (
                "count" | "count-spans" | "count-captures" | "grep" | "grep-captures",
                "first-public-operation",
            ) => false,
            ("compile", "allocator-warm-public-compile")
            | (
                "count" | "count-spans" | "count-captures" | "grep" | "grep-captures",
                "steady-public-operation",
            ) => true,
            _ => {
                return Err(format!(
                    "unexpected reference lifecycle {:?}/{boundary:?}",
                    self.model
                )
                .into());
            }
        };
        let (max_iters, max_time_ns, policy) = if needs_verified_predecessor {
            (
                2,
                u64::MAX,
                ReferenceExecutionPolicy {
                    sample_count: 2,
                    publish_index: 1,
                },
            )
        } else {
            (
                1,
                0,
                ReferenceExecutionPolicy {
                    sample_count: 1,
                    publish_index: 0,
                },
            )
        };
        if self.max_iters != max_iters
            || self.max_warmup_iters != 0
            || self.max_time_ns != max_time_ns
            || self.max_warmup_time_ns != 0
        {
            return Err(format!(
                "reference lifecycle requires max-iters={max_iters}, max-warmup-iters=0, max-time={max_time_ns}, max-warmup-time=0"
            )
            .into());
        }
        Ok(policy)
    }

    fn input_receipt(&self) -> InputReceipt {
        InputReceipt {
            pattern_sha256: self
                .patterns
                .iter()
                .map(|pattern| sha256(pattern.as_bytes()))
                .collect(),
            haystack_sha256: sha256(&self.haystack),
            haystack_bytes: self.haystack.len(),
            unicode: self.unicode,
            case_insensitive: self.case_insensitive,
        }
    }
}

fn parse_sample_output(
    bytes: &[u8],
    expected_samples: usize,
) -> Result<Vec<(Duration, u64)>, CompareError> {
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err(CompareError::new(
            "reference timing samples are not LF-terminated lines",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| CompareError::new(format!("reference samples are not UTF-8: {error}")))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != expected_samples {
        return Err(CompareError::new(format!(
            "reference runner returned {} samples, expected {expected_samples}",
            lines.len()
        )));
    }
    lines.into_iter().map(parse_sample_line).collect()
}

fn append_klv_field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
    output.extend_from_slice(key.as_bytes());
    output.push(b':');
    output.extend_from_slice(value.len().to_string().as_bytes());
    output.push(b':');
    output.extend_from_slice(value);
    output.push(b'\n');
}

fn select_verified_sample(
    bytes: &[u8],
    expected: u64,
    policy: ReferenceExecutionPolicy,
) -> Result<(Duration, u64), CompareError> {
    let samples = parse_sample_output(bytes, policy.sample_count)?;
    for (index, (_, actual)) in samples.iter().enumerate() {
        if *actual != expected {
            return Err(CompareError::new(format!(
                "reference runner sample {index} returned {actual}, expected {expected}"
            )));
        }
    }
    samples
        .get(policy.publish_index)
        .copied()
        .ok_or_else(|| CompareError::new("reference publication index is absent"))
}

fn parse_sample_line(line: &str) -> Result<(Duration, u64), CompareError> {
    let (duration, count) = line
        .split_once(',')
        .ok_or_else(|| CompareError::new("reference sample lacks comma delimiter"))?;
    let duration_ns = duration
        .parse::<u64>()
        .map_err(|error| CompareError::new(format!("reference sample duration: {error}")))?;
    let count = count
        .parse::<u64>()
        .map_err(|error| CompareError::new(format!("reference sample count: {error}")))?;
    if duration_ns == 0 {
        return Err(CompareError::new(
            "reference runner returned a zero-duration sample",
        ));
    }
    Ok((Duration::from_nanos(duration_ns), count))
}

fn exact_output_line<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, CompareError> {
    if bytes.last() != Some(&b'\n')
        || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err(CompareError::new(format!(
            "{label} is not exactly one LF-terminated line"
        )));
    }
    std::str::from_utf8(&bytes[..bytes.len().saturating_sub(1)])
        .map_err(|error| CompareError::new(format!("{label} is not UTF-8: {error}")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    length: u64,
}

impl FileSnapshot {
    fn capture(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            length: metadata.len(),
        }
    }
}

#[derive(Debug)]
struct PrivateExecutable {
    directory: PathBuf,
    path: PathBuf,
    length: u64,
    directory_snapshot: Option<FileSnapshot>,
    executable_snapshot: Option<FileSnapshot>,
    cleaned: bool,
}

impl PrivateExecutable {
    fn create(bytes: &[u8]) -> Result<Self, CompareError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_RUNNER_BYTES)
        {
            return Err(CompareError::new(
                "authenticated reference executable bytes are empty or oversized",
            ));
        }
        let directory = create_private_directory()?;
        let path = directory.join("reference-runner");
        let mut private = Self {
            directory,
            path,
            length: u64::try_from(bytes.len())
                .map_err(|_| CompareError::new("reference executable length does not fit u64"))?,
            directory_snapshot: None,
            executable_snapshot: None,
            cleaned: false,
        };
        let initialized = (|| -> Result<(), CompareError> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o500)
                .open(&private.path)
                .map_err(|error| {
                    CompareError::new(format!(
                        "create private reference executable {}: {error}",
                        private.path.display()
                    ))
                })?;
            output.write_all(bytes).map_err(|error| {
                CompareError::new(format!("write private reference executable: {error}"))
            })?;
            output
                .set_permissions(fs::Permissions::from_mode(0o500))
                .map_err(|error| {
                    CompareError::new(format!("protect private reference executable: {error}"))
                })?;
            output.sync_all().map_err(|error| {
                CompareError::new(format!("sync private reference executable: {error}"))
            })?;
            drop(output);
            private.validate()?;
            private.directory_snapshot = Some(FileSnapshot::capture(
                &fs::symlink_metadata(&private.directory).map_err(|error| {
                    CompareError::new(format!("snapshot private reference directory: {error}"))
                })?,
            ));
            private.executable_snapshot = Some(FileSnapshot::capture(
                &fs::symlink_metadata(&private.path).map_err(|error| {
                    CompareError::new(format!("snapshot private reference executable: {error}"))
                })?,
            ));
            private.validate()?;
            let directory = File::open(&private.directory).map_err(|error| {
                CompareError::new(format!("open private reference directory: {error}"))
            })?;
            directory.sync_all().map_err(|error| {
                CompareError::new(format!("sync private reference directory: {error}"))
            })?;
            Ok(())
        })();
        if let Err(error) = initialized {
            let _ = private.cleanup();
            return Err(error);
        }
        Ok(private)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn validate(&self) -> Result<(), CompareError> {
        let directory = fs::symlink_metadata(&self.directory).map_err(|error| {
            CompareError::new(format!("stat private reference directory: {error}"))
        })?;
        if !directory.file_type().is_dir() || directory.mode() & 0o777 != 0o700 {
            return Err(CompareError::new(
                "private reference directory type or mode changed",
            ));
        }
        if self
            .directory_snapshot
            .is_some_and(|expected| FileSnapshot::capture(&directory) != expected)
        {
            return Err(CompareError::new(
                "private reference directory inode or ownership changed",
            ));
        }
        let executable = fs::symlink_metadata(&self.path).map_err(|error| {
            CompareError::new(format!("stat private reference executable: {error}"))
        })?;
        if !executable.file_type().is_file()
            || executable.mode() & 0o777 != 0o500
            || executable.nlink() != 1
            || executable.len() != self.length
        {
            return Err(CompareError::new(
                "private reference executable type, mode, link count, or length changed",
            ));
        }
        if self
            .executable_snapshot
            .is_some_and(|expected| FileSnapshot::capture(&executable) != expected)
        {
            return Err(CompareError::new(
                "private reference executable inode or ownership changed",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), CompareError> {
        if self.cleaned {
            return Ok(());
        }
        self.validate()?;
        fs::remove_file(&self.path).map_err(|error| {
            CompareError::new(format!("remove private reference executable: {error}"))
        })?;
        fs::remove_dir(&self.directory).map_err(|error| {
            CompareError::new(format!("remove private reference directory: {error}"))
        })?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateExecutable {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}

fn create_private_directory() -> Result<PathBuf, CompareError> {
    let parent = fs::canonicalize(env::temp_dir())
        .map_err(|error| CompareError::new(format!("canonicalize temp directory: {error}")))?;
    if !parent.is_dir() {
        return Err(CompareError::new("canonical temp path is not a directory"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CompareError::new(format!("private-copy system time: {error}")))?;
    for _ in 0..16 {
        let sequence = PRIVATE_COPY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nonce = format!("{}:{}:{sequence}", std::process::id(), now.as_nanos());
        let directory = parent.join(format!("fre-reference-{}", &sha256(nonce.as_bytes())[..32]));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(CompareError::new(format!(
                    "create private reference directory: {error}"
                )));
            }
        }
    }
    Err(CompareError::new(
        "could not allocate a unique private reference directory",
    ))
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, CompareError> {
    let mut input = File::open(path).map_err(|error| {
        CompareError::new(format!("open reference runner {}: {error}", path.display()))
    })?;
    let before_metadata = input.metadata().map_err(|error| {
        CompareError::new(format!("stat reference runner {}: {error}", path.display()))
    })?;
    if !before_metadata.is_file()
        || before_metadata.len() == 0
        || before_metadata.len() > MAX_RUNNER_BYTES
    {
        return Err(CompareError::new(format!(
            "reference runner {} is not a bounded nonempty regular file",
            path.display()
        )));
    }
    let before = FileSnapshot::capture(&before_metadata);
    let mut bytes = Vec::new();
    (&mut input)
        .take(MAX_RUNNER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| CompareError::new(format!("read reference runner: {error}")))?;
    let after = FileSnapshot::capture(
        &input
            .metadata()
            .map_err(|error| CompareError::new(format!("restat reference runner: {error}")))?,
    );
    if before != after
        || u64::try_from(bytes.len()).ok() != Some(before.length)
        || before.length > MAX_RUNNER_BYTES
    {
        return Err(CompareError::new(
            "reference runner metadata or length changed while reading",
        ));
    }
    Ok(bytes)
}

fn spawn_bounded_pipe_reader<R>(
    pipe: R,
    label: &'static str,
) -> thread::JoinHandle<Result<Vec<u8>, CompareError>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_bounded_child_pipe(pipe, label))
}

fn read_bounded_child_pipe(mut pipe: impl Read, label: &str) -> Result<Vec<u8>, CompareError> {
    let mut bytes = Vec::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 4_096];
    loop {
        let read = pipe
            .read(&mut chunk)
            .map_err(|error| CompareError::new(format!("read {label}: {error}")))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| CompareError::new(format!("{label} read size overflow")))?,
            )
            .ok_or_else(|| CompareError::new(format!("{label} byte count overflow")))?;
        if bytes.len() < usize::try_from(MAX_CHILD_OUTPUT_BYTES).unwrap_or(usize::MAX) {
            let remaining = usize::try_from(MAX_CHILD_OUTPUT_BYTES)
                .unwrap_or(usize::MAX)
                .saturating_sub(bytes.len());
            bytes.extend_from_slice(&chunk[..read.min(remaining)]);
        }
    }
    if total > MAX_CHILD_OUTPUT_BYTES {
        return Err(CompareError::new(format!("{label} exceeds its byte limit")));
    }
    Ok(bytes)
}

fn join_pipe_reader(
    reader: thread::JoinHandle<Result<Vec<u8>, CompareError>>,
    label: &str,
) -> Result<Vec<u8>, CompareError> {
    reader
        .join()
        .map_err(|_| CompareError::new(format!("{label} reader panicked")))?
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn file_sha256(path: &Path) -> Result<String, CompareError> {
    read_bounded_regular_file(path).map(|bytes| sha256(&bytes))
}

fn require_digest(value: &str, label: &str) -> Result<(), CompareError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CompareError::new(format!(
            "{label} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn require_comparator_digest(
    comparator: ReferenceComparator,
    supplied: &str,
) -> Result<(), CompareError> {
    if supplied != comparator.runner_sha256() {
        return Err(CompareError::new(format!(
            "reference runner digest {supplied} is not the pinned {} digest",
            comparator.version()
        )));
    }
    Ok(())
}

fn require_equal(label: &str, expected: &str, actual: &str) -> Result<(), DynError> {
    if expected != actual {
        return Err(
            format!("reference {label} identity {actual:?} differs from {expected:?}").into(),
        );
    }
    Ok(())
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
        return Err(format!("duplicate scalar field {key:?}").into());
    }
    Ok(())
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, DynError> {
    value.ok_or_else(|| format!("missing required {key}").into())
}

fn required_ref<'a>(value: Option<&'a str>, key: &str) -> Result<&'a str, DynError> {
    value.ok_or_else(|| format!("missing required {key}").into())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn klv(model: &str, patterns: &[&str], verified_predecessor: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        field(&mut bytes, "name", b"fixture/reference");
        field(&mut bytes, "model", model.as_bytes());
        field(&mut bytes, "case-insensitive", b"false");
        field(&mut bytes, "unicode", b"true");
        field(
            &mut bytes,
            "max-iters",
            if verified_predecessor { b"2" } else { b"1" },
        );
        field(&mut bytes, "max-warmup-iters", b"0");
        let max_time = if verified_predecessor {
            u64::MAX.to_string()
        } else {
            "0".to_string()
        };
        field(&mut bytes, "max-time", max_time.as_bytes());
        field(&mut bytes, "max-warmup-time", b"0");
        for pattern in patterns {
            field(&mut bytes, "pattern", pattern.as_bytes());
        }
        field(&mut bytes, "haystack", b"aba\nzzz\n");
        bytes
    }

    fn field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
        write!(output, "{key}:{}:", value.len()).expect("write field prefix");
        output.extend_from_slice(value);
        output.push(b'\n');
    }

    fn expectations(model: &str, boundary: &str, comparator: &str) -> Expectations {
        Expectations {
            runner: Some(PathBuf::from("/not-used-by-fixed-sample")),
            runner_sha256: Some("a".repeat(64)),
            comparator: Some(comparator.to_string()),
            benchmark: Some("fixture/reference".to_string()),
            model: Some(model.to_string()),
            count: Some(2),
            job_id: Some("fixture/reference@rust/regex".to_string()),
            contract_id: Some("fixture-performance-contract-v1".to_string()),
            canonical_sha: Some("b".repeat(40)),
            canonical_tree: Some("c".repeat(40)),
            semantic_receipts: Some("d".repeat(64)),
            boundary: Some(boundary.to_string()),
            process_token: Some("e".repeat(64)),
        }
    }

    #[test]
    fn exact_upstream_lifecycle_policy_emits_reference_arms_without_a_clock() {
        for (model, first, steady) in [
            (
                "compile",
                "cold-public-compile",
                "allocator-warm-public-compile",
            ),
            ("count", "first-public-operation", "steady-public-operation"),
            (
                "count-spans",
                "first-public-operation",
                "steady-public-operation",
            ),
            (
                "count-captures",
                "first-public-operation",
                "steady-public-operation",
            ),
            ("grep", "first-public-operation", "steady-public-operation"),
            (
                "grep-captures",
                "first-public-operation",
                "steady-public-operation",
            ),
        ] {
            for (boundary, verified_predecessor) in [(first, false), (steady, true)] {
                let benchmark =
                    Benchmark::parse(&klv(model, &["a"], verified_predecessor)).expect("KLV");
                let observation = model_reference_raw_with_sample(
                    &benchmark,
                    &expectations(model, boundary, "rust-regex-1.12.4"),
                    || Ok((Duration::from_nanos(17), 2)),
                )
                .expect("fixed reference sample");
                assert_eq!(
                    observation.arm,
                    rebar_compare::performance_contract::CapturePairArm::Reference
                );
                let expected_prime = u8::from(model != "compile" && verified_predecessor);
                assert_eq!(observation.priming_operations, expected_prime);
                assert_eq!(observation.elapsed_ns, 17);
                assert_eq!(observation.candidate_plan, None);
                assert_eq!(observation.candidate_runtime, None);
            }
        }
    }

    #[test]
    fn malformed_policy_or_re2_multiplicity_is_rejected_before_sampling() {
        let sampled = Cell::new(false);
        let wrong_policy = Benchmark::parse(&klv("count", &["a"], true)).expect("KLV");
        assert!(
            model_reference_raw_with_sample(
                &wrong_policy,
                &expectations("count", "first-public-operation", "rust-regex-1.12.4"),
                || {
                    sampled.set(true);
                    Ok((Duration::from_nanos(1), 2))
                },
            )
            .is_err()
        );
        assert!(!sampled.get());

        let many = Benchmark::parse(&klv("count", &["a", "b"], false)).expect("multi KLV");
        assert!(
            model_reference_raw_with_sample(
                &many,
                &expectations("count", "first-public-operation", "re2-2025-11-05"),
                || {
                    sampled.set(true);
                    Ok((Duration::from_nanos(1), 2))
                },
            )
            .is_err()
        );
        assert!(!sampled.get());
    }

    #[test]
    fn reference_sample_output_is_exact_and_nonzero() {
        assert_eq!(
            parse_sample_output(b"19,2\n", 1).expect("exact sample"),
            vec![(Duration::from_nanos(19), 2)]
        );
        assert_eq!(
            parse_sample_output(b"17,2\n19,2\n", 2).expect("verified predecessor and sample"),
            vec![(Duration::from_nanos(17), 2), (Duration::from_nanos(19), 2)]
        );
        for malformed in [
            b"0,2\n".as_slice(),
            b"19,2".as_slice(),
            b"19,2\n20,2\n".as_slice(),
            b"19,2\r\n".as_slice(),
            b"19\n".as_slice(),
        ] {
            assert!(parse_sample_output(malformed, 1).is_err());
        }
        assert!(parse_sample_output(b"19,2\n", 2).is_err());

        let two = ReferenceExecutionPolicy {
            sample_count: 2,
            publish_index: 1,
        };
        assert_eq!(
            select_verified_sample(b"17,2\n19,2\n", 2, two).expect("both reducers verified"),
            (Duration::from_nanos(19), 2)
        );
        assert!(select_verified_sample(b"17,1\n19,2\n", 2, two).is_err());
        assert!(select_verified_sample(b"17,2\n19,1\n", 2, two).is_err());
        assert_eq!(
            read_bounded_child_pipe(io::Cursor::new(vec![b'x'; 4_096]), "fixture pipe")
                .expect("exact output bound")
                .len(),
            4_096
        );
        assert!(
            read_bounded_child_pipe(io::Cursor::new(vec![b'x'; 4_097]), "fixture pipe").is_err()
        );
        assert_eq!(
            ReferenceComparator::RustRegex.runner_sha256(),
            RUST_RUNNER_SHA256
        );
        assert_eq!(ReferenceComparator::Re2.runner_sha256(), RE2_RUNNER_SHA256);
        assert!(
            require_comparator_digest(ReferenceComparator::RustRegex, RUST_RUNNER_SHA256).is_ok()
        );
        assert!(
            require_comparator_digest(ReferenceComparator::RustRegex, RE2_RUNNER_SHA256).is_err()
        );
    }

    #[test]
    fn canonical_klv_and_private_executable_fail_closed_without_running_it() {
        let canonical = klv("count", &["a"], false);
        assert!(Benchmark::parse(&canonical).is_ok());
        let needle = b"max-iters:1:1\n";
        let offset = canonical
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("canonical max-iters field");
        let mut noncanonical = canonical[..offset].to_vec();
        noncanonical.extend_from_slice(b"max-iters:01:1\n");
        noncanonical.extend_from_slice(&canonical[offset + needle.len()..]);
        assert!(Benchmark::parse(&noncanonical).is_err());

        let mut duplicate = None;
        set_once(&mut duplicate, 1_u64, "fixture").expect("first field");
        assert!(set_once(&mut duplicate, 2_u64, "fixture").is_err());

        let mut private = PrivateExecutable::create(b"private executable fixture")
            .expect("create protected private copy");
        let directory = private.directory.clone();
        let path = private.path.clone();
        private.validate().expect("private copy validates");
        assert_eq!(
            fs::symlink_metadata(&directory)
                .expect("private directory metadata")
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("private executable metadata")
                .mode()
                & 0o777,
            0o500
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("mutate private mode fixture");
        assert!(private.validate().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500))
            .expect("restore private mode fixture");
        private.validate().expect("restored private copy validates");
        private.cleanup().expect("private cleanup");
        assert!(!path.exists());
        assert!(!directory.exists());
    }
}
