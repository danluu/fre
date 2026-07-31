use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    hint::black_box,
    io::{self, BufWriter, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Instant,
};

use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy};
use fre_jit_runtime::{PublicationLimits, PublishedKernel, RuntimeOperation};
use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, Exists, MatchSpan, SearchWindow, SelectedEnd, Span,
    ValidateLimits, ValidatedProgram, build_exact_literal,
};
use fre_search_v26_development_gate::{
    EXPECTED_CELL_COUNT, EXPECTED_POPULATION_SHA256, GateFixture, GateWindowShape, build_fixture,
    cell_record, expected_output_identity, shard_for_width,
};
use fre_search_v26_synthetic_runner::{
    SyntheticLiteral, SyntheticOutput, generate_population, hex,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CALIBRATION_TARGET_NS: u64 = 4_000_000;
const EXPECTED_SHARD_CELLS: usize = 2_592;
const BUILD_SOURCE_COMMIT: &str = env!("FRE_V26_SOURCE_COMMIT");
const BUILD_SOURCE_TREE: &str = env!("FRE_V26_SOURCE_TREE");
const BUILD_SOURCE_ARCHIVE_SHA256: &str = env!("FRE_V26_SOURCE_ARCHIVE_SHA256");
const BUILD_TARGET: &str = env!("FRE_V26_BUILD_TARGET");
const BUILD_HOST: &str = env!("FRE_V26_BUILD_HOST");
const BUILD_PROFILE: &str = env!("FRE_V26_BUILD_PROFILE");
const BUILD_OPT_LEVEL: &str = env!("FRE_V26_BUILD_OPT_LEVEL");
const BUILD_DEBUG: &str = env!("FRE_V26_BUILD_DEBUG");
const BUILD_CRT_STATIC: &str = env!("FRE_V26_BUILD_CRT_STATIC");
const RUSTC_IDENTITY_SHA256: &str = env!("FRE_V26_RUSTC_IDENTITY_SHA256");
const CARGO_IDENTITY_SHA256: &str = env!("FRE_V26_CARGO_IDENTITY_SHA256");
const RUNNER_SOURCE_SET_SHA256: &str = env!("FRE_V26_RUNNER_SOURCE_SET_SHA256");
const BUILD_CONFIGURATION_SHA256: &str = env!("FRE_V26_BUILD_CONFIGURATION_SHA256");
const BUILD_IDENTITY_MARKER: &str = concat!(
    "FRE-V26-RUNNER-BUILD-IDENTITY-V1|",
    env!("FRE_V26_SOURCE_COMMIT"),
    "|",
    env!("FRE_V26_SOURCE_TREE"),
    "|",
    env!("FRE_V26_SOURCE_ARCHIVE_SHA256"),
    "|",
    env!("FRE_V26_BUILD_TARGET"),
    "|",
    env!("FRE_V26_BUILD_PROFILE"),
    "|",
    env!("FRE_V26_BUILD_CRT_STATIC"),
    "|",
    env!("FRE_V26_RUNNER_SOURCE_SET_SHA256"),
    "|",
    env!("FRE_V26_BUILD_CONFIGURATION_SHA256"),
    "|",
    env!("FRE_V26_RUSTC_IDENTITY_SHA256"),
    "|",
    env!("FRE_V26_CARGO_IDENTITY_SHA256")
);

type GateResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
struct BuildIdentity {
    schema: &'static str,
    source_commit: &'static str,
    source_tree: &'static str,
    source_archive_sha256: &'static str,
    target_triple: &'static str,
    host_triple: &'static str,
    profile: &'static str,
    opt_level: &'static str,
    debug: &'static str,
    crt_static: &'static str,
    rustc_identity_sha256: &'static str,
    cargo_identity_sha256: &'static str,
    runner_source_set_sha256: &'static str,
    build_configuration_sha256: &'static str,
    crate_version: &'static str,
    candidate_backend: u16,
    reference_backend: u16,
}

fn build_identity() -> BuildIdentity {
    black_box(BUILD_IDENTITY_MARKER);
    BuildIdentity {
        schema: "fre-search-v26-development-gate-runner-build-identity-v1",
        source_commit: BUILD_SOURCE_COMMIT,
        source_tree: BUILD_SOURCE_TREE,
        source_archive_sha256: BUILD_SOURCE_ARCHIVE_SHA256,
        target_triple: BUILD_TARGET,
        host_triple: BUILD_HOST,
        profile: BUILD_PROFILE,
        opt_level: BUILD_OPT_LEVEL,
        debug: BUILD_DEBUG,
        crt_static: BUILD_CRT_STATIC,
        rustc_identity_sha256: RUSTC_IDENTITY_SHA256,
        cargo_identity_sha256: CARGO_IDENTITY_SHA256,
        runner_source_set_sha256: RUNNER_SOURCE_SET_SHA256,
        build_configuration_sha256: BUILD_CONFIGURATION_SHA256,
        crate_version: env!("CARGO_PKG_VERSION"),
        candidate_backend: 39,
        reference_backend: 30,
    }
}

fn build_identity_bytes() -> GateResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&build_identity())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    schema: String,
    status: String,
    source_commit: String,
    source_tree: String,
    source_archive_sha256: String,
    runner_binary_sha256: String,
    runner_binary_bytes: u64,
    runner_build_identity_sha256: String,
    taskset_path: String,
    taskset_binary_sha256: String,
    taskset_binary_bytes: u64,
    contract_sha256: String,
    cell_manifest_sha256: String,
    launcher_sha256: String,
    analyzer_sha256: String,
    authorization_nonce: String,
    one_shot_registry: String,
    timing_runs: u8,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShardCpu {
    shard_id: u8,
    cpu_id: usize,
    shard_nonce: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunManifest {
    schema: String,
    status: String,
    one_shot_seal_sha256: String,
    authorization_nonce: String,
    run_nonce: String,
    source_commit: String,
    source_tree: String,
    source_archive_sha256: String,
    runner_binary_sha256: String,
    runner_binary_bytes: u64,
    runner_build_identity_sha256: String,
    taskset_binary_sha256: String,
    taskset_binary_bytes: u64,
    contract_sha256: String,
    cell_manifest_sha256: String,
    host_fingerprint_sha256: String,
    cpu_ids: Vec<usize>,
    shard_cpu_map: Vec<ShardCpu>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedMarker {
    schema: String,
    one_shot_seal_sha256: String,
    authorization_nonce: String,
    run_manifest_sha256: String,
    run_nonce: String,
    preflight_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightProof {
    shard_id: u8,
    cpu_id: usize,
    shard_nonce: String,
    sha256: String,
    bytes: u64,
    cells: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightManifest {
    schema: String,
    status: String,
    one_shot_seal_sha256: String,
    run_manifest_sha256: String,
    source_commit: String,
    source_tree: String,
    source_archive_sha256: String,
    runner_binary_sha256: String,
    runner_binary_bytes: u64,
    runner_build_identity_sha256: String,
    taskset_binary_sha256: String,
    taskset_binary_bytes: u64,
    contract_sha256: String,
    cell_manifest_sha256: String,
    host_fingerprint_sha256: String,
    run_nonce: String,
    proofs: Vec<PreflightProof>,
    cells: usize,
    semantic_comparisons: usize,
    complete: bool,
}

#[derive(Debug, Serialize)]
struct ShardHeader<'a> {
    schema: &'static str,
    shard_id: u8,
    candidate_backend: u16,
    reference_backend: u16,
    source_commit: &'a str,
    source_tree: &'a str,
    source_archive_sha256: &'a str,
    runner_binary_sha256: &'a str,
    runner_binary_bytes: u64,
    runner_build_identity_sha256: &'a str,
    taskset_binary_sha256: &'a str,
    taskset_binary_bytes: u64,
    contract_sha256: &'a str,
    cell_manifest_sha256: &'a str,
    host_fingerprint_sha256: &'a str,
    cpu_id: usize,
    shard_nonce: &'a str,
    run_nonce: &'a str,
    one_shot_seal_sha256: &'a str,
    one_shot_consumption_sha256: &'a str,
    preflight_manifest_sha256: &'a str,
    run_manifest_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct PreflightHeader<'a> {
    schema: &'static str,
    shard_id: u8,
    candidate_backend: u16,
    reference_backend: u16,
    source_commit: &'a str,
    source_tree: &'a str,
    source_archive_sha256: &'a str,
    runner_binary_sha256: &'a str,
    runner_binary_bytes: u64,
    runner_build_identity_sha256: &'a str,
    taskset_binary_sha256: &'a str,
    taskset_binary_bytes: u64,
    contract_sha256: &'a str,
    cell_manifest_sha256: &'a str,
    host_fingerprint_sha256: &'a str,
    cpu_id: usize,
    shard_nonce: &'a str,
    run_nonce: &'a str,
    one_shot_seal_sha256: &'a str,
    run_manifest_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct PreflightFooter<'a> {
    schema: &'static str,
    shard_id: u8,
    cells: usize,
    semantic_comparisons: usize,
    complete: bool,
    shard_nonce: &'a str,
    run_nonce: &'a str,
}

#[derive(Debug, Serialize)]
struct ShardFooter<'a> {
    schema: &'static str,
    shard_id: u8,
    cells: usize,
    complete: bool,
    shard_nonce: &'a str,
    run_nonce: &'a str,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Engine {
    Portable,
    V17,
    V26,
}

const ORDERS: [[Engine; 3]; 12] = [
    [Engine::Portable, Engine::V17, Engine::V26],
    [Engine::Portable, Engine::V26, Engine::V17],
    [Engine::V17, Engine::Portable, Engine::V26],
    [Engine::V17, Engine::V26, Engine::Portable],
    [Engine::V26, Engine::Portable, Engine::V17],
    [Engine::V26, Engine::V17, Engine::Portable],
    [Engine::Portable, Engine::V17, Engine::V26],
    [Engine::Portable, Engine::V26, Engine::V17],
    [Engine::V17, Engine::Portable, Engine::V26],
    [Engine::V17, Engine::V26, Engine::Portable],
    [Engine::V26, Engine::Portable, Engine::V17],
    [Engine::V26, Engine::V17, Engine::Portable],
];

impl Engine {
    const fn name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::V17 => "v17",
            Self::V26 => "v26",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct Calibration {
    iterations: u64,
    elapsed_ns: u64,
    previous_iterations: Option<u64>,
    previous_elapsed_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct Sample {
    elapsed_ns: u64,
    iterations: u64,
}

#[derive(Debug, Serialize)]
struct Repetition {
    #[serde(rename = "repetition")]
    ordinal: usize,
    order: [Engine; 3],
    engines: BTreeMap<&'static str, Sample>,
}

#[derive(Debug, Serialize)]
struct Semantics<'a> {
    equal: bool,
    expected: &'a str,
    portable: &'a str,
    v17: &'a str,
    v26: &'a str,
}

trait GateOperation: RuntimeOperation
where
    Self::Output: Copy + Eq,
{
    fn output_identity(output: Self::Output) -> GateResult<String>;
    fn expected_output(fixture: &GateFixture) -> Self::Output;
}

impl GateOperation for Exists {
    fn output_identity(output: bool) -> GateResult<String> {
        expected_output_identity(1, output.then_some((0, 0)))
            .map_err(|error| invalid(format!("Exists output identity failed: {error}")).into())
    }

    fn expected_output(fixture: &GateFixture) -> bool {
        fixture.expected_match.is_some()
    }
}

impl GateOperation for SelectedEnd {
    fn output_identity(output: Option<usize>) -> GateResult<String> {
        expected_output_identity(2, output.map(|end| (0, end)))
            .map_err(|error| invalid(format!("SelectedEnd output identity failed: {error}")).into())
    }

    fn expected_output(fixture: &GateFixture) -> Option<usize> {
        fixture.expected_match.map(|(_, end)| end)
    }
}

impl GateOperation for Span {
    fn output_identity(output: Option<MatchSpan>) -> GateResult<String> {
        expected_output_identity(3, output.map(|span| (span.start(), span.end())))
            .map_err(|error| invalid(format!("Span output identity failed: {error}")).into())
    }

    fn expected_output(fixture: &GateFixture) -> Option<MatchSpan> {
        fixture
            .expected_match
            .map(|(start, end)| MatchSpan::new(start, end))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn read_bounded(path: &Path, maximum_bytes: usize) -> GateResult<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(invalid(format!(
            "{} is not a regular non-symlink file",
            path.display()
        ))
        .into());
    }
    let length = usize::try_from(path_metadata.len())
        .map_err(|_| invalid(format!("{} length exceeds usize", path.display())))?;
    if length > maximum_bytes {
        return Err(invalid(format!("{} exceeds its size bound", path.display())).into());
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if (
        path_metadata.dev(),
        path_metadata.ino(),
        path_metadata.len(),
        path_metadata.mtime(),
        path_metadata.mtime_nsec(),
        path_metadata.ctime(),
        path_metadata.ctime_nsec(),
        path_metadata.mode(),
    ) != (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
        before.mode(),
    ) {
        return Err(invalid(format!("{} changed while being opened", path.display())).into());
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(invalid(format!("{} changed while being read", path.display())).into());
    }
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
        before.mode(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
        after.mode(),
    ) {
        return Err(invalid(format!("{} changed while being read", path.display())).into());
    }
    Ok(bytes)
}

fn read_live_executable(maximum_bytes: usize) -> GateResult<Vec<u8>> {
    let mut file = File::open("/proc/self/exe")?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(invalid("/proc/self/exe does not resolve to a regular file").into());
    }
    let length = usize::try_from(before.len())
        .map_err(|_| invalid("live executable length exceeds usize"))?;
    if length > maximum_bytes {
        return Err(invalid("live executable exceeds its size bound").into());
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(invalid("live executable changed while being read").into());
    }
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
        before.mode(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
        after.mode(),
    ) {
        return Err(invalid("live executable changed across its read").into());
    }
    Ok(bytes)
}

fn require_read_only(path: &Path) -> GateResult<()> {
    if fs::symlink_metadata(path)?.permissions().mode() & 0o222 != 0 {
        return Err(invalid(format!("{} remains writable", path.display())).into());
    }
    Ok(())
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], name: &str) -> GateResult<T> {
    if !bytes.ends_with(b"\n") {
        return Err(invalid(format!("{name} lacks a final newline")).into());
    }
    Ok(serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("cannot decode {name}: {error}")))?)
}

fn require_lower_hex(value: &str, length: usize, name: &str) -> GateResult<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{name} is not canonical lowercase hex")).into());
    }
    Ok(())
}

fn require_nonce(value: &str, name: &str) -> GateResult<()> {
    require_lower_hex(value, 64, name)?;
    if value.bytes().all(|byte| byte == b'0') || value.bytes().all(|byte| byte == b'f') {
        return Err(invalid(format!("{name} uses a forbidden sentinel")).into());
    }
    Ok(())
}

fn require_single_cpu_affinity(cpu_id: usize) -> GateResult<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .ok_or_else(|| invalid("/proc/self/status has no Cpus_allowed_list"))?;
    if allowed != cpu_id.to_string() {
        return Err(invalid(format!(
            "runner affinity is {allowed}, expected only CPU {cpu_id}"
        ))
        .into());
    }
    Ok(())
}

fn elapsed_ns(start: Instant) -> GateResult<u64> {
    u64::try_from(start.elapsed().as_nanos())
        .map_err(|_| invalid("elapsed duration exceeds u64 nanoseconds").into())
}

fn time_iterations<T, F>(iterations: u64, expected_output: T, mut search: F) -> GateResult<u64>
where
    T: Copy + Eq,
    F: FnMut() -> GateResult<T>,
{
    if iterations == 0 {
        return Err(invalid("zero timing iterations").into());
    }
    let start = Instant::now();
    let mut last_output = None;
    for _ in 0..iterations {
        last_output = Some(black_box(search()?));
    }
    let elapsed = elapsed_ns(start)?;
    if last_output != Some(expected_output) {
        return Err(invalid("post-batch result differs from sealed preflight expectation").into());
    }
    if elapsed == 0 {
        return Err(invalid("zero elapsed nanoseconds").into());
    }
    Ok(elapsed)
}

fn calibrate<F>(mut time: F) -> GateResult<Calibration>
where
    F: FnMut(u64) -> GateResult<u64>,
{
    let mut iterations = 1_u64;
    let mut previous: Option<(u64, u64)> = None;
    loop {
        let elapsed_ns = time(iterations)?;
        if elapsed_ns >= CALIBRATION_TARGET_NS {
            return Ok(Calibration {
                iterations,
                elapsed_ns,
                previous_iterations: previous.map(|value| value.0),
                previous_elapsed_ns: previous.map(|value| value.1),
            });
        }
        previous = Some((iterations, elapsed_ns));
        iterations = iterations
            .checked_mul(2)
            .ok_or_else(|| invalid("calibration iteration count overflow"))?;
    }
}

fn portable_once<O: GateOperation>(
    program: &ValidatedProgram<O>,
    haystack: &[u8],
    window: SearchWindow,
    limits: ExecutionLimits,
) -> GateResult<O::Output>
where
    O::Output: Copy + Eq,
{
    Ok(program
        .execute(black_box(haystack), black_box(window), black_box(limits))
        .map_err(|error| invalid(format!("portable execution failed: {error}")))?
        .into_output())
}

fn native_once<O: GateOperation>(
    kernel: &PublishedKernel<O>,
    haystack: &[u8],
    window: SearchWindow,
) -> GateResult<O::Output>
where
    O::Output: Copy + Eq,
{
    Ok(kernel
        .search(black_box(haystack), black_box(window))
        .map_err(|error| invalid(format!("native execution failed: {error}")))?)
}

fn make_result_value(
    identity: Value,
    semantics: &Semantics<'_>,
    calibrations: &BTreeMap<&'static str, Calibration>,
    repetitions: &[Repetition],
) -> GateResult<Value> {
    let Value::Object(mut object) = identity else {
        return Err(invalid("serialized cell identity is not an object").into());
    };
    object.insert(
        "schema".to_owned(),
        Value::String("fre-search-v26-development-gate-cell-result-v1".to_owned()),
    );
    object.insert("semantics".to_owned(), serde_json::to_value(semantics)?);
    object.insert(
        "calibrations".to_owned(),
        serde_json::to_value(calibrations)?,
    );
    object.insert("repetitions".to_owned(), serde_json::to_value(repetitions)?);
    Ok(Value::Object(object))
}

fn make_preflight_value(identity: Value, semantics: &Semantics<'_>) -> GateResult<Value> {
    let Value::Object(mut object) = identity else {
        return Err(invalid("serialized preflight cell identity is not an object").into());
    };
    object.insert(
        "schema".to_owned(),
        Value::String("fre-search-v26-development-gate-preflight-cell-v1".to_owned()),
    );
    object.insert("semantics".to_owned(), serde_json::to_value(semantics)?);
    Ok(Value::Object(object))
}

struct TimingContext<'a, O: GateOperation>
where
    O::Output: Copy + Eq,
{
    program: &'a ValidatedProgram<O>,
    v17: &'a PublishedKernel<O>,
    v26: &'a PublishedKernel<O>,
    haystack: &'a [u8],
    window: SearchWindow,
    limits: ExecutionLimits,
    expected_output: O::Output,
}

impl<O: GateOperation> TimingContext<'_, O>
where
    O::Output: Copy + Eq,
{
    fn time(&self, engine: Engine, iterations: u64) -> GateResult<u64> {
        match engine {
            Engine::Portable => time_iterations(iterations, self.expected_output, || {
                portable_once(self.program, self.haystack, self.window, self.limits)
            }),
            Engine::V17 => time_iterations(iterations, self.expected_output, || {
                native_once(self.v17, self.haystack, self.window)
            }),
            Engine::V26 => time_iterations(iterations, self.expected_output, || {
                native_once(self.v26, self.haystack, self.window)
            }),
        }
    }
}

fn verify_manifest_line<T: Serialize>(
    cells_lines: &[&[u8]],
    cell_id: usize,
    expected_identity: &T,
) -> GateResult<()> {
    let observed = cells_lines
        .get(cell_id)
        .ok_or_else(|| invalid(format!("cell manifest lacks cell {cell_id}")))?;
    let mut expected = serde_json::to_vec(expected_identity)?;
    expected.push(b'\n');
    if *observed != expected {
        return Err(invalid(format!(
            "cell {cell_id} differs byte-for-byte from independent reconstruction"
        ))
        .into());
    }
    Ok(())
}

fn json_line<T: Serialize>(value: &T) -> GateResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

struct PreparedLiteral<O: GateOperation>
where
    O::Output: Copy + Eq,
{
    program: ValidatedProgram<O>,
    v17: PublishedKernel<O>,
    v26: PublishedKernel<O>,
}

fn prepare_literal<O: GateOperation>(literal: &SyntheticLiteral) -> GateResult<PreparedLiteral<O>>
where
    O::Output: Copy + Eq,
{
    let program = build_exact_literal::<O>(
        literal.literal(),
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .map_err(|error| invalid(format!("KIR construction failed: {error}")))?;
    let v17_image = fre_jit_aarch64::emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .map_err(|error| invalid(format!("V17 emission failed: {error}")))?;
    let v26_image = fre_jit_aarch64::emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV26,
        EmitLimits::default(),
    )
    .map_err(|error| invalid(format!("V26 emission failed: {error}")))?;
    let v17 = fre_jit_runtime::publish_audited::<O>(&v17_image, PublicationLimits::default())
        .map_err(|error| invalid(format!("V17 publication failed: {error}")))?;
    let v26 = fre_jit_runtime::publish_audited::<O>(&v26_image, PublicationLimits::default())
        .map_err(|error| invalid(format!("V26 publication failed: {error}")))?;
    Ok(PreparedLiteral { program, v17, v26 })
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete untimed semantic preflight remains adjacent for audit"
)]
fn preflight_literal<O: GateOperation>(
    writer: &mut BufWriter<File>,
    literal: &SyntheticLiteral,
    population_index: usize,
    cells_lines: &[&[u8]],
) -> GateResult<usize>
where
    O::Output: Copy + Eq,
{
    let prepared = prepare_literal::<O>(literal)?;
    let mut cells = 0_usize;
    for (shape_index, shape) in GateWindowShape::ALL.into_iter().enumerate() {
        let fixture = build_fixture(literal, shape)
            .map_err(|error| invalid(format!("fixture construction failed: {error}")))?;
        let cell_id = population_index
            .checked_mul(GateWindowShape::ALL.len())
            .and_then(|value| value.checked_add(shape_index))
            .ok_or_else(|| invalid("cell id overflow"))?;
        let identity = cell_record(cell_id, literal, &fixture)
            .map_err(|error| invalid(format!("cell identity failed: {error}")))?;
        verify_manifest_line(cells_lines, cell_id, &identity)?;
        let identity_value = serde_json::to_value(&identity)?;
        let window = SearchWindow::new(fixture.window_start, fixture.window_end);
        let portable_output = portable_once(
            &prepared.program,
            &fixture.haystack,
            window,
            ExecutionLimits::unlimited(),
        )?;
        let v17_output = native_once(&prepared.v17, &fixture.haystack, window)?;
        let v26_output = native_once(&prepared.v26, &fixture.haystack, window)?;
        if portable_output != v17_output || portable_output != v26_output {
            return Err(invalid(format!("cell {cell_id} exact semantics mismatch")).into());
        }
        let portable_digest = O::output_identity(portable_output)?;
        let v17_digest = O::output_identity(v17_output)?;
        let v26_digest = O::output_identity(v26_output)?;
        if portable_digest != identity.expected_output_sha256
            || v17_digest != identity.expected_output_sha256
            || v26_digest != identity.expected_output_sha256
        {
            return Err(invalid(format!(
                "cell {cell_id} output identity differs from absolute-coordinate expectation"
            ))
            .into());
        }
        let semantics = Semantics {
            equal: true,
            expected: &identity.expected_output_sha256,
            portable: &portable_digest,
            v17: &v17_digest,
            v26: &v26_digest,
        };
        let value = make_preflight_value(identity_value, &semantics)?;
        serde_json::to_writer(&mut *writer, &value)?;
        writer.write_all(b"\n")?;
        cells = cells
            .checked_add(1)
            .ok_or_else(|| invalid("preflight cell count overflow"))?;
    }
    Ok(cells)
}

#[allow(
    clippy::too_many_lines,
    reason = "the frozen per-cell semantics, calibration, and 12 orders stay adjacent for audit"
)]
fn time_literal<O: GateOperation>(
    writer: &mut BufWriter<File>,
    literal: &SyntheticLiteral,
    population_index: usize,
    cells_lines: &[&[u8]],
) -> GateResult<usize>
where
    O::Output: Copy + Eq,
{
    let prepared = prepare_literal::<O>(literal)?;
    let mut cells = 0_usize;
    for (shape_index, shape) in GateWindowShape::ALL.into_iter().enumerate() {
        let fixture = build_fixture(literal, shape)
            .map_err(|error| invalid(format!("fixture construction failed: {error}")))?;
        let cell_id = population_index
            .checked_mul(GateWindowShape::ALL.len())
            .and_then(|value| value.checked_add(shape_index))
            .ok_or_else(|| invalid("cell id overflow"))?;
        let identity = cell_record(cell_id, literal, &fixture)
            .map_err(|error| invalid(format!("cell identity failed: {error}")))?;
        verify_manifest_line(cells_lines, cell_id, &identity)?;
        let identity_value = serde_json::to_value(&identity)?;

        let semantics = Semantics {
            equal: true,
            expected: &identity.expected_output_sha256,
            portable: &identity.expected_output_sha256,
            v17: &identity.expected_output_sha256,
            v26: &identity.expected_output_sha256,
        };
        let window = SearchWindow::new(fixture.window_start, fixture.window_end);
        let context = TimingContext {
            program: &prepared.program,
            v17: &prepared.v17,
            v26: &prepared.v26,
            haystack: &fixture.haystack,
            window,
            limits: ExecutionLimits::unlimited(),
            expected_output: O::expected_output(&fixture),
        };
        let mut calibrations = BTreeMap::new();
        for engine in [Engine::Portable, Engine::V17, Engine::V26] {
            calibrations.insert(
                engine.name(),
                calibrate(|iterations| context.time(engine, iterations))?,
            );
        }
        let mut repetitions = Vec::with_capacity(ORDERS.len());
        for (repetition, order) in ORDERS.into_iter().enumerate() {
            let mut engines = BTreeMap::new();
            for engine in order {
                let calibration = calibrations
                    .get(engine.name())
                    .ok_or_else(|| invalid("calibration map is incomplete"))?;
                engines.insert(
                    engine.name(),
                    Sample {
                        elapsed_ns: context.time(engine, calibration.iterations)?,
                        iterations: calibration.iterations,
                    },
                );
            }
            repetitions.push(Repetition {
                ordinal: repetition,
                order,
                engines,
            });
        }
        let result = make_result_value(identity_value, &semantics, &calibrations, &repetitions)?;
        serde_json::to_writer(&mut *writer, &result)?;
        writer.write_all(b"\n")?;
        cells = cells
            .checked_add(1)
            .ok_or_else(|| invalid("shard cell count overflow"))?;
    }
    Ok(cells)
}

fn publish_result<F>(destination: &Path, write: F) -> GateResult<()>
where
    F: FnOnce(&mut BufWriter<File>) -> GateResult<()>,
{
    if destination.exists() {
        return Err(invalid(format!("result already exists: {}", destination.display())).into());
    }
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("result path has no UTF-8 file name"))?;
    let temporary =
        destination.with_file_name(format!(".{file_name}.partial.{}", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let write_result = (|| {
        let mut writer = BufWriter::new(file);
        write(&mut writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    let mut permissions = fs::metadata(&temporary)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&temporary, permissions)?;
    fs::hard_link(&temporary, destination)?;
    fs::remove_file(&temporary)?;
    let parent = destination
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Preflight,
    Timing,
}

struct Arguments {
    supervision_ready_fd: i32,
    phase: Phase,
    shard_id: u8,
    seal: PathBuf,
    contract: PathBuf,
    cells: PathBuf,
    run_manifest: PathBuf,
    consumed_marker: Option<PathBuf>,
    preflight_manifest: Option<PathBuf>,
    preflight_proofs: Vec<PathBuf>,
    output: PathBuf,
}

fn parse_args() -> GateResult<Arguments> {
    let mut arguments = env::args_os().skip(1);
    let mut supervision_ready_fd = None;
    let mut phase = None;
    let mut shard_id = None;
    let mut seal = None;
    let mut contract = None;
    let mut cells = None;
    let mut run_manifest = None;
    let mut consumed_marker = None;
    let mut preflight_manifest = None;
    let mut preflight_proofs = Vec::new();
    let mut output = None;
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid("every runner option requires one value"))?;
        match argument.to_str() {
            Some("--supervision-ready-fd") => {
                let parsed = value
                    .to_str()
                    .ok_or_else(|| invalid("supervision-ready FD is not UTF-8"))?
                    .parse::<i32>()?;
                if parsed < 0 {
                    return Err(invalid("supervision-ready FD must be nonnegative").into());
                }
                supervision_ready_fd = Some(parsed);
            }
            Some("--phase") => {
                phase = Some(match value.to_str() {
                    Some("preflight") => Phase::Preflight,
                    Some("timing") => Phase::Timing,
                    _ => return Err(invalid("phase must be preflight or timing").into()),
                });
            }
            Some("--shard-id") => {
                let parsed = value
                    .to_str()
                    .ok_or_else(|| invalid("shard ID is not UTF-8"))?
                    .parse::<u8>()?;
                shard_id = Some(parsed);
            }
            Some("--seal") => seal = Some(PathBuf::from(value)),
            Some("--contract") => contract = Some(PathBuf::from(value)),
            Some("--cells") => cells = Some(PathBuf::from(value)),
            Some("--run-manifest") => run_manifest = Some(PathBuf::from(value)),
            Some("--consumed-marker") => consumed_marker = Some(PathBuf::from(value)),
            Some("--preflight-manifest") => {
                preflight_manifest = Some(PathBuf::from(value));
            }
            Some("--preflight-proof") => preflight_proofs.push(PathBuf::from(value)),
            Some("--output") => output = Some(PathBuf::from(value)),
            _ => return Err(invalid("unknown runner option").into()),
        }
    }
    let phase = phase.ok_or_else(|| invalid("--phase is required"))?;
    match phase {
        Phase::Preflight
            if consumed_marker.is_some()
                || preflight_manifest.is_some()
                || !preflight_proofs.is_empty() =>
        {
            return Err(invalid("preflight phase forbids timing authority inputs").into());
        }
        Phase::Timing
            if consumed_marker.is_none()
                || preflight_manifest.is_none()
                || preflight_proofs.len() != 3 =>
        {
            return Err(invalid(
                "timing phase requires marker, manifest, and exactly three proofs",
            )
            .into());
        }
        _ => {}
    }
    Ok(Arguments {
        supervision_ready_fd: supervision_ready_fd
            .ok_or_else(|| invalid("--supervision-ready-fd is required"))?,
        phase,
        shard_id: shard_id.ok_or_else(|| invalid("--shard-id is required"))?,
        seal: seal.ok_or_else(|| invalid("--seal is required"))?,
        contract: contract.ok_or_else(|| invalid("--contract is required"))?,
        cells: cells.ok_or_else(|| invalid("--cells is required"))?,
        run_manifest: run_manifest.ok_or_else(|| invalid("--run-manifest is required"))?,
        consumed_marker,
        preflight_manifest,
        preflight_proofs,
        output: output.ok_or_else(|| invalid("--output is required"))?,
    })
}

fn await_pidfd_supervision(descriptor: i32) -> GateResult<()> {
    // Opening the inherited pipe through procfs duplicates it without unsafe
    // ownership conversion. This is the first action after argument parsing.
    let mut readiness = File::open(format!("/proc/self/fd/{descriptor}"))?;
    let mut marker = [0_u8; 2];
    let observed = readiness.read(&mut marker)?;
    if observed != 1 || marker[0] != 1 {
        return Err(invalid("launcher did not establish pidfd supervision").into());
    }
    if readiness.read(&mut marker[..1])? != 0 {
        return Err(invalid("supervision readiness pipe has trailing bytes").into());
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the one-shard identity closure remains linear and fail-closed"
)]
fn validate_authority(arguments: &Arguments) -> GateResult<Authority> {
    if arguments.shard_id > 2 {
        return Err(invalid("shard ID must be 0, 1, or 2").into());
    }
    let environment = env::vars().collect::<BTreeMap<_, _>>();
    if environment
        != BTreeMap::from([
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("TZ".to_owned(), "UTC".to_owned()),
        ])
    {
        return Err(invalid("runner environment is not the exact sealed allowlist").into());
    }
    for path in [
        &arguments.seal,
        &arguments.contract,
        &arguments.cells,
        &arguments.run_manifest,
    ] {
        require_read_only(path)?;
    }
    let seal_bytes = read_bounded(&arguments.seal, 256 * 1024)?;
    let contract_bytes = read_bounded(&arguments.contract, 256 * 1024)?;
    let cells_bytes = read_bounded(&arguments.cells, 64 * 1024 * 1024)?;
    let run_manifest_bytes = read_bounded(&arguments.run_manifest, 256 * 1024)?;
    let seal_sha256 = sha256_bytes(&seal_bytes);
    let contract_sha256 = sha256_bytes(&contract_bytes);
    let cells_sha256 = sha256_bytes(&cells_bytes);
    let run_manifest_sha256 = sha256_bytes(&run_manifest_bytes);
    let seal: Seal = parse_json(&seal_bytes, "one-shot seal")?;
    let run_manifest: RunManifest = parse_json(&run_manifest_bytes, "run manifest")?;
    if seal.schema != "fre-search-v26-development-gate-one-shot-seal-v1"
        || seal.status != "SEALED_READY_FOR_ONE_SHOT_TIMING"
        || seal.timing_runs != 1
        || run_manifest.schema != "fre-search-v26-development-gate-run-manifest-v1"
        || run_manifest.status != "SEALED_BEFORE_TIMING"
    {
        return Err(invalid("seal or run-manifest authority schema/status drifted").into());
    }
    if run_manifest.one_shot_seal_sha256 != seal_sha256
        || run_manifest.authorization_nonce != seal.authorization_nonce
        || run_manifest.source_commit != seal.source_commit
        || run_manifest.source_tree != seal.source_tree
        || run_manifest.source_archive_sha256 != seal.source_archive_sha256
        || run_manifest.runner_binary_sha256 != seal.runner_binary_sha256
        || run_manifest.runner_binary_bytes != seal.runner_binary_bytes
        || run_manifest.runner_build_identity_sha256 != seal.runner_build_identity_sha256
        || run_manifest.taskset_binary_sha256 != seal.taskset_binary_sha256
        || run_manifest.taskset_binary_bytes != seal.taskset_binary_bytes
        || run_manifest.contract_sha256 != seal.contract_sha256
        || run_manifest.cell_manifest_sha256 != seal.cell_manifest_sha256
        || contract_sha256 != seal.contract_sha256
        || cells_sha256 != seal.cell_manifest_sha256
    {
        return Err(invalid("seal/run/input identity closure failed").into());
    }
    if seal.taskset_path != "/usr/bin/taskset"
        || seal.runner_binary_bytes == 0
        || seal.taskset_binary_bytes == 0
    {
        return Err(invalid("sealed taskset path or executable sizes drifted").into());
    }
    for (value, length, name) in [
        (&seal.source_commit, 40, "source commit"),
        (&seal.source_tree, 40, "source tree"),
        (&seal.source_archive_sha256, 64, "source archive SHA-256"),
        (&seal.runner_binary_sha256, 64, "runner binary SHA-256"),
        (
            &seal.runner_build_identity_sha256,
            64,
            "runner build identity SHA-256",
        ),
        (&seal.taskset_binary_sha256, 64, "taskset binary SHA-256"),
        (&seal.contract_sha256, 64, "contract SHA-256"),
        (&seal.cell_manifest_sha256, 64, "cell manifest SHA-256"),
        (&seal.launcher_sha256, 64, "launcher SHA-256"),
        (&seal.analyzer_sha256, 64, "analyzer SHA-256"),
        (&seal.authorization_nonce, 64, "authorization nonce"),
        (&run_manifest.run_nonce, 64, "run nonce"),
        (
            &run_manifest.host_fingerprint_sha256,
            64,
            "host fingerprint",
        ),
    ] {
        require_lower_hex(value, length, name)?;
    }
    if run_manifest.cpu_ids.len() != 3
        || run_manifest.shard_cpu_map.len() != 3
        || run_manifest
            .cpu_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 3
    {
        return Err(invalid("run manifest does not bind three distinct CPUs").into());
    }
    require_nonce(&seal.authorization_nonce, "authorization nonce")?;
    require_nonce(&run_manifest.run_nonce, "run nonce")?;
    let mut nonce_set = std::collections::BTreeSet::from([
        seal.authorization_nonce.as_str(),
        run_manifest.run_nonce.as_str(),
    ]);
    for (expected_shard, mapping) in run_manifest.shard_cpu_map.iter().enumerate() {
        if usize::from(mapping.shard_id) != expected_shard
            || mapping.cpu_id != run_manifest.cpu_ids[expected_shard]
        {
            return Err(invalid("run manifest shard/CPU map drifted").into());
        }
        require_nonce(&mapping.shard_nonce, "shard nonce")?;
        nonce_set.insert(mapping.shard_nonce.as_str());
    }
    if nonce_set.len() != 5 {
        return Err(invalid("authorization, run, and shard nonces are not distinct").into());
    }
    let shard = &run_manifest.shard_cpu_map[usize::from(arguments.shard_id)];
    require_single_cpu_affinity(shard.cpu_id)?;
    let executable_bytes = read_live_executable(512 * 1024 * 1024)?;
    let executable_len = u64::try_from(executable_bytes.len())
        .map_err(|_| invalid("runner executable length exceeds u64"))?;
    if sha256_bytes(&executable_bytes) != seal.runner_binary_sha256
        || executable_len != seal.runner_binary_bytes
    {
        return Err(invalid("running executable differs from the sealed runner").into());
    }
    let identity = build_identity();
    let identity_bytes = build_identity_bytes()?;
    if sha256_bytes(&identity_bytes) != seal.runner_build_identity_sha256
        || identity.source_commit != seal.source_commit
        || identity.source_tree != seal.source_tree
        || identity.source_archive_sha256 != seal.source_archive_sha256
        || identity.target_triple != "aarch64-unknown-linux-gnu"
        || identity.profile != "release"
        || identity.opt_level != "3"
        || identity.debug != "false"
        || identity.crt_static != "true"
        || identity.crate_version != "0.1.0"
        || identity.candidate_backend != 39
        || identity.reference_backend != 30
    {
        return Err(invalid("embedded runner build identity differs from the seal").into());
    }
    for (value, name) in [
        (identity.rustc_identity_sha256, "embedded rustc identity"),
        (identity.cargo_identity_sha256, "embedded cargo identity"),
        (
            identity.runner_source_set_sha256,
            "embedded runner source-set identity",
        ),
        (
            identity.build_configuration_sha256,
            "embedded build-configuration identity",
        ),
    ] {
        require_lower_hex(value, 64, name)?;
    }
    let marker = BUILD_IDENTITY_MARKER.as_bytes();
    if executable_bytes
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count()
        != 1
    {
        return Err(invalid("runner executable lacks one exact embedded build marker").into());
    }
    if !cells_bytes.ends_with(b"\n") {
        return Err(invalid("cell manifest lacks a final newline").into());
    }
    let cells_lines = cells_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if cells_lines.len() != EXPECTED_CELL_COUNT {
        return Err(invalid(format!(
            "cell manifest has {} lines, expected {EXPECTED_CELL_COUNT}",
            cells_lines.len()
        ))
        .into());
    }
    let population = generate_population()
        .map_err(|error| invalid(format!("population generation failed: {error}")))?;
    if population.population_sha256_hex() != EXPECTED_POPULATION_SHA256 {
        return Err(invalid("synthetic population identity drifted").into());
    }
    Ok(Authority {
        seal,
        run_manifest,
        seal_sha256,
        contract_sha256,
        cells_sha256,
        run_manifest_sha256,
        cells_bytes,
        population,
    })
}

struct Authority {
    seal: Seal,
    run_manifest: RunManifest,
    seal_sha256: String,
    contract_sha256: String,
    cells_sha256: String,
    run_manifest_sha256: String,
    cells_bytes: Vec<u8>,
    population: fre_search_v26_synthetic_runner::SyntheticPopulation,
}

fn run_preflight(arguments: &Arguments, authority: &Authority) -> GateResult<()> {
    let seal = &authority.seal;
    let run_manifest = &authority.run_manifest;
    let shard = &run_manifest.shard_cpu_map[usize::from(arguments.shard_id)];
    let cells_lines = authority
        .cells_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let header = PreflightHeader {
        schema: "fre-search-v26-development-gate-preflight-header-v1",
        shard_id: arguments.shard_id,
        candidate_backend: 39,
        reference_backend: 30,
        source_commit: &seal.source_commit,
        source_tree: &seal.source_tree,
        source_archive_sha256: &seal.source_archive_sha256,
        runner_binary_sha256: &seal.runner_binary_sha256,
        runner_binary_bytes: seal.runner_binary_bytes,
        runner_build_identity_sha256: &seal.runner_build_identity_sha256,
        taskset_binary_sha256: &seal.taskset_binary_sha256,
        taskset_binary_bytes: seal.taskset_binary_bytes,
        contract_sha256: &authority.contract_sha256,
        cell_manifest_sha256: &authority.cells_sha256,
        host_fingerprint_sha256: &run_manifest.host_fingerprint_sha256,
        cpu_id: shard.cpu_id,
        shard_nonce: &shard.shard_nonce,
        run_nonce: &run_manifest.run_nonce,
        one_shot_seal_sha256: &authority.seal_sha256,
        run_manifest_sha256: &authority.run_manifest_sha256,
    };
    publish_result(&arguments.output, |writer| {
        serde_json::to_writer(&mut *writer, &header)?;
        writer.write_all(b"\n")?;
        let mut shard_cells = 0_usize;
        for (population_index, literal) in authority.population.literals().iter().enumerate() {
            if shard_for_width(literal.width) != Some(arguments.shard_id) {
                continue;
            }
            let added = match literal.output {
                SyntheticOutput::Exists => {
                    preflight_literal::<Exists>(writer, literal, population_index, &cells_lines)?
                }
                SyntheticOutput::Span => {
                    preflight_literal::<Span>(writer, literal, population_index, &cells_lines)?
                }
                SyntheticOutput::SelectedEnd => preflight_literal::<SelectedEnd>(
                    writer,
                    literal,
                    population_index,
                    &cells_lines,
                )?,
            };
            shard_cells = shard_cells
                .checked_add(added)
                .ok_or_else(|| invalid("preflight shard cell count overflow"))?;
        }
        if shard_cells != EXPECTED_SHARD_CELLS {
            return Err(invalid(format!(
                "preflight shard emitted {shard_cells} cells, expected {EXPECTED_SHARD_CELLS}"
            ))
            .into());
        }
        let footer = PreflightFooter {
            schema: "fre-search-v26-development-gate-preflight-footer-v1",
            shard_id: arguments.shard_id,
            cells: shard_cells,
            semantic_comparisons: shard_cells
                .checked_mul(3)
                .ok_or_else(|| invalid("semantic comparison count overflow"))?,
            complete: true,
            shard_nonce: &shard.shard_nonce,
            run_nonce: &run_manifest.run_nonce,
        };
        serde_json::to_writer(&mut *writer, &footer)?;
        writer.write_all(b"\n")?;
        Ok(())
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "all three proof and one-shot phase-boundary bindings remain adjacent for audit"
)]
fn verify_preflight_authority(
    arguments: &Arguments,
    authority: &Authority,
) -> GateResult<(String, String)> {
    let manifest_path = arguments
        .preflight_manifest
        .as_ref()
        .ok_or_else(|| invalid("timing phase lacks preflight manifest"))?;
    let marker_path = arguments
        .consumed_marker
        .as_ref()
        .ok_or_else(|| invalid("timing phase lacks consumption marker"))?;
    require_read_only(manifest_path)?;
    require_read_only(marker_path)?;
    let manifest_bytes = read_bounded(manifest_path, 256 * 1024)?;
    let marker_bytes = read_bounded(marker_path, 256 * 1024)?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let marker_sha256 = sha256_bytes(&marker_bytes);
    let manifest: PreflightManifest = parse_json(&manifest_bytes, "preflight manifest")?;
    let marker: ConsumedMarker = parse_json(&marker_bytes, "one-shot consumption marker")?;
    let seal = &authority.seal;
    let run_manifest = &authority.run_manifest;
    if manifest.schema != "fre-search-v26-development-gate-preflight-manifest-v1"
        || manifest.status != "COMPLETE_BEFORE_TIMING"
        || !manifest.complete
        || manifest.cells != EXPECTED_CELL_COUNT
        || manifest.semantic_comparisons != EXPECTED_CELL_COUNT * 3
        || manifest.one_shot_seal_sha256 != authority.seal_sha256
        || manifest.run_manifest_sha256 != authority.run_manifest_sha256
        || manifest.source_commit != seal.source_commit
        || manifest.source_tree != seal.source_tree
        || manifest.source_archive_sha256 != seal.source_archive_sha256
        || manifest.runner_binary_sha256 != seal.runner_binary_sha256
        || manifest.runner_binary_bytes != seal.runner_binary_bytes
        || manifest.runner_build_identity_sha256 != seal.runner_build_identity_sha256
        || manifest.taskset_binary_sha256 != seal.taskset_binary_sha256
        || manifest.taskset_binary_bytes != seal.taskset_binary_bytes
        || manifest.contract_sha256 != authority.contract_sha256
        || manifest.cell_manifest_sha256 != authority.cells_sha256
        || manifest.host_fingerprint_sha256 != run_manifest.host_fingerprint_sha256
        || manifest.run_nonce != run_manifest.run_nonce
        || manifest.proofs.len() != 3
    {
        return Err(invalid("preflight manifest identity/closure failed").into());
    }
    let shard = &run_manifest.shard_cpu_map[usize::from(arguments.shard_id)];
    for (shard_id, (entry, proof_path)) in manifest
        .proofs
        .iter()
        .zip(&arguments.preflight_proofs)
        .enumerate()
    {
        require_read_only(proof_path)?;
        let proof_bytes = read_bounded(proof_path, 64 * 1024 * 1024)?;
        let expected_mapping = &run_manifest.shard_cpu_map[shard_id];
        if usize::from(entry.shard_id) != shard_id
            || entry.cpu_id != expected_mapping.cpu_id
            || entry.shard_nonce != expected_mapping.shard_nonce
            || entry.sha256 != sha256_bytes(&proof_bytes)
            || entry.bytes
                != u64::try_from(proof_bytes.len())
                    .map_err(|_| invalid("preflight proof length exceeds u64"))?
            || entry.cells != EXPECTED_SHARD_CELLS
        {
            return Err(invalid(format!("preflight proof {shard_id} identity failed")).into());
        }
        let lines = proof_bytes
            .split_inclusive(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        if lines.len() != EXPECTED_SHARD_CELLS + 2
            || lines.iter().any(|line| !line.ends_with(b"\n"))
        {
            return Err(invalid(format!("preflight proof {shard_id} closure failed")).into());
        }
        let expected_header = PreflightHeader {
            schema: "fre-search-v26-development-gate-preflight-header-v1",
            shard_id: u8::try_from(shard_id)
                .map_err(|_| invalid("preflight shard ID exceeds u8"))?,
            candidate_backend: 39,
            reference_backend: 30,
            source_commit: &seal.source_commit,
            source_tree: &seal.source_tree,
            source_archive_sha256: &seal.source_archive_sha256,
            runner_binary_sha256: &seal.runner_binary_sha256,
            runner_binary_bytes: seal.runner_binary_bytes,
            runner_build_identity_sha256: &seal.runner_build_identity_sha256,
            taskset_binary_sha256: &seal.taskset_binary_sha256,
            taskset_binary_bytes: seal.taskset_binary_bytes,
            contract_sha256: &authority.contract_sha256,
            cell_manifest_sha256: &authority.cells_sha256,
            host_fingerprint_sha256: &run_manifest.host_fingerprint_sha256,
            cpu_id: expected_mapping.cpu_id,
            shard_nonce: &expected_mapping.shard_nonce,
            run_nonce: &run_manifest.run_nonce,
            one_shot_seal_sha256: &authority.seal_sha256,
            run_manifest_sha256: &authority.run_manifest_sha256,
        };
        let expected_footer = PreflightFooter {
            schema: "fre-search-v26-development-gate-preflight-footer-v1",
            shard_id: expected_header.shard_id,
            cells: EXPECTED_SHARD_CELLS,
            semantic_comparisons: EXPECTED_SHARD_CELLS * 3,
            complete: true,
            shard_nonce: &expected_mapping.shard_nonce,
            run_nonce: &run_manifest.run_nonce,
        };
        if lines[0] != json_line(&expected_header)?
            || *lines
                .last()
                .ok_or_else(|| invalid("preflight proof unexpectedly has no lines"))?
                != json_line(&expected_footer)?
        {
            return Err(invalid(format!(
                "preflight proof {shard_id} header/footer binding failed"
            ))
            .into());
        }
    }
    if marker.schema != "fre-search-v26-development-gate-consumed-seal-v1"
        || marker.one_shot_seal_sha256 != authority.seal_sha256
        || marker.authorization_nonce != seal.authorization_nonce
        || marker.run_manifest_sha256 != authority.run_manifest_sha256
        || marker.run_nonce != run_manifest.run_nonce
        || marker.preflight_manifest_sha256 != manifest_sha256
    {
        return Err(invalid("one-shot consumption marker identity closure failed").into());
    }
    let registry = Path::new(&seal.one_shot_registry);
    let expected_marker = registry.join(format!("{}.consumed-v1.json", authority.seal_sha256));
    if fs::canonicalize(registry)? != registry
        || fs::canonicalize(marker_path)? != expected_marker
        || shard.cpu_id != run_manifest.cpu_ids[usize::from(arguments.shard_id)]
    {
        return Err(invalid("one-shot marker registry or shard binding drifted").into());
    }
    Ok((manifest_sha256, marker_sha256))
}

fn run_timing(arguments: &Arguments, authority: &Authority) -> GateResult<()> {
    let (preflight_manifest_sha256, consumed_marker_sha256) =
        verify_preflight_authority(arguments, authority)?;
    let seal = &authority.seal;
    let run_manifest = &authority.run_manifest;
    let shard = &run_manifest.shard_cpu_map[usize::from(arguments.shard_id)];
    let cells_lines = authority
        .cells_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let header = ShardHeader {
        schema: "fre-search-v26-development-gate-shard-header-v1",
        shard_id: arguments.shard_id,
        candidate_backend: 39,
        reference_backend: 30,
        source_commit: &seal.source_commit,
        source_tree: &seal.source_tree,
        source_archive_sha256: &seal.source_archive_sha256,
        runner_binary_sha256: &seal.runner_binary_sha256,
        runner_binary_bytes: seal.runner_binary_bytes,
        runner_build_identity_sha256: &seal.runner_build_identity_sha256,
        taskset_binary_sha256: &seal.taskset_binary_sha256,
        taskset_binary_bytes: seal.taskset_binary_bytes,
        contract_sha256: &authority.contract_sha256,
        cell_manifest_sha256: &authority.cells_sha256,
        host_fingerprint_sha256: &run_manifest.host_fingerprint_sha256,
        cpu_id: shard.cpu_id,
        shard_nonce: &shard.shard_nonce,
        run_nonce: &run_manifest.run_nonce,
        one_shot_seal_sha256: &authority.seal_sha256,
        one_shot_consumption_sha256: &consumed_marker_sha256,
        preflight_manifest_sha256: &preflight_manifest_sha256,
        run_manifest_sha256: &authority.run_manifest_sha256,
    };
    publish_result(&arguments.output, |writer| {
        serde_json::to_writer(&mut *writer, &header)?;
        writer.write_all(b"\n")?;
        let mut shard_cells = 0_usize;
        for (population_index, literal) in authority.population.literals().iter().enumerate() {
            if shard_for_width(literal.width) != Some(arguments.shard_id) {
                continue;
            }
            let added = match literal.output {
                SyntheticOutput::Exists => {
                    time_literal::<Exists>(writer, literal, population_index, &cells_lines)?
                }
                SyntheticOutput::Span => {
                    time_literal::<Span>(writer, literal, population_index, &cells_lines)?
                }
                SyntheticOutput::SelectedEnd => {
                    time_literal::<SelectedEnd>(writer, literal, population_index, &cells_lines)?
                }
            };
            shard_cells = shard_cells
                .checked_add(added)
                .ok_or_else(|| invalid("shard cell count overflow"))?;
        }
        if shard_cells != EXPECTED_SHARD_CELLS {
            return Err(invalid(format!(
                "shard emitted {shard_cells} cells, expected {EXPECTED_SHARD_CELLS}"
            ))
            .into());
        }
        let footer = ShardFooter {
            schema: "fre-search-v26-development-gate-shard-footer-v1",
            shard_id: arguments.shard_id,
            cells: shard_cells,
            complete: true,
            shard_nonce: &shard.shard_nonce,
            run_nonce: &run_manifest.run_nonce,
        };
        serde_json::to_writer(&mut *writer, &footer)?;
        writer.write_all(b"\n")?;
        Ok(())
    })
}

fn run(arguments: &Arguments) -> GateResult<()> {
    let authority = validate_authority(arguments)?;
    match arguments.phase {
        Phase::Preflight => run_preflight(arguments, &authority),
        Phase::Timing => run_timing(arguments, &authority),
    }
}

fn main() -> GateResult<()> {
    if env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--build-identity")])
    {
        io::stdout().lock().write_all(&build_identity_bytes()?)?;
        return Ok(());
    }
    let arguments = parse_args()?;
    await_pidfd_supervision(arguments.supervision_ready_fd)?;
    run(&arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_orders_are_six_permutations_twice() {
        assert_eq!(ORDERS.len(), 12);
        for index in 0..6 {
            assert_eq!(
                ORDERS[index].map(Engine::name),
                ORDERS[index + 6].map(Engine::name)
            );
        }
    }

    #[test]
    fn build_identity_handshake_is_present_and_unsealed_tests_are_obvious() {
        let identity = build_identity();
        assert_eq!(
            identity.schema,
            "fre-search-v26-development-gate-runner-build-identity-v1"
        );
        assert_eq!(identity.candidate_backend, 39);
        assert_eq!(identity.reference_backend, 30);
        assert!(BUILD_IDENTITY_MARKER.starts_with("FRE-V26-RUNNER-BUILD-IDENTITY-V1|"));
        if identity.source_commit == "UNSEALED" {
            assert_eq!(identity.source_tree, "UNSEALED");
            assert_eq!(identity.source_archive_sha256, "UNSEALED");
        }
    }

    #[test]
    fn calibration_doubles_and_retains_terminal_predecessor() {
        let calibration = calibrate(|iterations| Ok(iterations * 1_000_000)).expect("calibration");
        assert_eq!(calibration.iterations, 4);
        assert_eq!(calibration.elapsed_ns, 4_000_000);
        assert_eq!(calibration.previous_iterations, Some(2));
        assert_eq!(calibration.previous_elapsed_ns, Some(2_000_000));
    }

    #[test]
    fn one_iteration_calibration_has_no_predecessor() {
        let calibration = calibrate(|_| Ok(4_000_000)).expect("calibration");
        assert_eq!(calibration.iterations, 1);
        assert_eq!(calibration.previous_iterations, None);
        assert_eq!(calibration.previous_elapsed_ns, None);
    }

    #[test]
    fn absolute_output_identities_do_not_rebase_nonzero_windows() {
        let absolute = <Span as GateOperation>::output_identity(Some(MatchSpan::new(32, 38)))
            .expect("absolute");
        let relative =
            <Span as GateOperation>::output_identity(Some(MatchSpan::new(0, 6))).expect("relative");
        assert_ne!(absolute, relative);
        let absolute_end =
            <SelectedEnd as GateOperation>::output_identity(Some(38)).expect("absolute end");
        let relative_end =
            <SelectedEnd as GateOperation>::output_identity(Some(6)).expect("relative end");
        assert_ne!(absolute_end, relative_end);
        assert_ne!(
            <Exists as GateOperation>::output_identity(true).expect("exists true"),
            <Exists as GateOperation>::output_identity(false).expect("exists false")
        );
    }

    #[test]
    fn timed_batch_rejects_a_wrong_terminal_result_after_the_bracket() {
        let mut call = 0_u64;
        let error = time_iterations(4, 7, || {
            call += 1;
            Ok(if call == 4 { 8 } else { 7 })
        })
        .expect_err("wrong terminal result");
        assert!(error.to_string().contains("post-batch result"));
    }

    #[test]
    fn first_cell_manifest_line_is_byte_exact_reconstruction() {
        let population = generate_population().expect("population");
        let literal = &population.literals()[0];
        let fixture = build_fixture(literal, GateWindowShape::NoMatch).expect("fixture");
        let identity = cell_record(0, literal, &fixture).expect("identity");
        let mut line = serde_json::to_vec(&identity).expect("line");
        line.push(b'\n');
        verify_manifest_line(&[&line], 0, &identity).expect("byte exact");
    }
}
