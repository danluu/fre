#![cfg_attr(
    not(all(
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    )),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(
    target_arch = "aarch64",
    target_pointer_width = "64",
    target_endian = "little",
    any(target_os = "linux", target_os = "macos")
)))]
compile_error!(
    "the optimizing Count-v3 Rebar runner requires little-endian AArch64 Linux or macOS"
);

#[cfg(all(feature = "qualification-private", feature = "production"))]
compile_error!("exactly one Count-v3 build-authority feature must be selected");

#[cfg(not(any(feature = "qualification-private", feature = "production")))]
compile_error!("one Count-v3 build-authority feature must be selected");

#[cfg(any(
    all(fre_count_v3_neon, fre_count_v3_sve),
    all(fre_count_v3_neon, fre_count_v3_sve2),
    all(fre_count_v3_sve, fre_count_v3_sve2),
))]
compile_error!("exactly one optimizing Count-v3 ISA cfg must be selected");

#[cfg(not(any(fre_count_v3_neon, fre_count_v3_sve, fre_count_v3_sve2)))]
compile_error!("the optimizing Count-v3 build script did not select an ISA cfg");

use std::{
    env,
    error::Error,
    fmt,
    fs::{self, File},
    hint::black_box,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(all(
    feature = "qualification-private",
    any(fre_count_v3_sve, fre_count_v3_sve2)
))]
use std::num::NonZeroU64;

#[cfg(all(feature = "qualification-private", fre_count_v3_neon))]
use fre::AggregateCountExactLiteralAotQualificationV3;
#[cfg(all(
    feature = "qualification-private",
    any(fre_count_v3_sve, fre_count_v3_sve2)
))]
use fre::AggregateCountExactLiteralAotSveQualificationV3;
#[cfg(all(feature = "production", any(fre_count_v3_sve, fre_count_v3_sve2)))]
use fre::AggregateCountExactLiteralAotSveV3;
#[cfg(all(feature = "production", fre_count_v3_neon))]
use fre::AggregateCountExactLiteralAotV3;
#[cfg(feature = "production")]
use fre::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MIN_HAYSTACK_BYTES_V3, AggregateCountExactLiteralAotRouteV3,
};
use fre::{
    AggregateBuildLimits, AggregateBuilder, AggregateCountRegex, AggregatePlanKind,
    AggregatePlanSelection, AggregateRunLimits, AggregateStrategy, LiteralAggregateReduceLimits,
    RustProfile,
};
use fre_aot_static_runtime::StaticCountVerifyErrorV3;
#[cfg(all(feature = "production", fre_count_v3_neon))]
use fre_aot_static_runtime::VerifiedStaticCountV3;
#[cfg(all(feature = "qualification-private", fre_count_v3_neon))]
use fre_aot_static_runtime::{
    StaticCountQualificationFacadeBindingV3, VerifiedStaticCountQualificationV3,
};
#[cfg(all(feature = "production", any(fre_count_v3_sve, fre_count_v3_sve2)))]
use fre_aot_static_runtime::{StaticCountSveFacadeBindingV3, VerifiedStaticCountSveV3};
#[cfg(all(
    feature = "qualification-private",
    any(fre_count_v3_sve, fre_count_v3_sve2)
))]
use fre_aot_static_runtime::{
    StaticCountSveQualificationFacadeBindingV3, VerifiedStaticCountSveQualificationV3,
    configure_current_thread_sve_vl16_for_count_v3_qualification,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(feature = "qualification-private")]
const REQUEST_SCHEMA: &str = "fre.optimizing-count-v3.runner-request.v1";
#[cfg(feature = "production")]
const REQUEST_SCHEMA: &str = "fre.optimizing-count-v3.production-confirmation-runner-request.v1";
#[cfg(feature = "qualification-private")]
const OBSERVATION_SCHEMA: &str = "fre.optimizing-count-v3.measurement-observation.v1";
#[cfg(feature = "production")]
const OBSERVATION_SCHEMA: &str = "fre.optimizing-count-v3.production-confirmation-observation.v1";
#[cfg(feature = "qualification-private")]
const RESULT_DOMAIN: &[u8] = b"fre.optimizing-count-v3.result.v1\0";
#[cfg(feature = "production")]
const RESULT_DOMAIN: &[u8] = b"fre.optimizing-count-v3.production-confirmation.result.v1\0";
#[cfg(feature = "qualification-private")]
const WORK_DOMAIN: &[u8] = b"fre.optimizing-count-v3.work.v1\0";
#[cfg(feature = "production")]
const WORK_DOMAIN: &[u8] = b"fre.optimizing-count-v3.production-confirmation.work.v1\0";
const BUILD_AUTHORITY_BINDING_DOMAIN: &[u8] =
    b"FRE-OPTIMIZING-COUNT-V3-BUILD-AUTHORITY-BINDING\0\x01";
const MAX_REQUEST_BYTES: u64 = 4_096;
const MAX_EXECUTABLE_BYTES: usize = 512 * 1_048_576;
const MAX_ARTIFACT_BYTES: usize = 64 * 1_048_576;

#[cfg(feature = "qualification-private")]
const COMPILED_BUILD_AUTHORITY: &str = "qualification-private";
#[cfg(feature = "production")]
const COMPILED_BUILD_AUTHORITY: &str = "production";
#[cfg(feature = "qualification-private")]
const COMPILED_REGISTRY_SCHEMA: &str = "fre.optimizing-count-v3.compiled-artifact-registry.v2";
#[cfg(feature = "production")]
const COMPILED_REGISTRY_SCHEMA: &str =
    "fre.optimizing-count-v3.production-confirmation-artifact-registry.v1";
#[cfg(feature = "qualification-private")]
const COMPILED_PRODUCTION_AUTHORITY: &str = "absent";
#[cfg(feature = "production")]
const COMPILED_PRODUCTION_AUTHORITY: &str = "source-reviewed-tuples-required";
#[cfg(feature = "qualification-private")]
const COMPILED_QUALIFICATION_AUTHORITY: &str = "private-only";
#[cfg(feature = "production")]
const COMPILED_QUALIFICATION_AUTHORITY: &str = "absent";

#[cfg(fre_count_v3_neon)]
const COMPILED_REQUIRED_ISA: &str = "neon";
#[cfg(fre_count_v3_sve)]
const COMPILED_REQUIRED_ISA: &str = "sve-vl16";
#[cfg(fre_count_v3_sve2)]
const COMPILED_REQUIRED_ISA: &str = "sve2-vl16";
#[cfg(fre_count_v3_neon)]
const COMPILED_REQUIRED_ISA_ID: u64 = 1;
#[cfg(fre_count_v3_sve)]
const COMPILED_REQUIRED_ISA_ID: u64 = 2;
#[cfg(fre_count_v3_sve2)]
const COMPILED_REQUIRED_ISA_ID: u64 = 3;
#[cfg(fre_count_v3_neon)]
const COMPILED_REGISTER_PLAN_ID: u64 = 1;
#[cfg(fre_count_v3_sve)]
const COMPILED_REGISTER_PLAN_ID: u64 = 4;
#[cfg(fre_count_v3_sve2)]
const COMPILED_REGISTER_PLAN_ID: u64 = 5;
#[cfg(fre_count_v3_neon)]
const COMPILED_FEATURES: u64 = 1;
#[cfg(fre_count_v3_sve)]
const COMPILED_FEATURES: u64 = 3;
#[cfg(fre_count_v3_sve2)]
const COMPILED_FEATURES: u64 = 7;
#[cfg(fre_count_v3_neon)]
const COMPILED_SVE_VECTOR_BYTES: u64 = 0;
#[cfg(any(fre_count_v3_sve, fre_count_v3_sve2))]
const COMPILED_SVE_VECTOR_BYTES: u64 = 16;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct RawCountResult {
    value: u64,
}

#[allow(
    unsafe_code,
    reason = "the type describes the separately audited raw Count-v2 control ABI"
)]
type RawCountEntry = unsafe extern "C" fn(*const u8, usize, *mut RawCountResult) -> u64;

#[cfg(all(feature = "qualification-private", fre_count_v3_neon))]
type V3AdoptFn =
    for<'binding> fn(
        StaticCountQualificationFacadeBindingV3<'binding>,
    ) -> Result<VerifiedStaticCountQualificationV3, StaticCountVerifyErrorV3>;

#[cfg(all(
    feature = "qualification-private",
    any(fre_count_v3_sve, fre_count_v3_sve2)
))]
type V3AdoptFn =
    for<'binding> fn(
        StaticCountSveQualificationFacadeBindingV3<'binding>,
    )
        -> Result<VerifiedStaticCountSveQualificationV3, StaticCountVerifyErrorV3>;

#[cfg(all(feature = "production", fre_count_v3_neon))]
type V3AdoptFn = fn() -> Result<VerifiedStaticCountV3, StaticCountVerifyErrorV3>;

#[cfg(all(feature = "production", any(fre_count_v3_sve, fre_count_v3_sve2)))]
type V3AdoptFn = for<'binding> fn(
    StaticCountSveFacadeBindingV3<'binding>,
) -> Result<VerifiedStaticCountSveV3, StaticCountVerifyErrorV3>;

#[derive(Clone, Copy, Debug)]
struct ArtifactDescriptor {
    pattern_input_id: &'static str,
    pattern_sha256: &'static str,
    transformed_pattern: &'static str,
    unicode: bool,
    literal_hex: &'static str,
    semantic_binding_identity: &'static str,
    planning_receipt_identity: &'static str,
    portable_artifact_id: &'static str,
    portable_artifact_file_path: &'static str,
    portable_artifact_file_sha256: &'static str,
    v2_artifact_id: &'static str,
    v2_artifact_file_path: &'static str,
    v2_artifact_file_sha256: &'static str,
    v3_artifact_id: &'static str,
    v3_artifact_file_path: &'static str,
    v3_artifact_file_sha256: &'static str,
    v2_entry: RawCountEntry,
    v3_adopt: V3AdoptFn,
}

#[derive(Clone, Copy, Debug)]
struct CellDescriptor {
    cell_id: &'static str,
    artifact_index: usize,
    input_sha256: &'static str,
    input_bytes: usize,
    expected_count: u64,
    oracle_receipt_sha256: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunKind {
    Correctness,
    Measure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Engine {
    PortableCurrent,
    CountV2Current,
    CountV3Aot,
}

impl Engine {
    fn parse(value: &str) -> Result<Self, RunnerError> {
        match value {
            "portable-current" => Ok(Self::PortableCurrent),
            "count-v2-current" => Ok(Self::CountV2Current),
            "count-v3-aot" => Ok(Self::CountV3Aot),
            _ => Err(RunnerError::new("unknown engine label")),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::PortableCurrent => "portable-current",
            Self::CountV2Current => "count-v2-current",
            Self::CountV3Aot => "count-v3-aot",
        }
    }

    const fn artifact_id(self, artifact: &ArtifactDescriptor) -> &'static str {
        match self {
            Self::PortableCurrent => artifact.portable_artifact_id,
            Self::CountV2Current => artifact.v2_artifact_id,
            Self::CountV3Aot => artifact.v3_artifact_id,
        }
    }

    const fn artifact_file(self, artifact: &ArtifactDescriptor) -> (&'static str, &'static str) {
        match self {
            Self::PortableCurrent => (
                artifact.portable_artifact_file_path,
                artifact.portable_artifact_file_sha256,
            ),
            Self::CountV2Current => (
                artifact.v2_artifact_file_path,
                artifact.v2_artifact_file_sha256,
            ),
            Self::CountV3Aot => (
                artifact.v3_artifact_file_path,
                artifact.v3_artifact_file_sha256,
            ),
        }
    }
}

#[derive(Debug)]
struct Invocation {
    kind: RunKind,
    cell_id: String,
    engine: Engine,
    iterations: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunnerRequest {
    process_nonce: String,
    schema: String,
    target_id: String,
}

#[derive(Debug, Serialize)]
struct Observation<'a> {
    schema: &'static str,
    request_sha256: &'a str,
    process_nonce: &'a str,
    target_id: &'static str,
    cell_id: &'static str,
    engine: &'static str,
    engine_binary_sha256: &'a str,
    artifact_id: &'static str,
    iterations: u64,
    searched_bytes: u64,
    elapsed_ns: u64,
    result_count: u64,
    result_checksum: &'a str,
    work_checksum: &'a str,
    status: &'static str,
}

#[cfg(feature = "production")]
#[derive(Debug, Serialize)]
struct ProductionAuthorization<'a> {
    artifact_id: &'static str,
    build_authority: &'static str,
    cell_id: &'static str,
    process_nonce: &'a str,
    schema: &'static str,
    target_id: &'static str,
}

#[derive(Debug)]
struct RunnerError(String);

impl RunnerError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for RunnerError {}

fn main() {
    if let Err(error) = run() {
        eprintln!("optimizing Count-v3 Rebar runner refused: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), RunnerError> {
    validate_embedded_isa()?;
    validate_embedded_tables()?;
    if sha256_hex(BUILD_REGISTRY_JSON.as_bytes()) != BUILD_REGISTRY_SHA256 {
        return Err(RunnerError::new(
            "embedded artifact registry bytes differ from their build digest",
        ));
    }
    validate_embedded_authority()?;
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        return Err(usage());
    };
    let command = command
        .into_string()
        .map_err(|_| RunnerError::new("command is not UTF-8"))?;
    if command == "inventory" {
        if arguments.next().is_some() {
            return Err(usage());
        }
        let mut output = BUILD_REGISTRY_JSON.as_bytes().to_vec();
        output.push(b'\n');
        io::stdout()
            .lock()
            .write_all(&output)
            .map_err(|error| RunnerError::new(format!("write inventory: {error}")))?;
        return Ok(());
    }
    #[cfg(feature = "production")]
    if command == "authorize" {
        return run_production_authorization(arguments);
    }
    let invocation = parse_invocation(command, arguments)?;
    let request_bytes = read_request()?;
    let request: RunnerRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| RunnerError::new(format!("decode canonical runner request: {error}")))?;
    validate_request(&request, &request_bytes)?;

    let cell = find_cell(&invocation.cell_id)?;
    let artifact = ARTIFACTS
        .get(cell.artifact_index)
        .ok_or_else(|| RunnerError::new("cell artifact index escaped the embedded table"))?;
    let haystack = load_haystack(cell)?;
    let executable_sha256 = executable_sha256()?;
    authenticate_selected_artifact(invocation.engine, artifact)?;
    let request_sha256 = sha256_hex(&request_bytes);
    let searched_bytes = u64::try_from(haystack.len())
        .ok()
        .and_then(|bytes| bytes.checked_mul(invocation.iterations))
        .ok_or_else(|| RunnerError::new("searched-byte accounting overflow"))?;

    let elapsed_ns = execute_engine(
        invocation.kind,
        invocation.engine,
        artifact,
        cell,
        &haystack,
        invocation.iterations,
    )?;
    let result_checksum = result_checksum(cell);
    let work_checksum = work_checksum(&result_checksum, invocation.iterations, searched_bytes);
    let observation = Observation {
        schema: OBSERVATION_SCHEMA,
        request_sha256: &request_sha256,
        process_nonce: &request.process_nonce,
        target_id: EMBEDDED_TARGET_ID,
        cell_id: cell.cell_id,
        engine: invocation.engine.name(),
        engine_binary_sha256: &executable_sha256,
        artifact_id: invocation.engine.artifact_id(artifact),
        iterations: invocation.iterations,
        searched_bytes,
        elapsed_ns,
        result_count: cell.expected_count,
        result_checksum: &result_checksum,
        work_checksum: &work_checksum,
        status: "pass",
    };
    let mut output = serde_json::to_vec(&observation)
        .map_err(|error| RunnerError::new(format!("serialize observation: {error}")))?;
    output.push(b'\n');
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|error| RunnerError::new(format!("write observation: {error}")))
}

#[cfg(feature = "production")]
fn run_production_authorization(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), RunnerError> {
    let cell_id = utf8_argument(arguments.next(), "cell ID")?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    let request_bytes = read_request()?;
    let request: RunnerRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| RunnerError::new(format!("decode canonical runner request: {error}")))?;
    validate_request(&request, &request_bytes)?;
    let cell = find_cell(&cell_id)?;
    let artifact = ARTIFACTS
        .get(cell.artifact_index)
        .ok_or_else(|| RunnerError::new("cell artifact index escaped the embedded table"))?;
    authenticate_selected_artifact(Engine::CountV3Aot, artifact)?;
    authorize_count_v3(artifact)?;
    let authorization = ProductionAuthorization {
        artifact_id: artifact.v3_artifact_id,
        build_authority: COMPILED_BUILD_AUTHORITY,
        cell_id: cell.cell_id,
        process_nonce: &request.process_nonce,
        schema: "fre.optimizing-count-v3.production-authorization.v1",
        target_id: EMBEDDED_TARGET_ID,
    };
    let mut output = serde_json::to_vec(&authorization).map_err(|error| {
        RunnerError::new(format!("serialize production authorization: {error}"))
    })?;
    output.push(b'\n');
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|error| RunnerError::new(format!("write production authorization: {error}")))
}

#[cfg(feature = "qualification-private")]
fn usage() -> RunnerError {
    RunnerError::new(
        "usage: fre-optimizing-count-v3-rebar inventory | \
         (correctness|measure) CELL_ID ENGINE ITERATIONS",
    )
}

#[cfg(feature = "production")]
fn usage() -> RunnerError {
    RunnerError::new(
        "usage: fre-optimizing-count-v3-rebar inventory | authorize CELL_ID | \
         (correctness|measure) CELL_ID ENGINE ITERATIONS",
    )
}

fn parse_invocation(
    command: String,
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Invocation, RunnerError> {
    let kind = match command.as_str() {
        "correctness" => RunKind::Correctness,
        "measure" => RunKind::Measure,
        _ => return Err(usage()),
    };
    let cell_id = utf8_argument(arguments.next(), "cell ID")?;
    let engine = Engine::parse(&utf8_argument(arguments.next(), "engine")?)?;
    let iterations_text = utf8_argument(arguments.next(), "iterations")?;
    if arguments.next().is_some()
        || iterations_text.is_empty()
        || iterations_text.starts_with('0')
        || !iterations_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(usage());
    }
    let iterations = iterations_text
        .parse::<u64>()
        .map_err(|_| RunnerError::new("iterations do not fit u64"))?;
    if iterations == 0 || iterations.to_string() != iterations_text {
        return Err(RunnerError::new(
            "iterations are not canonical positive decimal",
        ));
    }
    if kind == RunKind::Correctness && iterations != 1 {
        return Err(RunnerError::new(
            "correctness invocation requires exactly one iteration",
        ));
    }
    Ok(Invocation {
        kind,
        cell_id,
        engine,
        iterations,
    })
}

fn utf8_argument(value: Option<std::ffi::OsString>, label: &str) -> Result<String, RunnerError> {
    value
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| RunnerError::new(format!("{label} is not UTF-8")))
}

fn read_request() -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RunnerError::new(format!("read runner request: {error}")))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
        return Err(RunnerError::new(
            "runner request byte length is outside the closed bound",
        ));
    }
    Ok(bytes)
}

fn validate_request(request: &RunnerRequest, bytes: &[u8]) -> Result<(), RunnerError> {
    if request.schema != REQUEST_SCHEMA {
        return Err(RunnerError::new("unexpected runner request schema"));
    }
    if request.target_id != EMBEDDED_TARGET_ID {
        return Err(RunnerError::new(
            "runner request target differs from embedded build target",
        ));
    }
    require_lower_hex_64(&request.process_nonce, "process nonce")?;
    let canonical = serde_json::to_vec(request)
        .map_err(|error| RunnerError::new(format!("re-encode runner request: {error}")))?;
    if canonical != bytes {
        return Err(RunnerError::new(
            "runner request is not exact sorted compact JSON without trailing bytes",
        ));
    }
    Ok(())
}

fn validate_embedded_isa() -> Result<(), RunnerError> {
    if EMBEDDED_REQUIRED_ISA != COMPILED_REQUIRED_ISA {
        return Err(RunnerError::new(
            "generated required ISA differs from the exact compiler cfg",
        ));
    }
    Ok(())
}

fn validate_embedded_authority() -> Result<(), RunnerError> {
    if EMBEDDED_BUILD_AUTHORITY != COMPILED_BUILD_AUTHORITY {
        return Err(RunnerError::new(
            "generated build authority differs from the exact Cargo feature",
        ));
    }
    require_lower_hex_64(
        BUILD_AUTHORITY_REGISTRY_BINDING_SHA256,
        "build-authority registry binding",
    )?;
    if build_authority_binding_sha256(EMBEDDED_BUILD_AUTHORITY, BUILD_REGISTRY_SHA256)
        != BUILD_AUTHORITY_REGISTRY_BINDING_SHA256
    {
        return Err(RunnerError::new(
            "embedded build authority is not bound to the embedded registry digest",
        ));
    }
    let registry: Value = serde_json::from_str(BUILD_REGISTRY_JSON)
        .map_err(|error| RunnerError::new(format!("decode embedded registry: {error}")))?;
    let object = registry
        .as_object()
        .ok_or_else(|| RunnerError::new("embedded registry is not an object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(COMPILED_REGISTRY_SCHEMA)
        || object.get("production_authority").and_then(Value::as_str)
            != Some(COMPILED_PRODUCTION_AUTHORITY)
        || object
            .get("qualification_authority")
            .and_then(Value::as_str)
            != Some(COMPILED_QUALIFICATION_AUTHORITY)
    {
        return Err(RunnerError::new(
            "embedded registry authority markers differ from the compiled mode",
        ));
    }
    #[cfg(feature = "qualification-private")]
    if [
        "build_authority",
        "cells",
        "promotion_authority_source_sha256",
        "promotion_manifest_sha256",
        "promotion_proposal_sha256",
    ]
    .iter()
    .any(|field| object.contains_key(*field))
    {
        return Err(RunnerError::new(
            "qualification registry unexpectedly gained production-only authority fields",
        ));
    }
    #[cfg(feature = "production")]
    {
        if object.get("build_authority").and_then(Value::as_str) != Some(COMPILED_BUILD_AUTHORITY) {
            return Err(RunnerError::new(
                "production registry lacks its exact build-authority field",
            ));
        }
        for (field, label) in [
            (
                "promotion_authority_source_sha256",
                "promotion authority source SHA-256",
            ),
            ("promotion_manifest_sha256", "promotion manifest SHA-256"),
            ("promotion_proposal_sha256", "promotion proposal SHA-256"),
        ] {
            let value = object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| RunnerError::new(format!("production registry lacks {label}")))?;
            require_lower_hex_64(value, label)?;
        }
    }

    let patterns = object
        .get("compiled_patterns")
        .and_then(Value::as_array)
        .ok_or_else(|| RunnerError::new("embedded registry lacks compiled patterns"))?;
    let mut v3_rows = 0_usize;
    for pattern in patterns {
        let engines = pattern
            .get("engines")
            .and_then(Value::as_array)
            .ok_or_else(|| RunnerError::new("embedded pattern lacks engine rows"))?;
        for engine in engines {
            if engine.get("engine").and_then(Value::as_str) == Some("count-v3-aot") {
                v3_rows = v3_rows
                    .checked_add(1)
                    .ok_or_else(|| RunnerError::new("Count-v3 registry row count overflow"))?;
                if engine.get("runtime_authority").and_then(Value::as_str)
                    != Some(COMPILED_BUILD_AUTHORITY)
                {
                    return Err(RunnerError::new(
                        "Count-v3 registry row has the wrong runtime authority",
                    ));
                }
                validate_embedded_count_v3_target(engine)?;
            }
        }
    }
    if v3_rows != ARTIFACTS.len() {
        return Err(RunnerError::new(
            "Count-v3 registry authority rows differ from the linked artifact table",
        ));
    }
    Ok(())
}

fn validate_embedded_count_v3_target(engine: &Value) -> Result<(), RunnerError> {
    let tuple = engine
        .get("general_eligibility_tuple")
        .and_then(Value::as_object)
        .ok_or_else(|| RunnerError::new("Count-v3 registry row lacks its eligibility tuple"))?;
    let field = |name: &str| {
        tuple
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| RunnerError::new(format!("Count-v3 tuple lacks integer {name}")))
    };
    if field("required_isa_id")? != COMPILED_REQUIRED_ISA_ID
        || field("register_plan_id")? != COMPILED_REGISTER_PLAN_ID
        || field("actual_features")? != COMPILED_FEATURES
        || field("allowed_features")? != COMPILED_FEATURES
        || field("candidate_block_starts")? != 16
        || field("vector_bytes")? != 16
        || field("sve_vector_length_bytes")? != COMPILED_SVE_VECTOR_BYTES
    {
        return Err(RunnerError::new(
            "Count-v3 registry tuple differs from the compiled mixed register/feature plan",
        ));
    }
    Ok(())
}

fn validate_embedded_tables() -> Result<(), RunnerError> {
    if CELLS.is_empty() || ARTIFACTS.is_empty() {
        return Err(RunnerError::new("embedded inventory tables are empty"));
    }
    if CELLS
        .windows(2)
        .any(|pair| pair[0].cell_id >= pair[1].cell_id)
    {
        return Err(RunnerError::new(
            "embedded cells are not in canonical unique cell-ID order",
        ));
    }
    if ARTIFACTS
        .windows(2)
        .any(|pair| pair[0].pattern_input_id >= pair[1].pattern_input_id)
    {
        return Err(RunnerError::new(
            "embedded artifacts are not in canonical unique pattern-input order",
        ));
    }
    for cell in CELLS {
        if cell.artifact_index >= ARTIFACTS.len() {
            return Err(RunnerError::new(
                "embedded cell has an out-of-range artifact index",
            ));
        }
        #[cfg(feature = "production")]
        if cell.input_bytes < AGGREGATE_COUNT_EXACT_LITERAL_AOT_MIN_HAYSTACK_BYTES_V3 {
            return Err(RunnerError::new(
                "production confirmation cell is below the evidence-backed AOT route floor",
            ));
        }
    }
    for artifact in ARTIFACTS {
        for (label, value) in [
            ("portable artifact ID", artifact.portable_artifact_id),
            (
                "portable artifact SHA-256",
                artifact.portable_artifact_file_sha256,
            ),
            ("Count-v2 artifact ID", artifact.v2_artifact_id),
            (
                "Count-v2 artifact SHA-256",
                artifact.v2_artifact_file_sha256,
            ),
            ("Count-v3 artifact ID", artifact.v3_artifact_id),
            (
                "Count-v3 artifact SHA-256",
                artifact.v3_artifact_file_sha256,
            ),
        ] {
            require_lower_hex_64(value, label)?;
        }
    }
    Ok(())
}

fn find_cell(cell_id: &str) -> Result<&'static CellDescriptor, RunnerError> {
    CELLS
        .binary_search_by_key(&cell_id, |cell| cell.cell_id)
        .ok()
        .and_then(|index| CELLS.get(index))
        .ok_or_else(|| RunnerError::new("cell ID is absent from the frozen inventory"))
}

fn load_haystack(cell: &CellDescriptor) -> Result<Vec<u8>, RunnerError> {
    require_lower_hex_64(cell.input_sha256, "embedded input SHA-256")?;
    let root = env::var_os("FRE_COUNT_V3_HAYSTACK_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| RunnerError::new("FRE_COUNT_V3_HAYSTACK_DIR is required"))?;
    if !root.is_absolute() {
        return Err(RunnerError::new(
            "FRE_COUNT_V3_HAYSTACK_DIR must be absolute",
        ));
    }
    let root_before = fs::symlink_metadata(&root)
        .map_err(|error| RunnerError::new(format!("stat haystack directory: {error}")))?;
    if root_before.file_type().is_symlink() || !root_before.is_dir() {
        return Err(RunnerError::new(
            "haystack directory is not a real directory",
        ));
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|error| RunnerError::new(format!("canonicalize haystack directory: {error}")))?;
    let path = canonical_root.join(cell.input_sha256);
    if path.parent() != Some(canonical_root.as_path())
        || path.file_name().and_then(|name| name.to_str()) != Some(cell.input_sha256)
    {
        return Err(RunnerError::new(
            "content-addressed haystack path escaped its directory",
        ));
    }
    let bytes = read_stable_regular(&path, cell.input_bytes, Some(cell.input_bytes), false)?;
    if sha256_hex(&bytes) != cell.input_sha256 {
        return Err(RunnerError::new(
            "haystack digest differs from the frozen inventory",
        ));
    }
    let root_after = fs::symlink_metadata(&canonical_root)
        .map_err(|error| RunnerError::new(format!("restat haystack directory: {error}")))?;
    if root_after.file_type().is_symlink()
        || !root_after.is_dir()
        || root_after.dev() != root_before.dev()
        || root_after.ino() != root_before.ino()
    {
        return Err(RunnerError::new(
            "haystack directory changed during authentication",
        ));
    }
    Ok(bytes)
}

fn executable_sha256() -> Result<String, RunnerError> {
    let executable = env::current_exe()
        .map_err(|error| RunnerError::new(format!("resolve current executable: {error}")))?;
    let bytes = read_stable_regular(&executable, MAX_EXECUTABLE_BYTES, None, false)?;
    Ok(sha256_hex(&bytes))
}

fn authenticate_selected_artifact(
    engine: Engine,
    artifact: &ArtifactDescriptor,
) -> Result<(), RunnerError> {
    let (path_text, expected_sha256) = engine.artifact_file(artifact);
    require_lower_hex_64(expected_sha256, "selected artifact SHA-256")?;
    let path = Path::new(path_text);
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_sha256)
    {
        return Err(RunnerError::new(
            "selected artifact is not at its absolute content-addressed path",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| RunnerError::new("selected artifact lacks a parent directory"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| RunnerError::new(format!("stat artifact root: {error}")))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(RunnerError::new(
            "selected artifact root is not a real directory",
        ));
    }
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| RunnerError::new(format!("canonicalize artifact root: {error}")))?;
    if canonical_parent != parent {
        return Err(RunnerError::new(
            "selected artifact root is not a normalized canonical path",
        ));
    }
    let bytes = read_stable_regular(path, MAX_ARTIFACT_BYTES, None, true)?;
    if sha256_hex(&bytes) != expected_sha256 {
        return Err(RunnerError::new(
            "selected engine artifact digest differs from the build registry",
        ));
    }
    let parent_after = fs::symlink_metadata(parent)
        .map_err(|error| RunnerError::new(format!("restat artifact root: {error}")))?;
    if parent_after.file_type().is_symlink()
        || !parent_after.is_dir()
        || parent_after.dev() != parent_metadata.dev()
        || parent_after.ino() != parent_metadata.ino()
    {
        return Err(RunnerError::new(
            "selected artifact root changed during authentication",
        ));
    }
    Ok(())
}

fn read_stable_regular(
    path: &Path,
    maximum: usize,
    exact_bytes: Option<usize>,
    require_read_only: bool,
) -> Result<Vec<u8>, RunnerError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::new(format!("stat {}: {error}", path.display())))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || require_read_only && before.mode() & 0o222 != 0
        || before.len() == 0
        || before.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
        || exact_bytes
            .is_some_and(|expected| before.len() != u64::try_from(expected).unwrap_or(u64::MAX))
    {
        return Err(RunnerError::new(format!(
            "{} is not an admissible bounded single-link regular file",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| RunnerError::new(format!("open {}: {error}", path.display())))?;
    let opened = file
        .metadata()
        .map_err(|error| RunnerError::new(format!("fstat {}: {error}", path.display())))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.nlink() != 1
    {
        return Err(RunnerError::new(format!(
            "{} changed while opening",
            path.display()
        )));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| RunnerError::new("regular file length does not fit usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| RunnerError::new(format!("read {}: {error}", path.display())))?;
    let after = file
        .metadata()
        .map_err(|error| RunnerError::new(format!("refstat {}: {error}", path.display())))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::new(format!("restat {}: {error}", path.display())))?;
    if bytes.len() != capacity
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.nlink() != 1
        || require_read_only && after.mode() & 0o222 != 0
        || after.mtime() != opened.mtime()
        || after.mtime_nsec() != opened.mtime_nsec()
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.dev() != opened.dev()
        || path_after.ino() != opened.ino()
        || path_after.len() != opened.len()
        || path_after.nlink() != 1
        || require_read_only && path_after.mode() & 0o222 != 0
    {
        return Err(RunnerError::new(format!(
            "{} changed while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn execute_engine(
    kind: RunKind,
    engine: Engine,
    artifact: &ArtifactDescriptor,
    cell: &CellDescriptor,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    match engine {
        Engine::PortableCurrent => {
            execute_portable(kind, artifact, cell.expected_count, haystack, iterations)
        }
        Engine::CountV2Current => {
            execute_count_v2(kind, artifact, cell.expected_count, haystack, iterations)
        }
        Engine::CountV3Aot => {
            execute_count_v3(kind, artifact, cell.expected_count, haystack, iterations)
        }
    }
}

#[cfg(all(feature = "production", fre_count_v3_neon))]
fn authorize_count_v3(artifact: &ArtifactDescriptor) -> Result<(), RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let verified = (artifact.v3_adopt)().map_err(|error| {
        RunnerError::new(format!(
            "source authority refused production NEON Count-v3 object: {error}"
        ))
    })?;
    let _facade = AggregateCountExactLiteralAotV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind production NEON facade: {error}")))?;
    Ok(())
}

#[cfg(all(feature = "production", any(fre_count_v3_sve, fre_count_v3_sve2)))]
fn authorize_count_v3(artifact: &ArtifactDescriptor) -> Result<(), RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let binding = AggregateCountExactLiteralAotSveV3::adoption_binding(&owner)
        .map_err(|error| RunnerError::new(format!("project production SVE binding: {error}")))?;
    let verified = (artifact.v3_adopt)(binding).map_err(|error| {
        RunnerError::new(format!(
            "source authority refused production SVE Count-v3 object: {error}"
        ))
    })?;
    let _facade = AggregateCountExactLiteralAotSveV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind production SVE facade: {error}")))?;
    Ok(())
}

fn execute_portable(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let portable = build_portable_owner(artifact)?;
    let limits = run_limits();
    let first = portable
        .count_value(black_box(haystack), &limits)
        .map_err(|error| RunnerError::new(format!("portable oracle call failed: {error}")))?;
    require_expected(first, expected, "portable-current")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }
    measure_safe_values(iterations, expected, || {
        portable.count_value(black_box(haystack), &limits)
    })
}

#[allow(
    unsafe_code,
    reason = "only the explicitly type-disjoint Count-v2 control is invoked through its audited raw ABI"
)]
fn execute_count_v2(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let mut first_result = RawCountResult { value: u64::MAX };
    // SAFETY: the build linked the freshly emitted Count-v2 object for this
    // descriptor and its fixed three-argument ABI.
    let first_status = unsafe {
        (artifact.v2_entry)(
            haystack.as_ptr(),
            haystack.len(),
            core::ptr::addr_of_mut!(first_result),
        )
    };
    if first_status != 0 {
        return Err(RunnerError::new(format!(
            "count-v2-current oracle call returned status {first_status}"
        )));
    }
    require_expected(first_result.value, expected, "count-v2-current")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }

    let start = Instant::now();
    let mut checksum = 0_u64;
    let mut status_or = 0_u64;
    for _ in 0..iterations {
        let mut result = RawCountResult { value: u64::MAX };
        // SAFETY: identical fixed linked ABI contract to the verified call
        // above; the result slot is fresh and writable for each invocation.
        let status = unsafe {
            (artifact.v2_entry)(
                black_box(haystack.as_ptr()),
                black_box(haystack.len()),
                core::ptr::addr_of_mut!(result),
            )
        };
        status_or |= status;
        checksum = checksum.wrapping_add(black_box(result.value));
    }
    let elapsed = elapsed_ns(start)?;
    if status_or != 0 {
        return Err(RunnerError::new(format!(
            "count-v2-current timed calls returned status mask {status_or}"
        )));
    }
    require_timed_checksum(checksum, expected, iterations, "count-v2-current")?;
    Ok(elapsed)
}

#[cfg(all(feature = "qualification-private", fre_count_v3_neon))]
fn execute_count_v3(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let binding = AggregateCountExactLiteralAotQualificationV3::adoption_binding(&owner)
        .map_err(|error| RunnerError::new(format!("project NEON facade binding: {error}")))?;
    let verified = (artifact.v3_adopt)(binding)
        .map_err(|error| RunnerError::new(format!("adopt NEON Count-v3 object: {error}")))?;
    let facade = AggregateCountExactLiteralAotQualificationV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind NEON Count-v3 facade: {error}")))?;
    let limits = run_limits();
    let first = facade
        .count_value(black_box(haystack), &limits)
        .map_err(|error| RunnerError::new(format!("NEON Count-v3 oracle call failed: {error}")))?;
    require_expected(first, expected, "count-v3-aot")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }
    measure_safe_values(iterations, expected, || {
        facade.count_value(black_box(haystack), &limits)
    })
}

#[cfg(all(
    feature = "qualification-private",
    any(fre_count_v3_sve, fre_count_v3_sve2)
))]
fn execute_count_v3(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let configured = configure_current_thread_sve_vl16_for_count_v3_qualification()
        .map_err(|error| RunnerError::new(format!("configure current-thread SVE VL16: {error}")))?;
    if configured != 16 {
        return Err(RunnerError::new(
            "SVE qualification configuration did not read back VL16",
        ));
    }
    let binding = AggregateCountExactLiteralAotSveQualificationV3::adoption_binding(&owner)
        .map_err(|error| RunnerError::new(format!("project SVE facade binding: {error}")))?;
    let verified = (artifact.v3_adopt)(binding)
        .map_err(|error| RunnerError::new(format!("adopt SVE Count-v3 object: {error}")))?;
    let facade = AggregateCountExactLiteralAotSveQualificationV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind SVE Count-v3 facade: {error}")))?;
    let session = facade
        .begin_current_thread_session()
        .map_err(|error| RunnerError::new(format!("open SVE Count-v3 session: {error}")))?;
    let limits = run_limits();
    let first = session
        .count_value(black_box(haystack), &limits)
        .map_err(|error| RunnerError::new(format!("SVE Count-v3 oracle call failed: {error}")))?;
    require_expected(first, expected, "count-v3-aot")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }
    let iterations = NonZeroU64::new(iterations)
        .ok_or_else(|| RunnerError::new("SVE repeated measurement requires nonzero iterations"))?;
    let start = Instant::now();
    let checksum = session
        .count_value_repeated(black_box(haystack), &limits, iterations)
        .map_err(|error| {
            RunnerError::new(format!(
                "SVE Count-v3 closed repeated measurement failed: {error}"
            ))
        })?;
    let elapsed = elapsed_ns(start)?;
    require_timed_checksum(
        black_box(checksum),
        expected,
        iterations.get(),
        "SVE Count-v3 closed repeated measurement",
    )?;
    Ok(elapsed)
}

#[cfg(all(feature = "production", fre_count_v3_neon))]
fn execute_count_v3(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let verified = (artifact.v3_adopt)().map_err(|error| {
        RunnerError::new(format!(
            "adopt source-authorized production NEON Count-v3 object: {error}"
        ))
    })?;
    let facade = AggregateCountExactLiteralAotV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind production NEON facade: {error}")))?;
    if facade.route_for_haystack_bytes(haystack.len())
        != AggregateCountExactLiteralAotRouteV3::AsimdAot
    {
        return Err(RunnerError::new(
            "production NEON confirmation refused a non-ASIMD route",
        ));
    }
    let limits = run_limits();
    let first = facade
        .count_value_with_route(black_box(haystack), &limits)
        .map_err(|error| {
            RunnerError::new(format!(
                "production NEON Count-v3 oracle call failed: {error}"
            ))
        })?;
    if first.route() != AggregateCountExactLiteralAotRouteV3::AsimdAot {
        return Err(RunnerError::new(
            "production NEON confirmation executed a non-ASIMD route",
        ));
    }
    require_expected(first.value(), expected, "count-v3-aot")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }
    measure_safe_values(iterations, expected, || {
        facade.count_value(black_box(haystack), &limits)
    })
}

#[cfg(all(feature = "production", any(fre_count_v3_sve, fre_count_v3_sve2)))]
fn execute_count_v3(
    kind: RunKind,
    artifact: &ArtifactDescriptor,
    expected: u64,
    haystack: &[u8],
    iterations: u64,
) -> Result<u64, RunnerError> {
    let owner = build_fixed_owner(artifact)?;
    let binding = AggregateCountExactLiteralAotSveV3::adoption_binding(&owner)
        .map_err(|error| RunnerError::new(format!("project production SVE binding: {error}")))?;
    let verified = (artifact.v3_adopt)(binding).map_err(|error| {
        RunnerError::new(format!(
            "adopt source-authorized production SVE Count-v3 object: {error}"
        ))
    })?;
    let facade = AggregateCountExactLiteralAotSveV3::bind(&owner, &verified)
        .map_err(|error| RunnerError::new(format!("bind production SVE facade: {error}")))?;
    if facade.route_for_haystack_bytes(haystack.len())
        != AggregateCountExactLiteralAotRouteV3::SveAot
    {
        return Err(RunnerError::new(
            "production SVE confirmation refused a non-SVE route",
        ));
    }
    let session = facade
        .begin_current_thread_session()
        .map_err(|error| RunnerError::new(format!("open production SVE session: {error}")))?;
    let limits = run_limits();
    let first = session
        .count_value_with_route(black_box(haystack), &limits)
        .map_err(|error| {
            RunnerError::new(format!(
                "production SVE Count-v3 oracle call failed: {error}"
            ))
        })?;
    if first.route() != AggregateCountExactLiteralAotRouteV3::SveAot {
        return Err(RunnerError::new(
            "production SVE confirmation executed a non-SVE route",
        ));
    }
    require_expected(first.value(), expected, "count-v3-aot")?;
    if kind == RunKind::Correctness {
        return Ok(0);
    }
    measure_safe_values(iterations, expected, || {
        session.count_value(black_box(haystack), &limits)
    })
}

fn build_portable_owner(artifact: &ArtifactDescriptor) -> Result<AggregateCountRegex, RunnerError> {
    let owner = AggregateBuilder::new(artifact.transformed_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(artifact.unicode)
        .case_insensitive(false)
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| {
            RunnerError::new(format!(
                "build portable owner for {}: {error}",
                artifact.pattern_input_id
            ))
        })?;
    if owner.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err(RunnerError::new(format!(
            "portable owner for {}/{} left the ExactLiteral route",
            artifact.pattern_input_id, artifact.pattern_sha256
        )));
    }
    Ok(owner)
}

fn build_fixed_owner(artifact: &ArtifactDescriptor) -> Result<AggregateCountRegex, RunnerError> {
    let owner = AggregateBuilder::new(artifact.transformed_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(artifact.unicode)
        .case_insensitive(false)
        .limits(AggregateBuildLimits::aot_count_exact_literal_v1())
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| {
            RunnerError::new(format!(
                "build fixed AOT owner for {}: {error}",
                artifact.pattern_input_id
            ))
        })?;
    let candidate = owner
        .exact_literal_aot_planned_candidate()
        .ok_or_else(|| RunnerError::new("fixed AOT owner lacks its planned candidate"))?;
    if hex(candidate.literal()) != artifact.literal_hex
        || hex(candidate.semantic_binding_identity().as_bytes())
            != artifact.semantic_binding_identity
        || hex(candidate.planning_receipt_identity().as_bytes())
            != artifact.planning_receipt_identity
    {
        return Err(RunnerError::new(format!(
            "fixed AOT owner identities differ for {}/{}",
            artifact.pattern_input_id, artifact.pattern_sha256
        )));
    }
    Ok(owner)
}

fn run_limits() -> AggregateRunLimits {
    AggregateRunLimits {
        exact_literal: LiteralAggregateReduceLimits::unlimited(),
        ..AggregateRunLimits::default()
    }
}

fn measure_safe_values<F, E>(
    iterations: u64,
    expected: u64,
    mut call: F,
) -> Result<u64, RunnerError>
where
    F: FnMut() -> Result<u64, E>,
    E: fmt::Display,
{
    let start = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..iterations {
        let value = call()
            .map_err(|error| RunnerError::new(format!("timed safe value call failed: {error}")))?;
        checksum = checksum.wrapping_add(black_box(value));
    }
    let elapsed = elapsed_ns(start)?;
    require_timed_checksum(checksum, expected, iterations, "safe value engine")?;
    Ok(elapsed)
}

fn elapsed_ns(start: Instant) -> Result<u64, RunnerError> {
    u64::try_from(start.elapsed().as_nanos())
        .map_err(|_| RunnerError::new("elapsed nanoseconds do not fit u64"))
}

fn require_expected(actual: u64, expected: u64, engine: &str) -> Result<(), RunnerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RunnerError::new(format!(
            "{engine} result {actual} differs from oracle {expected}"
        )))
    }
}

fn require_timed_checksum(
    actual: u64,
    expected_value: u64,
    iterations: u64,
    engine: &str,
) -> Result<(), RunnerError> {
    let expected = expected_value.wrapping_mul(iterations);
    if actual == expected {
        Ok(())
    } else {
        Err(RunnerError::new(format!(
            "{engine} timed checksum {actual} differs from {expected}"
        )))
    }
}

fn result_checksum(cell: &CellDescriptor) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RESULT_DOMAIN);
    hasher.update(cell.cell_id.as_bytes());
    hasher.update([0]);
    hasher.update(cell.expected_count.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(cell.oracle_receipt_sha256.as_bytes());
    hex(&hasher.finalize())
}

fn work_checksum(result_checksum: &str, iterations: u64, searched_bytes: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WORK_DOMAIN);
    hasher.update(result_checksum.as_bytes());
    hasher.update([0]);
    hasher.update(iterations.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(searched_bytes.to_string().as_bytes());
    hex(&hasher.finalize())
}

fn require_lower_hex_64(value: &str, label: &str) -> Result<(), RunnerError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RunnerError::new(format!(
            "{label} is not canonical lowercase SHA-256 hex"
        )))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn build_authority_binding_sha256(authority: &str, registry_sha256: &str) -> String {
    let authority_bytes = u64::try_from(authority.len())
        .expect("build authority length is statically bounded")
        .to_le_bytes();
    let registry_bytes = u64::try_from(registry_sha256.len())
        .expect("registry digest text length is statically bounded")
        .to_le_bytes();
    let mut hasher = Sha256::new();
    hasher.update(BUILD_AUTHORITY_BINDING_DOMAIN);
    hasher.update(authority_bytes);
    hasher.update(authority.as_bytes());
    hasher.update(registry_bytes);
    hasher.update(registry_sha256.as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
