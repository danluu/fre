//! Frozen, deterministic non-Rebar holdout qualification for FRE.
//!
//! The committed suite is visible, not secret. Authentication freezes its
//! exact bytes and the output of the specified deterministic generators. The
//! correctness report is deterministic and excludes clocks. Optional timing
//! diagnostics use a different schema and file so they cannot affect semantic
//! status or suite authentication.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    hint::black_box,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    time::Instant,
};

use fre::{
    BuildError, BuildLimits, PlanKind, PortableBuilder, PortableRegex, SearchAccounting,
    SearchError, SearchLimits,
};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stable deterministic correctness-report schema.
pub const REPORT_SCHEMA: &str = "fre.holdout.correctness.v1";
/// Stable non-normative timing-diagnostic schema.
pub const PERFORMANCE_SCHEMA: &str = "fre.holdout.performance.v4";
/// Stable committed suite schema.
pub const SUITE_SCHEMA: &str = "fre.holdout.suite.v1";
/// Stable digest sidecar schema.
pub const DIGEST_SCHEMA: &str = "fre.holdout.digests.v1";
/// Canonical architecture-independent expanded-record framing.
pub const EXPANDED_FRAMING: &str = "fre.holdout.expanded-inputs.v2";
/// Exact semantic oracle version.
pub const RUST_REGEX_VERSION: &str = "1.12.4";

const MAX_CASE_SPECS: usize = 1_024;
const MAX_INPUT_VARIANTS: usize = 100_000;
const MAX_INPUT_BYTES: usize = 8 * 1_048_576;
const MAX_TOTAL_INPUT_BYTES: usize = 256 * 1_048_576;

/// Paths needed for an authenticated run.
#[derive(Clone, Debug)]
pub struct RunConfig {
    pub suite: PathBuf,
    pub schema: PathBuf,
    pub digests: PathBuf,
    pub correctness_output: PathBuf,
    pub performance_output: Option<PathBuf>,
}

/// One declared qualification dimension, including intentionally absent work.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DimensionDeclaration {
    pub id: String,
    pub status: DimensionStatus,
    pub detail: String,
}

/// Honest state of a declared dimension.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DimensionStatus {
    Covered,
    Partial,
    Unsupported,
    Future,
    RuntimeRequired,
}

/// Timing policy stored with the frozen suite but excluded from correctness.
/// Operation timing interprets each count as repetitions per expanded input;
/// build timing interprets it as repetitions per case pattern.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TimingPolicy {
    pub warmup_iterations: usize,
    pub measured_iterations: usize,
}

/// Frozen suite manifest.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SuiteManifest {
    pub schema: String,
    pub suite_id: String,
    pub freeze_date: String,
    pub oracle: OracleDeclaration,
    pub timing: TimingPolicy,
    pub dimensions: Vec<DimensionDeclaration>,
    pub cases: Vec<CaseSpec>,
}

/// Exact semantic oracle declaration.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OracleDeclaration {
    pub implementation: String,
    pub version: String,
    pub api: String,
    pub unicode: bool,
}

/// One pattern and a deterministic family of changing haystacks.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    pub id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub pattern: String,
    pub generator: GeneratorSpec,
}

/// Frozen deterministic input generator specifications.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GeneratorSpec {
    Explicit {
        inputs: Vec<ExplicitInput>,
    },
    SeededBytes {
        seed: String,
        alphabet_hex: String,
        lengths: Vec<usize>,
        variants_per_length: usize,
        injection: Option<InjectionSpec>,
    },
    RepeatedByte {
        prefix_hex: String,
        byte_hex: String,
        lengths: Vec<usize>,
        suffix_hex: String,
        intent: String,
    },
}

/// One exact input encoded without JSON's text restrictions.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExplicitInput {
    pub hex: String,
    pub intent: String,
}

/// Deterministic positive-case injection into seeded data.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InjectionSpec {
    pub needle_hex: String,
    pub variants: Vec<usize>,
    pub placement: InjectionPlacement,
}

/// Position used for deterministic injection.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionPlacement {
    Start,
    Middle,
    End,
    Seeded,
}

/// Committed digest root for the visible frozen suite.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DigestManifest {
    pub schema: String,
    pub expanded_framing: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub case_specs: usize,
    pub input_variants: usize,
    pub semantic_comparisons: usize,
}

/// Expanded immutable haystack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedInput {
    pub case_id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub pattern: String,
    pub ordinal: usize,
    pub intent: String,
    pub haystack: Vec<u8>,
}

/// Authenticated suite and exact raw identities.
#[derive(Clone, Debug)]
pub struct AuthenticatedSuite {
    pub manifest: SuiteManifest,
    pub inputs: Vec<ExpandedInput>,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
}

/// Candidate execution mode.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    HotReuse,
    OneShot,
}

/// Capture-free semantic operation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Find,
    Exists,
    SelectedEnd,
}

/// Exact oracle or candidate value.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum SemanticValue {
    Span(Option<SpanValue>),
    Boolean(bool),
    End(Option<usize>),
}

/// Serializable half-open span.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SpanValue {
    pub start: usize,
    pub end: usize,
}

/// One of four non-overlapping FRE qualification outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Pass,
    Unsupported,
    Fail,
    Fault,
}

/// Deterministic receipt for one input, mode and operation.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Receipt {
    pub case_id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub input_ordinal: usize,
    pub declared_intent: String,
    pub oracle_class: String,
    pub haystack_sha256: String,
    pub haystack_bytes: usize,
    pub mode: ExecutionMode,
    pub operation: Operation,
    pub expected: SemanticValue,
    pub actual: Option<SemanticValue>,
    pub status: Status,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub plan: Option<String>,
    pub work_or_linear_terms: Option<u64>,
}

/// Exact deterministic coverage counters.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Coverage {
    pub receipts: usize,
    pub by_status: BTreeMap<Status, usize>,
    pub by_family_status: BTreeMap<String, BTreeMap<Status, usize>>,
    pub by_mode_status: BTreeMap<ExecutionMode, BTreeMap<Status, usize>>,
    pub by_operation_status: BTreeMap<Operation, BTreeMap<Status, usize>>,
}

/// Deterministic correctness report. It contains no clock samples.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct CorrectnessReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub oracle_identity: String,
    pub candidate_identity: String,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub mode_boundaries: BTreeMap<ExecutionMode, String>,
    pub dimensions: Vec<DimensionDeclaration>,
    pub receipts_sha256: String,
    pub coverage: Coverage,
    pub receipts: Vec<Receipt>,
}

/// Non-normative diagnostic build timing series.
#[derive(Clone, Debug, Serialize)]
pub struct BuildTimingSeries {
    pub engine: TimingEngine,
    pub case_id: String,
    pub measured_iterations: usize,
    pub elapsed_ns: Vec<u64>,
    pub terminal_state: String,
}

/// Non-normative diagnostic search timing series.
#[derive(Clone, Debug, Serialize)]
pub struct OperationTimingSeries {
    pub engine: TimingEngine,
    pub case_id: String,
    pub mode: ExecutionMode,
    pub operation: Operation,
    pub changing_haystacks: bool,
    pub input_count: usize,
    pub warmup_repetitions_per_input: usize,
    pub measured_repetitions_per_input: usize,
    pub samples: Vec<OperationTimingSample>,
    pub terminal_state: String,
}

/// One measured operation attempt. Together with the containing series,
/// `(input_ordinal, repetition_index)` is the stable key for matching FRE and
/// oracle observations without mixing different haystacks.
#[derive(Clone, Debug, Serialize)]
pub struct OperationTimingSample {
    pub input_ordinal: usize,
    pub repetition_index: usize,
    pub compile_ns: Option<u64>,
    pub search_ns: Option<u64>,
    pub terminal_state: String,
}

/// Engine identity for timing diagnostics. Correctness always uses Rust regex
/// as the oracle and FRE as the candidate, independently of these samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimingEngine {
    FreCandidate,
    RustRegexOracle,
}

/// Timing-only report with no pass/fail thresholds.
#[derive(Clone, Debug, Serialize)]
pub struct PerformanceReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub correctness_receipts_sha256: String,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub policy: TimingPolicy,
    pub normative: bool,
    pub planner_feedback_permitted: bool,
    pub mode_boundaries: BTreeMap<ExecutionMode, String>,
    pub input_schedule: String,
    pub measurement_scope: String,
    pub selected_end_adapter: String,
    pub builds: Vec<BuildTimingSeries>,
    pub operations: Vec<OperationTimingSeries>,
}

/// Tool failure. Candidate semantic mismatches remain receipts, not tool
/// errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldoutError {
    message: String,
}

impl HoldoutError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for HoldoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HoldoutError {}

/// Authenticate, execute and write deterministic correctness plus optional
/// separate performance diagnostics.
pub fn run(config: &RunConfig) -> Result<CorrectnessReport, HoldoutError> {
    let authenticated = authenticate_paths(&config.suite, &config.schema, &config.digests)?;
    let correctness = run_correctness(&authenticated)?;
    write_json(&config.correctness_output, &correctness)?;
    if let Some(path) = &config.performance_output {
        let performance = run_performance(&authenticated, &correctness)?;
        write_json(path, &performance)?;
    }
    Ok(correctness)
}

/// Enforce the semantic gate used by CI after a report has been written.
/// Unsupported receipts remain visible coverage gaps; semantic mismatches and
/// candidate faults fail the gate.
pub fn enforce_strict_gate(report: &CorrectnessReport) -> Result<(), HoldoutError> {
    let failures = report
        .coverage
        .by_status
        .get(&Status::Fail)
        .copied()
        .unwrap_or(0);
    let faults = report
        .coverage
        .by_status
        .get(&Status::Fault)
        .copied()
        .unwrap_or(0);
    if failures == 0 && faults == 0 {
        Ok(())
    } else {
        Err(HoldoutError::new(format!(
            "strict correctness gate rejected {failures} semantic failures and {faults} candidate faults; inspect the already-written receipts"
        )))
    }
}

/// Authenticate committed files without executing either engine.
pub fn authenticate_paths(
    suite: &Path,
    schema: &Path,
    digests: &Path,
) -> Result<AuthenticatedSuite, HoldoutError> {
    let suite_bytes = fs::read(suite)
        .map_err(|error| HoldoutError::new(format!("read suite {}: {error}", suite.display())))?;
    let schema_bytes = fs::read(schema)
        .map_err(|error| HoldoutError::new(format!("read schema {}: {error}", schema.display())))?;
    let digest_bytes = fs::read(digests).map_err(|error| {
        HoldoutError::new(format!("read digests {}: {error}", digests.display()))
    })?;
    authenticate_bytes(&suite_bytes, &schema_bytes, &digest_bytes)
}

/// Authenticate raw committed contents. Exposed for deterministic tamper
/// tests and external packaging.
pub fn authenticate_bytes(
    suite_bytes: &[u8],
    schema_bytes: &[u8],
    digest_bytes: &[u8],
) -> Result<AuthenticatedSuite, HoldoutError> {
    validate_schema_document(schema_bytes)?;
    let digests: DigestManifest = serde_json::from_slice(digest_bytes)
        .map_err(|error| HoldoutError::new(format!("parse digest manifest: {error}")))?;
    if digests.schema != DIGEST_SCHEMA {
        return Err(HoldoutError::new(format!(
            "digest schema {} is not {DIGEST_SCHEMA}",
            digests.schema
        )));
    }
    if digests.expanded_framing != EXPANDED_FRAMING {
        return Err(HoldoutError::new(format!(
            "expanded framing {} is not {EXPANDED_FRAMING}",
            digests.expanded_framing
        )));
    }
    let suite_sha256 = sha256(suite_bytes);
    let json_schema_sha256 = sha256(schema_bytes);
    verify_digest("suite", &suite_sha256, &digests.suite_sha256)?;
    verify_digest(
        "JSON schema",
        &json_schema_sha256,
        &digests.json_schema_sha256,
    )?;
    let manifest: SuiteManifest = serde_json::from_slice(suite_bytes)
        .map_err(|error| HoldoutError::new(format!("parse suite manifest: {error}")))?;
    validate_manifest(&manifest)?;
    let inputs = expand_manifest(&manifest)?;
    let expanded_inputs_sha256 = expanded_digest(&inputs)?;
    verify_digest(
        "expanded inputs",
        &expanded_inputs_sha256,
        &digests.expanded_inputs_sha256,
    )?;
    let comparisons = checked_mul(inputs.len(), 6, "semantic comparison count")?;
    if digests.case_specs != manifest.cases.len()
        || digests.input_variants != inputs.len()
        || digests.semantic_comparisons != comparisons
    {
        return Err(HoldoutError::new(format!(
            "digest counts ({}, {}, {}) differ from expanded counts ({}, {}, {})",
            digests.case_specs,
            digests.input_variants,
            digests.semantic_comparisons,
            manifest.cases.len(),
            inputs.len(),
            comparisons
        )));
    }
    Ok(AuthenticatedSuite {
        manifest,
        inputs,
        suite_sha256,
        json_schema_sha256,
        expanded_inputs_sha256,
    })
}

/// Derive a digest sidecar for an intentionally reviewed suite/schema update.
/// Normal qualification uses [`authenticate_bytes`] and never rewrites it.
pub fn derive_digest_manifest(
    suite_bytes: &[u8],
    schema_bytes: &[u8],
) -> Result<DigestManifest, HoldoutError> {
    validate_schema_document(schema_bytes)?;
    let manifest: SuiteManifest = serde_json::from_slice(suite_bytes)
        .map_err(|error| HoldoutError::new(format!("parse suite manifest: {error}")))?;
    validate_manifest(&manifest)?;
    let inputs = expand_manifest(&manifest)?;
    Ok(DigestManifest {
        schema: DIGEST_SCHEMA.to_string(),
        expanded_framing: EXPANDED_FRAMING.to_string(),
        suite_sha256: sha256(suite_bytes),
        json_schema_sha256: sha256(schema_bytes),
        expanded_inputs_sha256: expanded_digest(&inputs)?,
        case_specs: manifest.cases.len(),
        input_variants: inputs.len(),
        semantic_comparisons: checked_mul(inputs.len(), 6, "semantic comparison count")?,
    })
}

fn validate_schema_document(schema_bytes: &[u8]) -> Result<(), HoldoutError> {
    let schema: serde_json::Value = serde_json::from_slice(schema_bytes)
        .map_err(|error| HoldoutError::new(format!("parse committed JSON Schema: {error}")))?;
    let Some(object) = schema.as_object() else {
        return Err(HoldoutError::new(
            "committed JSON Schema root must be an object",
        ));
    };
    if object.get("type").and_then(serde_json::Value::as_str) != Some("object")
        || object
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .and_then(|properties| properties.get("schema"))
            .and_then(serde_json::Value::as_object)
            .and_then(|schema_property| schema_property.get("const"))
            .and_then(serde_json::Value::as_str)
            != Some(SUITE_SCHEMA)
    {
        return Err(HoldoutError::new(
            "committed JSON Schema does not identify the frozen suite object",
        ));
    }
    Ok(())
}

/// Expand a validated suite with stable `SplitMix64` generation.
pub fn expand_manifest(manifest: &SuiteManifest) -> Result<Vec<ExpandedInput>, HoldoutError> {
    let mut output = Vec::new();
    let mut total_bytes = 0_usize;
    for case in &manifest.cases {
        let generated = expand_case(case)?;
        if generated.is_empty() {
            return Err(HoldoutError::new(format!(
                "case {} expands to no inputs",
                case.id
            )));
        }
        for (ordinal, generated) in generated.into_iter().enumerate() {
            if generated.haystack.len() > MAX_INPUT_BYTES {
                return Err(HoldoutError::new(format!(
                    "case {} input {ordinal} has {} bytes, limit is {MAX_INPUT_BYTES}",
                    case.id,
                    generated.haystack.len()
                )));
            }
            total_bytes = checked_add(total_bytes, generated.haystack.len(), "total input bytes")?;
            if total_bytes > MAX_TOTAL_INPUT_BYTES {
                return Err(HoldoutError::new(format!(
                    "expanded input bytes {total_bytes} exceed {MAX_TOTAL_INPUT_BYTES}"
                )));
            }
            if output.len() >= MAX_INPUT_VARIANTS {
                return Err(HoldoutError::new(format!(
                    "expanded inputs exceed {MAX_INPUT_VARIANTS}"
                )));
            }
            output
                .try_reserve(1)
                .map_err(|_| HoldoutError::new("allocate expanded input list"))?;
            output.push(ExpandedInput {
                case_id: case.id.clone(),
                family: case.family.clone(),
                labels: case.labels.clone(),
                pattern: case.pattern.clone(),
                ordinal,
                intent: generated.intent,
                haystack: generated.haystack,
            });
        }
    }
    Ok(output)
}

#[derive(Debug)]
struct GeneratedInput {
    intent: String,
    haystack: Vec<u8>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the three frozen generator formats stay together so their framing is auditable"
)]
fn expand_case(case: &CaseSpec) -> Result<Vec<GeneratedInput>, HoldoutError> {
    match &case.generator {
        GeneratorSpec::Explicit { inputs } => {
            if inputs.len() > MAX_INPUT_VARIANTS {
                return Err(HoldoutError::new(format!(
                    "case {} requests {} explicit variants, limit is {MAX_INPUT_VARIANTS}",
                    case.id,
                    inputs.len()
                )));
            }
            inputs
                .iter()
                .map(|input| {
                    Ok(GeneratedInput {
                        intent: input.intent.clone(),
                        haystack: decode_hex(&input.hex)?,
                    })
                })
                .collect()
        }
        GeneratorSpec::SeededBytes {
            seed,
            alphabet_hex,
            lengths,
            variants_per_length,
            injection,
        } => {
            let seed = parse_seed(seed)?;
            let alphabet = decode_hex(alphabet_hex)?;
            if alphabet.is_empty() {
                return Err(HoldoutError::new(format!(
                    "case {} has an empty seeded alphabet",
                    case.id
                )));
            }
            if *variants_per_length == 0 {
                return Err(HoldoutError::new(format!(
                    "case {} requests zero variants",
                    case.id
                )));
            }
            let generated_count = checked_mul(
                lengths.len(),
                *variants_per_length,
                "seeded input variant count",
            )?;
            if generated_count > MAX_INPUT_VARIANTS {
                return Err(HoldoutError::new(format!(
                    "case {} requests {generated_count} seeded variants, limit is {MAX_INPUT_VARIANTS}",
                    case.id
                )));
            }
            let decoded_injection = injection
                .as_ref()
                .map(|spec| decode_hex(&spec.needle_hex).map(|needle| (spec, needle)))
                .transpose()?;
            let mut generated = Vec::new();
            generated
                .try_reserve_exact(generated_count)
                .map_err(|_| HoldoutError::new("allocate seeded input list"))?;
            for &length in lengths {
                if length > MAX_INPUT_BYTES {
                    return Err(HoldoutError::new(format!(
                        "case {} seeded length {length} exceeds {MAX_INPUT_BYTES}",
                        case.id
                    )));
                }
                for variant in 0..*variants_per_length {
                    let length_key = u64::try_from(length)
                        .map_err(|_| HoldoutError::new("input length does not fit u64"))?;
                    let variant_key = u64::try_from(variant)
                        .map_err(|_| HoldoutError::new("variant does not fit u64"))?;
                    let mut rng = SplitMix64::new(
                        seed ^ length_key.rotate_left(17) ^ variant_key.rotate_left(41),
                    );
                    let mut haystack = Vec::new();
                    haystack
                        .try_reserve_exact(length)
                        .map_err(|_| HoldoutError::new("allocate seeded haystack"))?;
                    for _ in 0..length {
                        let alphabet_len = u64::try_from(alphabet.len())
                            .map_err(|_| HoldoutError::new("alphabet length does not fit u64"))?;
                        let index = usize::try_from(rng.next().rem_euclid(alphabet_len))
                            .map_err(|_| HoldoutError::new("alphabet index does not fit usize"))?;
                        haystack.push(alphabet[index]);
                    }
                    let injected = decoded_injection.as_ref().is_some_and(|(spec, needle)| {
                        spec.variants.contains(&variant) && needle.len() <= haystack.len()
                    });
                    if let Some((spec, needle)) = &decoded_injection
                        && injected
                    {
                        inject(&mut haystack, needle, spec.placement, &mut rng)?;
                    }
                    generated.push(GeneratedInput {
                        intent: if injected {
                            "positive-injected".to_string()
                        } else {
                            "negative-targeted".to_string()
                        },
                        haystack,
                    });
                }
            }
            Ok(generated)
        }
        GeneratorSpec::RepeatedByte {
            prefix_hex,
            byte_hex,
            lengths,
            suffix_hex,
            intent,
        } => {
            let prefix = decode_hex(prefix_hex)?;
            let bytes = decode_hex(byte_hex)?;
            let [byte] = bytes.as_slice() else {
                return Err(HoldoutError::new(format!(
                    "case {} repeated byte must decode to one byte",
                    case.id
                )));
            };
            let suffix = decode_hex(suffix_hex)?;
            let mut generated = Vec::new();
            if lengths.len() > MAX_INPUT_VARIANTS {
                return Err(HoldoutError::new(format!(
                    "case {} requests {} repeated variants, limit is {MAX_INPUT_VARIANTS}",
                    case.id,
                    lengths.len()
                )));
            }
            generated
                .try_reserve_exact(lengths.len())
                .map_err(|_| HoldoutError::new("allocate repeated input list"))?;
            for &length in lengths {
                let capacity = checked_add(
                    checked_add(prefix.len(), length, "repeated input length")?,
                    suffix.len(),
                    "repeated input length",
                )?;
                if capacity > MAX_INPUT_BYTES {
                    return Err(HoldoutError::new(format!(
                        "case {} repeated input has {capacity} bytes, limit is {MAX_INPUT_BYTES}",
                        case.id
                    )));
                }
                let mut haystack = Vec::new();
                haystack
                    .try_reserve_exact(capacity)
                    .map_err(|_| HoldoutError::new("allocate repeated haystack"))?;
                haystack.extend_from_slice(&prefix);
                haystack.resize(
                    checked_add(haystack.len(), length, "repeated resize")?,
                    *byte,
                );
                haystack.extend_from_slice(&suffix);
                generated.push(GeneratedInput {
                    intent: intent.clone(),
                    haystack,
                });
            }
            Ok(generated)
        }
    }
}

fn inject(
    haystack: &mut [u8],
    needle: &[u8],
    placement: InjectionPlacement,
    rng: &mut SplitMix64,
) -> Result<(), HoldoutError> {
    let available = haystack
        .len()
        .checked_sub(needle.len())
        .ok_or_else(|| HoldoutError::new("injection needle exceeds haystack"))?;
    let start = match placement {
        InjectionPlacement::Start => 0,
        InjectionPlacement::Middle => available / 2,
        InjectionPlacement::End => available,
        InjectionPlacement::Seeded => {
            let positions = checked_add(available, 1, "injection positions")?;
            let positions = u64::try_from(positions)
                .map_err(|_| HoldoutError::new("injection positions do not fit u64"))?;
            usize::try_from(rng.next().rem_euclid(positions))
                .map_err(|_| HoldoutError::new("injection position does not fit usize"))?
        }
    };
    let end = checked_add(start, needle.len(), "injection end")?;
    haystack[start..end].copy_from_slice(needle);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

fn validate_manifest(manifest: &SuiteManifest) -> Result<(), HoldoutError> {
    if manifest.schema != SUITE_SCHEMA {
        return Err(HoldoutError::new(format!(
            "suite schema {} is not {SUITE_SCHEMA}",
            manifest.schema
        )));
    }
    if manifest.oracle.implementation != "rust-regex"
        || manifest.oracle.version != RUST_REGEX_VERSION
        || manifest.oracle.api != "bytes"
        || manifest.oracle.unicode
    {
        return Err(HoldoutError::new(
            "oracle must be rust-regex 1.12.4 bytes with Unicode disabled",
        ));
    }
    if manifest.suite_id.is_empty() {
        return Err(HoldoutError::new("suite ID must not be empty"));
    }
    if !is_iso_date_shape(&manifest.freeze_date) {
        return Err(HoldoutError::new(
            "freeze date must have the ASCII shape YYYY-MM-DD",
        ));
    }
    if manifest.cases.is_empty() || manifest.cases.len() > MAX_CASE_SPECS {
        return Err(HoldoutError::new(format!(
            "suite case count must be 1..={MAX_CASE_SPECS}"
        )));
    }
    if manifest.timing.measured_iterations == 0
        || manifest.timing.measured_iterations > 10_000
        || manifest.timing.warmup_iterations > 10_000
    {
        return Err(HoldoutError::new(
            "timing iteration policy is outside hard limits",
        ));
    }
    let mut case_ids = BTreeSet::new();
    for case in &manifest.cases {
        if case.id.is_empty() || !case_ids.insert(&case.id) {
            return Err(HoldoutError::new(format!(
                "case ID {:?} is empty or duplicated",
                case.id
            )));
        }
        if case.family.is_empty() {
            return Err(HoldoutError::new(format!(
                "case {} has an empty family",
                case.id
            )));
        }
        validate_generator_declaration(case)?;
        oracle_regex(&case.pattern).map_err(|error| {
            HoldoutError::new(format!(
                "case {} oracle pattern is invalid: {error}",
                case.id
            ))
        })?;
    }
    let mut dimension_ids = BTreeSet::new();
    for dimension in &manifest.dimensions {
        if dimension.id.is_empty()
            || dimension.detail.is_empty()
            || !dimension_ids.insert(dimension.id.clone())
        {
            return Err(HoldoutError::new(format!(
                "dimension {:?} has an empty/duplicate ID or empty detail",
                dimension.id
            )));
        }
    }
    for required in [
        "captures",
        "unicode-text",
        "re2-profiles",
        "pattern-fleets",
        "replacement-split",
        "streaming-vectored",
        "concurrency",
        "jit-denied",
        "memory-pressure",
        "architecture-aarch64",
        "architecture-x86_64",
    ] {
        if !dimension_ids.contains(required) {
            return Err(HoldoutError::new(format!(
                "suite omits required declared dimension {required}"
            )));
        }
    }
    Ok(())
}

fn is_iso_date_shape(date: &str) -> bool {
    let bytes = date.as_bytes();
    bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn validate_generator_declaration(case: &CaseSpec) -> Result<(), HoldoutError> {
    match &case.generator {
        GeneratorSpec::Explicit { inputs } => {
            if inputs.is_empty() {
                return Err(HoldoutError::new(format!(
                    "case {} has no explicit inputs",
                    case.id
                )));
            }
            if inputs.iter().any(|input| input.intent.is_empty()) {
                return Err(HoldoutError::new(format!(
                    "case {} has an explicit input with empty intent",
                    case.id
                )));
            }
        }
        GeneratorSpec::SeededBytes {
            lengths,
            variants_per_length,
            injection,
            ..
        } => {
            if lengths.is_empty() || *variants_per_length == 0 {
                return Err(HoldoutError::new(format!(
                    "case {} needs seeded lengths and at least one variant per length",
                    case.id
                )));
            }
            if let Some(injection) = injection
                && injection
                    .variants
                    .iter()
                    .any(|variant| *variant >= *variants_per_length)
            {
                return Err(HoldoutError::new(format!(
                    "case {} injection names a variant outside variants_per_length",
                    case.id
                )));
            }
        }
        GeneratorSpec::RepeatedByte {
            lengths, intent, ..
        } => {
            if lengths.is_empty() || intent.is_empty() {
                return Err(HoldoutError::new(format!(
                    "case {} needs repeated lengths and non-empty intent",
                    case.id
                )));
            }
        }
    }
    Ok(())
}

fn verify_digest(name: &str, actual: &str, expected: &str) -> Result<(), HoldoutError> {
    if actual != expected {
        return Err(HoldoutError::new(format!(
            "{name} SHA-256 {actual} differs from committed {expected}"
        )));
    }
    Ok(())
}

fn expanded_digest(inputs: &[ExpandedInput]) -> Result<String, HoldoutError> {
    let mut digest = Sha256::new();
    digest.update(EXPANDED_FRAMING.as_bytes());
    digest.update(b"\0");
    digest_usize(&mut digest, inputs.len(), "expanded input count")?;
    for input in inputs {
        digest.update(b"input\0");
        digest.update(b"case-id\0");
        digest_field(&mut digest, input.case_id.as_bytes())?;
        digest.update(b"family\0");
        digest_field(&mut digest, input.family.as_bytes())?;
        digest.update(b"label-count\0");
        digest_usize(&mut digest, input.labels.len(), "label count")?;
        for label in &input.labels {
            digest.update(b"label\0");
            digest_field(&mut digest, label.as_bytes())?;
        }
        digest.update(b"pattern\0");
        digest_field(&mut digest, input.pattern.as_bytes())?;
        digest.update(b"ordinal-u64\0");
        digest_usize(&mut digest, input.ordinal, "input ordinal")?;
        digest.update(b"intent\0");
        digest_field(&mut digest, input.intent.as_bytes())?;
        digest.update(b"haystack\0");
        digest_field(&mut digest, &input.haystack)?;
    }
    Ok(encode_hex(&digest.finalize()))
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) -> Result<(), HoldoutError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| HoldoutError::new("digest field length does not fit canonical u64 framing"))?;
    digest.update(length.to_le_bytes());
    digest.update(bytes);
    Ok(())
}

fn digest_usize(digest: &mut Sha256, value: usize, what: &str) -> Result<(), HoldoutError> {
    let canonical = u64::try_from(value)
        .map_err(|_| HoldoutError::new(format!("{what} does not fit canonical u64 framing")))?;
    digest.update(canonical.to_le_bytes());
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    output
}

fn decode_hex(text: &str) -> Result<Vec<u8>, HoldoutError> {
    let max_hex_bytes = MAX_INPUT_BYTES
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("hex input cap overflow"))?;
    if text.len() > max_hex_bytes {
        return Err(HoldoutError::new(format!(
            "hex input has {} digits, limit is {max_hex_bytes}",
            text.len()
        )));
    }
    if !text.len().is_multiple_of(2) {
        return Err(HoldoutError::new("hex input has odd length"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(text.len() / 2)
        .map_err(|_| HoldoutError::new("allocate decoded hex"))?;
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Result<u8, HoldoutError> {
    match byte {
        b'0'..=b'9' => Ok(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(HoldoutError::new(format!(
            "invalid hex digit {:?}",
            char::from(byte)
        ))),
    }
}

fn parse_seed(text: &str) -> Result<u64, HoldoutError> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map_err(|error| HoldoutError::new(format!("invalid hexadecimal seed: {error}")))
    } else {
        text.parse::<u64>()
            .map_err(|error| HoldoutError::new(format!("invalid decimal seed: {error}")))
    }
}

fn checked_add(left: usize, right: usize, what: &str) -> Result<usize, HoldoutError> {
    left.checked_add(right)
        .ok_or_else(|| HoldoutError::new(format!("{what} overflow")))
}

fn checked_mul(left: usize, right: usize, what: &str) -> Result<usize, HoldoutError> {
    left.checked_mul(right)
        .ok_or_else(|| HoldoutError::new(format!("{what} overflow")))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), HoldoutError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| HoldoutError::new(format!("serialize {}: {error}", path.display())))?;
    bytes.push(b'\n');
    fs::write(path, bytes)
        .map_err(|error| HoldoutError::new(format!("write {}: {error}", path.display())))
}

/// Execute the exact semantic qualification without consulting any timing.
pub fn run_correctness(
    authenticated: &AuthenticatedSuite,
) -> Result<CorrectnessReport, HoldoutError> {
    let mut receipts = Vec::new();
    for case in &authenticated.manifest.cases {
        let oracle = oracle_regex(&case.pattern).map_err(|error| {
            HoldoutError::new(format!("case {} oracle construction: {error}", case.id))
        })?;
        let hot_accounted = build_candidate(&case.pattern);
        let hot_ordinary = build_candidate(&case.pattern);
        for input in authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == case.id)
        {
            let oracle_match = oracle.find(&input.haystack).map(|matched| SpanValue {
                start: matched.start(),
                end: matched.end(),
            });
            let oracle_class = match oracle_match {
                None => "negative",
                Some(span) if span.start == span.end => "positive-empty",
                Some(_) => "positive-nonempty",
            };
            for mode in [ExecutionMode::HotReuse, ExecutionMode::OneShot] {
                for operation in [Operation::Find, Operation::Exists, Operation::SelectedEnd] {
                    let expected = oracle_value(&oracle, &input.haystack, operation);
                    let outcome = match mode {
                        ExecutionMode::HotReuse => execute_candidate_with_ordinary_parity(
                            &hot_accounted,
                            &hot_ordinary,
                            &input.haystack,
                            operation,
                            &expected,
                        ),
                        ExecutionMode::OneShot => {
                            let accounted = build_candidate(&case.pattern);
                            let ordinary = build_candidate(&case.pattern);
                            execute_candidate_with_ordinary_parity(
                                &accounted,
                                &ordinary,
                                &input.haystack,
                                operation,
                                &expected,
                            )
                        }
                    };
                    receipts
                        .try_reserve(1)
                        .map_err(|_| HoldoutError::new("allocate correctness receipts"))?;
                    receipts.push(make_receipt(
                        input,
                        mode,
                        operation,
                        oracle_class,
                        expected,
                        outcome,
                    ));
                }
            }
        }
    }
    let expected_receipts = checked_mul(authenticated.inputs.len(), 6, "receipt count")?;
    if receipts.len() != expected_receipts {
        return Err(HoldoutError::new(format!(
            "generated {} receipts, expected {expected_receipts}",
            receipts.len()
        )));
    }
    let coverage = coverage(&receipts);
    let receipt_bytes = serde_json::to_vec(&receipts)
        .map_err(|error| HoldoutError::new(format!("serialize receipt digest: {error}")))?;
    let receipts_sha256 = sha256(&receipt_bytes);
    let mode_boundaries = BTreeMap::from([
        (
            ExecutionMode::HotReuse,
            "one candidate construction per case and API surface; every changing haystack and operation reuses its immutable matcher; the ordinary surface is checked outside all timing against the finite accounted receipt surface"
                .to_string(),
        ),
        (
            ExecutionMode::OneShot,
            "one candidate construction per API surface occurs inside every (case,input,operation) receipt before one search on each; the ordinary result is checked outside all timing against the finite accounted receipt result"
                .to_string(),
        ),
    ]);
    Ok(CorrectnessReport {
        schema: REPORT_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        json_schema_sha256: authenticated.json_schema_sha256.clone(),
        expanded_inputs_sha256: authenticated.expanded_inputs_sha256.clone(),
        oracle_identity: "regex::bytes 1.12.4; unicode=false; leftmost-first".to_string(),
        candidate_identity: "current fre::PortableBuilder auto plan; unicode=false; receipts use default checked limits and include untimed ordinary-API parity validation"
            .to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_pointer_width: usize::BITS,
        mode_boundaries,
        dimensions: authenticated.manifest.dimensions.clone(),
        receipts_sha256,
        coverage,
        receipts,
    })
}

fn oracle_regex(pattern: &str) -> Result<Regex, regex::Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
}

fn oracle_value(regex: &Regex, haystack: &[u8], operation: Operation) -> SemanticValue {
    match operation {
        Operation::Find => SemanticValue::Span(regex.find(haystack).map(|matched| SpanValue {
            start: matched.start(),
            end: matched.end(),
        })),
        Operation::Exists => SemanticValue::Boolean(regex.is_match(haystack)),
        Operation::SelectedEnd => {
            SemanticValue::End(regex.find(haystack).map(|matched| matched.end()))
        }
    }
}

#[derive(Clone, Debug)]
struct CandidateFailure {
    status: Status,
    code: String,
    reason: String,
}

#[derive(Clone, Debug)]
enum CandidateOutcome {
    Executed {
        value: SemanticValue,
        plan: String,
        work: u64,
    },
    Failure(CandidateFailure),
}

fn build_candidate(pattern: &str) -> Result<PortableRegex, CandidateFailure> {
    build_candidate_with_limits(pattern, &BuildLimits::default())
}

fn build_candidate_with_limits(
    pattern: &str,
    limits: &BuildLimits,
) -> Result<PortableRegex, CandidateFailure> {
    match catch_unwind(AssertUnwindSafe(|| {
        PortableBuilder::new(pattern)
            .unicode(false)
            .limits(*limits)
            .build()
    })) {
        Err(_) => Err(CandidateFailure {
            status: Status::Fault,
            code: "build.panic".to_string(),
            reason: "candidate panicked during construction".to_string(),
        }),
        Ok(Ok(regex)) => Ok(regex),
        Ok(Err(error)) => Err(classify_build_error(&error)),
    }
}

fn classify_build_error(error: &BuildError) -> CandidateFailure {
    let (status, code) = match error {
        BuildError::Syntax(error) => classify_syntax_build_error(error),
        BuildError::Lower(error) => classify_lower_build_error(error),
        BuildError::Literal(error) => classify_literal_build_error(error),
        BuildError::LiteralSet(error) => classify_literal_set_build_error(error),
        BuildError::RequiredLiteral(error) => classify_required_literal_build_error(error),
        BuildError::ForwardAnchored(error) => classify_forward_anchored_build_error(error),
        BuildError::RequiredLiteralShape | BuildError::ForwardAnchoredShape => {
            (Status::Fault, "build.fault.unexpected-forced-shape")
        }
        BuildError::PlannerWorkLimit { .. } => (Status::Unsupported, "build.resource.planner-work"),
        BuildError::AllocationFailed { .. } => (Status::Fault, "build.fault.allocation"),
        BuildError::InternalInvariant(_) => (Status::Fault, "build.fault.internal-invariant"),
        _ => (Status::Fault, "build.unknown-fault"),
    };
    CandidateFailure {
        status,
        code: code.to_string(),
        reason: error.to_string(),
    }
}

fn classify_syntax_build_error(error: &fre_syntax::ParseError) -> (Status, &'static str) {
    match &error.category {
        fre_syntax::ErrorCategory::FreResourceLimit { .. }
        | fre_syntax::ErrorCategory::StrictQualificationFailure { .. } => {
            (Status::Unsupported, "build.resource.syntax")
        }
        fre_syntax::ErrorCategory::UnsupportedNotYetImplemented { .. } => {
            (Status::Unsupported, "build.semantic.syntax-not-implemented")
        }
        fre_syntax::ErrorCategory::InvalidPatternEncoding
        | fre_syntax::ErrorCategory::UpstreamRustSyntax
        | fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { .. }
        | fre_syntax::ErrorCategory::Re2Syntax { .. }
        | fre_syntax::ErrorCategory::InvalidConfiguration => {
            (Status::Fault, "build.fault.syntax-or-profile")
        }
    }
}

fn classify_lower_build_error(error: &fre_lower::LowerError) -> (Status, &'static str) {
    match error {
        fre_lower::LowerError::Unsupported(_) => (Status::Unsupported, "build.semantic.lowering"),
        fre_lower::LowerError::ResourceLimit { .. }
        | fre_lower::LowerError::Automata(fre_automata::CompileError::ResourceLimit { .. }) => {
            (Status::Unsupported, "build.resource.lowering")
        }
        fre_lower::LowerError::ArithmeticOverflow { .. }
        | fre_lower::LowerError::AllocationFailed { .. }
        | fre_lower::LowerError::InternalInvariant { .. }
        | fre_lower::LowerError::Automata(_) => (Status::Fault, "build.fault.lowering"),
        _ => (Status::Fault, "build.fault.lowering-unknown"),
    }
}

fn classify_literal_build_error(error: &fre_kernels::LiteralError) -> (Status, &'static str) {
    match error {
        fre_kernels::LiteralError::NeedleLimit { .. } => {
            (Status::Unsupported, "build.resource.literal-needle")
        }
        fre_kernels::LiteralError::InvalidWindow { .. }
        | fre_kernels::LiteralError::LinearTermLimit { .. }
        | fre_kernels::LiteralError::ArithmeticOverflow { .. } => {
            (Status::Fault, "build.fault.literal")
        }
        _ => (Status::Fault, "build.fault.literal-unknown"),
    }
}

fn classify_literal_set_build_error(
    error: &fre_kernels::LiteralSetError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::LiteralSetError::EmptyPatternSet => {
            (Status::Fault, "build.fault.literal-set-empty")
        }
        fre_kernels::LiteralSetError::PatternLimit { .. }
        | fre_kernels::LiteralSetError::PatternBytesLimit { .. }
        | fre_kernels::LiteralSetError::BuildWorkLimit { .. }
        | fre_kernels::LiteralSetError::BuildBytesLimit { .. }
        | fre_kernels::LiteralSetError::PersistentBytesLimit { .. } => {
            (Status::Unsupported, "build.resource.literal-set")
        }
        fre_kernels::LiteralSetError::InvalidWindow { .. }
        | fre_kernels::LiteralSetError::TransitionLimit { .. }
        | fre_kernels::LiteralSetError::ArithmeticOverflow { .. }
        | fre_kernels::LiteralSetError::AutomatonBuild { .. } => {
            (Status::Fault, "build.fault.literal-set")
        }
        _ => (Status::Fault, "build.fault.literal-set-unknown"),
    }
}

fn classify_required_literal_build_error(
    error: &fre_kernels::RequiredLiteralBuildError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::RequiredLiteralBuildError::EmptyClass
        | fre_kernels::RequiredLiteralBuildError::EmptySuffix
        | fre_kernels::RequiredLiteralBuildError::FirstSuffixByteInClass { .. }
        | fre_kernels::RequiredLiteralBuildError::OverlappingSuffix { .. } => {
            (Status::Fault, "build.fault.required-literal-auto-proof")
        }
        fre_kernels::RequiredLiteralBuildError::SuffixLimit { .. }
        | fre_kernels::RequiredLiteralBuildError::WorkLimit { .. }
        | fre_kernels::RequiredLiteralBuildError::ScratchLimit { .. }
        | fre_kernels::RequiredLiteralBuildError::PersistentLimit { .. }
        | fre_kernels::RequiredLiteralBuildError::PeakLimit { .. } => {
            (Status::Unsupported, "build.resource.required-literal")
        }
        fre_kernels::RequiredLiteralBuildError::AllocationFailed { .. }
        | fre_kernels::RequiredLiteralBuildError::ArithmeticOverflow { .. } => {
            (Status::Fault, "build.fault.required-literal")
        }
        _ => (Status::Fault, "build.fault.required-literal-unknown"),
    }
}

fn classify_forward_anchored_build_error(
    error: &fre_kernels::ForwardAnchoredBuildError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::ForwardAnchoredBuildError::MissingAbsoluteStart
        | fre_kernels::ForwardAnchoredBuildError::EmptyClass
        | fre_kernels::ForwardAnchoredBuildError::EmptySuffix
        | fre_kernels::ForwardAnchoredBuildError::FirstSuffixByteInClass { .. } => {
            (Status::Fault, "build.fault.forward-anchored-auto-proof")
        }
        fre_kernels::ForwardAnchoredBuildError::SuffixLimit { .. }
        | fre_kernels::ForwardAnchoredBuildError::WorkLimit { .. }
        | fre_kernels::ForwardAnchoredBuildError::ScratchLimit { .. }
        | fre_kernels::ForwardAnchoredBuildError::PersistentLimit { .. }
        | fre_kernels::ForwardAnchoredBuildError::PeakLimit { .. } => {
            (Status::Unsupported, "build.resource.forward-anchored")
        }
        fre_kernels::ForwardAnchoredBuildError::AllocationFailed { .. }
        | fre_kernels::ForwardAnchoredBuildError::ArithmeticOverflow { .. } => {
            (Status::Fault, "build.fault.forward-anchored")
        }
        _ => (Status::Fault, "build.fault.forward-anchored-unknown"),
    }
}

#[cfg(test)]
fn execute_candidate(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
) -> CandidateOutcome {
    execute_candidate_with_limits(regex, haystack, operation, SearchLimits::default())
}

fn execute_candidate_with_ordinary_parity(
    accounted: &Result<PortableRegex, CandidateFailure>,
    ordinary: &Result<PortableRegex, CandidateFailure>,
    haystack: &[u8],
    operation: Operation,
    expected: &SemanticValue,
) -> CandidateOutcome {
    execute_candidate_with_ordinary_parity_and_limits(
        accounted,
        ordinary,
        haystack,
        operation,
        expected,
        SearchLimits::default(),
    )
}

fn execute_candidate_with_ordinary_parity_and_limits(
    accounted: &Result<PortableRegex, CandidateFailure>,
    ordinary: &Result<PortableRegex, CandidateFailure>,
    haystack: &[u8],
    operation: Operation,
    expected: &SemanticValue,
    limits: SearchLimits,
) -> CandidateOutcome {
    // Validate the API that performance actually times independently of the
    // finite diagnostic surface. In particular, a default finite scratch
    // refusal must not prevent the ordinary, construction-bounded API from
    // being checked against Rust.
    let ordinary_value = match ordinary {
        Ok(regex) => match execute_candidate_ordinary(regex, haystack, operation) {
            Ok(value) => value,
            Err(failure) => return CandidateOutcome::Failure(failure),
        },
        Err(failure) => return CandidateOutcome::Failure(failure.clone()),
    };
    if ordinary_value != *expected {
        return CandidateOutcome::Failure(CandidateFailure {
            status: Status::Fail,
            code: "search.semantic.ordinary-oracle-parity".to_string(),
            reason: format!(
                "ordinary FRE value {ordinary_value:?} differs from Rust-regex value {expected:?}"
            ),
        });
    }

    let accounted = match accounted {
        Ok(regex) => execute_candidate_with_limits(regex, haystack, operation, limits),
        Err(failure) => CandidateOutcome::Failure(failure.clone()),
    };
    let (accounted_value, plan, work) = match accounted {
        CandidateOutcome::Executed { value, plan, work } => (value, plan, work),
        CandidateOutcome::Failure(failure) => return CandidateOutcome::Failure(failure),
    };
    if ordinary_value != accounted_value {
        return CandidateOutcome::Failure(CandidateFailure {
            status: Status::Fail,
            code: "search.semantic.ordinary-accounted-parity".to_string(),
            reason: format!(
                "ordinary FRE value {ordinary_value:?} differs from finite accounted FRE value {accounted_value:?}"
            ),
        });
    }
    CandidateOutcome::Executed {
        value: accounted_value,
        plan,
        work,
    }
}

fn execute_candidate_ordinary(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
) -> Result<SemanticValue, CandidateFailure> {
    catch_unwind(AssertUnwindSafe(|| {
        execute_candidate_ordinary_inner(regex, haystack, operation)
    }))
    .map_err(|_| CandidateFailure {
        status: Status::Fault,
        code: "search.panic.ordinary".to_string(),
        reason: "candidate ordinary API panicked during search".to_string(),
    })
}

fn execute_candidate_with_limits(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
    limits: SearchLimits,
) -> CandidateOutcome {
    match catch_unwind(AssertUnwindSafe(|| {
        execute_candidate_inner(regex, haystack, operation, limits)
    })) {
        Err(_) => CandidateOutcome::Failure(CandidateFailure {
            status: Status::Fault,
            code: "search.panic".to_string(),
            reason: "candidate panicked during search".to_string(),
        }),
        Ok(Ok((value, accounting))) => CandidateOutcome::Executed {
            value,
            plan: plan_name(accounting.plan()).to_string(),
            work: accounting.work_or_linear_terms(),
        },
        Ok(Err(error)) => CandidateOutcome::Failure(classify_search_error(&error)),
    }
}

fn execute_candidate_inner(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
    limits: SearchLimits,
) -> Result<(SemanticValue, SearchAccounting), SearchError> {
    match operation {
        Operation::Find => {
            let (matched, accounting) = regex.find_accounted(haystack, limits)?;
            Ok((
                SemanticValue::Span(matched.map(|matched| SpanValue {
                    start: matched.start(),
                    end: matched.end(),
                })),
                accounting,
            ))
        }
        Operation::Exists => {
            let (matched, accounting) = regex.is_match_accounted(haystack, limits)?;
            Ok((SemanticValue::Boolean(matched), accounting))
        }
        Operation::SelectedEnd => {
            let (end, accounting) = regex.selected_end_accounted(haystack, limits)?;
            Ok((SemanticValue::End(end), accounting))
        }
    }
}

fn execute_candidate_ordinary_inner(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
) -> SemanticValue {
    match operation {
        Operation::Find => SemanticValue::Span(regex.find(haystack).map(|matched| SpanValue {
            start: matched.start(),
            end: matched.end(),
        })),
        Operation::Exists => SemanticValue::Boolean(regex.is_match(haystack)),
        Operation::SelectedEnd => {
            SemanticValue::End(regex.find(haystack).map(|matched| matched.end()))
        }
    }
}

fn classify_search_error(error: &SearchError) -> CandidateFailure {
    let (status, code) = match error {
        SearchError::K0(error) => classify_k0_search_error(error),
        SearchError::ExactLiteral(error) => classify_literal_search_error(error),
        SearchError::PackedLiteralSet(error) => classify_packed_literal_set_search_error(error),
        SearchError::LiteralSetDfa(error) => classify_literal_set_search_error(error),
        SearchError::RequiredLiteral(error) => classify_required_literal_search_error(error),
        SearchError::ForwardAnchored(error) => classify_forward_anchored_search_error(error),
        _ => (Status::Fault, "search.fault.unknown"),
    };
    CandidateFailure {
        status,
        code: code.to_string(),
        reason: error.to_string(),
    }
}

fn classify_k0_search_error(error: &fre_automata::SearchError) -> (Status, &'static str) {
    match error {
        fre_automata::SearchError::ResourceLimit { .. }
        | fre_automata::SearchError::WorkspaceSetupWorkLimitExceeded { .. }
        | fre_automata::SearchError::WorkLimitExceeded { .. } => {
            (Status::Unsupported, "search.resource.k0")
        }
        fre_automata::SearchError::InvalidWindow { .. }
        | fre_automata::SearchError::WorkspaceLayoutMismatch { .. }
        | fre_automata::SearchError::ArithmeticOverflow { .. }
        | fre_automata::SearchError::ScratchAllocationFailed { .. }
        | fre_automata::SearchError::InternalInvariant { .. } => (Status::Fault, "search.fault.k0"),
        _ => (Status::Fault, "search.fault.k0-unknown"),
    }
}

fn classify_literal_search_error(error: &fre_kernels::LiteralError) -> (Status, &'static str) {
    match error {
        fre_kernels::LiteralError::LinearTermLimit { .. } => {
            (Status::Unsupported, "search.resource.literal-linear-terms")
        }
        fre_kernels::LiteralError::NeedleLimit { .. }
        | fre_kernels::LiteralError::InvalidWindow { .. }
        | fre_kernels::LiteralError::ArithmeticOverflow { .. } => {
            (Status::Fault, "search.fault.literal")
        }
        _ => (Status::Fault, "search.fault.literal-unknown"),
    }
}

fn classify_packed_literal_set_search_error(
    error: &fre_kernels::PackedLiteralSetError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::PackedLiteralSetError::WorkLimit { .. } => {
            (Status::Unsupported, "search.resource.packed-literal-set")
        }
        fre_kernels::PackedLiteralSetError::EmptyPatternSet
        | fre_kernels::PackedLiteralSetError::EmptyPattern { .. }
        | fre_kernels::PackedLiteralSetError::PatternLimit { .. }
        | fre_kernels::PackedLiteralSetError::PatternBytesLimit { .. }
        | fre_kernels::PackedLiteralSetError::BuildWorkLimit { .. }
        | fre_kernels::PackedLiteralSetError::BuildBytesLimit { .. }
        | fre_kernels::PackedLiteralSetError::PersistentBytesLimit { .. }
        | fre_kernels::PackedLiteralSetError::UnsupportedTargetOrShape
        | fre_kernels::PackedLiteralSetError::InvalidWindow { .. }
        | fre_kernels::PackedLiteralSetError::ArithmeticOverflow { .. } => {
            (Status::Fault, "search.fault.packed-literal-set")
        }
        _ => (Status::Fault, "search.fault.packed-literal-set-unknown"),
    }
}

fn classify_literal_set_search_error(
    error: &fre_kernels::LiteralSetError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::LiteralSetError::TransitionLimit { .. } => {
            (Status::Unsupported, "search.resource.literal-set")
        }
        fre_kernels::LiteralSetError::EmptyPatternSet
        | fre_kernels::LiteralSetError::PatternLimit { .. }
        | fre_kernels::LiteralSetError::PatternBytesLimit { .. }
        | fre_kernels::LiteralSetError::BuildWorkLimit { .. }
        | fre_kernels::LiteralSetError::BuildBytesLimit { .. }
        | fre_kernels::LiteralSetError::PersistentBytesLimit { .. }
        | fre_kernels::LiteralSetError::InvalidWindow { .. }
        | fre_kernels::LiteralSetError::ArithmeticOverflow { .. }
        | fre_kernels::LiteralSetError::AutomatonBuild { .. } => {
            (Status::Fault, "search.fault.literal-set")
        }
        _ => (Status::Fault, "search.fault.literal-set-unknown"),
    }
}

fn classify_required_literal_search_error(
    error: &fre_kernels::RequiredLiteralSearchError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::RequiredLiteralSearchError::CandidateLimit { .. }
        | fre_kernels::RequiredLiteralSearchError::WorkLimit { .. }
        | fre_kernels::RequiredLiteralSearchError::ScratchLimit { .. } => {
            (Status::Unsupported, "search.resource.required-literal")
        }
        fre_kernels::RequiredLiteralSearchError::InvalidWindow { .. }
        | fre_kernels::RequiredLiteralSearchError::ArithmeticOverflow { .. } => {
            (Status::Fault, "search.fault.required-literal")
        }
        _ => (Status::Fault, "search.fault.required-literal-unknown"),
    }
}

fn classify_forward_anchored_search_error(
    error: &fre_kernels::ForwardAnchoredSearchError,
) -> (Status, &'static str) {
    match error {
        fre_kernels::ForwardAnchoredSearchError::ExaminedBytesLimit { .. }
        | fre_kernels::ForwardAnchoredSearchError::WorkLimit { .. }
        | fre_kernels::ForwardAnchoredSearchError::ScratchLimit { .. } => {
            (Status::Unsupported, "search.resource.forward-anchored")
        }
        fre_kernels::ForwardAnchoredSearchError::InvalidWindow { .. }
        | fre_kernels::ForwardAnchoredSearchError::ArithmeticOverflow { .. } => {
            (Status::Fault, "search.fault.forward-anchored")
        }
        _ => (Status::Fault, "search.fault.forward-anchored-unknown"),
    }
}

fn plan_name(plan: PlanKind) -> &'static str {
    match plan {
        PlanKind::ExactLiteral => "exact-literal",
        PlanKind::PackedLiteralSet => "packed-literal-set",
        PlanKind::LiteralSetDfa => "literal-set-dfa",
        PlanKind::RequiredLiteral => "required-literal",
        PlanKind::LiteralClassRunLiteral => "literal-class-run-literal",
        PlanKind::PureByteClassRepeat => "pure-byte-class-repeat",
        PlanKind::BoundedByteClassSequence => "bounded-byte-class-sequence",
        PlanKind::ForwardAnchored => "forward-anchored",
        PlanKind::K0 => "k0",
        PlanKind::ReverseInner => "reverse-inner",
        PlanKind::PrefixClassAlternation => "prefix-class-alternation",
        PlanKind::UnicodeFoldedLiteral => "unicode-folded-literal",
        PlanKind::UnicodeWordRun => "unicode-word-run",
        PlanKind::UnicodeScalarRun => "unicode-scalar-run",
        PlanKind::LineDomainByteAtoms => "line-domain-byte-atoms",
        PlanKind::FixedPredicateWord64 => "fixed-predicate-word64",
    }
}

fn make_receipt(
    input: &ExpandedInput,
    mode: ExecutionMode,
    operation: Operation,
    oracle_class: &str,
    expected: SemanticValue,
    outcome: CandidateOutcome,
) -> Receipt {
    let (actual, status, reason_code, reason, plan, work) = match outcome {
        CandidateOutcome::Executed { value, plan, work } => {
            let status = if value == expected {
                Status::Pass
            } else {
                Status::Fail
            };
            let (code, reason) = if status == Status::Fail {
                (
                    Some("semantic-mismatch".to_string()),
                    Some("candidate value differs from exact Rust-regex oracle".to_string()),
                )
            } else {
                (None, None)
            };
            (Some(value), status, code, reason, Some(plan), Some(work))
        }
        CandidateOutcome::Failure(failure) => (
            None,
            failure.status,
            Some(failure.code),
            Some(failure.reason),
            None,
            None,
        ),
    };
    Receipt {
        case_id: input.case_id.clone(),
        family: input.family.clone(),
        labels: input.labels.clone(),
        input_ordinal: input.ordinal,
        declared_intent: input.intent.clone(),
        oracle_class: oracle_class.to_string(),
        haystack_sha256: sha256(&input.haystack),
        haystack_bytes: input.haystack.len(),
        mode,
        operation,
        expected,
        actual,
        status,
        reason_code,
        reason,
        plan,
        work_or_linear_terms: work,
    }
}

fn coverage(receipts: &[Receipt]) -> Coverage {
    let mut coverage = Coverage {
        receipts: receipts.len(),
        ..Coverage::default()
    };
    for receipt in receipts {
        increment(coverage.by_status.entry(receipt.status).or_default());
        increment(
            coverage
                .by_family_status
                .entry(receipt.family.clone())
                .or_default()
                .entry(receipt.status)
                .or_default(),
        );
        increment(
            coverage
                .by_mode_status
                .entry(receipt.mode)
                .or_default()
                .entry(receipt.status)
                .or_default(),
        );
        increment(
            coverage
                .by_operation_status
                .entry(receipt.operation)
                .or_default()
                .entry(receipt.status)
                .or_default(),
        );
    }
    coverage
}

fn increment(counter: &mut usize) {
    *counter = counter
        .checked_add(1)
        .expect("receipt counts are bounded by the authenticated suite caps");
}

/// Run non-normative timing diagnostics. These samples never determine a
/// correctness status, plan, threshold or suite digest.
pub fn run_performance(
    authenticated: &AuthenticatedSuite,
    correctness: &CorrectnessReport,
) -> Result<PerformanceReport, HoldoutError> {
    let policy = authenticated.manifest.timing;
    let mut builds = Vec::new();
    let mut operations = Vec::new();
    for case in &authenticated.manifest.cases {
        let inputs = authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == case.id)
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            return Err(HoldoutError::new(format!(
                "case {} has no expanded timing inputs",
                case.id
            )));
        }
        builds.push(time_fre_build(case, policy));
        builds.push(time_oracle_build(case, policy));

        let fre_hot = build_candidate(&case.pattern);
        let oracle_hot = build_timing_oracle(&case.pattern);
        for operation in [Operation::Find, Operation::Exists, Operation::SelectedEnd] {
            operations.push(time_fre_hot_operation(
                case, &inputs, operation, &fre_hot, policy,
            ));
            operations.push(time_fre_one_shot_operation(
                case, &inputs, operation, policy,
            ));
            operations.push(time_oracle_hot_operation(
                case,
                &inputs,
                operation,
                &oracle_hot,
                policy,
            ));
            operations.push(time_oracle_one_shot_operation(
                case, &inputs, operation, policy,
            ));
        }
    }
    let mode_boundaries = BTreeMap::from([
        (
            ExecutionMode::HotReuse,
            "construction is outside both warmup and measured search samples; one immutable matcher is reused for complete per-input warmup and measured sweeps"
                .to_string(),
        ),
        (
            ExecutionMode::OneShot,
            "each sample constructs one matcher, records construction separately, then performs exactly one operation; warmup and measurement each cover every input equally"
                .to_string(),
        ),
    ]);
    Ok(PerformanceReport {
        schema: PERFORMANCE_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        correctness_receipts_sha256: correctness.receipts_sha256.clone(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_pointer_width: usize::BITS,
        policy,
        normative: false,
        planner_feedback_permitted: false,
        mode_boundaries,
        input_schedule:
            "warmup and measurement are independent complete sweeps in repetition-major, ascending input-ordinal order; every case input receives the policy repetition count"
                .to_string(),
        measurement_scope:
            "search elapsed_ns spans the ordinary Rust-style engine API call plus semantic value extraction; FRE and Rust-regex both use find/is_match with no per-search work limit, selected-end maps ordinary find to the match end, and panic classification and report construction occur after the clock sample; finite-limit and accounting validation is untimed"
                .to_string(),
        selected_end_adapter:
            "neither timed baseline uses a selected_end-specific API; both invoke ordinary find exactly once and map the selected match to end"
                .to_string(),
        builds,
        operations,
    })
}

fn time_fre_build(case: &CaseSpec, policy: TimingPolicy) -> BuildTimingSeries {
    for _ in 0..policy.warmup_iterations {
        let _ = black_box(build_candidate(black_box(&case.pattern)));
    }
    let mut elapsed_ns_samples = Vec::new();
    let mut terminal = "not-run".to_string();
    for _ in 0..policy.measured_iterations {
        let started = Instant::now();
        let result = build_candidate(black_box(&case.pattern));
        elapsed_ns_samples.push(elapsed_ns(started));
        terminal = build_state(&result).to_string();
        let _ = black_box(result);
    }
    BuildTimingSeries {
        engine: TimingEngine::FreCandidate,
        case_id: case.id.clone(),
        measured_iterations: policy.measured_iterations,
        elapsed_ns: elapsed_ns_samples,
        terminal_state: terminal,
    }
}

fn time_oracle_build(case: &CaseSpec, policy: TimingPolicy) -> BuildTimingSeries {
    for _ in 0..policy.warmup_iterations {
        let _ = black_box(build_timing_oracle(black_box(&case.pattern)));
    }
    let mut elapsed_ns_samples = Vec::new();
    let mut terminal = "not-run".to_string();
    for _ in 0..policy.measured_iterations {
        let started = Instant::now();
        let result = build_timing_oracle(black_box(&case.pattern));
        elapsed_ns_samples.push(elapsed_ns(started));
        terminal = oracle_build_state(&result).to_string();
        let _ = black_box(result);
    }
    BuildTimingSeries {
        engine: TimingEngine::RustRegexOracle,
        case_id: case.id.clone(),
        measured_iterations: policy.measured_iterations,
        elapsed_ns: elapsed_ns_samples,
        terminal_state: terminal,
    }
}

fn time_fre_hot_operation(
    case: &CaseSpec,
    inputs: &[&ExpandedInput],
    operation: Operation,
    hot: &Result<PortableRegex, CandidateFailure>,
    policy: TimingPolicy,
) -> OperationTimingSeries {
    let mut terminal = build_state(hot).to_string();
    let mut samples = Vec::new();
    for_each_input_repetition(inputs, policy.warmup_iterations, |_, input| {
        if let Ok(regex) = hot {
            let _ = black_box(measure_fre_search(regex, &input.haystack, operation));
        }
    });
    for_each_input_repetition(
        inputs,
        policy.measured_iterations,
        |repetition_index, input| {
            let (search_ns, state) = if let Ok(regex) = hot {
                let (elapsed, state) = measure_fre_search(regex, &input.haystack, operation);
                (Some(elapsed), state)
            } else {
                (None, build_state(hot))
            };
            samples.push(OperationTimingSample {
                input_ordinal: input.ordinal,
                repetition_index,
                compile_ns: None,
                search_ns,
                terminal_state: state.to_string(),
            });
            terminal = state.to_string();
        },
    );
    OperationTimingSeries {
        engine: TimingEngine::FreCandidate,
        case_id: case.id.clone(),
        mode: ExecutionMode::HotReuse,
        operation,
        changing_haystacks: inputs.len() > 1,
        input_count: inputs.len(),
        warmup_repetitions_per_input: policy.warmup_iterations,
        measured_repetitions_per_input: policy.measured_iterations,
        samples,
        terminal_state: terminal,
    }
}

fn time_fre_one_shot_operation(
    case: &CaseSpec,
    inputs: &[&ExpandedInput],
    operation: Operation,
    policy: TimingPolicy,
) -> OperationTimingSeries {
    for_each_input_repetition(inputs, policy.warmup_iterations, |_, input| {
        if let Ok(regex) = build_candidate(&case.pattern) {
            let _ = black_box(measure_fre_search(&regex, &input.haystack, operation));
        }
    });
    let mut samples = Vec::new();
    let mut terminal = "not-run".to_string();
    for_each_input_repetition(
        inputs,
        policy.measured_iterations,
        |repetition_index, input| {
            let compile_started = Instant::now();
            let built = build_candidate(&case.pattern);
            let compile_ns = elapsed_ns(compile_started);
            let mut search_ns = None;
            let mut state = build_state(&built);
            if let Ok(regex) = built {
                let (elapsed, search_state) =
                    measure_fre_search(&regex, &input.haystack, operation);
                search_ns = Some(elapsed);
                state = search_state;
            }
            samples.push(OperationTimingSample {
                input_ordinal: input.ordinal,
                repetition_index,
                compile_ns: Some(compile_ns),
                search_ns,
                terminal_state: state.to_string(),
            });
            terminal = state.to_string();
        },
    );
    OperationTimingSeries {
        engine: TimingEngine::FreCandidate,
        case_id: case.id.clone(),
        mode: ExecutionMode::OneShot,
        operation,
        changing_haystacks: inputs.len() > 1,
        input_count: inputs.len(),
        warmup_repetitions_per_input: policy.warmup_iterations,
        measured_repetitions_per_input: policy.measured_iterations,
        samples,
        terminal_state: terminal,
    }
}

fn for_each_input_repetition(
    inputs: &[&ExpandedInput],
    repetitions: usize,
    mut visit: impl FnMut(usize, &ExpandedInput),
) {
    for repetition_index in 0..repetitions {
        for &input in inputs {
            visit(repetition_index, input);
        }
    }
}

fn measure_fre_search(
    regex: &PortableRegex,
    haystack: &[u8],
    operation: Operation,
) -> (u64, &'static str) {
    let started = Instant::now();
    let raw = catch_unwind(AssertUnwindSafe(|| {
        execute_candidate_ordinary_inner(regex, haystack, operation)
    }));
    let elapsed = elapsed_ns(started);
    let state = if raw.is_ok() { "executed" } else { "fault" };
    let _ = black_box(raw);
    (elapsed, state)
}

fn build_timing_oracle(pattern: &str) -> Result<Regex, String> {
    match catch_unwind(AssertUnwindSafe(|| oracle_regex(pattern))) {
        Err(_) => Err("rust-regex panicked during construction".to_string()),
        Ok(Err(error)) => Err(error.to_string()),
        Ok(Ok(regex)) => Ok(regex),
    }
}

fn execute_timing_oracle(
    regex: &Regex,
    haystack: &[u8],
    operation: Operation,
) -> Result<SemanticValue, &'static str> {
    catch_unwind(AssertUnwindSafe(|| {
        oracle_value(regex, haystack, operation)
    }))
    .map_err(|_| "rust-regex panicked during search")
}

fn time_oracle_hot_operation(
    case: &CaseSpec,
    inputs: &[&ExpandedInput],
    operation: Operation,
    hot: &Result<Regex, String>,
    policy: TimingPolicy,
) -> OperationTimingSeries {
    let mut terminal = oracle_build_state(hot).to_string();
    let mut samples = Vec::new();
    for_each_input_repetition(inputs, policy.warmup_iterations, |_, input| {
        if let Ok(regex) = hot {
            let _ = black_box(measure_oracle_search(
                regex,
                black_box(&input.haystack),
                operation,
            ));
        }
    });
    for_each_input_repetition(
        inputs,
        policy.measured_iterations,
        |repetition_index, input| {
            let (search_ns, state) = if let Ok(regex) = hot {
                let (elapsed, state) =
                    measure_oracle_search(regex, black_box(&input.haystack), operation);
                (Some(elapsed), state)
            } else {
                (None, oracle_build_state(hot))
            };
            samples.push(OperationTimingSample {
                input_ordinal: input.ordinal,
                repetition_index,
                compile_ns: None,
                search_ns,
                terminal_state: state.to_string(),
            });
            terminal = state.to_string();
        },
    );
    OperationTimingSeries {
        engine: TimingEngine::RustRegexOracle,
        case_id: case.id.clone(),
        mode: ExecutionMode::HotReuse,
        operation,
        changing_haystacks: inputs.len() > 1,
        input_count: inputs.len(),
        warmup_repetitions_per_input: policy.warmup_iterations,
        measured_repetitions_per_input: policy.measured_iterations,
        samples,
        terminal_state: terminal,
    }
}

fn time_oracle_one_shot_operation(
    case: &CaseSpec,
    inputs: &[&ExpandedInput],
    operation: Operation,
    policy: TimingPolicy,
) -> OperationTimingSeries {
    for_each_input_repetition(inputs, policy.warmup_iterations, |_, input| {
        if let Ok(regex) = build_timing_oracle(black_box(&case.pattern)) {
            let _ = black_box(measure_oracle_search(
                &regex,
                black_box(&input.haystack),
                operation,
            ));
        }
    });
    let mut samples = Vec::new();
    let mut terminal = "not-run".to_string();
    for_each_input_repetition(
        inputs,
        policy.measured_iterations,
        |repetition_index, input| {
            let compile_started = Instant::now();
            let built = build_timing_oracle(black_box(&case.pattern));
            let compile_ns = elapsed_ns(compile_started);
            let mut search_ns = None;
            let mut state = oracle_build_state(&built);
            if let Ok(regex) = built {
                let (elapsed, search_state) =
                    measure_oracle_search(&regex, black_box(&input.haystack), operation);
                search_ns = Some(elapsed);
                state = search_state;
            }
            samples.push(OperationTimingSample {
                input_ordinal: input.ordinal,
                repetition_index,
                compile_ns: Some(compile_ns),
                search_ns,
                terminal_state: state.to_string(),
            });
            terminal = state.to_string();
        },
    );
    OperationTimingSeries {
        engine: TimingEngine::RustRegexOracle,
        case_id: case.id.clone(),
        mode: ExecutionMode::OneShot,
        operation,
        changing_haystacks: inputs.len() > 1,
        input_count: inputs.len(),
        warmup_repetitions_per_input: policy.warmup_iterations,
        measured_repetitions_per_input: policy.measured_iterations,
        samples,
        terminal_state: terminal,
    }
}

fn measure_oracle_search(
    regex: &Regex,
    haystack: &[u8],
    operation: Operation,
) -> (u64, &'static str) {
    let started = Instant::now();
    let outcome = execute_timing_oracle(regex, haystack, operation);
    let elapsed = elapsed_ns(started);
    let state = oracle_outcome_state(&outcome);
    let _ = black_box(outcome);
    (elapsed, state)
}

fn oracle_build_state(result: &Result<Regex, String>) -> &'static str {
    if result.is_ok() { "executed" } else { "fault" }
}

fn oracle_outcome_state(result: &Result<SemanticValue, &'static str>) -> &'static str {
    if result.is_ok() { "executed" } else { "fault" }
}

fn build_state(result: &Result<PortableRegex, CandidateFailure>) -> &'static str {
    match result {
        Ok(_) => "executed",
        Err(failure) if failure.status == Status::Unsupported => "unsupported",
        Err(_) => "fault",
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_plan_has_a_stable_receipt_name() {
        assert_eq!(plan_name(PlanKind::UnicodeWordRun), "unicode-word-run");
        assert_eq!(
            plan_name(PlanKind::UnicodeFoldedLiteral),
            "unicode-folded-literal"
        );
    }

    #[test]
    fn expanded_digest_uses_cross_width_canonical_framing() {
        let ordinal = usize::try_from(u32::MAX).expect("u32 always fits usize on supported hosts");
        let inputs = [ExpandedInput {
            case_id: "case".to_string(),
            family: "family".to_string(),
            labels: vec!["one".to_string(), "two".to_string()],
            pattern: "a+".to_string(),
            ordinal,
            intent: "golden".to_string(),
            haystack: vec![0, 0xFF, b'a'],
        }];
        assert_eq!(
            expanded_digest(&inputs).expect("golden digest"),
            "18bf911a6f4dd30ec456bab1ebdcf26af81521b1f7383b14e392933a8d92082b"
        );
    }

    #[test]
    fn input_repetition_schedule_is_a_complete_balanced_sweep() {
        let inputs = (0..3)
            .map(|ordinal| ExpandedInput {
                case_id: "case".to_string(),
                family: "family".to_string(),
                labels: Vec::new(),
                pattern: "a".to_string(),
                ordinal,
                intent: "schedule".to_string(),
                haystack: vec![b'a'],
            })
            .collect::<Vec<_>>();
        let input_refs = inputs.iter().collect::<Vec<_>>();
        let mut visits = Vec::new();
        for_each_input_repetition(&input_refs, 2, |repetition_index, input| {
            visits.push((repetition_index, input.ordinal));
        });
        assert_eq!(visits, vec![(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]);
    }

    #[test]
    fn ordinary_accounted_and_rust_surfaces_have_value_parity() {
        for (pattern, haystack) in [
            (r"(?:a+b|a)", b"xxaaabyy".as_slice()),
            (r"(?m:^a+)", b"z\naaa\nz".as_slice()),
            (r"a{0,100}b", b"aaaaaaaaab".as_slice()),
        ] {
            let regex = build_candidate(pattern).expect("comparison fixture builds");
            let rust = oracle_regex(pattern).expect("comparison oracle builds");
            for operation in [Operation::Find, Operation::Exists, Operation::SelectedEnd] {
                let accounted =
                    execute_candidate_inner(&regex, haystack, operation, SearchLimits::default())
                        .expect("accounting correctness surface executes")
                        .0;
                let ordinary = execute_candidate_ordinary_inner(&regex, haystack, operation);
                let rust = execute_timing_oracle(&rust, haystack, operation)
                    .expect("Rust comparison surface executes");
                assert_eq!(
                    ordinary, accounted,
                    "ordinary/accounted mismatch: pattern={pattern:?} operation={operation:?}"
                );
                assert_eq!(
                    ordinary, rust,
                    "ordinary/Rust mismatch: pattern={pattern:?} operation={operation:?}"
                );
            }
        }
    }

    #[test]
    fn ordinary_oracle_check_precedes_an_explicit_finite_refusal() {
        let accounted = build_candidate("a");
        let ordinary = build_candidate("a");
        let refusing = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };

        let correct = execute_candidate_with_ordinary_parity_and_limits(
            &accounted,
            &ordinary,
            b"a",
            Operation::Exists,
            &SemanticValue::Boolean(true),
            refusing,
        );
        match correct {
            CandidateOutcome::Failure(failure) => {
                assert_eq!(failure.status, Status::Unsupported);
                assert_ne!(failure.code, "search.semantic.ordinary-oracle-parity");
            }
            CandidateOutcome::Executed { .. } => {
                panic!("zero finite limits unexpectedly executed")
            }
        }

        let deliberately_wrong_oracle = execute_candidate_with_ordinary_parity_and_limits(
            &accounted,
            &ordinary,
            b"a",
            Operation::Exists,
            &SemanticValue::Boolean(false),
            refusing,
        );
        match deliberately_wrong_oracle {
            CandidateOutcome::Failure(failure) => {
                assert_eq!(failure.status, Status::Fail);
                assert_eq!(failure.code, "search.semantic.ordinary-oracle-parity");
            }
            CandidateOutcome::Executed { .. } => {
                panic!("wrong ordinary oracle unexpectedly passed")
            }
        }
    }

    #[test]
    fn checked_search_limit_refusal_is_unsupported_but_default_executes() {
        let regex = build_candidate("needle").expect("default literal build");
        let haystack = b"xxneedleyy";
        let default = execute_candidate(&regex, haystack, Operation::Find);
        let needed = match default {
            CandidateOutcome::Executed { value, work, .. } => {
                assert_eq!(
                    value,
                    SemanticValue::Span(Some(SpanValue { start: 2, end: 8 }))
                );
                work
            }
            CandidateOutcome::Failure(failure) => {
                panic!("default search failed: {}", failure.reason)
            }
        };
        let limited = execute_candidate_with_limits(
            &regex,
            haystack,
            Operation::Find,
            SearchLimits {
                max_work: needed.checked_sub(1).expect("literal work is positive"),
                max_scratch_bytes: SearchLimits::default().max_scratch_bytes,
            },
        );
        match limited {
            CandidateOutcome::Failure(failure) => {
                assert_eq!(failure.status, Status::Unsupported);
                assert_eq!(failure.code, "search.resource.literal-linear-terms");
            }
            CandidateOutcome::Executed { .. } => panic!("one-below search limit executed"),
        }
    }

    #[test]
    fn checked_build_limit_refusal_is_unsupported_but_default_executes() {
        let default = build_candidate("a").expect("default literal build");
        let needed = default.build_report().planner_work;
        assert!(needed > 0);
        let limits = BuildLimits {
            max_planner_work: needed.checked_sub(1).expect("planner work is positive"),
            ..BuildLimits::default()
        };
        let failure = build_candidate_with_limits("a", &limits)
            .expect_err("one-below planner limit must refuse");
        assert_eq!(failure.status, Status::Unsupported);
        assert_eq!(failure.code, "build.resource.planner-work");
    }

    #[test]
    fn typed_resource_and_invariant_errors_do_not_alias() {
        let resource = classify_search_error(&SearchError::K0(
            fre_automata::SearchError::WorkLimitExceeded {
                limit: 1,
                consumed: 1,
                requested: 1,
                position: 0,
            },
        ));
        assert_eq!(resource.status, Status::Unsupported);
        assert_eq!(resource.code, "search.resource.k0");

        let invariant = classify_search_error(&SearchError::K0(
            fre_automata::SearchError::InternalInvariant { detail: "test" },
        ));
        assert_eq!(invariant.status, Status::Fault);
        assert_eq!(invariant.code, "search.fault.k0");

        let planner = classify_build_error(&BuildError::PlannerWorkLimit {
            needed: 2,
            limit: 1,
        });
        assert_eq!(planner.status, Status::Unsupported);
        assert_eq!(planner.code, "build.resource.planner-work");
    }
}
