//! Deterministic expansion of a pinned Rebar benchmark checkout.
//!
//! This crate resolves Rebar's static TOML and data-file transformations. It
//! deliberately does not claim that an engine is installed, that a benchmark
//! executes successfully, or that two engines have equivalent semantics.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::Arc,
};

use bstr::ByteSlice;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Manifest schema emitted by this crate.
pub const SCHEMA: &str = "fre.rebar.expanded.v1";

/// Rebar revision this expander has been audited against.
pub const AUDITED_REBAR_REVISION: &str = "463d00f31887e84c38467805b9e3122c314b9521";

const TARGET_ENGINES: [&str; 2] = ["re2", "rust/regex"];

/// Checked resource limits used while resolving source inputs.
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    /// Maximum definition files accepted.
    pub definition_files: usize,
    /// Maximum bytes read from one source file.
    pub source_file_bytes: usize,
    /// Maximum bytes in one transformed pattern or haystack.
    pub transformed_bytes: usize,
    /// Maximum number of benchmark definitions.
    pub definitions: usize,
    /// Maximum number of emitted jobs.
    pub jobs: usize,
    /// Maximum number of patterns in one definition.
    pub patterns_per_definition: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            definition_files: 1_024,
            source_file_bytes: 512 * 1_024 * 1_024,
            transformed_bytes: 512 * 1_024 * 1_024,
            definitions: 100_000,
            jobs: 100_000,
            patterns_per_definition: 1_000_000,
        }
    }
}

/// Expansion request.
#[derive(Clone, Debug)]
pub struct ExpandConfig {
    /// Root of the pinned Rebar checkout.
    pub checkout: PathBuf,
    /// Rebar binary used only as a normalized list oracle.
    pub rebar_bin: PathBuf,
    /// Required source revision.
    pub expected_revision: String,
    /// Resource limits.
    pub limits: Limits,
}

/// A fully expanded, deterministic qualification manifest.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Manifest {
    /// Schema identifier.
    pub schema: String,
    /// Pinned source identity.
    pub source: SourceIdentity,
    /// Scope and cardinalities.
    pub scope: Scope,
    /// Every TOML definition file, including files with no selected jobs.
    pub definition_files: Vec<DefinitionFile>,
    /// Benchmark definitions excluded because neither target was listed.
    pub exclusions: Vec<Exclusion>,
    /// Static adapter configurations and explicitly unresolved dynamic state.
    pub adapters: Vec<Adapter>,
    /// Exact shared reducer/timing contracts.
    pub model_contracts: Vec<ModelContract>,
    /// Expanded target jobs.
    pub jobs: Vec<Job>,
    /// Comparison against Rebar's normalized `measure --list` output.
    pub validation: Validation,
    /// Claims this artifact explicitly does not make.
    pub unresolved: Vec<String>,
}

/// Pinned Rebar source identity.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SourceIdentity {
    /// Upstream repository URL.
    pub repository: String,
    /// Full Git revision observed locally.
    pub revision: String,
    /// Whether tracked source files differ from the revision.
    pub tracked_worktree_clean: bool,
    /// Hash of the checked-in benchmark engine configuration.
    pub engines_toml_sha256: String,
}

/// Manifest scope.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Scope {
    /// Selected high-level engine names.
    pub engines: Vec<String>,
    /// TOML files inventoried.
    pub definition_file_count: usize,
    /// Benchmark definitions decoded.
    pub definition_count: usize,
    /// Jobs emitted after engine selection.
    pub job_count: usize,
    /// Distinct benchmark names among jobs.
    pub selected_definition_count: usize,
    /// Target jobs per engine.
    pub jobs_by_engine: BTreeMap<String, usize>,
    /// Target jobs per Rebar model.
    pub jobs_by_model: BTreeMap<String, usize>,
}

/// Inventory record for one definition file.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct DefinitionFile {
    /// Checkout-relative path.
    pub path: String,
    /// SHA-256 of source bytes.
    pub sha256: String,
    /// Source byte length.
    pub bytes: usize,
    /// Definitions decoded from this file.
    pub definitions: usize,
    /// Jobs selected from this file.
    pub selected_jobs: usize,
    /// Static decode status.
    pub status: String,
    /// Error, if one occurred. Successful generation keeps this null.
    pub error: Option<String>,
}

/// An explicit benchmark-level exclusion.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Exclusion {
    /// Full Rebar benchmark name.
    pub benchmark: String,
    /// Stable source location.
    pub provenance: Provenance,
    /// Engines listed by the definition.
    pub listed_engines: Vec<String>,
    /// Stable exclusion reason.
    pub reason: String,
}

/// Stable provenance for a decoded `[[bench]]` table.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Provenance {
    /// Checkout-relative TOML path.
    pub definition_file: String,
    /// Zero-based `[[bench]]` index within the file.
    pub bench_index: usize,
    /// Hash of the containing TOML source.
    pub definition_file_sha256: String,
}

/// Static configuration of a selected adapter.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Adapter {
    /// Rebar engine name.
    pub engine: String,
    /// Exact configured working directory, relative to `benchmarks`.
    pub configured_cwd: String,
    /// Exact run command from `engines.toml`.
    pub run: AdapterCommand,
    /// Exact version-receipt command from `engines.toml`.
    pub version: AdapterVersion,
    /// Build commands, not executed by this tool.
    pub build: Vec<AdapterCommand>,
    /// Clean commands, not executed by this tool.
    pub clean: Vec<AdapterCommand>,
    /// Dependency commands, not executed by this tool.
    pub dependencies: Vec<AdapterDependency>,
    /// Adapter and binding sources that define timed behavior.
    pub evidence: Vec<SourceFile>,
    /// Audited engine-specific compile configuration.
    pub compile_configuration: Vec<String>,
    /// Exact noteworthy adapter dependency configuration.
    pub dependency_configuration: Vec<String>,
    /// Explicit runtime availability state.
    pub runtime_availability: String,
}

/// A command from Rebar's engine configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdapterCommand {
    /// Optional command-specific working directory.
    pub cwd: Option<String>,
    /// Executable name/path.
    pub bin: String,
    /// Argument vector.
    pub args: Vec<String>,
    /// Environment variables.
    pub envs: Vec<AdapterEnv>,
}

/// Environment assignment in a command.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdapterEnv {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// Version receipt configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdapterVersion {
    /// Command, when command-based.
    pub command: Option<AdapterCommand>,
    /// File, when file-based.
    pub file: Option<String>,
    /// Extraction expression, when configured.
    pub regex: Option<String>,
}

/// Dependency receipt configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AdapterDependency {
    /// Command to run.
    pub command: AdapterCommand,
    /// Optional success expression.
    pub regex: Option<String>,
}

/// Hashed checkout source used as adapter evidence.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SourceFile {
    /// Checkout-relative path.
    pub path: String,
    /// SHA-256.
    pub sha256: String,
    /// Byte length.
    pub bytes: usize,
}

/// Shared semantic contract for one Rebar model.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ModelContract {
    /// Rebar model name.
    pub model: String,
    /// Value compared with `count` in the definition.
    pub reducer: String,
    /// Exact timed boundary in the two selected adapters.
    pub timed_boundary: String,
    /// Work outside the sample duration that is still used for verification.
    pub untimed_verification: String,
    /// Empty-match/line/capture details that affect equivalence.
    pub iteration_semantics: String,
}

/// One expanded `(definition, engine)` job.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Job {
    /// Stable `benchmark@engine` identifier.
    pub id: String,
    /// Full Rebar benchmark name.
    pub benchmark: String,
    /// Engine name.
    pub engine: String,
    /// Rebar model.
    pub model: String,
    /// Source provenance.
    pub provenance: Provenance,
    /// Expanded regex inputs and syntax flags.
    pub regex: ExpandedRegex,
    /// Expanded haystack identity and transformation recipe.
    pub haystack: ExpandedHaystack,
    /// Engine-specific expected reducer result.
    pub expected: ExpectedResult,
    /// Default Rebar measurement controls. CLI overrides are unresolved.
    pub measurement: MeasurementDefaults,
    /// Required source/data inputs.
    pub required_files: Vec<SourceFile>,
    /// Static and dynamic availability state.
    pub availability: Availability,
}

/// Exact transformed regex input.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExpandedRegex {
    /// Ordered transformed patterns. Each digest names a raw blob file.
    pub patterns: Vec<PatternBlob>,
    /// Definition-level case-insensitive flag.
    pub case_insensitive: bool,
    /// Definition-level Unicode flag.
    pub unicode: bool,
    /// Original source identity.
    pub source: InputSource,
    /// Transform recipe in Rebar execution order.
    pub transforms: RegexTransforms,
}

/// One transformed UTF-8 pattern blob.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PatternBlob {
    /// Pattern position in `build_many`/definition order.
    pub ordinal: usize,
    /// SHA-256 of exact UTF-8 bytes.
    pub sha256: String,
    /// Byte length.
    pub bytes: usize,
    /// Checkout-output-relative raw blob path.
    pub blob: String,
}

/// Exact transformed haystack identity.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExpandedHaystack {
    /// SHA-256 of exact transformed bytes.
    pub sha256: String,
    /// Transformed byte length.
    pub bytes: usize,
    /// Whether transformed bytes are valid UTF-8.
    pub valid_utf8: bool,
    /// Original source identity.
    pub source: InputSource,
    /// Transform recipe in Rebar execution order.
    pub transforms: HaystackTransforms,
}

/// Inline or checkout-file source identity before transformations.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct InputSource {
    /// `inline` or `file`.
    pub kind: String,
    /// Checkout-relative path for a file source.
    pub path: Option<String>,
    /// Canonical interpretation of the hashed source bytes.
    pub encoding: String,
    /// Hash before transformations.
    pub sha256: String,
    /// Byte length before transformations.
    pub bytes: usize,
}

/// Rebar regex transformation configuration.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct RegexTransforms {
    /// Escape each source pattern with `regex_lite::escape`.
    pub literal: bool,
    /// `none`, `alternate`, or `pattern`.
    pub per_line: String,
    /// Prefix after literal escaping.
    pub prepend: Option<String>,
    /// Suffix after prefixing.
    pub append: Option<String>,
}

impl Default for RegexTransforms {
    fn default() -> Self {
        Self {
            literal: false,
            per_line: "none".to_string(),
            prepend: None,
            append: None,
        }
    }
}

/// Rebar haystack transformation configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(default)]
pub struct HaystackTransforms {
    /// Replace invalid UTF-8 with U+FFFD first.
    #[serde(alias = "utf8-lossy")]
    pub utf8_lossy: bool,
    /// Trim bstr whitespace second.
    pub trim: bool,
    /// Zero-based first line after trimming.
    #[serde(alias = "line-start")]
    pub line_start: Option<usize>,
    /// Exclusive zero-based line end after trimming.
    #[serde(alias = "line-end")]
    pub line_end: Option<usize>,
    /// Repeat count after line selection.
    pub repeat: Option<usize>,
    /// UTF-8 bytes inserted after repetition.
    pub prepend: Option<String>,
    /// UTF-8 bytes appended last.
    pub append: Option<String>,
}

/// Expected engine-specific reducer result.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExpectedResult {
    /// Numeric result required by Rebar.
    pub count: u64,
    /// Original rule: scalar or first matching engine regex.
    pub selected_by: String,
    /// Model contract reference.
    pub reducer_contract: String,
}

/// Rebar `measure` defaults at the audited revision.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MeasurementDefaults {
    /// Maximum measured iterations.
    pub max_iters: u64,
    /// Maximum warmup iterations.
    pub max_warmup_iters: u64,
    /// Maximum measured wall time in nanoseconds.
    pub max_time_ns: u64,
    /// Maximum warmup wall time in nanoseconds.
    pub max_warmup_time_ns: u64,
    /// Process timeout in nanoseconds.
    pub timeout_ns: u64,
    /// Stopping rule.
    pub stop_rule: String,
    /// Override state.
    pub overrides: String,
}

/// Availability without conflating static presence with dynamic execution.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Availability {
    /// Definition, pattern and haystack sources resolved.
    pub static_inputs: String,
    /// Adapter executable/dependency/version status.
    pub engine_runtime: String,
    /// Whether the job has actually passed its expected result.
    pub semantic_execution: String,
}

/// Rebar list-oracle validation.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Validation {
    /// Normalized rows compared exactly, excluding dynamic version receipts.
    pub status: String,
    /// Number of normalized rows.
    pub normalized_row_count: usize,
    /// SHA-256 over sorted `name\0model\0engine\n` rows.
    pub normalized_rows_sha256: String,
    /// Counts reported by the normalized list output.
    pub rows_by_engine: BTreeMap<String, usize>,
    /// Result of direct KLV byte comparison for transformation representatives.
    pub representative_klv_status: String,
    /// Benchmarks whose model, patterns, flags and haystack bytes were compared.
    pub representative_klv_benchmarks: Vec<String>,
    /// Why the version column is not persisted.
    pub dynamic_fields_ignored: Vec<String>,
}

/// Error from checked expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandError(String);

impl fmt::Display for ExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ExpandError {}

impl ExpandError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFile {
    #[serde(rename = "bench", default)]
    benches: Vec<WireBench>,
    analysis: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WireBench {
    model: String,
    name: String,
    regex: WireRegex,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    unicode: bool,
    haystack: WireHaystack,
    count: WireCount,
    engines: Vec<String>,
    analysis: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum WireRegex {
    Inline(WirePatterns),
    Full(WireRegexFull),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum WirePatterns {
    One(String),
    Many(Vec<String>),
}

impl WirePatterns {
    fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(pattern) => vec![pattern.clone()],
            Self::Many(patterns) => patterns.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WireRegexFull {
    patterns: Option<WirePatterns>,
    path: Option<String>,
    #[serde(flatten)]
    transforms: WireRegexTransforms,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct WireRegexTransforms {
    #[serde(default)]
    literal: bool,
    #[serde(default)]
    per_line: WirePerLine,
    prepend: Option<String>,
    append: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WirePerLine {
    #[default]
    None,
    Alternate,
    Pattern,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum WireHaystack {
    Inline(String),
    Full(WireHaystackFull),
}

#[derive(Clone, Debug, Deserialize)]
struct WireHaystackFull {
    contents: Option<String>,
    path: Option<String>,
    #[serde(flatten)]
    transforms: HaystackTransforms,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum WireCount {
    Engines(Vec<WireEngineCount>),
    All(u64),
}

#[derive(Clone, Debug, Deserialize)]
struct WireEngineCount {
    engine: String,
    count: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct WireEngines {
    #[serde(rename = "engine", default)]
    engines: Vec<WireEngine>,
}

#[derive(Clone, Debug, Deserialize)]
struct WireEngine {
    name: String,
    cwd: Option<String>,
    run: WireCommand,
    version: WireVersion,
    #[serde(default)]
    dependency: Vec<WireDependency>,
    #[serde(default)]
    build: Vec<WireCommand>,
    #[serde(default)]
    clean: Vec<WireCommand>,
}

#[derive(Clone, Debug, Deserialize)]
struct WireCommand {
    cwd: Option<String>,
    bin: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    envs: Vec<AdapterEnv>,
}

#[derive(Clone, Debug, Deserialize)]
struct WireVersion {
    file: Option<String>,
    regex: Option<String>,
    cwd: Option<String>,
    bin: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    envs: Vec<AdapterEnv>,
}

#[derive(Clone, Debug, Deserialize)]
struct WireDependency {
    regex: Option<String>,
    cwd: Option<String>,
    bin: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    envs: Vec<AdapterEnv>,
}

#[derive(Clone, Debug)]
struct ResolvedRegex {
    patterns: Vec<Vec<u8>>,
    source: InputSource,
    transforms: RegexTransforms,
    required_file: Option<SourceFile>,
}

#[derive(Clone, Debug)]
struct ResolvedHaystack {
    bytes: Vec<u8>,
    sha256: String,
    valid_utf8: bool,
    source: InputSource,
    transforms: HaystackTransforms,
    required_file: Option<SourceFile>,
}

/// Expand the pinned source and validate its normalized job set against Rebar.
#[allow(
    clippy::too_many_lines,
    reason = "top-level orchestration keeps the expansion transaction and its audit order visible"
)]
pub fn expand(config: &ExpandConfig) -> Result<(Manifest, BTreeMap<String, Vec<u8>>), ExpandError> {
    let checkout = canonical(&config.checkout, "checkout")?;
    let revision = command_text(
        Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD"]),
        "read Rebar Git revision",
    )?;
    if revision != config.expected_revision {
        return Err(ExpandError::new(format!(
            "Rebar revision mismatch: expected {}, observed {revision}",
            config.expected_revision
        )));
    }
    let dirty = !command_success(
        Command::new("git").arg("-C").arg(&checkout).args([
            "diff",
            "--quiet",
            "--ignore-submodules",
            "HEAD",
            "--",
        ]),
        "inspect Rebar tracked worktree",
    )?;

    let bench_root = checkout.join("benchmarks");
    let definition_root = bench_root.join("definitions");
    let engine_path = bench_root.join("engines.toml");
    let engine_bytes = read_checked(&engine_path, &config.limits)?;
    let wire_engines: WireEngines = toml::from_slice(&engine_bytes)
        .map_err(|error| ExpandError::new(format!("decode {}: {error}", engine_path.display())))?;
    let adapters = resolve_adapters(&checkout, &wire_engines, &config.limits)?;

    let mut paths = definition_paths(&definition_root)?;
    if paths.len() > config.limits.definition_files {
        return Err(ExpandError::new(format!(
            "definition file limit exceeded: {} > {}",
            paths.len(),
            config.limits.definition_files
        )));
    }
    paths.sort();

    let mut definition_files = Vec::with_capacity(paths.len());
    let mut exclusions = vec![];
    let mut jobs = vec![];
    let mut blobs = BTreeMap::new();
    let mut regex_cache: BTreeMap<(String, RegexTransforms), Arc<ResolvedRegex>> = BTreeMap::new();
    let mut haystack_cache: BTreeMap<(String, HaystackTransforms), Arc<ResolvedHaystack>> =
        BTreeMap::new();
    let mut definition_count = 0usize;
    for path in paths {
        let bytes = read_checked(&path, &config.limits)?;
        let file_hash = sha256(&bytes);
        let relative = relative_string(&checkout, &path)?;
        let group = group_name(&definition_root, &path)?;
        let wire: WireFile = toml::from_slice(&bytes)
            .map_err(|error| ExpandError::new(format!("decode {relative}: {error}")))?;
        let _ = &wire.analysis;
        definition_count = definition_count
            .checked_add(wire.benches.len())
            .ok_or_else(|| ExpandError::new("definition count overflow"))?;
        if definition_count > config.limits.definitions {
            return Err(ExpandError::new(format!(
                "definition limit exceeded: {definition_count} > {}",
                config.limits.definitions
            )));
        }
        let first_job = jobs.len();
        for (bench_index, bench) in wire.benches.into_iter().enumerate() {
            let benchmark = format!("{group}/{}", bench.name);
            let provenance = Provenance {
                definition_file: relative.clone(),
                bench_index,
                definition_file_sha256: file_hash.clone(),
            };
            let selected: Vec<&str> = TARGET_ENGINES
                .iter()
                .copied()
                .filter(|target| bench.engines.iter().any(|engine| engine == target))
                .collect();
            if selected.is_empty() {
                exclusions.push(Exclusion {
                    benchmark,
                    provenance,
                    listed_engines: bench.engines,
                    reason: "definition does not list rust/regex or re2".to_string(),
                });
                continue;
            }
            let resolved_regex =
                resolve_regex_cached(&checkout, &bench.regex, &config.limits, &mut regex_cache)?;
            let resolved_haystack = resolve_haystack_cached(
                &checkout,
                &bench.haystack,
                &config.limits,
                &mut haystack_cache,
            )?;
            if resolved_regex.patterns.len() > config.limits.patterns_per_definition {
                return Err(ExpandError::new(format!(
                    "pattern limit exceeded for {benchmark}: {} > {}",
                    resolved_regex.patterns.len(),
                    config.limits.patterns_per_definition
                )));
            }
            let pattern_blobs = materialize_patterns(&resolved_regex.patterns, &mut blobs);
            for engine in selected {
                if engine == "re2" && bench.model != "regex-redux" && pattern_blobs.len() != 1 {
                    return Err(ExpandError::new(format!(
                        "RE2 adapter requires exactly one pattern for {benchmark}, got {}",
                        pattern_blobs.len()
                    )));
                }
                let (expected_count, selected_by) = expected_count(&bench.count, engine)?;
                let mut required_files = vec![SourceFile {
                    path: relative.clone(),
                    sha256: file_hash.clone(),
                    bytes: bytes.len(),
                }];
                if let Some(source) = &resolved_regex.required_file {
                    required_files.push(source.clone());
                }
                if let Some(source) = &resolved_haystack.required_file {
                    required_files.push(source.clone());
                }
                required_files.sort_by(|left, right| left.path.cmp(&right.path));
                required_files.dedup_by(|left, right| left.path == right.path);
                jobs.push(Job {
                    id: format!("{benchmark}@{engine}"),
                    benchmark: benchmark.clone(),
                    engine: engine.to_string(),
                    model: bench.model.clone(),
                    provenance: provenance.clone(),
                    regex: ExpandedRegex {
                        patterns: pattern_blobs.clone(),
                        case_insensitive: bench.case_insensitive,
                        unicode: bench.unicode,
                        source: resolved_regex.source.clone(),
                        transforms: resolved_regex.transforms.clone(),
                    },
                    haystack: ExpandedHaystack {
                        sha256: resolved_haystack.sha256.clone(),
                        bytes: resolved_haystack.bytes.len(),
                        valid_utf8: resolved_haystack.valid_utf8,
                        source: resolved_haystack.source.clone(),
                        transforms: resolved_haystack.transforms.clone(),
                    },
                    expected: ExpectedResult {
                        count: expected_count,
                        selected_by,
                        reducer_contract: format!("model:{}", bench.model),
                    },
                    measurement: measurement_defaults(),
                    required_files,
                    availability: Availability {
                        static_inputs: "available-and-hash-verified-in-pinned-checkout".to_string(),
                        engine_runtime: "unresolved-dynamic-version/dependency/build-receipt-not-executed-by-expander".to_string(),
                        semantic_execution: "unverified-job-not-run".to_string(),
                    },
                });
                if jobs.len() > config.limits.jobs {
                    return Err(ExpandError::new(format!(
                        "job limit exceeded: {} > {}",
                        jobs.len(),
                        config.limits.jobs
                    )));
                }
            }
            let _ = &bench.analysis;
        }
        definition_files.push(DefinitionFile {
            path: relative,
            sha256: file_hash,
            bytes: bytes.len(),
            definitions: definition_count_for_file(&bytes)?,
            selected_jobs: jobs
                .len()
                .checked_sub(first_job)
                .ok_or_else(|| ExpandError::new("selected job count underflow"))?,
            status: "decoded".to_string(),
            error: None,
        });
    }

    jobs.sort_by(|left, right| left.id.cmp(&right.id));
    exclusions.sort_by(|left, right| left.benchmark.cmp(&right.benchmark));
    let mut validation = validate_rebar_list(&checkout, &config.rebar_bin, &jobs)?;
    validation.representative_klv_benchmarks =
        validate_representative_klv(&checkout, &config.rebar_bin, &jobs)?;
    validation.representative_klv_status = "exact-byte-match".to_string();
    let scope = make_scope(definition_files.len(), definition_count, &jobs)?;
    let manifest = Manifest {
        schema: SCHEMA.to_string(),
        source: SourceIdentity {
            repository: "https://github.com/BurntSushi/rebar".to_string(),
            revision,
            tracked_worktree_clean: !dirty,
            engines_toml_sha256: sha256(&engine_bytes),
        },
        scope,
        definition_files,
        exclusions,
        adapters,
        model_contracts: model_contracts(),
        jobs,
        validation,
        unresolved: vec![
            "runtime engine availability and version receipts are dynamic and were not persisted"
                .to_string(),
            "benchmark jobs have not been executed or semantically compared".to_string(),
            "Rebar command-line overrides to measurement defaults are execution-time inputs"
                .to_string(),
            "speed measurements and claims are outside this static expansion artifact".to_string(),
            "cross-engine equivalence of engine-specific expected counts remains unverified"
                .to_string(),
        ],
    };
    Ok((manifest, blobs))
}

/// Write a manifest, its digest, raw pattern blobs and a human summary.
pub fn write_output(
    output: &Path,
    manifest: &Manifest,
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<(), ExpandError> {
    let blob_dir = output.join("blobs");
    fs::create_dir_all(&blob_dir)
        .map_err(|error| ExpandError::new(format!("create {}: {error}", blob_dir.display())))?;
    for (digest, bytes) in blobs {
        let path = blob_dir.join(format!("sha256-{digest}.pattern"));
        fs::write(&path, bytes)
            .map_err(|error| ExpandError::new(format!("write {}: {error}", path.display())))?;
    }
    let encoded = serde_json::to_vec(manifest)
        .map_err(|error| ExpandError::new(format!("encode manifest JSON: {error}")))?;
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, &encoded)
        .map_err(|error| ExpandError::new(format!("write {}: {error}", manifest_path.display())))?;
    let digest = format!("{}  manifest.json\n", sha256(&encoded));
    fs::write(output.join("manifest.sha256"), digest)
        .map_err(|error| ExpandError::new(format!("write manifest digest: {error}")))?;
    fs::write(output.join("README.md"), summary(manifest, blobs.len()))
        .map_err(|error| ExpandError::new(format!("write summary: {error}")))?;
    Ok(())
}

/// Human-readable, claim-limited manifest summary.
#[must_use]
pub fn summary(manifest: &Manifest, blob_count: usize) -> String {
    let rust = manifest
        .scope
        .jobs_by_engine
        .get("rust/regex")
        .copied()
        .unwrap_or(0);
    let re2 = manifest
        .scope
        .jobs_by_engine
        .get("re2")
        .copied()
        .unwrap_or(0);
    format!(
        "# Expanded Rebar qualification inputs\n\n\
         This is a **static input manifest**, not a correctness or speed result. It expands the\n\
         pinned Rebar revision `{revision}` for the high-level `rust/regex` and `re2`\n\
         adapters. Runtime availability, semantic comparison and timing remain explicitly\n\
         unresolved.\n\n\
         - Definition files inventoried: {files}\n\
         - Benchmark definitions decoded: {definitions}\n\
         - Selected jobs: {jobs} (`rust/regex`: {rust}, `re2`: {re2})\n\
         - Excluded definitions retained: {excluded}\n\
         - Unique transformed pattern blobs: {blob_count}\n\
         - Rebar normalized list check: {validation}\n\
         - Representative Rebar KLV byte checks: {klv_count} ({klv_status})\n\n\
         `manifest.json` is compact JSON. `manifest.sha256` authenticates it. Exact\n\
         transformed patterns live under `blobs/`; transformed haystacks are identified by\n\
         byte length and SHA-256 plus a reproducible source/transform recipe, avoiding a\n\
         duplicate copy of Rebar's large data files.\n",
        revision = manifest.source.revision,
        files = manifest.scope.definition_file_count,
        definitions = manifest.scope.definition_count,
        jobs = manifest.scope.job_count,
        excluded = manifest.exclusions.len(),
        validation = manifest.validation.status,
        klv_count = manifest.validation.representative_klv_benchmarks.len(),
        klv_status = manifest.validation.representative_klv_status,
    )
}

fn resolve_regex_cached(
    checkout: &Path,
    wire: &WireRegex,
    limits: &Limits,
    cache: &mut BTreeMap<(String, RegexTransforms), Arc<ResolvedRegex>>,
) -> Result<Arc<ResolvedRegex>, ExpandError> {
    let key = match wire {
        WireRegex::Full(full) => full
            .path
            .as_ref()
            .map(|path| (path.clone(), public_regex_transforms(&full.transforms))),
        WireRegex::Inline(_) => None,
    };
    if let Some(key) = key {
        if let Some(resolved) = cache.get(&key) {
            return Ok(Arc::clone(resolved));
        }
        let resolved = Arc::new(resolve_regex(checkout, wire, limits)?);
        cache.insert(key, Arc::clone(&resolved));
        Ok(resolved)
    } else {
        Ok(Arc::new(resolve_regex(checkout, wire, limits)?))
    }
}

fn resolve_haystack_cached(
    checkout: &Path,
    wire: &WireHaystack,
    limits: &Limits,
    cache: &mut BTreeMap<(String, HaystackTransforms), Arc<ResolvedHaystack>>,
) -> Result<Arc<ResolvedHaystack>, ExpandError> {
    let key = match wire {
        WireHaystack::Full(full) => full
            .path
            .as_ref()
            .map(|path| (path.clone(), full.transforms.clone())),
        WireHaystack::Inline(_) => None,
    };
    if let Some(key) = key {
        if let Some(resolved) = cache.get(&key) {
            return Ok(Arc::clone(resolved));
        }
        let resolved = Arc::new(resolve_haystack(checkout, wire, limits)?);
        cache.insert(key, Arc::clone(&resolved));
        Ok(resolved)
    } else {
        Ok(Arc::new(resolve_haystack(checkout, wire, limits)?))
    }
}

fn resolve_regex(
    checkout: &Path,
    wire: &WireRegex,
    limits: &Limits,
) -> Result<ResolvedRegex, ExpandError> {
    match wire {
        WireRegex::Inline(patterns) => {
            let strings = patterns.to_vec();
            let raw = encode_pattern_sequence(&strings, limits)?;
            let transformed =
                checked_pattern_transform(strings, &WireRegexTransforms::default(), limits)?;
            Ok(ResolvedRegex {
                patterns: transformed.into_iter().map(String::into_bytes).collect(),
                source: InputSource {
                    kind: "inline".to_string(),
                    path: None,
                    encoding: "u64le-length-prefixed-utf8-pattern-sequence".to_string(),
                    sha256: sha256(&raw),
                    bytes: raw.len(),
                },
                transforms: RegexTransforms::default(),
                required_file: None,
            })
        }
        WireRegex::Full(full) => {
            if full.path.is_some() == full.patterns.is_some() {
                return Err(ExpandError::new(
                    "full regex must define exactly one of path or patterns",
                ));
            }
            let transforms = public_regex_transforms(&full.transforms);
            match (&full.path, &full.patterns) {
                (Some(path), None) => {
                    let source_path =
                        checked_input_path(&checkout.join("benchmarks/regexes"), path, "regex")?;
                    let raw = read_checked(&source_path, limits)?;
                    let text = std::str::from_utf8(&raw).map_err(|error| {
                        ExpandError::new(format!(
                            "regex source {} is not UTF-8: {error}",
                            source_path.display()
                        ))
                    })?;
                    let initial = match full.transforms.per_line {
                        WirePerLine::None => vec![text.trim().to_string()],
                        WirePerLine::Alternate | WirePerLine::Pattern => {
                            text.lines().map(str::to_string).collect()
                        }
                    };
                    let mut transformed =
                        checked_pattern_transform(initial, &full.transforms, limits)?;
                    if matches!(full.transforms.per_line, WirePerLine::Alternate) {
                        for pattern in &mut transformed {
                            *pattern = format!("(?:{pattern})");
                            check_len(
                                pattern.len(),
                                limits.transformed_bytes,
                                "alternate pattern",
                            )?;
                        }
                        let joined = transformed.join("|");
                        check_len(
                            joined.len(),
                            limits.transformed_bytes,
                            "joined alternate pattern",
                        )?;
                        transformed = vec![joined];
                    }
                    let source = source_file(checkout, &source_path, &raw)?;
                    Ok(ResolvedRegex {
                        patterns: transformed.into_iter().map(String::into_bytes).collect(),
                        source: InputSource {
                            kind: "file".to_string(),
                            path: Some(source.path.clone()),
                            encoding: "raw-file-utf8".to_string(),
                            sha256: source.sha256.clone(),
                            bytes: source.bytes,
                        },
                        transforms,
                        required_file: Some(source),
                    })
                }
                (None, Some(patterns)) => {
                    let strings = patterns.to_vec();
                    let raw = encode_pattern_sequence(&strings, limits)?;
                    // Rebar intentionally ignores `per-line` for inline full regexes.
                    let transformed = checked_pattern_transform(strings, &full.transforms, limits)?;
                    Ok(ResolvedRegex {
                        patterns: transformed.into_iter().map(String::into_bytes).collect(),
                        source: InputSource {
                            kind: "inline".to_string(),
                            path: None,
                            encoding: "u64le-length-prefixed-utf8-pattern-sequence".to_string(),
                            sha256: sha256(&raw),
                            bytes: raw.len(),
                        },
                        transforms,
                        required_file: None,
                    })
                }
                _ => Err(ExpandError::new("unreachable regex source shape")),
            }
        }
    }
}

fn resolve_haystack(
    checkout: &Path,
    wire: &WireHaystack,
    limits: &Limits,
) -> Result<ResolvedHaystack, ExpandError> {
    match wire {
        WireHaystack::Inline(contents) => {
            let raw = contents.as_bytes();
            let bytes = raw.to_vec();
            Ok(ResolvedHaystack {
                sha256: sha256(&bytes),
                valid_utf8: std::str::from_utf8(&bytes).is_ok(),
                bytes,
                source: InputSource {
                    kind: "inline".to_string(),
                    path: None,
                    encoding: "inline-utf8".to_string(),
                    sha256: sha256(raw),
                    bytes: raw.len(),
                },
                transforms: HaystackTransforms::default(),
                required_file: None,
            })
        }
        WireHaystack::Full(full) => {
            if full.path.is_some() == full.contents.is_some() {
                return Err(ExpandError::new(
                    "full haystack must define exactly one of path or contents",
                ));
            }
            match (&full.path, &full.contents) {
                (Some(path), None) => {
                    let source_path = checked_input_path(
                        &checkout.join("benchmarks/haystacks"),
                        path,
                        "haystack",
                    )?;
                    let raw = read_checked(&source_path, limits)?;
                    let transformed = checked_haystack_transform(&raw, &full.transforms, limits)?;
                    let source = source_file(checkout, &source_path, &raw)?;
                    Ok(ResolvedHaystack {
                        sha256: sha256(&transformed),
                        valid_utf8: std::str::from_utf8(&transformed).is_ok(),
                        bytes: transformed,
                        source: InputSource {
                            kind: "file".to_string(),
                            path: Some(source.path.clone()),
                            encoding: "raw-file-bytes".to_string(),
                            sha256: source.sha256.clone(),
                            bytes: source.bytes,
                        },
                        transforms: full.transforms.clone(),
                        required_file: Some(source),
                    })
                }
                (None, Some(contents)) => {
                    let raw = contents.as_bytes();
                    let transformed = checked_haystack_transform(raw, &full.transforms, limits)?;
                    Ok(ResolvedHaystack {
                        sha256: sha256(&transformed),
                        valid_utf8: std::str::from_utf8(&transformed).is_ok(),
                        bytes: transformed,
                        source: InputSource {
                            kind: "inline".to_string(),
                            path: None,
                            encoding: "inline-utf8".to_string(),
                            sha256: sha256(raw),
                            bytes: raw.len(),
                        },
                        transforms: full.transforms.clone(),
                        required_file: None,
                    })
                }
                _ => Err(ExpandError::new("unreachable haystack source shape")),
            }
        }
    }
}

fn checked_pattern_transform(
    mut patterns: Vec<String>,
    options: &WireRegexTransforms,
    limits: &Limits,
) -> Result<Vec<String>, ExpandError> {
    if patterns.len() > limits.patterns_per_definition {
        return Err(ExpandError::new(format!(
            "source pattern limit exceeded: {} > {}",
            patterns.len(),
            limits.patterns_per_definition
        )));
    }
    for pattern in &mut patterns {
        if options.literal {
            *pattern = regex_lite::escape(pattern);
        }
        if let Some(prepend) = &options.prepend {
            pattern.insert_str(0, prepend);
        }
        if let Some(append) = &options.append {
            pattern.push_str(append);
        }
        check_len(
            pattern.len(),
            limits.transformed_bytes,
            "transformed pattern",
        )?;
    }
    Ok(patterns)
}

fn checked_haystack_transform(
    raw: &[u8],
    options: &HaystackTransforms,
    limits: &Limits,
) -> Result<Vec<u8>, ExpandError> {
    let mut bytes = if options.utf8_lossy {
        String::from_utf8_lossy(raw).into_owned().into_bytes()
    } else {
        raw.to_vec()
    };
    check_len(bytes.len(), limits.transformed_bytes, "lossy haystack")?;
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
        let repeated_len = bytes
            .len()
            .checked_mul(repeat)
            .ok_or_else(|| ExpandError::new("haystack repeat length overflow"))?;
        check_len(repeated_len, limits.transformed_bytes, "repeated haystack")?;
        bytes = bytes.repeat(repeat);
    }
    let prepend_len = options.prepend.as_ref().map_or(0, String::len);
    let append_len = options.append.as_ref().map_or(0, String::len);
    let final_len = bytes
        .len()
        .checked_add(prepend_len)
        .and_then(|length| length.checked_add(append_len))
        .ok_or_else(|| ExpandError::new("haystack affix length overflow"))?;
    check_len(final_len, limits.transformed_bytes, "affixed haystack")?;
    if let Some(prepend) = &options.prepend {
        bytes.splice(0..0, prepend.as_bytes().iter().copied());
    }
    if let Some(append) = &options.append {
        bytes.extend_from_slice(append.as_bytes());
    }
    Ok(bytes)
}

fn materialize_patterns(
    patterns: &[Vec<u8>],
    blobs: &mut BTreeMap<String, Vec<u8>>,
) -> Vec<PatternBlob> {
    patterns
        .iter()
        .enumerate()
        .map(|(ordinal, pattern)| {
            let digest = sha256(pattern);
            blobs
                .entry(digest.clone())
                .or_insert_with(|| pattern.clone());
            PatternBlob {
                ordinal,
                sha256: digest.clone(),
                bytes: pattern.len(),
                blob: format!("blobs/sha256-{digest}.pattern"),
            }
        })
        .collect()
}

fn expected_count(count: &WireCount, engine: &str) -> Result<(u64, String), ExpandError> {
    match count {
        WireCount::All(count) => Ok((*count, "scalar-for-all-engines".to_string())),
        WireCount::Engines(entries) => {
            for entry in entries {
                let expression = format!("^(?:{})$", entry.engine);
                let regex = regex_lite::Regex::new(&expression).map_err(|error| {
                    ExpandError::new(format!(
                        "invalid count engine expression {}: {error}",
                        entry.engine
                    ))
                })?;
                if regex.is_match(engine) {
                    return Ok((
                        entry.count,
                        format!("first-matching-engine-regex:{}", entry.engine),
                    ));
                }
            }
            Err(ExpandError::new(format!(
                "no expected count rule matches engine {engine}"
            )))
        }
    }
}

struct AdapterAudit {
    evidence_paths: &'static [&'static str],
    compile_configuration: Vec<String>,
    dependency_configuration: Vec<String>,
}

fn adapter_audit(target: &str) -> Result<AdapterAudit, ExpandError> {
    match target {
        "rust/regex" => Ok(AdapterAudit {
            evidence_paths: &[
                "engines/rust/regex/main.rs",
                "engines/rust/regex/Cargo.toml",
                "shared/timer/lib.rs",
                "shared/regexredux/lib.rs",
            ],
            compile_configuration: vec![
                "regex-automata meta::Regex builder; regex crate receipt pinned by adapter Cargo.toml".to_string(),
                "utf8_empty=false; Thompson NFA size limit=104857600 bytes".to_string(),
                "syntax utf8=false; unicode=<job.unicode>; case_insensitive=<job.case_insensitive>".to_string(),
                "build_many over ordered patterns; compilation outside timing except compile and regex-redux models".to_string(),
            ],
            dependency_configuration: vec![
                "regex = { version = \"=1.12.4\", default-features = true (implicit because key is omitted), features = [\"logging\", \"perf-dfa-full\"] }".to_string(),
                "regex-automata = \"=0.4.14\"".to_string(),
            ],
        }),
        "re2" => Ok(AdapterAudit {
            evidence_paths: &[
                "engines/re2/main.rs",
                "engines/re2/ffi.rs",
                "engines/re2/binding.cpp",
                "engines/re2/version.rs",
                "engines/re2/upstream/re2/re2.h",
                "shared/timer/lib.rs",
                "shared/regexredux/lib.rs",
            ],
            compile_configuration: vec![
                "RE2 constructor through checked Rust/C++ shim; exactly one definition pattern".to_string(),
                "EncodingUTF8 when job.unicode=true, EncodingLatin1 otherwise".to_string(),
                "case_sensitive=!job.case_insensitive; log_errors=false; max_mem=8388608 bytes (RE2 kDefaultMaxMem)".to_string(),
                "remaining RE2 Options defaults: posix_syntax=false, longest_match=false, literal=false, never_nl=false, dot_nl=false, never_capture=false, perl_classes=false, word_boundary=false, one_line=false".to_string(),
                "compilation outside timing except compile and regex-redux models".to_string(),
            ],
            dependency_configuration: vec![
                "libc = \"0.2.139\"; C++ RE2 sources are vendored in the pinned Rebar checkout".to_string(),
                "build-dependencies: cc = { version = \"1.0.83\", features = [\"parallel\"] }; pkg-config = \"0.3.26\"".to_string(),
                "engines.toml runtime dependency receipt additionally requires pkg-config --libs --cflags absl_base".to_string(),
            ],
        }),
        _ => Err(ExpandError::new("unexpected target engine")),
    }
}

fn resolve_adapters(
    checkout: &Path,
    engines: &WireEngines,
    limits: &Limits,
) -> Result<Vec<Adapter>, ExpandError> {
    let mut adapters = vec![];
    for target in TARGET_ENGINES {
        let wire = engines
            .engines
            .iter()
            .find(|engine| engine.name == target)
            .ok_or_else(|| ExpandError::new(format!("missing engine config for {target}")))?;
        let audit = adapter_audit(target)?;
        let mut evidence = vec![];
        for relative in audit.evidence_paths {
            let path = checkout.join(relative);
            let bytes = read_checked(&path, limits)?;
            evidence.push(source_file(checkout, &path, &bytes)?);
        }
        let version_command = wire.version.bin.as_ref().map(|bin| AdapterCommand {
            cwd: wire.version.cwd.clone(),
            bin: bin.clone(),
            args: wire.version.args.clone(),
            envs: wire.version.envs.clone(),
        });
        adapters.push(Adapter {
            engine: target.to_string(),
            configured_cwd: wire.cwd.clone().unwrap_or_else(|| ".".to_string()),
            run: public_command(&wire.run),
            version: AdapterVersion {
                command: version_command,
                file: wire.version.file.clone(),
                regex: wire.version.regex.clone(),
            },
            build: wire.build.iter().map(public_command).collect(),
            clean: wire.clean.iter().map(public_command).collect(),
            dependencies: wire
                .dependency
                .iter()
                .map(|dependency| AdapterDependency {
                    command: AdapterCommand {
                        cwd: dependency.cwd.clone(),
                        bin: dependency.bin.clone(),
                        args: dependency.args.clone(),
                        envs: dependency.envs.clone(),
                    },
                    regex: dependency.regex.clone(),
                })
                .collect(),
            evidence,
            compile_configuration: audit.compile_configuration,
            dependency_configuration: audit.dependency_configuration,
            runtime_availability:
                "unresolved-dynamic: version/dependency/build commands deliberately not executed"
                    .to_string(),
        });
    }
    adapters.sort_by(|left, right| left.engine.cmp(&right.engine));
    Ok(adapters)
}

fn validate_rebar_list(
    checkout: &Path,
    rebar_bin: &Path,
    jobs: &[Job],
) -> Result<Validation, ExpandError> {
    let absolute_bin = if rebar_bin.is_absolute() {
        rebar_bin.to_path_buf()
    } else {
        checkout.join(rebar_bin)
    };
    let output = Command::new(&absolute_bin)
        .current_dir(checkout)
        .args(["measure", "--list", "-e", "^(?:rust/regex|re2)$"])
        .output()
        .map_err(|error| ExpandError::new(format!("run {}: {error}", absolute_bin.display())))?;
    if !output.status.success() {
        return Err(ExpandError::new(format!(
            "Rebar list oracle failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| ExpandError::new(format!("Rebar list output is not UTF-8: {error}")))?;
    let mut oracle = BTreeSet::new();
    let mut rows_by_engine = BTreeMap::new();
    for (line_number, line) in stdout.lines().enumerate() {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 4 {
            return Err(ExpandError::new(format!(
                "Rebar list row {} has {} fields, expected 4",
                line_number
                    .checked_add(1)
                    .ok_or_else(|| ExpandError::new("Rebar list line number overflow"))?,
                fields.len()
            )));
        }
        let normalized = format!("{}\0{}\0{}\n", fields[0], fields[1], fields[2]);
        if !oracle.insert(normalized) {
            return Err(ExpandError::new(format!(
                "duplicate Rebar list row for {}/{}/{}",
                fields[0], fields[1], fields[2]
            )));
        }
        let count = rows_by_engine
            .entry(fields[2].to_string())
            .or_insert(0usize);
        *count = count
            .checked_add(1)
            .ok_or_else(|| ExpandError::new("Rebar list engine count overflow"))?;
    }
    let ours: BTreeSet<String> = jobs
        .iter()
        .map(|job| format!("{}\0{}\0{}\n", job.benchmark, job.model, job.engine))
        .collect();
    if oracle != ours {
        let missing: Vec<&String> = oracle.difference(&ours).take(8).collect();
        let extra: Vec<&String> = ours.difference(&oracle).take(8).collect();
        return Err(ExpandError::new(format!(
            "expanded job set differs from Rebar list: missing={missing:?}, extra={extra:?}"
        )));
    }
    let joined: Vec<u8> = oracle.iter().flat_map(|row| row.bytes()).collect();
    Ok(Validation {
        status: "exact-normalized-job-set-match".to_string(),
        normalized_row_count: oracle.len(),
        normalized_rows_sha256: sha256(&joined),
        rows_by_engine,
        representative_klv_status: "not-run".to_string(),
        representative_klv_benchmarks: vec![],
        dynamic_fields_ignored: vec![
            "engine version column: depends on locally runnable version receipt; excluded before comparison and hashing".to_string(),
        ],
    })
}

fn validate_representative_klv(
    checkout: &Path,
    rebar_bin: &Path,
    jobs: &[Job],
) -> Result<Vec<String>, ExpandError> {
    const REPRESENTATIVES: [&str; 7] = [
        "curated/01-literal/sherlock-en",
        "curated/12-dictionary/multi",
        "reported/i787-keywords/ascii",
        "folly/awyer-inn-busted",
        "curated/03-date/ascii",
        "curated/13-noseyparker/single",
        "imported/rsc/easy0-32",
    ];
    let absolute_bin = if rebar_bin.is_absolute() {
        rebar_bin.to_path_buf()
    } else {
        checkout.join(rebar_bin)
    };
    for benchmark in REPRESENTATIVES {
        let job = jobs
            .iter()
            .find(|job| job.benchmark == benchmark)
            .ok_or_else(|| ExpandError::new(format!("missing representative job {benchmark}")))?;
        let output = Command::new(&absolute_bin)
            .current_dir(checkout)
            .args(["klv", benchmark])
            .output()
            .map_err(|error| {
                ExpandError::new(format!("run Rebar KLV representative {benchmark}: {error}"))
            })?;
        if !output.status.success() {
            return Err(ExpandError::new(format!(
                "Rebar KLV representative {benchmark} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let fields = parse_klv(&output.stdout)?;
        require_klv_scalar(&fields, "name", benchmark.as_bytes(), benchmark)?;
        require_klv_scalar(&fields, "model", job.model.as_bytes(), benchmark)?;
        require_klv_scalar(
            &fields,
            "case-insensitive",
            if job.regex.case_insensitive {
                b"true"
            } else {
                b"false"
            },
            benchmark,
        )?;
        require_klv_scalar(
            &fields,
            "unicode",
            if job.regex.unicode { b"true" } else { b"false" },
            benchmark,
        )?;
        let patterns = fields.get("pattern").ok_or_else(|| {
            ExpandError::new(format!(
                "KLV representative {benchmark} has no pattern field"
            ))
        })?;
        if patterns.len() != job.regex.patterns.len() {
            return Err(ExpandError::new(format!(
                "KLV representative {benchmark} pattern count differs: Rebar {}, manifest {}",
                patterns.len(),
                job.regex.patterns.len()
            )));
        }
        for (actual, expected) in patterns.iter().zip(&job.regex.patterns) {
            if actual.len() != expected.bytes || sha256(actual) != expected.sha256 {
                return Err(ExpandError::new(format!(
                    "KLV representative {benchmark} pattern {} differs",
                    expected.ordinal
                )));
            }
        }
        let haystacks = fields.get("haystack").ok_or_else(|| {
            ExpandError::new(format!(
                "KLV representative {benchmark} has no haystack field"
            ))
        })?;
        if haystacks.len() != 1
            || haystacks[0].len() != job.haystack.bytes
            || sha256(&haystacks[0]) != job.haystack.sha256
        {
            return Err(ExpandError::new(format!(
                "KLV representative {benchmark} haystack bytes differ"
            )));
        }
    }
    Ok(REPRESENTATIVES.iter().map(ToString::to_string).collect())
}

fn parse_klv(bytes: &[u8]) -> Result<BTreeMap<String, Vec<Vec<u8>>>, ExpandError> {
    let mut fields: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let key_end = bytes[at..]
            .iter()
            .position(|&byte| byte == b':')
            .and_then(|offset| at.checked_add(offset))
            .ok_or_else(|| ExpandError::new("KLV key delimiter missing"))?;
        let key = std::str::from_utf8(&bytes[at..key_end])
            .map_err(|error| ExpandError::new(format!("KLV key is not UTF-8: {error}")))?
            .to_string();
        let length_start = key_end
            .checked_add(1)
            .ok_or_else(|| ExpandError::new("KLV length start overflow"))?;
        let length_end = bytes[length_start..]
            .iter()
            .position(|&byte| byte == b':')
            .and_then(|offset| length_start.checked_add(offset))
            .ok_or_else(|| ExpandError::new("KLV length delimiter missing"))?;
        let length_text = std::str::from_utf8(&bytes[length_start..length_end])
            .map_err(|error| ExpandError::new(format!("KLV length is not UTF-8: {error}")))?;
        let length = length_text
            .parse::<usize>()
            .map_err(|error| ExpandError::new(format!("invalid KLV length: {error}")))?;
        let value_start = length_end
            .checked_add(1)
            .ok_or_else(|| ExpandError::new("KLV value start overflow"))?;
        let value_end = value_start
            .checked_add(length)
            .ok_or_else(|| ExpandError::new("KLV value end overflow"))?;
        let newline = value_end
            .checked_add(1)
            .ok_or_else(|| ExpandError::new("KLV newline index overflow"))?;
        if newline > bytes.len() || bytes.get(value_end) != Some(&b'\n') {
            return Err(ExpandError::new("KLV value is truncated or lacks newline"));
        }
        fields
            .entry(key)
            .or_default()
            .push(bytes[value_start..value_end].to_vec());
        at = newline;
    }
    Ok(fields)
}

fn require_klv_scalar(
    fields: &BTreeMap<String, Vec<Vec<u8>>>,
    key: &str,
    expected: &[u8],
    benchmark: &str,
) -> Result<(), ExpandError> {
    let values = fields.get(key).ok_or_else(|| {
        ExpandError::new(format!("KLV representative {benchmark} lacks {key} field"))
    })?;
    if values.len() != 1 || values[0] != expected {
        return Err(ExpandError::new(format!(
            "KLV representative {benchmark} has unexpected {key} field"
        )));
    }
    Ok(())
}

fn make_scope(
    file_count: usize,
    definition_count: usize,
    jobs: &[Job],
) -> Result<Scope, ExpandError> {
    let mut jobs_by_engine = BTreeMap::new();
    let mut jobs_by_model = BTreeMap::new();
    let mut selected = BTreeSet::new();
    for job in jobs {
        checked_increment(&mut jobs_by_engine, &job.engine)?;
        checked_increment(&mut jobs_by_model, &job.model)?;
        selected.insert(job.benchmark.clone());
    }
    Ok(Scope {
        engines: TARGET_ENGINES.iter().map(ToString::to_string).collect(),
        definition_file_count: file_count,
        definition_count,
        job_count: jobs.len(),
        selected_definition_count: selected.len(),
        jobs_by_engine,
        jobs_by_model,
    })
}

fn measurement_defaults() -> MeasurementDefaults {
    MeasurementDefaults {
        max_iters: 1_000_000,
        max_warmup_iters: 1_000_000,
        max_time_ns: 3_000_000_000,
        max_warmup_time_ns: 1_500_000_000,
        timeout_ns: 10_000_000_000,
        stop_rule: "stop each warmup/measurement phase after its iteration maximum or wall-time maximum, whichever is reached first".to_string(),
        overrides: "none-recorded: these are Rebar measure defaults; an actual run must record any CLI overrides separately".to_string(),
    }
}

fn model_contracts() -> Vec<ModelContract> {
    vec![
        ModelContract {
            model: "compile".to_string(),
            reducer: "number of successive non-overlapping matches, used only to verify each compiled regex".to_string(),
            timed_boundary: "construct configured regex from supplied pattern(s)".to_string(),
            untimed_verification: "iterate all matches on the haystack and compare the count after the constructor duration is captured".to_string(),
            iteration_semantics: "adapter find iterator, including its adjacent-empty suppression".to_string(),
        },
        ModelContract {
            model: "count".to_string(),
            reducer: "number of successive non-overlapping matches".to_string(),
            timed_boundary: "complete find-iterator traversal and count; regex compilation is outside timing".to_string(),
            untimed_verification: "Rebar compares the returned count with the engine-specific expected value".to_string(),
            iteration_semantics: "adapter find iterator advances after empty matches and suppresses an adjacent empty match overlapping the previous match".to_string(),
        },
        ModelContract {
            model: "count-spans".to_string(),
            reducer: "sum in bytes of end-start for every successive non-overlapping match".to_string(),
            timed_boundary: "complete span iterator and byte-length sum; regex compilation is outside timing".to_string(),
            untimed_verification: "Rebar compares the returned sum with the engine-specific expected value".to_string(),
            iteration_semantics: "same non-overlapping/empty-match iterator as count, but both match bounds are requested".to_string(),
        },
        ModelContract {
            model: "count-captures".to_string(),
            reducer: "count participating groups, including group 0, across successive matches".to_string(),
            timed_boundary: "capture allocation is outside timing; repeated capture searches, participation scan and count are timed".to_string(),
            untimed_verification: "Rebar compares participating-group count with the engine-specific expected value".to_string(),
            iteration_semantics: "definitions promise no empty matches; next search starts at the previous overall match end".to_string(),
        },
        ModelContract {
            model: "grep".to_string(),
            reducer: "number of lines containing at least one match".to_string(),
            timed_boundary: "bstr line splitting plus one existence search per line; compilation is outside timing".to_string(),
            untimed_verification: "Rebar compares matching-line count with the engine-specific expected value".to_string(),
            iteration_semantics: "bstr lines exclude LF and an immediately preceding CR; trailing empty line behavior follows bstr::ByteSlice::lines".to_string(),
        },
        ModelContract {
            model: "grep-captures".to_string(),
            reducer: "sum participating groups, including group 0, over all matches on every line".to_string(),
            timed_boundary: "line splitting, repeated capture searches and participation scans are timed; capture allocation and compilation are outside timing".to_string(),
            untimed_verification: "Rebar compares participating-group count with the engine-specific expected value".to_string(),
            iteration_semantics: "definitions promise no empty matches; search restarts at offset 0 on each bstr line and then at each previous match end".to_string(),
        },
        ModelContract {
            model: "regex-redux".to_string(),
            reducer: "final transformed sequence byte length; adapter also verifies the complete canonical report internally".to_string(),
            timed_boundary: "entire regex-redux generic operation, including compilation of its built-in regexes, searches, allocations and substitutions".to_string(),
            untimed_verification: "timer bookkeeping and Rebar expected-count comparison; internal report verification occurs inside the timed operation".to_string(),
            iteration_semantics: "built-in non-empty patterns search successive suffixes; replacement preserves unmatched prefixes and inserts fixed replacements".to_string(),
        },
    ]
}

fn definition_paths(root: &Path) -> Result<Vec<PathBuf>, ExpandError> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = vec![];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| ExpandError::new(format!("read {}: {error}", directory.display())))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| ExpandError::new(format!("read directory entry: {error}")))?;
            let file_type = entry.file_type().map_err(|error| {
                ExpandError::new(format!("stat {}: {error}", entry.path().display()))
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && entry.path().extension().is_some_and(|ext| ext == "toml")
            {
                paths.push(entry.path());
            }
        }
    }
    Ok(paths)
}

fn definition_count_for_file(bytes: &[u8]) -> Result<usize, ExpandError> {
    let wire: WireFile = toml::from_slice(bytes)
        .map_err(|error| ExpandError::new(format!("re-decode definition count: {error}")))?;
    Ok(wire.benches.len())
}

fn group_name(root: &Path, path: &Path) -> Result<String, ExpandError> {
    let suffix = path
        .strip_prefix(root)
        .map_err(|error| ExpandError::new(format!("derive definition group: {error}")))?
        .with_extension("");
    Ok(suffix.to_string_lossy().replace('\\', "/"))
}

fn public_regex_transforms(wire: &WireRegexTransforms) -> RegexTransforms {
    RegexTransforms {
        literal: wire.literal,
        per_line: match wire.per_line {
            WirePerLine::None => "none",
            WirePerLine::Alternate => "alternate",
            WirePerLine::Pattern => "pattern",
        }
        .to_string(),
        prepend: wire.prepend.clone(),
        append: wire.append.clone(),
    }
}

fn public_command(wire: &WireCommand) -> AdapterCommand {
    AdapterCommand {
        cwd: wire.cwd.clone(),
        bin: wire.bin.clone(),
        args: wire.args.clone(),
        envs: wire.envs.clone(),
    }
}

fn encode_pattern_sequence(patterns: &[String], limits: &Limits) -> Result<Vec<u8>, ExpandError> {
    let length = patterns.iter().try_fold(0usize, |length, pattern| {
        length
            .checked_add(8)
            .and_then(|length| length.checked_add(pattern.len()))
            .ok_or_else(|| ExpandError::new("inline pattern source length overflow"))
    })?;
    check_len(
        length,
        limits.source_file_bytes,
        "encoded inline pattern source",
    )?;
    let mut bytes = Vec::with_capacity(length);
    for pattern in patterns {
        let length = u64::try_from(pattern.len())
            .map_err(|_| ExpandError::new("pattern length does not fit u64"))?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(pattern.as_bytes());
    }
    Ok(bytes)
}

fn checked_input_path(base: &Path, relative: &str, kind: &str) -> Result<PathBuf, ExpandError> {
    let relative_path = Path::new(relative);
    if relative_path.as_os_str().is_empty()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ExpandError::new(format!(
            "{kind} source path is not a confined relative path: {relative:?}"
        )));
    }
    let canonical_base = canonical(base, &format!("{kind} input root"))?;
    let candidate = canonical(
        &canonical_base.join(relative_path),
        &format!("{kind} input"),
    )?;
    if !candidate.starts_with(&canonical_base) {
        return Err(ExpandError::new(format!(
            "{kind} source path escapes its input root: {relative:?}"
        )));
    }
    Ok(candidate)
}

fn source_file(checkout: &Path, path: &Path, bytes: &[u8]) -> Result<SourceFile, ExpandError> {
    Ok(SourceFile {
        path: relative_string(checkout, path)?,
        sha256: sha256(bytes),
        bytes: bytes.len(),
    })
}

fn relative_string(root: &Path, path: &Path) -> Result<String, ExpandError> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|error| ExpandError::new(format!("make {} relative: {error}", path.display())))
}

fn read_checked(path: &Path, limits: &Limits) -> Result<Vec<u8>, ExpandError> {
    let metadata = fs::metadata(path)
        .map_err(|error| ExpandError::new(format!("stat {}: {error}", path.display())))?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| ExpandError::new(format!("{} length does not fit usize", path.display())))?;
    check_len(
        length,
        limits.source_file_bytes,
        &format!("source file {}", path.display()),
    )?;
    let bytes = fs::read(path)
        .map_err(|error| ExpandError::new(format!("read {}: {error}", path.display())))?;
    if bytes.len() != length {
        return Err(ExpandError::new(format!(
            "{} changed while being read: metadata {length}, read {}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn check_len(observed: usize, maximum: usize, what: &str) -> Result<(), ExpandError> {
    if observed > maximum {
        return Err(ExpandError::new(format!(
            "{what} exceeds limit: {observed} > {maximum}"
        )));
    }
    Ok(())
}

fn canonical(path: &Path, label: &str) -> Result<PathBuf, ExpandError> {
    fs::canonicalize(path).map_err(|error| {
        ExpandError::new(format!("canonicalize {label} {}: {error}", path.display()))
    })
}

fn command_text(command: &mut Command, label: &str) -> Result<String, ExpandError> {
    let output = command
        .output()
        .map_err(|error| ExpandError::new(format!("{label}: {error}")))?;
    if !output.status.success() {
        return Err(ExpandError::new(format!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_string())
        .map_err(|error| ExpandError::new(format!("{label} output is not UTF-8: {error}")))
}

fn command_success(command: &mut Command, label: &str) -> Result<bool, ExpandError> {
    command
        .status()
        .map(|status| status.success())
        .map_err(|error| ExpandError::new(format!("{label}: {error}")))
}

fn checked_increment(counts: &mut BTreeMap<String, usize>, key: &str) -> Result<(), ExpandError> {
    let count = counts.entry(key.to_string()).or_insert(0);
    *count = count
        .checked_add(1)
        .ok_or_else(|| ExpandError::new(format!("count overflow for {key}")))?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../research/rebar/expanded")
    }

    #[test]
    fn haystack_transform_order_matches_rebar_examples() {
        let options = HaystackTransforms {
            trim: true,
            line_start: Some(1),
            line_end: Some(3),
            repeat: Some(2),
            prepend: Some("<".to_string()),
            append: Some(">".to_string()),
            ..HaystackTransforms::default()
        };
        let got =
            checked_haystack_transform(b"  zero\none\ntwo\nthree  ", &options, &Limits::default())
                .unwrap();
        assert_eq!(b"<one\ntwo\none\ntwo\n>", got.as_slice());
    }

    #[test]
    fn regex_file_alternate_wraps_after_common_transforms() {
        let options = WireRegexTransforms {
            literal: true,
            per_line: WirePerLine::Alternate,
            prepend: Some("^".to_string()),
            append: Some("$".to_string()),
        };
        let mut got = checked_pattern_transform(
            vec!["a+".to_string(), "b?".to_string()],
            &options,
            &Limits::default(),
        )
        .unwrap();
        for pattern in &mut got {
            *pattern = format!("(?:{pattern})");
        }
        assert_eq!(r"(?:^a\+$)|(?:^b\?$)", got.join("|"));
    }

    #[test]
    fn count_rule_is_first_match() {
        let count = WireCount::Engines(vec![
            WireEngineCount {
                engine: "rust/.*".to_string(),
                count: 7,
            },
            WireEngineCount {
                engine: ".*".to_string(),
                count: 9,
            },
        ]);
        assert_eq!(
            (7, "first-matching-engine-regex:rust/.*".to_string()),
            expected_count(&count, "rust/regex").unwrap()
        );
        assert_eq!(
            (9, "first-matching-engine-regex:.*".to_string()),
            expected_count(&count, "re2").unwrap()
        );
    }

    #[test]
    fn resource_limit_rejects_repeat_before_allocation() {
        let limits = Limits {
            transformed_bytes: 7,
            ..Limits::default()
        };
        let options = HaystackTransforms {
            repeat: Some(3),
            ..HaystackTransforms::default()
        };
        let error = checked_haystack_transform(b"abc", &options, &limits).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repeated haystack exceeds limit")
        );
    }

    #[test]
    #[ignore = "requires the separately generated full Rebar expanded-artifact fixture"]
    fn generated_artifact_round_trips_and_covers_representative_definitions() {
        let root = artifact_root();
        let encoded = fs::read(root.join("manifest.json")).unwrap();
        let manifest: Manifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(encoded, serde_json::to_vec(&manifest).unwrap());
        assert_eq!(68, manifest.scope.definition_file_count);
        assert_eq!(360, manifest.scope.definition_count);
        assert_eq!(629, manifest.scope.job_count);
        assert_eq!(Some(&344), manifest.scope.jobs_by_engine.get("rust/regex"));
        assert_eq!(Some(&285), manifest.scope.jobs_by_engine.get("re2"));
        assert_eq!("exact-normalized-job-set-match", manifest.validation.status);

        let literal = manifest
            .jobs
            .iter()
            .find(|job| job.id == "curated/01-literal/sherlock-en@rust/regex")
            .unwrap();
        assert_eq!(513, literal.expected.count);
        assert_eq!("none", literal.regex.transforms.per_line);
        assert_eq!(899_232, literal.haystack.bytes);
        assert_eq!(
            b"Sherlock Holmes",
            fs::read(root.join(&literal.regex.patterns[0].blob))
                .unwrap()
                .as_slice()
        );

        let dictionary = manifest
            .jobs
            .iter()
            .find(|job| job.id == "curated/12-dictionary/multi@rust/regex")
            .unwrap();
        assert_eq!(2_663, dictionary.regex.patterns.len());
        assert!(dictionary.regex.transforms.literal);
        assert_eq!("pattern", dictionary.regex.transforms.per_line);

        let rust_adapter = manifest
            .adapters
            .iter()
            .find(|adapter| adapter.engine == "rust/regex")
            .unwrap();
        assert!(rust_adapter.dependency_configuration.iter().any(|entry| {
            entry.contains("=1.12.4")
                && entry.contains("logging")
                && entry.contains("perf-dfa-full")
                && entry.contains("default-features = true")
        }));

        let digest_file = fs::read_to_string(root.join("manifest.sha256")).unwrap();
        assert_eq!(
            format!("{}  manifest.json\n", sha256(&encoded)),
            digest_file
        );
    }

    #[test]
    #[ignore = "requires the separately generated full Rebar expanded-artifact fixture"]
    fn every_referenced_pattern_blob_has_exact_content_hash() {
        let root = artifact_root();
        let encoded = fs::read(root.join("manifest.json")).unwrap();
        let manifest: Manifest = serde_json::from_slice(&encoded).unwrap();
        let mut seen = BTreeSet::new();
        for pattern in manifest
            .jobs
            .iter()
            .flat_map(|job| job.regex.patterns.iter())
        {
            if !seen.insert(pattern.sha256.clone()) {
                continue;
            }
            let bytes = fs::read(root.join(&pattern.blob)).unwrap();
            assert_eq!(pattern.bytes, bytes.len());
            assert_eq!(pattern.sha256, sha256(&bytes));
        }
        assert_eq!(3_039, seen.len());
    }

    #[test]
    #[ignore = "full pinned-checkout regeneration; run explicitly for release qualification"]
    fn pinned_checkout_regeneration_is_deterministic() {
        let checkout = std::env::var_os("FRE_TEST_REBAR_CHECKOUT")
            .map_or_else(|| PathBuf::from("/tmp/rebar-fre"), PathBuf::from);
        let config = ExpandConfig {
            rebar_bin: PathBuf::from("target/debug/rebar"),
            checkout,
            expected_revision: AUDITED_REBAR_REVISION.to_string(),
            limits: Limits::default(),
        };
        let first = expand(&config).unwrap();
        let second = expand(&config).unwrap();
        assert_eq!(first, second);
    }
}
