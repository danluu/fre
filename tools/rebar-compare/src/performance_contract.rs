//! Executable current-main performance qualification contract.
//!
//! This module deliberately validates coverage before it accepts timing
//! observations. A benchmark row cannot disappear because it is unsupported,
//! slow, missing a comparator, or inconvenient for an aggregate score.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Write as _,
    path::Path,
    process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Report, Status, report_bytes};

/// Stable schema for a performance qualification contract.
pub const PERFORMANCE_CONTRACT_SCHEMA: &str = "fre.rebar.performance-contract.v1";
/// Stable schema for pointwise performance observations.
pub const PERFORMANCE_OBSERVATIONS_SCHEMA: &str = "fre.rebar.performance-observations.v1";
/// Complete Rebar operation-model universe.
pub const REBAR_MODELS: [&str; 7] = [
    "compile",
    "count",
    "count-captures",
    "count-spans",
    "grep",
    "grep-captures",
    "regex-redux",
];

/// Validation failure with a stable human-readable diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractError {
    message: String,
}

impl ContractError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ContractError {}

/// Exact canonical Git identity required by the contract.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalIdentity {
    /// Protected canonical reference.
    pub reference: String,
    /// Exact canonical commit.
    pub commit: String,
    /// Exact canonical tree.
    pub tree: String,
}

/// Exact semantic frontier that defines the performance denominator.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentity {
    /// Required semantic report schema.
    pub report_schema: String,
    /// Accepted host-specific canonical report digests.
    pub accepted_report_sha256: Vec<String>,
    /// Expanded-manifest digest.
    pub manifest_sha256: String,
    /// Canonical semantic receipt-array digest.
    pub receipts_sha256: String,
    /// Pinned Rebar source revision.
    pub rebar_revision: String,
    /// Exact FRE adapter identity selected from the semantic report.
    pub fre_adapter: String,
    /// Fixed Rust-target row denominator.
    pub denominator_rows: usize,
    /// Passing rows in this exact semantic frontier.
    pub supported_rows: usize,
    /// Explicitly unsupported rows in this exact semantic frontier.
    pub unsupported_rows: usize,
}

/// One Rebar model's exact semantic denominator and lifecycle boundaries.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelContract {
    /// Rebar model name.
    pub model: String,
    /// All Rust-target semantic rows for this model.
    pub denominator_rows: usize,
    /// Passing rows for this model.
    pub supported_rows: usize,
    /// Explicitly unsupported rows for this model.
    pub unsupported_rows: usize,
    /// Exact lifecycle boundary IDs required for every supported row.
    pub lifecycle_boundaries: Vec<String>,
}

/// Lifecycle phase measured by one boundary.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum LifecyclePhase {
    /// Fresh public construction, including configuration.
    ColdConstruction,
    /// Fresh construction after allocator and process initialization.
    AllocatorWarmConstruction,
    /// First operation on one already-built artifact.
    FirstOperation,
    /// Repeated operation on one already-built artifact.
    SteadyOperation,
    /// Complete composite workload whose construction is part of the model.
    CompositeOperation,
}

/// Exact timed API boundary and required output fields.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleBoundary {
    /// Stable boundary ID referenced by model contracts and observations.
    pub id: String,
    /// Lifecycle phase.
    pub phase: LifecyclePhase,
    /// Models to which this boundary applies.
    pub models: Vec<String>,
    /// Work included inside the timer.
    pub includes: String,
    /// Work intentionally outside the timer.
    pub excludes: String,
    /// Required per-arm output fields.
    pub required_metrics: Vec<String>,
}

/// Comparator whose presence or absence must be reported pointwise.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComparatorContract {
    /// Stable comparator label in performance observations.
    pub id: String,
    /// Exact semantic adapter identity used to establish availability.
    pub semantic_adapter: String,
}

/// Pointwise reporting and promotion policy.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReportingPolicy {
    /// Every semantic denominator row must have one observation row.
    pub require_every_denominator_row: bool,
    /// Every lifecycle boundary and comparator is reported separately.
    pub require_pointwise_boundaries: bool,
    /// An aggregate cannot rescue a failed or absent point.
    pub aggregate_cannot_hide_pointwise_failure: bool,
    /// Exact fresh-process pairs per available comparator and boundary.
    pub pairs_per_comparator: u32,
    /// Minimum candidate pair wins for a passing point.
    pub minimum_candidate_wins: u32,
    /// Passing ratios must be strictly below this parts-per-million value.
    pub ratio_ppm_exclusive_upper_bound: u64,
    /// Comparators that must be explicit even when unavailable.
    pub comparators: Vec<ComparatorContract>,
}

/// Complete executable performance contract.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceContract {
    /// Contract schema.
    pub schema: String,
    /// Stable human-readable contract ID.
    pub contract_id: String,
    /// Exact canonical Git identity.
    pub canonical: CanonicalIdentity,
    /// Exact semantic frontier.
    pub semantic: SemanticIdentity,
    /// All seven model contracts.
    pub models: Vec<ModelContract>,
    /// Reusable lifecycle boundary definitions.
    pub lifecycle_boundaries: Vec<LifecycleBoundary>,
    /// Pointwise reporting policy.
    pub reporting: ReportingPolicy,
}

/// Observation artifact state.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationPhase {
    /// Coverage-complete preregistration; available comparisons may be pending.
    Draft,
    /// Final qualification; no available comparison may remain pending.
    Qualification,
}

/// Semantic state repeated in every performance row.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RowSemanticStatus {
    /// The exact candidate semantic receipt passed.
    Supported,
    /// The exact candidate semantic receipt was explicitly unsupported.
    Unsupported,
}

/// Pointwise comparator observation state.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    /// An authenticated paired comparison was measured.
    Measured,
    /// The semantic report has no passing comparable reference row.
    NotComparable,
    /// The comparison is declared but not yet measured in a draft.
    Pending,
}

/// One pointwise comparison summary.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonObservation {
    /// Comparator ID from the contract.
    pub comparator: String,
    /// Observation state.
    pub status: ComparisonStatus,
    /// Median candidate/reference ratio in parts per million.
    pub ratio_ppm: Option<u64>,
    /// Number of fresh-process pairs.
    pub pair_count: Option<u32>,
    /// Number of pairs won by the candidate.
    pub candidate_wins: Option<u32>,
    /// Pointwise decision derived from the contract threshold.
    pub pointwise_pass: Option<bool>,
    /// Required explanation for pending or non-comparable points.
    pub reason: Option<String>,
}

/// All comparator observations at one lifecycle boundary.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryObservation {
    /// Boundary ID from the model contract.
    pub boundary: String,
    /// Explicit comparator observations.
    pub comparisons: Vec<ComparisonObservation>,
}

/// One fixed-denominator benchmark row.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRow {
    /// Exact semantic receipt job ID.
    pub job_id: String,
    /// Exact Rebar model.
    pub model: String,
    /// Candidate semantic state.
    pub semantic_status: RowSemanticStatus,
    /// Required reason for an unsupported row.
    pub reason: Option<String>,
    /// Every required lifecycle boundary for a supported row.
    pub boundaries: Vec<BoundaryObservation>,
}

/// Coverage-complete pointwise performance observations.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceObservations {
    /// Observation schema.
    pub schema: String,
    /// Exact contract ID.
    pub contract_id: String,
    /// Exact canonical commit.
    pub canonical_commit: String,
    /// Exact canonical tree.
    pub canonical_tree: String,
    /// Exact semantic receipt-array digest.
    pub semantic_receipts_sha256: String,
    /// Draft or final qualification state.
    pub phase: ObservationPhase,
    /// Exactly one row for every semantic denominator row.
    pub rows: Vec<PerformanceRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticRow {
    model: String,
    status: RowSemanticStatus,
    reason: Option<String>,
    comparator_statuses: BTreeMap<String, Option<Status>>,
}

/// Authenticated semantic row universe used to validate observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticUniverse {
    rows: BTreeMap<String, SemanticRow>,
}

impl SemanticUniverse {
    /// Number of fixed-denominator rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the universe contains no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Read and decode a performance contract.
pub fn read_contract(path: &Path) -> Result<PerformanceContract, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))
}

/// Read and decode pointwise performance observations.
pub fn read_observations(path: &Path) -> Result<PerformanceObservations, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))
}

/// Generate an honest coverage-complete pending draft without running timing.
///
/// Passing semantic comparator receipts become explicit `pending` points.
/// Missing or nonpassing comparator receipts become explicit
/// `not-comparable` points. Unsupported FRE rows retain their exact semantic
/// reason and never acquire timing boundaries.
pub fn generate_draft_observations(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<PerformanceObservations, ContractError> {
    validate_contract(contract)?;
    let models: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let mut rows = Vec::with_capacity(universe.rows.len());
    for (job_id, semantic) in &universe.rows {
        let boundaries = if semantic.status == RowSemanticStatus::Supported {
            let model = models.get(semantic.model.as_str()).ok_or_else(|| {
                ContractError::new(format!(
                    "semantic universe model {:?} is absent from contract",
                    semantic.model
                ))
            })?;
            let mut boundaries = Vec::with_capacity(model.lifecycle_boundaries.len());
            for boundary in &model.lifecycle_boundaries {
                let mut comparisons = Vec::with_capacity(contract.reporting.comparators.len());
                for comparator in &contract.reporting.comparators {
                    let reference_status = semantic
                        .comparator_statuses
                        .get(&comparator.id)
                        .copied()
                        .ok_or_else(|| {
                            ContractError::new(format!(
                                "semantic universe row {job_id:?} lacks comparator {:?}",
                                comparator.id
                            ))
                        })?;
                    comparisons.push(draft_comparison(&comparator.id, reference_status));
                }
                boundaries.push(BoundaryObservation {
                    boundary: boundary.clone(),
                    comparisons,
                });
            }
            boundaries
        } else {
            Vec::new()
        };
        rows.push(PerformanceRow {
            job_id: job_id.clone(),
            model: semantic.model.clone(),
            semantic_status: semantic.status,
            reason: semantic.reason.clone(),
            boundaries,
        });
    }
    let observations = PerformanceObservations {
        schema: PERFORMANCE_OBSERVATIONS_SCHEMA.to_string(),
        contract_id: contract.contract_id.clone(),
        canonical_commit: contract.canonical.commit.clone(),
        canonical_tree: contract.canonical.tree.clone(),
        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
        phase: ObservationPhase::Draft,
        rows,
    };
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

fn draft_comparison(comparator: &str, reference_status: Option<Status>) -> ComparisonObservation {
    let (status, reason) = match reference_status {
        Some(Status::Pass) => (
            ComparisonStatus::Pending,
            "passing semantic comparator available; timing not run".to_string(),
        ),
        Some(status) => (
            ComparisonStatus::NotComparable,
            format!(
                "semantic comparator is not a pass: {}",
                status_label(status)
            ),
        ),
        None => (
            ComparisonStatus::NotComparable,
            "semantic report has no matching comparator receipt".to_string(),
        ),
    };
    ComparisonObservation {
        comparator: comparator.to_string(),
        status,
        ratio_ppm: None,
        pair_count: None,
        candidate_wins: None,
        pointwise_pass: None,
        reason: Some(reason),
    }
}

const fn status_label(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Unsupported => "unsupported",
        Status::Unresolved => "unresolved",
        Status::Fault => "fault",
    }
}

/// Serialize observations in one deterministic compact JSON representation.
pub fn observation_bytes(observations: &PerformanceObservations) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(observations)
        .map_err(|error| ContractError::new(format!("serialize observations: {error}")))
}

/// Publish observations to a new path without overwriting prior evidence.
pub fn write_new_observations(
    path: &Path,
    observations: &PerformanceObservations,
) -> Result<(), ContractError> {
    let parent = path.parent().ok_or_else(|| {
        ContractError::new(format!("observation path {} has no parent", path.display()))
    })?;
    if !parent.is_dir() {
        return Err(ContractError::new(format!(
            "observation parent {} is not a directory",
            parent.display()
        )));
    }
    let bytes = observation_bytes(observations)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ContractError::new(format!(
                "create new observation {}: {error}",
                path.display()
            ))
        })?;
    output.write_all(&bytes).map_err(|error| {
        ContractError::new(format!("write observation {}: {error}", path.display()))
    })?;
    output.sync_all().map_err(|error| {
        ContractError::new(format!("sync observation {}: {error}", path.display()))
    })
}

/// Resolve the exact protected main commit and tree from `repo`.
pub fn resolve_exact_main(repo: &Path) -> Result<CanonicalIdentity, ContractError> {
    if !repo.is_dir() {
        return Err(ContractError::new(format!(
            "repository root {} is not a directory",
            repo.display()
        )));
    }
    let commit = git_object(repo, "refs/heads/main^{commit}")?;
    let tree = git_object(repo, "refs/heads/main^{tree}")?;
    Ok(CanonicalIdentity {
        reference: "refs/heads/main".to_string(),
        commit,
        tree,
    })
}

fn git_object(repo: &Path, revision: &str) -> Result<String, ContractError> {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", revision])
        .output()
        .map_err(|error| ContractError::new(format!("execute /usr/bin/git: {error}")))?;
    if !output.status.success() {
        return Err(ContractError::new(format!(
            "/usr/bin/git could not resolve {revision} in {}",
            repo.display()
        )));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|error| ContractError::new(format!("git output is not UTF-8: {error}")))?
        .trim_end();
    require_oid(value, revision)?;
    Ok(value.to_string())
}

/// Validate contract structure, all-model coverage, and reporting invariants.
pub fn validate_contract(contract: &PerformanceContract) -> Result<(), ContractError> {
    if contract.schema != PERFORMANCE_CONTRACT_SCHEMA {
        return Err(ContractError::new(format!(
            "contract schema {:?} differs from {PERFORMANCE_CONTRACT_SCHEMA}",
            contract.schema
        )));
    }
    require_token(&contract.contract_id, "contract_id")?;
    if contract.canonical.reference != "refs/heads/main" {
        return Err(ContractError::new(
            "canonical reference must be exactly refs/heads/main",
        ));
    }
    require_oid(&contract.canonical.commit, "canonical commit")?;
    require_oid(&contract.canonical.tree, "canonical tree")?;
    validate_semantic_identity(&contract.semantic)?;

    let expected_models: BTreeSet<&str> = REBAR_MODELS.into_iter().collect();
    let mut models = BTreeMap::new();
    let mut denominator_rows = 0_usize;
    let mut supported_rows = 0_usize;
    let mut unsupported_rows = 0_usize;
    for model in &contract.models {
        if !expected_models.contains(model.model.as_str()) {
            return Err(ContractError::new(format!(
                "unexpected Rebar model {:?}",
                model.model
            )));
        }
        if models.insert(model.model.as_str(), model).is_some() {
            return Err(ContractError::new(format!(
                "duplicate Rebar model {:?}",
                model.model
            )));
        }
        require_partition(
            model.denominator_rows,
            model.supported_rows,
            model.unsupported_rows,
            &format!("model {}", model.model),
        )?;
        denominator_rows = checked_sum(denominator_rows, model.denominator_rows, "denominator")?;
        supported_rows = checked_sum(supported_rows, model.supported_rows, "supported")?;
        unsupported_rows = checked_sum(unsupported_rows, model.unsupported_rows, "unsupported")?;
    }
    let actual_models: BTreeSet<&str> = models.keys().copied().collect();
    if actual_models != expected_models {
        return Err(ContractError::new(format!(
            "model set {actual_models:?} differs from {expected_models:?}"
        )));
    }
    if denominator_rows != contract.semantic.denominator_rows
        || supported_rows != contract.semantic.supported_rows
        || unsupported_rows != contract.semantic.unsupported_rows
    {
        return Err(ContractError::new(
            "per-model coverage does not sum to the semantic frontier",
        ));
    }

    let boundaries = validate_boundaries(&contract.lifecycle_boundaries, &models)?;
    validate_model_phases(&models, &boundaries)?;
    validate_reporting_policy(&contract.reporting)?;
    Ok(())
}

fn validate_semantic_identity(semantic: &SemanticIdentity) -> Result<(), ContractError> {
    require_token(&semantic.report_schema, "semantic report schema")?;
    require_digest(&semantic.manifest_sha256, "semantic manifest")?;
    require_digest(&semantic.receipts_sha256, "semantic receipts")?;
    require_oid(&semantic.rebar_revision, "Rebar revision")?;
    require_token(&semantic.fre_adapter, "FRE adapter")?;
    if semantic.accepted_report_sha256.is_empty() {
        return Err(ContractError::new(
            "semantic frontier has no accepted report digest",
        ));
    }
    let mut report_hashes = BTreeSet::new();
    for digest in &semantic.accepted_report_sha256 {
        require_digest(digest, "accepted semantic report")?;
        if !report_hashes.insert(digest) {
            return Err(ContractError::new(
                "accepted semantic report digests contain a duplicate",
            ));
        }
    }
    require_partition(
        semantic.denominator_rows,
        semantic.supported_rows,
        semantic.unsupported_rows,
        "semantic frontier",
    )
}

fn validate_boundaries<'a>(
    definitions: &'a [LifecycleBoundary],
    models: &BTreeMap<&str, &ModelContract>,
) -> Result<BTreeMap<&'a str, &'a LifecycleBoundary>, ContractError> {
    let mut boundaries = BTreeMap::new();
    for boundary in definitions {
        require_token(&boundary.id, "lifecycle boundary ID")?;
        require_text(&boundary.includes, "lifecycle includes")?;
        require_text(&boundary.excludes, "lifecycle excludes")?;
        if boundaries.insert(boundary.id.as_str(), boundary).is_some() {
            return Err(ContractError::new(format!(
                "duplicate lifecycle boundary {:?}",
                boundary.id
            )));
        }
        let model_set = unique_tokens(&boundary.models, "lifecycle boundary models")?;
        if model_set.is_empty() {
            return Err(ContractError::new(format!(
                "lifecycle boundary {:?} has no models",
                boundary.id
            )));
        }
        for model in &model_set {
            let Some(model_contract) = models.get(model.as_str()) else {
                return Err(ContractError::new(format!(
                    "lifecycle boundary {:?} references unknown model {model:?}",
                    boundary.id
                )));
            };
            if !model_contract.lifecycle_boundaries.contains(&boundary.id) {
                return Err(ContractError::new(format!(
                    "model {model:?} does not reciprocally reference boundary {:?}",
                    boundary.id
                )));
            }
        }
        let metrics = unique_tokens(&boundary.required_metrics, "required metrics")?;
        for required in ["elapsed_ns", "result_digest"] {
            if !metrics.contains(required) {
                return Err(ContractError::new(format!(
                    "lifecycle boundary {:?} lacks required metric {required:?}",
                    boundary.id
                )));
            }
        }
    }
    for (model_name, model) in models {
        let model_boundaries = unique_tokens(
            &model.lifecycle_boundaries,
            &format!("model {model_name} lifecycle boundaries"),
        )?;
        if model_boundaries.is_empty() {
            return Err(ContractError::new(format!(
                "model {model_name:?} has no lifecycle boundary"
            )));
        }
        for boundary_id in model_boundaries {
            let Some(boundary) = boundaries.get(boundary_id.as_str()) else {
                return Err(ContractError::new(format!(
                    "model {model_name:?} references unknown boundary {boundary_id:?}"
                )));
            };
            if !boundary.models.iter().any(|value| value == model_name) {
                return Err(ContractError::new(format!(
                    "boundary {boundary_id:?} does not reciprocally include model {model_name:?}"
                )));
            }
        }
    }
    Ok(boundaries)
}

fn validate_model_phases(
    models: &BTreeMap<&str, &ModelContract>,
    boundaries: &BTreeMap<&str, &LifecycleBoundary>,
) -> Result<(), ContractError> {
    for (name, model) in models {
        let phases: BTreeSet<LifecyclePhase> = model
            .lifecycle_boundaries
            .iter()
            .map(|boundary| boundaries[boundary.as_str()].phase)
            .collect();
        let expected: BTreeSet<LifecyclePhase> = match *name {
            "compile" => [
                LifecyclePhase::ColdConstruction,
                LifecyclePhase::AllocatorWarmConstruction,
            ]
            .into_iter()
            .collect(),
            "regex-redux" => [LifecyclePhase::CompositeOperation].into_iter().collect(),
            _ => [
                LifecyclePhase::FirstOperation,
                LifecyclePhase::SteadyOperation,
            ]
            .into_iter()
            .collect(),
        };
        if phases != expected || phases.len() != model.lifecycle_boundaries.len() {
            return Err(ContractError::new(format!(
                "model {name:?} lifecycle phases {phases:?} differ from {expected:?}"
            )));
        }
    }
    Ok(())
}

fn validate_reporting_policy(reporting: &ReportingPolicy) -> Result<(), ContractError> {
    if !reporting.require_every_denominator_row
        || !reporting.require_pointwise_boundaries
        || !reporting.aggregate_cannot_hide_pointwise_failure
    {
        return Err(ContractError::new(
            "reporting policy must require the denominator, pointwise boundaries, and no aggregate rescue",
        ));
    }
    if reporting.pairs_per_comparator == 0
        || reporting.minimum_candidate_wins > reporting.pairs_per_comparator
        || reporting.ratio_ppm_exclusive_upper_bound == 0
    {
        return Err(ContractError::new(
            "reporting pair count, win threshold, or ratio threshold is invalid",
        ));
    }
    if reporting.comparators.is_empty() {
        return Err(ContractError::new("reporting policy has no comparators"));
    }
    let mut ids = BTreeSet::new();
    let mut adapters = BTreeSet::new();
    for comparator in &reporting.comparators {
        require_token(&comparator.id, "comparator ID")?;
        require_token(&comparator.semantic_adapter, "comparator adapter")?;
        if !ids.insert(comparator.id.as_str()) {
            return Err(ContractError::new(format!(
                "duplicate comparator ID {:?}",
                comparator.id
            )));
        }
        if !adapters.insert(comparator.semantic_adapter.as_str()) {
            return Err(ContractError::new(format!(
                "duplicate comparator adapter {:?}",
                comparator.semantic_adapter
            )));
        }
    }
    Ok(())
}

/// Require the observed protected main identity to equal the contract.
pub fn validate_exact_main(
    contract: &PerformanceContract,
    observed: &CanonicalIdentity,
) -> Result<(), ContractError> {
    if observed != &contract.canonical {
        return Err(ContractError::new(format!(
            "observed canonical identity {observed:?} differs from contract {:?}",
            contract.canonical
        )));
    }
    Ok(())
}

/// Authenticate a semantic report and construct its exact performance universe.
pub fn validate_semantic_report(
    contract: &PerformanceContract,
    bytes: &[u8],
) -> Result<SemanticUniverse, ContractError> {
    validate_contract(contract)?;
    let report_hash = digest(bytes);
    if !contract
        .semantic
        .accepted_report_sha256
        .contains(&report_hash)
    {
        return Err(ContractError::new(format!(
            "semantic report SHA-256 {report_hash} is not accepted by the contract"
        )));
    }
    let report: Report = serde_json::from_slice(bytes)
        .map_err(|error| ContractError::new(format!("decode semantic report: {error}")))?;
    let canonical = report_bytes(&report)
        .map_err(|error| ContractError::new(format!("serialize semantic report: {error}")))?;
    if canonical != bytes {
        return Err(ContractError::new(
            "semantic report is not canonical comparator serialization",
        ));
    }
    validate_report_identity(contract, &report)?;
    semantic_universe(contract, &report)
}

fn validate_report_identity(
    contract: &PerformanceContract,
    report: &Report,
) -> Result<(), ContractError> {
    if report.schema != contract.semantic.report_schema
        || report.manifest_sha256 != contract.semantic.manifest_sha256
        || report.rebar_revision != contract.semantic.rebar_revision
    {
        return Err(ContractError::new(
            "semantic report schema, manifest, or Rebar revision differs from contract",
        ));
    }
    let receipts = serde_json::to_vec(&report.receipts)
        .map_err(|error| ContractError::new(format!("serialize semantic receipts: {error}")))?;
    let receipts_hash = digest(&receipts);
    if receipts_hash != report.receipts_sha256 || receipts_hash != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(format!(
            "semantic receipt digest {receipts_hash} differs from report or contract"
        )));
    }
    if report.coverage.total != report.receipts.len() {
        return Err(ContractError::new(
            "semantic report coverage total differs from receipt count",
        ));
    }
    let adapters: BTreeSet<&str> = report
        .adapters
        .iter()
        .map(|adapter| adapter.adapter.as_str())
        .collect();
    if !adapters.contains(contract.semantic.fre_adapter.as_str()) {
        return Err(ContractError::new(
            "semantic report lacks the contracted FRE adapter",
        ));
    }
    for comparator in &contract.reporting.comparators {
        if !adapters.contains(comparator.semantic_adapter.as_str()) {
            return Err(ContractError::new(format!(
                "semantic report lacks comparator adapter {:?}",
                comparator.semantic_adapter
            )));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "receipt authentication, exact denominator construction, and coverage reconciliation stay in one fail-closed transaction"
)]
fn semantic_universe(
    contract: &PerformanceContract,
    report: &Report,
) -> Result<SemanticUniverse, ContractError> {
    let mut references: BTreeMap<(&str, &str, &str), Status> = BTreeMap::new();
    for receipt in &report.receipts {
        for comparator in &contract.reporting.comparators {
            if receipt.adapter == comparator.semantic_adapter
                && references
                    .insert(
                        (
                            receipt.benchmark.as_str(),
                            receipt.model.as_str(),
                            comparator.id.as_str(),
                        ),
                        receipt.status,
                    )
                    .is_some()
            {
                return Err(ContractError::new(format!(
                    "duplicate comparator receipt for benchmark {:?}, model {:?}, comparator {:?}",
                    receipt.benchmark, receipt.model, comparator.id
                )));
            }
        }
    }

    let model_contracts: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let mut model_counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut rows = BTreeMap::new();
    for receipt in report
        .receipts
        .iter()
        .filter(|receipt| receipt.adapter == contract.semantic.fre_adapter)
    {
        let Some(_) = model_contracts.get(receipt.model.as_str()) else {
            return Err(ContractError::new(format!(
                "FRE receipt {:?} has unexpected model {:?}",
                receipt.job_id, receipt.model
            )));
        };
        let (status, reason) = match receipt.status {
            Status::Pass if receipt.reason.is_none() => (RowSemanticStatus::Supported, None),
            Status::Unsupported
                if receipt
                    .reason
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()) =>
            {
                (RowSemanticStatus::Unsupported, receipt.reason.clone())
            }
            other => {
                return Err(ContractError::new(format!(
                    "FRE receipt {:?} has inadmissible status {other:?} or reason",
                    receipt.job_id
                )));
            }
        };
        let counts = model_counts.entry(receipt.model.as_str()).or_insert((0, 0));
        match status {
            RowSemanticStatus::Supported => {
                counts.0 = counts
                    .0
                    .checked_add(1)
                    .ok_or_else(|| ContractError::new("supported row count overflow"))?;
            }
            RowSemanticStatus::Unsupported => {
                counts.1 = counts
                    .1
                    .checked_add(1)
                    .ok_or_else(|| ContractError::new("unsupported row count overflow"))?;
            }
        }
        let comparator_statuses = contract
            .reporting
            .comparators
            .iter()
            .map(|comparator| {
                let status = references
                    .get(&(
                        receipt.benchmark.as_str(),
                        receipt.model.as_str(),
                        comparator.id.as_str(),
                    ))
                    .copied();
                (comparator.id.clone(), status)
            })
            .collect();
        let row = SemanticRow {
            model: receipt.model.clone(),
            status,
            reason,
            comparator_statuses,
        };
        if rows.insert(receipt.job_id.clone(), row).is_some() {
            return Err(ContractError::new(format!(
                "duplicate FRE semantic job ID {:?}",
                receipt.job_id
            )));
        }
    }
    if rows.len() != contract.semantic.denominator_rows {
        return Err(ContractError::new(format!(
            "semantic universe has {} rows, expected {}",
            rows.len(),
            contract.semantic.denominator_rows
        )));
    }
    for model in &contract.models {
        let actual = model_counts
            .get(model.model.as_str())
            .copied()
            .unwrap_or((0, 0));
        if actual != (model.supported_rows, model.unsupported_rows) {
            return Err(ContractError::new(format!(
                "semantic model {:?} counts {actual:?} differ from ({}, {})",
                model.model, model.supported_rows, model.unsupported_rows
            )));
        }
    }
    let coverage = report
        .coverage
        .by_adapter_status
        .get(&contract.semantic.fre_adapter)
        .ok_or_else(|| ContractError::new("semantic coverage lacks FRE adapter"))?;
    if coverage.get(&Status::Pass).copied().unwrap_or(0) != contract.semantic.supported_rows
        || coverage.get(&Status::Unsupported).copied().unwrap_or(0)
            != contract.semantic.unsupported_rows
        || coverage.iter().any(|(status, count)| {
            !matches!(status, Status::Pass | Status::Unsupported) && *count > 0
        })
    {
        return Err(ContractError::new(
            "semantic top-level FRE coverage differs from receipt-level contract",
        ));
    }
    Ok(SemanticUniverse { rows })
}

/// Validate coverage-complete, pointwise observations against a semantic universe.
pub fn validate_observations(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    observations: &PerformanceObservations,
) -> Result<(), ContractError> {
    if observations.schema != PERFORMANCE_OBSERVATIONS_SCHEMA
        || observations.contract_id != contract.contract_id
        || observations.canonical_commit != contract.canonical.commit
        || observations.canonical_tree != contract.canonical.tree
        || observations.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "observation schema, contract, canonical identity, or semantic identity mismatch",
        ));
    }
    if observations.rows.len() != universe.rows.len() {
        return Err(ContractError::new(format!(
            "observations have {} rows, semantic denominator has {}",
            observations.rows.len(),
            universe.rows.len()
        )));
    }
    let models: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let comparator_ids: BTreeSet<&str> = contract
        .reporting
        .comparators
        .iter()
        .map(|comparator| comparator.id.as_str())
        .collect();
    let mut seen_rows = BTreeSet::new();
    for row in &observations.rows {
        if !seen_rows.insert(row.job_id.as_str()) {
            return Err(ContractError::new(format!(
                "duplicate observation job ID {:?}",
                row.job_id
            )));
        }
        let semantic = universe.rows.get(&row.job_id).ok_or_else(|| {
            ContractError::new(format!(
                "observation job {:?} is not in denominator",
                row.job_id
            ))
        })?;
        if row.model != semantic.model || row.semantic_status != semantic.status {
            return Err(ContractError::new(format!(
                "observation job {:?} model or semantic status mismatch",
                row.job_id
            )));
        }
        match semantic.status {
            RowSemanticStatus::Unsupported => {
                if !row.boundaries.is_empty() || row.reason.as_deref() != semantic.reason.as_deref()
                {
                    return Err(ContractError::new(format!(
                        "unsupported row {:?} must preserve its reason and have no timing boundaries",
                        row.job_id
                    )));
                }
            }
            RowSemanticStatus::Supported => {
                if row.reason.is_some() {
                    return Err(ContractError::new(format!(
                        "supported row {:?} has an unsupported reason",
                        row.job_id
                    )));
                }
                let model = models[row.model.as_str()];
                validate_supported_row(
                    contract,
                    observations.phase,
                    row,
                    semantic,
                    model,
                    &comparator_ids,
                )?;
            }
        }
    }
    let expected_rows: BTreeSet<&str> = universe.rows.keys().map(String::as_str).collect();
    if seen_rows != expected_rows {
        return Err(ContractError::new(
            "observation row IDs do not equal the semantic denominator",
        ));
    }
    Ok(())
}

fn validate_supported_row(
    contract: &PerformanceContract,
    phase: ObservationPhase,
    row: &PerformanceRow,
    semantic: &SemanticRow,
    model: &ModelContract,
    comparator_ids: &BTreeSet<&str>,
) -> Result<(), ContractError> {
    let mut boundaries = BTreeMap::new();
    for boundary in &row.boundaries {
        if boundaries
            .insert(boundary.boundary.as_str(), boundary)
            .is_some()
        {
            return Err(ContractError::new(format!(
                "row {:?} repeats boundary {:?}",
                row.job_id, boundary.boundary
            )));
        }
    }
    let expected_boundaries: BTreeSet<&str> = model
        .lifecycle_boundaries
        .iter()
        .map(String::as_str)
        .collect();
    let actual_boundaries: BTreeSet<&str> = boundaries.keys().copied().collect();
    if actual_boundaries != expected_boundaries {
        return Err(ContractError::new(format!(
            "row {:?} boundary set {actual_boundaries:?} differs from {expected_boundaries:?}",
            row.job_id
        )));
    }
    for boundary in boundaries.values() {
        let mut comparisons = BTreeMap::new();
        for comparison in &boundary.comparisons {
            if comparisons
                .insert(comparison.comparator.as_str(), comparison)
                .is_some()
            {
                return Err(ContractError::new(format!(
                    "row {:?} boundary {:?} repeats comparator {:?}",
                    row.job_id, boundary.boundary, comparison.comparator
                )));
            }
        }
        let actual_comparators: BTreeSet<&str> = comparisons.keys().copied().collect();
        if &actual_comparators != comparator_ids {
            return Err(ContractError::new(format!(
                "row {:?} boundary {:?} comparator set is incomplete",
                row.job_id, boundary.boundary
            )));
        }
        for (comparator, comparison) in comparisons {
            validate_comparison(
                contract,
                phase,
                comparison,
                semantic.comparator_statuses[comparator],
            )?;
        }
    }
    Ok(())
}

fn validate_comparison(
    contract: &PerformanceContract,
    phase: ObservationPhase,
    observation: &ComparisonObservation,
    reference_status: Option<Status>,
) -> Result<(), ContractError> {
    match (reference_status, observation.status) {
        (Some(Status::Pass), ComparisonStatus::Measured) => {
            let ratio = observation
                .ratio_ppm
                .filter(|value| *value > 0)
                .ok_or_else(|| ContractError::new("measured comparison lacks positive ratio"))?;
            let pair_count = observation
                .pair_count
                .ok_or_else(|| ContractError::new("measured comparison lacks pair count"))?;
            let wins = observation
                .candidate_wins
                .ok_or_else(|| ContractError::new("measured comparison lacks candidate wins"))?;
            if pair_count != contract.reporting.pairs_per_comparator || wins > pair_count {
                return Err(ContractError::new(
                    "measured comparison has wrong pair count or impossible wins",
                ));
            }
            let expected_pass = ratio < contract.reporting.ratio_ppm_exclusive_upper_bound
                && wins >= contract.reporting.minimum_candidate_wins;
            if observation.pointwise_pass != Some(expected_pass) || observation.reason.is_some() {
                return Err(ContractError::new(
                    "measured comparison has inconsistent pointwise decision or reason",
                ));
            }
        }
        (Some(Status::Pass), ComparisonStatus::Pending) if phase == ObservationPhase::Draft => {
            require_empty_measurement(observation, true)?;
        }
        (Some(Status::Pass), ComparisonStatus::Pending) => {
            return Err(ContractError::new(
                "qualification observations cannot retain pending comparisons",
            ));
        }
        (Some(Status::Pass), ComparisonStatus::NotComparable) => {
            return Err(ContractError::new(
                "passing semantic comparator cannot be reported as not comparable",
            ));
        }
        (Some(_) | None, ComparisonStatus::NotComparable) => {
            require_empty_measurement(observation, true)?;
        }
        (Some(_) | None, ComparisonStatus::Measured | ComparisonStatus::Pending) => {
            return Err(ContractError::new(
                "unavailable or nonpassing comparator must be explicitly not comparable",
            ));
        }
    }
    Ok(())
}

fn require_empty_measurement(
    observation: &ComparisonObservation,
    require_reason: bool,
) -> Result<(), ContractError> {
    if observation.ratio_ppm.is_some()
        || observation.pair_count.is_some()
        || observation.candidate_wins.is_some()
        || observation.pointwise_pass.is_some()
        || (require_reason && observation.reason.as_deref().is_none_or(str::is_empty))
    {
        return Err(ContractError::new(
            "unmeasured comparison has measurement fields or lacks a reason",
        ));
    }
    Ok(())
}

fn require_partition(
    total: usize,
    supported: usize,
    unsupported: usize,
    label: &str,
) -> Result<(), ContractError> {
    let sum = supported
        .checked_add(unsupported)
        .ok_or_else(|| ContractError::new(format!("{label} coverage overflow")))?;
    if total == 0 || sum != total {
        return Err(ContractError::new(format!(
            "{label} coverage {supported}+{unsupported} differs from {total}"
        )));
    }
    Ok(())
}

fn checked_sum(left: usize, right: usize, label: &str) -> Result<usize, ContractError> {
    left.checked_add(right)
        .ok_or_else(|| ContractError::new(format!("{label} row count overflow")))
}

fn unique_tokens(values: &[String], label: &str) -> Result<BTreeSet<String>, ContractError> {
    let mut unique = BTreeSet::new();
    for value in values {
        require_token(value, label)?;
        if !unique.insert(value.clone()) {
            return Err(ContractError::new(format!(
                "{label} contains duplicate {value:?}"
            )));
        }
    }
    Ok(unique)
}

fn require_text(value: &str, label: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.contains(['\n', '\r', '\t']) {
        return Err(ContractError::new(format!("{label} is empty or multiline")));
    }
    Ok(())
}

fn require_token(value: &str, label: &str) -> Result<(), ContractError> {
    require_text(value, label)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ContractError::new(format!(
            "{label} must be a whitespace-free token"
        )));
    }
    Ok(())
}

fn require_oid(value: &str, label: &str) -> Result<(), ContractError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::new(format!(
            "{label} is not an exact lowercase 40-hex object ID"
        )));
    }
    Ok(())
}

fn require_digest(value: &str, label: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::new(format!(
            "{label} is not an exact lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterIdentity, Coverage, InputReceipt, Receipt};

    const CURRENT_CONTRACT: &str =
        include_str!("../../../research/rebar/performance/current-main-a1a87d11-contract.json");

    fn contract() -> PerformanceContract {
        serde_json::from_str(CURRENT_CONTRACT).expect("checked-in contract decodes")
    }

    fn receipt(
        job_id: String,
        benchmark: String,
        model: String,
        adapter: String,
        target_engine: &str,
        status: Status,
    ) -> Receipt {
        Receipt {
            job_id,
            benchmark,
            target_engine: target_engine.to_string(),
            adapter,
            model,
            input: InputReceipt {
                pattern_sha256: vec!["1".repeat(64)],
                haystack_sha256: "2".repeat(64),
                haystack_bytes: 1,
                unicode: false,
                case_insensitive: false,
            },
            expected: 0,
            actual: (status == Status::Pass).then_some(0),
            candidate_plan: None,
            status,
            reason: (status != Status::Pass).then(|| "typed unsupported".to_string()),
        }
    }

    fn synthetic_semantic_report(
        contract: &mut PerformanceContract,
    ) -> (Vec<u8>, SemanticUniverse) {
        let rust = contract.reporting.comparators[0].semantic_adapter.clone();
        let re2 = contract.reporting.comparators[1].semantic_adapter.clone();
        let mut receipts = Vec::new();
        for model in &contract.models {
            for index in 0..model.denominator_rows {
                let benchmark = format!("fixture/{}/row-{index:03}", model.model);
                let job_id = format!("{benchmark}@rust/regex");
                let candidate_status = if index < model.supported_rows {
                    Status::Pass
                } else {
                    Status::Unsupported
                };
                receipts.push(receipt(
                    job_id.clone(),
                    benchmark.clone(),
                    model.model.clone(),
                    contract.semantic.fre_adapter.clone(),
                    "rust/regex",
                    candidate_status,
                ));
                receipts.push(receipt(
                    job_id,
                    benchmark.clone(),
                    model.model.clone(),
                    rust.clone(),
                    "rust/regex",
                    Status::Pass,
                ));
                receipts.push(receipt(
                    format!("{benchmark}@re2"),
                    benchmark,
                    model.model.clone(),
                    re2.clone(),
                    "re2",
                    Status::Pass,
                ));
            }
        }
        receipts.sort_by(|left, right| {
            (&left.job_id, &left.adapter).cmp(&(&right.job_id, &right.adapter))
        });
        let receipt_bytes = serde_json::to_vec(&receipts).expect("serialize receipts");
        contract.semantic.receipts_sha256 = digest(&receipt_bytes);
        let mut by_adapter_status = BTreeMap::new();
        by_adapter_status.insert(
            contract.semantic.fre_adapter.clone(),
            BTreeMap::from([
                (Status::Pass, contract.semantic.supported_rows),
                (Status::Unsupported, contract.semantic.unsupported_rows),
            ]),
        );
        by_adapter_status.insert(
            rust.clone(),
            BTreeMap::from([(Status::Pass, contract.semantic.denominator_rows)]),
        );
        by_adapter_status.insert(
            re2.clone(),
            BTreeMap::from([(Status::Pass, contract.semantic.denominator_rows)]),
        );
        let report = Report {
            schema: contract.semantic.report_schema.clone(),
            input_schema: "fixture-input-v1".to_string(),
            manifest_sha256: contract.semantic.manifest_sha256.clone(),
            rebar_revision: contract.semantic.rebar_revision.clone(),
            adapters: vec![
                AdapterIdentity {
                    adapter: contract.semantic.fre_adapter.clone(),
                    identity: "fixture FRE".to_string(),
                    availability: "fixture".to_string(),
                    runtime_sha256: None,
                },
                AdapterIdentity {
                    adapter: rust,
                    identity: "fixture Rust".to_string(),
                    availability: "fixture".to_string(),
                    runtime_sha256: None,
                },
                AdapterIdentity {
                    adapter: re2,
                    identity: "fixture RE2".to_string(),
                    availability: "fixture".to_string(),
                    runtime_sha256: None,
                },
            ],
            coverage: Coverage {
                by_adapter_status,
                by_model_status: BTreeMap::new(),
                total: receipts.len(),
            },
            receipts_sha256: contract.semantic.receipts_sha256.clone(),
            receipts,
            klv_differentials: Vec::new(),
        };
        let bytes = report_bytes(&report).expect("serialize report");
        contract.semantic.accepted_report_sha256 = vec![digest(&bytes)];
        let universe =
            validate_semantic_report(contract, &bytes).expect("semantic report validates");
        (bytes, universe)
    }

    #[test]
    fn checked_in_contract_covers_every_model_and_exact_main() {
        let contract = contract();
        validate_contract(&contract).expect("checked-in contract validates");
        validate_exact_main(&contract, &contract.canonical).expect("exact identity validates");
        let mut moved = contract.canonical.clone();
        moved.commit = "0".repeat(40);
        assert!(validate_exact_main(&contract, &moved).is_err());
    }

    #[test]
    fn semantic_report_binds_the_complete_denominator() {
        let mut contract = contract();
        let (bytes, universe) = synthetic_semantic_report(&mut contract);
        assert_eq!(universe.len(), 344);

        let mut report: Report = serde_json::from_slice(&bytes).expect("decode report");
        let removed = report
            .receipts
            .iter()
            .position(|receipt| receipt.adapter == contract.semantic.fre_adapter)
            .expect("FRE receipt exists");
        report.receipts.remove(removed);
        report.coverage.total = report.receipts.len();
        let receipt_bytes = serde_json::to_vec(&report.receipts).expect("serialize receipts");
        report.receipts_sha256 = digest(&receipt_bytes);
        contract.semantic.receipts_sha256 = report.receipts_sha256.clone();
        let hidden = report_bytes(&report).expect("serialize hidden report");
        contract.semantic.accepted_report_sha256 = vec![digest(&hidden)];
        assert!(validate_semantic_report(&contract, &hidden).is_err());
    }

    #[test]
    fn pointwise_draft_reports_every_row_boundary_and_comparator() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let observations =
            generate_draft_observations(&contract, &universe).expect("draft generation succeeds");
        validate_observations(&contract, &universe, &observations)
            .expect("coverage-complete draft validates");

        let encoded = observation_bytes(&observations).expect("draft serializes");
        let decoded: PerformanceObservations =
            serde_json::from_slice(&encoded).expect("draft round trips");
        assert_eq!(decoded, observations);

        let mut hidden_row = observations.clone();
        hidden_row.rows.pop();
        assert!(validate_observations(&contract, &universe, &hidden_row).is_err());

        let mut duplicate_row = observations.clone();
        duplicate_row.rows[1] = duplicate_row.rows[0].clone();
        assert!(validate_observations(&contract, &universe, &duplicate_row).is_err());

        let mut wrong_model = observations.clone();
        wrong_model.rows[0].model = "grep".to_string();
        assert!(validate_observations(&contract, &universe, &wrong_model).is_err());

        let mut wrong_support = observations.clone();
        wrong_support.rows[0].semantic_status = match wrong_support.rows[0].semantic_status {
            RowSemanticStatus::Supported => RowSemanticStatus::Unsupported,
            RowSemanticStatus::Unsupported => RowSemanticStatus::Supported,
        };
        assert!(validate_observations(&contract, &universe, &wrong_support).is_err());

        let mut hidden_comparator = observations.clone();
        let supported = hidden_comparator
            .rows
            .iter_mut()
            .find(|row| row.semantic_status == RowSemanticStatus::Supported)
            .expect("supported row exists");
        supported.boundaries[0].comparisons.pop();
        assert!(validate_observations(&contract, &universe, &hidden_comparator).is_err());
    }

    #[test]
    fn qualification_rejects_pending_or_inconsistent_pointwise_results() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let mut observations =
            generate_draft_observations(&contract, &universe).expect("draft generation succeeds");
        observations.phase = ObservationPhase::Qualification;
        assert!(validate_observations(&contract, &universe, &observations).is_err());

        observations.phase = ObservationPhase::Draft;
        let measured = observations
            .rows
            .iter_mut()
            .find(|row| row.semantic_status == RowSemanticStatus::Supported)
            .expect("supported row exists")
            .boundaries
            .first_mut()
            .expect("boundary exists")
            .comparisons
            .first_mut()
            .expect("comparison exists");
        measured.status = ComparisonStatus::Measured;
        measured.ratio_ppm = Some(900_000);
        measured.pair_count = Some(contract.reporting.pairs_per_comparator);
        measured.candidate_wins = Some(contract.reporting.minimum_candidate_wins);
        measured.pointwise_pass = Some(false);
        measured.reason = None;
        assert!(validate_observations(&contract, &universe, &observations).is_err());
    }
}
