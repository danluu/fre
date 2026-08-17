//! Executable immutable-tested-source performance qualification contract.
//!
//! This module deliberately validates coverage before it accepts timing
//! observations. A benchmark row cannot disappear because it is unsupported,
//! slow, missing a comparator, or inconvenient for an aggregate score.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
    process::Command,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CompareError, CurrentFreCaptureLifecycle, InputReceipt, Report, Status, report_bytes};

/// Stable schema for a performance qualification contract.
pub const PERFORMANCE_CONTRACT_SCHEMA: &str = "fre.rebar.performance-contract.v2";
/// Stable schema for pointwise performance observations.
pub const PERFORMANCE_OBSERVATIONS_SCHEMA: &str = "fre.rebar.performance-observations.v2";
/// Stable schema for one raw current-FRE capture lifecycle sample.
pub const CAPTURE_LIFECYCLE_RAW_SCHEMA: &str = "fre.rebar.capture-lifecycle-raw.v1";
/// Stable schema for a deterministic fresh-process capture pair schedule.
pub const CAPTURE_PAIR_SCHEDULE_SCHEMA: &str = "fre.rebar.capture-pair-schedule.v1";
/// Stable schema for the complete all-model fresh-process pair schedule.
pub const PERFORMANCE_PAIR_SCHEDULE_SCHEMA: &str = "fre.rebar.performance-pair-schedule.v1";
/// Stable schema for one all-model candidate or reference timing arm.
pub const PERFORMANCE_RAW_SCHEMA: &str = "fre.rebar.performance-raw.v2";
/// Stable schema for one all-model resource observation arm.
pub const PERFORMANCE_RESOURCE_RAW_SCHEMA: &str = "fre.rebar.performance-resource-raw.v1";
/// Stable schema for deterministic current-FRE runner route admission.
pub const PERFORMANCE_RUNNER_MANIFEST_SCHEMA: &str = "fre.rebar.performance-runner-manifest.v1";
/// Stable schema for an independently authorized all-model timing execution
/// packet.
pub const PERFORMANCE_EXECUTION_PACKET_SCHEMA: &str = "fre.rebar.performance-execution-packet.v1";
/// Stable schema for one immutable attempt at one exact pair-schedule slot.
pub const PERFORMANCE_PAIR_TASK_SCHEMA: &str = "fre.rebar.performance-pair-task.v1";
/// Stable schema for one raw Rust/RE2 capture reference arm.
pub const CAPTURE_REFERENCE_RAW_SCHEMA: &str = "fre.rebar.capture-reference-raw.v1";
/// Stable schema for one raw capture resource-observation arm.
pub const CAPTURE_RESOURCE_RAW_SCHEMA: &str = "fre.rebar.capture-resource-raw.v1";
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

/// Exact immutable Git source identity measured by the contract.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TestedSourceIdentity {
    /// Exact tested source commit.
    pub commit: String,
    /// Exact tested source tree.
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
    /// Exact immutable Git source identity measured by this contract.
    pub tested_source: TestedSourceIdentity,
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

/// State of one engine's resource metric at one lifecycle boundary.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceMetricStatus {
    /// A draft declares the metric but has no observation yet.
    Pending,
    /// The complete fresh-process sample set produced a median value.
    Measured,
    /// The authenticated collector cannot provide this metric.
    Unavailable,
    /// The semantic comparator point does not exist, so no metric applies.
    NotComparable,
}

/// One engine's aggregate for one resource metric.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceArmSummary {
    /// Pending, measured, or explicitly unavailable.
    pub status: ResourceMetricStatus,
    /// Exact collector identity for measured or probed-unavailable evidence.
    pub collector: Option<ResourceCollectorIdentity>,
    /// Median raw metric value across the contracted pair count.
    pub median: Option<u64>,
    /// Number of fresh-process samples represented by the median.
    pub sample_count: Option<u32>,
    /// Required explanation for pending or unavailable metrics.
    pub reason: Option<String>,
}

/// Candidate and reference aggregates for one resource metric.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourcePairSummary {
    /// Current-FRE resource aggregate.
    pub candidate: ResourceArmSummary,
    /// Rust-regex or RE2 resource aggregate.
    pub reference: ResourceArmSummary,
}

/// Allocation, retained, and process-peak resources for one exact point.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonResourceObservation {
    /// Number of allocator calls inside the lifecycle boundary.
    pub allocation_count: ResourcePairSummary,
    /// Total allocator bytes requested inside the lifecycle boundary.
    pub allocated_bytes: ResourcePairSummary,
    /// Live bytes retained after the lifecycle boundary completes.
    pub persistent_bytes: ResourcePairSummary,
    /// Process high-water resident set during the lifecycle boundary.
    pub peak_rss_bytes: ResourcePairSummary,
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
    /// Resource observations kept separate from elapsed-time state.
    pub resources: ComparisonResourceObservation,
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
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt-array digest.
    pub semantic_receipts_sha256: String,
    /// Draft or final qualification state.
    pub phase: ObservationPhase,
    /// Exactly one row for every semantic denominator row.
    pub rows: Vec<PerformanceRow>,
}

/// Exact capture operation boundary measured by one fresh runner process.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureLifecycleBoundary {
    /// First complete operation after construction and limit preparation.
    FirstPublicOperation,
    /// One untimed verified prime followed by one measured operation.
    SteadyPublicOperation,
}

impl CaptureLifecycleBoundary {
    /// Parse an exact performance-contract boundary ID.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "first-public-operation" => Ok(Self::FirstPublicOperation),
            "steady-public-operation" => Ok(Self::SteadyPublicOperation),
            other => Err(ContractError::new(format!(
                "unexpected capture lifecycle boundary {other:?}"
            ))),
        }
    }

    /// Exact performance-contract boundary ID.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstPublicOperation => "first-public-operation",
            Self::SteadyPublicOperation => "steady-public-operation",
        }
    }

    const fn priming_operations(self) -> u8 {
        match self {
            Self::FirstPublicOperation => 0,
            Self::SteadyPublicOperation => 1,
        }
    }
}

/// Contract and input identity supplied to one capture runner invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureLifecycleObservationIdentity {
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt-array digest.
    pub semantic_receipts_sha256: String,
    /// Exact Rust-target semantic job ID.
    pub job_id: String,
    /// Exact Rebar benchmark name.
    pub benchmark: String,
    /// Unique token provisioned for this fresh runner process.
    pub process_token_sha256: String,
}

/// One unaggregated, self-identifying current-FRE capture lifecycle sample.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureLifecycleRawObservation {
    /// Raw observation schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt-array digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact Rebar benchmark name.
    pub benchmark: String,
    /// Capture Rebar model.
    pub model: String,
    /// First or steady public operation.
    pub boundary: CaptureLifecycleBoundary,
    /// Authenticated current-FRE plan label.
    pub candidate_plan: String,
    /// Complete semantic input identity recomputed from runner input.
    pub input: InputReceipt,
    /// Reducer copy emitted from `actual`; trusted validation joins it to the semantic row.
    pub expected: u64,
    /// Reducer returned inside the measured operation.
    pub actual: u64,
    /// Untimed operations completed before measurement.
    pub priming_operations: u8,
    /// Operations included in `elapsed_ns`.
    pub measured_operations: u8,
    /// Raw elapsed nanoseconds for the single measured operation.
    pub elapsed_ns: u64,
    /// SHA-256 of `actual.to_le_bytes()`.
    pub result_sha256: String,
    /// Unique token provisioned for this runner invocation.
    pub process_token_sha256: String,
}

/// Candidate/reference process order within one paired sample.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum CapturePairArm {
    /// Current-FRE capture lifecycle process.
    Candidate,
    /// Pinned Rust-regex or RE2 process.
    Reference,
}

/// One exact pair slot in the deterministic fresh-process schedule.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct CapturePairSlot {
    /// Global pair sequence.
    pub sequence: usize,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Capture model.
    pub model: String,
    /// First or steady operation boundary.
    pub boundary: CaptureLifecycleBoundary,
    /// Comparator ID from the performance contract.
    pub comparator: String,
    /// Zero-based pair index within this point.
    pub pair_index: u32,
    /// Alternating process order; every arm is a fresh invocation.
    pub order: [CapturePairArm; 2],
}

/// Explicit reason one semantic comparator receives no pair slots.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct CaptureUnavailableComparator {
    /// Exact semantic job ID.
    pub job_id: String,
    /// Capture model.
    pub model: String,
    /// Contracted lifecycle boundary.
    pub boundary: CaptureLifecycleBoundary,
    /// Comparator ID from the performance contract.
    pub comparator: String,
    /// Exact semantic absence/nonpass reason.
    pub reason: String,
}

/// Complete deterministic schedule for supported capture rows.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapturePairSchedule {
    /// Schedule schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Pairs required for every available comparator point.
    pub pairs_per_comparator: u32,
    /// Every available comparator pair slot in execution order.
    pub slots: Vec<CapturePairSlot>,
    /// Every unavailable comparator point, retained explicitly.
    pub unavailable: Vec<CaptureUnavailableComparator>,
}

/// One pair slot in the complete all-model performance schedule.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct PerformancePairSlot {
    /// Global pair sequence.
    pub sequence: usize,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary ID from the contract.
    pub boundary: String,
    /// Comparator ID from the contract.
    pub comparator: String,
    /// Zero-based pair index within this point.
    pub pair_index: u32,
    /// Alternating fresh-process arm order.
    pub order: [CapturePairArm; 2],
}

/// One all-model comparator point omitted from pair execution.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct PerformanceUnavailableComparator {
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary ID from the contract.
    pub boundary: String,
    /// Comparator ID from the contract.
    pub comparator: String,
    /// Exact semantic absence/nonpass reason.
    pub reason: String,
}

/// Complete deterministic fresh-process schedule for every supported model.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformancePairSchedule {
    /// Schedule schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Pairs required for every available comparator point.
    pub pairs_per_comparator: u32,
    /// Every available all-model pair slot in execution order.
    pub slots: Vec<PerformancePairSlot>,
    /// Every unavailable comparator point, retained explicitly.
    pub unavailable: Vec<PerformanceUnavailableComparator>,
}

/// Exact untimed process/artifact state before one lifecycle measurement.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PerformanceLifecyclePreparation {
    /// No process or allocator warm-up beyond input loading.
    ColdProcess,
    /// Process and allocator initialized without reusing a regex artifact.
    AllocatorInitialized,
    /// One already-built artifact before its first public operation.
    BuiltArtifact,
    /// One already-built artifact after one verified untimed operation.
    PrimedArtifact,
    /// Fresh complete composite workload state.
    CompositeFresh,
}

/// Complete identity provisioned to one current-FRE all-model candidate arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceCandidateObservationIdentity {
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary.
    pub boundary: String,
    /// Comparator paired with this candidate process.
    pub comparator: String,
    /// Authenticated construction-selected current-FRE plan.
    pub candidate_plan: String,
    /// Authenticated selected grep runtime; absent for non-grep models.
    pub candidate_runtime: Option<String>,
    /// Complete input identity recomputed from runner input.
    pub input: InputReceipt,
    /// Unique token provisioned for this fresh process.
    pub process_token_sha256: String,
}

/// Complete identity provisioned to one Rust-regex or RE2 all-model
/// reference arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerformanceReferenceObservationIdentity {
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary.
    pub boundary: String,
    /// Exact reference comparator executed by this process.
    pub comparator: String,
    /// Complete input identity recomputed from runner input.
    pub input: InputReceipt,
    /// Unique token provisioned for this fresh process.
    pub process_token_sha256: String,
}

/// One self-identifying all-model timing arm.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRawObservation {
    /// Raw observation schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary ID.
    pub boundary: String,
    /// Comparator point to which this arm belongs.
    pub comparator: String,
    /// Candidate or reference engine.
    pub arm: CapturePairArm,
    /// Exact current-FRE plan for a candidate arm; absent for a reference.
    pub candidate_plan: Option<String>,
    /// Exact selected current-FRE grep runtime; absent for other arms/models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_runtime: Option<String>,
    /// Complete semantic input identity.
    pub input: InputReceipt,
    /// Reducer copy emitted from `actual`; trusted validation joins it to the semantic row.
    pub expected: u64,
    /// Reducer returned by the observed operation.
    pub actual: u64,
    /// Exact untimed state required by the lifecycle phase.
    pub preparation: PerformanceLifecyclePreparation,
    /// Untimed lifecycle operations completed before measurement.
    pub priming_operations: u8,
    /// Lifecycle operations included in `elapsed_ns`.
    pub measured_operations: u8,
    /// Raw elapsed nanoseconds for one complete lifecycle operation.
    pub elapsed_ns: u64,
    /// SHA-256 of `actual.to_le_bytes()`.
    pub result_sha256: String,
    /// Unique token provisioned for this fresh process.
    pub process_token_sha256: String,
}

/// Candidate and reference timing arms for one all-model schedule slot.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformancePairEvidence {
    /// Exact schedule slot.
    pub slot: PerformancePairSlot,
    /// Current-FRE timing arm.
    pub candidate: PerformanceRawObservation,
    /// Rust-regex or RE2 timing arm.
    pub reference: PerformanceRawObservation,
}

/// One self-identifying all-model resource-observation arm.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceResourceRawObservation {
    /// Raw resource schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary ID.
    pub boundary: String,
    /// Comparator point to which this arm belongs.
    pub comparator: String,
    /// Candidate or reference engine.
    pub arm: CapturePairArm,
    /// Exact current-FRE plan for a candidate arm; absent for a reference.
    pub candidate_plan: Option<String>,
    /// Complete semantic input identity.
    pub input: InputReceipt,
    /// Expected semantic reducer.
    pub expected: u64,
    /// Reducer returned by the observed operation.
    pub actual: u64,
    /// Exact untimed state required by the lifecycle phase.
    pub preparation: PerformanceLifecyclePreparation,
    /// Untimed lifecycle operations completed before resource observation.
    pub priming_operations: u8,
    /// Lifecycle operations included in this resource observation.
    pub observed_operations: u8,
    /// SHA-256 of `actual.to_le_bytes()`.
    pub result_sha256: String,
    /// Exact authenticated resource collector.
    pub collector: ResourceCollectorIdentity,
    /// Unique token provisioned for this fresh collector process.
    pub process_token_sha256: String,
    /// Allocator calls inside the exact boundary.
    pub allocation_count: RawResourceMetric,
    /// Allocator bytes requested inside the exact boundary.
    pub allocated_bytes: RawResourceMetric,
    /// Live bytes retained when the exact boundary completes.
    pub persistent_bytes: RawResourceMetric,
    /// Process high-water resident set during the exact boundary.
    pub peak_rss_bytes: RawResourceMetric,
}

/// Candidate and reference resource arms for one all-model schedule slot.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceResourcePairEvidence {
    /// Exact schedule slot.
    pub slot: PerformancePairSlot,
    /// Current-FRE resource arm.
    pub candidate: PerformanceResourceRawObservation,
    /// Rust/RE2 resource arm.
    pub reference: PerformanceResourceRawObservation,
}

/// Exact current-FRE runner family admitted for one supported semantic row.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum PerformanceRunnerRoute {
    /// One-pattern aggregate compile/count/span-sum lifecycle.
    AggregateSingle,
    /// Ordered multi-pattern aggregate compile/count/span-sum/capture-count lifecycle.
    AggregateMany,
    /// Portable line-oriented grep lifecycle.
    PortableGrep,
    /// Persistent-history capture lifecycle.
    Capture,
    /// Complete fresh composite lifecycle.
    Composite,
}

/// One supported row's exact candidate runner admission record.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRunnerRow {
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact Rebar model.
    pub model: String,
    /// Authenticated candidate plan.
    pub candidate_plan: String,
    /// Number of exact pattern identities in the semantic input.
    pub pattern_count: usize,
    /// Admitted candidate runner family.
    pub route: PerformanceRunnerRoute,
    /// Every exact lifecycle boundary required for this row.
    pub boundaries: Vec<String>,
    /// Pair slots generated for passing comparators on this row.
    pub pair_slots: usize,
    /// Explicit unavailable boundary/comparator points on this row.
    pub unavailable_points: usize,
}

/// Complete deterministic current-FRE runner admission manifest.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRunnerManifest {
    /// Runner manifest schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exactly one row for every supported current-FRE semantic receipt.
    pub rows: Vec<PerformanceRunnerRow>,
}

/// Exact executable and version policy authorized for timing execution.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceExecutablePolicy {
    /// SHA-256 of the exact executable bytes.
    pub sha256: String,
    /// Exact executable length.
    pub bytes: u64,
    /// Exact one-line `--version` stdout, including LF.
    pub version_stdout: String,
    /// SHA-256 of the exact version stdout bytes.
    pub version_stdout_sha256: String,
    /// Source commit bound by the authenticated build receipt.
    pub source_commit: String,
    /// Source tree bound by the authenticated build receipt.
    pub source_tree: String,
    /// Immutable build receipt that binds executable bytes to source and build
    /// policy.
    pub build_receipt_sha256: String,
}

/// Packet-bound timing authority required before either arm may execute.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceTimingAuthorityPolicy {
    /// Stable authorization/lease protocol.
    pub protocol_id: String,
    /// Exact coordinator executable or policy digest.
    pub coordinator_sha256: String,
    /// Immutable authorization receipt digest. Receipt owner, scope, TTL and
    /// packet binding are authenticated by the independent publication and
    /// later live-lease transitions, not inferred from this digest.
    pub authorization_receipt_sha256: String,
    /// Required resource scope; currently exactly `timing`.
    pub required_scope: String,
}

/// Hard process and I/O limits for one pair attempt.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformancePairExecutionLimits {
    /// Maximum bytes in either canonical KLV arm.
    pub max_klv_bytes: u64,
    /// Maximum retained child stdout bytes.
    pub max_stdout_bytes: u64,
    /// Maximum retained child stderr bytes.
    pub max_stderr_bytes: u64,
    /// Hard process-group deadline for one arm.
    pub arm_deadline_ms: u64,
}

/// Independently authorized executable, input, and timing policy for a
/// complete all-model pair campaign.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceExecutionPacket {
    /// Packet schema.
    pub schema: String,
    /// SHA-256 of the exact contract bytes.
    pub contract_sha256: String,
    /// SHA-256 of the exact accepted semantic report.
    pub semantic_report_sha256: String,
    /// SHA-256 of the exact expanded Rebar manifest.
    pub expanded_manifest_sha256: String,
    /// SHA-256 of the canonical complete pair schedule.
    pub pair_schedule_sha256: String,
    /// SHA-256 of the canonical current-FRE runner manifest.
    pub runner_manifest_sha256: String,
    /// Exact tested-source commit repeated from the contract (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree repeated from the contract (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic adapter implemented by the candidate wrapper.
    pub candidate_adapter: String,
    /// Pair executor authorized by the timing authority.
    pub executor: PerformanceExecutablePolicy,
    /// Current-FRE candidate wrapper authorized for every candidate arm.
    pub candidate_wrapper: PerformanceExecutablePolicy,
    /// Reference adapter wrapper authorized for every reference arm.
    pub reference_wrapper: PerformanceExecutablePolicy,
    /// Exact upstream runtime authorized for each comparator ID.
    pub reference_runners: BTreeMap<String, PerformanceExecutablePolicy>,
    /// External timing authorization protocol.
    pub timing_authority: PerformanceTimingAuthorityPolicy,
    /// Hard per-attempt limits.
    pub limits: PerformancePairExecutionLimits,
}

/// One prepublished attempt declaration at one exact schedule sequence.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PerformancePairTask {
    /// Task schema.
    pub schema: String,
    /// Independently authorized execution-packet digest.
    pub execution_packet_sha256: String,
    /// Exact global pair-schedule sequence.
    pub sequence: usize,
    /// Stable declared attempt ID. The executor ledger must reject reuse.
    pub attempt_id: String,
    /// Candidate process token digest reserved by the executor ledger.
    pub candidate_process_token_sha256: String,
    /// Reference process token digest reserved by the executor ledger.
    pub reference_process_token_sha256: String,
}

/// Opaque proof that one execution packet passed independent authorization
/// and every contract-derived validation. Task admission requires this value
/// so packet validation cannot be accidentally skipped.
#[derive(Debug)]
pub struct ValidatedPerformanceExecutionContext {
    universe: SemanticUniverse,
    packet_sha256: String,
    pair_schedule_sha256: String,
}

impl ValidatedPerformanceExecutionContext {
    /// Authenticated semantic universe used for raw-arm validation.
    #[must_use]
    pub const fn universe(&self) -> &SemanticUniverse {
        &self.universe
    }

    /// Independently authorized packet digest.
    #[must_use]
    pub fn packet_sha256(&self) -> &str {
        &self.packet_sha256
    }
}

/// Opaque proof that one independently authorized task passed packet,
/// schedule, attempt, and process-token validation.
#[derive(Debug)]
pub struct ValidatedPerformancePairTaskContext {
    packet_sha256: String,
    task_sha256: String,
    slot: PerformancePairSlot,
    attempt_id: String,
    candidate_process_token_sha256: String,
    reference_process_token_sha256: String,
}

impl ValidatedPerformancePairTaskContext {
    /// Independently authorized execution-packet digest.
    #[must_use]
    pub fn packet_sha256(&self) -> &str {
        &self.packet_sha256
    }

    /// Independently authorized task digest.
    #[must_use]
    pub fn task_sha256(&self) -> &str {
        &self.task_sha256
    }

    /// Exact canonical pair-schedule slot.
    #[must_use]
    pub const fn slot(&self) -> &PerformancePairSlot {
        &self.slot
    }

    /// Exact attempt identifier.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Candidate process token reserved by this task.
    #[must_use]
    pub fn candidate_process_token_sha256(&self) -> &str {
        &self.candidate_process_token_sha256
    }

    /// Reference process token reserved by this task.
    #[must_use]
    pub fn reference_process_token_sha256(&self) -> &str {
        &self.reference_process_token_sha256
    }
}

/// One raw pinned-reference arm corresponding to a schedule slot.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureReferenceRawObservation {
    /// Reference raw schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Capture model.
    pub model: String,
    /// Contracted lifecycle boundary.
    pub boundary: CaptureLifecycleBoundary,
    /// Comparator ID from the performance contract.
    pub comparator: String,
    /// Exact semantic input identity.
    pub input: InputReceipt,
    /// Expected semantic reducer.
    pub expected: u64,
    /// Actual reference reducer.
    pub actual: u64,
    /// Untimed reference operations completed before measurement.
    pub priming_operations: u8,
    /// Reference operations included in `elapsed_ns`.
    pub measured_operations: u8,
    /// Raw elapsed nanoseconds for one operation.
    pub elapsed_ns: u64,
    /// SHA-256 of `actual.to_le_bytes()`.
    pub result_sha256: String,
    /// Unique token provisioned for this fresh reference process.
    pub process_token_sha256: String,
}

/// Candidate and reference arms collected for one exact pair slot.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapturePairEvidence {
    /// Exact schedule slot.
    pub slot: CapturePairSlot,
    /// Current-FRE raw arm.
    pub candidate: CaptureLifecycleRawObservation,
    /// Rust/RE2 raw arm.
    pub reference: CaptureReferenceRawObservation,
}

/// Engine arm whose resources were observed.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceObservationArm {
    /// Current FRE.
    Candidate,
    /// The comparator named by the enclosing schedule slot.
    Reference,
}

/// Authenticated identity of the resource collector expected by conversion.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceCollectorIdentity {
    /// Stable collector/probe configuration ID.
    pub collector_id: String,
    /// SHA-256 of the exact collector executable or immutable probe bundle.
    pub collector_sha256: String,
}

/// One unaggregated resource metric from a fresh process.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawResourceMetric {
    /// Raw evidence is measured or explicitly unavailable; never pending.
    pub status: ResourceMetricStatus,
    /// Raw metric value when measured.
    pub value: Option<u64>,
    /// Exact collector reason when unavailable.
    pub reason: Option<String>,
}

/// One self-identifying candidate or reference resource arm.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureResourceRawObservation {
    /// Raw resource observation schema.
    pub schema: String,
    /// Exact performance contract ID.
    pub contract_id: String,
    /// Exact tested-source commit (legacy artifact field name).
    pub canonical_commit: String,
    /// Exact tested-source tree (legacy artifact field name).
    pub canonical_tree: String,
    /// Exact semantic receipt digest.
    pub semantic_receipts_sha256: String,
    /// Exact semantic job ID.
    pub job_id: String,
    /// Exact benchmark name.
    pub benchmark: String,
    /// Exact Rebar model.
    pub model: String,
    /// Exact lifecycle boundary measured in this process.
    pub boundary: CaptureLifecycleBoundary,
    /// Comparator point to which this arm belongs.
    pub comparator: String,
    /// Candidate or reference engine arm.
    pub arm: ResourceObservationArm,
    /// Current-FRE plan for a candidate arm; absent for a reference arm.
    pub candidate_plan: Option<String>,
    /// Complete semantic input identity.
    pub input: InputReceipt,
    /// Exact semantic reducer expected by the collector.
    pub expected: u64,
    /// Reducer returned by the observed lifecycle operation.
    pub actual: u64,
    /// Untimed lifecycle operations completed before resource observation.
    pub priming_operations: u8,
    /// Lifecycle operations included in this resource observation.
    pub observed_operations: u8,
    /// SHA-256 of `actual.to_le_bytes()`.
    pub result_sha256: String,
    /// Exact authenticated resource collector.
    pub collector: ResourceCollectorIdentity,
    /// Unique token provisioned for this fresh collector process.
    pub process_token_sha256: String,
    /// Allocator calls inside the exact boundary.
    pub allocation_count: RawResourceMetric,
    /// Allocator bytes requested inside the exact boundary.
    pub allocated_bytes: RawResourceMetric,
    /// Live bytes retained when the exact boundary completes.
    pub persistent_bytes: RawResourceMetric,
    /// Process high-water resident set during the exact boundary.
    pub peak_rss_bytes: RawResourceMetric,
}

/// Candidate and reference resource arms for one deterministic pair slot.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureResourcePairEvidence {
    /// Exact schedule slot.
    pub slot: CapturePairSlot,
    /// Current-FRE resource arm.
    pub candidate: CaptureResourceRawObservation,
    /// Rust/RE2 resource arm.
    pub reference: CaptureResourceRawObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticRow {
    benchmark: String,
    model: String,
    status: RowSemanticStatus,
    reason: Option<String>,
    input: InputReceipt,
    expected: u64,
    candidate_plan: Option<String>,
    comparator_statuses: BTreeMap<String, Option<Status>>,
}

/// Authenticated semantic row universe used to validate observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticUniverse {
    rows: BTreeMap<String, SemanticRow>,
}

type CapturePointKey = (String, CaptureLifecycleBoundary, String);
type CapturePairMeasurement = (u32, u64, bool);
type CapturePairGroups = BTreeMap<CapturePointKey, Vec<CapturePairMeasurement>>;
type PerformancePointKey = (String, String, String);
type PerformancePairGroups = BTreeMap<PerformancePointKey, Vec<CapturePairMeasurement>>;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ResourceMetricKind {
    AllocationCount,
    AllocatedBytes,
    PersistentBytes,
    PeakRssBytes,
}
type ResourcePointKey = (
    String,
    CaptureLifecycleBoundary,
    String,
    ResourceObservationArm,
    ResourceMetricKind,
);
type ResourceMetricSamples = Vec<(u32, RawResourceMetric)>;
type ResourceMetricGroups = BTreeMap<ResourcePointKey, ResourceMetricSamples>;
type PerformanceResourcePointKey = (String, String, String, CapturePairArm, ResourceMetricKind);
type PerformanceResourceMetricGroups = BTreeMap<PerformanceResourcePointKey, ResourceMetricSamples>;

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
        canonical_commit: contract.tested_source.commit.clone(),
        canonical_tree: contract.tested_source.tree.clone(),
        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
        phase: ObservationPhase::Draft,
        rows,
    };
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

fn draft_comparison(comparator: &str, reference_status: Option<Status>) -> ComparisonObservation {
    let resources = draft_resource_observation(reference_status);
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
        resources,
    }
}

fn draft_resource_observation(reference_status: Option<Status>) -> ComparisonResourceObservation {
    let pair = if reference_status == Some(Status::Pass) {
        ResourcePairSummary {
            candidate: pending_resource_arm(),
            reference: pending_resource_arm(),
        }
    } else {
        let reason = comparator_unavailable_reason(reference_status);
        ResourcePairSummary {
            candidate: not_comparable_resource_arm(&reason),
            reference: not_comparable_resource_arm(&reason),
        }
    };
    ComparisonResourceObservation {
        allocation_count: pair.clone(),
        allocated_bytes: pair.clone(),
        persistent_bytes: pair.clone(),
        peak_rss_bytes: pair,
    }
}

fn pending_resource_arm() -> ResourceArmSummary {
    ResourceArmSummary {
        status: ResourceMetricStatus::Pending,
        collector: None,
        median: None,
        sample_count: None,
        reason: Some("resource observation not run".to_string()),
    }
}

fn unavailable_resource_arm(
    reason: &str,
    sample_count: u32,
    collector: &ResourceCollectorIdentity,
) -> ResourceArmSummary {
    ResourceArmSummary {
        status: ResourceMetricStatus::Unavailable,
        collector: Some(collector.clone()),
        median: None,
        sample_count: Some(sample_count),
        reason: Some(reason.to_string()),
    }
}

fn not_comparable_resource_arm(reason: &str) -> ResourceArmSummary {
    ResourceArmSummary {
        status: ResourceMetricStatus::NotComparable,
        collector: None,
        median: None,
        sample_count: None,
        reason: Some(reason.to_string()),
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

/// Serialize an all-model pair schedule as canonical compact JSON plus LF.
pub fn performance_pair_schedule_bytes(
    schedule: &PerformancePairSchedule,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(schedule)
        .map_err(|error| ContractError::new(format!("serialize performance schedule: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read a canonically serialized all-model pair schedule.
pub fn read_performance_pair_schedule(
    path: &Path,
) -> Result<PerformancePairSchedule, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let schedule: PerformancePairSchedule = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_pair_schedule_bytes(&schedule)? != bytes {
        return Err(ContractError::new(format!(
            "performance pair schedule {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(schedule)
}

/// Publish an all-model pair schedule to a new path without overwrite.
pub fn write_new_performance_pair_schedule(
    path: &Path,
    schedule: &PerformancePairSchedule,
) -> Result<(), ContractError> {
    let parent = path.parent().ok_or_else(|| {
        ContractError::new(format!("schedule path {} has no parent", path.display()))
    })?;
    if !parent.is_dir() {
        return Err(ContractError::new(format!(
            "schedule parent {} is not a directory",
            parent.display()
        )));
    }
    let bytes = performance_pair_schedule_bytes(schedule)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ContractError::new(format!("create new schedule {}: {error}", path.display()))
        })?;
    output.write_all(&bytes).map_err(|error| {
        ContractError::new(format!("write schedule {}: {error}", path.display()))
    })?;
    output
        .sync_all()
        .map_err(|error| ContractError::new(format!("sync schedule {}: {error}", path.display())))
}

/// Serialize a current-FRE runner manifest as canonical compact JSON plus LF.
pub fn performance_runner_manifest_bytes(
    manifest: &PerformanceRunnerManifest,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(manifest)
        .map_err(|error| ContractError::new(format!("serialize runner manifest: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read a canonically serialized current-FRE runner manifest.
pub fn read_performance_runner_manifest(
    path: &Path,
) -> Result<PerformanceRunnerManifest, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let manifest: PerformanceRunnerManifest = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_runner_manifest_bytes(&manifest)? != bytes {
        return Err(ContractError::new(format!(
            "performance runner manifest {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(manifest)
}

/// Publish a current-FRE runner manifest to a new path without overwrite.
pub fn write_new_performance_runner_manifest(
    path: &Path,
    manifest: &PerformanceRunnerManifest,
) -> Result<(), ContractError> {
    let parent = path.parent().ok_or_else(|| {
        ContractError::new(format!(
            "runner manifest path {} has no parent",
            path.display()
        ))
    })?;
    if !parent.is_dir() {
        return Err(ContractError::new(format!(
            "runner manifest parent {} is not a directory",
            parent.display()
        )));
    }
    let bytes = performance_runner_manifest_bytes(manifest)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ContractError::new(format!(
                "create new runner manifest {}: {error}",
                path.display()
            ))
        })?;
    output.write_all(&bytes).map_err(|error| {
        ContractError::new(format!("write runner manifest {}: {error}", path.display()))
    })?;
    output.sync_all().map_err(|error| {
        ContractError::new(format!("sync runner manifest {}: {error}", path.display()))
    })
}

/// Serialize an authorized performance execution packet as canonical compact
/// JSON plus LF.
pub fn performance_execution_packet_bytes(
    packet: &PerformanceExecutionPacket,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(packet)
        .map_err(|error| ContractError::new(format!("serialize execution packet: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read one canonically serialized authorized execution packet.
pub fn read_performance_execution_packet(
    path: &Path,
) -> Result<PerformanceExecutionPacket, ContractError> {
    let bytes = read_bounded_regular_file(path, 1_048_576, "execution packet")?;
    let packet: PerformanceExecutionPacket = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_execution_packet_bytes(&packet)? != bytes {
        return Err(ContractError::new(format!(
            "execution packet {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(packet)
}

/// Serialize one prepublished pair task as canonical compact JSON plus LF.
pub fn performance_pair_task_bytes(task: &PerformancePairTask) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(task)
        .map_err(|error| ContractError::new(format!("serialize pair task: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read one canonically serialized prepublished pair task.
pub fn read_performance_pair_task(path: &Path) -> Result<PerformancePairTask, ContractError> {
    let bytes = read_bounded_regular_file(path, 65_536, "performance pair task")?;
    let task: PerformancePairTask = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_pair_task_bytes(&task)? != bytes {
        return Err(ContractError::new(format!(
            "pair task {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(task)
}

fn read_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, ContractError> {
    let parent = path
        .parent()
        .ok_or_else(|| ContractError::new(format!("{label} {} has no parent", path.display())))?;
    let parent_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|error| {
            ContractError::new(format!("open parent {}: {error}", parent.display()))
        })?;
    let parent_metadata = parent_file.metadata().map_err(|error| {
        ContractError::new(format!("inspect parent {}: {error}", parent.display()))
    })?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ContractError::new(format!("open {}: {error}", path.display())))?;
    let before = file
        .metadata()
        .map_err(|error| ContractError::new(format!("inspect {}: {error}", path.display())))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.mode() & 0o7777 != 0o700
        || !before.file_type().is_file()
        || before.len() > max_bytes
        || before.mode() & 0o7777 != 0o400
        || before.nlink() != 1
        || before.uid() != parent_metadata.uid()
    {
        return Err(ContractError::new(format!(
            "{label} {} is not in an owner-private same-owner directory as a mode-0400 nlink-1 bounded regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let after = file
        .metadata()
        .map_err(|error| ContractError::new(format!("reinspect {}: {error}", path.display())))?;
    if u64::try_from(bytes.len()) != Ok(before.len())
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
    {
        return Err(ContractError::new(format!(
            "{label} {} changed while it was read",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Serialize one all-model raw timing arm as canonical compact JSON plus LF.
pub fn performance_raw_observation_bytes(
    observation: &PerformanceRawObservation,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(observation)
        .map_err(|error| ContractError::new(format!("serialize performance raw arm: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read one canonically serialized all-model raw timing arm.
pub fn read_performance_raw_observation(
    path: &Path,
) -> Result<PerformanceRawObservation, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let observation: PerformanceRawObservation = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_raw_observation_bytes(&observation)? != bytes {
        return Err(ContractError::new(format!(
            "performance raw observation {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(observation)
}

/// Serialize one complete all-model candidate/reference pair as canonical
/// compact JSON plus LF.
pub fn performance_pair_evidence_bytes(
    evidence: &PerformancePairEvidence,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(evidence)
        .map_err(|error| ContractError::new(format!("serialize performance pair: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read one canonically serialized all-model candidate/reference pair.
pub fn read_performance_pair_evidence(
    path: &Path,
) -> Result<PerformancePairEvidence, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let evidence: PerformancePairEvidence = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_pair_evidence_bytes(&evidence)? != bytes {
        return Err(ContractError::new(format!(
            "performance pair {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(evidence)
}

/// Write one canonically serialized intermediate all-model pair to a new path
/// without overwrite. This helper does not provide crash-atomic owner-only
/// publication and therefore cannot substitute for the authenticated final
/// execution envelope.
pub fn write_new_performance_pair_evidence(
    path: &Path,
    evidence: &PerformancePairEvidence,
) -> Result<(), ContractError> {
    let parent = path.parent().ok_or_else(|| {
        ContractError::new(format!(
            "performance pair path {} has no parent",
            path.display()
        ))
    })?;
    if !parent.is_dir() {
        return Err(ContractError::new(format!(
            "performance pair parent {} is not a directory",
            parent.display()
        )));
    }
    let bytes = performance_pair_evidence_bytes(evidence)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ContractError::new(format!(
                "create new performance pair {}: {error}",
                path.display()
            ))
        })?;
    output.write_all(&bytes).map_err(|error| {
        ContractError::new(format!(
            "write performance pair {}: {error}",
            path.display()
        ))
    })?;
    output.sync_all().map_err(|error| {
        ContractError::new(format!("sync performance pair {}: {error}", path.display()))
    })
}

/// Serialize one all-model raw resource arm as canonical compact JSON plus LF.
pub fn performance_resource_observation_bytes(
    observation: &PerformanceResourceRawObservation,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(observation).map_err(|error| {
        ContractError::new(format!("serialize performance resource arm: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read one canonically serialized all-model raw resource arm.
pub fn read_performance_resource_observation(
    path: &Path,
) -> Result<PerformanceResourceRawObservation, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let observation: PerformanceResourceRawObservation = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if performance_resource_observation_bytes(&observation)? != bytes {
        return Err(ContractError::new(format!(
            "performance resource observation {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(observation)
}

/// Measure one exact current-FRE candidate operation and construct its
/// canonical all-model raw arm. The caller owns lifecycle preparation and
/// supplies the measurement closure, permitting deterministic no-clock tests.
///
/// # Errors
///
/// Returns an error before measurement for malformed identity or an invalid
/// model/boundary pair, and after measurement for failure, zero/overflowed
/// duration, or inconsistent output.
pub fn produce_performance_candidate_observation<F>(
    identity: &PerformanceCandidateObservationIdentity,
    measure: F,
) -> Result<PerformanceRawObservation, ContractError>
where
    F: FnOnce() -> Result<(Duration, u64), CompareError>,
{
    validate_performance_candidate_identity_shape(identity)?;
    let (preparation, priming_operations) =
        raw_lifecycle_preparation(&identity.model, &identity.boundary)?;
    let (elapsed, actual) = measure()
        .map_err(|error| ContractError::new(format!("performance measurement: {error}")))?;
    let elapsed_ns = u64::try_from(elapsed.as_nanos())
        .map_err(|_| ContractError::new("performance duration does not fit u64"))?;
    let observation = PerformanceRawObservation {
        schema: PERFORMANCE_RAW_SCHEMA.to_string(),
        contract_id: identity.contract_id.clone(),
        canonical_commit: identity.canonical_commit.clone(),
        canonical_tree: identity.canonical_tree.clone(),
        semantic_receipts_sha256: identity.semantic_receipts_sha256.clone(),
        job_id: identity.job_id.clone(),
        benchmark: identity.benchmark.clone(),
        model: identity.model.clone(),
        boundary: identity.boundary.clone(),
        comparator: identity.comparator.clone(),
        arm: CapturePairArm::Candidate,
        candidate_plan: Some(identity.candidate_plan.clone()),
        candidate_runtime: identity.candidate_runtime.clone(),
        input: identity.input.clone(),
        expected: actual,
        actual,
        preparation,
        priming_operations,
        measured_operations: 1,
        elapsed_ns,
        result_sha256: digest(&actual.to_le_bytes()),
        process_token_sha256: identity.process_token_sha256.clone(),
    };
    validate_performance_raw_observation_shape(&observation, CapturePairArm::Candidate)?;
    Ok(observation)
}

/// Measure one exact Rust-regex or RE2 reference operation and construct its
/// canonical all-model raw arm. The caller owns lifecycle preparation and
/// supplies the measurement closure, permitting deterministic no-clock tests.
///
/// # Errors
///
/// Returns an error before measurement for malformed identity or an invalid
/// model/boundary pair, and after measurement for failure, zero/overflowed
/// duration, or inconsistent output.
pub fn produce_performance_reference_observation<F>(
    identity: &PerformanceReferenceObservationIdentity,
    measure: F,
) -> Result<PerformanceRawObservation, ContractError>
where
    F: FnOnce() -> Result<(Duration, u64), CompareError>,
{
    validate_performance_reference_identity_shape(identity)?;
    let (preparation, priming_operations) =
        raw_lifecycle_preparation(&identity.model, &identity.boundary)?;
    let (elapsed, actual) = measure()
        .map_err(|error| ContractError::new(format!("performance measurement: {error}")))?;
    let elapsed_ns = u64::try_from(elapsed.as_nanos())
        .map_err(|_| ContractError::new("performance duration does not fit u64"))?;
    let observation = PerformanceRawObservation {
        schema: PERFORMANCE_RAW_SCHEMA.to_string(),
        contract_id: identity.contract_id.clone(),
        canonical_commit: identity.canonical_commit.clone(),
        canonical_tree: identity.canonical_tree.clone(),
        semantic_receipts_sha256: identity.semantic_receipts_sha256.clone(),
        job_id: identity.job_id.clone(),
        benchmark: identity.benchmark.clone(),
        model: identity.model.clone(),
        boundary: identity.boundary.clone(),
        comparator: identity.comparator.clone(),
        arm: CapturePairArm::Reference,
        candidate_plan: None,
        candidate_runtime: None,
        input: identity.input.clone(),
        expected: actual,
        actual,
        preparation,
        priming_operations,
        measured_operations: 1,
        elapsed_ns,
        result_sha256: digest(&actual.to_le_bytes()),
        process_token_sha256: identity.process_token_sha256.clone(),
    };
    validate_performance_raw_observation_shape(&observation, CapturePairArm::Reference)?;
    Ok(observation)
}

/// Execute the explicit first/steady schedule and construct one raw capture
/// observation. The caller supplies the measurement closure, which permits
/// deterministic no-clock validation fixtures.
///
/// # Errors
///
/// Returns an error for malformed identity, a failed/mismatched prime,
/// measurement failure, zero/overflowed duration, or inconsistent output.
pub fn produce_capture_lifecycle_observation<F>(
    identity: &CaptureLifecycleObservationIdentity,
    lifecycle: &mut CurrentFreCaptureLifecycle,
    pattern: &str,
    haystack: &[u8],
    boundary: CaptureLifecycleBoundary,
    measure: F,
) -> Result<CaptureLifecycleRawObservation, ContractError>
where
    F: FnOnce(&mut CurrentFreCaptureLifecycle, &[u8]) -> Result<(Duration, u64), CompareError>,
{
    validate_capture_identity_shape(identity)?;
    let primed = if boundary == CaptureLifecycleBoundary::SteadyPublicOperation {
        Some(
            lifecycle
                .execute(haystack)
                .map_err(|error| ContractError::new(format!("capture lifecycle prime: {error}")))?,
        )
    } else {
        None
    };
    let (elapsed, actual) = measure(lifecycle, haystack)
        .map_err(|error| ContractError::new(format!("capture lifecycle measurement: {error}")))?;
    if let Some(primed) = primed
        && primed != actual
    {
        return Err(ContractError::new(format!(
            "capture lifecycle measured reducer {actual} differs from its prime {primed}"
        )));
    }
    let elapsed_ns = u64::try_from(elapsed.as_nanos())
        .map_err(|_| ContractError::new("capture lifecycle duration does not fit u64"))?;
    let observation = CaptureLifecycleRawObservation {
        schema: CAPTURE_LIFECYCLE_RAW_SCHEMA.to_string(),
        contract_id: identity.contract_id.clone(),
        canonical_commit: identity.canonical_commit.clone(),
        canonical_tree: identity.canonical_tree.clone(),
        semantic_receipts_sha256: identity.semantic_receipts_sha256.clone(),
        job_id: identity.job_id.clone(),
        benchmark: identity.benchmark.clone(),
        model: lifecycle.model().to_string(),
        boundary,
        candidate_plan: lifecycle.plan().to_string(),
        input: InputReceipt {
            pattern_sha256: vec![digest(pattern.as_bytes())],
            haystack_sha256: digest(haystack),
            haystack_bytes: haystack.len(),
            unicode: lifecycle.unicode(),
            case_insensitive: lifecycle.case_insensitive(),
        },
        expected: actual,
        actual,
        priming_operations: boundary.priming_operations(),
        measured_operations: 1,
        elapsed_ns,
        result_sha256: digest(&actual.to_le_bytes()),
        process_token_sha256: identity.process_token_sha256.clone(),
    };
    validate_capture_observation_shape(&observation)?;
    if observation.model != lifecycle.model() || observation.candidate_plan != lifecycle.plan() {
        return Err(ContractError::new(
            "capture lifecycle output differs from its prepared identity or semantic result",
        ));
    }
    Ok(observation)
}

/// Validate a raw capture sample against the authenticated contract and
/// semantic denominator.
pub fn validate_capture_lifecycle_observation(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    observation: &CaptureLifecycleRawObservation,
) -> Result<(), ContractError> {
    validate_contract(contract)?;
    validate_capture_observation_shape(observation)?;
    if observation.contract_id != contract.contract_id
        || observation.canonical_commit != contract.tested_source.commit
        || observation.canonical_tree != contract.tested_source.tree
        || observation.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "raw capture observation contract, canonical, or semantic identity mismatch",
        ));
    }
    let semantic = universe.rows.get(&observation.job_id).ok_or_else(|| {
        ContractError::new(format!(
            "raw capture job {:?} is absent from the semantic denominator",
            observation.job_id
        ))
    })?;
    if semantic.status != RowSemanticStatus::Supported
        || semantic.model != observation.model
        || semantic.benchmark != observation.benchmark
        || semantic.input != observation.input
        || semantic.expected != observation.expected
        || semantic.candidate_plan.as_deref() != Some(observation.candidate_plan.as_str())
    {
        return Err(ContractError::new(format!(
            "raw capture job {:?} differs from its passing semantic receipt",
            observation.job_id
        )));
    }
    let model = contract
        .models
        .iter()
        .find(|model| model.model == observation.model)
        .ok_or_else(|| ContractError::new("raw capture model is absent from contract"))?;
    if !matches!(
        observation.model.as_str(),
        "count-captures" | "grep-captures"
    ) || !crate::is_current_fre_capture_route(
        observation.model.as_str(),
        &observation.candidate_plan,
    ) || !model
        .lifecycle_boundaries
        .iter()
        .any(|boundary| boundary == observation.boundary.as_str())
    {
        return Err(ContractError::new(
            "raw capture model or lifecycle boundary is not contracted",
        ));
    }
    Ok(())
}

/// Generate the exact fresh-process pair schedule for every supported capture
/// row and semantically available comparator.
pub fn generate_capture_pair_schedule(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<CapturePairSchedule, ContractError> {
    validate_contract(contract)?;
    let pairs_per_comparator = contract.reporting.pairs_per_comparator;
    let (slots, unavailable) = capture_schedule_contents(contract, universe)?;
    let schedule = CapturePairSchedule {
        schema: CAPTURE_PAIR_SCHEDULE_SCHEMA.to_string(),
        contract_id: contract.contract_id.clone(),
        canonical_commit: contract.tested_source.commit.clone(),
        canonical_tree: contract.tested_source.tree.clone(),
        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
        pairs_per_comparator,
        slots,
        unavailable,
    };
    validate_capture_pair_schedule(contract, universe, &schedule)?;
    Ok(schedule)
}

/// Validate a capture schedule by recomputing its complete slot and
/// unavailable-comparator sets from the semantic denominator.
pub fn validate_capture_pair_schedule(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &CapturePairSchedule,
) -> Result<(), ContractError> {
    validate_contract(contract)?;
    let pairs = contract.reporting.pairs_per_comparator;
    if schedule.schema != CAPTURE_PAIR_SCHEDULE_SCHEMA
        || schedule.contract_id != contract.contract_id
        || schedule.canonical_commit != contract.tested_source.commit
        || schedule.canonical_tree != contract.tested_source.tree
        || schedule.semantic_receipts_sha256 != contract.semantic.receipts_sha256
        || schedule.pairs_per_comparator != pairs
    {
        return Err(ContractError::new(
            "capture pair schedule schema, contract, semantic identity, or pair count mismatch",
        ));
    }
    let (expected_slots, expected_unavailable) = capture_schedule_contents(contract, universe)?;
    if schedule.slots != expected_slots || schedule.unavailable != expected_unavailable {
        return Err(ContractError::new(
            "capture pair schedule differs from the semantic comparator universe",
        ));
    }
    Ok(())
}

/// Generate the complete deterministic fresh-process pair schedule for every
/// supported semantic row, contracted lifecycle boundary, and comparator.
pub fn generate_performance_pair_schedule(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<PerformancePairSchedule, ContractError> {
    validate_contract(contract)?;
    let (slots, unavailable) = performance_schedule_contents(contract, universe)?;
    let schedule = PerformancePairSchedule {
        schema: PERFORMANCE_PAIR_SCHEDULE_SCHEMA.to_string(),
        contract_id: contract.contract_id.clone(),
        canonical_commit: contract.tested_source.commit.clone(),
        canonical_tree: contract.tested_source.tree.clone(),
        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
        pairs_per_comparator: contract.reporting.pairs_per_comparator,
        slots,
        unavailable,
    };
    validate_performance_pair_schedule(contract, universe, &schedule)?;
    Ok(schedule)
}

/// Validate an all-model pair schedule by recomputing its complete slot and
/// unavailable-point sets from the authenticated semantic denominator.
pub fn validate_performance_pair_schedule(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &PerformancePairSchedule,
) -> Result<(), ContractError> {
    validate_contract(contract)?;
    if schedule.schema != PERFORMANCE_PAIR_SCHEDULE_SCHEMA
        || schedule.contract_id != contract.contract_id
        || schedule.canonical_commit != contract.tested_source.commit
        || schedule.canonical_tree != contract.tested_source.tree
        || schedule.semantic_receipts_sha256 != contract.semantic.receipts_sha256
        || schedule.pairs_per_comparator != contract.reporting.pairs_per_comparator
    {
        return Err(ContractError::new(
            "performance pair schedule schema, contract, semantic identity, or pair count mismatch",
        ));
    }
    let (expected_slots, expected_unavailable) = performance_schedule_contents(contract, universe)?;
    if schedule.slots != expected_slots || schedule.unavailable != expected_unavailable {
        return Err(ContractError::new(
            "performance pair schedule differs from the all-model semantic universe",
        ));
    }
    Ok(())
}

/// Generate the exact current-FRE runner route for every supported semantic
/// row. Unknown plan/model/pattern-count combinations fail closed.
pub fn generate_performance_runner_manifest(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<PerformanceRunnerManifest, ContractError> {
    validate_contract(contract)?;
    let rows = performance_runner_rows(contract, universe)?;
    let manifest = PerformanceRunnerManifest {
        schema: PERFORMANCE_RUNNER_MANIFEST_SCHEMA.to_string(),
        contract_id: contract.contract_id.clone(),
        canonical_commit: contract.tested_source.commit.clone(),
        canonical_tree: contract.tested_source.tree.clone(),
        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
        rows,
    };
    validate_performance_runner_manifest(contract, universe, &manifest)?;
    Ok(manifest)
}

fn performance_runner_rows(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<Vec<PerformanceRunnerRow>, ContractError> {
    let models: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let mut rows = Vec::with_capacity(contract.semantic.supported_rows);
    for (job_id, semantic) in &universe.rows {
        if semantic.status != RowSemanticStatus::Supported {
            continue;
        }
        let plan = semantic.candidate_plan.as_deref().ok_or_else(|| {
            ContractError::new(format!("supported row {job_id:?} has no candidate plan"))
        })?;
        require_token(plan, "performance runner candidate plan")?;
        let pattern_count = semantic.input.pattern_sha256.len();
        let route = performance_runner_route(&semantic.model, plan, pattern_count)?;
        let model = models.get(semantic.model.as_str()).ok_or_else(|| {
            ContractError::new(format!("runner model {:?} is absent", semantic.model))
        })?;
        let passing = semantic
            .comparator_statuses
            .values()
            .filter(|status| **status == Some(Status::Pass))
            .count();
        let unavailable_comparators = contract
            .reporting
            .comparators
            .len()
            .checked_sub(passing)
            .ok_or_else(|| ContractError::new("runner comparator count underflow"))?;
        let points = model
            .lifecycle_boundaries
            .len()
            .checked_mul(passing)
            .ok_or_else(|| ContractError::new("runner available-point overflow"))?;
        let pair_slots = points
            .checked_mul(
                usize::try_from(contract.reporting.pairs_per_comparator)
                    .map_err(|_| ContractError::new("runner pair count does not fit usize"))?,
            )
            .ok_or_else(|| ContractError::new("runner pair-slot overflow"))?;
        let unavailable_points = model
            .lifecycle_boundaries
            .len()
            .checked_mul(unavailable_comparators)
            .ok_or_else(|| ContractError::new("runner unavailable-point overflow"))?;
        rows.push(PerformanceRunnerRow {
            job_id: job_id.clone(),
            model: semantic.model.clone(),
            candidate_plan: plan.to_string(),
            pattern_count,
            route,
            boundaries: model.lifecycle_boundaries.clone(),
            pair_slots,
            unavailable_points,
        });
    }
    if rows.len() != contract.semantic.supported_rows {
        return Err(ContractError::new(format!(
            "runner manifest has {} supported rows, expected {}",
            rows.len(),
            contract.semantic.supported_rows
        )));
    }
    Ok(rows)
}

/// Validate a runner manifest by exact deterministic regeneration.
pub fn validate_performance_runner_manifest(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    manifest: &PerformanceRunnerManifest,
) -> Result<(), ContractError> {
    validate_contract(contract)?;
    if manifest.schema != PERFORMANCE_RUNNER_MANIFEST_SCHEMA
        || manifest.contract_id != contract.contract_id
        || manifest.canonical_commit != contract.tested_source.commit
        || manifest.canonical_tree != contract.tested_source.tree
        || manifest.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "performance runner manifest identity differs from the contract",
        ));
    }
    let expected_rows = performance_runner_rows(contract, universe)?;
    if manifest.rows != expected_rows {
        return Err(ContractError::new(
            "performance runner manifest rows differ from exact regeneration",
        ));
    }
    Ok(())
}

/// Validate an execution packet against a digest obtained from an independent
/// authorization transition, then recompute every contract-derived artifact
/// identity. Supplying a packet and its digest through one unauthenticated
/// channel does not establish authority. Executable build policies and timing
/// authority remain packet-authorized; reference runtime digests are also
/// required to equal the matching authenticated semantic adapter. The
/// independent packet-publication transition must authenticate each named
/// build-receipt body and the owned timing-authorization receipt (including
/// owner, scope, TTL, and packet binding); this validator binds their digests
/// without claiming to validate absent receipt bytes.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "keeping every exact packet input and derived provenance check in one admission transaction prevents ambient authority or partial validation"
)]
pub fn validate_performance_execution_packet(
    contract: &PerformanceContract,
    contract_bytes: &[u8],
    semantic_report_bytes: &[u8],
    expanded_manifest_bytes: &[u8],
    schedule: &PerformancePairSchedule,
    runner_manifest: &PerformanceRunnerManifest,
    packet: &PerformanceExecutionPacket,
    authorized_packet_sha256: &str,
) -> Result<ValidatedPerformanceExecutionContext, ContractError> {
    require_digest(
        authorized_packet_sha256,
        "authorized performance execution packet",
    )?;
    if digest(&performance_execution_packet_bytes(packet)?) != authorized_packet_sha256 {
        return Err(ContractError::new(
            "execution packet differs from the independently authorized digest",
        ));
    }
    validate_contract(contract)?;
    let decoded_contract: PerformanceContract = serde_json::from_slice(contract_bytes)
        .map_err(|error| ContractError::new(format!("decode execution contract: {error}")))?;
    if &decoded_contract != contract {
        return Err(ContractError::new(
            "execution contract bytes differ from the supplied contract",
        ));
    }
    let universe = validate_semantic_report(contract, semantic_report_bytes)?;
    validate_performance_pair_schedule(contract, &universe, schedule)?;
    validate_performance_runner_manifest(contract, &universe, runner_manifest)?;
    let schedule_bytes = performance_pair_schedule_bytes(schedule)?;
    let runner_manifest_bytes = performance_runner_manifest_bytes(runner_manifest)?;
    if packet.schema != PERFORMANCE_EXECUTION_PACKET_SCHEMA
        || packet.contract_sha256 != digest(contract_bytes)
        || packet.semantic_report_sha256 != digest(semantic_report_bytes)
        || packet.expanded_manifest_sha256 != digest(expanded_manifest_bytes)
        || packet.expanded_manifest_sha256 != contract.semantic.manifest_sha256
        || packet.pair_schedule_sha256 != digest(&schedule_bytes)
        || packet.runner_manifest_sha256 != digest(&runner_manifest_bytes)
        || packet.canonical_commit != contract.tested_source.commit
        || packet.canonical_tree != contract.tested_source.tree
        || packet.candidate_adapter != contract.semantic.fre_adapter
    {
        return Err(ContractError::new(
            "execution packet schema or contract-derived identity mismatch",
        ));
    }
    validate_performance_executable_policy(&packet.executor, "pair executor")?;
    validate_performance_executable_policy(&packet.candidate_wrapper, "candidate wrapper")?;
    validate_performance_executable_policy(&packet.reference_wrapper, "reference wrapper")?;
    let wrapper_digests = [
        packet.executor.sha256.as_str(),
        packet.candidate_wrapper.sha256.as_str(),
        packet.reference_wrapper.sha256.as_str(),
    ];
    if wrapper_digests.into_iter().collect::<BTreeSet<_>>().len() != wrapper_digests.len() {
        return Err(ContractError::new(
            "executor and candidate/reference wrapper digests are not distinct",
        ));
    }
    validate_performance_timing_authority(&packet.timing_authority)?;
    validate_performance_execution_limits(&packet.limits)?;

    let report: Report = serde_json::from_slice(semantic_report_bytes)
        .map_err(|error| ContractError::new(format!("decode semantic adapters: {error}")))?;
    let comparator_ids = contract
        .reporting
        .comparators
        .iter()
        .map(|comparator| comparator.id.as_str())
        .collect::<BTreeSet<_>>();
    let runner_ids = packet
        .reference_runners
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if runner_ids != comparator_ids {
        return Err(ContractError::new(
            "execution packet reference runner set differs from contract comparators",
        ));
    }
    for comparator in &contract.reporting.comparators {
        let policy = packet
            .reference_runners
            .get(&comparator.id)
            .ok_or_else(|| ContractError::new("execution packet reference runner is absent"))?;
        validate_performance_executable_policy(policy, "reference runner")?;
        let mut adapters = report
            .adapters
            .iter()
            .filter(|adapter| adapter.adapter == comparator.semantic_adapter);
        let adapter = adapters.next().ok_or_else(|| {
            ContractError::new(format!(
                "semantic report lacks reference adapter {:?}",
                comparator.semantic_adapter
            ))
        })?;
        if adapters.next().is_some() {
            return Err(ContractError::new(format!(
                "semantic report duplicates reference adapter {:?}",
                comparator.semantic_adapter
            )));
        }
        let runtime = adapter.runtime_sha256.as_deref().ok_or_else(|| {
            ContractError::new(format!(
                "semantic reference adapter {:?} has no runtime digest",
                comparator.semantic_adapter
            ))
        })?;
        require_digest(runtime, "semantic reference runtime")?;
        if runtime != policy.sha256 {
            return Err(ContractError::new(format!(
                "packet runner for comparator {:?} differs from semantic runtime",
                comparator.id
            )));
        }
    }
    Ok(ValidatedPerformanceExecutionContext {
        universe,
        packet_sha256: authorized_packet_sha256.to_string(),
        pair_schedule_sha256: packet.pair_schedule_sha256.clone(),
    })
}

fn validate_performance_executable_policy(
    policy: &PerformanceExecutablePolicy,
    label: &str,
) -> Result<(), ContractError> {
    const MAX_EXECUTABLE_BYTES: u64 = 1_073_741_824;
    const MAX_VERSION_BYTES: usize = 4_096;
    require_digest(&policy.sha256, &format!("{label} digest"))?;
    require_digest(
        &policy.version_stdout_sha256,
        &format!("{label} version digest"),
    )?;
    if policy.bytes == 0 || policy.bytes > MAX_EXECUTABLE_BYTES {
        return Err(ContractError::new(format!(
            "{label} length is zero or exceeds {MAX_EXECUTABLE_BYTES}"
        )));
    }
    let Some(version) = policy.version_stdout.strip_suffix('\n') else {
        return Err(ContractError::new(format!(
            "{label} version is not exactly LF terminated"
        )));
    };
    if version.is_empty()
        || policy.version_stdout.len() > MAX_VERSION_BYTES
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        || digest(policy.version_stdout.as_bytes()) != policy.version_stdout_sha256
    {
        return Err(ContractError::new(format!(
            "{label} version output is empty, multiline, or has the wrong digest"
        )));
    }
    require_oid(&policy.source_commit, &format!("{label} source commit"))?;
    require_oid(&policy.source_tree, &format!("{label} source tree"))?;
    require_digest(
        &policy.build_receipt_sha256,
        &format!("{label} build receipt"),
    )?;
    if policy.build_receipt_sha256 == policy.sha256
        || policy.build_receipt_sha256 == policy.version_stdout_sha256
    {
        return Err(ContractError::new(format!(
            "{label} build receipt digest aliases executable or version bytes"
        )));
    }
    Ok(())
}

fn validate_performance_timing_authority(
    authority: &PerformanceTimingAuthorityPolicy,
) -> Result<(), ContractError> {
    require_token(&authority.protocol_id, "timing authority protocol")?;
    require_digest(
        &authority.coordinator_sha256,
        "timing authority coordinator",
    )?;
    require_digest(
        &authority.authorization_receipt_sha256,
        "timing authority receipt",
    )?;
    if authority.required_scope != "timing" {
        return Err(ContractError::new(
            "performance execution requires exact timing resource scope",
        ));
    }
    Ok(())
}

fn validate_performance_execution_limits(
    limits: &PerformancePairExecutionLimits,
) -> Result<(), ContractError> {
    const REQUIRED_KLV_BYTES: u64 = 64 * 1_048_576;
    const REQUIRED_OUTPUT_BYTES: u64 = 1_048_576;
    const REQUIRED_ARM_DEADLINE_MS: u64 = 3_600_000;
    if limits.max_klv_bytes != REQUIRED_KLV_BYTES
        || limits.max_stdout_bytes != REQUIRED_OUTPUT_BYTES
        || limits.max_stderr_bytes != REQUIRED_OUTPUT_BYTES
        || limits.arm_deadline_ms != REQUIRED_ARM_DEADLINE_MS
    {
        return Err(ContractError::new(
            "performance execution KLV, output, or deadline limit is invalid",
        ));
    }
    Ok(())
}

/// Validate one prepublished task using the opaque context produced by full
/// packet admission plus an externally authorized task digest, then return an
/// opaque context bound to its exact schedule slot and tokens. Supplying a
/// task and its digest through one
/// unauthenticated channel does not establish authority; the caller must
/// obtain the task digest from its immutable publication transition. This
/// single-task check does not persist global uniqueness or consumed state;
/// the publication ledger must reject attempt/token reuse across tasks and
/// consume both tokens once either arm starts.
pub fn validate_performance_pair_task(
    context: &ValidatedPerformanceExecutionContext,
    packet: &PerformanceExecutionPacket,
    packet_bytes: &[u8],
    schedule: &PerformancePairSchedule,
    task: &PerformancePairTask,
    authorized_task_sha256: &str,
) -> Result<ValidatedPerformancePairTaskContext, ContractError> {
    require_digest(authorized_task_sha256, "authorized performance pair task")?;
    if performance_execution_packet_bytes(packet)? != packet_bytes
        || digest(packet_bytes) != context.packet_sha256
        || packet.schema != PERFORMANCE_EXECUTION_PACKET_SCHEMA
        || digest(&performance_pair_task_bytes(task)?) != authorized_task_sha256
        || task.schema != PERFORMANCE_PAIR_TASK_SCHEMA
        || task.execution_packet_sha256 != context.packet_sha256
        || packet.pair_schedule_sha256 != context.pair_schedule_sha256
        || digest(&performance_pair_schedule_bytes(schedule)?) != context.pair_schedule_sha256
    {
        return Err(ContractError::new(
            "pair task packet bytes, authorization, schema, or schedule mismatch",
        ));
    }
    validate_performance_attempt_id(&task.attempt_id, task.sequence)?;
    require_digest(
        &task.candidate_process_token_sha256,
        "candidate pair process token",
    )?;
    require_digest(
        &task.reference_process_token_sha256,
        "reference pair process token",
    )?;
    if task.candidate_process_token_sha256 == task.reference_process_token_sha256 {
        return Err(ContractError::new(
            "candidate and reference pair process tokens are identical",
        ));
    }
    let slot = schedule.slots.get(task.sequence).ok_or_else(|| {
        ContractError::new("performance pair task sequence is outside the schedule")
    })?;
    if slot.sequence != task.sequence {
        return Err(ContractError::new(
            "performance pair task sequence is not the canonical slot index",
        ));
    }
    Ok(ValidatedPerformancePairTaskContext {
        packet_sha256: context.packet_sha256.clone(),
        task_sha256: authorized_task_sha256.to_string(),
        slot: slot.clone(),
        attempt_id: task.attempt_id.clone(),
        candidate_process_token_sha256: task.candidate_process_token_sha256.clone(),
        reference_process_token_sha256: task.reference_process_token_sha256.clone(),
    })
}

fn validate_performance_attempt_id(value: &str, sequence: usize) -> Result<(), ContractError> {
    let prefix = format!("P{sequence}-A");
    let Some(nonce) = value.strip_prefix(&prefix) else {
        return Err(ContractError::new(
            "performance pair attempt ID does not bind its sequence",
        ));
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::new(
            "performance pair attempt ID requires a 128-bit lowercase-hex nonce",
        ));
    }
    Ok(())
}

fn performance_runner_route(
    model: &str,
    plan: &str,
    pattern_count: usize,
) -> Result<PerformanceRunnerRoute, ContractError> {
    let route = match (model, plan, pattern_count) {
        (
            "compile",
            "compile-aggregate-exact-literal"
            | "compile-aggregate-unicode-scalar-class"
            | "compile-aggregate-finite-literal-dfa"
            | "compile-aggregate-finite-literal-packed-v3"
            | "compile-aggregate-continuation-program"
            | "compile-aggregate-url",
            1,
        )
        | (
            "count" | "count-spans",
            "aggregate-exact-literal"
            | "aggregate-fixed-absolute-domain"
            | "aggregate-unicode-scalar-class"
            | "aggregate-finite-literal-dfa"
            | "aggregate-finite-literal-packed-v3"
            | "aggregate-continuation-program"
            | "aggregate-url",
            1,
        ) => PerformanceRunnerRoute::AggregateSingle,
        ("compile", "compile-many-ordered-literal" | "compile-many-continuation-program", 2..)
        | (
            "count" | "count-spans",
            "aggregate-many-ordered-literal" | "aggregate-many-continuation-program",
            2..,
        ) => PerformanceRunnerRoute::AggregateMany,
        ("grep", crate::CURRENT_FRE_REBAR_GREP_PLAN, 1) => PerformanceRunnerRoute::PortableGrep,
        (model @ ("count-captures" | "grep-captures"), plan, 1)
            if crate::is_current_fre_capture_route(model, plan) =>
        {
            PerformanceRunnerRoute::Capture
        }
        ("regex-redux", crate::CURRENT_FRE_REGEX_REDUX_PLAN, 0) => {
            PerformanceRunnerRoute::Composite
        }
        _ => {
            return Err(ContractError::new(format!(
                "unsupported performance runner route model={model:?} plan={plan:?} patterns={pattern_count}"
            )));
        }
    };
    Ok(route)
}

fn performance_schedule_contents(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<
    (
        Vec<PerformancePairSlot>,
        Vec<PerformanceUnavailableComparator>,
    ),
    ContractError,
> {
    let models: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let mut slots = Vec::new();
    let mut unavailable = Vec::new();
    let mut sequence = 0_usize;
    for (job_id, semantic) in &universe.rows {
        if semantic.status != RowSemanticStatus::Supported {
            continue;
        }
        let model = models.get(semantic.model.as_str()).ok_or_else(|| {
            ContractError::new(format!("performance model {:?} is absent", semantic.model))
        })?;
        for boundary in &model.lifecycle_boundaries {
            for comparator in &contract.reporting.comparators {
                let status = semantic
                    .comparator_statuses
                    .get(&comparator.id)
                    .copied()
                    .flatten();
                if status == Some(Status::Pass) {
                    for pair_index in 0..contract.reporting.pairs_per_comparator {
                        slots.push(PerformancePairSlot {
                            sequence,
                            job_id: job_id.clone(),
                            model: semantic.model.clone(),
                            boundary: boundary.clone(),
                            comparator: comparator.id.clone(),
                            pair_index,
                            order: pair_order(pair_index),
                        });
                        sequence = sequence
                            .checked_add(1)
                            .ok_or_else(|| ContractError::new("performance schedule overflow"))?;
                    }
                } else {
                    unavailable.push(PerformanceUnavailableComparator {
                        job_id: job_id.clone(),
                        model: semantic.model.clone(),
                        boundary: boundary.clone(),
                        comparator: comparator.id.clone(),
                        reason: comparator_unavailable_reason(status),
                    });
                }
            }
        }
    }
    Ok((slots, unavailable))
}

const fn pair_order(pair_index: u32) -> [CapturePairArm; 2] {
    if pair_index.is_multiple_of(2) {
        [CapturePairArm::Candidate, CapturePairArm::Reference]
    } else {
        [CapturePairArm::Reference, CapturePairArm::Candidate]
    }
}

/// Convert a complete all-model fresh-process timing evidence set into the
/// fixed 344-row draft. Resource states are preserved exactly.
pub fn apply_performance_pair_evidence(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    draft: &PerformanceObservations,
    schedule: &PerformancePairSchedule,
    evidence: &[PerformancePairEvidence],
) -> Result<PerformanceObservations, ContractError> {
    validate_performance_pair_schedule(contract, universe, schedule)?;
    validate_observations(contract, universe, draft)?;
    if draft.phase != ObservationPhase::Draft {
        return Err(ContractError::new(
            "all-model pair conversion requires a draft observation artifact",
        ));
    }
    let groups = collect_performance_pair_groups(contract, universe, schedule, evidence)?;
    let mut observations = draft.clone();
    for ((job_id, boundary, comparator), mut pairs) in groups {
        pairs.sort_unstable_by_key(|pair| pair.0);
        let expected_pairs = contract.reporting.pairs_per_comparator;
        let expected_len = usize::try_from(expected_pairs)
            .map_err(|_| ContractError::new("performance pair count does not fit usize"))?;
        if pairs.len() != expected_len
            || pairs
                .iter()
                .enumerate()
                .any(|(index, pair)| u32::try_from(index) != Ok(pair.0))
        {
            return Err(ContractError::new(format!(
                "performance point {job_id:?}/{boundary:?}/{comparator:?} has incomplete pair indices"
            )));
        }
        let ratios: Vec<u64> = pairs.iter().map(|pair| pair.1).collect();
        let ratio_ppm = capture_median(&ratios)?;
        let wins = u32::try_from(pairs.iter().filter(|pair| pair.2).count())
            .map_err(|_| ContractError::new("performance win count does not fit u32"))?;
        let pointwise_pass = ratio_ppm < contract.reporting.ratio_ppm_exclusive_upper_bound
            && wins >= contract.reporting.minimum_candidate_wins;
        let comparison =
            performance_comparison_mut(&mut observations, &job_id, &boundary, &comparator)?;
        if comparison.status != ComparisonStatus::Pending {
            return Err(ContractError::new(format!(
                "performance point {job_id:?}/{boundary:?}/{comparator:?} is not pending"
            )));
        }
        comparison.status = ComparisonStatus::Measured;
        comparison.ratio_ppm = Some(ratio_ppm);
        comparison.pair_count = Some(expected_pairs);
        comparison.candidate_wins = Some(wins);
        comparison.pointwise_pass = Some(pointwise_pass);
        comparison.reason = None;
    }
    for unavailable in &schedule.unavailable {
        let comparison = performance_comparison_mut(
            &mut observations,
            &unavailable.job_id,
            &unavailable.boundary,
            &unavailable.comparator,
        )?;
        if comparison.status != ComparisonStatus::NotComparable
            || comparison.reason.as_deref() != Some(unavailable.reason.as_str())
        {
            return Err(ContractError::new(format!(
                "unavailable performance comparator {:?} was not retained exactly",
                unavailable.comparator
            )));
        }
        validate_not_comparable_resource_observation(&comparison.resources, &unavailable.reason)?;
    }
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

fn collect_performance_pair_groups(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &PerformancePairSchedule,
    evidence: &[PerformancePairEvidence],
) -> Result<PerformancePairGroups, ContractError> {
    if evidence.len() != schedule.slots.len() {
        return Err(ContractError::new(format!(
            "performance evidence has {} pairs, schedule requires {}",
            evidence.len(),
            schedule.slots.len()
        )));
    }
    let mut process_tokens = BTreeSet::new();
    let mut groups = PerformancePairGroups::new();
    for (slot, pair) in schedule.slots.iter().zip(evidence) {
        validate_performance_pair_evidence(contract, universe, slot, pair)?;
        for token in [
            pair.candidate.process_token_sha256.as_str(),
            pair.reference.process_token_sha256.as_str(),
        ] {
            if !process_tokens.insert(token) {
                return Err(ContractError::new(format!(
                    "performance process token is reused at sequence {}",
                    slot.sequence
                )));
            }
        }
        let ratio = capture_ratio_ppm(pair.candidate.elapsed_ns, pair.reference.elapsed_ns)?;
        groups
            .entry((
                slot.job_id.clone(),
                slot.boundary.clone(),
                slot.comparator.clone(),
            ))
            .or_default()
            .push((
                slot.pair_index,
                ratio,
                pair.candidate.elapsed_ns < pair.reference.elapsed_ns,
            ));
    }
    Ok(groups)
}

/// Validate the semantic payload of one complete pair against its exact
/// schedule slot. Production evidence additionally requires the authenticated
/// execution packet, task, lease, KLV, executable, and raw-arm provenance
/// envelope.
pub fn validate_performance_pair_evidence(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    slot: &PerformancePairSlot,
    evidence: &PerformancePairEvidence,
) -> Result<(), ContractError> {
    if &evidence.slot != slot {
        return Err(ContractError::new(format!(
            "performance pair slot differs at sequence {}",
            slot.sequence
        )));
    }
    validate_performance_raw_observation(
        contract,
        universe,
        &evidence.candidate,
        CapturePairArm::Candidate,
    )?;
    validate_performance_raw_observation(
        contract,
        universe,
        &evidence.reference,
        CapturePairArm::Reference,
    )?;
    if evidence.candidate.job_id != slot.job_id
        || evidence.candidate.model != slot.model
        || evidence.candidate.boundary != slot.boundary
        || evidence.candidate.comparator != slot.comparator
        || evidence.reference.job_id != slot.job_id
        || evidence.reference.model != slot.model
        || evidence.reference.boundary != slot.boundary
        || evidence.reference.comparator != slot.comparator
        || evidence.candidate.input != evidence.reference.input
        || evidence.candidate.expected != evidence.reference.expected
    {
        return Err(ContractError::new(format!(
            "performance pair identity differs from sequence {}",
            slot.sequence
        )));
    }
    if evidence.candidate.process_token_sha256 == evidence.reference.process_token_sha256 {
        return Err(ContractError::new(format!(
            "performance pair reuses a process token at sequence {}",
            slot.sequence
        )));
    }
    let _ = capture_ratio_ppm(evidence.candidate.elapsed_ns, evidence.reference.elapsed_ns)?;
    Ok(())
}

/// Validate one all-model raw arm against the exact contract, semantic row,
/// lifecycle boundary, comparator, and candidate/reference role.
pub fn validate_performance_raw_observation(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    observation: &PerformanceRawObservation,
    expected_arm: CapturePairArm,
) -> Result<(), ContractError> {
    validate_contract(contract)?;
    validate_performance_raw_observation_shape(observation, expected_arm)?;
    if observation.contract_id != contract.contract_id
        || observation.canonical_commit != contract.tested_source.commit
        || observation.canonical_tree != contract.tested_source.tree
        || observation.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "performance raw contract or semantic identity mismatch",
        ));
    }
    let semantic = universe.rows.get(&observation.job_id).ok_or_else(|| {
        ContractError::new("performance raw job is absent from semantic denominator")
    })?;
    let comparator_status = semantic
        .comparator_statuses
        .get(&observation.comparator)
        .copied()
        .flatten();
    if semantic.status != RowSemanticStatus::Supported
        || semantic.model != observation.model
        || semantic.benchmark != observation.benchmark
        || semantic.input != observation.input
        || semantic.expected != observation.expected
        || comparator_status != Some(Status::Pass)
    {
        return Err(ContractError::new(
            "performance raw arm differs from its passing semantic point",
        ));
    }
    match expected_arm {
        CapturePairArm::Candidate => {
            let plan = observation
                .candidate_plan
                .as_deref()
                .ok_or_else(|| ContractError::new("candidate performance raw arm has no plan"))?;
            if semantic.candidate_plan.as_deref() != Some(plan) {
                return Err(ContractError::new(
                    "candidate performance raw arm has the wrong plan",
                ));
            }
        }
        CapturePairArm::Reference => {
            if observation.candidate_plan.is_some() {
                return Err(ContractError::new(
                    "reference performance raw arm must not claim a candidate plan",
                ));
            }
        }
    }
    let boundary = contract
        .lifecycle_boundaries
        .iter()
        .find(|boundary| boundary.id == observation.boundary)
        .ok_or_else(|| ContractError::new("performance raw boundary is absent"))?;
    let (preparation, priming_operations) = lifecycle_preparation(boundary.phase);
    if !boundary
        .models
        .iter()
        .any(|model| model == &observation.model)
        || observation.preparation != preparation
        || observation.priming_operations != priming_operations
    {
        return Err(ContractError::new(
            "performance raw boundary, model, or priming count is inconsistent",
        ));
    }
    Ok(())
}

fn validate_performance_candidate_identity_shape(
    identity: &PerformanceCandidateObservationIdentity,
) -> Result<(), ContractError> {
    validate_performance_candidate_observation_request(identity)?;
    if identity.model == "grep" && identity.candidate_runtime.is_none() {
        return Err(ContractError::new(
            "grep performance identity has no selected runtime",
        ));
    }
    Ok(())
}

/// Validate every caller-provisioned candidate identity and lifecycle field
/// before an untimed artifact is constructed. A grep request may omit only
/// its selected runtime because the trusted runner derives that value from the
/// artifact it subsequently constructs; the raw-arm producer still requires
/// the derived runtime before it can emit evidence.
pub fn validate_performance_candidate_observation_request(
    identity: &PerformanceCandidateObservationIdentity,
) -> Result<(), ContractError> {
    require_token(&identity.contract_id, "performance contract ID")?;
    require_oid(
        &identity.canonical_commit,
        "performance tested-source commit",
    )?;
    require_oid(&identity.canonical_tree, "performance tested-source tree")?;
    require_digest(
        &identity.semantic_receipts_sha256,
        "performance semantic receipts",
    )?;
    require_token(&identity.job_id, "performance job ID")?;
    require_text(&identity.benchmark, "performance benchmark")?;
    require_token(&identity.model, "performance model")?;
    require_token(&identity.boundary, "performance boundary")?;
    require_token(&identity.comparator, "performance comparator")?;
    require_token(&identity.candidate_plan, "performance candidate plan")?;
    match (
        identity.model.as_str(),
        identity.candidate_runtime.as_deref(),
    ) {
        ("grep", Some(runtime)) => require_performance_grep_runtime(runtime)?,
        (_, Some(_)) => {
            return Err(ContractError::new(
                "non-grep performance identity claims a selected runtime",
            ));
        }
        (_, None) => {}
    }
    require_digest(&identity.process_token_sha256, "performance process token")?;
    validate_performance_input_shape(&identity.model, &identity.input)?;
    let _ = raw_lifecycle_preparation(&identity.model, &identity.boundary)?;
    Ok(())
}

fn validate_performance_reference_identity_shape(
    identity: &PerformanceReferenceObservationIdentity,
) -> Result<(), ContractError> {
    require_token(&identity.contract_id, "performance contract ID")?;
    require_oid(
        &identity.canonical_commit,
        "performance tested-source commit",
    )?;
    require_oid(&identity.canonical_tree, "performance tested-source tree")?;
    require_digest(
        &identity.semantic_receipts_sha256,
        "performance semantic receipts",
    )?;
    require_token(&identity.job_id, "performance job ID")?;
    require_text(&identity.benchmark, "performance benchmark")?;
    require_token(&identity.model, "performance model")?;
    require_token(&identity.boundary, "performance boundary")?;
    require_token(&identity.comparator, "performance comparator")?;
    require_digest(&identity.process_token_sha256, "performance process token")?;
    validate_performance_input_shape(&identity.model, &identity.input)?;
    let _ = raw_lifecycle_preparation(&identity.model, &identity.boundary)?;
    Ok(())
}

fn validate_performance_raw_observation_shape(
    observation: &PerformanceRawObservation,
    expected_arm: CapturePairArm,
) -> Result<(), ContractError> {
    if observation.schema != PERFORMANCE_RAW_SCHEMA || observation.arm != expected_arm {
        return Err(ContractError::new(
            "performance raw schema or arm identity mismatch",
        ));
    }
    require_token(&observation.contract_id, "performance raw contract ID")?;
    require_oid(
        &observation.canonical_commit,
        "performance raw tested-source commit",
    )?;
    require_oid(
        &observation.canonical_tree,
        "performance raw tested-source tree",
    )?;
    require_digest(
        &observation.semantic_receipts_sha256,
        "performance raw semantic receipts",
    )?;
    require_token(&observation.job_id, "performance raw job ID")?;
    require_text(&observation.benchmark, "performance raw benchmark")?;
    require_token(&observation.model, "performance raw model")?;
    require_token(&observation.boundary, "performance raw boundary")?;
    require_token(&observation.comparator, "performance raw comparator")?;
    require_digest(
        &observation.process_token_sha256,
        "performance raw process token",
    )?;
    require_digest(&observation.result_sha256, "performance raw result digest")?;
    validate_performance_input_shape(&observation.model, &observation.input)?;
    match expected_arm {
        CapturePairArm::Candidate => {
            require_token(
                observation.candidate_plan.as_deref().ok_or_else(|| {
                    ContractError::new("candidate performance raw arm has no plan")
                })?,
                "candidate performance raw plan",
            )?;
            match (
                observation.model.as_str(),
                observation.candidate_runtime.as_deref(),
            ) {
                ("grep", Some(runtime)) => {
                    require_performance_grep_runtime(runtime)?;
                }
                ("grep", None) => {
                    return Err(ContractError::new(
                        "grep candidate performance raw arm has no runtime",
                    ));
                }
                (_, Some(_)) => {
                    return Err(ContractError::new(
                        "non-grep candidate performance raw arm claims a runtime",
                    ));
                }
                (_, None) => {}
            }
        }
        CapturePairArm::Reference
            if observation.candidate_plan.is_some() || observation.candidate_runtime.is_some() =>
        {
            return Err(ContractError::new(
                "reference performance raw arm must not claim a candidate plan or runtime",
            ));
        }
        CapturePairArm::Reference => {}
    }
    let (preparation, priming_operations) =
        raw_lifecycle_preparation(&observation.model, &observation.boundary)?;
    if observation.actual != observation.expected
        || observation.preparation != preparation
        || observation.priming_operations != priming_operations
        || observation.measured_operations != 1
        || observation.elapsed_ns == 0
        || observation.result_sha256 != digest(&observation.actual.to_le_bytes())
    {
        return Err(ContractError::new(
            "performance raw reducer, lifecycle, duration, or digest is inconsistent",
        ));
    }
    Ok(())
}

fn validate_performance_input_shape(
    model: &str,
    input: &InputReceipt,
) -> Result<(), ContractError> {
    match (model, input.pattern_sha256.is_empty()) {
        ("regex-redux", false) => {
            return Err(ContractError::new(
                "regex-redux performance input has external pattern identities",
            ));
        }
        ("regex-redux", true) | (_, false) => {}
        (_, true) => {
            return Err(ContractError::new(
                "performance input has no pattern identities",
            ));
        }
    }
    for pattern in &input.pattern_sha256 {
        require_digest(pattern, "performance input pattern digest")?;
    }
    require_digest(&input.haystack_sha256, "performance input haystack digest")
}

fn require_performance_grep_runtime(runtime: &str) -> Result<(), ContractError> {
    require_token(runtime, "candidate performance grep runtime")?;
    match runtime {
        "exact-literal" | "k0" | "ascii-word-run-linear-v1" | "unicode-word-run-linear-v1" => {
            Ok(())
        }
        other => Err(ContractError::new(format!(
            "unrecognized candidate performance grep runtime {other:?}"
        ))),
    }
}

fn raw_lifecycle_preparation(
    model: &str,
    boundary: &str,
) -> Result<(PerformanceLifecyclePreparation, u8), ContractError> {
    let lifecycle = match (model, boundary) {
        ("compile", "cold-public-compile") => (PerformanceLifecyclePreparation::ColdProcess, 0),
        ("compile", "allocator-warm-public-compile") => {
            (PerformanceLifecyclePreparation::AllocatorInitialized, 0)
        }
        (
            "count" | "count-captures" | "count-spans" | "grep" | "grep-captures",
            "first-public-operation",
        ) => (PerformanceLifecyclePreparation::BuiltArtifact, 0),
        (
            "count" | "count-captures" | "count-spans" | "grep" | "grep-captures",
            "steady-public-operation",
        ) => (PerformanceLifecyclePreparation::PrimedArtifact, 1),
        ("regex-redux", "complete-regex-redux") => {
            (PerformanceLifecyclePreparation::CompositeFresh, 0)
        }
        _ => {
            return Err(ContractError::new(format!(
                "unexpected performance lifecycle {model:?}/{boundary:?}"
            )));
        }
    };
    Ok(lifecycle)
}

const fn lifecycle_preparation(phase: LifecyclePhase) -> (PerformanceLifecyclePreparation, u8) {
    match phase {
        LifecyclePhase::ColdConstruction => (PerformanceLifecyclePreparation::ColdProcess, 0),
        LifecyclePhase::AllocatorWarmConstruction => {
            (PerformanceLifecyclePreparation::AllocatorInitialized, 0)
        }
        LifecyclePhase::FirstOperation => (PerformanceLifecyclePreparation::BuiltArtifact, 0),
        LifecyclePhase::SteadyOperation => (PerformanceLifecyclePreparation::PrimedArtifact, 1),
        LifecyclePhase::CompositeOperation => (PerformanceLifecyclePreparation::CompositeFresh, 0),
    }
}

/// Convert complete authenticated all-model resource evidence into the fixed
/// 344-row draft while preserving every timing field exactly.
pub fn apply_performance_resource_evidence(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    draft: &PerformanceObservations,
    schedule: &PerformancePairSchedule,
    collector: &ResourceCollectorIdentity,
    evidence: &[PerformanceResourcePairEvidence],
) -> Result<PerformanceObservations, ContractError> {
    validate_performance_pair_schedule(contract, universe, schedule)?;
    validate_observations(contract, universe, draft)?;
    validate_resource_collector(collector)?;
    if draft.phase != ObservationPhase::Draft {
        return Err(ContractError::new(
            "all-model resource conversion requires a draft observation artifact",
        ));
    }
    let groups =
        collect_performance_resource_groups(contract, universe, schedule, collector, evidence)?;
    let mut observations = draft.clone();
    for ((job_id, boundary, comparator, arm, metric), samples) in groups {
        let summary = aggregate_resource_samples(contract, &samples, metric, collector)?;
        let target = performance_resource_arm_mut(
            &mut observations,
            &job_id,
            &boundary,
            &comparator,
            arm,
            metric,
        )?;
        if target.status != ResourceMetricStatus::Pending {
            return Err(ContractError::new(format!(
                "performance resource point {job_id:?}/{boundary:?}/{comparator:?}/{arm:?}/{metric:?} is not pending"
            )));
        }
        *target = summary;
    }
    for unavailable in &schedule.unavailable {
        let comparison = performance_comparison_mut(
            &mut observations,
            &unavailable.job_id,
            &unavailable.boundary,
            &unavailable.comparator,
        )?;
        validate_not_comparable_resource_observation(&comparison.resources, &unavailable.reason)?;
    }
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

fn collect_performance_resource_groups(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &PerformancePairSchedule,
    collector: &ResourceCollectorIdentity,
    evidence: &[PerformanceResourcePairEvidence],
) -> Result<PerformanceResourceMetricGroups, ContractError> {
    if evidence.len() != schedule.slots.len() {
        return Err(ContractError::new(format!(
            "performance resource evidence has {} pairs, schedule requires {}",
            evidence.len(),
            schedule.slots.len()
        )));
    }
    let mut process_tokens = BTreeSet::new();
    let mut groups = PerformanceResourceMetricGroups::new();
    for (slot, pair) in schedule.slots.iter().zip(evidence) {
        if &pair.slot != slot {
            return Err(ContractError::new(format!(
                "performance resource evidence slot differs at sequence {}",
                slot.sequence
            )));
        }
        validate_performance_resource_observation(
            contract,
            universe,
            collector,
            &pair.candidate,
            CapturePairArm::Candidate,
        )?;
        validate_performance_resource_observation(
            contract,
            universe,
            collector,
            &pair.reference,
            CapturePairArm::Reference,
        )?;
        if pair.candidate.job_id != slot.job_id
            || pair.candidate.model != slot.model
            || pair.candidate.boundary != slot.boundary
            || pair.candidate.comparator != slot.comparator
            || pair.reference.job_id != slot.job_id
            || pair.reference.model != slot.model
            || pair.reference.boundary != slot.boundary
            || pair.reference.comparator != slot.comparator
            || pair.candidate.input != pair.reference.input
            || pair.candidate.expected != pair.reference.expected
        {
            return Err(ContractError::new(format!(
                "performance resource evidence identity differs from sequence {}",
                slot.sequence
            )));
        }
        for token in [
            pair.candidate.process_token_sha256.as_str(),
            pair.reference.process_token_sha256.as_str(),
        ] {
            if !process_tokens.insert(token) {
                return Err(ContractError::new(format!(
                    "performance resource process token is reused at sequence {}",
                    slot.sequence
                )));
            }
        }
        insert_performance_resource_samples(&mut groups, slot, &pair.candidate);
        insert_performance_resource_samples(&mut groups, slot, &pair.reference);
    }
    Ok(groups)
}

fn insert_performance_resource_samples(
    groups: &mut PerformanceResourceMetricGroups,
    slot: &PerformancePairSlot,
    observation: &PerformanceResourceRawObservation,
) {
    for (metric, sample) in [
        (
            ResourceMetricKind::AllocationCount,
            &observation.allocation_count,
        ),
        (
            ResourceMetricKind::AllocatedBytes,
            &observation.allocated_bytes,
        ),
        (
            ResourceMetricKind::PersistentBytes,
            &observation.persistent_bytes,
        ),
        (
            ResourceMetricKind::PeakRssBytes,
            &observation.peak_rss_bytes,
        ),
    ] {
        groups
            .entry((
                slot.job_id.clone(),
                slot.boundary.clone(),
                slot.comparator.clone(),
                observation.arm,
                metric,
            ))
            .or_default()
            .push((slot.pair_index, sample.clone()));
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "all-model raw identity, semantic, lifecycle, collector, and metric states form one fail-closed validation transaction"
)]
/// Validate one all-model raw resource arm against its exact point and role.
pub fn validate_performance_resource_observation(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    collector: &ResourceCollectorIdentity,
    observation: &PerformanceResourceRawObservation,
    expected_arm: CapturePairArm,
) -> Result<(), ContractError> {
    if observation.schema != PERFORMANCE_RESOURCE_RAW_SCHEMA
        || observation.contract_id != contract.contract_id
        || observation.canonical_commit != contract.tested_source.commit
        || observation.canonical_tree != contract.tested_source.tree
        || observation.semantic_receipts_sha256 != contract.semantic.receipts_sha256
        || observation.collector != *collector
        || observation.arm != expected_arm
    {
        return Err(ContractError::new(
            "performance resource schema, contract, semantic, collector, or arm identity mismatch",
        ));
    }
    require_token(&observation.job_id, "performance resource job ID")?;
    require_text(&observation.benchmark, "performance resource benchmark")?;
    require_token(&observation.model, "performance resource model")?;
    require_token(&observation.boundary, "performance resource boundary")?;
    require_token(&observation.comparator, "performance resource comparator")?;
    require_digest(
        &observation.process_token_sha256,
        "performance resource process token",
    )?;
    require_digest(
        &observation.result_sha256,
        "performance resource result digest",
    )?;
    if observation.actual != observation.expected
        || observation.observed_operations != 1
        || observation.result_sha256 != digest(&observation.actual.to_le_bytes())
    {
        return Err(ContractError::new(
            "performance resource reducer, operation count, or digest is inconsistent",
        ));
    }
    let semantic = universe.rows.get(&observation.job_id).ok_or_else(|| {
        ContractError::new("performance resource job is absent from semantic denominator")
    })?;
    let comparator_status = semantic
        .comparator_statuses
        .get(&observation.comparator)
        .copied()
        .flatten();
    if semantic.status != RowSemanticStatus::Supported
        || semantic.model != observation.model
        || semantic.benchmark != observation.benchmark
        || semantic.input != observation.input
        || semantic.expected != observation.expected
        || comparator_status != Some(Status::Pass)
    {
        return Err(ContractError::new(
            "performance resource arm differs from its passing semantic point",
        ));
    }
    match expected_arm {
        CapturePairArm::Candidate => {
            let plan = observation.candidate_plan.as_deref().ok_or_else(|| {
                ContractError::new("candidate performance resource arm has no plan")
            })?;
            require_token(plan, "candidate performance resource plan")?;
            if semantic.candidate_plan.as_deref() != Some(plan) {
                return Err(ContractError::new(
                    "candidate performance resource arm has the wrong plan",
                ));
            }
        }
        CapturePairArm::Reference => {
            if observation.candidate_plan.is_some() {
                return Err(ContractError::new(
                    "reference performance resource arm must not claim a candidate plan",
                ));
            }
        }
    }
    let boundary = contract
        .lifecycle_boundaries
        .iter()
        .find(|boundary| boundary.id == observation.boundary)
        .ok_or_else(|| ContractError::new("performance resource boundary is absent"))?;
    let (preparation, priming_operations) = lifecycle_preparation(boundary.phase);
    if !boundary
        .models
        .iter()
        .any(|model| model == &observation.model)
        || observation.preparation != preparation
        || observation.priming_operations != priming_operations
    {
        return Err(ContractError::new(
            "performance resource boundary, model, preparation, or prime is inconsistent",
        ));
    }
    for (metric, sample) in [
        (
            ResourceMetricKind::AllocationCount,
            &observation.allocation_count,
        ),
        (
            ResourceMetricKind::AllocatedBytes,
            &observation.allocated_bytes,
        ),
        (
            ResourceMetricKind::PersistentBytes,
            &observation.persistent_bytes,
        ),
        (
            ResourceMetricKind::PeakRssBytes,
            &observation.peak_rss_bytes,
        ),
    ] {
        validate_raw_resource_metric(sample, metric)?;
    }
    Ok(())
}

fn performance_resource_arm_mut<'a>(
    observations: &'a mut PerformanceObservations,
    job_id: &str,
    boundary: &str,
    comparator: &str,
    arm: CapturePairArm,
    metric: ResourceMetricKind,
) -> Result<&'a mut ResourceArmSummary, ContractError> {
    let comparison = performance_comparison_mut(observations, job_id, boundary, comparator)?;
    let pair = match metric {
        ResourceMetricKind::AllocationCount => &mut comparison.resources.allocation_count,
        ResourceMetricKind::AllocatedBytes => &mut comparison.resources.allocated_bytes,
        ResourceMetricKind::PersistentBytes => &mut comparison.resources.persistent_bytes,
        ResourceMetricKind::PeakRssBytes => &mut comparison.resources.peak_rss_bytes,
    };
    Ok(match arm {
        CapturePairArm::Candidate => &mut pair.candidate,
        CapturePairArm::Reference => &mut pair.reference,
    })
}

fn capture_schedule_contents(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
) -> Result<(Vec<CapturePairSlot>, Vec<CaptureUnavailableComparator>), ContractError> {
    let models: BTreeMap<&str, &ModelContract> = contract
        .models
        .iter()
        .map(|model| (model.model.as_str(), model))
        .collect();
    let pair_count = contract.reporting.pairs_per_comparator;
    let mut slots = Vec::new();
    let mut unavailable = Vec::new();
    let mut sequence = 0_usize;
    for (job_id, semantic) in &universe.rows {
        if semantic.status != RowSemanticStatus::Supported
            || !matches!(semantic.model.as_str(), "count-captures" | "grep-captures")
        {
            continue;
        }
        let model = models.get(semantic.model.as_str()).ok_or_else(|| {
            ContractError::new(format!("capture model {:?} is absent", semantic.model))
        })?;
        for boundary in &model.lifecycle_boundaries {
            let boundary = CaptureLifecycleBoundary::parse(boundary)?;
            for comparator in &contract.reporting.comparators {
                let status = semantic
                    .comparator_statuses
                    .get(&comparator.id)
                    .copied()
                    .flatten();
                if status == Some(Status::Pass) {
                    for pair_index in 0..pair_count {
                        slots.push(CapturePairSlot {
                            sequence,
                            job_id: job_id.clone(),
                            model: semantic.model.clone(),
                            boundary,
                            comparator: comparator.id.clone(),
                            pair_index,
                            order: pair_order(pair_index),
                        });
                        sequence = sequence
                            .checked_add(1)
                            .ok_or_else(|| ContractError::new("capture schedule overflow"))?;
                    }
                } else {
                    unavailable.push(CaptureUnavailableComparator {
                        job_id: job_id.clone(),
                        model: semantic.model.clone(),
                        boundary,
                        comparator: comparator.id.clone(),
                        reason: comparator_unavailable_reason(status),
                    });
                }
            }
        }
    }
    Ok((slots, unavailable))
}

fn comparator_unavailable_reason(status: Option<Status>) -> String {
    match status {
        Some(status) => format!(
            "semantic comparator is not a pass: {}",
            status_label(status)
        ),
        None => "semantic report has no matching comparator receipt".to_string(),
    }
}

/// Convert an exact complete set of fresh-process capture pairs into measured
/// points in a coverage-complete 344-row draft.
pub fn apply_capture_pair_evidence(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    draft: &PerformanceObservations,
    schedule: &CapturePairSchedule,
    evidence: &[CapturePairEvidence],
) -> Result<PerformanceObservations, ContractError> {
    validate_capture_pair_schedule(contract, universe, schedule)?;
    validate_observations(contract, universe, draft)?;
    if draft.phase != ObservationPhase::Draft {
        return Err(ContractError::new(
            "capture pair conversion requires a draft observation artifact",
        ));
    }
    let groups = collect_capture_pair_groups(contract, universe, schedule, evidence)?;
    let mut observations = draft.clone();
    for ((job_id, boundary, comparator), mut pairs) in groups {
        pairs.sort_unstable_by_key(|pair| pair.0);
        let expected_pairs = contract.reporting.pairs_per_comparator;
        let expected_pair_count = usize::try_from(expected_pairs)
            .map_err(|_| ContractError::new("capture pair count does not fit usize"))?;
        if pairs.len() != expected_pair_count
            || pairs
                .iter()
                .enumerate()
                .any(|(index, pair)| u32::try_from(index) != Ok(pair.0))
        {
            return Err(ContractError::new(format!(
                "capture point {job_id:?}/{boundary:?}/{comparator:?} has incomplete pair indices"
            )));
        }
        let ratios: Vec<u64> = pairs.iter().map(|pair| pair.1).collect();
        let ratio_ppm = capture_median(&ratios)?;
        let wins = u32::try_from(pairs.iter().filter(|pair| pair.2).count())
            .map_err(|_| ContractError::new("capture win count does not fit u32"))?;
        let pointwise_pass = ratio_ppm < contract.reporting.ratio_ppm_exclusive_upper_bound
            && wins >= contract.reporting.minimum_candidate_wins;
        let comparison = capture_comparison_mut(&mut observations, &job_id, boundary, &comparator)?;
        if comparison.status != ComparisonStatus::Pending {
            return Err(ContractError::new(format!(
                "capture point {job_id:?}/{boundary:?}/{comparator:?} is not pending"
            )));
        }
        comparison.status = ComparisonStatus::Measured;
        comparison.ratio_ppm = Some(ratio_ppm);
        comparison.pair_count = Some(expected_pairs);
        comparison.candidate_wins = Some(wins);
        comparison.pointwise_pass = Some(pointwise_pass);
        comparison.reason = None;
    }
    for unavailable in &schedule.unavailable {
        let comparison = capture_comparison_mut(
            &mut observations,
            &unavailable.job_id,
            unavailable.boundary,
            &unavailable.comparator,
        )?;
        if comparison.status != ComparisonStatus::NotComparable
            || comparison.reason.as_deref() != Some(unavailable.reason.as_str())
        {
            return Err(ContractError::new(format!(
                "unavailable capture comparator {:?} was not retained exactly",
                unavailable.comparator
            )));
        }
    }
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

/// Convert a complete authenticated resource sample set for the capture pair
/// schedule into the same coverage-complete 344-row draft. Timing fields are
/// preserved exactly; allocation activity, retained bytes, and peak RSS have
/// independent measured/unavailable states for each engine arm.
pub fn apply_capture_resource_evidence(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    draft: &PerformanceObservations,
    schedule: &CapturePairSchedule,
    collector: &ResourceCollectorIdentity,
    evidence: &[CaptureResourcePairEvidence],
) -> Result<PerformanceObservations, ContractError> {
    validate_capture_pair_schedule(contract, universe, schedule)?;
    validate_observations(contract, universe, draft)?;
    validate_resource_collector(collector)?;
    if draft.phase != ObservationPhase::Draft {
        return Err(ContractError::new(
            "capture resource conversion requires a draft observation artifact",
        ));
    }
    let groups =
        collect_capture_resource_groups(contract, universe, schedule, collector, evidence)?;
    let mut observations = draft.clone();
    for ((job_id, boundary, comparator, arm, metric), samples) in groups {
        let summary = aggregate_resource_samples(contract, &samples, metric, collector)?;
        let target = capture_resource_arm_mut(
            &mut observations,
            &job_id,
            boundary,
            &comparator,
            arm,
            metric,
        )?;
        if target.status != ResourceMetricStatus::Pending {
            return Err(ContractError::new(format!(
                "capture resource point {job_id:?}/{boundary:?}/{comparator:?}/{arm:?}/{metric:?} is not pending"
            )));
        }
        *target = summary;
    }
    for unavailable in &schedule.unavailable {
        let comparison = capture_comparison_mut(
            &mut observations,
            &unavailable.job_id,
            unavailable.boundary,
            &unavailable.comparator,
        )?;
        validate_not_comparable_resource_observation(&comparison.resources, &unavailable.reason)?;
    }
    validate_observations(contract, universe, &observations)?;
    Ok(observations)
}

fn validate_resource_collector(collector: &ResourceCollectorIdentity) -> Result<(), ContractError> {
    require_token(&collector.collector_id, "resource collector ID")?;
    require_digest(&collector.collector_sha256, "resource collector digest")
}

fn collect_capture_resource_groups(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &CapturePairSchedule,
    collector: &ResourceCollectorIdentity,
    evidence: &[CaptureResourcePairEvidence],
) -> Result<ResourceMetricGroups, ContractError> {
    if evidence.len() != schedule.slots.len() {
        return Err(ContractError::new(format!(
            "capture resource evidence has {} pairs, schedule requires {}",
            evidence.len(),
            schedule.slots.len()
        )));
    }
    let mut process_tokens = BTreeSet::new();
    let mut groups = ResourceMetricGroups::new();
    for (slot, pair) in schedule.slots.iter().zip(evidence) {
        if &pair.slot != slot {
            return Err(ContractError::new(format!(
                "capture resource evidence slot differs at sequence {}",
                slot.sequence
            )));
        }
        validate_capture_resource_observation(
            contract,
            universe,
            collector,
            &pair.candidate,
            ResourceObservationArm::Candidate,
        )?;
        validate_capture_resource_observation(
            contract,
            universe,
            collector,
            &pair.reference,
            ResourceObservationArm::Reference,
        )?;
        if pair.candidate.job_id != slot.job_id
            || pair.candidate.model != slot.model
            || pair.candidate.boundary != slot.boundary
            || pair.candidate.comparator != slot.comparator
            || pair.reference.job_id != slot.job_id
            || pair.reference.model != slot.model
            || pair.reference.boundary != slot.boundary
            || pair.reference.comparator != slot.comparator
            || pair.candidate.input != pair.reference.input
            || pair.candidate.expected != pair.reference.expected
        {
            return Err(ContractError::new(format!(
                "capture resource evidence identity differs from sequence {}",
                slot.sequence
            )));
        }
        for token in [
            pair.candidate.process_token_sha256.as_str(),
            pair.reference.process_token_sha256.as_str(),
        ] {
            if !process_tokens.insert(token) {
                return Err(ContractError::new(format!(
                    "capture resource process token is reused at sequence {}",
                    slot.sequence
                )));
            }
        }
        insert_resource_arm_samples(&mut groups, slot, &pair.candidate);
        insert_resource_arm_samples(&mut groups, slot, &pair.reference);
    }
    Ok(groups)
}

fn insert_resource_arm_samples(
    groups: &mut ResourceMetricGroups,
    slot: &CapturePairSlot,
    observation: &CaptureResourceRawObservation,
) {
    for (metric, sample) in [
        (
            ResourceMetricKind::AllocationCount,
            &observation.allocation_count,
        ),
        (
            ResourceMetricKind::AllocatedBytes,
            &observation.allocated_bytes,
        ),
        (
            ResourceMetricKind::PersistentBytes,
            &observation.persistent_bytes,
        ),
        (
            ResourceMetricKind::PeakRssBytes,
            &observation.peak_rss_bytes,
        ),
    ] {
        groups
            .entry((
                slot.job_id.clone(),
                slot.boundary,
                slot.comparator.clone(),
                observation.arm,
                metric,
            ))
            .or_default()
            .push((slot.pair_index, sample.clone()));
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "raw identity, semantic binding, arm binding, and all four metric states are one fail-closed validation transaction"
)]
/// Validate one raw capture resource arm against its contract, semantic point,
/// expected collector, lifecycle boundary, and engine role.
pub fn validate_capture_resource_observation(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    collector: &ResourceCollectorIdentity,
    observation: &CaptureResourceRawObservation,
    expected_arm: ResourceObservationArm,
) -> Result<(), ContractError> {
    if observation.schema != CAPTURE_RESOURCE_RAW_SCHEMA
        || observation.contract_id != contract.contract_id
        || observation.canonical_commit != contract.tested_source.commit
        || observation.canonical_tree != contract.tested_source.tree
        || observation.semantic_receipts_sha256 != contract.semantic.receipts_sha256
        || observation.collector != *collector
        || observation.arm != expected_arm
    {
        return Err(ContractError::new(
            "capture resource schema, contract, semantic, collector, or arm identity mismatch",
        ));
    }
    require_token(&observation.job_id, "capture resource job ID")?;
    require_text(&observation.benchmark, "capture resource benchmark")?;
    require_token(&observation.model, "capture resource model")?;
    require_token(&observation.comparator, "capture resource comparator")?;
    require_digest(
        &observation.process_token_sha256,
        "capture resource process token",
    )?;
    require_digest(&observation.result_sha256, "capture resource result digest")?;
    if observation.actual != observation.expected
        || observation.priming_operations != observation.boundary.priming_operations()
        || observation.observed_operations != 1
        || observation.result_sha256 != digest(&observation.actual.to_le_bytes())
    {
        return Err(ContractError::new(
            "capture resource reducer or result digest is inconsistent",
        ));
    }
    let semantic = universe.rows.get(&observation.job_id).ok_or_else(|| {
        ContractError::new("capture resource job is absent from semantic denominator")
    })?;
    let comparator_status = semantic
        .comparator_statuses
        .get(&observation.comparator)
        .copied()
        .flatten();
    if semantic.status != RowSemanticStatus::Supported
        || semantic.model != observation.model
        || semantic.benchmark != observation.benchmark
        || semantic.input != observation.input
        || semantic.expected != observation.expected
        || comparator_status != Some(Status::Pass)
    {
        return Err(ContractError::new(
            "capture resource arm differs from its passing semantic point",
        ));
    }
    match expected_arm {
        ResourceObservationArm::Candidate => {
            if observation.candidate_plan != semantic.candidate_plan {
                return Err(ContractError::new(
                    "candidate resource arm has the wrong authenticated plan",
                ));
            }
        }
        ResourceObservationArm::Reference => {
            if observation.candidate_plan.is_some() {
                return Err(ContractError::new(
                    "reference resource arm must not claim a candidate plan",
                ));
            }
        }
    }
    let model = contract
        .models
        .iter()
        .find(|model| model.model == observation.model)
        .ok_or_else(|| ContractError::new("capture resource model is absent"))?;
    if !contract
        .reporting
        .comparators
        .iter()
        .any(|comparator| comparator.id == observation.comparator)
        || !model
            .lifecycle_boundaries
            .iter()
            .any(|boundary| boundary == observation.boundary.as_str())
    {
        return Err(ContractError::new(
            "capture resource comparator or lifecycle boundary is not contracted",
        ));
    }
    for (metric, sample) in [
        (
            ResourceMetricKind::AllocationCount,
            &observation.allocation_count,
        ),
        (
            ResourceMetricKind::AllocatedBytes,
            &observation.allocated_bytes,
        ),
        (
            ResourceMetricKind::PersistentBytes,
            &observation.persistent_bytes,
        ),
        (
            ResourceMetricKind::PeakRssBytes,
            &observation.peak_rss_bytes,
        ),
    ] {
        validate_raw_resource_metric(sample, metric)?;
    }
    Ok(())
}

fn validate_raw_resource_metric(
    sample: &RawResourceMetric,
    metric: ResourceMetricKind,
) -> Result<(), ContractError> {
    match sample.status {
        ResourceMetricStatus::Measured => {
            let value = sample.value.ok_or_else(|| {
                ContractError::new(format!("measured {metric:?} resource sample has no value"))
            })?;
            if sample.reason.is_some() || (metric == ResourceMetricKind::PeakRssBytes && value == 0)
            {
                return Err(ContractError::new(format!(
                    "measured {metric:?} resource sample has a reason or invalid value"
                )));
            }
        }
        ResourceMetricStatus::Unavailable => {
            if sample.value.is_some() || sample.reason.as_deref().is_none_or(str::is_empty) {
                return Err(ContractError::new(format!(
                    "unavailable {metric:?} resource sample has a value or lacks a reason"
                )));
            }
        }
        ResourceMetricStatus::Pending | ResourceMetricStatus::NotComparable => {
            return Err(ContractError::new(format!(
                "raw {metric:?} resource sample must be measured or unavailable"
            )));
        }
    }
    Ok(())
}

fn aggregate_resource_samples(
    contract: &PerformanceContract,
    samples: &[(u32, RawResourceMetric)],
    metric: ResourceMetricKind,
    collector: &ResourceCollectorIdentity,
) -> Result<ResourceArmSummary, ContractError> {
    let mut samples = samples.to_vec();
    samples.sort_unstable_by_key(|sample| sample.0);
    let expected = contract.reporting.pairs_per_comparator;
    let expected_len = usize::try_from(expected)
        .map_err(|_| ContractError::new("resource sample count does not fit usize"))?;
    if samples.len() != expected_len
        || samples
            .iter()
            .enumerate()
            .any(|(index, sample)| u32::try_from(index) != Ok(sample.0))
    {
        return Err(ContractError::new(format!(
            "{metric:?} resource sample set has incomplete pair indices"
        )));
    }
    if samples
        .iter()
        .all(|sample| sample.1.status == ResourceMetricStatus::Measured)
    {
        let values: Result<Vec<u64>, ContractError> = samples
            .iter()
            .map(|sample| {
                sample
                    .1
                    .value
                    .ok_or_else(|| ContractError::new("measured resource sample has no value"))
            })
            .collect();
        return Ok(ResourceArmSummary {
            status: ResourceMetricStatus::Measured,
            collector: Some(collector.clone()),
            median: Some(capture_median(&values?)?),
            sample_count: Some(expected),
            reason: None,
        });
    }
    if samples
        .iter()
        .all(|sample| sample.1.status == ResourceMetricStatus::Unavailable)
    {
        let reasons: BTreeSet<&str> = samples
            .iter()
            .filter_map(|sample| sample.1.reason.as_deref())
            .collect();
        if reasons.len() != 1 {
            return Err(ContractError::new(format!(
                "{metric:?} unavailable resource samples disagree on reason"
            )));
        }
        return Ok(unavailable_resource_arm(
            reasons
                .first()
                .copied()
                .ok_or_else(|| ContractError::new("resource reason set is empty"))?,
            expected,
            collector,
        ));
    }
    Err(ContractError::new(format!(
        "{metric:?} resource samples mix measured and unavailable states"
    )))
}

fn capture_resource_arm_mut<'a>(
    observations: &'a mut PerformanceObservations,
    job_id: &str,
    boundary: CaptureLifecycleBoundary,
    comparator: &str,
    arm: ResourceObservationArm,
    metric: ResourceMetricKind,
) -> Result<&'a mut ResourceArmSummary, ContractError> {
    let comparison = capture_comparison_mut(observations, job_id, boundary, comparator)?;
    let pair = match metric {
        ResourceMetricKind::AllocationCount => &mut comparison.resources.allocation_count,
        ResourceMetricKind::AllocatedBytes => &mut comparison.resources.allocated_bytes,
        ResourceMetricKind::PersistentBytes => &mut comparison.resources.persistent_bytes,
        ResourceMetricKind::PeakRssBytes => &mut comparison.resources.peak_rss_bytes,
    };
    Ok(match arm {
        ResourceObservationArm::Candidate => &mut pair.candidate,
        ResourceObservationArm::Reference => &mut pair.reference,
    })
}

fn validate_not_comparable_resource_observation(
    resources: &ComparisonResourceObservation,
    reason: &str,
) -> Result<(), ContractError> {
    for pair in [
        &resources.allocation_count,
        &resources.allocated_bytes,
        &resources.persistent_bytes,
        &resources.peak_rss_bytes,
    ] {
        for arm in [&pair.candidate, &pair.reference] {
            if arm.status != ResourceMetricStatus::NotComparable
                || arm.collector.is_some()
                || arm.median.is_some()
                || arm.sample_count.is_some()
                || arm.reason.as_deref() != Some(reason)
            {
                return Err(ContractError::new(
                    "semantically unavailable comparator has inconsistent resource state",
                ));
            }
        }
    }
    Ok(())
}

fn collect_capture_pair_groups(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    schedule: &CapturePairSchedule,
    evidence: &[CapturePairEvidence],
) -> Result<CapturePairGroups, ContractError> {
    if evidence.len() != schedule.slots.len() {
        return Err(ContractError::new(format!(
            "capture evidence has {} pairs, schedule requires {}",
            evidence.len(),
            schedule.slots.len()
        )));
    }
    let mut process_tokens = BTreeSet::new();
    let mut groups = CapturePairGroups::new();
    for (slot, pair) in schedule.slots.iter().zip(evidence) {
        if &pair.slot != slot {
            return Err(ContractError::new(format!(
                "capture evidence slot differs at sequence {}",
                slot.sequence
            )));
        }
        validate_capture_lifecycle_observation(contract, universe, &pair.candidate)?;
        validate_capture_reference_observation(contract, universe, &pair.reference)?;
        if pair.candidate.job_id != slot.job_id
            || pair.candidate.model != slot.model
            || pair.candidate.boundary != slot.boundary
            || pair.reference.job_id != slot.job_id
            || pair.reference.model != slot.model
            || pair.reference.boundary != slot.boundary
            || pair.reference.comparator != slot.comparator
            || pair.candidate.input != pair.reference.input
            || pair.candidate.expected != pair.reference.expected
        {
            return Err(ContractError::new(format!(
                "capture evidence identity differs from sequence {}",
                slot.sequence
            )));
        }
        for token in [
            pair.candidate.process_token_sha256.as_str(),
            pair.reference.process_token_sha256.as_str(),
        ] {
            if !process_tokens.insert(token) {
                return Err(ContractError::new(format!(
                    "capture process token is reused at sequence {}",
                    slot.sequence
                )));
            }
        }
        let ratio = capture_ratio_ppm(pair.candidate.elapsed_ns, pair.reference.elapsed_ns)?;
        groups
            .entry((slot.job_id.clone(), slot.boundary, slot.comparator.clone()))
            .or_default()
            .push((
                slot.pair_index,
                ratio,
                pair.candidate.elapsed_ns < pair.reference.elapsed_ns,
            ));
    }
    Ok(groups)
}

fn validate_capture_reference_observation(
    contract: &PerformanceContract,
    universe: &SemanticUniverse,
    observation: &CaptureReferenceRawObservation,
) -> Result<(), ContractError> {
    if observation.schema != CAPTURE_REFERENCE_RAW_SCHEMA
        || observation.contract_id != contract.contract_id
        || observation.canonical_commit != contract.tested_source.commit
        || observation.canonical_tree != contract.tested_source.tree
        || observation.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "capture reference schema, contract, canonical, or semantic identity mismatch",
        ));
    }
    require_token(&observation.job_id, "capture reference job ID")?;
    require_text(&observation.benchmark, "capture reference benchmark")?;
    require_token(&observation.model, "capture reference model")?;
    require_token(&observation.comparator, "capture reference comparator")?;
    require_digest(
        &observation.process_token_sha256,
        "capture reference process token",
    )?;
    require_digest(
        &observation.result_sha256,
        "capture reference result digest",
    )?;
    if observation.actual != observation.expected
        || observation.priming_operations != observation.boundary.priming_operations()
        || observation.measured_operations != 1
        || observation.elapsed_ns == 0
        || observation.result_sha256 != digest(&observation.actual.to_le_bytes())
    {
        return Err(ContractError::new(
            "capture reference reducer, duration, or result digest is inconsistent",
        ));
    }
    let semantic = universe.rows.get(&observation.job_id).ok_or_else(|| {
        ContractError::new("capture reference job is absent from semantic denominator")
    })?;
    let comparator_status = semantic
        .comparator_statuses
        .get(&observation.comparator)
        .copied()
        .flatten();
    if semantic.status != RowSemanticStatus::Supported
        || semantic.model != observation.model
        || semantic.benchmark != observation.benchmark
        || semantic.input != observation.input
        || semantic.expected != observation.expected
        || comparator_status != Some(Status::Pass)
    {
        return Err(ContractError::new(
            "capture reference differs from its passing semantic receipt",
        ));
    }
    let model = contract
        .models
        .iter()
        .find(|model| model.model == observation.model)
        .ok_or_else(|| ContractError::new("capture reference model is absent"))?;
    if !contract
        .reporting
        .comparators
        .iter()
        .any(|comparator| comparator.id == observation.comparator)
        || !model
            .lifecycle_boundaries
            .iter()
            .any(|boundary| boundary == observation.boundary.as_str())
    {
        return Err(ContractError::new(
            "capture reference comparator or boundary is not contracted",
        ));
    }
    Ok(())
}

fn capture_comparison_mut<'a>(
    observations: &'a mut PerformanceObservations,
    job_id: &str,
    boundary: CaptureLifecycleBoundary,
    comparator: &str,
) -> Result<&'a mut ComparisonObservation, ContractError> {
    performance_comparison_mut(observations, job_id, boundary.as_str(), comparator)
}

fn performance_comparison_mut<'a>(
    observations: &'a mut PerformanceObservations,
    job_id: &str,
    boundary: &str,
    comparator: &str,
) -> Result<&'a mut ComparisonObservation, ContractError> {
    observations
        .rows
        .iter_mut()
        .find(|row| row.job_id == job_id)
        .and_then(|row| {
            row.boundaries
                .iter_mut()
                .find(|item| item.boundary == boundary)
        })
        .and_then(|item| {
            item.comparisons
                .iter_mut()
                .find(|item| item.comparator == comparator)
        })
        .ok_or_else(|| {
            ContractError::new(format!(
                "performance comparison {job_id:?}/{boundary:?}/{comparator:?} is absent"
            ))
        })
}

fn capture_ratio_ppm(candidate: u64, reference: u64) -> Result<u64, ContractError> {
    if candidate == 0 || reference == 0 {
        return Err(ContractError::new(
            "capture pair durations must both be nonzero",
        ));
    }
    let scaled = u128::from(candidate)
        .checked_mul(1_000_000)
        .ok_or_else(|| ContractError::new("capture ratio multiplication overflow"))?
        .checked_div(u128::from(reference))
        .ok_or_else(|| ContractError::new("capture ratio denominator is zero"))?;
    u64::try_from(scaled).map_err(|_| ContractError::new("capture ratio does not fit u64"))
}

fn capture_median(values: &[u64]) -> Result<u64, ContractError> {
    if values.is_empty() {
        return Err(ContractError::new("capture ratio set is empty"));
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let middle = values
        .len()
        .checked_div(2)
        .ok_or_else(|| ContractError::new("capture median denominator is zero"))?;
    if values.len().is_multiple_of(2) {
        let left = middle
            .checked_sub(1)
            .ok_or_else(|| ContractError::new("capture ratio median index underflow"))?;
        values[left]
            .checked_add(values[middle])
            .ok_or_else(|| ContractError::new("capture ratio median overflow"))
            .and_then(|sum| {
                sum.checked_div(2)
                    .ok_or_else(|| ContractError::new("capture median denominator is zero"))
            })
    } else {
        Ok(values[middle])
    }
}

fn validate_capture_identity_shape(
    identity: &CaptureLifecycleObservationIdentity,
) -> Result<(), ContractError> {
    require_token(&identity.contract_id, "raw capture contract ID")?;
    require_oid(
        &identity.canonical_commit,
        "raw capture tested-source commit",
    )?;
    require_oid(&identity.canonical_tree, "raw capture tested-source tree")?;
    require_digest(
        &identity.semantic_receipts_sha256,
        "raw capture semantic receipts",
    )?;
    require_token(&identity.job_id, "raw capture job ID")?;
    require_text(&identity.benchmark, "raw capture benchmark")?;
    require_digest(&identity.process_token_sha256, "raw capture process token")
}

fn validate_capture_observation_shape(
    observation: &CaptureLifecycleRawObservation,
) -> Result<(), ContractError> {
    if observation.schema != CAPTURE_LIFECYCLE_RAW_SCHEMA {
        return Err(ContractError::new(
            "raw capture observation schema mismatch",
        ));
    }
    validate_capture_identity_shape(&CaptureLifecycleObservationIdentity {
        contract_id: observation.contract_id.clone(),
        canonical_commit: observation.canonical_commit.clone(),
        canonical_tree: observation.canonical_tree.clone(),
        semantic_receipts_sha256: observation.semantic_receipts_sha256.clone(),
        job_id: observation.job_id.clone(),
        benchmark: observation.benchmark.clone(),
        process_token_sha256: observation.process_token_sha256.clone(),
    })?;
    require_token(&observation.model, "raw capture model")?;
    require_token(&observation.candidate_plan, "raw capture plan")?;
    if observation.input.pattern_sha256.len() != 1 {
        return Err(ContractError::new(
            "raw capture observation requires exactly one pattern digest",
        ));
    }
    require_digest(
        &observation.input.pattern_sha256[0],
        "raw capture pattern digest",
    )?;
    require_digest(
        &observation.input.haystack_sha256,
        "raw capture haystack digest",
    )?;
    require_digest(&observation.result_sha256, "raw capture result digest")?;
    if observation.actual != observation.expected
        || observation.priming_operations != observation.boundary.priming_operations()
        || observation.measured_operations != 1
        || observation.elapsed_ns == 0
        || observation.result_sha256 != digest(&observation.actual.to_le_bytes())
    {
        return Err(ContractError::new(
            "raw capture result, schedule, duration, or digest is inconsistent",
        ));
    }
    Ok(())
}

/// Serialize one raw capture observation as canonical compact JSON plus LF.
pub fn capture_lifecycle_observation_bytes(
    observation: &CaptureLifecycleRawObservation,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(observation).map_err(|error| {
        ContractError::new(format!("serialize raw capture observation: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read a canonically serialized raw capture observation.
pub fn read_capture_lifecycle_observation(
    path: &Path,
) -> Result<CaptureLifecycleRawObservation, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let observation: CaptureLifecycleRawObservation = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if capture_lifecycle_observation_bytes(&observation)? != bytes {
        return Err(ContractError::new(format!(
            "raw capture observation {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(observation)
}

/// Serialize one raw capture resource arm as canonical compact JSON plus LF.
pub fn capture_resource_observation_bytes(
    observation: &CaptureResourceRawObservation,
) -> Result<Vec<u8>, ContractError> {
    let mut bytes = serde_json::to_vec(observation).map_err(|error| {
        ContractError::new(format!(
            "serialize raw capture resource observation: {error}"
        ))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Read a canonically serialized raw capture resource arm.
pub fn read_capture_resource_observation(
    path: &Path,
) -> Result<CaptureResourceRawObservation, ContractError> {
    let bytes = fs::read(path)
        .map_err(|error| ContractError::new(format!("read {}: {error}", path.display())))?;
    let observation: CaptureResourceRawObservation = serde_json::from_slice(&bytes)
        .map_err(|error| ContractError::new(format!("decode {}: {error}", path.display())))?;
    if capture_resource_observation_bytes(&observation)? != bytes {
        return Err(ContractError::new(format!(
            "raw capture resource observation {} is not canonical serialization",
            path.display()
        )));
    }
    Ok(observation)
}

/// Resolve the immutable tested-source commit and tree from `repo`.
///
/// This deliberately resolves the contract's exact commit object. It does not
/// read `refs/heads/main`, so later canonical integration cannot invalidate
/// historical performance evidence.
pub fn resolve_tested_source(
    repo: &Path,
    expected: &TestedSourceIdentity,
) -> Result<TestedSourceIdentity, ContractError> {
    if !repo.is_dir() {
        return Err(ContractError::new(format!(
            "repository root {} is not a directory",
            repo.display()
        )));
    }
    require_oid(&expected.commit, "tested source commit")?;
    require_oid(&expected.tree, "tested source tree")?;
    let commit_revision = format!("{}^{{commit}}", expected.commit);
    let tree_revision = format!("{}^{{tree}}", expected.commit);
    let commit = git_object(repo, &commit_revision)?;
    let tree = git_object(repo, &tree_revision)?;
    Ok(TestedSourceIdentity { commit, tree })
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
    require_oid(&contract.tested_source.commit, "tested source commit")?;
    require_oid(&contract.tested_source.tree, "tested source tree")?;
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

/// Require the resolved immutable tested-source identity to equal the contract.
pub fn validate_tested_source(
    contract: &PerformanceContract,
    observed: &TestedSourceIdentity,
) -> Result<(), ContractError> {
    if observed != &contract.tested_source {
        return Err(ContractError::new(format!(
            "observed tested-source identity {observed:?} differs from contract {:?}",
            contract.tested_source
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
            benchmark: receipt.benchmark.clone(),
            model: receipt.model.clone(),
            status,
            reason,
            input: receipt.input.clone(),
            expected: receipt.expected,
            candidate_plan: receipt.candidate_plan.clone(),
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
        || observations.canonical_commit != contract.tested_source.commit
        || observations.canonical_tree != contract.tested_source.tree
        || observations.semantic_receipts_sha256 != contract.semantic.receipts_sha256
    {
        return Err(ContractError::new(
            "observation schema, contract, tested-source identity, or semantic identity mismatch",
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
    validate_comparison_resources(contract, phase, &observation.resources, reference_status)?;
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

fn validate_comparison_resources(
    contract: &PerformanceContract,
    phase: ObservationPhase,
    resources: &ComparisonResourceObservation,
    reference_status: Option<Status>,
) -> Result<(), ContractError> {
    if reference_status != Some(Status::Pass) {
        return validate_not_comparable_resource_observation(
            resources,
            &comparator_unavailable_reason(reference_status),
        );
    }
    for (metric, pair) in [
        (
            ResourceMetricKind::AllocationCount,
            &resources.allocation_count,
        ),
        (
            ResourceMetricKind::AllocatedBytes,
            &resources.allocated_bytes,
        ),
        (
            ResourceMetricKind::PersistentBytes,
            &resources.persistent_bytes,
        ),
        (ResourceMetricKind::PeakRssBytes, &resources.peak_rss_bytes),
    ] {
        validate_resource_arm_summary(contract, phase, metric, &pair.candidate)?;
        validate_resource_arm_summary(contract, phase, metric, &pair.reference)?;
    }
    Ok(())
}

fn validate_resource_arm_summary(
    contract: &PerformanceContract,
    phase: ObservationPhase,
    metric: ResourceMetricKind,
    summary: &ResourceArmSummary,
) -> Result<(), ContractError> {
    match summary.status {
        ResourceMetricStatus::Pending if phase == ObservationPhase::Draft => {
            if summary.collector.is_some()
                || summary.median.is_some()
                || summary.sample_count.is_some()
                || summary.reason.as_deref().is_none_or(str::is_empty)
            {
                return Err(ContractError::new(format!(
                    "pending {metric:?} resource summary has values or lacks a reason"
                )));
            }
        }
        ResourceMetricStatus::Pending => {
            return Err(ContractError::new(format!(
                "qualification cannot retain pending {metric:?} resources"
            )));
        }
        ResourceMetricStatus::Measured => {
            let collector = summary.collector.as_ref().ok_or_else(|| {
                ContractError::new(format!("measured {metric:?} resource has no collector"))
            })?;
            validate_resource_collector(collector)?;
            let median = summary.median.ok_or_else(|| {
                ContractError::new(format!("measured {metric:?} resource has no median"))
            })?;
            if summary.sample_count != Some(contract.reporting.pairs_per_comparator)
                || summary.reason.is_some()
                || (metric == ResourceMetricKind::PeakRssBytes && median == 0)
            {
                return Err(ContractError::new(format!(
                    "measured {metric:?} resource has wrong count, reason, or value"
                )));
            }
        }
        ResourceMetricStatus::Unavailable => {
            let collector = summary.collector.as_ref().ok_or_else(|| {
                ContractError::new(format!("unavailable {metric:?} resource has no collector"))
            })?;
            validate_resource_collector(collector)?;
            if summary.median.is_some()
                || summary.sample_count != Some(contract.reporting.pairs_per_comparator)
                || summary.reason.as_deref().is_none_or(str::is_empty)
            {
                return Err(ContractError::new(format!(
                    "unavailable {metric:?} resource has a median, wrong count, or lacks a reason"
                )));
            }
        }
        ResourceMetricStatus::NotComparable => {
            return Err(ContractError::new(format!(
                "passing comparator cannot have not-comparable {metric:?} resources"
            )));
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

    const TESTED_SOURCE_CONTRACT: &str =
        include_str!("../../../research/rebar/performance/tested-source-a1a87d11-contract.json");

    fn contract() -> PerformanceContract {
        serde_json::from_str(TESTED_SOURCE_CONTRACT).expect("checked-in contract decodes")
    }

    fn test_git(repo: &Path, arguments: &[&str]) -> String {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(arguments)
            .output()
            .expect("execute fixture git");
        assert!(
            output.status.success(),
            "fixture git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("fixture git output is UTF-8")
            .trim_end()
            .to_string()
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

    fn bind_fixture_candidate_plan(mut receipt: Receipt) -> Receipt {
        if receipt.status == Status::Pass {
            let plan = match receipt.model.as_str() {
                "compile" => "compile-aggregate-exact-literal",
                "count" => "aggregate-exact-literal",
                "count-spans" => "aggregate-continuation-program",
                "grep" => crate::CURRENT_FRE_REBAR_GREP_PLAN,
                "count-captures" => crate::CURRENT_FRE_REBAR_COUNT_CAPTURES_PLAN,
                "grep-captures" => crate::CURRENT_FRE_REBAR_GREP_CAPTURES_PLAN,
                other => panic!("fixture has no supported runner plan for {other:?}"),
            };
            receipt.candidate_plan = Some(plan.to_string());
        }
        receipt
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
                receipts.push(bind_fixture_candidate_plan(receipt(
                    job_id.clone(),
                    benchmark.clone(),
                    model.model.clone(),
                    contract.semantic.fre_adapter.clone(),
                    "rust/regex",
                    candidate_status,
                )));
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
                    runtime_sha256: Some("4".repeat(64)),
                },
                AdapterIdentity {
                    adapter: re2,
                    identity: "fixture RE2".to_string(),
                    availability: "fixture".to_string(),
                    runtime_sha256: Some("5".repeat(64)),
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

    fn fixture_capture_evidence(
        contract: &PerformanceContract,
        universe: &SemanticUniverse,
        schedule: &CapturePairSchedule,
    ) -> Vec<CapturePairEvidence> {
        schedule
            .slots
            .iter()
            .map(|slot| {
                let semantic = &universe.rows[&slot.job_id];
                let candidate_token = digest(format!("candidate:{}", slot.sequence).as_bytes());
                let reference_token = digest(format!("reference:{}", slot.sequence).as_bytes());
                CapturePairEvidence {
                    slot: slot.clone(),
                    candidate: CaptureLifecycleRawObservation {
                        schema: CAPTURE_LIFECYCLE_RAW_SCHEMA.to_string(),
                        contract_id: contract.contract_id.clone(),
                        canonical_commit: contract.tested_source.commit.clone(),
                        canonical_tree: contract.tested_source.tree.clone(),
                        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
                        job_id: slot.job_id.clone(),
                        benchmark: semantic.benchmark.clone(),
                        model: semantic.model.clone(),
                        boundary: slot.boundary,
                        candidate_plan: semantic
                            .candidate_plan
                            .clone()
                            .expect("capture fixture plan"),
                        input: semantic.input.clone(),
                        expected: semantic.expected,
                        actual: semantic.expected,
                        priming_operations: slot.boundary.priming_operations(),
                        measured_operations: 1,
                        elapsed_ns: 80,
                        result_sha256: digest(&semantic.expected.to_le_bytes()),
                        process_token_sha256: candidate_token,
                    },
                    reference: CaptureReferenceRawObservation {
                        schema: CAPTURE_REFERENCE_RAW_SCHEMA.to_string(),
                        contract_id: contract.contract_id.clone(),
                        canonical_commit: contract.tested_source.commit.clone(),
                        canonical_tree: contract.tested_source.tree.clone(),
                        semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
                        job_id: slot.job_id.clone(),
                        benchmark: semantic.benchmark.clone(),
                        model: semantic.model.clone(),
                        boundary: slot.boundary,
                        comparator: slot.comparator.clone(),
                        input: semantic.input.clone(),
                        expected: semantic.expected,
                        actual: semantic.expected,
                        priming_operations: slot.boundary.priming_operations(),
                        measured_operations: 1,
                        elapsed_ns: 100,
                        result_sha256: digest(&semantic.expected.to_le_bytes()),
                        process_token_sha256: reference_token,
                    },
                }
            })
            .collect()
    }

    fn fixture_performance_evidence(
        contract: &PerformanceContract,
        universe: &SemanticUniverse,
        schedule: &PerformancePairSchedule,
    ) -> Vec<PerformancePairEvidence> {
        schedule
            .slots
            .iter()
            .map(|slot| {
                let semantic = &universe.rows[&slot.job_id];
                let boundary = contract
                    .lifecycle_boundaries
                    .iter()
                    .find(|boundary| boundary.id == slot.boundary)
                    .expect("fixture boundary");
                let (preparation, priming_operations) = lifecycle_preparation(boundary.phase);
                let raw = |arm: CapturePairArm, elapsed_ns: u64| PerformanceRawObservation {
                    schema: PERFORMANCE_RAW_SCHEMA.to_string(),
                    contract_id: contract.contract_id.clone(),
                    canonical_commit: contract.tested_source.commit.clone(),
                    canonical_tree: contract.tested_source.tree.clone(),
                    semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
                    job_id: slot.job_id.clone(),
                    benchmark: semantic.benchmark.clone(),
                    model: semantic.model.clone(),
                    boundary: slot.boundary.clone(),
                    comparator: slot.comparator.clone(),
                    arm,
                    candidate_plan: (arm == CapturePairArm::Candidate)
                        .then(|| semantic.candidate_plan.clone())
                        .flatten(),
                    candidate_runtime: (arm == CapturePairArm::Candidate
                        && semantic.model == "grep")
                        .then(|| "k0".to_string()),
                    input: semantic.input.clone(),
                    expected: semantic.expected,
                    actual: semantic.expected,
                    preparation,
                    priming_operations,
                    measured_operations: 1,
                    elapsed_ns,
                    result_sha256: digest(&semantic.expected.to_le_bytes()),
                    process_token_sha256: digest(
                        format!("performance:{arm:?}:{}", slot.sequence).as_bytes(),
                    ),
                };
                PerformancePairEvidence {
                    slot: slot.clone(),
                    candidate: raw(CapturePairArm::Candidate, 80),
                    reference: raw(CapturePairArm::Reference, 100),
                }
            })
            .collect()
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "small fixed no-clock fixture values make lifecycle and arm medians visibly distinct"
    )]
    fn fixture_performance_resource_evidence(
        contract: &PerformanceContract,
        universe: &SemanticUniverse,
        schedule: &PerformancePairSchedule,
        collector: &ResourceCollectorIdentity,
    ) -> Vec<PerformanceResourcePairEvidence> {
        schedule
            .slots
            .iter()
            .map(|slot| {
                let semantic = &universe.rows[&slot.job_id];
                let boundary = contract
                    .lifecycle_boundaries
                    .iter()
                    .find(|boundary| boundary.id == slot.boundary)
                    .expect("fixture boundary");
                let (preparation, priming_operations) = lifecycle_preparation(boundary.phase);
                let phase_offset = match boundary.phase {
                    LifecyclePhase::ColdConstruction => 0,
                    LifecyclePhase::AllocatorWarmConstruction => 100,
                    LifecyclePhase::FirstOperation => 200,
                    LifecyclePhase::SteadyOperation => 300,
                    LifecyclePhase::CompositeOperation => 400,
                };
                let pair_offset = u64::from(slot.pair_index);
                let raw = |arm: CapturePairArm, base: u64| PerformanceResourceRawObservation {
                    schema: PERFORMANCE_RESOURCE_RAW_SCHEMA.to_string(),
                    contract_id: contract.contract_id.clone(),
                    canonical_commit: contract.tested_source.commit.clone(),
                    canonical_tree: contract.tested_source.tree.clone(),
                    semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
                    job_id: slot.job_id.clone(),
                    benchmark: semantic.benchmark.clone(),
                    model: semantic.model.clone(),
                    boundary: slot.boundary.clone(),
                    comparator: slot.comparator.clone(),
                    arm,
                    candidate_plan: (arm == CapturePairArm::Candidate)
                        .then(|| semantic.candidate_plan.clone())
                        .flatten(),
                    input: semantic.input.clone(),
                    expected: semantic.expected,
                    actual: semantic.expected,
                    preparation,
                    priming_operations,
                    observed_operations: 1,
                    result_sha256: digest(&semantic.expected.to_le_bytes()),
                    collector: collector.clone(),
                    process_token_sha256: digest(
                        format!("performance-resource:{arm:?}:{}", slot.sequence).as_bytes(),
                    ),
                    allocation_count: measured_resource(base + phase_offset + pair_offset),
                    allocated_bytes: measured_resource(base * 10 + phase_offset + pair_offset),
                    persistent_bytes: measured_resource(base * 100 + phase_offset + pair_offset),
                    peak_rss_bytes: measured_resource(base * 1_000 + phase_offset + pair_offset),
                };
                PerformanceResourcePairEvidence {
                    slot: slot.clone(),
                    candidate: raw(CapturePairArm::Candidate, 10),
                    reference: raw(CapturePairArm::Reference, 20),
                }
            })
            .collect()
    }

    fn measured_resource(value: u64) -> RawResourceMetric {
        RawResourceMetric {
            status: ResourceMetricStatus::Measured,
            value: Some(value),
            reason: None,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "small fixed no-clock fixture values make boundary and arm medians visibly distinct"
    )]
    fn fixture_capture_resource_evidence(
        contract: &PerformanceContract,
        universe: &SemanticUniverse,
        schedule: &CapturePairSchedule,
        collector: &ResourceCollectorIdentity,
    ) -> Vec<CaptureResourcePairEvidence> {
        schedule
            .slots
            .iter()
            .map(|slot| {
                let semantic = &universe.rows[&slot.job_id];
                let boundary_offset = match slot.boundary {
                    CaptureLifecycleBoundary::FirstPublicOperation => 0,
                    CaptureLifecycleBoundary::SteadyPublicOperation => 100,
                };
                let pair_offset = u64::from(slot.pair_index);
                let raw = |arm: ResourceObservationArm, base: u64| CaptureResourceRawObservation {
                    schema: CAPTURE_RESOURCE_RAW_SCHEMA.to_string(),
                    contract_id: contract.contract_id.clone(),
                    canonical_commit: contract.tested_source.commit.clone(),
                    canonical_tree: contract.tested_source.tree.clone(),
                    semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
                    job_id: slot.job_id.clone(),
                    benchmark: semantic.benchmark.clone(),
                    model: semantic.model.clone(),
                    boundary: slot.boundary,
                    comparator: slot.comparator.clone(),
                    arm,
                    candidate_plan: (arm == ResourceObservationArm::Candidate)
                        .then(|| semantic.candidate_plan.clone())
                        .flatten(),
                    input: semantic.input.clone(),
                    expected: semantic.expected,
                    actual: semantic.expected,
                    priming_operations: slot.boundary.priming_operations(),
                    observed_operations: 1,
                    result_sha256: digest(&semantic.expected.to_le_bytes()),
                    collector: collector.clone(),
                    process_token_sha256: digest(
                        format!("resource:{arm:?}:{}", slot.sequence).as_bytes(),
                    ),
                    allocation_count: measured_resource(base + boundary_offset + pair_offset),
                    allocated_bytes: measured_resource(base * 10 + boundary_offset + pair_offset),
                    persistent_bytes: measured_resource(base * 100 + boundary_offset + pair_offset),
                    peak_rss_bytes: measured_resource(base * 1_000 + boundary_offset + pair_offset),
                };
                CaptureResourcePairEvidence {
                    slot: slot.clone(),
                    candidate: raw(ResourceObservationArm::Candidate, 10),
                    reference: raw(ResourceObservationArm::Reference, 20),
                }
            })
            .collect()
    }

    fn resource_status_count(
        observations: &PerformanceObservations,
        status: ResourceMetricStatus,
    ) -> usize {
        observations
            .rows
            .iter()
            .flat_map(|row| &row.boundaries)
            .flat_map(|boundary| &boundary.comparisons)
            .flat_map(|comparison| {
                [
                    &comparison.resources.allocation_count,
                    &comparison.resources.allocated_bytes,
                    &comparison.resources.persistent_bytes,
                    &comparison.resources.peak_rss_bytes,
                ]
            })
            .flat_map(|pair| [&pair.candidate, &pair.reference])
            .filter(|summary| summary.status == status)
            .count()
    }

    fn comparison_status_count(
        observations: &PerformanceObservations,
        status: ComparisonStatus,
    ) -> usize {
        observations
            .rows
            .iter()
            .flat_map(|row| &row.boundaries)
            .flat_map(|boundary| &boundary.comparisons)
            .filter(|comparison| comparison.status == status)
            .count()
    }

    #[test]
    fn checked_in_contract_covers_every_model_and_tested_source() {
        let contract = contract();
        validate_contract(&contract).expect("checked-in contract validates");
        validate_tested_source(&contract, &contract.tested_source)
            .expect("exact identity validates");
        let mut moved = contract.tested_source.clone();
        moved.commit = "0".repeat(40);
        assert!(validate_tested_source(&contract, &moved).is_err());
    }

    #[test]
    fn tested_source_contract_survives_main_movement_without_retargeting() {
        let repository = std::env::temp_dir().join(format!(
            "fre-rebar-tested-source-contract-{}",
            std::process::id()
        ));
        if repository.exists() {
            fs::remove_dir_all(&repository).expect("remove stale fixture repository");
        }
        fs::create_dir(&repository).expect("create fixture repository");
        test_git(&repository, &["init", "--quiet", "--initial-branch=main"]);
        fs::write(repository.join("source.txt"), b"first\n").expect("write first source");
        test_git(&repository, &["add", "source.txt"]);
        test_git(
            &repository,
            &[
                "-c",
                "user.name=FRE fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--quiet",
                "-m",
                "first source",
            ],
        );
        let tested_source = TestedSourceIdentity {
            commit: git_object(&repository, "HEAD^{commit}").expect("first commit"),
            tree: git_object(&repository, "HEAD^{tree}").expect("first tree"),
        };
        fs::write(repository.join("source.txt"), b"second\n").expect("write second source");
        test_git(&repository, &["add", "source.txt"]);
        test_git(
            &repository,
            &[
                "-c",
                "user.name=FRE fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--quiet",
                "-m",
                "move main",
            ],
        );
        assert_ne!(
            git_object(&repository, "refs/heads/main^{commit}").expect("moved main"),
            tested_source.commit
        );

        let mut contract = contract();
        contract.tested_source = tested_source;
        let observed = resolve_tested_source(&repository, &contract.tested_source)
            .expect("historical tested source remains resolvable after main moves");
        validate_tested_source(&contract, &observed)
            .expect("resolved historical source matches the contract");

        let mut wrong_tree = contract.tested_source.clone();
        wrong_tree.tree = "0".repeat(40);
        let observed = resolve_tested_source(&repository, &wrong_tree)
            .expect("the exact commit resolves independently of the claimed tree");
        assert!(
            validate_tested_source(
                &PerformanceContract {
                    tested_source: wrong_tree,
                    ..contract
                },
                &observed
            )
            .is_err()
        );
        fs::remove_dir_all(repository).expect("remove fixture repository");
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
        assert_eq!(observations.schema, PERFORMANCE_OBSERVATIONS_SCHEMA);
        assert_eq!(
            resource_status_count(&observations, ResourceMetricStatus::Pending),
            8_224
        );
        assert_eq!(
            resource_status_count(&observations, ResourceMetricStatus::NotComparable),
            0
        );

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
    fn specialized_capture_plans_are_not_formal_rebar_routes() {
        for plan in [
            "legacy-ruff-space-operator",
            "legacy-ruff-shebang",
            "legacy-ruff-string-quote",
            "legacy-ruff-keywords",
            "legacy-ascii-separated-fields",
            crate::CURRENT_FRE_CAPTURE_ANCHORED_LINE_PLAN,
            "capture-line-space-around-operator-stream-v2",
            "capture-line-ruff-shebang-stream-v1",
            "capture-line-ruff-string-quote-stream-v2",
            "capture-line-ruff-python-keywords-stream-v1",
            "capture-line-anchored-ascii-separated-fields-v2",
            "anchored-line-capture.grep-participation-count.v1",
        ] {
            assert!(!crate::is_current_fre_capture_plan(plan));
            assert!(performance_runner_route("grep-captures", plan, 1).is_err());
            assert!(performance_runner_route("grep-captures", plan, 2).is_err());
            assert!(performance_runner_route("count-captures", plan, 1).is_err());
            assert!(
                performance_runner_route("grep-captures", &format!("{plan}-alias"), 1).is_err()
            );
        }
    }

    #[test]
    fn composite_route_is_exact_and_capture_many_is_not_formal_rebar() {
        for plan in [
            "capture-many-ordered-literal",
            "capture-many-continuation-program",
        ] {
            assert!(performance_runner_route("count-captures", plan, 88).is_err());
            assert!(performance_runner_route("count-captures", plan, 1).is_err());
            assert!(performance_runner_route("grep-captures", plan, 88).is_err());
            assert!(
                performance_runner_route("count-captures", &format!("{plan}-alias"), 88).is_err()
            );
        }
        assert_eq!(
            performance_runner_route("regex-redux", crate::CURRENT_FRE_REGEX_REDUX_PLAN, 0)
                .expect("exact regex-redux composite route"),
            PerformanceRunnerRoute::Composite
        );
        assert!(
            performance_runner_route("regex-redux", crate::CURRENT_FRE_REGEX_REDUX_PLAN, 1)
                .is_err()
        );
        assert!(performance_runner_route("regex-redux", "regex-redux-composite-alias", 0).is_err());
    }

    #[test]
    fn fixed_absolute_domain_is_registered_only_for_single_aggregate_operations() {
        for model in ["count", "count-spans"] {
            assert_eq!(
                performance_runner_route(model, "aggregate-fixed-absolute-domain", 1)
                    .expect("fixed absolute-domain operation route"),
                PerformanceRunnerRoute::AggregateSingle
            );
            assert!(performance_runner_route(model, "aggregate-fixed-absolute-domain", 2).is_err());
        }
        assert!(
            performance_runner_route("compile", "compile-aggregate-fixed-absolute-domain", 1)
                .is_err()
        );
        assert!(
            performance_runner_route("count", "aggregate-fixed-absolute-domain-alias", 1).is_err()
        );
    }

    #[test]
    fn packed_finite_is_registered_only_for_single_aggregate_operations() {
        assert_eq!(
            performance_runner_route("compile", "compile-aggregate-finite-literal-packed-v3", 1,)
                .expect("packed finite compile route"),
            PerformanceRunnerRoute::AggregateSingle
        );
        for model in ["count", "count-spans"] {
            assert_eq!(
                performance_runner_route(model, "aggregate-finite-literal-packed-v3", 1,)
                    .expect("packed finite operation route"),
                PerformanceRunnerRoute::AggregateSingle
            );
            assert!(
                performance_runner_route(model, "aggregate-finite-literal-packed-v3", 2,).is_err()
            );
        }
        assert!(
            performance_runner_route("count", "aggregate-finite-literal-packed-v3-alias", 1,)
                .is_err()
        );
    }

    #[test]
    fn capture_lifecycle_schedule_and_raw_validation_need_no_clock() {
        let contract = contract();
        let pattern = r"(a)(b)?";
        let haystack = b"a ab";
        let mut lifecycle = crate::current_fre_rebar_capture_lifecycle(
            "count-captures",
            pattern,
            false,
            false,
            haystack.len(),
        )
        .expect("capture lifecycle");
        let identity = CaptureLifecycleObservationIdentity {
            contract_id: contract.contract_id.clone(),
            canonical_commit: contract.tested_source.commit.clone(),
            canonical_tree: contract.tested_source.tree.clone(),
            semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
            job_id: "fixture/count-captures@rust/regex".to_string(),
            benchmark: "fixture/count-captures".to_string(),
            process_token_sha256: digest(b"first capture process"),
        };
        let first = produce_capture_lifecycle_observation(
            &identity,
            &mut lifecycle,
            pattern,
            haystack,
            CaptureLifecycleBoundary::FirstPublicOperation,
            |operation, input| Ok((Duration::from_nanos(37), operation.execute(input)?)),
        )
        .expect("fixed first observation");
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.elapsed_ns, 37);
        assert_eq!(first.actual, 5);
        assert_eq!(first.input.pattern_sha256, vec![digest(pattern.as_bytes())]);
        assert_eq!(first.input.haystack_sha256, digest(haystack));

        let mut steady_identity = identity.clone();
        steady_identity.process_token_sha256 = digest(b"steady capture process");
        let steady = produce_capture_lifecycle_observation(
            &steady_identity,
            &mut lifecycle,
            pattern,
            haystack,
            CaptureLifecycleBoundary::SteadyPublicOperation,
            |operation, input| Ok((Duration::from_nanos(41), operation.execute(input)?)),
        )
        .expect("fixed steady observation");
        assert_eq!(steady.priming_operations, 1);
        assert_eq!(steady.elapsed_ns, 41);
        let bytes = capture_lifecycle_observation_bytes(&steady).expect("serialize raw capture");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<CaptureLifecycleRawObservation>(&bytes)
                .expect("raw capture round trip"),
            steady
        );

        let called = std::cell::Cell::new(false);
        assert!(
            produce_capture_lifecycle_observation(
                &identity,
                &mut lifecycle,
                pattern,
                haystack,
                CaptureLifecycleBoundary::SteadyPublicOperation,
                |_operation, _input| {
                    called.set(true);
                    Ok((Duration::from_nanos(1), 6))
                },
            )
            .is_err()
        );
        assert!(called.get(), "steady consistency check must measure once");
    }

    #[test]
    fn raw_capture_observation_is_bound_to_the_semantic_row() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let mut observation = CaptureLifecycleRawObservation {
            schema: CAPTURE_LIFECYCLE_RAW_SCHEMA.to_string(),
            contract_id: contract.contract_id.clone(),
            canonical_commit: contract.tested_source.commit.clone(),
            canonical_tree: contract.tested_source.tree.clone(),
            semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
            job_id: "fixture/count-captures/row-000@rust/regex".to_string(),
            benchmark: "fixture/count-captures/row-000".to_string(),
            model: "count-captures".to_string(),
            boundary: CaptureLifecycleBoundary::FirstPublicOperation,
            candidate_plan: crate::CURRENT_FRE_REBAR_COUNT_CAPTURES_PLAN.to_string(),
            input: InputReceipt {
                pattern_sha256: vec!["1".repeat(64)],
                haystack_sha256: "2".repeat(64),
                haystack_bytes: 1,
                unicode: false,
                case_insensitive: false,
            },
            expected: 0,
            actual: 0,
            priming_operations: 0,
            measured_operations: 1,
            elapsed_ns: 23,
            result_sha256: digest(&0_u64.to_le_bytes()),
            process_token_sha256: digest(b"semantic fixture process"),
        };
        validate_capture_lifecycle_observation(&contract, &universe, &observation)
            .expect("exact raw capture observation validates");

        let exact = observation.clone();
        observation.input.haystack_sha256 = "3".repeat(64);
        assert!(
            validate_capture_lifecycle_observation(&contract, &universe, &observation).is_err()
        );
        observation = exact.clone();
        observation.model = "grep-captures".to_string();
        assert!(
            validate_capture_lifecycle_observation(&contract, &universe, &observation).is_err()
        );
        observation = exact.clone();
        observation.candidate_plan = "capture-other".to_string();
        assert!(
            validate_capture_lifecycle_observation(&contract, &universe, &observation).is_err()
        );
        observation = exact.clone();
        observation.elapsed_ns = 0;
        assert!(
            validate_capture_lifecycle_observation(&contract, &universe, &observation).is_err()
        );
        observation = exact;
        observation.job_id = "fixture/count-captures/row-003@rust/regex".to_string();
        observation.benchmark = "fixture/count-captures/row-003".to_string();
        assert!(
            validate_capture_lifecycle_observation(&contract, &universe, &observation).is_err()
        );
    }

    #[test]
    fn capture_pair_schedule_converts_complete_fixed_duration_evidence() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_capture_pair_schedule(&contract, &universe).expect("capture schedule");
        assert_eq!(schedule.slots.len(), 192);
        assert!(schedule.unavailable.is_empty());
        assert!(schedule.slots.iter().enumerate().all(|(index, slot)| {
            slot.sequence == index
                && slot.order
                    == if slot.pair_index.is_multiple_of(2) {
                        [CapturePairArm::Candidate, CapturePairArm::Reference]
                    } else {
                        [CapturePairArm::Reference, CapturePairArm::Candidate]
                    }
        }));
        let mut incomplete_schedule = schedule.clone();
        incomplete_schedule.slots.pop();
        assert!(
            validate_capture_pair_schedule(&contract, &universe, &incomplete_schedule).is_err()
        );
        let evidence = fixture_capture_evidence(&contract, &universe, &schedule);
        assert_eq!(evidence.len(), 192);
        let converted =
            apply_capture_pair_evidence(&contract, &universe, &draft, &schedule, &evidence)
                .expect("complete capture evidence converts");
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            32
        );
        for comparison in converted
            .rows
            .iter()
            .flat_map(|row| &row.boundaries)
            .flat_map(|boundary| &boundary.comparisons)
            .filter(|comparison| comparison.status == ComparisonStatus::Measured)
        {
            assert_eq!(comparison.ratio_ppm, Some(800_000));
            assert_eq!(comparison.pair_count, Some(6));
            assert_eq!(comparison.candidate_wins, Some(6));
            assert_eq!(comparison.pointwise_pass, Some(true));
        }

        assert!(
            apply_capture_pair_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &evidence[..evidence.len() - 1],
            )
            .is_err()
        );
        let mut reused_process = evidence.clone();
        reused_process[1].candidate.process_token_sha256 =
            reused_process[0].candidate.process_token_sha256.clone();
        assert!(
            apply_capture_pair_evidence(&contract, &universe, &draft, &schedule, &reused_process,)
                .is_err()
        );
        let mut wrong_slot = evidence;
        wrong_slot.swap(0, 1);
        assert!(
            apply_capture_pair_evidence(&contract, &universe, &draft, &schedule, &wrong_slot,)
                .is_err()
        );
    }

    #[test]
    fn all_model_schedule_is_complete_deterministic_and_canonical() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        assert_eq!(schedule.slots.len(), 6_168);
        assert_eq!(schedule.slots.len().checked_mul(2), Some(12_336));
        assert!(schedule.unavailable.is_empty());
        assert!(schedule.slots.iter().enumerate().all(|(sequence, slot)| {
            slot.sequence == sequence && slot.order == pair_order(slot.pair_index)
        }));
        let by_model: BTreeMap<&str, usize> = REBAR_MODELS
            .into_iter()
            .map(|model| {
                (
                    model,
                    schedule
                        .slots
                        .iter()
                        .filter(|slot| slot.model == model)
                        .count(),
                )
            })
            .collect();
        assert_eq!(by_model["compile"], 672);
        assert_eq!(by_model["count"], 2_400);
        assert_eq!(by_model["count-captures"], 72);
        assert_eq!(by_model["count-spans"], 2_640);
        assert_eq!(by_model["grep"], 264);
        assert_eq!(by_model["grep-captures"], 120);
        assert_eq!(by_model["regex-redux"], 0);
        assert_eq!(
            schedule
                .slots
                .iter()
                .filter(|slot| matches!(slot.model.as_str(), "count-captures" | "grep-captures"))
                .count(),
            192
        );
        let bytes = performance_pair_schedule_bytes(&schedule).expect("schedule serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<PerformancePairSchedule>(&bytes).expect("schedule round trip"),
            schedule
        );
        let mut incomplete = schedule;
        incomplete.slots.pop();
        assert!(validate_performance_pair_schedule(&contract, &universe, &incomplete).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixed-duration fixture covers every lifecycle plus premeasurement rejection"
    )]
    fn candidate_raw_producer_binds_identity_and_every_lifecycle_without_a_clock() {
        let identity = PerformanceCandidateObservationIdentity {
            contract_id: "fixture-performance-contract-v1".to_string(),
            canonical_commit: "a".repeat(40),
            canonical_tree: "b".repeat(40),
            semantic_receipts_sha256: "c".repeat(64),
            job_id: "fixture/count-many@rust/regex".to_string(),
            benchmark: "fixture/count-many".to_string(),
            model: "count".to_string(),
            boundary: "first-public-operation".to_string(),
            comparator: "rust-regex-1.12.4".to_string(),
            candidate_plan: "aggregate-many-ordered-literal".to_string(),
            candidate_runtime: None,
            input: InputReceipt {
                pattern_sha256: vec!["d".repeat(64), "e".repeat(64)],
                haystack_sha256: "f".repeat(64),
                haystack_bytes: 11,
                unicode: true,
                case_insensitive: false,
            },
            process_token_sha256: digest(b"candidate raw producer token"),
        };
        let first = produce_performance_candidate_observation(&identity, || {
            Ok((Duration::from_nanos(17), 3))
        })
        .expect("fixed first-operation sample");
        assert_eq!(first.arm, CapturePairArm::Candidate);
        assert_eq!(
            first.preparation,
            PerformanceLifecyclePreparation::BuiltArtifact
        );
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.elapsed_ns, 17);
        assert_eq!(first.input.pattern_sha256, identity.input.pattern_sha256);
        assert_eq!(first.result_sha256, digest(&3_u64.to_le_bytes()));
        let bytes = performance_raw_observation_bytes(&first).expect("raw serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));

        let mut steady_identity = identity.clone();
        steady_identity.boundary = "steady-public-operation".to_string();
        steady_identity.process_token_sha256 = digest(b"candidate steady token");
        let steady = produce_performance_candidate_observation(&steady_identity, || {
            Ok((Duration::from_nanos(19), 3))
        })
        .expect("fixed steady-operation sample");
        assert_eq!(
            steady.preparation,
            PerformanceLifecyclePreparation::PrimedArtifact
        );
        assert_eq!(steady.priming_operations, 1);

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
            let mut compile_identity = identity.clone();
            compile_identity.model = "compile".to_string();
            compile_identity.boundary = boundary.to_string();
            compile_identity.candidate_plan = "compile-many-ordered-literal".to_string();
            let observation = produce_performance_candidate_observation(&compile_identity, || {
                Ok((Duration::from_nanos(23), 3))
            })
            .expect("fixed compile sample");
            assert_eq!(observation.preparation, preparation);
            assert_eq!(observation.priming_operations, 0);
        }

        let measured = std::cell::Cell::new(false);
        let mut malformed = identity.clone();
        malformed.boundary = "cold-public-compile".to_string();
        assert!(
            produce_performance_candidate_observation(&malformed, || {
                measured.set(true);
                Ok((Duration::from_nanos(1), 3))
            })
            .is_err()
        );
        assert!(!measured.get(), "malformed identity ran the measurement");
        malformed = identity.clone();
        malformed.input.pattern_sha256[0] = "malformed".to_string();
        assert!(
            produce_performance_candidate_observation(&malformed, || {
                measured.set(true);
                Ok((Duration::from_nanos(1), 3))
            })
            .is_err()
        );
        assert!(!measured.get(), "malformed input ran the measurement");
        assert!(
            produce_performance_candidate_observation(&identity, || { Ok((Duration::ZERO, 3)) })
                .is_err()
        );
        let untrusted = produce_performance_candidate_observation(&identity, || {
            Ok((Duration::from_nanos(1), 2))
        })
        .expect("producer records a reducer without knowing its semantic answer");
        assert_eq!(untrusted.expected, 2);
        assert_eq!(untrusted.actual, 2);
    }

    #[test]
    fn candidate_raw_producer_yields_a_contract_valid_arm() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let (job_id, semantic) = universe
            .rows
            .iter()
            .find(|(_, row)| row.status == RowSemanticStatus::Supported && row.model == "count")
            .expect("supported count row");
        let comparator = contract.reporting.comparators[0].id.clone();
        let identity = PerformanceCandidateObservationIdentity {
            contract_id: contract.contract_id.clone(),
            canonical_commit: contract.tested_source.commit.clone(),
            canonical_tree: contract.tested_source.tree.clone(),
            semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
            job_id: job_id.clone(),
            benchmark: semantic.benchmark.clone(),
            model: semantic.model.clone(),
            boundary: "first-public-operation".to_string(),
            comparator,
            candidate_plan: semantic
                .candidate_plan
                .clone()
                .expect("supported candidate plan"),
            candidate_runtime: None,
            input: semantic.input.clone(),
            process_token_sha256: digest(b"contract-valid candidate process"),
        };
        let observation = produce_performance_candidate_observation(&identity, || {
            Ok((Duration::from_nanos(29), semantic.expected))
        })
        .expect("produce contract-valid candidate arm");
        validate_performance_raw_observation(
            &contract,
            &universe,
            &observation,
            CapturePairArm::Candidate,
        )
        .expect("candidate arm validates against semantic contract");

        let wrong_reducer = produce_performance_candidate_observation(&identity, || {
            Ok((
                Duration::from_nanos(31),
                semantic.expected.saturating_add(1),
            ))
        })
        .expect("raw producer has no semantic answer");
        assert!(
            validate_performance_raw_observation(
                &contract,
                &universe,
                &wrong_reducer,
                CapturePairArm::Candidate,
            )
            .is_err(),
            "trusted validation must reject a candidate reducer that differs from the semantic row"
        );

        let mut wrong_plan = observation;
        wrong_plan.candidate_plan = Some("aggregate-continuation-program".to_string());
        assert!(
            validate_performance_raw_observation(
                &contract,
                &universe,
                &wrong_plan,
                CapturePairArm::Candidate,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixed-duration fixture covers every reference lifecycle and fail-closed identity validation"
    )]
    fn reference_raw_producer_binds_identity_and_every_lifecycle_without_a_clock() {
        let identity = PerformanceReferenceObservationIdentity {
            contract_id: "fixture-performance-contract-v1".to_string(),
            canonical_commit: "a".repeat(40),
            canonical_tree: "b".repeat(40),
            semantic_receipts_sha256: "c".repeat(64),
            job_id: "fixture/count-many@rust/regex".to_string(),
            benchmark: "fixture/count-many".to_string(),
            model: "count".to_string(),
            boundary: "first-public-operation".to_string(),
            comparator: "rust-regex-1.12.4".to_string(),
            input: InputReceipt {
                pattern_sha256: vec!["d".repeat(64), "e".repeat(64)],
                haystack_sha256: "f".repeat(64),
                haystack_bytes: 11,
                unicode: true,
                case_insensitive: false,
            },
            process_token_sha256: digest(b"reference raw producer token"),
        };
        let first = produce_performance_reference_observation(&identity, || {
            Ok((Duration::from_nanos(17), 3))
        })
        .expect("fixed first-operation reference sample");
        assert_eq!(first.arm, CapturePairArm::Reference);
        assert_eq!(first.candidate_plan, None);
        assert_eq!(first.candidate_runtime, None);
        assert_eq!(
            first.preparation,
            PerformanceLifecyclePreparation::BuiltArtifact
        );
        assert_eq!(first.priming_operations, 0);
        assert_eq!(first.elapsed_ns, 17);
        assert_eq!(first.result_sha256, digest(&3_u64.to_le_bytes()));
        let bytes = performance_raw_observation_bytes(&first).expect("raw serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));

        let mut steady_identity = identity.clone();
        steady_identity.boundary = "steady-public-operation".to_string();
        steady_identity.process_token_sha256 = digest(b"reference steady token");
        let steady = produce_performance_reference_observation(&steady_identity, || {
            Ok((Duration::from_nanos(19), 3))
        })
        .expect("fixed steady-operation reference sample");
        assert_eq!(
            steady.preparation,
            PerformanceLifecyclePreparation::PrimedArtifact
        );
        assert_eq!(steady.priming_operations, 1);

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
            let mut compile_identity = identity.clone();
            compile_identity.model = "compile".to_string();
            compile_identity.boundary = boundary.to_string();
            let observation = produce_performance_reference_observation(&compile_identity, || {
                Ok((Duration::from_nanos(23), 3))
            })
            .expect("fixed compile reference sample");
            assert_eq!(observation.preparation, preparation);
            assert_eq!(observation.priming_operations, 0);
        }

        let measured = std::cell::Cell::new(false);
        let mut malformed = identity.clone();
        malformed.boundary = "cold-public-compile".to_string();
        assert!(
            produce_performance_reference_observation(&malformed, || {
                measured.set(true);
                Ok((Duration::from_nanos(1), 3))
            })
            .is_err()
        );
        assert!(!measured.get(), "malformed identity ran the measurement");
        malformed = identity.clone();
        malformed.comparator = "rust regex".to_string();
        assert!(
            produce_performance_reference_observation(&malformed, || {
                measured.set(true);
                Ok((Duration::from_nanos(1), 3))
            })
            .is_err()
        );
        assert!(!measured.get(), "malformed comparator ran the measurement");
        assert!(
            produce_performance_reference_observation(&identity, || { Ok((Duration::ZERO, 3)) })
                .is_err()
        );
        let untrusted = produce_performance_reference_observation(&identity, || {
            Ok((Duration::from_nanos(1), 2))
        })
        .expect("producer records a reducer without knowing its semantic answer");
        assert_eq!(untrusted.expected, 2);
        assert_eq!(untrusted.actual, 2);
    }

    #[test]
    fn reference_raw_producer_yields_a_contract_valid_arm() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let (job_id, semantic) = universe
            .rows
            .iter()
            .find(|(_, row)| row.status == RowSemanticStatus::Supported && row.model == "count")
            .expect("supported count row");
        let comparator = contract.reporting.comparators[0].id.clone();
        let identity = PerformanceReferenceObservationIdentity {
            contract_id: contract.contract_id.clone(),
            canonical_commit: contract.tested_source.commit.clone(),
            canonical_tree: contract.tested_source.tree.clone(),
            semantic_receipts_sha256: contract.semantic.receipts_sha256.clone(),
            job_id: job_id.clone(),
            benchmark: semantic.benchmark.clone(),
            model: semantic.model.clone(),
            boundary: "first-public-operation".to_string(),
            comparator,
            input: semantic.input.clone(),
            process_token_sha256: digest(b"contract-valid reference process"),
        };
        let observation = produce_performance_reference_observation(&identity, || {
            Ok((Duration::from_nanos(29), semantic.expected))
        })
        .expect("produce contract-valid reference arm");
        validate_performance_raw_observation(
            &contract,
            &universe,
            &observation,
            CapturePairArm::Reference,
        )
        .expect("reference arm validates against semantic contract");

        let wrong_reducer = produce_performance_reference_observation(&identity, || {
            Ok((
                Duration::from_nanos(31),
                semantic.expected.saturating_add(1),
            ))
        })
        .expect("raw producer has no semantic answer");
        assert!(
            validate_performance_raw_observation(
                &contract,
                &universe,
                &wrong_reducer,
                CapturePairArm::Reference,
            )
            .is_err(),
            "trusted validation must reject a reference reducer that differs from the semantic row"
        );

        let mut candidate_claim = observation;
        candidate_claim.candidate_plan = Some("aggregate-exact-literal".to_string());
        assert!(
            validate_performance_raw_observation(
                &contract,
                &universe,
                &candidate_claim,
                CapturePairArm::Reference,
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_raw_runtime_identity_is_exactly_grep_scoped() {
        let mut identity = PerformanceCandidateObservationIdentity {
            contract_id: "fixture-performance-contract-v1".to_string(),
            canonical_commit: "a".repeat(40),
            canonical_tree: "b".repeat(40),
            semantic_receipts_sha256: "c".repeat(64),
            job_id: "fixture/grep@rust/regex".to_string(),
            benchmark: "fixture/grep".to_string(),
            model: "grep".to_string(),
            boundary: "first-public-operation".to_string(),
            comparator: "rust-regex-1.12.4".to_string(),
            candidate_plan: crate::CURRENT_FRE_REBAR_GREP_PLAN.to_string(),
            candidate_runtime: Some("unicode-word-run-linear-v1".to_string()),
            input: InputReceipt {
                pattern_sha256: vec!["d".repeat(64)],
                haystack_sha256: "e".repeat(64),
                haystack_bytes: 26,
                unicode: true,
                case_insensitive: false,
            },
            process_token_sha256: "f".repeat(64),
        };
        let grep = produce_performance_candidate_observation(&identity, || {
            Ok((Duration::from_nanos(31), 1))
        })
        .expect("grep runtime identity");
        assert_eq!(
            grep.candidate_runtime.as_deref(),
            Some("unicode-word-run-linear-v1")
        );

        identity.candidate_runtime = Some("unrecognized-runtime".to_string());
        assert!(
            produce_performance_candidate_observation(&identity, || {
                Ok((Duration::from_nanos(1), 1))
            })
            .is_err()
        );
        identity.candidate_runtime = None;
        validate_performance_candidate_observation_request(&identity)
            .expect("pre-construction grep request may leave runtime unresolved");
        assert!(
            produce_performance_candidate_observation(&identity, || {
                Ok((Duration::from_nanos(1), 1))
            })
            .is_err()
        );
        identity.canonical_commit = "malformed".to_string();
        assert!(validate_performance_candidate_observation_request(&identity).is_err());
        identity.canonical_commit = "a".repeat(40);
        identity.model = "count".to_string();
        identity.candidate_plan = "aggregate-exact-literal".to_string();
        identity.candidate_runtime = Some("k0".to_string());
        assert!(
            produce_performance_candidate_observation(&identity, || {
                Ok((Duration::from_nanos(1), 1))
            })
            .is_err()
        );
    }

    #[test]
    fn runner_manifest_is_complete_deterministic_and_canonical() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let manifest =
            generate_performance_runner_manifest(&contract, &universe).expect("runner manifest");
        assert_eq!(manifest.rows.len(), 257);
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.route == PerformanceRunnerRoute::AggregateSingle)
                .count(),
            238
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.route == PerformanceRunnerRoute::AggregateMany)
                .count(),
            0
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.route == PerformanceRunnerRoute::PortableGrep)
                .count(),
            11
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.route == PerformanceRunnerRoute::Capture)
                .count(),
            8
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .map(|row| row.pair_slots)
                .sum::<usize>(),
            6_168
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .map(|row| row.unavailable_points)
                .sum::<usize>(),
            0
        );
        let bytes = performance_runner_manifest_bytes(&manifest).expect("manifest serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<PerformanceRunnerManifest>(&bytes)
                .expect("runner manifest round trip"),
            manifest
        );

        let mut altered = manifest.clone();
        altered.rows[0].pair_slots += 1;
        assert!(validate_performance_runner_manifest(&contract, &universe, &altered).is_err());

        let path = std::env::temp_dir().join(format!(
            "fre-performance-runner-manifest-selftest-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        write_new_performance_runner_manifest(&path, &manifest).expect("publish runner manifest");
        assert_eq!(
            read_performance_runner_manifest(&path).expect("read runner manifest"),
            manifest
        );
        assert!(write_new_performance_runner_manifest(&path, &manifest).is_err());
        fs::remove_file(path).expect("remove runner manifest fixture");
    }

    #[test]
    fn runner_manifest_admits_multi_pattern_and_rejects_plan_aliases() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let mut many_universe = universe.clone();
        let compile_job = many_universe
            .rows
            .iter()
            .find(|(_, row)| row.status == RowSemanticStatus::Supported && row.model == "compile")
            .map(|(job_id, _)| job_id.clone())
            .expect("supported compile fixture");
        let compile_row = many_universe
            .rows
            .get_mut(&compile_job)
            .expect("compile fixture row");
        compile_row.candidate_plan = Some("compile-many-ordered-literal".to_string());
        compile_row.input.pattern_sha256.push("3".repeat(64));
        let many_manifest = generate_performance_runner_manifest(&contract, &many_universe)
            .expect("multi-pattern route");
        assert_eq!(
            many_manifest
                .rows
                .iter()
                .find(|row| row.job_id == compile_job)
                .expect("multi-pattern manifest row")
                .route,
            PerformanceRunnerRoute::AggregateMany
        );

        let mut bad_multiplicity = many_universe.clone();
        bad_multiplicity
            .rows
            .get_mut(&compile_job)
            .expect("compile fixture row")
            .candidate_plan = Some("compile-aggregate-exact-literal".to_string());
        assert!(
            generate_performance_runner_manifest(&contract, &bad_multiplicity).is_err(),
            "a single-pattern plan must reject a multi-pattern input"
        );
        let mut bad_plan = universe.clone();
        bad_plan
            .rows
            .get_mut(&compile_job)
            .expect("compile fixture row")
            .candidate_plan = Some("fixture-unadmitted-plan".to_string());
        assert!(generate_performance_runner_manifest(&contract, &bad_plan).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one no-clock packet fixture covers exact artifact derivation, executable provenance, authorization, limits, and task identity"
    )]
    fn execution_packet_and_pair_task_are_exact_and_authorized() {
        fn executable(seed: char, version: &str) -> PerformanceExecutablePolicy {
            let version_stdout = format!("{version}\n");
            PerformanceExecutablePolicy {
                sha256: seed.to_string().repeat(64),
                bytes: 4_096,
                version_stdout_sha256: digest(version_stdout.as_bytes()),
                version_stdout,
                source_commit: "a".repeat(40),
                source_tree: "b".repeat(40),
                build_receipt_sha256: digest(format!("fixture build receipt {seed}").as_bytes()),
            }
        }

        let expanded_manifest = b"fixture expanded manifest\n";
        let mut contract = contract();
        contract.semantic.manifest_sha256 = digest(expanded_manifest);
        let (semantic_bytes, universe) = synthetic_semantic_report(&mut contract);
        let mut contract_bytes = serde_json::to_vec(&contract).expect("serialize contract");
        contract_bytes.push(b'\n');
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("pair schedule");
        let runner_manifest =
            generate_performance_runner_manifest(&contract, &universe).expect("runner manifest");
        let mut packet = PerformanceExecutionPacket {
            schema: PERFORMANCE_EXECUTION_PACKET_SCHEMA.to_string(),
            contract_sha256: digest(&contract_bytes),
            semantic_report_sha256: digest(&semantic_bytes),
            expanded_manifest_sha256: digest(expanded_manifest),
            pair_schedule_sha256: digest(
                &performance_pair_schedule_bytes(&schedule).expect("schedule bytes"),
            ),
            runner_manifest_sha256: digest(
                &performance_runner_manifest_bytes(&runner_manifest).expect("manifest bytes"),
            ),
            canonical_commit: contract.tested_source.commit.clone(),
            canonical_tree: contract.tested_source.tree.clone(),
            candidate_adapter: contract.semantic.fre_adapter.clone(),
            executor: executable('6', "fixture-pair-executor-v1"),
            candidate_wrapper: executable('7', "fixture-candidate-wrapper-v1"),
            reference_wrapper: executable('8', "fixture-reference-wrapper-v1"),
            reference_runners: BTreeMap::from([
                (
                    contract.reporting.comparators[0].id.clone(),
                    executable('4', "fixture-rust-reference-v1"),
                ),
                (
                    contract.reporting.comparators[1].id.clone(),
                    executable('5', "fixture-re2-reference-v1"),
                ),
            ]),
            timing_authority: PerformanceTimingAuthorityPolicy {
                protocol_id: "fixture-timing-authority-v1".to_string(),
                coordinator_sha256: "9".repeat(64),
                authorization_receipt_sha256: "a".repeat(64),
                required_scope: "timing".to_string(),
            },
            limits: PerformancePairExecutionLimits {
                max_klv_bytes: 64 * 1_048_576,
                max_stdout_bytes: 1_048_576,
                max_stderr_bytes: 1_048_576,
                arm_deadline_ms: 3_600_000,
            },
        };
        let packet_bytes = performance_execution_packet_bytes(&packet).expect("packet bytes");
        let packet_sha256 = digest(&packet_bytes);
        let original = packet.clone();
        let validate_packet = |value: &PerformanceExecutionPacket| {
            let bytes = performance_execution_packet_bytes(value).expect("packet bytes");
            validate_performance_execution_packet(
                &contract,
                &contract_bytes,
                &semantic_bytes,
                expanded_manifest,
                &schedule,
                &runner_manifest,
                value,
                &digest(&bytes),
            )
        };
        let context = validate_packet(&packet).expect("exact execution packet validates");
        assert_eq!(context.universe().len(), universe.len());
        assert_eq!(context.packet_sha256(), packet_sha256);
        assert!(
            validate_performance_execution_packet(
                &contract,
                &contract_bytes,
                &semantic_bytes,
                expanded_manifest,
                &schedule,
                &runner_manifest,
                &packet,
                &"f".repeat(64),
            )
            .is_err()
        );
        let task = PerformancePairTask {
            schema: PERFORMANCE_PAIR_TASK_SCHEMA.to_string(),
            execution_packet_sha256: packet_sha256.clone(),
            sequence: 0,
            attempt_id: format!("P0-A{}", "d".repeat(32)),
            candidate_process_token_sha256: "b".repeat(64),
            reference_process_token_sha256: "c".repeat(64),
        };
        let task_bytes = performance_pair_task_bytes(&task).expect("task bytes");
        let validate_task = |value: &PerformancePairTask,
                             value_schedule: &PerformancePairSchedule| {
            let bytes = performance_pair_task_bytes(value).expect("task bytes");
            validate_performance_pair_task(
                &context,
                &original,
                &packet_bytes,
                value_schedule,
                value,
                &digest(&bytes),
            )
        };
        let task_context = validate_task(&task, &schedule).expect("authorized task");
        assert_eq!(task_context.packet_sha256(), packet_sha256);
        assert_eq!(task_context.task_sha256(), digest(&task_bytes));
        assert_eq!(task_context.slot(), &schedule.slots[0]);
        assert_eq!(task_context.attempt_id(), task.attempt_id);
        assert_eq!(
            task_context.candidate_process_token_sha256(),
            task.candidate_process_token_sha256
        );
        assert_eq!(
            task_context.reference_process_token_sha256(),
            task.reference_process_token_sha256
        );
        let mut forged_schedule = schedule.clone();
        forged_schedule.slots[0].boundary = "forged-boundary".to_string();
        assert!(validate_task(&task, &forged_schedule).is_err());
        assert_eq!(task_bytes.last(), Some(&b'\n'));
        assert!(
            validate_performance_pair_task(
                &context,
                &packet,
                &packet_bytes,
                &schedule,
                &task,
                &"0".repeat(64),
            )
            .is_err()
        );
        let fixture_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock after epoch")
            .as_nanos();
        let fixture_root = std::env::temp_dir().join(format!(
            "fre-performance-execution-admission-selftest-{}-{fixture_nonce}",
            std::process::id()
        ));
        fs::create_dir(&fixture_root).expect("create private admission fixture");
        fs::set_permissions(
            &fixture_root,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("protect admission fixture");
        let packet_path = fixture_root.join("packet.json");
        let task_path = fixture_root.join("task.json");
        fs::write(&packet_path, &packet_bytes).expect("write packet fixture");
        fs::write(&task_path, &task_bytes).expect("write task fixture");
        fs::set_permissions(
            &packet_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o400),
        )
        .expect("protect packet fixture");
        fs::set_permissions(
            &task_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o400),
        )
        .expect("protect task fixture");
        assert_eq!(
            read_performance_execution_packet(&packet_path).expect("read packet fixture"),
            packet
        );
        assert_eq!(
            read_performance_pair_task(&task_path).expect("read task fixture"),
            task
        );
        let symlink_path = fixture_root.join("task-symlink.json");
        std::os::unix::fs::symlink(&task_path, &symlink_path).expect("create task symlink");
        assert!(read_performance_pair_task(&symlink_path).is_err());
        fs::remove_file(symlink_path).expect("remove task symlink");

        let hardlink_path = fixture_root.join("task-hardlink.json");
        fs::hard_link(&task_path, &hardlink_path).expect("create task hardlink");
        assert!(read_performance_pair_task(&hardlink_path).is_err());
        fs::remove_file(hardlink_path).expect("remove task hardlink");

        let loose_path = fixture_root.join("task-loose.json");
        fs::write(&loose_path, &task_bytes).expect("write loose task");
        assert!(read_performance_pair_task(&loose_path).is_err());
        fs::remove_file(loose_path).expect("remove loose task");

        let oversized_path = fixture_root.join("packet-oversized.json");
        fs::write(&oversized_path, vec![b'x'; 1_048_577]).expect("write oversized packet");
        fs::set_permissions(
            &oversized_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o400),
        )
        .expect("protect oversized packet");
        assert!(read_performance_execution_packet(&oversized_path).is_err());
        fs::remove_file(oversized_path).expect("remove oversized packet");

        let unknown_path = fixture_root.join("task-unknown.json");
        let mut unknown = task_bytes.clone();
        unknown.splice(
            unknown.len() - 2..unknown.len() - 2,
            b",\"unknown\":0".iter().copied(),
        );
        fs::write(&unknown_path, unknown).expect("write unknown-field task");
        fs::set_permissions(
            &unknown_path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o400),
        )
        .expect("protect unknown-field task");
        assert!(read_performance_pair_task(&unknown_path).is_err());
        fs::remove_file(unknown_path).expect("remove unknown-field task");

        fs::remove_file(packet_path).expect("remove packet fixture");
        fs::remove_file(task_path).expect("remove task fixture");
        fs::remove_dir(fixture_root).expect("remove admission fixture");

        validate_performance_execution_limits(&original.limits).expect("reviewed exact limits");
        let mut invalid_limits = Vec::new();
        for value in [0, 64 * 1_048_576 - 1, 64 * 1_048_576 + 1] {
            let mut limits = original.limits.clone();
            limits.max_klv_bytes = value;
            invalid_limits.push(limits);
        }
        for value in [0, 65_536, 1_048_575, 1_048_577] {
            let mut limits = original.limits.clone();
            limits.max_stdout_bytes = value;
            invalid_limits.push(limits);
            let mut limits = original.limits.clone();
            limits.max_stderr_bytes = value;
            invalid_limits.push(limits);
        }
        for value in [0, 999, 60_000, 3_599_999, 3_600_001] {
            let mut limits = original.limits.clone();
            limits.arm_deadline_ms = value;
            invalid_limits.push(limits);
        }
        assert!(
            invalid_limits
                .iter()
                .all(|limits| validate_performance_execution_limits(limits).is_err())
        );

        let valid_executable = original.candidate_wrapper.clone();
        validate_performance_executable_policy(&valid_executable, "fixture executable")
            .expect("exact executable policy");
        let mut invalid_executables = Vec::new();
        let mut invalid = valid_executable.clone();
        invalid.bytes = 0;
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.bytes = 1_073_741_825;
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.version_stdout = "no-final-lf".to_string();
        invalid.version_stdout_sha256 = digest(invalid.version_stdout.as_bytes());
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.version_stdout = "control\tbyte\n".to_string();
        invalid.version_stdout_sha256 = digest(invalid.version_stdout.as_bytes());
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.version_stdout = format!("{}\n", "x".repeat(4_096));
        invalid.version_stdout_sha256 = digest(invalid.version_stdout.as_bytes());
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.version_stdout_sha256 = "f".repeat(64);
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.source_commit = "malformed".to_string();
        invalid_executables.push(invalid);
        let mut invalid = valid_executable.clone();
        invalid.build_receipt_sha256 = invalid.sha256.clone();
        invalid_executables.push(invalid);
        assert!(invalid_executables.iter().all(|policy| {
            validate_performance_executable_policy(policy, "fixture executable").is_err()
        }));

        packet
            .reference_runners
            .get_mut(&contract.reporting.comparators[0].id)
            .expect("Rust runner")
            .sha256 = "d".repeat(64);
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet
            .reference_runners
            .remove(&contract.reporting.comparators[0].id);
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet
            .reference_runners
            .insert("extra-comparator".to_string(), executable('d', "extra-v1"));
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet.candidate_wrapper = packet.executor.clone();
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet.candidate_wrapper.version_stdout.push('\n');
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet.timing_authority.required_scope = "build".to_string();
        assert!(validate_packet(&packet).is_err());
        packet = original.clone();
        packet.limits.arm_deadline_ms = 0;
        assert!(validate_packet(&packet).is_err());

        let invalid_semantic_runtime = |report: Report| {
            let report_bytes = report_bytes(&report).expect("altered semantic report bytes");
            let mut altered_contract = contract.clone();
            altered_contract.semantic.accepted_report_sha256 = vec![digest(&report_bytes)];
            let mut altered_contract_bytes =
                serde_json::to_vec(&altered_contract).expect("altered contract bytes");
            altered_contract_bytes.push(b'\n');
            let mut altered_packet = original.clone();
            altered_packet.contract_sha256 = digest(&altered_contract_bytes);
            altered_packet.semantic_report_sha256 = digest(&report_bytes);
            let altered_packet_bytes =
                performance_execution_packet_bytes(&altered_packet).expect("altered packet bytes");
            validate_performance_execution_packet(
                &altered_contract,
                &altered_contract_bytes,
                &report_bytes,
                expanded_manifest,
                &schedule,
                &runner_manifest,
                &altered_packet,
                &digest(&altered_packet_bytes),
            )
            .is_err()
        };
        let mut missing_runtime: Report =
            serde_json::from_slice(&semantic_bytes).expect("fixture semantic report");
        missing_runtime
            .adapters
            .iter_mut()
            .find(|adapter| adapter.adapter == contract.reporting.comparators[0].semantic_adapter)
            .expect("Rust semantic adapter")
            .runtime_sha256 = None;
        assert!(invalid_semantic_runtime(missing_runtime));
        let mut duplicate_runtime: Report =
            serde_json::from_slice(&semantic_bytes).expect("fixture semantic report");
        let duplicate = duplicate_runtime
            .adapters
            .iter()
            .find(|adapter| adapter.adapter == contract.reporting.comparators[0].semantic_adapter)
            .expect("Rust semantic adapter")
            .clone();
        duplicate_runtime.adapters.push(duplicate);
        assert!(invalid_semantic_runtime(duplicate_runtime));

        let mut wrong_task = task.clone();
        wrong_task.reference_process_token_sha256 =
            wrong_task.candidate_process_token_sha256.clone();
        assert!(validate_task(&wrong_task, &schedule).is_err());
        wrong_task = task.clone();
        wrong_task.sequence = schedule.slots.len();
        assert!(validate_task(&wrong_task, &schedule).is_err());
        wrong_task = task.clone();
        wrong_task.execution_packet_sha256 = "e".repeat(64);
        assert!(validate_task(&wrong_task, &schedule).is_err());
        wrong_task = task.clone();
        wrong_task.schema = "wrong-task-schema".to_string();
        assert!(validate_task(&wrong_task, &schedule).is_err());
        wrong_task = task.clone();
        wrong_task.candidate_process_token_sha256 = "not-a-digest".to_string();
        assert!(validate_task(&wrong_task, &schedule).is_err());
        for invalid_attempt in [
            format!("P0-A{}", "A".repeat(32)),
            format!("P1-A{}", "d".repeat(32)),
            "../escape".to_string(),
            format!(".P0-A{}", "d".repeat(32)),
            format!("P0-A{}", "d".repeat(31)),
            format!("P0-A{}\0", "d".repeat(32)),
        ] {
            wrong_task = task.clone();
            wrong_task.attempt_id = invalid_attempt;
            assert!(validate_task(&wrong_task, &schedule).is_err());
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one no-clock all-model fixture covers complete conversion and primary identity/lifecycle rejection cases"
    )]
    fn all_model_raw_evidence_converts_every_available_point() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        let evidence = fixture_performance_evidence(&contract, &universe, &schedule);
        assert_eq!(evidence.len(), 6_168);
        let bytes = performance_raw_observation_bytes(&evidence[0].candidate)
            .expect("raw performance serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<PerformanceRawObservation>(&bytes)
                .expect("raw performance round trip"),
            evidence[0].candidate
        );
        let converted =
            apply_performance_pair_evidence(&contract, &universe, &draft, &schedule, &evidence)
                .expect("complete fixed-duration evidence converts");
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            1_028
        );
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Pending),
            0
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Pending),
            8_224
        );
        assert!(
            converted
                .rows
                .iter()
                .flat_map(|row| &row.boundaries)
                .flat_map(|boundary| &boundary.comparisons)
                .all(|comparison| {
                    comparison.ratio_ppm == Some(800_000)
                        && comparison.pair_count == Some(6)
                        && comparison.candidate_wins == Some(6)
                        && comparison.pointwise_pass == Some(true)
                })
        );
        assert!(evidence.iter().all(|pair| {
            let phase = contract
                .lifecycle_boundaries
                .iter()
                .find(|boundary| boundary.id == pair.slot.boundary)
                .expect("evidence boundary")
                .phase;
            let (preparation, priming_operations) = lifecycle_preparation(phase);
            pair.candidate.preparation == preparation
                && pair.reference.preparation == preparation
                && pair.candidate.priming_operations == priming_operations
                && pair.reference.priming_operations == priming_operations
        }));

        let mut missing = evidence.clone();
        missing.pop();
        assert!(
            apply_performance_pair_evidence(&contract, &universe, &draft, &schedule, &missing,)
                .is_err()
        );
        let mut reused_process = evidence.clone();
        reused_process[1].reference.process_token_sha256 =
            reused_process[0].candidate.process_token_sha256.clone();
        assert!(
            apply_performance_pair_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &reused_process,
            )
            .is_err()
        );
        let mut wrong_plan = evidence.clone();
        wrong_plan[0].candidate.candidate_plan = Some("different-plan".to_string());
        assert!(
            apply_performance_pair_evidence(&contract, &universe, &draft, &schedule, &wrong_plan,)
                .is_err()
        );
        let mut wrong_lifecycle = evidence.clone();
        wrong_lifecycle[0].candidate.priming_operations ^= 1;
        assert!(
            apply_performance_pair_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &wrong_lifecycle,
            )
            .is_err()
        );
        let mut wrong_preparation = evidence.clone();
        wrong_preparation[0].candidate.preparation = PerformanceLifecyclePreparation::BuiltArtifact;
        assert!(
            apply_performance_pair_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &wrong_preparation,
            )
            .is_err()
        );
        let mut wrong_boundary = evidence;
        wrong_boundary[0].candidate.boundary = "steady-public-operation".to_string();
        assert!(
            apply_performance_pair_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &wrong_boundary,
            )
            .is_err()
        );
    }

    #[test]
    fn one_all_model_pair_has_canonical_nonoverwriting_publication() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        let evidence = fixture_performance_evidence(&contract, &universe, &schedule);
        let slot = &schedule.slots[0];
        let pair = &evidence[0];
        validate_performance_pair_evidence(&contract, &universe, slot, pair)
            .expect("exact pair validates");

        let bytes = performance_pair_evidence_bytes(pair).expect("pair serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<PerformancePairEvidence>(&bytes).expect("pair round trip"),
            *pair
        );
        let path = std::env::temp_dir().join(format!(
            "fre-performance-pair-selftest-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        write_new_performance_pair_evidence(&path, pair).expect("publish pair");
        assert_eq!(
            read_performance_pair_evidence(&path).expect("read pair"),
            *pair
        );
        assert!(write_new_performance_pair_evidence(&path, pair).is_err());
        fs::remove_file(path).expect("remove pair fixture");

        let mut wrong_slot = pair.clone();
        wrong_slot.slot.sequence += 1;
        assert!(
            validate_performance_pair_evidence(&contract, &universe, slot, &wrong_slot).is_err()
        );
        let mut reused_token = pair.clone();
        reused_token.reference.process_token_sha256 =
            reused_token.candidate.process_token_sha256.clone();
        assert!(
            validate_performance_pair_evidence(&contract, &universe, slot, &reused_token).is_err()
        );
        let mut wrong_arm = pair.clone();
        wrong_arm.reference.arm = CapturePairArm::Candidate;
        assert!(
            validate_performance_pair_evidence(&contract, &universe, slot, &wrong_arm).is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one no-clock all-model resource fixture covers complete composition, lifecycle separation, and primary rejection cases"
    )]
    fn all_model_resource_evidence_converts_every_available_metric() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        let timing_evidence = fixture_performance_evidence(&contract, &universe, &schedule);
        let timed = apply_performance_pair_evidence(
            &contract,
            &universe,
            &draft,
            &schedule,
            &timing_evidence,
        )
        .expect("timing evidence converts first");
        let collector = ResourceCollectorIdentity {
            collector_id: "fixture-all-model-resources-v1".to_string(),
            collector_sha256: digest(b"fixture all-model resource collector"),
        };
        let mut evidence =
            fixture_performance_resource_evidence(&contract, &universe, &schedule, &collector);
        assert_eq!(evidence.len(), 6_168);
        let bytes = performance_resource_observation_bytes(&evidence[0].candidate)
            .expect("resource serialization");
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<PerformanceResourceRawObservation>(&bytes)
                .expect("resource round trip"),
            evidence[0].candidate
        );
        let converted = apply_performance_resource_evidence(
            &contract, &universe, &timed, &schedule, &collector, &evidence,
        )
        .expect("complete all-model resources convert");
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            1_028
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Measured),
            8_224
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Pending),
            0
        );
        let first_slot = &schedule.slots[0];
        let cold = performance_comparison_mut(
            &mut converted.clone(),
            &first_slot.job_id,
            "cold-public-compile",
            &first_slot.comparator,
        )
        .expect("cold compile point")
        .clone();
        let warm = performance_comparison_mut(
            &mut converted.clone(),
            &first_slot.job_id,
            "allocator-warm-public-compile",
            &first_slot.comparator,
        )
        .expect("warm compile point")
        .clone();
        assert_eq!(cold.resources.allocation_count.candidate.median, Some(12));
        assert_eq!(warm.resources.allocation_count.candidate.median, Some(112));
        assert_eq!(
            cold.resources.peak_rss_bytes.reference.collector,
            Some(collector.clone())
        );

        assert!(
            apply_performance_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &evidence[..evidence.len() - 1],
            )
            .is_err()
        );
        let original_token = evidence[1].reference.process_token_sha256.clone();
        evidence[1].reference.process_token_sha256 =
            evidence[0].candidate.process_token_sha256.clone();
        assert!(
            apply_performance_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &evidence,
            )
            .is_err()
        );
        evidence[1].reference.process_token_sha256 = original_token;
        let original_collector = evidence[0].candidate.collector.clone();
        evidence[0].candidate.collector.collector_sha256 = digest(b"different collector");
        assert!(
            apply_performance_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &evidence,
            )
            .is_err()
        );
        evidence[0].candidate.collector = original_collector;
        evidence[0].candidate.preparation = PerformanceLifecyclePreparation::BuiltArtifact;
        assert!(
            apply_performance_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &evidence,
            )
            .is_err()
        );
    }

    #[test]
    fn all_model_resource_unavailability_is_one_metric_and_one_arm() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        let collector = ResourceCollectorIdentity {
            collector_id: "fixture-all-model-resources-v1".to_string(),
            collector_sha256: digest(b"fixture all-model resource collector"),
        };
        let mut evidence =
            fixture_performance_resource_evidence(&contract, &universe, &schedule, &collector);
        let point = (
            schedule.slots[0].job_id.clone(),
            schedule.slots[0].boundary.clone(),
            schedule.slots[0].comparator.clone(),
        );
        let indices: Vec<usize> = evidence
            .iter()
            .enumerate()
            .filter(|(_, pair)| {
                pair.slot.job_id == point.0
                    && pair.slot.boundary == point.1
                    && pair.slot.comparator == point.2
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(indices.len(), 6);
        for index in &indices {
            evidence[*index].reference.peak_rss_bytes = RawResourceMetric {
                status: ResourceMetricStatus::Unavailable,
                value: None,
                reason: Some("reference RSS probe unavailable".to_string()),
            };
        }
        let converted = apply_performance_resource_evidence(
            &contract, &universe, &draft, &schedule, &collector, &evidence,
        )
        .expect("one unavailable metric converts");
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Measured),
            8_223
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Unavailable),
            1
        );
        evidence[indices[0]].reference.peak_rss_bytes = measured_resource(20_000);
        assert!(
            apply_performance_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &evidence,
            )
            .is_err()
        );
    }

    #[test]
    fn all_model_schedule_retains_exact_unavailable_points() {
        let mut contract = contract();
        let (_, mut universe) = synthetic_semantic_report(&mut contract);
        let comparator = contract.reporting.comparators[1].id.clone();
        let row = universe
            .rows
            .iter_mut()
            .find(|(_, row)| row.status == RowSemanticStatus::Supported && row.model == "count")
            .expect("supported count row");
        row.1.comparator_statuses.insert(comparator.clone(), None);
        let unavailable_job = row.0.clone();
        let schedule =
            generate_performance_pair_schedule(&contract, &universe).expect("all-model schedule");
        assert_eq!(schedule.slots.len(), 6_156);
        assert_eq!(schedule.unavailable.len(), 2);
        assert!(schedule.unavailable.iter().all(|point| {
            point.job_id == unavailable_job
                && point.model == "count"
                && point.comparator == comparator
                && point.reason == "semantic report has no matching comparator receipt"
        }));
        assert!(
            !schedule
                .slots
                .iter()
                .any(|slot| slot.job_id == unavailable_job && slot.comparator == comparator)
        );
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let evidence = fixture_performance_evidence(&contract, &universe, &schedule);
        let converted =
            apply_performance_pair_evidence(&contract, &universe, &draft, &schedule, &evidence)
                .expect("available all-model points convert");
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            1_026
        );
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::NotComparable),
            2
        );
        let collector = ResourceCollectorIdentity {
            collector_id: "fixture-all-model-resources-v1".to_string(),
            collector_sha256: digest(b"fixture all-model resource collector"),
        };
        let resource_evidence =
            fixture_performance_resource_evidence(&contract, &universe, &schedule, &collector);
        let complete = apply_performance_resource_evidence(
            &contract,
            &universe,
            &converted,
            &schedule,
            &collector,
            &resource_evidence,
        )
        .expect("available all-model resources convert");
        assert_eq!(
            resource_status_count(&complete, ResourceMetricStatus::Measured),
            8_208
        );
        assert_eq!(
            resource_status_count(&complete, ResourceMetricStatus::NotComparable),
            16
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle test covers complete conversion, composition, boundary separation, and primary rejection cases"
    )]
    fn capture_resources_convert_independently_at_each_boundary() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_capture_pair_schedule(&contract, &universe).expect("capture schedule");
        let collector = ResourceCollectorIdentity {
            collector_id: "fixture-allocation-rss-v1".to_string(),
            collector_sha256: digest(b"fixture resource collector"),
        };
        let timing_evidence = fixture_capture_evidence(&contract, &universe, &schedule);
        let timed =
            apply_capture_pair_evidence(&contract, &universe, &draft, &schedule, &timing_evidence)
                .expect("capture timing evidence converts first");
        let evidence =
            fixture_capture_resource_evidence(&contract, &universe, &schedule, &collector);
        assert_eq!(evidence.len(), 192);
        let raw_bytes = capture_resource_observation_bytes(&evidence[0].candidate)
            .expect("resource raw serialization");
        assert_eq!(raw_bytes.last(), Some(&b'\n'));
        let decoded: CaptureResourceRawObservation =
            serde_json::from_slice(&raw_bytes).expect("resource raw round trip");
        assert_eq!(decoded, evidence[0].candidate);
        let converted = apply_capture_resource_evidence(
            &contract, &universe, &timed, &schedule, &collector, &evidence,
        )
        .expect("complete no-clock resource evidence converts");
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Measured),
            256
        );
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            32
        );
        let first_slot = &schedule.slots[0];
        let first = capture_comparison_mut(
            &mut converted.clone(),
            &first_slot.job_id,
            CaptureLifecycleBoundary::FirstPublicOperation,
            &first_slot.comparator,
        )
        .expect("first resource comparison")
        .clone();
        let steady = capture_comparison_mut(
            &mut converted.clone(),
            &first_slot.job_id,
            CaptureLifecycleBoundary::SteadyPublicOperation,
            &first_slot.comparator,
        )
        .expect("steady resource comparison")
        .clone();
        assert_eq!(first.status, ComparisonStatus::Measured);
        assert_eq!(first.resources.allocation_count.candidate.median, Some(12));
        assert_eq!(first.resources.allocated_bytes.candidate.median, Some(102));
        assert_eq!(
            first.resources.persistent_bytes.candidate.median,
            Some(1_002)
        );
        assert_eq!(
            first.resources.peak_rss_bytes.candidate.median,
            Some(10_002)
        );
        assert_eq!(
            steady.resources.allocation_count.candidate.median,
            Some(112)
        );
        assert_eq!(
            steady.resources.peak_rss_bytes.reference.median,
            Some(20_102)
        );
        assert_eq!(
            first.resources.peak_rss_bytes.candidate.sample_count,
            Some(6)
        );
        assert_eq!(
            first.resources.peak_rss_bytes.candidate.collector,
            Some(collector.clone())
        );

        let mut missing = evidence.clone();
        missing.pop();
        assert!(
            apply_capture_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &missing,
            )
            .is_err()
        );
        let mut wrong_collector = evidence.clone();
        wrong_collector[0].candidate.collector.collector_sha256 = digest(b"other collector");
        assert!(
            apply_capture_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &wrong_collector,
            )
            .is_err()
        );
        let mut reused_process = evidence.clone();
        reused_process[1].reference.process_token_sha256 =
            reused_process[0].candidate.process_token_sha256.clone();
        assert!(
            apply_capture_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &reused_process,
            )
            .is_err()
        );
        let mut pending_raw = evidence.clone();
        pending_raw[0].candidate.allocation_count = RawResourceMetric {
            status: ResourceMetricStatus::Pending,
            value: None,
            reason: Some("not collected".to_string()),
        };
        assert!(
            apply_capture_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &pending_raw,
            )
            .is_err()
        );
        let mut wrong_lifecycle = evidence.clone();
        wrong_lifecycle[0].candidate.priming_operations = 1;
        assert!(
            apply_capture_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &wrong_lifecycle,
            )
            .is_err()
        );
        let mut wrong_boundary = evidence;
        wrong_boundary[0].candidate.boundary = CaptureLifecycleBoundary::SteadyPublicOperation;
        assert!(
            apply_capture_resource_evidence(
                &contract,
                &universe,
                &draft,
                &schedule,
                &collector,
                &wrong_boundary,
            )
            .is_err()
        );
    }

    #[test]
    fn capture_resource_metric_unavailability_is_arm_specific_and_strict() {
        let mut contract = contract();
        let (_, universe) = synthetic_semantic_report(&mut contract);
        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_capture_pair_schedule(&contract, &universe).expect("capture schedule");
        let collector = ResourceCollectorIdentity {
            collector_id: "fixture-allocation-rss-v1".to_string(),
            collector_sha256: digest(b"fixture resource collector"),
        };
        let mut evidence =
            fixture_capture_resource_evidence(&contract, &universe, &schedule, &collector);
        let point = (
            schedule.slots[0].job_id.clone(),
            schedule.slots[0].boundary,
            schedule.slots[0].comparator.clone(),
        );
        for pair in evidence.iter_mut().filter(|pair| {
            pair.slot.job_id == point.0
                && pair.slot.boundary == point.1
                && pair.slot.comparator == point.2
        }) {
            pair.reference.peak_rss_bytes = RawResourceMetric {
                status: ResourceMetricStatus::Unavailable,
                value: None,
                reason: Some("reference collector exposes no process RSS".to_string()),
            };
        }
        let converted = apply_capture_resource_evidence(
            &contract, &universe, &draft, &schedule, &collector, &evidence,
        )
        .expect("one explicitly unavailable resource metric converts");
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Measured),
            255
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Unavailable),
            1
        );
        let unavailable =
            capture_comparison_mut(&mut converted.clone(), &point.0, point.1, &point.2)
                .expect("resource comparison")
                .resources
                .peak_rss_bytes
                .reference
                .clone();
        assert_eq!(unavailable.status, ResourceMetricStatus::Unavailable);
        assert_eq!(unavailable.collector, Some(collector.clone()));
        assert_eq!(unavailable.median, None);
        assert_eq!(unavailable.sample_count, Some(6));
        assert_eq!(
            unavailable.reason.as_deref(),
            Some("reference collector exposes no process RSS")
        );

        let mixed_index = evidence
            .iter()
            .position(|pair| {
                pair.slot.job_id == point.0
                    && pair.slot.boundary == point.1
                    && pair.slot.comparator == point.2
            })
            .expect("point evidence");
        let mut disagree = evidence.clone();
        disagree[mixed_index].reference.peak_rss_bytes.reason =
            Some("different unavailable reason".to_string());
        assert!(
            apply_capture_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &disagree,
            )
            .is_err()
        );
        evidence[mixed_index].reference.peak_rss_bytes = measured_resource(20_000);
        assert!(
            apply_capture_resource_evidence(
                &contract, &universe, &draft, &schedule, &collector, &evidence,
            )
            .is_err()
        );
    }

    #[test]
    fn unavailable_capture_comparator_gets_no_slots_and_stays_explicit() {
        let mut contract = contract();
        let (_, mut universe) = synthetic_semantic_report(&mut contract);
        let re2 = contract.reporting.comparators[1].id.clone();
        let row = universe
            .rows
            .iter_mut()
            .find(|(_, row)| {
                row.status == RowSemanticStatus::Supported && row.model == "count-captures"
            })
            .expect("supported capture row");
        row.1.comparator_statuses.insert(re2.clone(), None);
        let unavailable_job = row.0.clone();

        let draft = generate_draft_observations(&contract, &universe).expect("draft");
        let schedule =
            generate_capture_pair_schedule(&contract, &universe).expect("capture schedule");
        assert_eq!(schedule.slots.len(), 180);
        assert_eq!(schedule.unavailable.len(), 2);
        assert!(schedule.unavailable.iter().all(|point| {
            point.job_id == unavailable_job
                && point.comparator == re2
                && point.reason == "semantic report has no matching comparator receipt"
        }));
        assert!(
            !schedule
                .slots
                .iter()
                .any(|slot| slot.job_id == unavailable_job && slot.comparator == re2)
        );

        let evidence = fixture_capture_evidence(&contract, &universe, &schedule);
        let converted =
            apply_capture_pair_evidence(&contract, &universe, &draft, &schedule, &evidence)
                .expect("available capture evidence converts");
        assert_eq!(
            comparison_status_count(&converted, ComparisonStatus::Measured),
            30
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::NotComparable),
            16
        );
        assert_eq!(
            resource_status_count(&converted, ResourceMetricStatus::Unavailable),
            0
        );
        for point in &schedule.unavailable {
            let comparison = converted
                .rows
                .iter()
                .find(|row| row.job_id == point.job_id)
                .and_then(|row| {
                    row.boundaries
                        .iter()
                        .find(|boundary| boundary.boundary == point.boundary.as_str())
                })
                .and_then(|boundary| {
                    boundary
                        .comparisons
                        .iter()
                        .find(|comparison| comparison.comparator == point.comparator)
                })
                .expect("unavailable comparison remains present");
            assert_eq!(comparison.status, ComparisonStatus::NotComparable);
            assert_eq!(comparison.reason.as_deref(), Some(point.reason.as_str()));
            validate_not_comparable_resource_observation(&comparison.resources, &point.reason)
                .expect("unavailable comparator resources remain explicit");
        }
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
