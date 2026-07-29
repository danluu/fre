//! Authenticated, untimed inventory for the optimizing Count-v3 AOT route.
//!
//! The selector deliberately stops before code generation. Its artifact rows
//! contain only a transformed pattern, fixed semantic options, and the
//! construction-authenticated literal projection. Job and haystack identities
//! live only in cell rows and are never inputs to an optimizer.

use std::collections::{BTreeMap, BTreeSet};

use fre::{
    AggregateBuildLimits, AggregateBuilder, AggregatePlanKind, AggregatePlanSelection,
    AggregateStrategy,
};
use rebar_expand::Manifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    AUDITED_REBAR_REVISION, CompareError, CurrentFreAggregateOperationInner, FRE_ADAPTER, Loader,
    REPORT_SCHEMA, RUST_ADAPTER, Report, RunConfig, RunLimits, Status, aggregate_run_limits,
    current_fre_rebar_aggregate_operation_lifecycle, read_limited, report_bytes, sha256,
    validate_manifest, verify_sidecar_hash,
};

/// Closed schema for an authenticated, untimed Count-v3 candidate inventory.
pub const OPTIMIZING_COUNT_V3_INVENTORY_SCHEMA: &str = "fre.optimizing-count-v3.inventory.v1";
/// Pattern-only compiler-input row schema.
pub const OPTIMIZING_COUNT_V3_ARTIFACT_INPUT_SCHEMA: &str =
    "fre.optimizing-count-v3.artifact-input.v1";
/// Complete manifest selector-decision row schema.
pub const OPTIMIZING_COUNT_V3_SELECTOR_DECISION_SCHEMA: &str =
    "fre.optimizing-count-v3.selector-decision.v1";
/// Fixed semantic profile used by the first production qualification.
pub const OPTIMIZING_COUNT_V3_SEMANTIC_PROFILE: &str = concat!(
    "rust-regex-1.12.4-rebar-bytes-case-sensitive-",
    "candidate-proven-exact-byte-equivalence-",
    "whole-haystack-nonoverlapping-count-v1"
);
/// Information policy required of every AOT compiler invocation.
pub const OPTIMIZING_COUNT_V3_INPUT_POLICY: &str = "pattern-semantic-options-target-only-v1";
/// Target-independent deployment envelope for long-running compiled Count.
pub const OPTIMIZING_COUNT_V3_LONG_SCAN_POLICY_V1: &str = "minimum-haystack-4096-bytes-v1";
/// Smallest haystack admitted by the versioned long-scan policy.
pub const OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1: usize = 4_096;

const SELECTOR_POLICY_PREFIX_V2: &str = "FRE-OPTIMIZING-COUNT-V3-SELECTOR\0\x02\
engine=rust/regex\n\
model=count\n\
patterns=1\n\
unicode=off-or-nonempty-exact-utf8-literal\n\
case_insensitive=false\n\
semantic_receipt=pass\n\
candidate_plan=aggregate-exact-literal\n\
compiler_plan=fixed-aot-count-exact-literal-v1\n\
literal_bytes=1..32\n";
const SHORT_INPUT_REASON_V1: &str = "input-shorter-than-4096-byte-long-scan-v1";
const SEMANTIC_OPTIONS_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-SEMANTIC-OPTIONS\0\x01";
const ARTIFACT_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-ARTIFACT\0\x01";
const PATTERN_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-PATTERN\0\x01";
const CELL_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-CELL\0\x01";
const JOB_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-JOB\0\x01";
const FAMILY_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-FAMILY\0\x01";
const CLUSTER_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-EXACT-LITERAL-CLUSTER\0\x01";
const ORACLE_RECEIPT_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-ORACLE-RECEIPT\0\x01";
const INVENTORY_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-INVENTORY\0\x01";

/// One complete selector decision for an expanded Rebar job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizingCountV3SelectorDecision {
    pub schema: String,
    /// Safe digest-derived alias; the raw Rebar ID is retained separately.
    pub job_id: String,
    pub rebar_job_id: String,
    pub selected: bool,
    /// Closed, stable decision tag.
    pub reason: String,
}

/// One compiler input shared by every cell with the same pattern semantics.
///
/// No job, family, partition, haystack, oracle, expected count, or timing
/// field is representable here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizingCountV3ArtifactInput {
    pub schema: String,
    pub pattern_input_id: String,
    pub input_policy: String,
    /// Digest of transformed source plus the exact Unicode-mode semantic
    /// variant. This is the qualification `pattern_sha256`.
    pub pattern_sha256: String,
    pub source_pattern_sha256: String,
    pub unicode: bool,
    pub semantic_options_sha256: String,
    /// Target-independent pattern/semantics identity. A target receipt later
    /// computes the qualification contract's `optimizer_input_sha256` by
    /// adding its explicit target-contract digest.
    pub pattern_semantics_identity: String,
    /// Exact transformed regex source used to reconstruct the opaque facade
    /// candidate outside all operation timers.
    pub transformed_pattern: String,
    /// Construction-authenticated exact literal, encoded without ambiguity.
    pub literal_hex: String,
    pub literal_sha256: String,
    pub literal_bytes: usize,
    pub semantic_binding_identity: String,
    pub planning_receipt_identity: String,
}

/// One eligible compiled Rebar cell. Attribution is intentionally separate
/// from [`OptimizingCountV3ArtifactInput`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizingCountV3Cell {
    pub cell_id: String,
    pub job_id: String,
    pub family_id: String,
    /// Exact-literal equivalence seed. The reviewed partitioning step must
    /// merge these seeds into broader near-duplicate clusters before assigning
    /// training, validation, or final holdout.
    pub exact_literal_cluster_seed: String,
    pub pattern_input_id: String,
    pub pattern_sha256: String,
    pub pattern_len: usize,
    pub input_sha256: String,
    pub input_bytes: usize,
    pub expected_count: u64,
    pub oracle_receipt_sha256: String,
}

/// Complete authenticated selector output before partitioning or timing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizingCountV3Inventory {
    pub schema: String,
    pub inventory_identity: String,
    pub manifest_sha256: String,
    pub semantic_report_sha256: String,
    pub rebar_revision: String,
    pub selector_policy_sha256: String,
    pub semantic_profile: String,
    pub semantic_options_sha256: String,
    pub input_policy: String,
    pub manifest_jobs: usize,
    pub selected_cells: usize,
    pub distinct_artifacts: usize,
    pub decisions: Vec<OptimizingCountV3SelectorDecision>,
    pub artifacts: Vec<OptimizingCountV3ArtifactInput>,
    pub cells: Vec<OptimizingCountV3Cell>,
}

/// Authenticate the pinned manifest and current semantic report, then project
/// the complete untimed Count-v3 candidate universe.
///
/// This function performs ordinary facade construction as the current
/// semantic control, then separately reconstructs the fixed-policy facade
/// owner required by the AOT compiler and executes both once for correctness.
/// It never compiles AOT code and never measures elapsed time.
pub fn inventory_optimizing_count_v3(
    config: &RunConfig,
    semantic_report: &Report,
) -> Result<OptimizingCountV3Inventory, CompareError> {
    if semantic_report.schema != REPORT_SCHEMA {
        return Err(CompareError::new(format!(
            "Count-v3 inventory requires {REPORT_SCHEMA}, got {}",
            semantic_report.schema
        )));
    }
    let receipt_bytes = serde_json::to_vec(&semantic_report.receipts)
        .map_err(|error| CompareError::new(format!("serialize semantic receipts: {error}")))?;
    let receipt_digest = sha256(&receipt_bytes);
    if receipt_digest != semantic_report.receipts_sha256 {
        return Err(CompareError::new(format!(
            "semantic receipt digest {receipt_digest} differs from embedded {}",
            semantic_report.receipts_sha256
        )));
    }

    let manifest_bytes = read_limited(&config.manifest, 64 * 1_048_576)?;
    let manifest_sha256 = sha256(&manifest_bytes);
    verify_sidecar_hash(&config.manifest, &manifest_sha256)?;
    if semantic_report.manifest_sha256 != manifest_sha256 {
        return Err(CompareError::new(
            "Count-v3 semantic report does not authenticate this manifest",
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| CompareError::new(format!("decode manifest: {error}")))?;
    validate_manifest(&manifest, &config.checkout, &config.limits)?;
    if manifest.source.revision != AUDITED_REBAR_REVISION
        || semantic_report.rebar_revision != manifest.source.revision
    {
        return Err(CompareError::new(
            "Count-v3 inventory Rebar revisions do not close",
        ));
    }

    let semantic_report_sha256 = sha256(&report_bytes(semantic_report)?);
    let semantic_options_sha256 = digest_fields(
        SEMANTIC_OPTIONS_DOMAIN,
        &[OPTIMIZING_COUNT_V3_SEMANTIC_PROFILE.as_bytes()],
    );
    let selector_policy = selector_policy_bytes_v2();
    let selector_policy_sha256 = sha256(&selector_policy);
    let receipt_index = index_receipts(semantic_report)?;
    let manifest_root = config
        .manifest
        .parent()
        .ok_or_else(|| CompareError::new("manifest has no parent directory"))?;
    let mut loader = Loader::new(manifest_root, &config.checkout, &config.limits);
    let mut decisions = Vec::new();
    let mut artifacts = BTreeMap::<String, OptimizingCountV3ArtifactInput>::new();
    let mut cells = Vec::new();
    decisions
        .try_reserve_exact(manifest.jobs.len())
        .map_err(|error| CompareError::new(format!("reserve selector decisions: {error}")))?;

    for job in &manifest.jobs {
        let safe_job_id = safe_id("job", JOB_ID_DOMAIN, job.id.as_bytes());
        let static_reason = static_exclusion_reason(job);
        if let Some(reason) = static_reason {
            decisions.push(decision(&safe_job_id, &job.id, false, reason));
            continue;
        }

        let rust_receipt = receipt_index
            .get(&(job.id.as_str(), RUST_ADAPTER))
            .ok_or_else(|| {
                CompareError::new(format!(
                    "Count-v3 selector lacks pinned Rust receipt for {}",
                    job.id
                ))
            })?;
        let fre_receipt = receipt_index
            .get(&(job.id.as_str(), FRE_ADAPTER))
            .ok_or_else(|| {
                CompareError::new(format!(
                    "Count-v3 selector lacks current FRE receipt for {}",
                    job.id
                ))
            })?;
        if rust_receipt.status != Status::Pass || rust_receipt.actual != Some(rust_receipt.expected)
        {
            return Err(CompareError::new(format!(
                "pinned Rust oracle receipt {} is not a semantic pass",
                job.id
            )));
        }
        if fre_receipt.status != Status::Pass || fre_receipt.actual != Some(fre_receipt.expected) {
            decisions.push(decision(
                &safe_job_id,
                &job.id,
                false,
                "current-fre-semantic-not-pass",
            ));
            continue;
        }
        if fre_receipt.candidate_plan.as_deref() != Some("aggregate-exact-literal") {
            decisions.push(decision(
                &safe_job_id,
                &job.id,
                false,
                "current-fre-plan-not-exact-literal",
            ));
            continue;
        }

        let loaded = loader.load(job)?;
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            "count",
            &loaded.patterns,
            job.regex.unicode,
            false,
            loaded.haystack.len(),
        )?;
        let CurrentFreAggregateOperationInner::CountSingle(regex, _) = &lifecycle.inner else {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} did not retain one Count artifact",
                job.id
            )));
        };
        if regex.build_report().plan != AggregatePlanKind::ExactLiteral
            || lifecycle.plan() != "aggregate-exact-literal"
        {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} rebuilt to a different plan",
                job.id
            )));
        }
        let current_candidate = regex.exact_literal_aot_candidate().ok_or_else(|| {
            CompareError::new(format!(
                "selected Count-v3 job {} lacks its authenticated exact-literal candidate",
                job.id
            ))
        })?;
        let current_literal = current_candidate.literal();
        if current_literal.is_empty() {
            decisions.push(decision(&safe_job_id, &job.id, false, "literal-empty"));
            continue;
        }
        if current_literal.len() > 32 {
            decisions.push(decision(
                &safe_job_id,
                &job.id,
                false,
                "literal-wider-than-32-bytes",
            ));
            continue;
        }
        if loaded.haystack.len() < OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1 {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} escaped the long-scan input floor",
                job.id
            )));
        }
        let observed = lifecycle.execute(&loaded.haystack)?;
        if observed != job.expected.count || observed != fre_receipt.expected {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} rebuilt value {observed} differs from oracle {}",
                job.id, job.expected.count
            )));
        }

        let [pattern] = loaded.patterns.as_slice() else {
            return Err(CompareError::new(
                "selected Count-v3 job lost its single-pattern shape",
            ));
        };
        let [pattern_descriptor] = job.regex.patterns.as_slice() else {
            return Err(CompareError::new(
                "selected Count-v3 manifest job lost its single-pattern shape",
            ));
        };
        let fixed_regex = AggregateBuilder::new(pattern.clone())
            .unicode(job.regex.unicode)
            .case_insensitive(false)
            .limits(AggregateBuildLimits::aot_count_exact_literal_v1())
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .map_err(|error| {
                CompareError::new(format!(
                    "selected Count-v3 job {} fixed-policy facade build: {error}",
                    job.id
                ))
            })?;
        if fixed_regex.build_report().plan != AggregatePlanKind::ExactLiteral {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} fixed-policy facade selected a different plan",
                job.id
            )));
        }
        let candidate = fixed_regex
            .exact_literal_aot_planned_candidate()
            .ok_or_else(|| {
                CompareError::new(format!(
                    "selected Count-v3 job {} lacks the authenticated fixed-policy AOT candidate",
                    job.id
                ))
            })?;
        let literal = candidate.literal();
        // The semantic-binding receipt intentionally includes plan selection,
        // so the ordinary Auto control and the forced AOT owner have distinct
        // receipts. Their retained literal and independent executions must
        // instead close over the same source/options and oracle value.
        if literal != current_literal {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} current and fixed-policy retained literals differ",
                job.id
            )));
        }
        let fixed_limits = aggregate_run_limits(
            loaded.haystack.len(),
            fixed_regex.build_report(),
            &RunLimits::default(),
        )
        .map_err(|error| {
            CompareError::new(format!(
                "selected Count-v3 job {} fixed-policy run limits: {}",
                job.id, error.message
            ))
        })?;
        let fixed_observed = fixed_regex
            .count_value(&loaded.haystack, fixed_limits)
            .map_err(|error| {
                CompareError::new(format!(
                    "selected Count-v3 job {} fixed-policy correctness execution: {error}",
                    job.id
                ))
            })?;
        if fixed_observed != observed {
            return Err(CompareError::new(format!(
                "selected Count-v3 job {} fixed-policy value {fixed_observed} differs from current value {observed}",
                job.id
            )));
        }
        let pattern_sha256 =
            qualified_pattern_identity(&pattern_descriptor.sha256, job.regex.unicode);
        let pattern_semantics_identity =
            pattern_semantics_identity(&pattern_sha256, &semantic_options_sha256);
        let pattern_input_id = format!("pattern-{pattern_semantics_identity}");
        let literal_sha256 = sha256(literal);
        let semantic_binding_identity = hex(candidate.semantic_binding_identity().as_bytes());
        let planning_receipt_identity = hex(candidate.planning_receipt_identity().as_bytes());
        let artifact = OptimizingCountV3ArtifactInput {
            schema: OPTIMIZING_COUNT_V3_ARTIFACT_INPUT_SCHEMA.to_string(),
            pattern_input_id: pattern_input_id.clone(),
            input_policy: OPTIMIZING_COUNT_V3_INPUT_POLICY.to_string(),
            pattern_sha256: pattern_sha256.clone(),
            source_pattern_sha256: pattern_descriptor.sha256.clone(),
            unicode: job.regex.unicode,
            semantic_options_sha256: semantic_options_sha256.clone(),
            pattern_semantics_identity,
            transformed_pattern: pattern.clone(),
            literal_hex: hex(literal),
            literal_sha256: literal_sha256.clone(),
            literal_bytes: literal.len(),
            semantic_binding_identity,
            planning_receipt_identity,
        };
        match artifacts.insert(pattern_input_id.clone(), artifact.clone()) {
            Some(previous) if previous != artifact => {
                return Err(CompareError::new(format!(
                    "artifact input {pattern_input_id} has inconsistent pattern-only projections"
                )));
            }
            _ => {}
        }

        let family_id = safe_id("family", FAMILY_ID_DOMAIN, job.benchmark.as_bytes());
        let exact_literal_cluster_seed = safe_id("cluster", CLUSTER_ID_DOMAIN, literal);
        let cell_id = safe_id(
            "cell",
            CELL_ID_DOMAIN,
            format!(
                "{}\0{}\0{}\0{}",
                job.id, pattern_sha256, job.haystack.sha256, pattern_input_id
            )
            .as_bytes(),
        );
        let oracle_bytes = serde_json::to_vec(rust_receipt)
            .map_err(|error| CompareError::new(format!("serialize Rust oracle: {error}")))?;
        let oracle_receipt_sha256 =
            digest_fields(ORACLE_RECEIPT_DOMAIN, &[oracle_bytes.as_slice()]);
        cells.push(OptimizingCountV3Cell {
            cell_id,
            job_id: safe_job_id.clone(),
            family_id,
            exact_literal_cluster_seed,
            pattern_input_id,
            pattern_sha256,
            pattern_len: literal.len(),
            input_sha256: job.haystack.sha256.clone(),
            input_bytes: job.haystack.bytes,
            expected_count: job.expected.count,
            oracle_receipt_sha256,
        });
        decisions.push(decision(&safe_job_id, &job.id, true, "eligible"));
    }

    cells.sort_by(|left, right| left.cell_id.cmp(&right.cell_id));
    decisions.sort_by(|left, right| left.job_id.cmp(&right.job_id));
    let artifacts: Vec<_> = artifacts.into_values().collect();
    require_closed_ids(&decisions, &cells)?;
    let selected_cells = cells.len();
    let distinct_artifacts = artifacts.len();
    let inventory_identity = inventory_identity(
        &manifest_sha256,
        &semantic_report_sha256,
        &selector_policy_sha256,
        &semantic_options_sha256,
        &decisions,
        &artifacts,
        &cells,
    )?;
    Ok(OptimizingCountV3Inventory {
        schema: OPTIMIZING_COUNT_V3_INVENTORY_SCHEMA.to_string(),
        inventory_identity,
        manifest_sha256,
        semantic_report_sha256,
        rebar_revision: manifest.source.revision,
        selector_policy_sha256,
        semantic_profile: OPTIMIZING_COUNT_V3_SEMANTIC_PROFILE.to_string(),
        semantic_options_sha256,
        input_policy: OPTIMIZING_COUNT_V3_INPUT_POLICY.to_string(),
        manifest_jobs: manifest.jobs.len(),
        selected_cells,
        distinct_artifacts,
        decisions,
        artifacts,
        cells,
    })
}

fn static_exclusion_reason(job: &rebar_expand::Job) -> Option<&'static str> {
    if job.engine != "rust/regex" {
        Some("engine-not-rust-regex")
    } else if job.model != "count" {
        Some("model-not-count")
    } else if job.regex.patterns.len() != 1 {
        Some("pattern-count-not-one")
    } else if job.regex.case_insensitive {
        Some("case-insensitive")
    } else {
        long_scan_exclusion_reason(job.haystack.bytes)
    }
}

fn long_scan_exclusion_reason(input_bytes: usize) -> Option<&'static str> {
    (input_bytes < OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1)
        .then_some(SHORT_INPUT_REASON_V1)
}

fn selector_policy_bytes_v2() -> Vec<u8> {
    format!(
        "{SELECTOR_POLICY_PREFIX_V2}long_scan_policy={OPTIMIZING_COUNT_V3_LONG_SCAN_POLICY_V1}\n\
         input_bytes={OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1}..\n"
    )
    .into_bytes()
}

fn index_receipts<'a>(
    report: &'a Report,
) -> Result<BTreeMap<(&'a str, &'a str), &'a super::Receipt>, CompareError> {
    let mut index = BTreeMap::new();
    for receipt in &report.receipts {
        let key = (receipt.job_id.as_str(), receipt.adapter.as_str());
        if index.insert(key, receipt).is_some() {
            return Err(CompareError::new(format!(
                "duplicate semantic receipt for {} and {}",
                receipt.job_id, receipt.adapter
            )));
        }
    }
    Ok(index)
}

fn pattern_semantics_identity(pattern_sha256: &str, semantic_options_sha256: &str) -> String {
    digest_fields(
        ARTIFACT_ID_DOMAIN,
        &[
            b"fre.optimizing-count-v3.pattern-semantics.v1",
            pattern_sha256.as_bytes(),
            semantic_options_sha256.as_bytes(),
        ],
    )
}

fn qualified_pattern_identity(source_pattern_sha256: &str, unicode: bool) -> String {
    digest_fields(
        PATTERN_ID_DOMAIN,
        &[
            source_pattern_sha256.as_bytes(),
            &[u8::from(unicode)],
            &[0_u8], // case-insensitive is rejected by the selector.
        ],
    )
}

fn decision(
    job_id: &str,
    rebar_job_id: &str,
    selected: bool,
    reason: &str,
) -> OptimizingCountV3SelectorDecision {
    OptimizingCountV3SelectorDecision {
        schema: OPTIMIZING_COUNT_V3_SELECTOR_DECISION_SCHEMA.to_string(),
        job_id: job_id.to_string(),
        rebar_job_id: rebar_job_id.to_string(),
        selected,
        reason: reason.to_string(),
    }
}

fn require_closed_ids(
    decisions: &[OptimizingCountV3SelectorDecision],
    cells: &[OptimizingCountV3Cell],
) -> Result<(), CompareError> {
    let mut decision_ids = BTreeSet::new();
    for row in decisions {
        if !decision_ids.insert(row.job_id.as_str()) {
            return Err(CompareError::new(format!(
                "duplicate selector job ID {}",
                row.job_id
            )));
        }
    }
    let mut cell_ids = BTreeSet::new();
    let mut selected_jobs = BTreeSet::new();
    for cell in cells {
        if !cell_ids.insert(cell.cell_id.as_str()) || !selected_jobs.insert(cell.job_id.as_str()) {
            return Err(CompareError::new(
                "Count-v3 inventory has duplicate cell or selected job IDs",
            ));
        }
    }
    let declared_selected: BTreeSet<_> = decisions
        .iter()
        .filter(|row| row.selected)
        .map(|row| row.job_id.as_str())
        .collect();
    if declared_selected != selected_jobs {
        return Err(CompareError::new(
            "Count-v3 selector decisions and cells do not close",
        ));
    }
    Ok(())
}

fn inventory_identity(
    manifest_sha256: &str,
    semantic_report_sha256: &str,
    selector_policy_sha256: &str,
    semantic_options_sha256: &str,
    decisions: &[OptimizingCountV3SelectorDecision],
    artifacts: &[OptimizingCountV3ArtifactInput],
    cells: &[OptimizingCountV3Cell],
) -> Result<String, CompareError> {
    let decisions = serde_json::to_vec(decisions)
        .map_err(|error| CompareError::new(format!("serialize selector decisions: {error}")))?;
    let artifacts = serde_json::to_vec(artifacts)
        .map_err(|error| CompareError::new(format!("serialize artifact inputs: {error}")))?;
    let cells = serde_json::to_vec(cells)
        .map_err(|error| CompareError::new(format!("serialize inventory cells: {error}")))?;
    Ok(digest_fields(
        INVENTORY_ID_DOMAIN,
        &[
            manifest_sha256.as_bytes(),
            semantic_report_sha256.as_bytes(),
            selector_policy_sha256.as_bytes(),
            semantic_options_sha256.as_bytes(),
            &decisions,
            &artifacts,
            &cells,
        ],
    ))
}

fn safe_id(prefix: &str, domain: &[u8], value: &[u8]) -> String {
    format!("{prefix}-{}", digest_fields(domain, &[value]))
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualification_pattern_identity_binds_unicode_variant() {
        let source = "11".repeat(32);
        assert_ne!(
            qualified_pattern_identity(&source, false),
            qualified_pattern_identity(&source, true)
        );
        assert_eq!(
            qualified_pattern_identity(&source, false),
            qualified_pattern_identity(&source, false)
        );
    }

    #[test]
    fn compiler_input_shape_cannot_carry_cell_attribution() {
        let artifact = OptimizingCountV3ArtifactInput {
            schema: OPTIMIZING_COUNT_V3_ARTIFACT_INPUT_SCHEMA.to_string(),
            pattern_input_id: format!("pattern-{}", "12".repeat(32)),
            input_policy: OPTIMIZING_COUNT_V3_INPUT_POLICY.to_string(),
            pattern_sha256: "23".repeat(32),
            source_pattern_sha256: "34".repeat(32),
            unicode: false,
            semantic_options_sha256: "45".repeat(32),
            pattern_semantics_identity: "56".repeat(32),
            transformed_pattern: "needle".to_string(),
            literal_hex: "6e6565646c65".to_string(),
            literal_sha256: "67".repeat(32),
            literal_bytes: 6,
            semantic_binding_identity: "78".repeat(32),
            planning_receipt_identity: "89".repeat(32),
        };
        let value = serde_json::to_value(artifact).expect("serialize artifact input");
        let object = value.as_object().expect("artifact input object");
        for forbidden in [
            "cell_id",
            "job_id",
            "family_id",
            "partition",
            "input_sha256",
            "input_bytes",
            "expected_count",
            "oracle_receipt_sha256",
            "elapsed_ns",
        ] {
            assert!(!object.contains_key(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn digest_field_boundaries_are_unambiguous() {
        assert_ne!(
            digest_fields(b"domain", &[b"a", b"bc"]),
            digest_fields(b"domain", &[b"ab", b"c"])
        );
        assert_ne!(
            digest_fields(b"domain-a", &[b"payload"]),
            digest_fields(b"domain-b", &[b"payload"])
        );
    }

    #[test]
    fn long_scan_policy_closes_selector_boundaries_and_identity() {
        assert_eq!(OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1, 4_096);
        assert_eq!(
            long_scan_exclusion_reason(4_095),
            Some("input-shorter-than-4096-byte-long-scan-v1")
        );
        assert_eq!(long_scan_exclusion_reason(4_096), None);
        assert_eq!(long_scan_exclusion_reason(4_097), None);
        let policy = String::from_utf8(selector_policy_bytes_v2()).expect("selector policy UTF-8");
        assert!(policy.starts_with("FRE-OPTIMIZING-COUNT-V3-SELECTOR\0\u{2}"));
        assert!(policy.contains(&format!(
            "long_scan_policy={OPTIMIZING_COUNT_V3_LONG_SCAN_POLICY_V1}\n"
        )));
        assert!(policy.ends_with(&format!(
            "input_bytes={OPTIMIZING_COUNT_V3_LONG_SCAN_MIN_INPUT_BYTES_V1}..\n"
        )));
    }
}
