//! Executable scheduling and strict-gain contracts for the authenticated
//! `regex-automata` package-suite inventory.
//!
//! The inventory deliberately has no pass disposition. This module keeps that
//! property: only an adapter function that is compiled into this crate and is
//! actually invoked can produce a pass receipt. The initial registry is empty,
//! so the first report is an honest zero-pass baseline and a deterministic
//! assignment, not an inferred compatibility claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    CandidateIdentity, InventoryError, RegexAutomataCorpusReport, RegexAutomataHarnessKind,
    RegexAutomataObligation, sha256,
};

/// Complete candidate coverage report over every feature-mode membership.
pub const REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v1";
/// One immutable source-work assignment derived from a complete report.
pub const REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.gap-assignment.v1";

const INVENTORY_UNSUPPORTED_REASON: &str = "fre-adapter.regex-automata-member-not-implemented";
const ASSIGNMENT_TARGET_LIMIT: usize = 16;
const REPORT_LIMITATIONS: [&str; 2] = [
    "A pass is emitted only after an exact registered adapter function executes successfully; absent registrations remain unsupported.",
    "One unique harness/case adapter disposition is projected across every authenticated feature-mode membership for that same identity.",
];

/// Candidate disposition for one exact feature-mode membership.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegexAutomataAdapterDisposition {
    Pass { evidence_sha256: String },
    Unsupported { reason_code: String },
    Fault { stage: String, reason_code: String },
}

/// One result bound to an exact inventory obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReceipt {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub disposition: RegexAutomataAdapterDisposition,
}

/// Complete result cardinalities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterCounts {
    pub pass: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload covered by [`RegexAutomataAdapterReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReportPayload {
    pub inventory_payload_sha256: String,
    pub obligation_inventory_sha256: String,
    pub candidate: CandidateIdentity,
    pub counts: RegexAutomataAdapterCounts,
    pub receipts: Vec<RegexAutomataAdapterReceipt>,
    pub limitations: Vec<String>,
}

/// Complete adapter report. Its denominator is always the inventory's exact
/// 3,842 feature-mode memberships.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexAutomataAdapterReportPayload,
}

/// All feature-mode memberships for one independently implementable case.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataGapTarget {
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub mode_ids: Vec<String>,
}

/// Deterministic work packet for one pending package-suite family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataGapAssignment {
    pub schema: String,
    pub attempt_id: String,
    pub slot: usize,
    pub base: String,
    pub baseline_report_sha256: String,
    pub baseline_payload_sha256: String,
    pub inventory_payload_sha256: String,
    pub obligation_inventory_sha256: String,
    pub family: String,
    pub targets: Vec<RegexAutomataGapTarget>,
    pub targets_sha256: String,
}

/// Strict-gain summary returned only after all no-regression checks pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStrictGain {
    pub family: String,
    pub gained_unique_cases: usize,
    pub gained_mode_memberships: usize,
    pub previous_pass: usize,
    pub current_pass: usize,
}

type AdapterFunction = fn() -> Result<String, String>;

#[derive(Clone, Copy)]
struct RegisteredAdapter {
    harness: RegexAutomataHarnessKind,
    case_id: &'static str,
    run: AdapterFunction,
}

// Source workers add narrowly reviewed registrations only after implementing
// a faithful adapter for an assigned upstream member. Keeping this empty is a
// deliberate zero-fake-pass baseline.
const REGISTERED_ADAPTERS: &[RegisteredAdapter] = &[];

/// Execute every registered adapter and retain every unregistered obligation
/// as unsupported.
pub fn build_regex_automata_adapter_report(
    inventory: &RegexAutomataCorpusReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    build_adapter_report_with_registry(inventory, candidate, REGISTERED_ADAPTERS)
}

fn build_adapter_report_with_registry(
    inventory: &RegexAutomataCorpusReport,
    candidate: CandidateIdentity,
    registry: &[RegisteredAdapter],
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    inventory.validate()?;
    validate_candidate(&candidate)?;
    let inventory_identities = inventory
        .payload
        .obligations
        .iter()
        .map(obligation_identity)
        .collect::<BTreeSet<_>>();
    let mut registered = BTreeMap::new();
    for adapter in registry {
        let key = (adapter.harness, adapter.case_id.to_owned());
        if !inventory_identities.contains(&key) || registered.insert(key, adapter.run).is_some() {
            return Err(InventoryError::new(
                "regex-automata adapter registry has a foreign or duplicate identity",
            ));
        }
    }
    let mut outcomes = BTreeMap::new();
    for (identity, run) in registered {
        let disposition = match catch_unwind(AssertUnwindSafe(run)) {
            Ok(Ok(transcript)) => {
                if !bounded_text(&transcript, 4096) {
                    return Err(InventoryError::new(
                        "regex-automata adapter transcript is invalid",
                    ));
                }
                let evidence = Evidence {
                    harness: identity.0,
                    case_id: identity.1.clone(),
                    transcript,
                };
                RegexAutomataAdapterDisposition::Pass {
                    evidence_sha256: hash_json(&evidence, "encode adapter evidence")?,
                }
            }
            Ok(Err(reason)) => RegexAutomataAdapterDisposition::Fault {
                stage: "adapter".to_owned(),
                reason_code: normalized_reason(&reason),
            },
            Err(_) => RegexAutomataAdapterDisposition::Fault {
                stage: "adapter".to_owned(),
                reason_code: "adapter-panic".to_owned(),
            },
        };
        outcomes.insert(identity, disposition);
    }
    let receipts = inventory
        .payload
        .obligations
        .iter()
        .map(|obligation| RegexAutomataAdapterReceipt {
            mode_id: obligation.mode_id.clone(),
            harness: obligation.harness,
            case_id: obligation.case_id.clone(),
            disposition: outcomes
                .get(&obligation_identity(obligation))
                .cloned()
                .unwrap_or_else(|| RegexAutomataAdapterDisposition::Unsupported {
                    reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
                }),
        })
        .collect::<Vec<_>>();
    let counts = adapter_counts(&receipts);
    let payload = RegexAutomataAdapterReportPayload {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        candidate,
        counts,
        receipts,
        limitations: REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode regex-automata adapter payload")?,
        payload,
    };
    report.validate(inventory)?;
    Ok(report)
}

/// Deterministically select the first pending family and a bounded slice of
/// unique cases. All memberships for each selected case travel together.
pub fn schedule_regex_automata_gap(
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
    attempt_id: &str,
    slot: usize,
) -> Result<RegexAutomataGapAssignment, InventoryError> {
    inventory.validate()?;
    baseline.validate(inventory)?;
    if !token(attempt_id) || slot > 255 {
        return Err(InventoryError::new(
            "invalid regex-automata assignment identity",
        ));
    }
    let clusters = pending_clusters(baseline)?;
    let (family, mut targets) = clusters
        .into_iter()
        .next()
        .ok_or_else(|| InventoryError::new("regex-automata package suite is complete"))?;
    targets.truncate(ASSIGNMENT_TARGET_LIMIT);
    let targets_sha256 = hash_json(&targets, "encode regex-automata gap targets")?;
    let assignment = RegexAutomataGapAssignment {
        schema: REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA.to_owned(),
        attempt_id: attempt_id.to_owned(),
        slot,
        base: baseline.payload.candidate.revision.clone(),
        baseline_report_sha256: hash_json(baseline, "encode baseline report")?,
        baseline_payload_sha256: baseline.payload_sha256.clone(),
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        family,
        targets,
        targets_sha256,
    };
    assignment.validate(inventory, baseline)?;
    Ok(assignment)
}

/// Require an exact-denominator, no-regression gain inside the assigned
/// cluster. Unassigned dispositions are immutable.
pub fn validate_regex_automata_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
    assignment: &RegexAutomataGapAssignment,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    inventory.validate()?;
    previous.validate(inventory)?;
    current.validate(inventory)?;
    assignment.validate(inventory, previous)?;
    if previous.payload.candidate.revision == current.payload.candidate.revision
        || previous.payload.candidate.tree == current.payload.candidate.tree
    {
        return Err(InventoryError::new(
            "regex-automata strict gain lacks a distinct candidate commit/tree",
        ));
    }
    let assigned = assignment
        .targets
        .iter()
        .map(|target| (target.harness, target.case_id.clone()))
        .collect::<BTreeSet<_>>();
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &assigned,
    )?;
    if current.payload.counts.fault != 0 {
        return Err(InventoryError::new(
            "regex-automata candidate strict gain contains a fault",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: assignment.family.clone(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: previous.payload.counts.pass,
        current_pass: current.payload.counts.pass,
    })
}

impl RegexAutomataAdapterReport {
    /// Validate the full inventory identity, candidate identity, exact receipt
    /// order, per-case consistency, counts and payload seal.
    pub fn validate(&self, inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
        inventory.validate()?;
        if self.schema != REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
            || self.payload_sha256
                != hash_json(&self.payload, "encode regex-automata adapter payload")?
            || self.payload.inventory_payload_sha256 != inventory.payload_sha256
            || self.payload.obligation_inventory_sha256
                != inventory.payload.harness.obligation_inventory_sha256
            || self.payload.limitations
                != REPORT_LIMITATIONS
                    .iter()
                    .map(|text| (*text).to_owned())
                    .collect::<Vec<_>>()
        {
            return Err(InventoryError::new(
                "regex-automata adapter report identity mismatch",
            ));
        }
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != inventory.payload.obligations.len() {
            return Err(InventoryError::new(
                "regex-automata adapter receipt denominator mismatch",
            ));
        }
        let mut per_case = BTreeMap::new();
        for (receipt, obligation) in self
            .payload
            .receipts
            .iter()
            .zip(&inventory.payload.obligations)
        {
            if receipt.mode_id != obligation.mode_id
                || receipt.harness != obligation.harness
                || receipt.case_id != obligation.case_id
            {
                return Err(InventoryError::new(
                    "regex-automata adapter receipt identity/order mismatch",
                ));
            }
            validate_disposition(&receipt.disposition)?;
            let key = (receipt.harness, receipt.case_id.clone());
            if let Some(prior) = per_case.insert(key, receipt.disposition.clone())
                && prior != receipt.disposition
            {
                return Err(InventoryError::new(
                    "regex-automata adapter disagrees across feature modes",
                ));
            }
        }
        if self.payload.counts != adapter_counts(&self.payload.receipts) {
            return Err(InventoryError::new(
                "regex-automata adapter disposition counts mismatch",
            ));
        }
        Ok(())
    }
}

impl RegexAutomataGapAssignment {
    /// Validate that this assignment is the exact deterministic current
    /// cluster derived from its bound complete baseline report.
    pub fn validate(
        &self,
        inventory: &RegexAutomataCorpusReport,
        baseline: &RegexAutomataAdapterReport,
    ) -> Result<(), InventoryError> {
        inventory.validate()?;
        baseline.validate(inventory)?;
        if self.schema != REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA
            || !token(&self.attempt_id)
            || self.slot > 255
            || self.base != baseline.payload.candidate.revision
            || self.baseline_report_sha256 != hash_json(baseline, "encode baseline report")?
            || self.baseline_payload_sha256 != baseline.payload_sha256
            || self.inventory_payload_sha256 != inventory.payload_sha256
            || self.obligation_inventory_sha256
                != inventory.payload.harness.obligation_inventory_sha256
            || self.targets.is_empty()
            || self.targets.len() > ASSIGNMENT_TARGET_LIMIT
            || self.targets.windows(2).any(|pair| pair[0] >= pair[1])
            || self.targets_sha256 != hash_json(&self.targets, "encode regex-automata gap targets")?
        {
            return Err(InventoryError::new(
                "invalid regex-automata gap assignment identity",
            ));
        }
        let clusters = pending_clusters(baseline)?;
        let (family, mut expected) = clusters
            .into_iter()
            .next()
            .ok_or_else(|| InventoryError::new("assignment baseline has no pending cases"))?;
        expected.truncate(ASSIGNMENT_TARGET_LIMIT);
        if self.family != family || self.targets != expected {
            return Err(InventoryError::new(
                "regex-automata assignment is not the next exact pending cluster",
            ));
        }
        Ok(())
    }
}

/// Read and validate a complete adapter report.
pub fn read_regex_automata_adapter_report(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let bytes = read_owned_regular(path)?;
    let report = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode regex-automata adapter report: {error}"))
    })?;
    RegexAutomataAdapterReport::validate(&report, inventory)?;
    Ok(report)
}

/// Read and validate an assignment against its complete baseline.
pub fn read_regex_automata_gap_assignment(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataGapAssignment, InventoryError> {
    let bytes = read_owned_regular(path)?;
    let assignment = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode regex-automata gap assignment: {error}"))
    })?;
    RegexAutomataGapAssignment::validate(&assignment, inventory, baseline)?;
    Ok(assignment)
}

/// Atomically publish a complete report without replacing evidence.
pub fn write_regex_automata_adapter_report(
    path: &Path,
    report: &RegexAutomataAdapterReport,
    inventory: &RegexAutomataCorpusReport,
) -> Result<(), InventoryError> {
    report.validate(inventory)?;
    write_new_json(path, report)
}

/// Atomically publish one assignment without replacement.
pub fn write_regex_automata_gap_assignment(
    path: &Path,
    assignment: &RegexAutomataGapAssignment,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    assignment.validate(inventory, baseline)?;
    write_new_json(path, assignment)
}

fn pending_clusters(
    report: &RegexAutomataAdapterReport,
) -> Result<BTreeMap<String, Vec<RegexAutomataGapTarget>>, InventoryError> {
    let mut cases: BTreeMap<
        (RegexAutomataHarnessKind, String),
        (RegexAutomataAdapterDisposition, BTreeSet<String>),
    > = BTreeMap::new();
    for receipt in &report.payload.receipts {
        let entry = cases
            .entry((receipt.harness, receipt.case_id.clone()))
            .or_insert_with(|| (receipt.disposition.clone(), BTreeSet::new()));
        if entry.0 != receipt.disposition || !entry.1.insert(receipt.mode_id.clone()) {
            return Err(InventoryError::new(
                "regex-automata report has inconsistent or duplicate memberships",
            ));
        }
    }
    let mut clusters: BTreeMap<String, Vec<RegexAutomataGapTarget>> = BTreeMap::new();
    for ((harness, case_id), (disposition, mode_ids)) in cases {
        if !matches!(
            disposition,
            RegexAutomataAdapterDisposition::Unsupported { .. }
        ) {
            continue;
        }
        let family = case_family(harness, &case_id)?;
        clusters
            .entry(family)
            .or_default()
            .push(RegexAutomataGapTarget {
                harness,
                case_id,
                mode_ids: mode_ids.into_iter().collect(),
            });
    }
    Ok(clusters)
}

fn case_family(harness: RegexAutomataHarnessKind, case_id: &str) -> Result<String, InventoryError> {
    let component = match harness {
        RegexAutomataHarnessKind::Unit | RegexAutomataHarnessKind::Integration => {
            case_id.split("::").next()
        }
        RegexAutomataHarnessKind::Doctest => case_id
            .strip_prefix("src/")
            .and_then(|rest| rest.split(" - ").next())
            .and_then(|source_path| source_path.split('/').next())
            .map(|component| component.strip_suffix(".rs").unwrap_or(component)),
    }
    .ok_or_else(|| InventoryError::new("cannot classify regex-automata case family"))?;
    if component.is_empty()
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(InventoryError::new(
            "invalid regex-automata family component",
        ));
    }
    let harness = match harness {
        RegexAutomataHarnessKind::Unit => "unit",
        RegexAutomataHarnessKind::Integration => "integration",
        RegexAutomataHarnessKind::Doctest => "doctest",
    };
    Ok(format!("{harness}-{component}"))
}

fn obligation_identity(obligation: &RegexAutomataObligation) -> (RegexAutomataHarnessKind, String) {
    (obligation.harness, obligation.case_id.clone())
}

fn adapter_counts(receipts: &[RegexAutomataAdapterReceipt]) -> RegexAutomataAdapterCounts {
    RegexAutomataAdapterCounts {
        pass: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Pass { .. }
                )
            })
            .count(),
        unsupported: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Unsupported { .. }
                )
            })
            .count(),
        fault: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Fault { .. }
                )
            })
            .count(),
        total: receipts.len(),
    }
}

fn validate_disposition(
    disposition: &RegexAutomataAdapterDisposition,
) -> Result<(), InventoryError> {
    match disposition {
        RegexAutomataAdapterDisposition::Pass { evidence_sha256 } => {
            if !hex(evidence_sha256, 64) {
                return Err(InventoryError::new("invalid regex-automata pass evidence"));
            }
        }
        RegexAutomataAdapterDisposition::Unsupported { reason_code } => {
            if reason_code != INVENTORY_UNSUPPORTED_REASON {
                return Err(InventoryError::new(
                    "invalid regex-automata unsupported reason",
                ));
            }
        }
        RegexAutomataAdapterDisposition::Fault { stage, reason_code } => {
            if !token(stage) || !token(reason_code) {
                return Err(InventoryError::new("invalid regex-automata fault"));
            }
        }
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !hex(&candidate.revision, 40)
        || !hex(&candidate.tree, 40)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "invalid regex-automata candidate identity",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct Evidence {
    harness: RegexAutomataHarnessKind,
    case_id: String,
    transcript: String,
}

fn normalized_reason(reason: &str) -> String {
    let normalized = reason
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || byte == b'-' {
                char::from(byte.to_ascii_lowercase())
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('-');
    if token(normalized) {
        normalized.to_owned()
    } else {
        "adapter-error".to_owned()
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains('\0')
        && !value.contains('\r')
        && value
            .chars()
            .all(|character| character == '\n' || !character.is_control())
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_json(value: &impl Serialize, context: &str) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("{context}: {error}")))
}

fn read_owned_regular(path: &Path) -> Result<Vec<u8>, InventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.len() > 8 * 1_048_576
    {
        return Err(InventoryError::new(
            "unsafe regex-automata progress artifact",
        ));
    }
    fs::read(path).map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<(), InventoryError> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "output exists: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new("output has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", parent.display())))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe_free_euid()
    {
        return Err(InventoryError::new("unsafe progress output directory"));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InventoryError::new("invalid progress output name"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create output: {error}")))?;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| InventoryError::new(format!("encode output: {error}")))?;
    bytes.push(b'\n');
    let result = (|| {
        output
            .write_all(&bytes)
            .map_err(|error| InventoryError::new(format!("write output: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync output: {error}")))?;
        fs::hard_link(&temporary, path)
            .map_err(|error| InventoryError::new(format!("install output: {error}")))?;
        fs::remove_file(&temporary)
            .map_err(|error| InventoryError::new(format!("remove temporary: {error}")))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn unsafe_free_euid() -> u32 {
    static EUID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *EUID.get_or_init(|| {
        std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .env_clear()
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                std::str::from_utf8(&output.stdout)
                    .ok()?
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(u32::MAX)
    })
}

fn gain_vectors(
    previous: &[RegexAutomataAdapterReceipt],
    current: &[RegexAutomataAdapterReceipt],
    assigned: &BTreeSet<(RegexAutomataHarnessKind, String)>,
) -> Result<(usize, usize), InventoryError> {
    if previous.len() != current.len() {
        return Err(InventoryError::new("strict-gain denominator changed"));
    }
    let mut unique = BTreeSet::new();
    let mut memberships = 0_usize;
    for (old, new) in previous.iter().zip(current) {
        if (old.mode_id.as_str(), old.harness, old.case_id.as_str())
            != (new.mode_id.as_str(), new.harness, new.case_id.as_str())
        {
            return Err(InventoryError::new("strict-gain receipt identity changed"));
        }
        let identity = (old.harness, old.case_id.clone());
        let old_pass = matches!(
            old.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        );
        let new_pass = matches!(
            new.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        );
        if old_pass && !new_pass {
            return Err(InventoryError::new("strict-gain pass loss"));
        }
        if !assigned.contains(&identity) && old.disposition != new.disposition {
            return Err(InventoryError::new("strict-gain unassigned change"));
        }
        if assigned.contains(&identity) && !old_pass && new_pass {
            unique.insert(identity);
            memberships = memberships
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("strict-gain count overflow"))?;
        }
    }
    if unique.is_empty() {
        return Err(InventoryError::new("strict-gain has no assigned gain"));
    }
    Ok((unique.len(), memberships))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(revision: char, tree: char) -> CandidateIdentity {
        CandidateIdentity {
            revision: revision.to_string().repeat(40),
            tree: tree.to_string().repeat(40),
            tracked_and_untracked_worktree_clean: true,
        }
    }

    fn receipt(
        mode: &str,
        case: &str,
        disposition: RegexAutomataAdapterDisposition,
    ) -> RegexAutomataAdapterReceipt {
        RegexAutomataAdapterReceipt {
            mode_id: mode.to_owned(),
            harness: RegexAutomataHarnessKind::Unit,
            case_id: case.to_owned(),
            disposition,
        }
    }

    #[test]
    fn strict_gain_rejects_unassigned_change_and_pass_loss() {
        let unsupported = RegexAutomataAdapterDisposition::Unsupported {
            reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
        };
        let pass = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: "a".repeat(64),
        };
        let old = vec![
            receipt("m0", "dfa::a", unsupported.clone()),
            receipt("m0", "nfa::b", pass.clone()),
        ];
        let mut current = old.clone();
        current[0].disposition = pass.clone();
        let assigned = BTreeSet::from([(RegexAutomataHarnessKind::Unit, "dfa::a".to_owned())]);
        assert_eq!(gain_vectors(&old, &current, &assigned).unwrap(), (1, 1));
        let mut foreign = current.clone();
        foreign[1].disposition = unsupported.clone();
        assert!(gain_vectors(&old, &foreign, &assigned).is_err());
        let mut unassigned = old.clone();
        unassigned[1].disposition = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: "b".repeat(64),
        };
        assert!(gain_vectors(&old, &unassigned, &assigned).is_err());
    }

    #[test]
    fn scheduler_family_and_case_memberships_are_deterministic() {
        assert_eq!(
            case_family(RegexAutomataHarnessKind::Unit, "dfa::dense::roundtrip").unwrap(),
            "unit-dfa",
        );
        assert_eq!(
            case_family(
                RegexAutomataHarnessKind::Doctest,
                "src/meta/regex.rs - meta::Regex (line 10)",
            )
            .unwrap(),
            "doctest-meta",
        );
        assert_eq!(
            case_family(RegexAutomataHarnessKind::Doctest, "src/lib.rs - (line 124)").unwrap(),
            "doctest-lib",
        );
        assert!(case_family(RegexAutomataHarnessKind::Unit, "bad family::x").is_err());
        assert!(validate_candidate(&candidate('a', 'b')).is_ok());
        assert!(validate_candidate(&candidate('g', 'b')).is_err());
    }
}
