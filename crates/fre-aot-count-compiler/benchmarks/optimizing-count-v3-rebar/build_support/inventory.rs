use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INVENTORY_SCHEMA: &str = "fre.optimizing-count-v3.inventory.v1";
pub const ARTIFACT_SCHEMA: &str = "fre.optimizing-count-v3.artifact-input.v1";
pub const DECISION_SCHEMA: &str = "fre.optimizing-count-v3.selector-decision.v1";
pub const INPUT_POLICY: &str = "pattern-semantic-options-target-only-v1";
pub const SEMANTIC_PROFILE: &str = concat!(
    "rust-regex-1.12.4-rebar-bytes-case-sensitive-",
    "candidate-proven-exact-byte-equivalence-",
    "whole-haystack-nonoverlapping-count-v1"
);
pub const MAX_INVENTORY_ROWS: usize = 16_384;
pub const MAX_CELLS: usize = 4_096;

const SEMANTIC_OPTIONS_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-SEMANTIC-OPTIONS\0\x01";
const ARTIFACT_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-ARTIFACT\0\x01";
const PATTERN_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-PATTERN\0\x01";
const INVENTORY_ID_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-INVENTORY\0\x01";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorDecision {
    pub schema: String,
    pub job_id: String,
    pub rebar_job_id: String,
    pub selected: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInput {
    pub schema: String,
    pub pattern_input_id: String,
    pub input_policy: String,
    pub pattern_sha256: String,
    pub source_pattern_sha256: String,
    pub unicode: bool,
    pub semantic_options_sha256: String,
    pub pattern_semantics_identity: String,
    pub transformed_pattern: String,
    pub literal_hex: String,
    pub literal_sha256: String,
    pub literal_bytes: usize,
    pub semantic_binding_identity: String,
    pub planning_receipt_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub cell_id: String,
    pub job_id: String,
    pub family_id: String,
    pub exact_literal_cluster_seed: String,
    pub pattern_input_id: String,
    pub pattern_sha256: String,
    pub pattern_len: usize,
    pub input_sha256: String,
    pub input_bytes: usize,
    pub expected_count: u64,
    pub oracle_receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
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
    pub decisions: Vec<SelectorDecision>,
    pub artifacts: Vec<ArtifactInput>,
    pub cells: Vec<Cell>,
}

/// Pattern-only compiler input. It is deliberately impossible to represent
/// cell, job, haystack, oracle, partition, or timing attribution here.
#[derive(Clone, Debug)]
pub struct CompilerArtifactInput {
    pub canonical_bytes: Vec<u8>,
    pub pattern_input_id: String,
    pub pattern_sha256: [u8; 32],
    pub source_pattern_sha256: [u8; 32],
    pub unicode: bool,
    pub semantic_options_sha256: [u8; 32],
    pub pattern_semantics_identity: [u8; 32],
    pub transformed_pattern: String,
    pub authenticated_literal: Vec<u8>,
    pub literal_sha256: [u8; 32],
    pub semantic_binding_identity: [u8; 32],
    pub planning_receipt_identity: [u8; 32],
}

impl CompilerArtifactInput {
    pub fn from_authenticated(row: &ArtifactInput) -> Result<Self, String> {
        Ok(Self {
            canonical_bytes: serde_json::to_vec(row)
                .map_err(|error| format!("serialize artifact input: {error}"))?,
            pattern_input_id: row.pattern_input_id.clone(),
            pattern_sha256: parse_hex_32(&row.pattern_sha256, "artifact pattern SHA-256")?,
            source_pattern_sha256: parse_hex_32(
                &row.source_pattern_sha256,
                "artifact source-pattern SHA-256",
            )?,
            unicode: row.unicode,
            semantic_options_sha256: parse_hex_32(
                &row.semantic_options_sha256,
                "artifact semantic-options SHA-256",
            )?,
            pattern_semantics_identity: parse_hex_32(
                &row.pattern_semantics_identity,
                "artifact pattern-semantics identity",
            )?,
            transformed_pattern: row.transformed_pattern.clone(),
            authenticated_literal: decode_lower_hex(&row.literal_hex, "artifact literal")?,
            literal_sha256: parse_hex_32(&row.literal_sha256, "artifact literal SHA-256")?,
            semantic_binding_identity: parse_hex_32(
                &row.semantic_binding_identity,
                "artifact semantic-binding identity",
            )?,
            planning_receipt_identity: parse_hex_32(
                &row.planning_receipt_identity,
                "artifact planning-receipt identity",
            )?,
        })
    }
}

pub fn parse_and_validate(bytes: &[u8]) -> Result<Inventory, String> {
    if bytes.is_empty() || bytes.len() > 64 * 1_048_576 {
        return Err("inventory byte length is outside (0, 64 MiB]".to_string());
    }
    if bytes.contains(&0) || bytes.contains(&b'\r') {
        return Err("inventory contains NUL or CR".to_string());
    }
    let inventory: Inventory =
        serde_json::from_slice(bytes).map_err(|error| format!("decode inventory: {error}"))?;
    validate(&inventory)?;
    Ok(inventory)
}

fn validate(inventory: &Inventory) -> Result<(), String> {
    if inventory.schema != INVENTORY_SCHEMA {
        return Err(format!("unexpected inventory schema {}", inventory.schema));
    }
    for (label, value) in [
        ("inventory identity", inventory.inventory_identity.as_str()),
        ("manifest SHA-256", inventory.manifest_sha256.as_str()),
        (
            "semantic report SHA-256",
            inventory.semantic_report_sha256.as_str(),
        ),
        (
            "selector policy SHA-256",
            inventory.selector_policy_sha256.as_str(),
        ),
        (
            "semantic options SHA-256",
            inventory.semantic_options_sha256.as_str(),
        ),
    ] {
        require_hex(value, 64, label)?;
    }
    require_hex(&inventory.rebar_revision, 40, "Rebar revision")?;
    if inventory.semantic_profile != SEMANTIC_PROFILE {
        return Err(format!(
            "unexpected semantic profile {}",
            inventory.semantic_profile
        ));
    }
    let expected_semantic_options = hex(&digest_fields(
        SEMANTIC_OPTIONS_DOMAIN,
        &[SEMANTIC_PROFILE.as_bytes()],
    ));
    if inventory.semantic_options_sha256 != expected_semantic_options {
        return Err(format!(
            "semantic-options SHA-256 differs: derived {expected_semantic_options}, embedded {}",
            inventory.semantic_options_sha256
        ));
    }
    if inventory.input_policy != INPUT_POLICY {
        return Err(format!(
            "unexpected inventory input policy {}",
            inventory.input_policy
        ));
    }
    if inventory.manifest_jobs == 0
        || inventory.manifest_jobs > MAX_INVENTORY_ROWS
        || inventory.decisions.len() != inventory.manifest_jobs
    {
        return Err("inventory decision count does not close manifest_jobs".to_string());
    }
    if inventory.selected_cells == 0
        || inventory.selected_cells > MAX_CELLS
        || inventory.cells.len() != inventory.selected_cells
    {
        return Err("inventory cell count does not close selected_cells".to_string());
    }
    if inventory.distinct_artifacts == 0
        || inventory.distinct_artifacts > MAX_CELLS
        || inventory.artifacts.len() != inventory.distinct_artifacts
    {
        return Err("inventory artifact count does not close distinct_artifacts".to_string());
    }

    let mut decision_ids = BTreeSet::new();
    let mut selected_jobs = BTreeSet::new();
    let mut previous = "";
    for decision in &inventory.decisions {
        if decision.schema != DECISION_SCHEMA {
            return Err("unexpected selector-decision schema".to_string());
        }
        require_safe_id(&decision.job_id, "selector job ID")?;
        require_text(&decision.rebar_job_id, "Rebar job ID")?;
        require_safe_id(&decision.reason, "selector reason")?;
        if decision.job_id.as_str() <= previous || !decision_ids.insert(decision.job_id.as_str()) {
            return Err("selector decisions are not sorted unique by job_id".to_string());
        }
        previous = &decision.job_id;
        if decision.selected {
            if decision.reason != "eligible" {
                return Err("selected decision is not eligible".to_string());
            }
            selected_jobs.insert(decision.job_id.as_str());
        } else if decision.reason == "eligible" {
            return Err("unselected decision is tagged eligible".to_string());
        }
    }

    let mut artifact_index = BTreeMap::new();
    let mut source_variants = BTreeMap::new();
    let mut previous = "";
    for artifact in &inventory.artifacts {
        validate_artifact(artifact, inventory)?;
        if artifact.pattern_input_id.as_str() <= previous
            || artifact_index
                .insert(artifact.pattern_input_id.as_str(), artifact)
                .is_some()
        {
            return Err("artifacts are not sorted unique by pattern_input_id".to_string());
        }
        previous = &artifact.pattern_input_id;
        let source_key = (artifact.source_pattern_sha256.as_str(), artifact.unicode);
        let source_projection = (
            artifact.transformed_pattern.as_str(),
            artifact.literal_hex.as_str(),
        );
        if let Some(prior) = source_variants.insert(source_key, source_projection) {
            if prior != source_projection {
                return Err(
                    "one source-pattern semantic variant has inconsistent projections".to_string(),
                );
            }
        }
    }

    let mut cell_ids = BTreeSet::new();
    let mut cell_jobs = BTreeSet::new();
    let mut used_artifacts = BTreeSet::new();
    let mut previous = "";
    for cell in &inventory.cells {
        for (label, value) in [
            ("cell ID", cell.cell_id.as_str()),
            ("cell job ID", cell.job_id.as_str()),
            ("cell family ID", cell.family_id.as_str()),
            (
                "cell exact-literal cluster seed",
                cell.exact_literal_cluster_seed.as_str(),
            ),
            ("cell pattern-input ID", cell.pattern_input_id.as_str()),
        ] {
            require_safe_id(value, label)?;
        }
        for (label, value) in [
            ("cell pattern SHA-256", cell.pattern_sha256.as_str()),
            ("cell input SHA-256", cell.input_sha256.as_str()),
            (
                "cell oracle-receipt SHA-256",
                cell.oracle_receipt_sha256.as_str(),
            ),
        ] {
            require_hex(value, 64, label)?;
        }
        if cell.cell_id.as_str() <= previous || !cell_ids.insert(cell.cell_id.as_str()) {
            return Err("cells are not sorted unique by cell_id".to_string());
        }
        previous = &cell.cell_id;
        if !cell_jobs.insert(cell.job_id.as_str()) {
            return Err("inventory has duplicate selected job IDs".to_string());
        }
        let artifact = artifact_index
            .get(cell.pattern_input_id.as_str())
            .ok_or_else(|| format!("cell {} refers to an unknown artifact", cell.cell_id))?;
        if cell.pattern_sha256 != artifact.pattern_sha256
            || cell.pattern_len != artifact.literal_bytes
        {
            return Err(format!(
                "cell {} pattern projection differs from its artifact",
                cell.cell_id
            ));
        }
        if cell.input_bytes == 0 || cell.input_bytes > (1_usize << 40) {
            return Err(format!(
                "cell {} input byte length is invalid",
                cell.cell_id
            ));
        }
        if cell.pattern_len == 0
            || cell.pattern_len > 32
            || u128::from(cell.expected_count)
                > u128::try_from(cell.input_bytes / cell.pattern_len).unwrap_or(u128::MAX)
        {
            return Err(format!(
                "cell {} expected count is impossible",
                cell.cell_id
            ));
        }
        used_artifacts.insert(cell.pattern_input_id.as_str());
    }
    if cell_jobs != selected_jobs {
        return Err("selected decisions and cells do not close".to_string());
    }
    if used_artifacts != artifact_index.keys().copied().collect() {
        return Err("inventory contains an unused or missing artifact".to_string());
    }
    let derived = inventory_identity(inventory)?;
    if derived != inventory.inventory_identity {
        return Err(format!(
            "inventory identity differs: derived {derived}, embedded {}",
            inventory.inventory_identity
        ));
    }
    Ok(())
}

fn validate_artifact(artifact: &ArtifactInput, inventory: &Inventory) -> Result<(), String> {
    if artifact.schema != ARTIFACT_SCHEMA {
        return Err(format!(
            "artifact {} has unexpected schema",
            artifact.pattern_input_id
        ));
    }
    require_safe_id(&artifact.pattern_input_id, "pattern-input ID")?;
    if artifact.input_policy != INPUT_POLICY {
        return Err(format!(
            "artifact {} has unexpected input policy",
            artifact.pattern_input_id
        ));
    }
    for (label, value) in [
        ("artifact pattern SHA-256", artifact.pattern_sha256.as_str()),
        (
            "artifact source-pattern SHA-256",
            artifact.source_pattern_sha256.as_str(),
        ),
        (
            "artifact semantic-options SHA-256",
            artifact.semantic_options_sha256.as_str(),
        ),
        (
            "artifact pattern-semantics identity",
            artifact.pattern_semantics_identity.as_str(),
        ),
        ("artifact literal SHA-256", artifact.literal_sha256.as_str()),
        (
            "artifact semantic-binding identity",
            artifact.semantic_binding_identity.as_str(),
        ),
        (
            "artifact planning-receipt identity",
            artifact.planning_receipt_identity.as_str(),
        ),
    ] {
        require_hex(value, 64, label)?;
    }
    if artifact.semantic_options_sha256 != inventory.semantic_options_sha256 {
        return Err(format!(
            "artifact {} semantic options differ from inventory",
            artifact.pattern_input_id
        ));
    }
    if artifact.transformed_pattern.contains(['\0', '\r']) {
        return Err(format!(
            "artifact {} transformed pattern contains a forbidden character",
            artifact.pattern_input_id
        ));
    }
    let literal = decode_lower_hex(&artifact.literal_hex, "artifact literal")?;
    if artifact.literal_bytes == 0
        || artifact.literal_bytes > 32
        || literal.len() != artifact.literal_bytes
    {
        return Err(format!(
            "artifact {} literal width is invalid",
            artifact.pattern_input_id
        ));
    }
    if hex(&Sha256::digest(&literal)) != artifact.literal_sha256 {
        return Err(format!(
            "artifact {} literal SHA-256 differs",
            artifact.pattern_input_id
        ));
    }
    let expected_pattern =
        qualified_pattern_identity(&artifact.source_pattern_sha256, artifact.unicode);
    if expected_pattern != artifact.pattern_sha256 {
        return Err(format!(
            "artifact {} qualified pattern identity differs",
            artifact.pattern_input_id
        ));
    }
    let expected_semantics =
        pattern_semantics_identity(&artifact.pattern_sha256, &artifact.semantic_options_sha256);
    if artifact.pattern_semantics_identity != expected_semantics
        || artifact.pattern_input_id != format!("pattern-{expected_semantics}")
    {
        return Err(format!(
            "artifact {} pattern/semantics identity differs",
            artifact.pattern_input_id
        ));
    }
    Ok(())
}

fn inventory_identity(inventory: &Inventory) -> Result<String, String> {
    let decisions = serde_json::to_vec(&inventory.decisions)
        .map_err(|error| format!("serialize decisions for identity: {error}"))?;
    let artifacts = serde_json::to_vec(&inventory.artifacts)
        .map_err(|error| format!("serialize artifacts for identity: {error}"))?;
    let cells = serde_json::to_vec(&inventory.cells)
        .map_err(|error| format!("serialize cells for identity: {error}"))?;
    Ok(hex(&digest_fields(
        INVENTORY_ID_DOMAIN,
        &[
            inventory.manifest_sha256.as_bytes(),
            inventory.semantic_report_sha256.as_bytes(),
            inventory.selector_policy_sha256.as_bytes(),
            inventory.semantic_options_sha256.as_bytes(),
            &decisions,
            &artifacts,
            &cells,
        ],
    )))
}

fn qualified_pattern_identity(source_sha256: &str, unicode: bool) -> String {
    hex(&digest_fields(
        PATTERN_ID_DOMAIN,
        &[source_sha256.as_bytes(), &[u8::from(unicode)], &[0]],
    ))
}

fn pattern_semantics_identity(pattern_sha256: &str, semantic_sha256: &str) -> String {
    hex(&digest_fields(
        ARTIFACT_ID_DOMAIN,
        &[
            b"fre.optimizing-count-v3.pattern-semantics.v1",
            pattern_sha256.as_bytes(),
            semantic_sha256.as_bytes(),
        ],
    ))
}

pub fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

pub fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    require_hex(value, 64, label)?;
    let bytes = decode_lower_hex(value, label)?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} did not decode to 32 bytes"))
}

pub fn decode_lower_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not nonempty canonical lowercase hex"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("noncanonical hex nibble".to_string()),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn require_hex(value: &str, digits: usize, label: &str) -> Result<(), String> {
    if value.len() != digits
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(format!(
            "{label} is not canonical {digits}-digit lowercase hex"
        ))
    } else {
        Ok(())
    }
}

fn require_safe_id(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 96
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Err(format!("{label} is not a canonical safe ID"))
    } else {
        Ok(())
    }
}

fn require_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        Err(format!(
            "{label} is empty or contains a forbidden character"
        ))
    } else {
        Ok(())
    }
}
