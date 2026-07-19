//! Authenticated, omission-proof inventory for the exact
//! `regex-automata` 0.4.14 package suite.
//!
//! This module deliberately does not execute FRE. Every discovered harness
//! member is emitted as an unsupported adapter obligation, so an inventory
//! checkpoint cannot be mistaken for a compatibility claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};

use crate::{InventoryError, sha256};

/// Schema for the sealed inventory-only report.
pub const REGEX_AUTOMATA_CORPUS_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.package-corpus-inventory.v1";

const UPSTREAM_REPOSITORY: &str = "https://github.com/rust-lang/regex";
const UPSTREAM_PACKAGE: &str = "regex-automata";
const UPSTREAM_VERSION: &str = "0.4.14";
const UPSTREAM_CRATE_SHA256: &str =
    "6e1dd4122fc1595e8162618945476892eefca7b88c52820e74af6262213cae8f";
const UPSTREAM_CRATE_BYTES: u64 = 618_012;
const UPSTREAM_REVISION: &str = "5e195de266e203441b2c8001d6ebefab1161a59e";
const UPSTREAM_TREE: &str = "96f8bc0c6f171fd7a748199250f776ed40eba5eb";
const UPSTREAM_TESTDATA_TREE: &str = "39b38f805649795a68ad274cf71bae2df0cbb4e6";
const UPSTREAM_TEST_SCRIPT_BLOB: &str = "df3e5ae98dea4762b3f36f1791e8d8c19e039cb8";
const UPSTREAM_TEST_SCRIPT_SHA256: &str =
    "39d79ce3532c31a51c0be89a2939816fad0e4868d2b03992c202cbe64dce9f6c";
const PACKAGE_TREE_INVENTORY_SHA256: &str =
    "ff14aa11ceea9793d936306fab916be7a34c01b5f6a7bf913fdff97cbb5017f1";
const PACKAGE_FILE_COUNT: usize = 105;
const PACKAGE_BYTES: u64 = 2_687_270;
const VCS_MATCHED_FILE_COUNT: usize = 102;
const VCS_SUPPORT_FILE_COUNT: usize = 50;
const VCS_SUPPORT_BYTES: u64 = 272_870;
const VCS_SUPPORT_INVENTORY_SHA256: &str =
    "c2bb5ebb6e45778197cc125620d41f219f47c343385baa3a8aa6d627c6cdcbc8";
const MAX_PACKAGE_FILE_BYTES: u64 = 4 * 1_048_576;
const UNSUPPORTED_REASON: &str = "fre-adapter.regex-automata-member-not-implemented";
const MODE_INVENTORY_SHA256: &str =
    "cde6acd19075477f9d8f1456517d98ed980cef9f09c5d4870b2979712cfdc30a";
const OBLIGATION_INVENTORY_SHA256: &str =
    "a0a791feca9f0b22ac3045a9997a5129d3beed0e772a1dcef73e9bb83fd54a04";
const TOTAL_MODE_MEMBERS: usize = 3_842;
const UNIQUE_UNIT_MEMBERS: usize = 135;
const UNIQUE_INTEGRATION_MEMBERS: usize = 58;
const UNIQUE_DOCTEST_MEMBERS: usize = 461;
const UNIQUE_MEMBERS: usize = 654;
const FEATURE_SCRIPT_MODES: usize = 42;
const SUPPLEMENTAL_DEFAULT_MODES: usize = 3;

// These are parsed from the exact authenticated VCS `regex-automata/test`
// script and then compared with this fixed semantic transcription. Keeping
// both checks means neither a parser bug nor a silent script edit can change
// the denominator.
const VCS_LIB_FEATURES: [&str; 28] = [
    "",
    "unicode-word-boundary",
    "unicode-word-boundary,syntax,unicode-perl",
    "unicode-word-boundary,syntax,dfa-build",
    "nfa",
    "dfa",
    "hybrid",
    "nfa,dfa",
    "nfa,hybrid",
    "dfa,hybrid",
    "dfa-onepass",
    "nfa-pikevm",
    "nfa-backtrack",
    "std",
    "alloc",
    "syntax",
    "syntax,nfa-pikevm",
    "syntax,hybrid",
    "perf-literal-substring",
    "perf-literal-multisubstring",
    "meta",
    "meta,nfa-backtrack",
    "meta,hybrid",
    "meta,dfa-build",
    "meta,dfa-onepass",
    "meta,nfa,dfa,hybrid,nfa-backtrack",
    "meta,nfa,dfa,hybrid,nfa-backtrack,perf-literal-substring",
    "meta,nfa,dfa,hybrid,nfa-backtrack,perf-literal-multisubstring",
];

const VCS_INTEGRATION_FEATURES: [&str; 11] = [
    "std,unicode,syntax,nfa-pikevm",
    "std,unicode,syntax,nfa-backtrack",
    "std,unicode,syntax,hybrid",
    "std,unicode,syntax,dfa-onepass",
    "std,unicode,syntax,dfa-search",
    "std,unicode,syntax,dfa-build",
    "std,unicode,meta",
    "std,unicode,meta,hybrid",
    "std,unicode,meta,dfa-onepass",
    "std,unicode,meta,dfa-build",
    "std,unicode,meta,nfa,dfa-onepass,hybrid",
];

/// One byte-authenticated file in the crates.io package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataPackageFile {
    pub path: String,
    pub mode: String,
    pub bytes: u64,
    pub sha256: String,
    pub vcs_path: Option<String>,
    pub vcs_blob: Option<String>,
}

/// Exact VCS-only bytes required to compile the package's integration
/// harness but intentionally excluded from the crates.io archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataVcsSupportFile {
    pub path: String,
    pub vcs_blob: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Immutable crates.io and VCS identity used by the inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub crates_io_archive_sha256: String,
    pub crates_io_archive_bytes: u64,
    pub vcs_revision: String,
    pub vcs_package_tree: String,
    pub vcs_testdata_tree: String,
    pub vcs_test_script_blob: String,
    pub vcs_test_script_sha256: String,
    pub package_tree_inventory_sha256: String,
    pub package_files: usize,
    pub package_bytes: u64,
    pub vcs_matched_files: usize,
    pub files: Vec<RegexAutomataPackageFile>,
    pub vcs_support_inventory_sha256: String,
    pub vcs_support_files: usize,
    pub vcs_support_bytes: u64,
    pub support_files: Vec<RegexAutomataVcsSupportFile>,
}

/// Test harness partition used for one Cargo listing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegexAutomataHarnessKind {
    Unit,
    Integration,
    Doctest,
}

/// One authenticated feature/harness mode and its complete member-list seal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataFeatureMode {
    pub id: String,
    pub harness: RegexAutomataHarnessKind,
    pub default_features: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub members: usize,
    pub member_ids_sha256: String,
}

/// Inventory-only disposition. There is intentionally no pass variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegexAutomataInventoryDisposition {
    Unsupported { reason_code: String },
}

/// One feature-mode member that requires a future FRE adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataObligation {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub disposition: RegexAutomataInventoryDisposition,
}

/// Cardinalities for both feature-mode memberships and unique identities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataInventoryCounts {
    pub feature_modes: usize,
    pub unit_mode_members: usize,
    pub integration_mode_members: usize,
    pub doctest_mode_members: usize,
    pub total_mode_members: usize,
    pub unique_unit_members: usize,
    pub unique_integration_members: usize,
    pub unique_doctest_members: usize,
    pub unique_members: usize,
    pub fre_pass: usize,
    pub unsupported: usize,
}

/// Tool identity for the no-clock Cargo membership listings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataHarnessIdentity {
    pub cargo_release: String,
    pub cargo_executable_sha256: String,
    pub rustc_release: String,
    pub rustc_executable_sha256: String,
    pub feature_script_modes: usize,
    pub supplemental_default_modes: usize,
    pub obligation_inventory_sha256: String,
}

/// Payload covered by `payload_sha256`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataCorpusReportPayload {
    pub source: RegexAutomataSourceIdentity,
    pub harness: RegexAutomataHarnessIdentity,
    pub modes: Vec<RegexAutomataFeatureMode>,
    pub counts: RegexAutomataInventoryCounts,
    pub obligations: Vec<RegexAutomataObligation>,
    pub limitations: Vec<String>,
}

/// Canonical inventory-only report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataCorpusReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexAutomataCorpusReportPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModeSpec {
    id: String,
    harness: RegexAutomataHarnessKind,
    default_features: bool,
    all_features: bool,
    features: Vec<String>,
}

struct VcsAuthentication {
    script: Vec<u8>,
}

const LIMITATIONS: [&str; 3] = [
    "This checkpoint inventories Cargo harness members but deliberately executes neither upstream tests nor FRE adapters.",
    "The denominator is the exact crates.io package plus the exact VCS-only integration fixtures excluded from that archive, under default/all-features and every lib/integration mode transcribed from the authenticated VCS test script.",
    "Platform-conditional membership is the native 64-bit little-endian non-Miri host view; cross-target and Miri inventories require separately labelled reports.",
];

/// Authenticate package/archive/VCS bytes and inventory every fixed harness
/// mode without executing tests.
#[allow(
    clippy::too_many_lines,
    reason = "the source transaction and complete mode listing remain adjacent for auditability"
)]
pub fn build_regex_automata_corpus_report(
    crate_archive: &Path,
    package: &Path,
    vcs_checkout: &Path,
    target_dir: &Path,
) -> Result<RegexAutomataCorpusReport, InventoryError> {
    authenticate_archive(crate_archive)?;
    let vcs = authenticate_vcs(vcs_checkout)?;
    let source = authenticate_package(package, vcs_checkout, true)?;
    let parsed_features = parse_test_script_features(&vcs.script)?;
    if parsed_features.0 != VCS_LIB_FEATURES || parsed_features.1 != VCS_INTEGRATION_FEATURES {
        return Err(InventoryError::new(
            "regex-automata test script feature transcription mismatch",
        ));
    }

    let target_dir = prepare_target_dir(target_dir, &[crate_archive, package, vcs_checkout])?;
    let snapshot_workspace = target_dir.join("upstream-snapshot");
    create_private_directory(&snapshot_workspace)?;
    let snapshot = snapshot_workspace.join("regex-automata");
    create_private_directory(&snapshot)?;
    snapshot_package(package, &snapshot, &source)?;
    snapshot_vcs_support(&snapshot_workspace, vcs_checkout, &source)?;
    validate_execution_snapshot(&snapshot_workspace, &source)?;
    reject_ancestor_cargo_configs(&snapshot)?;
    let cargo_home = resolve_cargo_home()?;
    reject_cargo_home_configs(&cargo_home)?;
    let build_target = target_dir.join("cargo-target");
    create_private_directory(&build_target)?;
    let cargo = resolve_tool("cargo")?;
    let rustc = resolve_tool("rustc")?;
    let cargo_release = tool_release(&cargo, "cargo")?;
    let rustc_release = tool_release(&rustc, "rustc")?;
    let cargo_executable_sha256 = hash_tool(&cargo, "cargo")?;
    let rustc_executable_sha256 = hash_tool(&rustc, "rustc")?;

    let specs = mode_specs();
    let mut modes = Vec::with_capacity(specs.len());
    let mut obligations = Vec::new();
    for spec in &specs {
        let members =
            list_mode_members(&snapshot, &build_target, &cargo_home, &cargo, &rustc, spec)?;
        let member_ids_sha256 = hash_line_list(&members);
        modes.push(RegexAutomataFeatureMode {
            id: spec.id.clone(),
            harness: spec.harness,
            default_features: spec.default_features,
            all_features: spec.all_features,
            features: spec.features.clone(),
            members: members.len(),
            member_ids_sha256,
        });
        obligations.extend(members.into_iter().map(|case_id| RegexAutomataObligation {
            mode_id: spec.id.clone(),
            harness: spec.harness,
            case_id,
            disposition: RegexAutomataInventoryDisposition::Unsupported {
                reason_code: UNSUPPORTED_REASON.to_owned(),
            },
        }));
    }

    authenticate_archive(crate_archive)?;
    if authenticate_vcs(vcs_checkout)?.script != vcs.script
        || authenticate_package(package, vcs_checkout, true)? != source
        || validate_execution_snapshot(&snapshot_workspace, &source).is_err()
        || tool_release(&cargo, "cargo")? != cargo_release
        || tool_release(&rustc, "rustc")? != rustc_release
        || hash_tool(&cargo, "cargo")? != cargo_executable_sha256
        || hash_tool(&rustc, "rustc")? != rustc_executable_sha256
    {
        return Err(InventoryError::new(
            "regex-automata source or harness identity changed during inventory",
        ));
    }
    reject_ancestor_cargo_configs(&snapshot)?;
    reject_cargo_home_configs(&cargo_home)?;

    let counts = counts_for(&modes, &obligations)?;
    let obligation_inventory_sha256 =
        hash_json(&obligations, "encode regex-automata obligation inventory")?;
    let harness = RegexAutomataHarnessIdentity {
        cargo_release,
        cargo_executable_sha256,
        rustc_release,
        rustc_executable_sha256,
        feature_script_modes: FEATURE_SCRIPT_MODES,
        supplemental_default_modes: SUPPLEMENTAL_DEFAULT_MODES,
        obligation_inventory_sha256,
    };
    let payload = RegexAutomataCorpusReportPayload {
        source,
        harness,
        modes,
        counts,
        obligations,
        limitations: LIMITATIONS.iter().map(|text| (*text).to_owned()).collect(),
    };
    let payload_sha256 = hash_json(&payload, "encode regex-automata inventory payload")?;
    let report = RegexAutomataCorpusReport {
        schema: REGEX_AUTOMATA_CORPUS_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and validate a sealed inventory report.
pub fn read_regex_automata_corpus_report(
    path: &Path,
) -> Result<RegexAutomataCorpusReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read regex-automata corpus report {}: {error}",
            path.display()
        ))
    })?;
    let report: RegexAutomataCorpusReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode regex-automata corpus report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically install canonical pretty JSON without replacing prior evidence.
pub fn write_regex_automata_corpus_report(
    path: &Path,
    report: &RegexAutomataCorpusReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "regex-automata corpus output already exists: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new("regex-automata corpus output has no parent"))?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        InventoryError::new(format!("stat output parent {}: {error}", parent.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "regex-automata output parent must be a real directory",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InventoryError::new("invalid regex-automata output name"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", temporary.display())))?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode report: {error}")))?;
    bytes.push(b'\n');
    let result = (|| {
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!("write {}: {error}", temporary.display()))
        })?;
        output.sync_all().map_err(|error| {
            InventoryError::new(format!("sync {}: {error}", temporary.display()))
        })?;
        fs::hard_link(&temporary, path)
            .map_err(|error| InventoryError::new(format!("install {}: {error}", path.display())))?;
        fs::remove_file(&temporary).map_err(|error| {
            InventoryError::new(format!("remove {}: {error}", temporary.display()))
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

impl RegexAutomataCorpusReport {
    /// Validate the exact source identity, mode denominator, zero-pass
    /// contract, ordering, cardinalities and payload seal.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != REGEX_AUTOMATA_CORPUS_REPORT_SCHEMA
            || self.payload_sha256
                != hash_json(&self.payload, "encode regex-automata inventory payload")?
        {
            return Err(InventoryError::new(
                "regex-automata corpus schema or payload seal mismatch",
            ));
        }
        validate_source(&self.payload.source)?;
        let specs = mode_specs();
        if self.payload.modes.len() != specs.len()
            || self.payload.modes.iter().zip(&specs).any(|(mode, spec)| {
                mode.id != spec.id
                    || mode.harness != spec.harness
                    || mode.default_features != spec.default_features
                    || mode.all_features != spec.all_features
                    || mode.features != spec.features
                    || mode.members == 0
                    || !is_sha256(&mode.member_ids_sha256)
            })
            || hash_json(&self.payload.modes, "encode regex-automata mode inventory")?
                != MODE_INVENTORY_SHA256
        {
            return Err(InventoryError::new(
                "regex-automata feature-mode inventory mismatch",
            ));
        }
        if self.payload.limitations
            != LIMITATIONS
                .iter()
                .map(|text| (*text).to_owned())
                .collect::<Vec<_>>()
        {
            return Err(InventoryError::new(
                "regex-automata inventory limitations mismatch",
            ));
        }
        let mut offset = 0_usize;
        for mode in &self.payload.modes {
            let end = offset
                .checked_add(mode.members)
                .ok_or_else(|| InventoryError::new("obligation offset overflow"))?;
            let members = self.payload.obligations.get(offset..end).ok_or_else(|| {
                InventoryError::new("regex-automata obligation denominator mismatch")
            })?;
            let ids = members
                .iter()
                .map(|row| row.case_id.clone())
                .collect::<BTreeSet<_>>();
            if ids.len() != members.len()
                || members
                    .windows(2)
                    .any(|pair| pair[0].case_id >= pair[1].case_id)
                || hash_line_list(&ids) != mode.member_ids_sha256
                || members.iter().any(|row| {
                    row.mode_id != mode.id
                        || row.harness != mode.harness
                        || row.case_id.is_empty()
                        || !matches!(
                            &row.disposition,
                            RegexAutomataInventoryDisposition::Unsupported { reason_code }
                                if reason_code == UNSUPPORTED_REASON
                        )
                })
            {
                return Err(InventoryError::new(
                    "regex-automata mode member inventory mismatch",
                ));
            }
            offset = end;
        }
        if offset != self.payload.obligations.len()
            || offset != TOTAL_MODE_MEMBERS
            || self.payload.harness.feature_script_modes != FEATURE_SCRIPT_MODES
            || self.payload.harness.supplemental_default_modes != SUPPLEMENTAL_DEFAULT_MODES
            || !is_sha256(&self.payload.harness.cargo_executable_sha256)
            || !is_sha256(&self.payload.harness.rustc_executable_sha256)
            || self.payload.harness.cargo_release.is_empty()
            || self.payload.harness.rustc_release.is_empty()
            || self.payload.harness.obligation_inventory_sha256 != OBLIGATION_INVENTORY_SHA256
            || hash_json(
                &self.payload.obligations,
                "encode regex-automata obligation inventory",
            )? != OBLIGATION_INVENTORY_SHA256
            || self.payload.counts != counts_for(&self.payload.modes, &self.payload.obligations)?
            || self.payload.counts.total_mode_members != TOTAL_MODE_MEMBERS
            || self.payload.counts.unique_unit_members != UNIQUE_UNIT_MEMBERS
            || self.payload.counts.unique_integration_members != UNIQUE_INTEGRATION_MEMBERS
            || self.payload.counts.unique_doctest_members != UNIQUE_DOCTEST_MEMBERS
            || self.payload.counts.unique_members != UNIQUE_MEMBERS
            || self.payload.counts.fre_pass != 0
            || self.payload.counts.unsupported != TOTAL_MODE_MEMBERS
        {
            return Err(InventoryError::new(
                "regex-automata harness or count inventory mismatch",
            ));
        }
        Ok(())
    }
}

fn authenticate_archive(crate_archive: &Path) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(crate_archive).map_err(|error| {
        InventoryError::new(format!(
            "stat crates.io archive {}: {error}",
            crate_archive.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.len() != UPSTREAM_CRATE_BYTES
    {
        return Err(InventoryError::new(
            "regex-automata crates.io archive metadata mismatch",
        ));
    }
    let bytes = fs::read(crate_archive)
        .map_err(|error| InventoryError::new(format!("read crates.io archive: {error}")))?;
    if sha256(&bytes) != UPSTREAM_CRATE_SHA256 {
        return Err(InventoryError::new(
            "regex-automata crates.io archive SHA-256 mismatch",
        ));
    }
    Ok(())
}

fn authenticate_vcs(vcs_checkout: &Path) -> Result<VcsAuthentication, InventoryError> {
    require_real_directory(vcs_checkout, "VCS checkout")?;
    require_real_directory(&vcs_checkout.join(".git"), "VCS metadata")?;
    let top = git_text(vcs_checkout, &["rev-parse", "--show-toplevel"])?;
    let canonical = vcs_checkout
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize VCS checkout: {error}")))?;
    if Path::new(&top) != canonical {
        return Err(InventoryError::new("VCS checkout top-level mismatch"));
    }
    let revision = git_text(
        vcs_checkout,
        &[
            "rev-parse",
            "--verify",
            &format!("{UPSTREAM_REVISION}^{{commit}}"),
        ],
    )?;
    let tree = git_text(
        vcs_checkout,
        &[
            "rev-parse",
            "--verify",
            &format!("{UPSTREAM_REVISION}:regex-automata"),
        ],
    )?;
    let testdata_tree = git_text(
        vcs_checkout,
        &[
            "rev-parse",
            "--verify",
            &format!("{UPSTREAM_REVISION}:testdata"),
        ],
    )?;
    let script_blob = git_text(
        vcs_checkout,
        &[
            "rev-parse",
            "--verify",
            &format!("{UPSTREAM_REVISION}:regex-automata/test"),
        ],
    )?;
    if revision != UPSTREAM_REVISION
        || tree != UPSTREAM_TREE
        || testdata_tree != UPSTREAM_TESTDATA_TREE
        || script_blob != UPSTREAM_TEST_SCRIPT_BLOB
    {
        return Err(InventoryError::new(
            "regex-automata immutable VCS identity mismatch",
        ));
    }
    let script = git_bytes(vcs_checkout, &["cat-file", "blob", &script_blob])?;
    if sha256(&script) != UPSTREAM_TEST_SCRIPT_SHA256 {
        return Err(InventoryError::new(
            "regex-automata VCS test script SHA-256 mismatch",
        ));
    }
    Ok(VcsAuthentication { script })
}

fn authenticate_package(
    package: &Path,
    vcs_checkout: &Path,
    require_cargo_marker: bool,
) -> Result<RegexAutomataSourceIdentity, InventoryError> {
    require_real_directory(package, "package")?;
    let marker = package.join(".cargo-ok");
    if require_cargo_marker {
        let bytes = read_owned_regular_file(&marker, MAX_PACKAGE_FILE_BYTES)?;
        if bytes != br#"{"v":1}"# {
            return Err(InventoryError::new("invalid Cargo extraction marker"));
        }
    } else if fs::symlink_metadata(&marker).is_ok() {
        return Err(InventoryError::new(
            "owned package snapshot unexpectedly contains Cargo marker",
        ));
    }
    let mut paths = Vec::new();
    collect_file_paths(package, package, &mut paths)?;
    paths.sort();
    let mut files = Vec::new();
    for relative in paths {
        if relative == ".cargo-ok" {
            continue;
        }
        let path = package.join(&relative);
        let bytes = read_owned_regular_file(&path, MAX_PACKAGE_FILE_BYTES)?;
        let vcs_path = match relative.as_str() {
            ".cargo_vcs_info.json" | "Cargo.lock" | "Cargo.toml" => None,
            "Cargo.toml.orig" => Some("regex-automata/Cargo.toml".to_owned()),
            _ => Some(format!("regex-automata/{relative}")),
        };
        let vcs_blob = if let Some(vcs_path) = &vcs_path {
            let blob = git_text(
                vcs_checkout,
                &[
                    "rev-parse",
                    "--verify",
                    &format!("{UPSTREAM_REVISION}:{vcs_path}"),
                ],
            )?;
            if !is_oid(&blob) || git_bytes(vcs_checkout, &["cat-file", "blob", &blob])? != bytes {
                return Err(InventoryError::new(format!(
                    "package/VCS byte mismatch for {relative}"
                )));
            }
            Some(blob)
        } else {
            None
        };
        files.push(RegexAutomataPackageFile {
            path: relative,
            mode: "0644".to_owned(),
            bytes: u64::try_from(bytes.len())
                .map_err(|_| InventoryError::new("package file length does not fit u64"))?,
            sha256: sha256(&bytes),
            vcs_path,
            vcs_blob,
        });
    }
    let package_bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| InventoryError::new("package byte count overflow"))
    })?;
    let inventory_hash = package_inventory_hash(&files);
    let vcs_matched_files = files.iter().filter(|file| file.vcs_blob.is_some()).count();
    let support_files = collect_vcs_support(vcs_checkout, &files)?;
    let vcs_support_bytes = support_files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| InventoryError::new("VCS support byte count overflow"))
    })?;
    let vcs_support_inventory_sha256 = vcs_support_inventory_hash(&support_files);
    let source = RegexAutomataSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        crates_io_archive_sha256: UPSTREAM_CRATE_SHA256.to_owned(),
        crates_io_archive_bytes: UPSTREAM_CRATE_BYTES,
        vcs_revision: UPSTREAM_REVISION.to_owned(),
        vcs_package_tree: UPSTREAM_TREE.to_owned(),
        vcs_testdata_tree: UPSTREAM_TESTDATA_TREE.to_owned(),
        vcs_test_script_blob: UPSTREAM_TEST_SCRIPT_BLOB.to_owned(),
        vcs_test_script_sha256: UPSTREAM_TEST_SCRIPT_SHA256.to_owned(),
        package_tree_inventory_sha256: inventory_hash,
        package_files: files.len(),
        package_bytes,
        vcs_matched_files,
        files,
        vcs_support_inventory_sha256,
        vcs_support_files: support_files.len(),
        vcs_support_bytes,
        support_files,
    };
    validate_source(&source)?;
    Ok(source)
}

fn validate_source(source: &RegexAutomataSourceIdentity) -> Result<(), InventoryError> {
    if source.repository != UPSTREAM_REPOSITORY
        || source.package != UPSTREAM_PACKAGE
        || source.version != UPSTREAM_VERSION
        || source.crates_io_archive_sha256 != UPSTREAM_CRATE_SHA256
        || source.crates_io_archive_bytes != UPSTREAM_CRATE_BYTES
        || source.vcs_revision != UPSTREAM_REVISION
        || source.vcs_package_tree != UPSTREAM_TREE
        || source.vcs_testdata_tree != UPSTREAM_TESTDATA_TREE
        || source.vcs_test_script_blob != UPSTREAM_TEST_SCRIPT_BLOB
        || source.vcs_test_script_sha256 != UPSTREAM_TEST_SCRIPT_SHA256
        || source.package_tree_inventory_sha256 != PACKAGE_TREE_INVENTORY_SHA256
        || source.package_files != PACKAGE_FILE_COUNT
        || source.package_bytes != PACKAGE_BYTES
        || source.vcs_matched_files != VCS_MATCHED_FILE_COUNT
        || source.vcs_support_inventory_sha256 != VCS_SUPPORT_INVENTORY_SHA256
        || source.vcs_support_files != VCS_SUPPORT_FILE_COUNT
        || source.vcs_support_bytes != VCS_SUPPORT_BYTES
        || source.files.len() != PACKAGE_FILE_COUNT
        || source
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        || source.files.iter().any(|file| {
            file.path.is_empty()
                || file.mode != "0644"
                || !is_sha256(&file.sha256)
                || file.bytes > MAX_PACKAGE_FILE_BYTES
                || file.vcs_path.is_some() != file.vcs_blob.is_some()
                || file.vcs_blob.as_ref().is_some_and(|oid| !is_oid(oid))
        })
        || package_inventory_hash(&source.files) != PACKAGE_TREE_INVENTORY_SHA256
        || source.support_files.len() != VCS_SUPPORT_FILE_COUNT
        || source
            .support_files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        || source.support_files.iter().any(|file| {
            file.path.is_empty()
                || !is_oid(&file.vcs_blob)
                || !is_sha256(&file.sha256)
                || file.bytes > MAX_PACKAGE_FILE_BYTES
        })
        || vcs_support_inventory_hash(&source.support_files) != VCS_SUPPORT_INVENTORY_SHA256
    {
        return Err(InventoryError::new(
            "regex-automata package source identity mismatch",
        ));
    }
    Ok(())
}

fn collect_file_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> Result<(), InventoryError> {
    for entry in fs::read_dir(directory).map_err(|error| {
        InventoryError::new(format!(
            "read package directory {}: {error}",
            directory.display()
        ))
    })? {
        let entry = entry.map_err(|error| InventoryError::new(format!("read entry: {error}")))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            InventoryError::new(format!("stat package entry {}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(InventoryError::new(format!(
                "package contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.file_type().is_dir() {
            collect_file_paths(root, &path, paths)?;
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| InventoryError::new("package path escaped root"))?
                .to_str()
                .ok_or_else(|| InventoryError::new("package path is not UTF-8"))?
                .replace('\\', "/");
            if relative.is_empty()
                || relative.starts_with('/')
                || relative.contains("..")
                || relative.contains('\t')
                || relative.contains('\n')
                || relative.contains('\r')
            {
                return Err(InventoryError::new("invalid package relative path"));
            }
            paths.push(relative);
        } else {
            return Err(InventoryError::new(format!(
                "package contains a non-regular entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_owned_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!("stat package file {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o644
        || metadata.len() > maximum
    {
        return Err(InventoryError::new(format!(
            "invalid package file metadata: {}",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| {
        InventoryError::new(format!("read package file {}: {error}", path.display()))
    })
}

fn package_inventory_hash(files: &[RegexAutomataPackageFile]) -> String {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.extend_from_slice(b"\t644\t");
        bytes.extend_from_slice(file.bytes.to_string().as_bytes());
        bytes.push(b'\t');
        bytes.extend_from_slice(file.sha256.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn collect_vcs_support(
    vcs_checkout: &Path,
    package_files: &[RegexAutomataPackageFile],
) -> Result<Vec<RegexAutomataVcsSupportFile>, InventoryError> {
    let package_paths = package_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let output = git_bytes(
        vcs_checkout,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            UPSTREAM_REVISION,
            "--",
            "regex-automata/tests",
            "testdata",
        ],
    )?;
    let output = std::str::from_utf8(&output)
        .map_err(|error| InventoryError::new(format!("VCS path list is not UTF-8: {error}")))?;
    let mut paths = BTreeSet::new();
    for path in output.lines() {
        let package_relative = path.strip_prefix("regex-automata/");
        let support = if let Some(relative) = package_relative {
            !package_paths.contains(relative)
        } else {
            path.starts_with("testdata/")
        };
        if !support {
            continue;
        }
        if path.is_empty()
            || (!path.starts_with("regex-automata/tests/") && !path.starts_with("testdata/"))
            || path.contains("..")
            || path.bytes().any(|byte| byte.is_ascii_control())
            || !paths.insert(path.to_owned())
        {
            return Err(InventoryError::new("invalid VCS support path inventory"));
        }
    }
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let blob = git_text(
            vcs_checkout,
            &[
                "rev-parse",
                "--verify",
                &format!("{UPSTREAM_REVISION}:{path}"),
            ],
        )?;
        if !is_oid(&blob) {
            return Err(InventoryError::new("invalid VCS support blob OID"));
        }
        let bytes = git_bytes(vcs_checkout, &["cat-file", "blob", &blob])?;
        if u64::try_from(bytes.len())
            .map_err(|_| InventoryError::new("VCS support length does not fit u64"))?
            > MAX_PACKAGE_FILE_BYTES
        {
            return Err(InventoryError::new("VCS support file exceeds size bound"));
        }
        files.push(RegexAutomataVcsSupportFile {
            path,
            vcs_blob: blob,
            bytes: u64::try_from(bytes.len())
                .map_err(|_| InventoryError::new("VCS support length does not fit u64"))?,
            sha256: sha256(&bytes),
        });
    }
    if files.len() != VCS_SUPPORT_FILE_COUNT
        || vcs_support_inventory_hash(&files) != VCS_SUPPORT_INVENTORY_SHA256
    {
        return Err(InventoryError::new(
            "VCS support file denominator or seal mismatch",
        ));
    }
    Ok(files)
}

fn vcs_support_inventory_hash(files: &[RegexAutomataVcsSupportFile]) -> String {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(b'\t');
        bytes.extend_from_slice(file.vcs_blob.as_bytes());
        bytes.push(b'\t');
        bytes.extend_from_slice(file.bytes.to_string().as_bytes());
        bytes.push(b'\t');
        bytes.extend_from_slice(file.sha256.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn snapshot_package(
    source_root: &Path,
    destination_root: &Path,
    source: &RegexAutomataSourceIdentity,
) -> Result<(), InventoryError> {
    for file in &source.files {
        let bytes = read_owned_regular_file(&source_root.join(&file.path), MAX_PACKAGE_FILE_BYTES)?;
        if u64::try_from(bytes.len()) != Ok(file.bytes) || sha256(&bytes) != file.sha256 {
            return Err(InventoryError::new(format!(
                "snapshot source changed: {}",
                file.path
            )));
        }
        let destination = destination_root.join(&file.path);
        let parent = destination
            .parent()
            .ok_or_else(|| InventoryError::new("snapshot path has no parent"))?;
        fs::create_dir_all(parent)
            .map_err(|error| InventoryError::new(format!("create snapshot directory: {error}")))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
            InventoryError::new(format!("set snapshot directory mode: {error}"))
        })?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|error| InventoryError::new(format!("create snapshot file: {error}")))?;
        output
            .write_all(&bytes)
            .map_err(|error| InventoryError::new(format!("write snapshot file: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync snapshot file: {error}")))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))
            .map_err(|error| InventoryError::new(format!("set snapshot file mode: {error}")))?;
    }
    Ok(())
}

fn snapshot_vcs_support(
    destination_root: &Path,
    vcs_checkout: &Path,
    source: &RegexAutomataSourceIdentity,
) -> Result<(), InventoryError> {
    for file in &source.support_files {
        let bytes = git_bytes(vcs_checkout, &["cat-file", "blob", &file.vcs_blob])?;
        if u64::try_from(bytes.len()) != Ok(file.bytes) || sha256(&bytes) != file.sha256 {
            return Err(InventoryError::new(format!(
                "VCS support source changed: {}",
                file.path
            )));
        }
        let destination = destination_root.join(&file.path);
        let parent = destination
            .parent()
            .ok_or_else(|| InventoryError::new("VCS support path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| {
            InventoryError::new(format!("create VCS support directory: {error}"))
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
            InventoryError::new(format!("set VCS support directory mode: {error}"))
        })?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|error| InventoryError::new(format!("create VCS support file: {error}")))?;
        output
            .write_all(&bytes)
            .map_err(|error| InventoryError::new(format!("write VCS support file: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync VCS support file: {error}")))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))
            .map_err(|error| InventoryError::new(format!("set VCS support file mode: {error}")))?;
    }
    Ok(())
}

fn validate_execution_snapshot(
    workspace: &Path,
    source: &RegexAutomataSourceIdentity,
) -> Result<(), InventoryError> {
    require_real_directory(workspace, "execution snapshot")?;
    let mut expected = BTreeMap::new();
    for file in &source.files {
        let path = format!("regex-automata/{}", file.path);
        if expected
            .insert(path, (file.bytes, file.sha256.as_str()))
            .is_some()
        {
            return Err(InventoryError::new("duplicate package snapshot path"));
        }
    }
    for file in &source.support_files {
        if expected
            .insert(file.path.clone(), (file.bytes, file.sha256.as_str()))
            .is_some()
        {
            return Err(InventoryError::new("duplicate VCS support snapshot path"));
        }
    }
    let mut observed = Vec::new();
    collect_file_paths(workspace, workspace, &mut observed)?;
    observed.sort();
    if observed.len() != expected.len()
        || observed
            .iter()
            .map(String::as_str)
            .ne(expected.keys().map(String::as_str))
    {
        return Err(InventoryError::new(
            "execution snapshot path inventory mismatch",
        ));
    }
    for path in observed {
        let (expected_bytes, expected_sha256) = expected
            .get(&path)
            .ok_or_else(|| InventoryError::new("unexpected execution snapshot path"))?;
        let bytes = read_owned_regular_file(&workspace.join(&path), MAX_PACKAGE_FILE_BYTES)?;
        if u64::try_from(bytes.len()) != Ok(*expected_bytes) || sha256(&bytes) != *expected_sha256 {
            return Err(InventoryError::new(format!(
                "execution snapshot byte mismatch: {path}"
            )));
        }
    }
    Ok(())
}

fn mode_specs() -> Vec<ModeSpec> {
    let mut specs = Vec::with_capacity(45);
    for harness in [
        RegexAutomataHarnessKind::Unit,
        RegexAutomataHarnessKind::Integration,
        RegexAutomataHarnessKind::Doctest,
    ] {
        specs.push(ModeSpec {
            id: format!("package-default-{}", harness_slug(harness)),
            harness,
            default_features: true,
            all_features: false,
            features: Vec::new(),
        });
    }
    for harness in [
        RegexAutomataHarnessKind::Unit,
        RegexAutomataHarnessKind::Integration,
        RegexAutomataHarnessKind::Doctest,
    ] {
        specs.push(ModeSpec {
            id: format!("vcs-all-features-{}", harness_slug(harness)),
            harness,
            default_features: true,
            all_features: true,
            features: Vec::new(),
        });
    }
    for (index, features) in VCS_LIB_FEATURES.iter().enumerate() {
        specs.push(ModeSpec {
            id: format!("vcs-lib-{index:02}"),
            harness: RegexAutomataHarnessKind::Unit,
            default_features: false,
            all_features: false,
            features: split_features(features),
        });
    }
    for (index, features) in VCS_INTEGRATION_FEATURES.iter().enumerate() {
        specs.push(ModeSpec {
            id: format!("vcs-integration-{index:02}"),
            harness: RegexAutomataHarnessKind::Integration,
            default_features: false,
            all_features: false,
            features: split_features(features),
        });
    }
    specs
}

fn split_features(features: &str) -> Vec<String> {
    if features.is_empty() {
        Vec::new()
    } else {
        features.split(',').map(str::to_owned).collect()
    }
}

const fn harness_slug(harness: RegexAutomataHarnessKind) -> &'static str {
    match harness {
        RegexAutomataHarnessKind::Unit => "unit",
        RegexAutomataHarnessKind::Integration => "integration",
        RegexAutomataHarnessKind::Doctest => "doctest",
    }
}

fn parse_test_script_features(script: &[u8]) -> Result<(Vec<&str>, Vec<&str>), InventoryError> {
    let script = std::str::from_utf8(script)
        .map_err(|error| InventoryError::new(format!("test script is not UTF-8: {error}")))?;
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in script.lines() {
        let line = line.trim();
        if line == "features=(" {
            if current.replace(Vec::new()).is_some() {
                return Err(InventoryError::new("nested test script feature blocks"));
            }
        } else if line == ")" {
            let block = current
                .take()
                .ok_or_else(|| InventoryError::new("unmatched test script feature block"))?;
            blocks.push(block);
        } else if let Some(block) = &mut current {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let value = line
                .strip_prefix('"')
                .and_then(|line| line.strip_suffix('"'))
                .ok_or_else(|| InventoryError::new("invalid test script feature row"))?;
            if value.contains('"')
                || value.contains('\\')
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(InventoryError::new("unsafe test script feature row"));
            }
            block.push(value);
        }
    }
    if current.is_some() || blocks.len() != 2 {
        return Err(InventoryError::new(
            "test script feature block denominator mismatch",
        ));
    }
    let second = blocks.pop().expect("length checked");
    let first = blocks.pop().expect("length checked");
    Ok((first, second))
}

fn list_mode_members(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    spec: &ModeSpec,
) -> Result<BTreeSet<String>, InventoryError> {
    let mut args = vec![
        "test".to_owned(),
        "--offline".to_owned(),
        "--locked".to_owned(),
    ];
    if spec.all_features {
        args.push("--all-features".to_owned());
    } else if !spec.default_features {
        args.push("--no-default-features".to_owned());
        if !spec.features.is_empty() {
            args.push("--features".to_owned());
            args.push(spec.features.join(","));
        }
    }
    match spec.harness {
        RegexAutomataHarnessKind::Unit => args.push("--lib".to_owned()),
        RegexAutomataHarnessKind::Integration => {
            args.push("--test".to_owned());
            args.push("integration".to_owned());
        }
        RegexAutomataHarnessKind::Doctest => args.push("--doc".to_owned()),
    }
    args.extend(["--".to_owned(), "--list".to_owned()]);
    let output = cargo_output(package, target, cargo_home, cargo, rustc, &args)
        .map_err(|error| InventoryError::new(format!("execute Cargo list: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!(
            "Cargo list failed for {}: evidence_sha256={}",
            spec.id,
            command_evidence(&output)
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| InventoryError::new(format!("Cargo list is not UTF-8: {error}")))?;
    parse_test_list(stdout)
}

fn parse_test_list(stdout: &str) -> Result<BTreeSet<String>, InventoryError> {
    let mut members = BTreeSet::new();
    let mut summary = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(case_id) = line.strip_suffix(": test") {
            if case_id.is_empty()
                || case_id.bytes().any(|byte| byte.is_ascii_control())
                || !members.insert(case_id.to_owned())
            {
                return Err(InventoryError::new(
                    "invalid or duplicate Cargo test identity",
                ));
            }
            continue;
        }
        if let Some(prefix) = line.strip_suffix(" tests, 0 benchmarks") {
            let count = prefix
                .parse::<usize>()
                .map_err(|_| InventoryError::new("invalid Cargo list summary"))?;
            if summary.replace(count).is_some() {
                return Err(InventoryError::new("duplicate Cargo list summary"));
            }
            continue;
        }
        return Err(InventoryError::new(format!(
            "unexpected Cargo list output: {line:?}"
        )));
    }
    if summary != Some(members.len()) {
        return Err(InventoryError::new(
            "Cargo list member count differs from summary",
        ));
    }
    Ok(members)
}

fn counts_for(
    modes: &[RegexAutomataFeatureMode],
    obligations: &[RegexAutomataObligation],
) -> Result<RegexAutomataInventoryCounts, InventoryError> {
    let mut counts = RegexAutomataInventoryCounts {
        feature_modes: modes.len(),
        fre_pass: 0,
        unsupported: obligations.len(),
        ..RegexAutomataInventoryCounts::default()
    };
    let mut units = BTreeSet::new();
    let mut integrations = BTreeSet::new();
    let mut doctests = BTreeSet::new();
    for row in obligations {
        let (counter, identities) = match row.harness {
            RegexAutomataHarnessKind::Unit => (&mut counts.unit_mode_members, &mut units),
            RegexAutomataHarnessKind::Integration => {
                (&mut counts.integration_mode_members, &mut integrations)
            }
            RegexAutomataHarnessKind::Doctest => (&mut counts.doctest_mode_members, &mut doctests),
        };
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| InventoryError::new("regex-automata count overflow"))?;
        identities.insert(row.case_id.clone());
    }
    counts.total_mode_members = counts
        .unit_mode_members
        .checked_add(counts.integration_mode_members)
        .and_then(|count| count.checked_add(counts.doctest_mode_members))
        .ok_or_else(|| InventoryError::new("regex-automata count overflow"))?;
    counts.unique_unit_members = units.len();
    counts.unique_integration_members = integrations.len();
    counts.unique_doctest_members = doctests.len();
    counts.unique_members = units
        .into_iter()
        .map(|id| (RegexAutomataHarnessKind::Unit, id))
        .chain(
            integrations
                .into_iter()
                .map(|id| (RegexAutomataHarnessKind::Integration, id)),
        )
        .chain(
            doctests
                .into_iter()
                .map(|id| (RegexAutomataHarnessKind::Doctest, id)),
        )
        .collect::<BTreeSet<_>>()
        .len();
    if counts.total_mode_members != obligations.len() || counts.unsupported != obligations.len() {
        return Err(InventoryError::new(
            "regex-automata disposition denominator mismatch",
        ));
    }
    Ok(counts)
}

fn prepare_target_dir(target: &Path, protected: &[&Path]) -> Result<PathBuf, InventoryError> {
    fs::create_dir(target).map_err(|error| {
        InventoryError::new(format!(
            "create inventory target {}: {error}",
            target.display()
        ))
    })?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))
        .map_err(|error| InventoryError::new(format!("set target mode: {error}")))?;
    require_real_directory(target, "inventory target")?;
    if fs::read_dir(target)
        .map_err(|error| InventoryError::new(format!("read inventory target: {error}")))?
        .next()
        .is_some()
    {
        return Err(InventoryError::new("inventory target must be empty"));
    }
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize target: {error}")))?;
    for path in protected {
        let path = path
            .canonicalize()
            .map_err(|error| InventoryError::new(format!("canonicalize source: {error}")))?;
        if target.starts_with(&path) || path.starts_with(&target) {
            return Err(InventoryError::new(
                "inventory target must be disjoint from authenticated sources",
            ));
        }
    }
    Ok(target)
}

fn create_private_directory(path: &Path) -> Result<(), InventoryError> {
    fs::create_dir(path).map_err(|error| {
        InventoryError::new(format!(
            "create private directory {}: {error}",
            path.display()
        ))
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| InventoryError::new(format!("set private directory mode: {error}")))?;
    require_real_directory(path, "private directory")
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!("stat {label} {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != unsafe_free_euid()
    {
        return Err(InventoryError::new(format!(
            "{label} must be an owned real directory"
        )));
    }
    Ok(())
}

fn reject_ancestor_cargo_configs(package: &Path) -> Result<(), InventoryError> {
    for ancestor in package.ancestors() {
        for name in ["config", "config.toml"] {
            let config = ancestor.join(".cargo").join(name);
            match fs::symlink_metadata(&config) {
                Ok(_) => {
                    return Err(InventoryError::new(format!(
                        "ambient Cargo config is not allowed: {}",
                        config.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(InventoryError::new(format!(
                        "stat ambient Cargo config {}: {error}",
                        config.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn resolve_cargo_home() -> Result<PathBuf, InventoryError> {
    let configured = if let Some(path) = std::env::var_os("CARGO_HOME") {
        PathBuf::from(path)
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| InventoryError::new("neither CARGO_HOME nor HOME is set"))?,
        )
        .join(".cargo")
    };
    require_real_directory(&configured, "Cargo home")?;
    configured
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize Cargo home: {error}")))
}

fn reject_cargo_home_configs(cargo_home: &Path) -> Result<(), InventoryError> {
    for name in ["config", "config.toml"] {
        let config = cargo_home.join(name);
        match fs::symlink_metadata(&config) {
            Ok(_) => {
                return Err(InventoryError::new(format!(
                    "Cargo home config is not allowed: {}",
                    config.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(InventoryError::new(format!(
                    "stat Cargo home config {}: {error}",
                    config.display()
                )));
            }
        }
    }
    Ok(())
}

fn cargo_output(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    args: &[String],
) -> std::io::Result<Output> {
    let mut command = Command::new(cargo);
    for (key, _) in std::env::vars_os() {
        let Some(key_text) = key.to_str() else {
            continue;
        };
        if matches!(
            key_text,
            "RUSTC"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "RUSTDOC"
                | "RUSTFLAGS"
                | "RUSTDOCFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
        ) || key_text.starts_with("RUSTC_")
            || key_text.starts_with("CARGO_BUILD_")
            || key_text.starts_with("CARGO_PROFILE_")
            || key_text.starts_with("CARGO_TARGET_")
        {
            command.env_remove(key);
        }
    }
    command
        .args(args)
        .current_dir(package)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC", rustc)
        .output()
}

fn resolve_tool(tool: &str) -> Result<PathBuf, InventoryError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| InventoryError::new("PATH is absent while resolving harness tools"))?;
    let current = std::env::current_dir()
        .map_err(|error| InventoryError::new(format!("read current directory: {error}")))?;
    for directory in std::env::split_paths(&path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            current.join(directory)
        };
        let candidate = directory.join(tool);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Ok(candidate);
        }
    }
    Err(InventoryError::new(format!(
        "cannot resolve executable {tool:?} from PATH"
    )))
}

fn tool_release(tool: &Path, name: &str) -> Result<String, InventoryError> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|error| InventoryError::new(format!("execute {name} --version: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!("{name} --version failed")));
    }
    let release = std::str::from_utf8(&output.stdout)
        .map_err(|error| InventoryError::new(format!("{name} version is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if release.is_empty() || release.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(InventoryError::new(format!("invalid {name} release")));
    }
    Ok(release)
}

fn hash_tool(tool: &Path, name: &str) -> Result<String, InventoryError> {
    fs::read(tool)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("read {name} executable: {error}")))
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, InventoryError> {
    let bytes = git_bytes(repo, args)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| InventoryError::new(format!("Git output is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if text.is_empty() || text.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(InventoryError::new("invalid Git text output"));
    }
    Ok(text)
}

fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, InventoryError> {
    let mut command = Command::new("/usr/bin/git");
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| key.starts_with("GIT_")) {
            command.env_remove(key);
        }
    }
    let output = command
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|error| InventoryError::new(format!("execute Git: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!(
            "Git command failed: evidence_sha256={}",
            command_evidence(&output)
        )));
    }
    Ok(output.stdout)
}

fn parse_euid(output: &[u8]) -> Option<u32> {
    std::str::from_utf8(output).ok()?.trim().parse().ok()
}

fn unsafe_free_euid() -> u32 {
    // `/usr/bin/id -u` avoids adding an unsafe libc call to this forbid-unsafe
    // crate. Failure maps to an impossible sentinel and therefore fail-closes
    // every ownership check.
    static EUID: OnceLock<u32> = OnceLock::new();
    *EUID.get_or_init(|| {
        Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| parse_euid(&output.stdout))
            .unwrap_or(u32::MAX)
    })
}

fn hash_line_list(values: &BTreeSet<String>) -> String {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn command_evidence(output: &Output) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.stdout);
    bytes.push(0);
    bytes.extend_from_slice(&output.stderr);
    sha256(&bytes)
}

fn hash_json(value: &impl Serialize, context: &str) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("{context}: {error}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_vcs_feature_script_parser_covers_both_blocks() {
        let script = br#"
features=(
  ""
  "std"
)
for f in "${features[@]}"; do true; done
features=(
  "std,unicode,meta"
  # "disabled-row"
)
"#;
        assert_eq!(
            parse_test_script_features(script).unwrap(),
            (vec!["", "std"], vec!["std,unicode,meta"]),
        );
        assert!(parse_test_script_features(b"features=(\n bad\n)\n").is_err());
    }

    #[test]
    fn cargo_member_parser_rejects_omission_and_duplicates() {
        let members = parse_test_list("alpha: test\nbeta: test\n2 tests, 0 benchmarks\n")
            .expect("valid member list");
        assert_eq!(members, ["alpha".to_owned(), "beta".to_owned()].into());
        assert!(parse_test_list("alpha: test\n0 tests, 0 benchmarks\n").is_err());
        assert!(parse_test_list("alpha: test\nalpha: test\n2 tests, 0 benchmarks\n").is_err());
        assert!(parse_test_list("alpha: benchmark\n0 tests, 0 benchmarks\n").is_err());
    }

    #[test]
    fn inventory_modes_are_fixed_and_zero_pass_is_unrepresentable() {
        let specs = mode_specs();
        assert_eq!(specs.len(), 45);
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.harness == RegexAutomataHarnessKind::Unit)
                .count(),
            30,
        );
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.harness == RegexAutomataHarnessKind::Integration)
                .count(),
            13,
        );
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.harness == RegexAutomataHarnessKind::Doctest)
                .count(),
            2,
        );
        let encoded = serde_json::to_string(&RegexAutomataInventoryDisposition::Unsupported {
            reason_code: UNSUPPORTED_REASON.to_owned(),
        })
        .unwrap();
        assert!(encoded.contains("unsupported"));
        assert!(!encoded.contains("pass"));
    }
}
