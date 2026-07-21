//! Authenticated, omission-proof inventory for the exact
//! `regex-automata` 0.4.14 package suite.
//!
//! This module deliberately does not execute FRE. Every discovered harness
//! member is emitted as an unsupported adapter obligation, so an inventory
//! checkpoint cannot be mistaken for a compatibility claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::process::CommandExt,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{InventoryError, sha256};

/// Schema for the sealed inventory-only report.
pub const REGEX_AUTOMATA_CORPUS_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.package-corpus-inventory.v1";

/// Schema for an authenticated, no-clock execution of the four pinned
/// `util::look` unit tests under every unit-harness feature mode.
pub const REGEX_AUTOMATA_LOOK_MODE_MATRIX_SCHEMA: &str =
    "fre.regex-automata-0.4.14.look-mode-matrix.v1";

/// Seal of the ordered 30-mode unit-harness contract. The contract is the
/// package-default unit mode, the VCS all-features unit mode and the 28 VCS
/// lib feature modes derived from the authenticated upstream `test` script.
pub const REGEX_AUTOMATA_LOOK_MODE_CONTRACT_SHA256: &str =
    "f6104b9cafdfc8a0c787bc78028327d465a145ef3ad671b0f24ca6b9f0f94841";

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
const LOOK_MODE_COUNT: usize = 30;
const LOOK_TESTS_PER_MODE: usize = 4;
const LOOK_TEST_MEMBERSHIPS: usize = LOOK_MODE_COUNT * LOOK_TESTS_PER_MODE;
const LOOK_SOURCE_SHA256: &str = "fca6dac7bf7b3b975f177db91e122af89e1510b3664d04210ca8b84738a08305";
const LOOK_SPAN_SHA256: &str = "7d4a1ac128aa3df29bab8bece1cd9481df88abfdb31ee7086668503f48eead84";
const LOOK_TARGET_IDS_SHA256: &str =
    "053675c6955c5ca165db98bf1a684105cbb59176b1893ab9b022a4d98fd16c9b";
const LOOK_SOURCE_FIRST_LINE: usize = 1700;
const LOOK_SOURCE_LAST_LINE: usize = 1767;
const LOOK_SOURCE_FIRST_INDEX: usize = 1699;
const MAX_LOOK_ARTIFACT_BYTES: u64 = 512 * 1_048_576;
const LOOK_COMPILE_TIMEOUT: Duration = Duration::from_secs(900);
const LOOK_TEST_TIMEOUT: Duration = Duration::from_secs(60);
const LOOK_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const LOOK_TERMINATE_GRACE: Duration = Duration::from_secs(3);
const LOOK_SIGNAL_TIMEOUT: Duration = Duration::from_secs(1);
const LOOK_PIPE_DRAIN_GRACE: Duration = Duration::from_secs(1);
const LOOK_CHILD_POLL: Duration = Duration::from_millis(10);
/// Maximum retained UTF-8 stdout or stderr bytes for one matrix command.
pub(crate) const REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES: usize = 512 * 1024;
/// Maximum compact or pretty serialized matrix size accepted by the validator.
pub(crate) const REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES: usize = 24 * 1_048_576;
const LOOK_FEATURE_GRAPH_SHA256: &str =
    "40d5101080f340f1a8a91a2dcb6a4813bc92f0aaec8d1a6425ceeff7146e31d4";
#[cfg(test)]
const LOOK_NORMALIZED_MANIFEST_SHA256: &str =
    "83e288a27db86536cc16d1b1b82e9c5e89276781340518d234ecc919dde093fc";
const LOOK_INVENTORY_RUSTC_HOST: &str = "x86_64-unknown-linux-gnu";
#[cfg(target_os = "linux")]
const LOOK_O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "macos")]
const LOOK_O_NOFOLLOW: i32 = 0x0000_0100;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const LOOK_O_NOFOLLOW: i32 = 0;

const LOOK_TEST_IDS: [&str; LOOK_TESTS_PER_MODE] = [
    "util::look::tests::look_matches_end_line",
    "util::look::tests::look_matches_end_text",
    "util::look::tests::look_matches_start_line",
    "util::look::tests::look_matches_start_text",
];

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

/// Exact toolchain and inventory authority for a look-mode matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookModeHarnessIdentity {
    pub inventory_payload_sha256: String,
    pub inventory_obligation_sha256: String,
    pub inventory_harness_sha256: String,
    pub inventory_cargo_release: String,
    pub inventory_cargo_executable_sha256: String,
    pub inventory_rustc_release: String,
    pub inventory_rustc_executable_sha256: String,
    pub cargo_path: String,
    pub cargo_release: String,
    pub cargo_executable_sha256: String,
    pub rustc_path: String,
    pub rustc_release: String,
    pub rustc_verbose: String,
    pub rustc_verbose_sha256: String,
    pub rustc_host: String,
    pub rustc_executable_sha256: String,
}

/// Bounded UTF-8 evidence for one no-clock subprocess. Raw output is retained
/// alongside its independently checked byte length and digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookCommandEvidence {
    pub argv: Vec<String>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout_bytes: u64,
    pub stdout_sha256: String,
    pub stdout: String,
    pub stderr_bytes: u64,
    pub stderr_sha256: String,
    pub stderr: String,
}

/// Outcome of compiling and directly executing one unit-harness mode.
/// Unavailability is evidence, never a passing disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "available and unavailable evidence remain directly inspectable in sealed JSON"
)]
pub enum RegexAutomataLookModeDisposition {
    Available {
        resolved_features: Vec<String>,
        resolved_features_sha256: String,
        compiled_artifact_path: String,
        artifact_path: String,
        artifact_bytes: u64,
        artifact_sha256: String,
        build: RegexAutomataLookCommandEvidence,
        runs: Vec<RegexAutomataLookCommandEvidence>,
        test_ids: Vec<String>,
        test_ids_sha256: String,
    },
    Unavailable {
        stage: String,
        reason_code: String,
        detail_sha256: String,
        evidence_sha256: String,
        attempted_argv: Vec<String>,
        command: Option<RegexAutomataLookCommandEvidence>,
    },
}

/// One exact mode tuple, its authenticated inventory membership seal and its
/// observed compile/execution disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookModeReceipt {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub default_features: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub inventory_members: usize,
    pub inventory_member_ids_sha256: String,
    pub mode_tuple_sha256: String,
    pub disposition: RegexAutomataLookModeDisposition,
}

/// Cardinalities distinguish executed memberships from unavailable modes.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookModeCounts {
    pub modes: usize,
    pub available_modes: usize,
    pub unavailable_modes: usize,
    pub tests_per_mode: usize,
    pub available_test_memberships: usize,
    pub total_test_memberships: usize,
}

/// Payload covered by `payload_sha256` in a look-mode matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookModeMatrixPayload {
    pub source: RegexAutomataSourceIdentity,
    pub source_identity_sha256: String,
    pub harness: RegexAutomataLookModeHarnessIdentity,
    pub snapshot_package_path: String,
    pub mode_target_root: String,
    pub local_feature_graph: BTreeMap<String, Vec<String>>,
    pub local_feature_graph_sha256: String,
    pub mode_contract_sha256: String,
    pub look_source_sha256: String,
    pub look_source_first_line: usize,
    pub look_source_last_line: usize,
    pub look_span_sha256: String,
    pub look_target_ids_sha256: String,
    pub target_test_ids: Vec<String>,
    pub receipts: Vec<RegexAutomataLookModeReceipt>,
    pub counts: RegexAutomataLookModeCounts,
}

/// Sealed, no-clock look-mode execution matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataLookModeMatrix {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexAutomataLookModeMatrixPayload,
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

/// Compile and directly execute the four authenticated `util::look` unit
/// tests under all 30 unit-harness modes. A mode-local failure is preserved as
/// `Unavailable`; it can never become a passing receipt.
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated snapshot and tool identity transaction stays contiguous"
)]
pub fn build_regex_automata_look_mode_matrix(
    crate_archive: &Path,
    package: &Path,
    vcs_checkout: &Path,
    inventory: &RegexAutomataCorpusReport,
    target_dir: &Path,
) -> Result<RegexAutomataLookModeMatrix, InventoryError> {
    inventory.validate()?;
    authenticate_archive(crate_archive)?;
    let vcs = authenticate_vcs(vcs_checkout)?;
    let source = authenticate_package(package, vcs_checkout, true)?;
    if source != inventory.payload.source {
        return Err(InventoryError::new(
            "look-mode source differs from authenticated corpus inventory",
        ));
    }
    let parsed_features = parse_test_script_features(&vcs.script)?;
    if parsed_features.0 != VCS_LIB_FEATURES || parsed_features.1 != VCS_INTEGRATION_FEATURES {
        return Err(InventoryError::new(
            "look-mode VCS feature transcription mismatch",
        ));
    }
    let inventory_modes = look_inventory_modes(inventory)?;

    let target_dir = prepare_target_dir(target_dir, &[crate_archive, package, vcs_checkout])?;
    let snapshot_workspace = target_dir.join("upstream-snapshot");
    create_private_directory(&snapshot_workspace)?;
    let snapshot = snapshot_workspace.join("regex-automata");
    create_private_directory(&snapshot)?;
    snapshot_package(package, &snapshot, &source)?;
    snapshot_vcs_support(&snapshot_workspace, vcs_checkout, &source)?;
    seal_execution_snapshot(&snapshot_workspace)?;
    validate_sealed_execution_snapshot(&snapshot_workspace, &source)?;
    authenticate_snapshot_look_source(&snapshot)?;
    reject_ancestor_cargo_configs(&snapshot)?;
    let local_feature_graph = authenticated_local_feature_graph(&snapshot)?;

    let cargo_home = resolve_cargo_home()?;
    reject_cargo_home_configs(&cargo_home)?;
    let cargo = canonical_tool("cargo")?;
    let rustc = canonical_tool("rustc")?;
    let cargo_release = sanitized_tool_release(&cargo, "cargo", false)?;
    let rustc_release = sanitized_tool_release(&rustc, "rustc", false)?;
    let rustc_verbose = sanitized_tool_release(&rustc, "rustc", true)?;
    let rustc_host = parse_rustc_host(&rustc_verbose)?;
    let cargo_executable_sha256 = hash_tool(&cargo, "cargo")?;
    let rustc_executable_sha256 = hash_tool(&rustc, "rustc")?;
    if cargo_release != inventory.payload.harness.cargo_release
        || cargo_executable_sha256 != inventory.payload.harness.cargo_executable_sha256
        || rustc_release != inventory.payload.harness.rustc_release
        || rustc_executable_sha256 != inventory.payload.harness.rustc_executable_sha256
        || rustc_host != LOOK_INVENTORY_RUSTC_HOST
    {
        return Err(InventoryError::new(
            "look-mode toolchain differs from authenticated inventory harness",
        ));
    }
    let harness = RegexAutomataLookModeHarnessIdentity {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        inventory_obligation_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        inventory_harness_sha256: hash_json(
            &inventory.payload.harness,
            "encode inventory harness authority",
        )?,
        inventory_cargo_release: inventory.payload.harness.cargo_release.clone(),
        inventory_cargo_executable_sha256: inventory
            .payload
            .harness
            .cargo_executable_sha256
            .clone(),
        inventory_rustc_release: inventory.payload.harness.rustc_release.clone(),
        inventory_rustc_executable_sha256: inventory
            .payload
            .harness
            .rustc_executable_sha256
            .clone(),
        cargo_path: path_text(&cargo, "cargo")?,
        cargo_release,
        cargo_executable_sha256,
        rustc_path: path_text(&rustc, "rustc")?,
        rustc_release,
        rustc_verbose_sha256: sha256(rustc_verbose.as_bytes()),
        rustc_verbose,
        rustc_host,
        rustc_executable_sha256,
    };

    let mode_targets = target_dir.join("mode-targets");
    create_private_directory(&mode_targets)?;
    let specs = look_mode_specs();
    let mut receipts = Vec::with_capacity(LOOK_MODE_COUNT);
    for (spec, inventory_mode) in specs.iter().zip(&inventory_modes) {
        validate_sealed_execution_snapshot(&snapshot_workspace, &source)?;
        authenticate_snapshot_look_source(&snapshot)?;
        let mode_target = mode_targets.join(&spec.id);
        create_private_directory(&mode_target)?;
        receipts.push(execute_look_mode(
            &snapshot,
            &mode_target,
            &cargo_home,
            &cargo,
            &rustc,
            spec,
            inventory_mode,
            &local_feature_graph,
        )?);
        validate_sealed_execution_snapshot(&snapshot_workspace, &source)?;
        authenticate_snapshot_look_source(&snapshot)?;
    }

    authenticate_archive(crate_archive)?;
    if authenticate_vcs(vcs_checkout)?.script != vcs.script
        || authenticate_package(package, vcs_checkout, true)? != source
        || validate_sealed_execution_snapshot(&snapshot_workspace, &source).is_err()
        || sanitized_tool_release(&cargo, "cargo", false)? != harness.cargo_release
        || sanitized_tool_release(&rustc, "rustc", false)? != harness.rustc_release
        || sanitized_tool_release(&rustc, "rustc", true)? != harness.rustc_verbose
        || hash_tool(&cargo, "cargo")? != harness.cargo_executable_sha256
        || hash_tool(&rustc, "rustc")? != harness.rustc_executable_sha256
    {
        return Err(InventoryError::new(
            "look-mode source, snapshot or tool identity changed during execution",
        ));
    }
    reject_ancestor_cargo_configs(&snapshot)?;
    reject_cargo_home_configs(&cargo_home)?;

    let counts = look_mode_counts(&receipts)?;
    let payload = RegexAutomataLookModeMatrixPayload {
        source_identity_sha256: hash_json(&source, "encode look-mode source identity")?,
        source,
        harness,
        snapshot_package_path: path_text(&snapshot, "look-mode snapshot package")?,
        mode_target_root: path_text(&mode_targets, "look-mode target root")?,
        local_feature_graph_sha256: hash_json(
            &local_feature_graph,
            "encode regex-automata local feature graph",
        )?,
        local_feature_graph,
        mode_contract_sha256: REGEX_AUTOMATA_LOOK_MODE_CONTRACT_SHA256.to_owned(),
        look_source_sha256: LOOK_SOURCE_SHA256.to_owned(),
        look_source_first_line: LOOK_SOURCE_FIRST_LINE,
        look_source_last_line: LOOK_SOURCE_LAST_LINE,
        look_span_sha256: LOOK_SPAN_SHA256.to_owned(),
        look_target_ids_sha256: LOOK_TARGET_IDS_SHA256.to_owned(),
        target_test_ids: look_test_ids(),
        receipts,
        counts,
    };
    let payload_sha256 = hash_json(&payload, "encode look-mode matrix payload")?;
    let matrix = RegexAutomataLookModeMatrix {
        schema: REGEX_AUTOMATA_LOOK_MODE_MATRIX_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    matrix.validate()?;
    Ok(matrix)
}

/// Read and fully validate one sealed look-mode matrix.
pub fn read_regex_automata_look_mode_matrix(
    path: &Path,
) -> Result<RegexAutomataLookModeMatrix, InventoryError> {
    let bytes = read_sealed_look_mode_matrix(path)?;
    let matrix: RegexAutomataLookModeMatrix = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode regex-automata look-mode matrix {}: {error}",
            path.display()
        ))
    })?;
    matrix.validate()?;
    Ok(matrix)
}

fn read_sealed_look_mode_matrix(path: &Path) -> Result<Vec<u8>, InventoryError> {
    read_sealed_look_mode_matrix_with_limit(path, REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES)
}

fn read_sealed_look_mode_matrix_with_limit(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, InventoryError> {
    if LOOK_O_NOFOLLOW == 0 {
        return Err(InventoryError::new(
            "look-mode matrix O_NOFOLLOW is unavailable on this platform",
        ));
    }
    if maximum == 0 {
        return Err(InventoryError::new("look-mode matrix read bound is zero"));
    }
    let maximum_u64 = u64::try_from(maximum)
        .map_err(|_| InventoryError::new("look-mode matrix maximum does not fit u64"))?;
    let before = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!("stat look-mode matrix {}: {error}", path.display()))
    })?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != unsafe_free_euid()
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o400
        || before.len() == 0
        || before.len() > maximum_u64
    {
        return Err(InventoryError::new("invalid look-mode matrix metadata"));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(LOOK_O_NOFOLLOW)
        .open(path)
        .map_err(|error| InventoryError::new(format!("open look-mode matrix: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat look-mode matrix: {error}")))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != before.uid()
        || opened.nlink() != before.nlink()
        || opened.permissions().mode() != before.permissions().mode()
        || opened.len() != before.len()
    {
        return Err(InventoryError::new(
            "look-mode matrix changed between lstat and open",
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| InventoryError::new("look-mode matrix length does not fit usize"))?,
    );
    std::io::Read::by_ref(&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| InventoryError::new(format!("read look-mode matrix: {error}")))?;
    let after = file.metadata().map_err(|error| {
        InventoryError::new(format!("fstat look-mode matrix after read: {error}"))
    })?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.uid() != opened.uid()
        || after.nlink() != opened.nlink()
        || after.permissions().mode() != opened.permissions().mode()
        || after.len() != opened.len()
        || u64::try_from(bytes.len()) != Ok(opened.len())
        || bytes.len() > maximum
    {
        return Err(InventoryError::new(
            "look-mode matrix changed while being read",
        ));
    }
    Ok(bytes)
}

/// Install canonical pretty JSON without replacing existing evidence.
pub fn write_regex_automata_look_mode_matrix(
    path: &Path,
    matrix: &RegexAutomataLookModeMatrix,
) -> Result<(), InventoryError> {
    matrix.validate()?;
    write_new_pretty_json(path, matrix, "regex-automata look-mode matrix")
}

fn write_new_pretty_json(
    path: &Path,
    value: &impl Serialize,
    label: &str,
) -> Result<(), InventoryError> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "{label} output already exists: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new(format!("{label} output has no parent")))?;
    require_real_directory(parent, "look-mode output parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.bytes().any(|byte| byte.is_ascii_control()))
        .ok_or_else(|| InventoryError::new(format!("invalid {label} output name")))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", temporary.display())))?;
    let bytes =
        encode_bounded_pretty_json(value, REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES, label)?;
    let result = (|| {
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!("write {}: {error}", temporary.display()))
        })?;
        output.sync_all().map_err(|error| {
            InventoryError::new(format!("sync {}: {error}", temporary.display()))
        })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400)).map_err(|error| {
            InventoryError::new(format!("seal {}: {error}", temporary.display()))
        })?;
        fs::hard_link(&temporary, path)
            .map_err(|error| InventoryError::new(format!("install {}: {error}", path.display())))?;
        fs::remove_file(&temporary).map_err(|error| {
            InventoryError::new(format!("remove {}: {error}", temporary.display()))
        })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| InventoryError::new(format!("sync output parent: {error}")))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn encode_bounded_pretty_json(
    value: &impl Serialize,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, InventoryError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| InventoryError::new(format!("encode {label}: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > maximum {
        return Err(InventoryError::new(format!(
            "encoded {label} exceeds the sealed read bound"
        )));
    }
    Ok(bytes)
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

impl RegexAutomataLookModeMatrix {
    /// Validate the source/tool authority, exact 30-row contract, every
    /// command receipt and the distinction between available and unavailable
    /// modes. This validation never interprets an unavailable mode as pass.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete sealed evidence contract is intentionally reviewed together"
    )]
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != REGEX_AUTOMATA_LOOK_MODE_MATRIX_SCHEMA
            || self.payload_sha256 != hash_json(&self.payload, "encode look-mode matrix payload")?
            || serde_json::to_vec(self)
                .map_err(|error| InventoryError::new(format!("encode look-mode matrix: {error}")))?
                .len()
                > REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES
            || serde_json::to_vec_pretty(self)
                .map_err(|error| {
                    InventoryError::new(format!("pretty-encode look-mode matrix: {error}"))
                })?
                .len()
                .checked_add(1)
                .is_none_or(|bytes| bytes > REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES)
        {
            return Err(InventoryError::new(
                "regex-automata look-mode schema or payload seal mismatch",
            ));
        }
        validate_source(&self.payload.source)?;
        let snapshot_path = Path::new(&self.payload.snapshot_package_path);
        let mode_target_path = Path::new(&self.payload.mode_target_root);
        let execution_root = snapshot_path.parent().and_then(Path::parent);
        if self.payload.source_identity_sha256
            != hash_json(&self.payload.source, "encode look-mode source identity")?
            || self.payload.mode_contract_sha256 != REGEX_AUTOMATA_LOOK_MODE_CONTRACT_SHA256
            || self.payload.look_source_sha256 != LOOK_SOURCE_SHA256
            || self.payload.look_source_first_line != LOOK_SOURCE_FIRST_LINE
            || self.payload.look_source_last_line != LOOK_SOURCE_LAST_LINE
            || self.payload.look_span_sha256 != LOOK_SPAN_SHA256
            || self.payload.look_target_ids_sha256 != LOOK_TARGET_IDS_SHA256
            || self.payload.target_test_ids != look_test_ids()
            || !safe_absolute_path_text(&self.payload.snapshot_package_path)
            || !safe_absolute_path_text(&self.payload.mode_target_root)
            || snapshot_path.file_name().and_then(|name| name.to_str()) != Some("regex-automata")
            || snapshot_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                != Some("upstream-snapshot")
            || mode_target_path.file_name().and_then(|name| name.to_str()) != Some("mode-targets")
            || mode_target_path.parent() != execution_root
            || self.payload.local_feature_graph_sha256 != LOOK_FEATURE_GRAPH_SHA256
            || hash_json(
                &self.payload.local_feature_graph,
                "encode regex-automata local feature graph",
            )? != LOOK_FEATURE_GRAPH_SHA256
        {
            return Err(InventoryError::new(
                "regex-automata look-mode source or target authority mismatch",
            ));
        }
        validate_look_harness(&self.payload.harness)?;
        let specs = look_mode_specs();
        if self.payload.receipts.len() != LOOK_MODE_COUNT
            || self.payload.receipts.len() != specs.len()
        {
            return Err(InventoryError::new(
                "regex-automata look-mode receipt denominator mismatch",
            ));
        }
        for (receipt, spec) in self.payload.receipts.iter().zip(&specs) {
            validate_look_mode_receipt(
                receipt,
                spec,
                &self.payload.harness,
                &self.payload.snapshot_package_path,
                &self.payload.mode_target_root,
                &self.payload.local_feature_graph,
            )?;
        }
        if look_mode_contract_hash(&self.payload.receipts)
            != REGEX_AUTOMATA_LOOK_MODE_CONTRACT_SHA256
            || self.payload.counts != look_mode_counts(&self.payload.receipts)?
        {
            return Err(InventoryError::new(
                "regex-automata look-mode contract or counts mismatch",
            ));
        }
        Ok(())
    }
}

fn validate_look_harness(
    harness: &RegexAutomataLookModeHarnessIdentity,
) -> Result<(), InventoryError> {
    let inventory_harness = RegexAutomataHarnessIdentity {
        cargo_release: harness.inventory_cargo_release.clone(),
        cargo_executable_sha256: harness.inventory_cargo_executable_sha256.clone(),
        rustc_release: harness.inventory_rustc_release.clone(),
        rustc_executable_sha256: harness.inventory_rustc_executable_sha256.clone(),
        feature_script_modes: FEATURE_SCRIPT_MODES,
        supplemental_default_modes: SUPPLEMENTAL_DEFAULT_MODES,
        obligation_inventory_sha256: harness.inventory_obligation_sha256.clone(),
    };
    if !is_sha256(&harness.inventory_payload_sha256)
        || harness.inventory_obligation_sha256 != OBLIGATION_INVENTORY_SHA256
        || !is_sha256(&harness.inventory_harness_sha256)
        || hash_json(&inventory_harness, "encode inventory harness authority")?
            != harness.inventory_harness_sha256
        || !is_sha256(&harness.inventory_cargo_executable_sha256)
        || !is_sha256(&harness.inventory_rustc_executable_sha256)
        || !is_sha256(&harness.cargo_executable_sha256)
        || !is_sha256(&harness.rustc_verbose_sha256)
        || !is_sha256(&harness.rustc_executable_sha256)
        || sha256(harness.rustc_verbose.as_bytes()) != harness.rustc_verbose_sha256
        || parse_rustc_host(&harness.rustc_verbose)? != harness.rustc_host
        || harness.cargo_release.is_empty()
        || harness.rustc_release.is_empty()
        || harness.inventory_cargo_release != harness.cargo_release
        || harness.inventory_cargo_executable_sha256 != harness.cargo_executable_sha256
        || harness.inventory_rustc_release != harness.rustc_release
        || harness.inventory_rustc_executable_sha256 != harness.rustc_executable_sha256
        || harness.rustc_host != LOOK_INVENTORY_RUSTC_HOST
        || harness
            .rustc_verbose
            .lines()
            .next()
            .is_none_or(|line| line.trim() != harness.rustc_release)
        || !safe_absolute_path_text(&harness.cargo_path)
        || !safe_absolute_path_text(&harness.rustc_path)
    {
        return Err(InventoryError::new(
            "regex-automata look-mode harness identity mismatch",
        ));
    }
    Ok(())
}

fn validate_look_mode_receipt(
    receipt: &RegexAutomataLookModeReceipt,
    spec: &ModeSpec,
    harness: &RegexAutomataLookModeHarnessIdentity,
    snapshot_package_path: &str,
    mode_target_root: &str,
    feature_graph: &BTreeMap<String, Vec<String>>,
) -> Result<(), InventoryError> {
    if receipt.mode_id != spec.id
        || receipt.harness != RegexAutomataHarnessKind::Unit
        || receipt.harness != spec.harness
        || receipt.default_features != spec.default_features
        || receipt.all_features != spec.all_features
        || receipt.features != spec.features
        || receipt.inventory_members == 0
        || !is_sha256(&receipt.inventory_member_ids_sha256)
        || receipt.mode_tuple_sha256 != sha256(look_mode_contract_line(receipt).as_bytes())
    {
        return Err(InventoryError::new(
            "regex-automata look-mode tuple mismatch",
        ));
    }
    match &receipt.disposition {
        RegexAutomataLookModeDisposition::Available { .. } => {
            validate_available_look_mode_receipt(
                &receipt.disposition,
                spec,
                harness,
                snapshot_package_path,
                mode_target_root,
                feature_graph,
                receipt.inventory_members,
            )?;
        }
        RegexAutomataLookModeDisposition::Unavailable { .. } => {
            validate_unavailable_look_mode_receipt(
                &receipt.disposition,
                spec,
                harness,
                mode_target_root,
            )?;
        }
    }
    Ok(())
}

fn validate_available_look_mode_receipt(
    disposition: &RegexAutomataLookModeDisposition,
    spec: &ModeSpec,
    harness: &RegexAutomataLookModeHarnessIdentity,
    snapshot_package_path: &str,
    mode_target_root: &str,
    feature_graph: &BTreeMap<String, Vec<String>>,
    inventory_members: usize,
) -> Result<(), InventoryError> {
    let RegexAutomataLookModeDisposition::Available {
        resolved_features,
        resolved_features_sha256,
        compiled_artifact_path,
        artifact_path,
        artifact_bytes,
        artifact_sha256,
        build,
        runs,
        test_ids,
        test_ids_sha256,
    } = disposition
    else {
        return Err(InventoryError::new(
            "expected available regex-automata look-mode receipt",
        ));
    };
    let expected_features = expected_local_feature_closure(spec, feature_graph)?;
    let stable_artifact = Path::new(mode_target_root)
        .join(&spec.id)
        .join("authenticated-look-test");
    let exact_mode_target = Path::new(mode_target_root).join(&spec.id);
    if resolved_features != &expected_features
        || resolved_features_sha256 != &hash_line_list(&expected_features.into_iter().collect())
        || resolved_features.iter().any(|feature| !safe_atom(feature))
        || !safe_absolute_path_text(compiled_artifact_path)
        || !Path::new(compiled_artifact_path).starts_with(&exact_mode_target)
        || !safe_absolute_path_text(artifact_path)
        || Path::new(artifact_path) != stable_artifact
        || *artifact_bytes == 0
        || *artifact_bytes > MAX_LOOK_ARTIFACT_BYTES
        || !is_sha256(artifact_sha256)
        || !build.success
        || build.argv != expected_look_compile_argv(&harness.cargo_path, spec)
        || runs.len() != LOOK_TESTS_PER_MODE
        || test_ids != &look_test_ids()
        || test_ids_sha256 != &look_test_ids_hash()
    {
        return Err(InventoryError::new(
            "regex-automata available look-mode evidence mismatch",
        ));
    }
    validate_command_evidence(build)?;
    let parsed = parse_look_compiler_artifact_evidence(&build.stdout, snapshot_package_path)?;
    if parsed.0.as_slice() != resolved_features.as_slice()
        || parsed.1.as_str() != compiled_artifact_path
    {
        return Err(InventoryError::new(
            "regex-automata look-mode compiler evidence changed",
        ));
    }
    for (run, test_id) in runs.iter().zip(LOOK_TEST_IDS) {
        validate_command_evidence(run)?;
        let filtered = inventory_members
            .checked_sub(1)
            .ok_or_else(|| InventoryError::new("look-mode member count underflow"))?;
        if !run.success
            || run.argv != expected_look_run_argv(artifact_path, test_id)
            || parse_single_look_test_run(&run.stdout, test_id, filtered).is_err()
        {
            return Err(InventoryError::new(
                "regex-automata look-mode run evidence changed",
            ));
        }
    }
    Ok(())
}

fn validate_unavailable_look_mode_receipt(
    disposition: &RegexAutomataLookModeDisposition,
    spec: &ModeSpec,
    harness: &RegexAutomataLookModeHarnessIdentity,
    mode_target_root: &str,
) -> Result<(), InventoryError> {
    let RegexAutomataLookModeDisposition::Unavailable {
        stage,
        reason_code,
        detail_sha256,
        evidence_sha256,
        attempted_argv,
        command,
    } = disposition
    else {
        return Err(InventoryError::new(
            "expected unavailable regex-automata look-mode receipt",
        ));
    };
    let valid_stage_reason = matches!(
        (stage.as_str(), reason_code.as_str()),
        (
            "compile-spawn" | "execute-spawn",
            "look-mode-tool-unavailable"
        ) | ("compile-exit", "look-mode-compile-failed")
            | (
                "compile-output",
                "look-mode-build-evidence-invalid" | "look-mode-compile-output-overflow"
            )
            | ("compile-timeout", "look-mode-compile-timeout")
            | ("artifact-authentication", "look-mode-artifact-invalid")
            | ("execute-exit", "look-mode-execution-failed")
            | (
                "execute-output",
                "look-mode-test-evidence-invalid" | "look-mode-execution-output-overflow"
            )
            | ("execute-timeout", "look-mode-execution-timeout")
            | ("artifact-drift", "look-mode-artifact-changed")
    );
    if !valid_stage_reason
        || !is_sha256(detail_sha256)
        || !is_sha256(evidence_sha256)
        || attempted_argv.is_empty()
    {
        return Err(InventoryError::new(
            "regex-automata unavailable look-mode evidence mismatch",
        ));
    }
    let compile_stage = stage.starts_with("compile") || stage == "artifact-authentication";
    let expected_compile = expected_look_compile_argv(&harness.cargo_path, spec);
    let expected_run = LOOK_TEST_IDS
        .iter()
        .map(|test_id| {
            expected_look_run_argv(
                &Path::new(mode_target_root)
                    .join(&spec.id)
                    .join("authenticated-look-test")
                    .to_string_lossy(),
                test_id,
            )
        })
        .collect::<Vec<_>>();
    if (compile_stage && attempted_argv != &expected_compile)
        || (!compile_stage && !expected_run.contains(attempted_argv))
        || evidence_sha256
            != &unavailable_evidence_hash(
                &spec.id,
                stage,
                reason_code,
                detail_sha256,
                attempted_argv,
                command.as_ref(),
            )?
    {
        return Err(InventoryError::new(
            "regex-automata unavailable stage command mismatch",
        ));
    }
    if let Some(command) = command {
        validate_command_evidence(command)?;
        if command.argv.as_slice() != attempted_argv.as_slice() {
            return Err(InventoryError::new(
                "regex-automata unavailable command/attempt mismatch",
            ));
        }
        let expected_success = !stage.ends_with("exit");
        if command.success != expected_success {
            return Err(InventoryError::new(
                "regex-automata unavailable command status/stage mismatch",
            ));
        }
    } else if !stage.ends_with("spawn")
        && !stage.ends_with("output")
        && !stage.ends_with("timeout")
        && stage != "artifact-drift"
    {
        return Err(InventoryError::new(
            "regex-automata unavailable evidence omitted executed command",
        ));
    }
    Ok(())
}

fn validate_command_evidence(
    evidence: &RegexAutomataLookCommandEvidence,
) -> Result<(), InventoryError> {
    if evidence.argv.is_empty()
        || !safe_absolute_path_text(&evidence.argv[0])
        || evidence
            .argv
            .iter()
            .any(|value| value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()))
        || !is_sha256(&evidence.stdout_sha256)
        || !is_sha256(&evidence.stderr_sha256)
        || evidence.stdout_bytes != u64::try_from(evidence.stdout.len()).unwrap_or(u64::MAX)
        || evidence.stderr_bytes != u64::try_from(evidence.stderr.len()).unwrap_or(u64::MAX)
        || evidence.stdout.len() > REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES
        || evidence.stderr.len() > REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES
        || sha256(evidence.stdout.as_bytes()) != evidence.stdout_sha256
        || sha256(evidence.stderr.as_bytes()) != evidence.stderr_sha256
        || evidence.success != (evidence.exit_code == Some(0))
    {
        return Err(InventoryError::new(
            "regex-automata look-mode command evidence mismatch",
        ));
    }
    Ok(())
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
        let bytes = read_snapshot_regular_file(&workspace.join(&path), MAX_PACKAGE_FILE_BYTES)?;
        if u64::try_from(bytes.len()) != Ok(*expected_bytes) || sha256(&bytes) != *expected_sha256 {
            return Err(InventoryError::new(format!(
                "execution snapshot byte mismatch: {path}"
            )));
        }
    }
    Ok(())
}

fn seal_execution_snapshot(workspace: &Path) -> Result<(), InventoryError> {
    seal_snapshot_node(workspace)
}

fn seal_snapshot_node(path: &Path) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat snapshot node: {error}")))?;
    if metadata.file_type().is_symlink() || metadata.uid() != unsafe_free_euid() {
        return Err(InventoryError::new("snapshot node ownership/type mismatch"));
    }
    if metadata.file_type().is_file() {
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o7777 != 0o644 {
            return Err(InventoryError::new(
                "snapshot file is not an unshared writable staging file",
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .map_err(|error| InventoryError::new(format!("seal snapshot file: {error}")))?;
        return Ok(());
    }
    if !metadata.file_type().is_dir() {
        return Err(InventoryError::new("snapshot contains a non-file node"));
    }
    let mut children = fs::read_dir(path)
        .map_err(|error| InventoryError::new(format!("read snapshot directory: {error}")))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| InventoryError::new(format!("read snapshot entry: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    for child in children {
        seal_snapshot_node(&child)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
        .map_err(|error| InventoryError::new(format!("seal snapshot directory: {error}")))
}

fn validate_sealed_execution_snapshot(
    workspace: &Path,
    source: &RegexAutomataSourceIdentity,
) -> Result<(), InventoryError> {
    validate_execution_snapshot(workspace, source)?;
    validate_sealed_snapshot_node(workspace)
}

fn validate_sealed_snapshot_node(path: &Path) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat sealed snapshot node: {error}")))?;
    if metadata.file_type().is_symlink() || metadata.uid() != unsafe_free_euid() {
        return Err(InventoryError::new(
            "sealed snapshot node ownership/type mismatch",
        ));
    }
    if metadata.file_type().is_file() {
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o7777 != 0o400 {
            return Err(InventoryError::new("sealed snapshot file mode mismatch"));
        }
        return Ok(());
    }
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o7777 != 0o500 {
        return Err(InventoryError::new(
            "sealed snapshot directory mode mismatch",
        ));
    }
    let mut children = fs::read_dir(path)
        .map_err(|error| InventoryError::new(format!("read sealed snapshot directory: {error}")))?
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|error| {
                InventoryError::new(format!("read sealed snapshot entry: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    for child in children {
        validate_sealed_snapshot_node(&child)?;
    }
    Ok(())
}

fn read_snapshot_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, InventoryError> {
    if LOOK_O_NOFOLLOW == 0 {
        return Err(InventoryError::new(
            "snapshot O_NOFOLLOW is unavailable on this platform",
        ));
    }
    let before = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!("stat snapshot file {}: {error}", path.display()))
    })?;
    let mode = before.permissions().mode() & 0o7777;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != unsafe_free_euid()
        || before.nlink() != 1
        || !matches!(mode, 0o400 | 0o644)
        || before.len() > maximum
    {
        return Err(InventoryError::new(format!(
            "invalid snapshot file metadata: {}",
            path.display()
        )));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(LOOK_O_NOFOLLOW)
        .open(path)
        .map_err(|error| InventoryError::new(format!("open snapshot file: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat snapshot file: {error}")))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != before.uid()
        || opened.nlink() != before.nlink()
        || opened.permissions().mode() != before.permissions().mode()
        || opened.len() != before.len()
    {
        return Err(InventoryError::new(
            "snapshot file changed between lstat and open",
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| InventoryError::new("snapshot file length does not fit usize"))?,
    );
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| InventoryError::new(format!("read snapshot file: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat snapshot file after read: {error}")))?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.uid() != opened.uid()
        || after.nlink() != opened.nlink()
        || after.permissions().mode() != opened.permissions().mode()
        || after.len() != opened.len()
        || u64::try_from(bytes.len()) != Ok(opened.len())
        || u64::try_from(bytes.len()).is_ok_and(|length| length > maximum)
    {
        return Err(InventoryError::new(
            "snapshot file changed while being read",
        ));
    }
    Ok(bytes)
}

fn authenticate_snapshot_look_source(package: &Path) -> Result<(), InventoryError> {
    let bytes =
        read_snapshot_regular_file(&package.join("src/util/look.rs"), MAX_PACKAGE_FILE_BYTES)?;
    if sha256(&bytes) != LOOK_SOURCE_SHA256 {
        return Err(InventoryError::new("snapshot look.rs SHA-256 mismatch"));
    }
    let lines = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let span = lines
        .get(LOOK_SOURCE_FIRST_INDEX..LOOK_SOURCE_LAST_LINE)
        .ok_or_else(|| InventoryError::new("snapshot look.rs line span is absent"))?;
    let span = span
        .iter()
        .flat_map(|line| line.iter().copied())
        .collect::<Vec<_>>();
    if span.len() != 1_955 || sha256(&span) != LOOK_SPAN_SHA256 {
        return Err(InventoryError::new(
            "snapshot look.rs authenticated line span mismatch",
        ));
    }
    Ok(())
}

fn authenticated_local_feature_graph(
    package: &Path,
) -> Result<BTreeMap<String, Vec<String>>, InventoryError> {
    let bytes = read_snapshot_regular_file(&package.join("Cargo.toml"), MAX_PACKAGE_FILE_BYTES)?;
    parse_local_feature_graph(&bytes)
}

fn parse_local_feature_graph(
    bytes: &[u8],
) -> Result<BTreeMap<String, Vec<String>>, InventoryError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| InventoryError::new(format!("Cargo.toml is not UTF-8: {error}")))?;
    let manifest: toml::Value = toml::from_str(text)
        .map_err(|error| InventoryError::new(format!("parse Cargo.toml: {error}")))?;
    if manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        != Some(UPSTREAM_PACKAGE)
        || manifest
            .get("package")
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
            != Some(UPSTREAM_VERSION)
    {
        return Err(InventoryError::new("Cargo.toml package identity mismatch"));
    }
    let table = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| InventoryError::new("Cargo.toml feature graph is absent"))?;
    let mut graph = BTreeMap::new();
    for (feature, edges) in table {
        if !safe_atom(feature) {
            return Err(InventoryError::new("Cargo.toml feature name is invalid"));
        }
        let edges = edges
            .as_array()
            .ok_or_else(|| InventoryError::new("Cargo.toml feature edges are not an array"))?
            .iter()
            .map(|edge| {
                edge.as_str()
                    .filter(|edge| {
                        !edge.is_empty() && !edge.bytes().any(|byte| byte.is_ascii_control())
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| InventoryError::new("Cargo.toml feature edge is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if graph.insert(feature.clone(), edges).is_some() {
            return Err(InventoryError::new("duplicate Cargo.toml feature"));
        }
    }
    if hash_json(&graph, "encode regex-automata local feature graph")? != LOOK_FEATURE_GRAPH_SHA256
    {
        return Err(InventoryError::new(
            "Cargo.toml local feature graph seal mismatch",
        ));
    }
    Ok(graph)
}

fn expected_local_feature_closure(
    spec: &ModeSpec,
    graph: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>, InventoryError> {
    let mut pending = if spec.all_features {
        graph.keys().cloned().collect::<Vec<_>>()
    } else {
        let mut pending = spec.features.clone();
        if spec.default_features {
            pending.push("default".to_owned());
        }
        pending
    };
    let mut enabled = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !enabled.insert(feature.clone()) {
            continue;
        }
        let edges = graph
            .get(&feature)
            .ok_or_else(|| InventoryError::new("requested local Cargo feature is absent"))?;
        for edge in edges {
            if graph.contains_key(edge) {
                pending.push(edge.clone());
            }
        }
    }
    Ok(enabled.into_iter().collect())
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

fn look_mode_specs() -> Vec<ModeSpec> {
    mode_specs()
        .into_iter()
        .filter(|spec| spec.harness == RegexAutomataHarnessKind::Unit)
        .collect()
}

fn look_inventory_modes(
    inventory: &RegexAutomataCorpusReport,
) -> Result<Vec<RegexAutomataFeatureMode>, InventoryError> {
    let specs = look_mode_specs();
    let mut modes = Vec::with_capacity(LOOK_MODE_COUNT);
    for spec in &specs {
        let mode = inventory
            .payload
            .modes
            .iter()
            .find(|mode| mode.id == spec.id)
            .ok_or_else(|| InventoryError::new("look mode absent from corpus inventory"))?;
        if mode.harness != RegexAutomataHarnessKind::Unit
            || mode.default_features != spec.default_features
            || mode.all_features != spec.all_features
            || mode.features != spec.features
        {
            return Err(InventoryError::new(
                "look mode differs from corpus inventory",
            ));
        }
        let obligations = inventory
            .payload
            .obligations
            .iter()
            .filter(|row| row.mode_id == mode.id && row.harness == RegexAutomataHarnessKind::Unit)
            .map(|row| row.case_id.as_str())
            .collect::<BTreeSet<_>>();
        if LOOK_TEST_IDS.iter().any(|id| !obligations.contains(*id)) {
            return Err(InventoryError::new(
                "look target absent from authenticated mode membership",
            ));
        }
        modes.push(mode.clone());
    }
    let provisional = specs
        .iter()
        .zip(&modes)
        .map(|(spec, mode)| RegexAutomataLookModeReceipt {
            mode_id: spec.id.clone(),
            harness: spec.harness,
            default_features: spec.default_features,
            all_features: spec.all_features,
            features: spec.features.clone(),
            inventory_members: mode.members,
            inventory_member_ids_sha256: mode.member_ids_sha256.clone(),
            mode_tuple_sha256: String::new(),
            disposition: RegexAutomataLookModeDisposition::Unavailable {
                stage: "compile-spawn".to_owned(),
                reason_code: "look-mode-tool-unavailable".to_owned(),
                detail_sha256: sha256(b"contract-only"),
                evidence_sha256: sha256(b"contract-only"),
                attempted_argv: Vec::new(),
                command: None,
            },
        })
        .collect::<Vec<_>>();
    if look_mode_contract_hash(&provisional) != REGEX_AUTOMATA_LOOK_MODE_CONTRACT_SHA256 {
        return Err(InventoryError::new(
            "authenticated look-mode contract hash mismatch",
        ));
    }
    Ok(modes)
}

fn look_mode_contract_line(receipt: &RegexAutomataLookModeReceipt) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        receipt.mode_id,
        harness_slug(receipt.harness),
        receipt.default_features,
        receipt.all_features,
        receipt.features.join(","),
        receipt.inventory_members,
        receipt.inventory_member_ids_sha256,
    )
}

fn look_mode_contract_hash(receipts: &[RegexAutomataLookModeReceipt]) -> String {
    let mut bytes = Vec::new();
    for receipt in receipts {
        bytes.extend_from_slice(look_mode_contract_line(receipt).as_bytes());
    }
    sha256(&bytes)
}

fn look_test_ids() -> Vec<String> {
    LOOK_TEST_IDS.iter().map(|id| (*id).to_owned()).collect()
}

fn look_test_ids_hash() -> String {
    hash_line_list(&LOOK_TEST_IDS.iter().map(|id| (*id).to_owned()).collect())
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

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all authenticated inputs and the fail-closed mode transaction stay adjacent"
)]
fn execute_look_mode(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    spec: &ModeSpec,
    inventory_mode: &RegexAutomataFeatureMode,
    feature_graph: &BTreeMap<String, Vec<String>>,
) -> Result<RegexAutomataLookModeReceipt, InventoryError> {
    let compile_command = expected_look_compile_argv(&path_text(cargo, "cargo")?, spec);
    let compile_cli_args = compile_command
        .get(1..)
        .ok_or_else(|| InventoryError::new("look-mode compile argv is empty"))?;
    let compile =
        match sanitized_cargo_output(package, target, cargo_home, cargo, rustc, compile_cli_args) {
            Ok(output) => output,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Err(InventoryError::new(format!(
                        "look-mode compile cleanup did not reach quiescence: {error}"
                    )));
                }
                let (stage, reason_code) = match error.kind() {
                    std::io::ErrorKind::TimedOut => {
                        ("compile-timeout", "look-mode-compile-timeout")
                    }
                    std::io::ErrorKind::InvalidData => {
                        ("compile-output", "look-mode-compile-output-overflow")
                    }
                    _ => ("compile-spawn", "look-mode-tool-unavailable"),
                };
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    stage,
                    reason_code,
                    &error.to_string(),
                    compile_command,
                    None,
                );
            }
        };
    let compile_evidence = match command_evidence_record(compile_command.clone(), &compile) {
        Ok(evidence) => evidence,
        Err(error) => {
            return unavailable_look_mode_receipt(
                spec,
                inventory_mode,
                "compile-output",
                "look-mode-build-evidence-invalid",
                &format!(
                    "{}; raw_evidence_sha256={}",
                    error,
                    command_evidence(&compile)
                ),
                compile_command,
                None,
            );
        }
    };
    if !compile.status.success() {
        return unavailable_look_mode_receipt(
            spec,
            inventory_mode,
            "compile-exit",
            "look-mode-compile-failed",
            "cargo test --no-run returned nonzero",
            compile_command,
            Some(compile_evidence),
        );
    }
    let (resolved_features, artifact) =
        match parse_look_compiler_artifact(&compile_evidence.stdout, package, target) {
            Ok(parsed) => parsed,
            Err(error) => {
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    "compile-output",
                    "look-mode-build-evidence-invalid",
                    &error.to_string(),
                    compile_command,
                    Some(compile_evidence),
                );
            }
        };
    let expected_features = expected_local_feature_closure(spec, feature_graph)?;
    if resolved_features != expected_features {
        return unavailable_look_mode_receipt(
            spec,
            inventory_mode,
            "compile-output",
            "look-mode-build-evidence-invalid",
            "Cargo resolved feature closure differs from authenticated Cargo.toml graph",
            compile_command,
            Some(compile_evidence),
        );
    }
    let (compiled_artifact_path, compiled_artifact_bytes, compiled_artifact_sha256) =
        match authenticate_look_artifact(&artifact, target) {
            Ok(identity) => identity,
            Err(error) => {
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    "artifact-authentication",
                    "look-mode-artifact-invalid",
                    &error.to_string(),
                    compile_command,
                    Some(compile_evidence),
                );
            }
        };
    let stable_artifact = target.join("authenticated-look-test");
    let authenticated_artifact =
        match install_stable_look_artifact(&artifact, &stable_artifact, target) {
            Ok(identity) => identity,
            Err(error) => {
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    "artifact-authentication",
                    "look-mode-artifact-invalid",
                    &error.to_string(),
                    compile_command,
                    Some(compile_evidence),
                );
            }
        };
    let artifact_path = authenticated_artifact.logical_path.clone();
    let artifact_bytes = authenticated_artifact.bytes;
    let artifact_sha256 = authenticated_artifact.sha256.clone();
    if artifact_bytes != compiled_artifact_bytes || artifact_sha256 != compiled_artifact_sha256 {
        return unavailable_look_mode_receipt(
            spec,
            inventory_mode,
            "artifact-authentication",
            "look-mode-artifact-invalid",
            "stable executable copy differs from authenticated Cargo artifact",
            compile_command,
            Some(compile_evidence),
        );
    }
    let mut runs = Vec::with_capacity(LOOK_TESTS_PER_MODE);
    for test_id in LOOK_TEST_IDS {
        let test_command = expected_look_run_argv(&artifact_path, test_id);
        let test_cli_args = test_command
            .get(1..)
            .ok_or_else(|| InventoryError::new("look-mode run argv is empty"))?;
        if let Err(error) = authenticate_held_look_artifact(&authenticated_artifact) {
            return unavailable_look_mode_receipt(
                spec,
                inventory_mode,
                "artifact-drift",
                "look-mode-artifact-changed",
                &error.to_string(),
                test_command,
                None,
            );
        }
        let run = match sanitized_direct_output(package, &authenticated_artifact, test_cli_args) {
            Ok(output) => output,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Err(InventoryError::new(format!(
                        "look-mode execution cleanup did not reach quiescence: {error}"
                    )));
                }
                let (stage, reason_code) = match error.kind() {
                    std::io::ErrorKind::TimedOut => {
                        ("execute-timeout", "look-mode-execution-timeout")
                    }
                    std::io::ErrorKind::InvalidData => {
                        ("execute-output", "look-mode-execution-output-overflow")
                    }
                    _ => ("execute-spawn", "look-mode-tool-unavailable"),
                };
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    stage,
                    reason_code,
                    &error.to_string(),
                    test_command,
                    None,
                );
            }
        };
        let run_evidence = match command_evidence_record(test_command.clone(), &run) {
            Ok(evidence) => evidence,
            Err(error) => {
                return unavailable_look_mode_receipt(
                    spec,
                    inventory_mode,
                    "execute-output",
                    "look-mode-test-evidence-invalid",
                    &format!("{}; raw_evidence_sha256={}", error, command_evidence(&run)),
                    test_command,
                    None,
                );
            }
        };
        if !run.status.success() {
            return unavailable_look_mode_receipt(
                spec,
                inventory_mode,
                "execute-exit",
                "look-mode-execution-failed",
                "direct exact look-mode test execution returned nonzero",
                test_command,
                Some(run_evidence),
            );
        }
        let filtered = inventory_mode
            .members
            .checked_sub(1)
            .ok_or_else(|| InventoryError::new("look-mode member count underflow"))?;
        if let Err(error) = parse_single_look_test_run(&run_evidence.stdout, test_id, filtered) {
            return unavailable_look_mode_receipt(
                spec,
                inventory_mode,
                "execute-output",
                "look-mode-test-evidence-invalid",
                &error.to_string(),
                test_command,
                Some(run_evidence),
            );
        }
        if let Err(error) = authenticate_held_look_artifact(&authenticated_artifact) {
            return unavailable_look_mode_receipt(
                spec,
                inventory_mode,
                "artifact-drift",
                "look-mode-artifact-changed",
                &error.to_string(),
                test_command,
                Some(run_evidence),
            );
        }
        runs.push(run_evidence);
    }
    let resolved_features_sha256 = hash_line_list(&resolved_features.iter().cloned().collect());
    let disposition = RegexAutomataLookModeDisposition::Available {
        resolved_features,
        resolved_features_sha256,
        compiled_artifact_path,
        artifact_path,
        artifact_bytes,
        artifact_sha256,
        build: compile_evidence,
        runs,
        test_ids: look_test_ids(),
        test_ids_sha256: look_test_ids_hash(),
    };
    Ok(make_look_mode_receipt(spec, inventory_mode, disposition))
}

fn make_look_mode_receipt(
    spec: &ModeSpec,
    inventory_mode: &RegexAutomataFeatureMode,
    disposition: RegexAutomataLookModeDisposition,
) -> RegexAutomataLookModeReceipt {
    let mut receipt = RegexAutomataLookModeReceipt {
        mode_id: spec.id.clone(),
        harness: spec.harness,
        default_features: spec.default_features,
        all_features: spec.all_features,
        features: spec.features.clone(),
        inventory_members: inventory_mode.members,
        inventory_member_ids_sha256: inventory_mode.member_ids_sha256.clone(),
        mode_tuple_sha256: String::new(),
        disposition,
    };
    receipt.mode_tuple_sha256 = sha256(look_mode_contract_line(&receipt).as_bytes());
    receipt
}

fn unavailable_look_mode_receipt(
    spec: &ModeSpec,
    inventory_mode: &RegexAutomataFeatureMode,
    stage: &str,
    reason_code: &str,
    detail: &str,
    attempted_argv: Vec<String>,
    command: Option<RegexAutomataLookCommandEvidence>,
) -> Result<RegexAutomataLookModeReceipt, InventoryError> {
    let detail_sha256 = sha256(detail.as_bytes());
    let evidence_sha256 = unavailable_evidence_hash(
        &spec.id,
        stage,
        reason_code,
        &detail_sha256,
        &attempted_argv,
        command.as_ref(),
    )?;
    Ok(make_look_mode_receipt(
        spec,
        inventory_mode,
        RegexAutomataLookModeDisposition::Unavailable {
            stage: stage.to_owned(),
            reason_code: reason_code.to_owned(),
            detail_sha256,
            evidence_sha256,
            attempted_argv,
            command,
        },
    ))
}

fn unavailable_evidence_hash(
    mode_id: &str,
    stage: &str,
    reason_code: &str,
    detail_sha256: &str,
    attempted_argv: &[String],
    command: Option<&RegexAutomataLookCommandEvidence>,
) -> Result<String, InventoryError> {
    hash_json(
        &(
            mode_id,
            stage,
            reason_code,
            detail_sha256,
            attempted_argv,
            command,
        ),
        "encode unavailable look-mode evidence",
    )
}

fn expected_look_compile_argv(cargo_path: &str, spec: &ModeSpec) -> Vec<String> {
    let mut argv = vec![
        cargo_path.to_owned(),
        "test".to_owned(),
        "--offline".to_owned(),
        "--locked".to_owned(),
        "--lib".to_owned(),
        "--no-run".to_owned(),
        "--message-format=json".to_owned(),
    ];
    if spec.all_features {
        argv.push("--all-features".to_owned());
    } else if !spec.default_features {
        argv.push("--no-default-features".to_owned());
        if !spec.features.is_empty() {
            argv.push("--features".to_owned());
            argv.push(spec.features.join(","));
        }
    }
    argv
}

fn expected_look_run_argv(artifact_path: &str, test_id: &str) -> Vec<String> {
    vec![
        artifact_path.to_owned(),
        test_id.to_owned(),
        "--exact".to_owned(),
        "--test-threads=1".to_owned(),
        "--nocapture".to_owned(),
    ]
}

fn parse_look_compiler_artifact(
    stdout: &str,
    package: &Path,
    target: &Path,
) -> Result<(Vec<String>, PathBuf), InventoryError> {
    let package_text = path_text(package, "look-mode snapshot package")?;
    let (features, artifact_text) = parse_look_compiler_artifact_evidence(stdout, &package_text)?;
    let artifact = PathBuf::from(artifact_text);
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize mode target: {error}")))?;
    let artifact = artifact
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize test artifact: {error}")))?;
    if !artifact.starts_with(&target) {
        return Err(InventoryError::new(
            "Cargo test artifact escaped its isolated mode target",
        ));
    }
    Ok((features, artifact))
}

#[allow(
    clippy::too_many_lines,
    reason = "the exact Cargo artifact JSON contract is reviewed as one transaction"
)]
fn parse_look_compiler_artifact_evidence(
    stdout: &str,
    snapshot_package_path: &str,
) -> Result<(Vec<String>, String), InventoryError> {
    let expected_package_id = format!("path+file://{snapshot_package_path}#{UPSTREAM_VERSION}");
    let expected_source = Path::new(snapshot_package_path).join("src/lib.rs");
    let expected_source = path_text(&expected_source, "regex-automata lib target")?;
    let mut artifacts = Vec::new();
    let mut build_finished = 0_usize;
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| InventoryError::new(format!("invalid Cargo JSON line: {error}")))?;
        match value.get("reason").and_then(serde_json::Value::as_str) {
            Some("compiler-artifact") => {
                let package_id = value.get("package_id").and_then(serde_json::Value::as_str);
                let target_value = value
                    .get("target")
                    .ok_or_else(|| InventoryError::new("Cargo artifact has no target"))?;
                let target_name = target_value.get("name").and_then(serde_json::Value::as_str);
                let kind = target_value
                    .get("kind")
                    .and_then(serde_json::Value::as_array);
                let crate_types = target_value
                    .get("crate_types")
                    .and_then(serde_json::Value::as_array);
                let source_path = target_value
                    .get("src_path")
                    .and_then(serde_json::Value::as_str);
                let target_test = target_value
                    .get("test")
                    .and_then(serde_json::Value::as_bool);
                let target_doc = target_value.get("doc").and_then(serde_json::Value::as_bool);
                let target_doctest = target_value
                    .get("doctest")
                    .and_then(serde_json::Value::as_bool);
                let target_edition = target_value
                    .get("edition")
                    .and_then(serde_json::Value::as_str);
                let profile = value.get("profile");
                let profile_test = profile
                    .and_then(|profile| profile.get("test"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let profile_debug_assertions = profile
                    .and_then(|profile| profile.get("debug_assertions"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let profile_overflow_checks = profile
                    .and_then(|profile| profile.get("overflow_checks"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let profile_opt_level = profile
                    .and_then(|profile| profile.get("opt_level"))
                    .and_then(serde_json::Value::as_str)
                    == Some("0");
                let Some(executable) = value.get("executable").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let exact_lib = kind
                    .is_some_and(|items| items.len() == 1 && items[0].as_str() == Some("lib"))
                    && crate_types
                        .is_some_and(|items| items.len() == 1 && items[0].as_str() == Some("lib"));
                if package_id == Some(expected_package_id.as_str())
                    && target_name == Some("regex_automata")
                    && exact_lib
                    && source_path == Some(expected_source.as_str())
                    && target_test == Some(true)
                    && target_doc == Some(true)
                    && target_doctest == Some(true)
                    && target_edition == Some("2021")
                    && profile_test
                    && profile_debug_assertions
                    && profile_overflow_checks
                    && profile_opt_level
                {
                    let mut features = value
                        .get("features")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| InventoryError::new("Cargo artifact has no feature list"))?
                        .iter()
                        .map(|feature| {
                            feature.as_str().map(str::to_owned).ok_or_else(|| {
                                InventoryError::new("Cargo artifact feature is not text")
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    features.sort();
                    if features.windows(2).any(|pair| pair[0] == pair[1])
                        || features.iter().any(|feature| !safe_atom(feature))
                    {
                        return Err(InventoryError::new(
                            "Cargo artifact feature list is invalid",
                        ));
                    }
                    if !safe_absolute_path_text(executable) {
                        return Err(InventoryError::new(
                            "Cargo lib-test executable path is invalid",
                        ));
                    }
                    artifacts.push((features, executable.to_owned()));
                }
            }
            Some("build-finished") => {
                if value.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(InventoryError::new(
                        "Cargo build-finished was not successful",
                    ));
                }
                build_finished = build_finished
                    .checked_add(1)
                    .ok_or_else(|| InventoryError::new("Cargo build-finished count overflow"))?;
            }
            Some("compiler-message" | "build-script-executed") => {}
            Some(_) | None => {
                return Err(InventoryError::new("unexpected Cargo JSON message kind"));
            }
        }
    }
    if artifacts.len() != 1 || build_finished != 1 {
        return Err(InventoryError::new(
            "Cargo output did not identify exactly one lib-test artifact",
        ));
    }
    Ok(artifacts.pop().expect("length checked"))
}

fn authenticate_look_artifact(
    artifact: &Path,
    target: &Path,
) -> Result<(String, u64, String), InventoryError> {
    let (path, bytes, sha256, _) = read_authenticated_look_artifact(artifact, target)?;
    Ok((path, bytes, sha256))
}

fn read_authenticated_look_artifact(
    artifact: &Path,
    target: &Path,
) -> Result<(String, u64, String, Vec<u8>), InventoryError> {
    if LOOK_O_NOFOLLOW == 0 {
        return Err(InventoryError::new(
            "look artifact O_NOFOLLOW is unavailable on this platform",
        ));
    }
    let before = fs::symlink_metadata(artifact)
        .map_err(|error| InventoryError::new(format!("lstat look test artifact: {error}")))?;
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize mode target: {error}")))?;
    let canonical = artifact.canonicalize().map_err(|error| {
        InventoryError::new(format!("canonicalize look test artifact: {error}"))
    })?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != unsafe_free_euid()
        || before.nlink() != 1
        || before.permissions().mode() & 0o111 == 0
        || before.len() == 0
        || before.len() > MAX_LOOK_ARTIFACT_BYTES
        || canonical.as_path() != artifact
        || !canonical.starts_with(target)
    {
        return Err(InventoryError::new("look test artifact metadata mismatch"));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(LOOK_O_NOFOLLOW)
        .open(&canonical)
        .map_err(|error| InventoryError::new(format!("open look test artifact: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat look test artifact: {error}")))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != before.uid()
        || opened.nlink() != before.nlink()
        || opened.len() != before.len()
        || opened.permissions().mode() != before.permissions().mode()
    {
        return Err(InventoryError::new(
            "look test artifact changed between lstat and open",
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| InventoryError::new("look artifact length does not fit usize"))?,
    );
    std::io::Read::by_ref(&mut file)
        .take(MAX_LOOK_ARTIFACT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| InventoryError::new(format!("read look test artifact: {error}")))?;
    let after = file.metadata().map_err(|error| {
        InventoryError::new(format!("fstat look test artifact after read: {error}"))
    })?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || u64::try_from(bytes.len()) != Ok(opened.len())
        || bytes.len() > usize::try_from(MAX_LOOK_ARTIFACT_BYTES).unwrap_or(usize::MAX)
    {
        return Err(InventoryError::new(
            "look test artifact changed while being read",
        ));
    }
    Ok((
        path_text(&canonical, "look test artifact")?,
        opened.len(),
        sha256(&bytes),
        bytes,
    ))
}

fn install_stable_look_artifact(
    source: &Path,
    destination: &Path,
    target: &Path,
) -> Result<AuthenticatedLookArtifact, InventoryError> {
    let (_, source_bytes, source_sha256, bytes) = read_authenticated_look_artifact(source, target)?;
    if !bytes.starts_with(b"\x7fELF") {
        return Err(InventoryError::new(
            "look test artifact is not a native ELF image",
        ));
    }
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o500)
        .custom_flags(LOOK_O_NOFOLLOW)
        .open(destination)
        .map_err(|error| InventoryError::new(format!("create stable look artifact: {error}")))?;
    output
        .write_all(&bytes)
        .map_err(|error| InventoryError::new(format!("write stable look artifact: {error}")))?;
    output
        .sync_all()
        .map_err(|error| InventoryError::new(format!("sync stable look artifact: {error}")))?;
    drop(output);
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500))
        .map_err(|error| InventoryError::new(format!("seal stable look artifact: {error}")))?;
    let logical_path = path_text(destination, "stable look artifact")?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(LOOK_O_NOFOLLOW)
        .open(destination)
        .map_err(|error| InventoryError::new(format!("open stable look artifact: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat stable look artifact: {error}")))?;
    let copied = read_held_look_artifact(&file, metadata.len())?;
    if metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o500
        || metadata.len() != source_bytes
        || sha256(&copied) != source_sha256
    {
        return Err(InventoryError::new(
            "stable look artifact differs from source artifact",
        ));
    }
    fs::remove_file(destination)
        .map_err(|error| InventoryError::new(format!("unlink stable look artifact: {error}")))?;
    let parent = destination
        .parent()
        .ok_or_else(|| InventoryError::new("stable look artifact has no parent"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| InventoryError::new(format!("sync stable artifact parent: {error}")))?;
    let artifact = AuthenticatedLookArtifact {
        logical_path,
        file,
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode(),
        bytes: metadata.len(),
        sha256: source_sha256,
    };
    authenticate_held_look_artifact(&artifact)?;
    Ok(artifact)
}

struct AuthenticatedLookArtifact {
    logical_path: String,
    file: fs::File,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    bytes: u64,
    sha256: String,
}

fn authenticate_held_look_artifact(
    artifact: &AuthenticatedLookArtifact,
) -> Result<(), InventoryError> {
    let metadata = artifact
        .file
        .metadata()
        .map_err(|error| InventoryError::new(format!("fstat held look artifact: {error}")))?;
    if metadata.dev() != artifact.dev
        || metadata.ino() != artifact.ino
        || metadata.uid() != artifact.uid
        || metadata.nlink() != 0
        || metadata.permissions().mode() != artifact.mode
        || metadata.len() != artifact.bytes
    {
        return Err(InventoryError::new("held look artifact metadata changed"));
    }
    let bytes = read_held_look_artifact(&artifact.file, artifact.bytes)?;
    if sha256(&bytes) != artifact.sha256 {
        return Err(InventoryError::new("held look artifact bytes changed"));
    }
    Ok(())
}

fn read_held_look_artifact(file: &fs::File, length: u64) -> Result<Vec<u8>, InventoryError> {
    if length == 0 || length > MAX_LOOK_ARTIFACT_BYTES {
        return Err(InventoryError::new("held look artifact length is invalid"));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| InventoryError::new("held look artifact length does not fit usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    while offset < length {
        let remaining = usize::try_from(length.saturating_sub(offset))
            .map_err(|_| InventoryError::new("held artifact remainder does not fit usize"))?
            .min(buffer.len());
        let read = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|error| InventoryError::new(format!("read held look artifact: {error}")))?;
        if read == 0 {
            return Err(InventoryError::new(
                "held look artifact ended before authenticated length",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        offset = offset
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| InventoryError::new("held artifact read does not fit u64"))?,
            )
            .ok_or_else(|| InventoryError::new("held artifact offset overflow"))?;
    }
    Ok(bytes)
}

fn parse_single_look_test_run(
    stdout: &str,
    expected_test_id: &str,
    expected_filtered: usize,
) -> Result<(), InventoryError> {
    let prefix = format!(
        "\nrunning 1 test\ntest {expected_test_id} ... ok\n\n\
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; \
{expected_filtered} filtered out; finished in ",
    );
    let Some(duration) = stdout
        .strip_prefix(prefix.as_str())
        .and_then(|rest| rest.strip_suffix("s\n"))
    else {
        return Err(InventoryError::new(
            "look test execution did not prove exactly one named pass",
        ));
    };
    let Some((whole, fractional)) = duration.split_once('.') else {
        return Err(InventoryError::new(
            "look test duration lacks decimal point",
        ));
    };
    if whole.is_empty()
        || fractional.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InventoryError::new("look test duration is malformed"));
    }
    Ok(())
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

fn look_mode_counts(
    receipts: &[RegexAutomataLookModeReceipt],
) -> Result<RegexAutomataLookModeCounts, InventoryError> {
    let available_modes = receipts
        .iter()
        .filter(|receipt| {
            matches!(
                &receipt.disposition,
                RegexAutomataLookModeDisposition::Available { .. }
            )
        })
        .count();
    let unavailable_modes = receipts
        .len()
        .checked_sub(available_modes)
        .ok_or_else(|| InventoryError::new("look-mode count underflow"))?;
    let available_test_memberships = available_modes
        .checked_mul(LOOK_TESTS_PER_MODE)
        .ok_or_else(|| InventoryError::new("look-mode membership count overflow"))?;
    Ok(RegexAutomataLookModeCounts {
        modes: receipts.len(),
        available_modes,
        unavailable_modes,
        tests_per_mode: LOOK_TESTS_PER_MODE,
        available_test_memberships,
        total_test_memberships: LOOK_TEST_MEMBERSHIPS,
    })
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
        .env("RUSTC", rustc);
    supervised_command_output_with_limit(
        &mut command,
        LOOK_COMPILE_TIMEOUT,
        usize::try_from(MAX_PACKAGE_FILE_BYTES).unwrap_or(usize::MAX),
    )
}

fn sanitized_cargo_output(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    args: &[String],
) -> std::io::Result<Output> {
    let temporary = target.join("tmp");
    fs::create_dir(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let mut command = Command::new(cargo);
    command
        .args(args)
        .current_dir(package)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", cargo_home)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC", rustc)
        .env("RUST_BACKTRACE", "0")
        .env("TMPDIR", temporary);
    supervised_command_output(&mut command, LOOK_COMPILE_TIMEOUT)
}

fn sanitized_direct_output(
    package: &Path,
    executable: &AuthenticatedLookArtifact,
    args: &[String],
) -> std::io::Result<Output> {
    let descriptor_path = format!("/proc/self/fd/{}", executable.file.as_raw_fd());
    let mut command = Command::new(&descriptor_path);
    command
        .arg0(&executable.logical_path)
        .args(args)
        .current_dir(package)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RUST_BACKTRACE", "0");
    supervised_command_output(&mut command, LOOK_TEST_TIMEOUT)
}

struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn supervised_command_output(command: &mut Command, timeout: Duration) -> std::io::Result<Output> {
    supervised_command_output_with_limit(
        command,
        timeout,
        REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES,
    )
}

fn supervised_command_output_with_limit(
    command: &mut Command,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> std::io::Result<Output> {
    if maximum_output_bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "supervised command output bound is zero",
        ));
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let process_group = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("supervised child stdout is absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("supervised child stderr is absent"))?;
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader =
        spawn_bounded_pipe_reader(stdout, Arc::clone(&output_exceeded), maximum_output_bytes);
    let stderr_reader =
        spawn_bounded_pipe_reader(stderr, Arc::clone(&output_exceeded), maximum_output_bytes);
    let started = Instant::now();
    let mut status: Option<ExitStatus> = None;
    loop {
        if output_exceeded.load(Ordering::Acquire) {
            cleanup_supervised_failure(
                &mut child,
                process_group,
                status.is_some(),
                stdout_reader,
                stderr_reader,
            )?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "supervised command output exceeded retained bound",
            ));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(observed)) => status = Some(observed),
                Ok(None) => {}
                Err(error) => {
                    cleanup_supervised_failure(
                        &mut child,
                        process_group,
                        false,
                        stdout_reader,
                        stderr_reader,
                    )?;
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!("poll supervised command: {error}"),
                    ));
                }
            }
        }
        if status.is_some() && stdout_reader.is_finished() && stderr_reader.is_finished() {
            break;
        }
        if started.elapsed() >= timeout {
            cleanup_supervised_failure(
                &mut child,
                process_group,
                status.is_some(),
                stdout_reader,
                stderr_reader,
            )?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "supervised command exceeded monotonic deadline",
            ));
        }
        thread::sleep(LOOK_CHILD_POLL);
    }
    let stdout = join_bounded_pipe(stdout_reader)?;
    let stderr = join_bounded_pipe(stderr_reader)?;
    if stdout.exceeded || stderr.exceeded {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "supervised command output exceeded retained bound",
        ));
    }
    Ok(Output {
        status: status.ok_or_else(|| {
            std::io::Error::other("supervised command completed without an exit status")
        })?,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn spawn_bounded_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    exceeded: Arc<AtomicBool>,
    maximum: usize,
) -> thread::JoinHandle<std::io::Result<BoundedPipe>> {
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(maximum.min(16 * 1024));
        let mut buffer = [0_u8; 8 * 1024];
        let mut over_limit = false;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let retained = maximum.saturating_sub(bytes.len()).min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            if retained != read {
                over_limit = true;
                exceeded.store(true, Ordering::Release);
            }
        }
        Ok(BoundedPipe {
            bytes,
            exceeded: over_limit,
        })
    })
}

fn join_bounded_pipe(
    reader: thread::JoinHandle<std::io::Result<BoundedPipe>>,
) -> std::io::Result<BoundedPipe> {
    reader
        .join()
        .map_err(|_| std::io::Error::other("supervised pipe reader panicked"))?
}

fn terminate_process_group_and_reap(
    child: &mut Child,
    process_group: u32,
    mut child_reaped: bool,
) -> std::io::Result<()> {
    let mut first_error = bounded_signal_process_group(process_group, "-TERM").err();
    let grace_started = Instant::now();
    while grace_started.elapsed() < LOOK_TERMINATE_GRACE {
        if !child_reaped {
            match child.try_wait() {
                Ok(Some(_)) => child_reaped = true,
                Ok(None) => {}
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        thread::sleep(LOOK_CHILD_POLL);
    }
    if let Err(error) = bounded_signal_process_group(process_group, "-KILL")
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    if !child_reaped {
        let _ = child.kill();
        if let Err(error) = child.wait()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn bounded_signal_process_group(process_group: u32, signal: &str) -> std::io::Result<()> {
    let process_group = format!("-{process_group}");
    let mut signaler = Command::new("/bin/kill")
        .args([signal, "--", process_group.as_str()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    loop {
        if signaler.try_wait()?.is_some() {
            // A nonzero exit is expected when TERM already emptied the group.
            // Quiescence is proved separately by both pipe readers reaching
            // EOF; a failed signal with a live pipe holder therefore cannot
            // be mistaken for successful cleanup.
            return Ok(());
        }
        if started.elapsed() >= LOOK_SIGNAL_TIMEOUT {
            let _ = signaler.kill();
            let _ = signaler.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "process-group signal command exceeded monotonic deadline",
            ));
        }
        thread::sleep(LOOK_CHILD_POLL);
    }
}

fn cleanup_supervised_failure(
    child: &mut Child,
    process_group: u32,
    child_reaped: bool,
    stdout_reader: thread::JoinHandle<std::io::Result<BoundedPipe>>,
    stderr_reader: thread::JoinHandle<std::io::Result<BoundedPipe>>,
) -> std::io::Result<()> {
    terminate_process_group_and_reap(child, process_group, child_reaped).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("supervised process-group cleanup failed: {error}"),
        )
    })?;
    let started = Instant::now();
    while started.elapsed() < LOOK_PIPE_DRAIN_GRACE
        && (!stdout_reader.is_finished() || !stderr_reader.is_finished())
    {
        thread::sleep(LOOK_CHILD_POLL);
    }
    if !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "supervised pipe holders survived process-group cleanup",
        ));
    }
    join_bounded_pipe(stdout_reader).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("supervised stdout cleanup failed: {error}"),
        )
    })?;
    join_bounded_pipe(stderr_reader).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("supervised stderr cleanup failed: {error}"),
        )
    })?;
    Ok(())
}

fn canonical_tool(tool: &str) -> Result<PathBuf, InventoryError> {
    let path = resolve_tool(tool)?;
    let canonical = path
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize {tool}: {error}")))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| InventoryError::new(format!("stat {tool}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(InventoryError::new(format!(
            "resolved {tool} is not an owned executable file"
        )));
    }
    Ok(canonical)
}

fn sanitized_tool_release(
    tool: &Path,
    name: &str,
    verbose: bool,
) -> Result<String, InventoryError> {
    let mut command = Command::new(tool);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("--version");
    if verbose {
        command.arg("--verbose");
    }
    let output = supervised_command_output(&mut command, LOOK_TOOL_TIMEOUT)
        .map_err(|error| InventoryError::new(format!("execute {name} --version: {error}")))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(InventoryError::new(format!(
            "sanitized {name} --version failed"
        )));
    }
    let release = std::str::from_utf8(&output.stdout)
        .map_err(|error| InventoryError::new(format!("{name} version is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if release.is_empty()
        || release
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && byte != b'\n'))
    {
        return Err(InventoryError::new(format!(
            "invalid sanitized {name} release"
        )));
    }
    Ok(release)
}

fn parse_rustc_host(verbose: &str) -> Result<String, InventoryError> {
    let mut host = None;
    for line in verbose.lines() {
        let Some(value) = line.strip_prefix("host: ") else {
            continue;
        };
        if host.replace(value.to_owned()).is_some() || !safe_atom(value) {
            return Err(InventoryError::new("invalid duplicate rustc host"));
        }
    }
    host.ok_or_else(|| InventoryError::new("rustc verbose output has no host"))
}

fn command_evidence_record(
    argv: Vec<String>,
    output: &Output,
) -> Result<RegexAutomataLookCommandEvidence, InventoryError> {
    if output.stdout.len() > REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES
        || output.stderr.len() > REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES
    {
        return Err(InventoryError::new(
            "look-mode command output exceeds retained evidence bound",
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| InventoryError::new(format!("command stdout is not UTF-8: {error}")))?
        .to_owned();
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|error| InventoryError::new(format!("command stderr is not UTF-8: {error}")))?
        .to_owned();
    Ok(RegexAutomataLookCommandEvidence {
        argv,
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout_bytes: u64::try_from(output.stdout.len())
            .map_err(|_| InventoryError::new("command stdout length does not fit u64"))?,
        stdout_sha256: sha256(&output.stdout),
        stdout,
        stderr_bytes: u64::try_from(output.stderr.len())
            .map_err(|_| InventoryError::new("command stderr length does not fit u64"))?,
        stderr_sha256: sha256(&output.stderr),
        stderr,
    })
}

fn path_text(path: &Path, label: &str) -> Result<String, InventoryError> {
    path.to_str()
        .filter(|text| safe_absolute_path_text(text))
        .map(str::to_owned)
        .ok_or_else(|| InventoryError::new(format!("invalid absolute {label} path")))
}

fn safe_absolute_path_text(value: &str) -> bool {
    Path::new(value).is_absolute()
        && !value.is_empty()
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && Path::new(value).components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
    let mut command = Command::new(tool);
    command.arg("--version");
    let output = supervised_command_output(&mut command, LOOK_TOOL_TIMEOUT)
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
    command
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    let output = supervised_command_output_with_limit(
        &mut command,
        LOOK_TOOL_TIMEOUT,
        usize::try_from(MAX_PACKAGE_FILE_BYTES).unwrap_or(usize::MAX),
    )
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
        let mut command = Command::new("/usr/bin/id");
        command.arg("-u").env_clear();
        supervised_command_output_with_limit(&mut command, LOOK_TOOL_TIMEOUT, 64)
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
    fn look_normalized_manifest_uses_the_document_parser() {
        const MANIFEST: &[u8] = include_bytes!("fixtures/regex-automata-0.4.14-Cargo.toml");
        assert_eq!(sha256(MANIFEST), LOOK_NORMALIZED_MANIFEST_SHA256);
        let graph = parse_local_feature_graph(MANIFEST).unwrap();
        assert_eq!(
            hash_json(&graph, "encode normalized-manifest test graph").unwrap(),
            LOOK_FEATURE_GRAPH_SHA256,
        );
        assert_eq!(
            graph.get("default").unwrap(),
            &[
                "std", "syntax", "perf", "unicode", "meta", "nfa", "dfa", "hybrid",
            ],
        );
    }

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

    #[test]
    fn look_mode_specs_are_the_exact_unit_projection() {
        let specs = look_mode_specs();
        assert_eq!(specs.len(), LOOK_MODE_COUNT);
        assert_eq!(specs[0].id, "package-default-unit");
        assert_eq!(specs[1].id, "vcs-all-features-unit");
        assert_eq!(specs[2].id, "vcs-lib-00");
        assert_eq!(specs[29].id, "vcs-lib-27");
        assert!(
            specs
                .iter()
                .all(|spec| spec.harness == RegexAutomataHarnessKind::Unit)
        );
        assert!(is_sha256(&look_test_ids_hash()));
    }

    #[test]
    fn look_test_output_parser_requires_one_exact_named_pass() {
        let case_id = "util::look::tests::look_matches_end_line";
        let good = "\nrunning 1 test\n\
test util::look::tests::look_matches_end_line ... ok\n\n\
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 134 filtered out; finished in 0.00s\n";
        parse_single_look_test_run(good, case_id, 134).unwrap();
        assert!(
            parse_single_look_test_run(&good.replace("... ok", "... FAILED"), case_id, 134)
                .is_err()
        );
        assert!(
            parse_single_look_test_run(
                &good.replace("look_matches_end_line", "look_matches_end_text"),
                case_id,
                134,
            )
            .is_err()
        );
        for forged in [
            format!("prefix{good}"),
            format!("{good}suffix"),
            good.replace("134 filtered", "133 filtered"),
            good.replace("0.00s", ".s"),
            good.replace("0.00s", "0.s"),
            good.replace("0.00s", ".00s"),
            good.replace("\nrunning 1 test\n", "\nrunning 1 test\n\nrunning 1 test\n"),
        ] {
            assert!(parse_single_look_test_run(&forged, case_id, 134).is_err());
        }
    }

    #[test]
    fn look_mode_supervisor_caps_output_and_reaps_deadline() {
        let exceeded = Arc::new(AtomicBool::new(false));
        let reader = spawn_bounded_pipe_reader(
            std::io::Cursor::new(vec![
                b'x';
                REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES + 1
            ]),
            Arc::clone(&exceeded),
            REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES,
        );
        let captured = join_bounded_pipe(reader).unwrap();
        assert!(captured.exceeded);
        assert!(exceeded.load(Ordering::Acquire));
        assert_eq!(
            captured.bytes.len(),
            REGEX_AUTOMATA_LOOK_MODE_MAX_COMMAND_OUTPUT_BYTES,
        );

        let mut command = Command::new("/bin/sleep");
        command.arg("5").env_clear();
        let started = Instant::now();
        let error = supervised_command_output(&mut command, Duration::from_millis(20))
            .expect_err("sleep must exceed the supervised deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));

        let mut descendant = Command::new("/bin/sh");
        descendant
            .args(["-c", "(trap '' TERM; sleep 30) & exit 0"])
            .env_clear();
        let started = Instant::now();
        let error = supervised_command_output(&mut descendant, Duration::from_millis(20))
            .expect_err("a descendant retaining the pipes must not outlive the deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));

        let mut overflow = Command::new("/bin/sh");
        overflow
            .args(["-c", "while :; do printf 0123456789abcdef; done"])
            .env_clear();
        let started = Instant::now();
        let error =
            supervised_command_output_with_limit(&mut overflow, Duration::from_secs(5), 1_024)
                .expect_err("unbounded child output must trip the retained-byte cap");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn look_mode_supervisor_kills_a_recorded_descendant() {
        let directory =
            std::env::temp_dir().join(format!("fre-look-descendant-test-{}", std::process::id(),));
        fs::create_dir(&directory).unwrap();
        let pid_path = directory.join("descendant.pid");
        let mut descendant = Command::new("/bin/sh");
        descendant
            .args([
                "-c",
                "(trap '' TERM; sleep 30) & child=$!; printf '%s\\n' \"$child\" > \"$FRE_PID_FILE\"; exit 0",
            ])
            .env_clear()
            .env("FRE_PID_FILE", &pid_path);
        let error = supervised_command_output(&mut descendant, Duration::from_millis(20))
            .expect_err("recorded descendant must exceed the deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let pid = fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let proc_path = PathBuf::from(format!("/proc/{pid}"));
        let started = Instant::now();
        while proc_path.exists() && started.elapsed() < LOOK_PIPE_DRAIN_GRACE {
            thread::sleep(LOOK_CHILD_POLL);
        }
        assert!(!proc_path.exists(), "recorded descendant survived cleanup");
        fs::remove_file(pid_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn look_mode_matrix_writer_and_reader_share_an_inclusive_bound() {
        let directory = std::env::temp_dir()
            .join(format!("fre-look-matrix-bound-test-{}", std::process::id(),));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("matrix.json");
        let value = BTreeMap::from([("key", "value")]);
        let exact = encode_bounded_pretty_json(&value, usize::MAX, "matrix test").unwrap();
        assert!(encode_bounded_pretty_json(&value, exact.len() - 1, "matrix test").is_err());
        write_new_pretty_json(&path, &value, "matrix test").unwrap();
        assert_eq!(
            read_sealed_look_mode_matrix_with_limit(&path, exact.len()).unwrap(),
            exact,
        );
        assert!(read_sealed_look_mode_matrix_with_limit(&path, exact.len() - 1).is_err());
        assert_eq!(
            REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES,
            24 * 1_048_576,
        );
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn look_mode_executes_an_unlinked_authenticated_descriptor() {
        let directory =
            std::env::temp_dir().join(format!("fre-look-fd-exec-test-{}", std::process::id(),));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let logical = directory.join("authenticated-look-test");
        fs::copy("/bin/true", &logical).unwrap();
        fs::set_permissions(&logical, fs::Permissions::from_mode(0o500)).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(LOOK_O_NOFOLLOW)
            .open(&logical)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let bytes = read_held_look_artifact(&file, metadata.len()).unwrap();
        fs::remove_file(&logical).unwrap();
        let artifact = AuthenticatedLookArtifact {
            logical_path: logical.to_str().unwrap().to_owned(),
            file,
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode(),
            bytes: metadata.len(),
            sha256: sha256(&bytes),
        };
        authenticate_held_look_artifact(&artifact).unwrap();
        let output = sanitized_direct_output(&directory, &artifact, &[]).unwrap();
        assert!(output.status.success());
        drop(artifact);
        fs::remove_dir(&directory).unwrap();
    }
}
