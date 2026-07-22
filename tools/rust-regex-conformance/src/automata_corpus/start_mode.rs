//! Exact feature-mode execution bridge for the authenticated `util::start`
//! unit-test cluster.
//!
//! Every pass in this report is backed by two executables compiled for the
//! same exact Cargo feature tuple: the authenticated upstream libtest and a
//! generated observer that executes FRE's prospectively bounded byte start
//! map. No result is projected from one mode to another.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    ops::Deref,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
};

#[cfg(not(target_os = "macos"))]
use std::os::fd::AsRawFd;

use serde::{Deserialize, Serialize};

use super::{
    MAX_PACKAGE_FILE_BYTES, ModeSpec, RegexAutomataCorpusReport, RegexAutomataHarnessKind,
    RegexAutomataSourceIdentity, authenticate_archive, authenticate_package, authenticate_vcs,
    command_evidence, create_private_directory, git_text, hash_json, hash_tool, is_oid, mode_specs,
    prepare_target_dir, read_owned_regular_file, reject_ancestor_cargo_configs,
    reject_cargo_home_configs, require_real_directory, resolve_cargo_home, resolve_tool, sha256,
    snapshot_package, snapshot_vcs_support, tool_release, unsafe_free_euid,
    validate_execution_snapshot,
};
use crate::{
    CandidateIdentity, InventoryError, REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA,
    RegexAutomataAdapterCounts, RegexAutomataAdapterDisposition, RegexAutomataAdapterReceipt,
    RegexAutomataAdapterReport, authenticate_candidate_source,
};

/// Schema for an exact, independently compiled start-mode matrix.
pub const REGEX_AUTOMATA_START_MODE_MATRIX_SCHEMA: &str =
    "fre.regex-automata-0.4.14.start-mode-matrix.v1";
/// Exact number of authenticated unit feature tuples.
pub const REGEX_AUTOMATA_START_MODE_COUNT: usize = 30;
/// Four exact cases in every exact unit tuple.
pub const REGEX_AUTOMATA_START_MODE_MEMBERSHIPS: usize = 120;
/// Four package-default memberships already authenticated by start-map v9.
pub const REGEX_AUTOMATA_START_MODE_RETAINED_MEMBERSHIPS: usize = 4;
/// Newly authenticated memberships outside the retained package-default mode.
pub const REGEX_AUTOMATA_START_MODE_GAINED_MEMBERSHIPS: usize = 116;

const START_SOURCE_PATH: &str = "src/util/start.rs";
const START_SOURCE_SHA256: &str =
    "1ab2dec7c452ae943118cd1c3b6becc84afba1fbb8b6894d81ef7d65141d95ab";
const START_SOURCE_BYTES: u64 = 17_914;
const START_FIXTURE_START_LINE: usize = 408;
const START_FIXTURE_END_LINE: usize = 479;
const START_FIXTURE_BYTES: usize = 2_299;
const START_FIXTURE_SHA256: &str =
    "c4794212267027e805d7450baf80d8b62318ea6ce3d6f6daaec6683fee59d32f";
const TARGET_MEMBERSHIPS_SHA256: &str =
    "9844772449601acffe64904ba4de4b9ffb205d0c411dd536c644779dfc9219ef";
const MODE_IDS_SHA256: &str = "6ccf3a57e8c270e47681c8760f16dade912a05de3a91b78efdcab8d48517ef6d";
const CASE_IDS_SHA256: &str = "f1eb392ffcc0400d97198ff69d0543afd0fb30c8e1254dc427c944e0a2378542";
const EXPECTED_ASSERTIONS_PER_MODE: usize = 16;
const COMMAND_OUTPUT_LIMIT: usize = 16 * 1_048_576;
const ARTIFACT_BYTES_LIMIT: u64 = 128 * 1_048_576;
const GENERATED_FILE_BYTES_LIMIT: u64 = 1_048_576;
const TARGET_FILE_COUNT_LIMIT: u64 = 100_000;
const TARGET_RETAINED_BYTES_LIMIT: u64 = 8 * 1_024 * 1_024 * 1_024;
const HELD_ARTIFACT_PEAK_BYTES_LIMIT: u64 = 2 * ARTIFACT_BYTES_LIMIT;
const REPORT_BYTES_LIMIT: usize = 64 * 1_048_576;
const REPORT_BYTES_LIMIT_U64: u64 = 64 * 1_048_576;
const EXACT_BASE_REVISION: &str = "82ce00ce18d94fc5843f632eb229b7d94b27b353";
const EXACT_BASE_TREE: &str = "ba855b4dd993fd440712096d76b8d5d24b195e39";
const EXACT_BASELINE_PAYLOAD_SHA256: &str =
    "b4978316e4338946f0f63aff88bf995aa1cc60233b279daded31a6f2d08ad229";
const EXACT_BASELINE_REPORT_SHA256: &str =
    "b5e9f004bf1405ec858101aab455230577dcd71c4865d7311a152041827308e8";
const EXACT_BASELINE_CANONICAL_SHA256: &str =
    "2c39878784eff95745f4a499eaa2c09de95b1c84a086db582db91edf4285e96e";
const RETAINED_START_MODE_ID: &str = "package-default-unit";
const EXACT_BUILD_PERSISTENT_BYTES: usize = 296;
const EXACT_BUILD_PEAK_BYTES: usize = 552;
const EXACT_SELFTEST_RETAINED_BYTES: usize = 592;
const EXACT_SELFTEST_PEAK_BYTES: usize = 848;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(target_os = "linux")]
const O_NOFOLLOW_FLAG: i32 = 0x0002_0000;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const O_NOFOLLOW_FLAG: i32 = 0;

const CASE_IDS: [&str; 4] = [
    "util::start::tests::start_fwd",
    "util::start::tests::start_fwd_done_range",
    "util::start::tests::start_rev",
    "util::start::tests::start_rev_done_range",
];

const DECLARED_FEATURES: [&str; 31] = [
    "alloc",
    "default",
    "dfa",
    "dfa-build",
    "dfa-onepass",
    "dfa-search",
    "hybrid",
    "internal-instrument",
    "internal-instrument-pikevm",
    "logging",
    "meta",
    "nfa",
    "nfa-backtrack",
    "nfa-pikevm",
    "nfa-thompson",
    "perf",
    "perf-inline",
    "perf-literal",
    "perf-literal-multisubstring",
    "perf-literal-substring",
    "std",
    "syntax",
    "unicode",
    "unicode-age",
    "unicode-bool",
    "unicode-case",
    "unicode-gencat",
    "unicode-perl",
    "unicode-script",
    "unicode-segment",
    "unicode-word-boundary",
];

#[derive(Clone, Copy)]
struct AssertionSpec {
    id: &'static str,
    line: usize,
    line_sha256: &'static str,
    expected: &'static str,
}

#[derive(Clone, Copy)]
struct CaseSpec {
    case_id: &'static str,
    span_start_line: usize,
    span_end_line: usize,
    span_sha256: &'static str,
    assertions: &'static [AssertionSpec],
    primary_input_bytes: usize,
    primary_context_reads: usize,
    primary_prospective_work: usize,
    primary_actual_work: usize,
}

const DONE_FWD_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    id: "start-fwd-done-text",
    line: 419,
    line_sha256: "480f12c6e2eda405e74fff8a57d323e3499043ec7b31fcce8004a3dfd6f1cf81",
    expected: "Text",
}];
const DONE_REV_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    id: "start-rev-done-text",
    line: 429,
    line_sha256: "480f12c6e2eda405e74fff8a57d323e3499043ec7b31fcce8004a3dfd6f1cf81",
    expected: "Text",
}];
const FWD_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        id: "start-fwd-empty-text",
        line: 443,
        line_sha256: "93c637a68d35b2be73d61ce89edf4ba4fae7c678f78eb59670695e3572dd5fda",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-fwd-begin-text",
        line: 444,
        line_sha256: "4f69edfb114207c9a770a181e825332243340b1cc9307f7f503c9dd17e562f9a",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-fwd-begin-lf-text",
        line: 445,
        line_sha256: "60184c22803c7d4715daeae84fa76fc336518a889e782cfe5b905996ceef5314",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-fwd-line-lf",
        line: 447,
        line_sha256: "678d11edde6b3ac7548b8337f5334364e6cd2ea820c3b1fc2c32ddcf0a96e16d",
        expected: "LineLF",
    },
    AssertionSpec {
        id: "start-fwd-line-cr",
        line: 449,
        line_sha256: "4de651af1669a2a3ae59dc896b49237ed96e28324bc03b8adcd1a3ca3f6a5c4a",
        expected: "LineCR",
    },
    AssertionSpec {
        id: "start-fwd-word",
        line: 451,
        line_sha256: "8e1430a9e8928321562655f08ca47e772e43845ef542dc9ee4f528117a42997a",
        expected: "WordByte",
    },
    AssertionSpec {
        id: "start-fwd-nonword",
        line: 453,
        line_sha256: "887298586e5dbf0ba05d1f30332d71866f28fd20cd4240db508916469eac3578",
        expected: "NonWordByte",
    },
];
const REV_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        id: "start-rev-empty-text",
        line: 467,
        line_sha256: "93c637a68d35b2be73d61ce89edf4ba4fae7c678f78eb59670695e3572dd5fda",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-rev-end-text",
        line: 468,
        line_sha256: "4f69edfb114207c9a770a181e825332243340b1cc9307f7f503c9dd17e562f9a",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-rev-end-lf-text",
        line: 469,
        line_sha256: "b9d1eba309dfb5aaa97b72b5eb9bb01c57df31f24821385eb63e7618526ed5c0",
        expected: "Text",
    },
    AssertionSpec {
        id: "start-rev-line-lf",
        line: 471,
        line_sha256: "fcaa5c96b9f5f6b28cd9378d562173f5788787ba0bf750c4d1bf9e44fed5a4d3",
        expected: "LineLF",
    },
    AssertionSpec {
        id: "start-rev-line-cr",
        line: 473,
        line_sha256: "11fa1ea9fbb73a7785716fab8e18cf997f09150346d44d87368b4daba7715459",
        expected: "LineCR",
    },
    AssertionSpec {
        id: "start-rev-word",
        line: 475,
        line_sha256: "abf07a2d9021ef2bc5dea322d50c80c4e86c72ff9f77a0473fe7b3db490757c9",
        expected: "WordByte",
    },
    AssertionSpec {
        id: "start-rev-nonword",
        line: 477,
        line_sha256: "f6f7552fdb210db8a1fee845900327496ebc4e6323ec0afd742aa80619647ec9",
        expected: "NonWordByte",
    },
];

const CASE_SPECS: [CaseSpec; 4] = [
    CaseSpec {
        case_id: "util::start::tests::start_fwd",
        span_start_line: 432,
        span_end_line: 454,
        span_sha256: "32fd4caf1625baec83c51c67bd1a2efe625caa7c453201cfed3c1f4807b4aa6c",
        assertions: FWD_ASSERTIONS,
        primary_input_bytes: 22,
        primary_context_reads: 4,
        primary_prospective_work: 560,
        primary_actual_work: 512,
    },
    CaseSpec {
        case_id: "util::start::tests::start_fwd_done_range",
        span_start_line: 412,
        span_end_line: 420,
        span_sha256: "5d0a25f679637415a0f46ace169710dd8b40ad8f645ae820e74ae63262f3d5d6",
        assertions: DONE_FWD_ASSERTIONS,
        primary_input_bytes: 0,
        primary_context_reads: 0,
        primary_prospective_work: 80,
        primary_actual_work: 64,
    },
    CaseSpec {
        case_id: "util::start::tests::start_rev",
        span_start_line: 456,
        span_end_line: 478,
        span_sha256: "103ddf5dea403463250722bd86698ec7c3ded206766c95a43c8633c6c05d0cfb",
        assertions: REV_ASSERTIONS,
        primary_input_bytes: 24,
        primary_context_reads: 4,
        primary_prospective_work: 560,
        primary_actual_work: 512,
    },
    CaseSpec {
        case_id: "util::start::tests::start_rev_done_range",
        span_start_line: 422,
        span_end_line: 430,
        span_sha256: "6b46ce5ff8117f13d05dc39a1f3310f3ff3f0430d8d53fce2fb08523b0c8333f",
        assertions: DONE_REV_ASSERTIONS,
        primary_input_bytes: 0,
        primary_context_reads: 0,
        primary_prospective_work: 80,
        primary_actual_work: 64,
    },
];

/// One authenticated upstream assertion bound to one source line.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartAssertionContract {
    pub assertion_id: String,
    pub source_line: usize,
    pub source_line_sha256: String,
    pub expected_observation: String,
}

/// Exact source span and complete assertion inventory for one upstream test.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartSourceContract {
    pub case_id: String,
    pub source_path: String,
    pub source_sha256: String,
    pub span_start_line: usize,
    pub span_end_line: usize,
    pub source_span_sha256: String,
    pub assertion_inventory_sha256: String,
    pub assertions: Vec<RegexAutomataStartAssertionContract>,
}

/// Hashes and bounded byte counts for one subprocess execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartCommandReceipt {
    pub command_contract_sha256: String,
    pub exit_code: i32,
    pub stdout_bytes: usize,
    pub stdout_sha256: String,
    pub stderr_bytes: usize,
    pub stderr_sha256: String,
    pub post_command_target_file_limit: u64,
    pub post_command_target_byte_limit: u64,
    pub target_files_after: u64,
    pub target_bytes_after: u64,
    pub evidence_sha256: String,
}

/// Immutable identity of a compiled executable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartArtifactIdentity {
    pub bytes: u64,
    pub sha256: String,
    pub mode: String,
    pub uid: u32,
    pub nlink: u64,
    pub device: u64,
    pub inode: u64,
}

/// Primary kernel accounting observed for one source case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartCaseAccounting {
    pub assertions: usize,
    pub input_bytes: usize,
    pub context_reads: usize,
    pub build_entries: usize,
    pub build_work: usize,
    pub build_scratch_bytes: usize,
    pub build_persistent_bytes: usize,
    pub build_peak_bytes: usize,
    pub lookup_prospective_work: usize,
    pub lookup_actual_work: usize,
}

/// Separately reported resource work for one per-mode adversarial selftest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartSelftestAccounting {
    pub successful_builds: usize,
    pub rejected_build_admissions: usize,
    pub build_prospective_work: usize,
    pub retained_persistent_bytes: usize,
    pub peak_bytes: usize,
    pub successful_lookups: usize,
    pub rejected_lookup_admissions: usize,
    pub invalid_windows: usize,
    pub lookup_input_bytes: usize,
    pub lookup_prospective_work: usize,
    pub lookup_actual_work: usize,
    pub random_access_bytes: usize,
    pub exhaustive_byte_probes: usize,
}

/// Exact execution evidence for one mode/case membership.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartCaseReceipt {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub source_contract_sha256: String,
    pub upstream_command: RegexAutomataStartCommandReceipt,
    pub observer_command: RegexAutomataStartCommandReceipt,
    pub observations: Vec<String>,
    pub accounting: RegexAutomataStartCaseAccounting,
    pub evidence_sha256: String,
}

/// One exact Cargo feature tuple and both compiled executables.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartModeReceipt {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub default_features: bool,
    pub all_features: bool,
    pub requested_features: Vec<String>,
    pub resolved_features: Vec<String>,
    pub cargo_arguments_sha256: String,
    pub observer_manifest_sha256: String,
    pub lockfile_sha256: String,
    pub lock_package_closure_sha256: String,
    pub lock_packages: usize,
    pub upstream_compile_command: RegexAutomataStartCommandReceipt,
    pub observer_lock_command: RegexAutomataStartCommandReceipt,
    pub observer_metadata_command: RegexAutomataStartCommandReceipt,
    pub observer_compile_command: RegexAutomataStartCommandReceipt,
    pub observer_upstream_manifest_sha256: String,
    pub observer_kernels_manifest_sha256: String,
    pub observer_dependency_features: Vec<String>,
    pub upstream_artifact: RegexAutomataStartArtifactIdentity,
    pub observer_artifact: RegexAutomataStartArtifactIdentity,
    pub selftest_command: RegexAutomataStartCommandReceipt,
    pub selftest_accounting: RegexAutomataStartSelftestAccounting,
    pub cases: Vec<RegexAutomataStartCaseReceipt>,
    pub evidence_sha256: String,
}

/// Exact cardinalities for the matrix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartModeMatrixCounts {
    pub modes: usize,
    pub memberships: usize,
    pub upstream_assertions: usize,
    pub observer_assertions: usize,
    pub faults: usize,
}

/// Prospective per-object bounds plus explicit post-command target bounds.
///
/// The target file and byte fields are not claims about transient filesystem
/// peaks within a Cargo command; that limitation is sealed in the report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartHarnessLimits {
    pub command_stdout_bytes: usize,
    pub command_stderr_bytes: usize,
    pub artifact_bytes: u64,
    pub generated_file_bytes: u64,
    pub target_files: u64,
    pub target_retained_bytes: u64,
    pub held_artifact_peak_bytes: u64,
}

/// Retained filesystem resources observed after the matrix execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartHarnessResources {
    pub target_files: u64,
    pub target_retained_bytes: u64,
    pub max_post_command_retained_files: u64,
    pub max_post_command_retained_bytes: u64,
    pub held_artifact_peak_bytes: u64,
}

/// Exact baseline-to-current adjudication backed by this matrix's executions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartQualification {
    pub baseline: RegexAutomataAdapterReport,
    pub baseline_report_sha256: String,
    pub baseline_counts: RegexAutomataAdapterCounts,
    pub current_counts: RegexAutomataAdapterCounts,
    pub current_receipts: Vec<RegexAutomataAdapterReceipt>,
    #[serde(default)]
    pub retained_target_memberships: usize,
    pub gained_memberships: usize,
    pub lost_memberships: usize,
    pub non_target_receipts_sha256: String,
}

/// Canonically hashed matrix payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartModeMatrixPayload {
    pub inventory_payload_sha256: String,
    pub obligation_inventory_sha256: String,
    pub candidate: CandidateIdentity,
    pub candidate_kernels_tree: String,
    pub candidate_lock_sha256: String,
    pub candidate_snapshot_archive_sha256: String,
    pub candidate_snapshot_tree_sha256: String,
    pub candidate_snapshot_entries: u64,
    pub candidate_snapshot_bytes: u64,
    pub candidate_archive_command: RegexAutomataStartCommandReceipt,
    pub candidate_extract_command: RegexAutomataStartCommandReceipt,
    pub upstream_lock_sha256: String,
    pub observer_source_sha256: String,
    pub source_fixture_sha256: String,
    pub source_fixture_bytes: usize,
    pub source_contracts: Vec<RegexAutomataStartSourceContract>,
    pub case_ids_sha256: String,
    pub mode_ids_sha256: String,
    pub target_memberships_sha256: String,
    pub cargo_release: String,
    pub cargo_executable_sha256: String,
    pub rustc_release: String,
    pub rustc_executable_sha256: String,
    pub limits: RegexAutomataStartHarnessLimits,
    pub resources: RegexAutomataStartHarnessResources,
    pub counts: RegexAutomataStartModeMatrixCounts,
    pub modes: Vec<RegexAutomataStartModeReceipt>,
    pub qualification: RegexAutomataStartQualification,
    pub limitations: Vec<String>,
}

/// Complete exact-mode report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStartModeMatrixReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexAutomataStartModeMatrixPayload,
}

/// Exact search-cluster-v11 predecessor admitted by the hardened full-file reader.
/// The private field prevents callers from bypassing the sealed byte identity
/// with an equivalent reserialization of the report object.
#[derive(Debug)]
pub struct RegexAutomataStartBaseline {
    report: RegexAutomataAdapterReport,
}

/// Held, descriptor-bound no-replace destination authenticated before a long
/// qualification run.
pub struct RegexAutomataStartModeOutputTarget {
    parent: fs::File,
    canonical_parent: PathBuf,
    name: String,
    parent_device: u64,
    parent_inode: u64,
}

impl std::fmt::Debug for RegexAutomataStartModeOutputTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegexAutomataStartModeOutputTarget")
            .field("canonical_parent", &self.canonical_parent)
            .field("name", &self.name)
            .field("parent_device", &self.parent_device)
            .field("parent_inode", &self.parent_inode)
            .finish_non_exhaustive()
    }
}

const LIMITATIONS: [&str; 4] = [
    "A pass covers only the exact authenticated util::start assertion vectors and the bounded byte-context projection; it is not a claim of complete Config or DFA equivalence.",
    "Every membership is compiled and executed in its own authenticated Cargo feature tuple; no result is projected across modes.",
    "Cargo target file and byte limits are checked after every command and final retention is sealed; transient within-command filesystem peak is not measured or claimed.",
    "On platforms without descriptor-relative executable and directory entry, including macOS, private single-link executables and the held output-parent path are descriptor-authenticated immediately before and after use; transient mutation by another process with the same uid is outside this local qualification's threat model.",
];

/// Authenticate all sources, compile every exact unit tuple and execute both
/// sides of every target membership.
#[allow(
    clippy::too_many_lines,
    reason = "the authentication and exact-mode execution transaction stays adjacent"
)]
pub fn build_regex_automata_start_mode_matrix(
    crate_archive: &Path,
    package: &Path,
    vcs_checkout: &Path,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataStartBaseline,
    candidate: &Path,
    target_dir: &Path,
) -> Result<RegexAutomataStartModeMatrixReport, InventoryError> {
    inventory.validate()?;
    authenticate_exact_baseline(inventory, &baseline.report)?;
    authenticate_archive(crate_archive)?;
    let vcs = authenticate_vcs(vcs_checkout)?;
    let source = authenticate_package(package, vcs_checkout, true)?;
    let candidate_identity = authenticate_candidate_source(candidate)?;
    let candidate = candidate
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize candidate: {error}")))?;
    let no_replace_revision = git_text(&candidate, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let no_replace_tree = git_text(&candidate, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    let no_replace_status = super::git_bytes(
        &candidate,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if no_replace_revision != candidate_identity.revision
        || no_replace_tree != candidate_identity.tree
        || !no_replace_status.is_empty()
    {
        return Err(InventoryError::new(
            "candidate no-replace revision/tree/clean identity mismatch",
        ));
    }
    let candidate_kernels_tree = git_text(
        &candidate,
        &["rev-parse", "--verify", "HEAD:crates/fre-kernels"],
    )?;
    if !is_oid(&candidate_kernels_tree) {
        return Err(InventoryError::new("invalid candidate fre-kernels tree"));
    }
    authenticate_candidate_lineage(&candidate)?;
    let candidate_lock = read_single_link_file(
        &candidate.join("Cargo.lock"),
        GENERATED_FILE_BYTES_LIMIT,
        Some(0o644),
    )?;
    let upstream_lock =
        read_owned_regular_file(&package.join("Cargo.lock"), MAX_PACKAGE_FILE_BYTES)?;
    let candidate_lock_sha256 = sha256(&candidate_lock);
    let upstream_lock_sha256 = sha256(&upstream_lock);
    if upstream_lock_sha256 != "77f6e67ada8562e7aaa78b27195fe65bdc9bf303cf666b30848229f2c77ceca9" {
        return Err(InventoryError::new("upstream lockfile identity mismatch"));
    }
    authenticate_start_source(package, &source)?;

    preflight_disjoint_new_path(
        target_dir,
        &[crate_archive, package, vcs_checkout, &candidate],
        "start-mode target",
    )?;
    let target_dir = prepare_target_dir(
        target_dir,
        &[crate_archive, package, vcs_checkout, &candidate],
    )?;
    let candidate_snapshot =
        snapshot_candidate_tree(&candidate, &candidate_identity.revision, &target_dir)?;
    if sha256(&read_single_link_file(
        &candidate_snapshot.root.join("Cargo.lock"),
        GENERATED_FILE_BYTES_LIMIT,
        Some(0o644),
    )?) != candidate_lock_sha256
    {
        return Err(InventoryError::new(
            "candidate snapshot lockfile identity mismatch",
        ));
    }
    let snapshot_workspace = target_dir.join("upstream-snapshot");
    create_private_directory(&snapshot_workspace)?;
    let snapshot = snapshot_workspace.join("regex-automata");
    create_private_directory(&snapshot)?;
    snapshot_package(package, &snapshot, &source)?;
    snapshot_vcs_support(&snapshot_workspace, vcs_checkout, &source)?;
    validate_execution_snapshot(&snapshot_workspace, &source)?;
    authenticate_start_source(&snapshot, &source)?;
    reject_ancestor_cargo_configs(&snapshot)?;
    let cargo_home = resolve_cargo_home()?;
    reject_cargo_home_configs(&cargo_home)?;

    let cargo = resolve_tool("cargo")?;
    let rustc = resolve_tool("rustc")?;
    let cargo_release = tool_release(&cargo, "cargo")?;
    let rustc_release = tool_release(&rustc, "rustc")?;
    let cargo_executable_sha256 = hash_tool(&cargo, "cargo")?;
    let rustc_executable_sha256 = hash_tool(&rustc, "rustc")?;
    if cargo_release != inventory.payload.harness.cargo_release
        || cargo_executable_sha256 != inventory.payload.harness.cargo_executable_sha256
        || rustc_release != inventory.payload.harness.rustc_release
        || rustc_executable_sha256 != inventory.payload.harness.rustc_executable_sha256
    {
        return Err(InventoryError::new(
            "execution toolchain differs from authenticated inventory",
        ));
    }
    let build_target = target_dir.join("cargo-target");
    create_private_directory(&build_target)?;
    let observer_root = target_dir.join("observers");
    create_private_directory(&observer_root)?;

    let specs = exact_unit_specs(inventory)?;
    let all_features = declared_features(&snapshot)?;
    let source_contracts = source_contracts()?;
    let mut modes = Vec::with_capacity(specs.len());
    for spec in &specs {
        modes.push(execute_mode(
            spec,
            &snapshot,
            &candidate_snapshot.root,
            &observer_root,
            &build_target,
            &cargo_home,
            &cargo,
            &rustc,
            &all_features,
            &source_contracts,
        )?);
    }

    authenticate_archive(crate_archive)?;
    if authenticate_vcs(vcs_checkout)?.script != vcs.script
        || authenticate_package(package, vcs_checkout, true)? != source
        || validate_execution_snapshot(&snapshot_workspace, &source).is_err()
        || authenticate_start_source(&snapshot, &source).is_err()
        || authenticate_candidate_source(&candidate)? != candidate_identity
        || git_text(
            &candidate,
            &["rev-parse", "--verify", "HEAD:crates/fre-kernels"],
        )? != candidate_kernels_tree
        || sha256(&read_single_link_file(
            &candidate.join("Cargo.lock"),
            GENERATED_FILE_BYTES_LIMIT,
            Some(0o644),
        )?) != candidate_lock_sha256
        || sha256(&read_owned_regular_file(
            &package.join("Cargo.lock"),
            MAX_PACKAGE_FILE_BYTES,
        )?) != upstream_lock_sha256
        || tool_release(&cargo, "cargo")? != cargo_release
        || tool_release(&rustc, "rustc")? != rustc_release
        || hash_tool(&cargo, "cargo")? != cargo_executable_sha256
        || hash_tool(&rustc, "rustc")? != rustc_executable_sha256
        || candidate_tree_seal(&candidate_snapshot.root)? != candidate_snapshot.tree_sha256
    {
        return Err(InventoryError::new(
            "source, candidate or tool identity changed during start-mode execution",
        ));
    }
    reject_ancestor_cargo_configs(&snapshot)?;
    reject_cargo_home_configs(&cargo_home)?;

    let target_resources = audit_tree_resources(&target_dir)?;
    let held_artifact_peak_bytes = modes
        .iter()
        .map(|mode| {
            mode.upstream_artifact
                .bytes
                .checked_add(mode.observer_artifact.bytes)
                .ok_or_else(|| InventoryError::new("held artifact peak overflow"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    if held_artifact_peak_bytes > HELD_ARTIFACT_PEAK_BYTES_LIMIT {
        return Err(InventoryError::new("held artifact peak bound exceeded"));
    }
    let (max_post_command_retained_files, max_post_command_retained_bytes) =
        post_command_target_maxima(&modes);

    let payload = RegexAutomataStartModeMatrixPayload {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        candidate: candidate_identity.clone(),
        candidate_kernels_tree,
        candidate_lock_sha256,
        candidate_snapshot_archive_sha256: candidate_snapshot.archive_sha256,
        candidate_snapshot_tree_sha256: candidate_snapshot.tree_sha256,
        candidate_snapshot_entries: candidate_snapshot.entries,
        candidate_snapshot_bytes: candidate_snapshot.bytes,
        candidate_archive_command: candidate_snapshot.archive_command,
        candidate_extract_command: candidate_snapshot.extract_command,
        upstream_lock_sha256,
        observer_source_sha256: sha256(OBSERVER_SOURCE.as_bytes()),
        source_fixture_sha256: START_FIXTURE_SHA256.to_owned(),
        source_fixture_bytes: START_FIXTURE_BYTES,
        source_contracts,
        case_ids_sha256: CASE_IDS_SHA256.to_owned(),
        mode_ids_sha256: MODE_IDS_SHA256.to_owned(),
        target_memberships_sha256: TARGET_MEMBERSHIPS_SHA256.to_owned(),
        cargo_release,
        cargo_executable_sha256,
        rustc_release,
        rustc_executable_sha256,
        limits: RegexAutomataStartHarnessLimits {
            command_stdout_bytes: COMMAND_OUTPUT_LIMIT,
            command_stderr_bytes: COMMAND_OUTPUT_LIMIT,
            artifact_bytes: ARTIFACT_BYTES_LIMIT,
            generated_file_bytes: GENERATED_FILE_BYTES_LIMIT,
            target_files: TARGET_FILE_COUNT_LIMIT,
            target_retained_bytes: TARGET_RETAINED_BYTES_LIMIT,
            held_artifact_peak_bytes: HELD_ARTIFACT_PEAK_BYTES_LIMIT,
        },
        resources: RegexAutomataStartHarnessResources {
            target_files: target_resources.files,
            target_retained_bytes: target_resources.bytes,
            max_post_command_retained_files,
            max_post_command_retained_bytes,
            held_artifact_peak_bytes,
        },
        counts: RegexAutomataStartModeMatrixCounts {
            modes: modes.len(),
            memberships: modes.iter().map(|mode| mode.cases.len()).sum(),
            upstream_assertions: modes
                .iter()
                .flat_map(|mode| &mode.cases)
                .map(|case| case.accounting.assertions)
                .sum(),
            observer_assertions: modes
                .iter()
                .flat_map(|mode| &mode.cases)
                .map(|case| case.observations.len())
                .sum(),
            faults: 0,
        },
        qualification: build_qualification(
            inventory,
            &baseline.report,
            &candidate_identity,
            &modes,
        )?,
        modes,
        limitations: LIMITATIONS.iter().map(|text| (*text).to_owned()).collect(),
    };
    let report = RegexAutomataStartModeMatrixReport {
        schema: REGEX_AUTOMATA_START_MODE_MATRIX_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode start-mode matrix payload")?,
        payload,
    };
    report.validate(inventory)?;
    Ok(report)
}

/// Read and structurally validate a sealed matrix.
pub fn read_regex_automata_start_mode_matrix(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
) -> Result<RegexAutomataStartModeMatrixReport, InventoryError> {
    let bytes = read_single_link_file(path, REPORT_BYTES_LIMIT_U64, Some(0o400))?;
    let report = serde_json::from_slice(&bytes)
        .map_err(|error| InventoryError::new(format!("decode start-mode matrix: {error}")))?;
    RegexAutomataStartModeMatrixReport::validate(&report, inventory)?;
    Ok(report)
}

/// Read the one immutable search-cluster-v11 report authorized as this transition's
/// baseline. The full-file digest includes its exact terminal LF; semantic
/// authentication separately pins the canonical object and payload digests.
pub fn read_regex_automata_start_baseline(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
) -> Result<RegexAutomataStartBaseline, InventoryError> {
    let bytes = read_single_link_file(path, REPORT_BYTES_LIMIT_U64, Some(0o400))?;
    if sha256(&bytes) != EXACT_BASELINE_REPORT_SHA256 {
        return Err(InventoryError::new(
            "start-mode baseline full-file identity mismatch",
        ));
    }
    let baseline = serde_json::from_slice(&bytes)
        .map_err(|error| InventoryError::new(format!("decode start-mode baseline: {error}")))?;
    authenticate_exact_baseline(inventory, &baseline)?;
    Ok(RegexAutomataStartBaseline { report: baseline })
}

/// Atomically publish a new matrix without replacing existing evidence.
pub fn write_regex_automata_start_mode_matrix(
    target: &RegexAutomataStartModeOutputTarget,
    report: &RegexAutomataStartModeMatrixReport,
    inventory: &RegexAutomataCorpusReport,
) -> Result<(), InventoryError> {
    report.validate(inventory)?;
    write_new_json(target, report)
}

/// Reject an output pathname that exists or overlaps authenticated inputs
/// before any build-side mutation occurs.
pub fn preflight_regex_automata_start_mode_output(
    path: &Path,
    protected: &[&Path],
) -> Result<RegexAutomataStartModeOutputTarget, InventoryError> {
    preflight_disjoint_new_path(path, protected, "start-mode output")?;
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new("start-mode output has no parent"))?
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize output parent: {error}")))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.bytes().any(|byte| byte.is_ascii_control()))
        .ok_or_else(|| InventoryError::new("invalid start-mode output name"))?
        .to_owned();
    let parent_file = fs::File::open(&parent)
        .map_err(|error| InventoryError::new(format!("hold output parent: {error}")))?;
    let metadata = parent_file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat held output parent: {error}")))?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe_free_euid() {
        return Err(InventoryError::new("unsafe held output parent"));
    }
    let target = RegexAutomataStartModeOutputTarget {
        parent: parent_file,
        canonical_parent: parent,
        name,
        parent_device: metadata.dev(),
        parent_inode: metadata.ino(),
    };
    authenticate_output_target(&target)?;
    if fs::symlink_metadata(output_target_path(&target)?).is_ok() {
        return Err(InventoryError::new("start-mode output already exists"));
    }
    Ok(target)
}

impl RegexAutomataStartModeMatrixReport {
    /// Validate exact inventory bindings, all 30 tuples, all 120 memberships,
    /// all 480 upstream/observer assertions and every nested evidence seal.
    #[allow(
        clippy::too_many_lines,
        reason = "all nested qualification invariants are validated in one transaction"
    )]
    pub fn validate(&self, inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
        inventory.validate()?;
        if self.schema != REGEX_AUTOMATA_START_MODE_MATRIX_SCHEMA
            || self.payload_sha256 != hash_json(&self.payload, "encode start-mode matrix payload")?
            || self.payload.inventory_payload_sha256 != inventory.payload_sha256
            || self.payload.obligation_inventory_sha256
                != inventory.payload.harness.obligation_inventory_sha256
            || self.payload.source_fixture_sha256 != START_FIXTURE_SHA256
            || self.payload.source_fixture_bytes != START_FIXTURE_BYTES
            || self.payload.case_ids_sha256 != CASE_IDS_SHA256
            || self.payload.mode_ids_sha256 != MODE_IDS_SHA256
            || self.payload.target_memberships_sha256 != TARGET_MEMBERSHIPS_SHA256
            || self.payload.limits
                != (RegexAutomataStartHarnessLimits {
                    command_stdout_bytes: COMMAND_OUTPUT_LIMIT,
                    command_stderr_bytes: COMMAND_OUTPUT_LIMIT,
                    artifact_bytes: ARTIFACT_BYTES_LIMIT,
                    generated_file_bytes: GENERATED_FILE_BYTES_LIMIT,
                    target_files: TARGET_FILE_COUNT_LIMIT,
                    target_retained_bytes: TARGET_RETAINED_BYTES_LIMIT,
                    held_artifact_peak_bytes: HELD_ARTIFACT_PEAK_BYTES_LIMIT,
                })
            || self.payload.resources.target_files > TARGET_FILE_COUNT_LIMIT
            || self.payload.resources.target_retained_bytes > TARGET_RETAINED_BYTES_LIMIT
            || self.payload.resources.max_post_command_retained_files > TARGET_FILE_COUNT_LIMIT
            || self.payload.resources.max_post_command_retained_bytes > TARGET_RETAINED_BYTES_LIMIT
            || self.payload.resources.held_artifact_peak_bytes > HELD_ARTIFACT_PEAK_BYTES_LIMIT
            || self.payload.limitations
                != LIMITATIONS
                    .iter()
                    .map(|text| (*text).to_owned())
                    .collect::<Vec<_>>()
            || !candidate_valid(&self.payload.candidate)
            || !is_oid(&self.payload.candidate_kernels_tree)
            || !hex64(&self.payload.candidate_lock_sha256)
            || !hex64(&self.payload.candidate_snapshot_archive_sha256)
            || !hex64(&self.payload.candidate_snapshot_tree_sha256)
            || self.payload.candidate_snapshot_entries == 0
            || self.payload.candidate_snapshot_entries > TARGET_FILE_COUNT_LIMIT
            || self.payload.candidate_snapshot_bytes == 0
            || self.payload.candidate_snapshot_bytes > TARGET_RETAINED_BYTES_LIMIT
            || self.payload.upstream_lock_sha256
                != "77f6e67ada8562e7aaa78b27195fe65bdc9bf303cf666b30848229f2c77ceca9"
            || self.payload.observer_source_sha256 != sha256(OBSERVER_SOURCE.as_bytes())
            || !hex64(&self.payload.cargo_executable_sha256)
            || !hex64(&self.payload.rustc_executable_sha256)
            || self.payload.cargo_release != inventory.payload.harness.cargo_release
            || self.payload.cargo_executable_sha256
                != inventory.payload.harness.cargo_executable_sha256
            || self.payload.rustc_release != inventory.payload.harness.rustc_release
            || self.payload.rustc_executable_sha256
                != inventory.payload.harness.rustc_executable_sha256
        {
            return Err(InventoryError::new("start-mode matrix identity mismatch"));
        }
        validate_command_receipt(&self.payload.candidate_archive_command)?;
        validate_command_receipt(&self.payload.candidate_extract_command)?;
        if self
            .payload
            .candidate_archive_command
            .post_command_target_file_limit
            != 0
            || self
                .payload
                .candidate_extract_command
                .post_command_target_file_limit
                != 0
            || self.payload.candidate_archive_command.stdout_sha256
                != self.payload.candidate_snapshot_archive_sha256
        {
            return Err(InventoryError::new(
                "candidate snapshot command evidence mismatch",
            ));
        }
        let expected_contracts = source_contracts()?;
        if self.payload.source_contracts != expected_contracts {
            return Err(InventoryError::new(
                "start-mode source contract inventory mismatch",
            ));
        }
        let specs = exact_unit_specs(inventory)?;
        if self.payload.modes.len() != specs.len() {
            return Err(InventoryError::new("start-mode denominator mismatch"));
        }
        let mut target_rows = BTreeSet::new();
        let mut upstream_assertions = 0_usize;
        let mut observer_assertions = 0_usize;
        for (mode, spec) in self.payload.modes.iter().zip(&specs) {
            validate_mode(mode, spec, &expected_contracts)?;
            for case in &mode.cases {
                if !target_rows.insert(format!("{}\tunit\t{}", mode.mode_id, case.case_id)) {
                    return Err(InventoryError::new("duplicate start-mode membership"));
                }
                upstream_assertions = upstream_assertions
                    .checked_add(case.accounting.assertions)
                    .ok_or_else(|| InventoryError::new("upstream assertion count overflow"))?;
                observer_assertions = observer_assertions
                    .checked_add(case.observations.len())
                    .ok_or_else(|| InventoryError::new("observer assertion count overflow"))?;
            }
        }
        let held_artifact_peak_bytes = self
            .payload
            .modes
            .iter()
            .map(|mode| {
                mode.upstream_artifact
                    .bytes
                    .checked_add(mode.observer_artifact.bytes)
                    .ok_or_else(|| InventoryError::new("held artifact peak validation overflow"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let (max_post_command_retained_files, max_post_command_retained_bytes) =
            post_command_target_maxima(&self.payload.modes);
        if hash_lines(&target_rows) != TARGET_MEMBERSHIPS_SHA256
            || self.payload.counts
                != (RegexAutomataStartModeMatrixCounts {
                    modes: REGEX_AUTOMATA_START_MODE_COUNT,
                    memberships: REGEX_AUTOMATA_START_MODE_MEMBERSHIPS,
                    upstream_assertions,
                    observer_assertions,
                    faults: 0,
                })
            || upstream_assertions != REGEX_AUTOMATA_START_MODE_COUNT * EXPECTED_ASSERTIONS_PER_MODE
            || observer_assertions != upstream_assertions
            || self.payload.resources.held_artifact_peak_bytes != held_artifact_peak_bytes
            || self.payload.resources.max_post_command_retained_files
                != max_post_command_retained_files
            || self.payload.resources.max_post_command_retained_bytes
                != max_post_command_retained_bytes
        {
            return Err(InventoryError::new(
                "start-mode count or target seal mismatch",
            ));
        }
        validate_qualification(
            inventory,
            &self.payload.candidate,
            &self.payload.modes,
            &self.payload.qualification,
        )?;
        Ok(())
    }
}

fn exact_unit_specs(
    inventory: &RegexAutomataCorpusReport,
) -> Result<Vec<ModeSpec>, InventoryError> {
    let specs = mode_specs()
        .into_iter()
        .filter(|spec| spec.harness == RegexAutomataHarnessKind::Unit)
        .collect::<Vec<_>>();
    if specs.len() != REGEX_AUTOMATA_START_MODE_COUNT {
        return Err(InventoryError::new(
            "start-mode feature tuple denominator mismatch",
        ));
    }
    let mut mode_ids = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for case_id in CASE_IDS {
        case_ids.insert(case_id.to_owned());
    }
    for spec in &specs {
        let mode = inventory
            .payload
            .modes
            .iter()
            .find(|mode| mode.id == spec.id)
            .ok_or_else(|| InventoryError::new("start-mode tuple absent from inventory"))?;
        if mode.harness != spec.harness
            || mode.default_features != spec.default_features
            || mode.all_features != spec.all_features
            || mode.features != spec.features
            || !mode_ids.insert(spec.id.clone())
        {
            return Err(InventoryError::new(
                "start-mode tuple differs from inventory",
            ));
        }
        for case_id in CASE_IDS {
            if !inventory.payload.obligations.iter().any(|obligation| {
                obligation.mode_id == spec.id
                    && obligation.harness == RegexAutomataHarnessKind::Unit
                    && obligation.case_id == case_id
            }) {
                return Err(InventoryError::new(
                    "start-mode target absent from authenticated inventory",
                ));
            }
            targets.insert(format!("{}\tunit\t{case_id}", spec.id));
        }
    }
    if hash_lines(&mode_ids) != MODE_IDS_SHA256
        || hash_lines(&case_ids) != CASE_IDS_SHA256
        || hash_lines(&targets) != TARGET_MEMBERSHIPS_SHA256
    {
        return Err(InventoryError::new(
            "start-mode target derivation seal mismatch",
        ));
    }
    Ok(specs)
}

fn source_contracts() -> Result<Vec<RegexAutomataStartSourceContract>, InventoryError> {
    CASE_SPECS
        .iter()
        .map(|spec| {
            let assertions = spec
                .assertions
                .iter()
                .map(|assertion| RegexAutomataStartAssertionContract {
                    assertion_id: assertion.id.to_owned(),
                    source_line: assertion.line,
                    source_line_sha256: assertion.line_sha256.to_owned(),
                    expected_observation: assertion.expected.to_owned(),
                })
                .collect::<Vec<_>>();
            Ok(RegexAutomataStartSourceContract {
                case_id: spec.case_id.to_owned(),
                source_path: START_SOURCE_PATH.to_owned(),
                source_sha256: START_SOURCE_SHA256.to_owned(),
                span_start_line: spec.span_start_line,
                span_end_line: spec.span_end_line,
                source_span_sha256: spec.span_sha256.to_owned(),
                assertion_inventory_sha256: hash_json(
                    &assertions,
                    "encode start assertion inventory",
                )?,
                assertions,
            })
        })
        .collect()
}

fn authenticate_start_source(
    package: &Path,
    source: &RegexAutomataSourceIdentity,
) -> Result<(), InventoryError> {
    let identity = source
        .files
        .iter()
        .find(|file| file.path == START_SOURCE_PATH)
        .ok_or_else(|| InventoryError::new("start source absent from package identity"))?;
    if identity.bytes != START_SOURCE_BYTES || identity.sha256 != START_SOURCE_SHA256 {
        return Err(InventoryError::new("start source identity mismatch"));
    }
    let bytes = read_owned_regular_file(&package.join(START_SOURCE_PATH), MAX_PACKAGE_FILE_BYTES)?;
    if u64::try_from(bytes.len()) != Ok(START_SOURCE_BYTES) || sha256(&bytes) != START_SOURCE_SHA256
    {
        return Err(InventoryError::new("start source bytes changed"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| InventoryError::new(format!("start source is not UTF-8: {error}")))?;
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    if lines.len() != START_FIXTURE_END_LINE {
        return Err(InventoryError::new(
            "start source line denominator mismatch",
        ));
    }
    let fixture = lines
        .get(START_FIXTURE_START_LINE - 1..START_FIXTURE_END_LINE)
        .ok_or_else(|| InventoryError::new("start fixture span unavailable"))?
        .concat();
    if fixture.len() != START_FIXTURE_BYTES || sha256(fixture.as_bytes()) != START_FIXTURE_SHA256 {
        return Err(InventoryError::new("start fixture byte seal mismatch"));
    }
    for spec in CASE_SPECS {
        let span_start = spec
            .span_start_line
            .checked_sub(1)
            .ok_or_else(|| InventoryError::new("invalid start case line"))?;
        let span = lines
            .get(span_start..spec.span_end_line)
            .ok_or_else(|| InventoryError::new("start case span unavailable"))?
            .concat();
        if sha256(span.as_bytes()) != spec.span_sha256 {
            return Err(InventoryError::new("start case span seal mismatch"));
        }
        for assertion in spec.assertions {
            let line_index = assertion
                .line
                .checked_sub(1)
                .ok_or_else(|| InventoryError::new("invalid start assertion line"))?;
            let line = lines
                .get(line_index)
                .ok_or_else(|| InventoryError::new("start assertion line unavailable"))?;
            if sha256(line.as_bytes()) != assertion.line_sha256 {
                return Err(InventoryError::new("start assertion line seal mismatch"));
            }
        }
    }
    Ok(())
}

fn declared_features(snapshot: &Path) -> Result<Vec<String>, InventoryError> {
    let bytes = read_owned_regular_file(&snapshot.join("Cargo.toml"), MAX_PACKAGE_FILE_BYTES)?;
    let manifest = std::str::from_utf8(&bytes)
        .map_err(|error| InventoryError::new(format!("package manifest is not UTF-8: {error}")))?;
    let manifest = toml::from_str::<toml::Value>(manifest)
        .map_err(|error| InventoryError::new(format!("decode package manifest: {error}")))?;
    let table = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| InventoryError::new("package manifest has no feature table"))?;
    let declared = table.keys().map(String::as_str).collect::<Vec<_>>();
    if declared != DECLARED_FEATURES {
        return Err(InventoryError::new("invalid declared feature inventory"));
    }
    Ok(declared
        .into_iter()
        .filter(|feature| *feature != "default")
        .map(str::to_owned)
        .collect())
}

fn expected_resolved_features(spec: &ModeSpec) -> Result<Vec<String>, InventoryError> {
    let mut enabled = BTreeSet::new();
    if spec.all_features {
        enabled.extend(DECLARED_FEATURES);
    } else {
        if spec.default_features {
            enabled.insert("default");
        }
        for feature in &spec.features {
            if !DECLARED_FEATURES.contains(&feature.as_str()) {
                return Err(InventoryError::new("requested undeclared feature"));
            }
            enabled.insert(feature);
        }
    }
    loop {
        let before = enabled.len();
        let active = enabled.iter().copied().collect::<Vec<_>>();
        for feature in active {
            enabled.extend(local_feature_dependencies(feature));
        }
        if enabled.len() == before {
            break;
        }
    }
    Ok(enabled.into_iter().map(str::to_owned).collect())
}

fn local_feature_dependencies(feature: &str) -> &'static [&'static str] {
    match feature {
        "default" => &[
            "std", "syntax", "perf", "unicode", "meta", "nfa", "dfa", "hybrid",
        ],
        "dfa" => &["dfa-build", "dfa-search", "dfa-onepass"],
        "dfa-build" => &["nfa-thompson", "dfa-search"],
        "dfa-onepass" | "nfa-backtrack" | "nfa-pikevm" => &["nfa-thompson"],
        "hybrid" => &["alloc", "nfa-thompson"],
        "internal-instrument" => &["internal-instrument-pikevm"],
        "internal-instrument-pikevm" => &["logging", "std"],
        "meta" => &["syntax", "nfa-pikevm"],
        "nfa" => &["nfa-thompson", "nfa-pikevm", "nfa-backtrack"],
        "nfa-thompson" | "std" | "syntax" => &["alloc"],
        "perf" => &["perf-inline", "perf-literal"],
        "perf-literal" => &["perf-literal-substring", "perf-literal-multisubstring"],
        "unicode" => &[
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "unicode-word-boundary",
        ],
        _ => &[],
    }
}

fn candidate_valid(candidate: &CandidateIdentity) -> bool {
    is_oid(&candidate.revision)
        && is_oid(&candidate.tree)
        && candidate.tracked_and_untracked_worktree_clean
}

fn authenticate_exact_baseline(
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    baseline.validate(inventory)?;
    let baseline_canonical_sha256 = hash_json(baseline, "encode exact start baseline report")?;
    if baseline.schema != REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA
        || baseline.payload_sha256 != EXACT_BASELINE_PAYLOAD_SHA256
        || baseline_canonical_sha256 != EXACT_BASELINE_CANONICAL_SHA256
        || baseline.payload.candidate.revision != EXACT_BASE_REVISION
        || baseline.payload.candidate.tree != EXACT_BASE_TREE
        || baseline.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 151,
                unsupported: 3_691,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new("start-mode baseline identity mismatch"));
    }
    Ok(())
}

fn authenticate_candidate_lineage(candidate: &Path) -> Result<(), InventoryError> {
    let line = git_text(candidate, &["rev-list", "--parents", "-n", "1", "HEAD"])?;
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 2 || fields[1] != EXACT_BASE_REVISION {
        return Err(InventoryError::new(
            "candidate must be one source-only commit on the exact checkpoint",
        ));
    }
    let changed = super::git_bytes(
        candidate,
        &[
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-z",
            "-r",
            "HEAD",
        ],
    )?;
    let allowed = BTreeSet::from([
        "tools/rust-regex-conformance/src/automata_corpus.rs".to_owned(),
        "tools/rust-regex-conformance/src/automata_corpus/start_mode.rs".to_owned(),
        "tools/rust-regex-conformance/src/fixtures/start-transition-v11-adversarial-v1.tsv"
            .to_owned(),
        "tools/rust-regex-conformance/src/lib.rs".to_owned(),
        "tools/rust-regex-conformance/src/main.rs".to_owned(),
    ]);
    let changed = parse_candidate_scope(&changed)?;
    if changed != allowed {
        return Err(InventoryError::new("candidate source scope mismatch"));
    }
    Ok(())
}

fn parse_candidate_scope(bytes: &[u8]) -> Result<BTreeSet<String>, InventoryError> {
    let Some(fields) = bytes.strip_suffix(&[0]) else {
        return Err(InventoryError::new(
            "candidate scope is not terminated Git -z output",
        ));
    };
    let mut paths = BTreeSet::new();
    for field in fields.split(|byte| *byte == 0) {
        let path = std::str::from_utf8(field)
            .ok()
            .filter(|path| !path.is_empty() && !path.bytes().any(|byte| byte.is_ascii_control()))
            .ok_or_else(|| InventoryError::new("invalid candidate scope path"))?;
        if !paths.insert(path.to_owned()) {
            return Err(InventoryError::new("duplicate candidate scope path"));
        }
    }
    Ok(paths)
}

fn adapter_counts(receipts: &[RegexAutomataAdapterReceipt]) -> RegexAutomataAdapterCounts {
    let mut counts = RegexAutomataAdapterCounts {
        total: receipts.len(),
        ..RegexAutomataAdapterCounts::default()
    };
    for receipt in receipts {
        match receipt.disposition {
            RegexAutomataAdapterDisposition::Pass { .. } => {
                counts.pass = counts.pass.checked_add(1).expect("bounded receipt count");
            }
            RegexAutomataAdapterDisposition::Unsupported { .. } => {
                counts.unsupported = counts
                    .unsupported
                    .checked_add(1)
                    .expect("bounded receipt count");
            }
            RegexAutomataAdapterDisposition::Fault { .. } => {
                counts.fault = counts.fault.checked_add(1).expect("bounded receipt count");
            }
        }
    }
    counts
}

fn post_command_target_maxima(modes: &[RegexAutomataStartModeReceipt]) -> (u64, u64) {
    let mut peak_files = 0_u64;
    let mut peak_bytes = 0_u64;
    for mode in modes {
        for receipt in [
            &mode.upstream_compile_command,
            &mode.observer_lock_command,
            &mode.observer_metadata_command,
            &mode.observer_compile_command,
        ] {
            peak_files = peak_files.max(receipt.target_files_after);
            peak_bytes = peak_bytes.max(receipt.target_bytes_after);
        }
    }
    (peak_files, peak_bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "baseline replay, target replacement and no-loss accounting stay adjacent"
)]
fn build_qualification(
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
    candidate: &CandidateIdentity,
    modes: &[RegexAutomataStartModeReceipt],
) -> Result<RegexAutomataStartQualification, InventoryError> {
    authenticate_exact_baseline(inventory, baseline)?;
    let specs = exact_unit_specs(inventory)?;
    if modes.len() != specs.len() {
        return Err(InventoryError::new(
            "start-mode qualification mode denominator mismatch",
        ));
    }
    let source_contracts = source_contracts()?;
    for (mode, spec) in modes.iter().zip(&specs) {
        validate_mode(mode, spec, &source_contracts)?;
    }
    if !candidate_valid(candidate)
        || candidate.revision == baseline.payload.candidate.revision
        || candidate.tree == baseline.payload.candidate.tree
    {
        return Err(InventoryError::new(
            "start-mode qualification lacks a distinct clean candidate",
        ));
    }
    let mut targets = BTreeMap::new();
    for mode in modes {
        for case in &mode.cases {
            let identity = (mode.mode_id.clone(), mode.harness, case.case_id.clone());
            let evidence = membership_evidence(candidate, mode, case)?;
            if targets.insert(identity, evidence).is_some() {
                return Err(InventoryError::new(
                    "duplicate start-mode qualification target",
                ));
            }
        }
    }
    if targets.len() != REGEX_AUTOMATA_START_MODE_MEMBERSHIPS {
        return Err(InventoryError::new(
            "start-mode qualification target denominator mismatch",
        ));
    }
    let mut current_receipts = baseline.payload.receipts.clone();
    let mut baseline_non_targets = Vec::new();
    let mut current_non_targets = Vec::new();
    let mut seen_target_memberships = 0usize;
    let mut retained_target_memberships = 0usize;
    for receipt in &mut current_receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if let Some(evidence_sha256) = targets.get(&identity) {
            seen_target_memberships = seen_target_memberships
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("start-mode target count overflow"))?;
            match &receipt.disposition {
                RegexAutomataAdapterDisposition::Unsupported { .. } => {
                    receipt.disposition = RegexAutomataAdapterDisposition::Pass {
                        evidence_sha256: evidence_sha256.clone(),
                    };
                }
                RegexAutomataAdapterDisposition::Pass { .. }
                    if receipt.mode_id == RETAINED_START_MODE_ID =>
                {
                    retained_target_memberships =
                        retained_target_memberships.checked_add(1).ok_or_else(|| {
                            InventoryError::new("retained start-mode target count overflow")
                        })?;
                }
                _ => {
                    return Err(InventoryError::new(
                        "start-mode target has an unauthorized baseline disposition",
                    ));
                }
            }
        } else {
            baseline_non_targets.push(receipt.clone());
            current_non_targets.push(receipt.clone());
        }
    }
    if seen_target_memberships != REGEX_AUTOMATA_START_MODE_MEMBERSHIPS
        || retained_target_memberships != REGEX_AUTOMATA_START_MODE_RETAINED_MEMBERSHIPS
    {
        return Err(InventoryError::new(
            "start-mode baseline target/retained denominator mismatch",
        ));
    }
    let baseline_non_target_sha256 =
        hash_json(&baseline_non_targets, "encode baseline non-target receipts")?;
    let current_non_target_sha256 =
        hash_json(&current_non_targets, "encode current non-target receipts")?;
    if baseline_non_target_sha256 != current_non_target_sha256 {
        return Err(InventoryError::new("non-target receipt changed"));
    }
    let baseline_counts = adapter_counts(&baseline.payload.receipts);
    let current_counts = adapter_counts(&current_receipts);
    let gained_memberships = baseline
        .payload
        .receipts
        .iter()
        .zip(&current_receipts)
        .filter(|(old, new)| {
            !matches!(
                old.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            ) && matches!(
                new.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            )
        })
        .count();
    let lost_memberships = baseline
        .payload
        .receipts
        .iter()
        .zip(&current_receipts)
        .filter(|(old, new)| {
            matches!(
                old.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            ) && !matches!(
                new.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            )
        })
        .count();
    if current_counts
        != (RegexAutomataAdapterCounts {
            pass: 267,
            unsupported: 3_575,
            fault: 0,
            total: 3_842,
        })
        || gained_memberships != REGEX_AUTOMATA_START_MODE_GAINED_MEMBERSHIPS
        || lost_memberships != 0
    {
        return Err(InventoryError::new(
            "start-mode baseline/current accounting mismatch",
        ));
    }
    Ok(RegexAutomataStartQualification {
        baseline: baseline.clone(),
        baseline_report_sha256: EXACT_BASELINE_REPORT_SHA256.to_owned(),
        baseline_counts,
        current_counts,
        current_receipts,
        retained_target_memberships,
        gained_memberships,
        lost_memberships,
        non_target_receipts_sha256: baseline_non_target_sha256,
    })
}

fn membership_evidence(
    candidate: &CandidateIdentity,
    mode: &RegexAutomataStartModeReceipt,
    case: &RegexAutomataStartCaseReceipt,
) -> Result<String, InventoryError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        candidate: &'a CandidateIdentity,
        mode_evidence_sha256: &'a str,
        case_evidence_sha256: &'a str,
    }
    hash_json(
        &Seal {
            candidate,
            mode_evidence_sha256: &mode.evidence_sha256,
            case_evidence_sha256: &case.evidence_sha256,
        },
        "encode start-mode membership evidence",
    )
}

fn validate_qualification(
    inventory: &RegexAutomataCorpusReport,
    candidate: &CandidateIdentity,
    modes: &[RegexAutomataStartModeReceipt],
    qualification: &RegexAutomataStartQualification,
) -> Result<(), InventoryError> {
    let expected = build_qualification(inventory, &qualification.baseline, candidate, modes)?;
    if qualification != &expected {
        return Err(InventoryError::new(
            "start-mode qualification evidence mismatch",
        ));
    }
    Ok(())
}

fn preflight_disjoint_new_path(
    path: &Path,
    protected: &[&Path],
    label: &str,
) -> Result<(), InventoryError> {
    if !path.is_absolute() {
        return Err(InventoryError::new(format!("{label} must be absolute")));
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(InventoryError::new(format!("{label} already exists"))),
        Err(error) => return Err(InventoryError::new(format!("stat {label}: {error}"))),
    }
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new(format!("{label} has no parent")))?;
    require_real_directory(parent, label)?;
    let parent = parent
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize {label} parent: {error}")))?;
    let name = path
        .file_name()
        .ok_or_else(|| InventoryError::new(format!("{label} has no name")))?;
    let prospective_path = parent.join(name);
    for protected in protected {
        let protected = protected.canonicalize().map_err(|error| {
            InventoryError::new(format!("canonicalize protected {label} path: {error}"))
        })?;
        if prospective_path.starts_with(&protected) || protected.starts_with(&prospective_path) {
            return Err(InventoryError::new(format!(
                "{label} overlaps an authenticated source"
            )));
        }
    }
    Ok(())
}

struct TreeResources {
    files: u64,
    bytes: u64,
}

struct CandidateSnapshot {
    root: PathBuf,
    archive_sha256: String,
    tree_sha256: String,
    entries: u64,
    bytes: u64,
    archive_command: RegexAutomataStartCommandReceipt,
    extract_command: RegexAutomataStartCommandReceipt,
}

#[derive(Serialize)]
struct CandidateSnapshotEntry {
    path: String,
    mode: String,
    bytes: u64,
    sha256: String,
}

fn candidate_tree_seal(root: &Path) -> Result<String, InventoryError> {
    require_real_directory(root, "candidate snapshot")?;
    let mut stack = vec![root.to_path_buf()];
    let mut entries = BTreeMap::new();
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| InventoryError::new(format!("read candidate snapshot: {error}")))?
        {
            let entry = entry.map_err(|error| {
                InventoryError::new(format!("read candidate snapshot entry: {error}"))
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                InventoryError::new(format!("stat candidate snapshot entry: {error}"))
            })?;
            if metadata.file_type().is_symlink()
                || (!metadata.file_type().is_dir() && !metadata.file_type().is_file())
                || metadata.uid() != unsafe_free_euid()
            {
                return Err(InventoryError::new("unsafe candidate snapshot entry"));
            }
            if metadata.file_type().is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| InventoryError::new("candidate snapshot path escaped root"))?
                .to_str()
                .filter(|value| {
                    !value.is_empty()
                        && !value.bytes().any(|byte| byte.is_ascii_control())
                        && !value
                            .split('/')
                            .any(|component| matches!(component, "" | "." | ".."))
                })
                .ok_or_else(|| InventoryError::new("invalid candidate snapshot path"))?
                .to_owned();
            let bytes = read_single_link_file(&path, MAX_PACKAGE_FILE_BYTES, None)?;
            let item = CandidateSnapshotEntry {
                path: relative.clone(),
                mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
                bytes: metadata.len(),
                sha256: sha256(&bytes),
            };
            if entries.insert(relative, item).is_some() {
                return Err(InventoryError::new("duplicate candidate snapshot path"));
            }
        }
    }
    if entries.is_empty() {
        return Err(InventoryError::new("candidate snapshot is empty"));
    }
    hash_json(
        &entries.into_values().collect::<Vec<_>>(),
        "encode candidate snapshot tree",
    )
}

fn audit_tree_resources(root: &Path) -> Result<TreeResources, InventoryError> {
    require_real_directory(root, "start-mode resource root")?;
    let mut stack = vec![root.to_path_buf()];
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| InventoryError::new(format!("read resource tree: {error}")))?
        {
            let entry = entry
                .map_err(|error| InventoryError::new(format!("read resource entry: {error}")))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| InventoryError::new(format!("stat resource entry: {error}")))?;
            if metadata.uid() != unsafe_free_euid() {
                return Err(InventoryError::new("resource tree contains foreign owner"));
            }
            if metadata.file_type().is_symlink()
                || (!metadata.file_type().is_dir() && !metadata.file_type().is_file())
            {
                return Err(InventoryError::new(
                    "resource tree contains symlink or special entry",
                ));
            }
            files = files
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("resource entry count overflow"))?;
            if metadata.file_type().is_dir() {
                stack.push(entry.path());
            } else {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| InventoryError::new("resource byte count overflow"))?;
            }
            if files > TARGET_FILE_COUNT_LIMIT || bytes > TARGET_RETAINED_BYTES_LIMIT {
                return Err(InventoryError::new("resource tree bound exceeded"));
            }
        }
    }
    Ok(TreeResources { files, bytes })
}

fn hash_lines(lines: &BTreeSet<String>) -> String {
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn feature_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one mode's exact compilation and execution transaction is kept together"
)]
fn execute_mode(
    spec: &ModeSpec,
    snapshot: &Path,
    candidate: &Path,
    observer_root: &Path,
    build_target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    all_features: &[String],
    source_contracts: &[RegexAutomataStartSourceContract],
) -> Result<RegexAutomataStartModeReceipt, InventoryError> {
    let cargo_args = upstream_compile_arguments(spec);
    let compile_output = bounded_cargo_output(
        snapshot,
        build_target,
        cargo_home,
        cargo,
        rustc,
        &cargo_args,
    )
    .map_err(|error| InventoryError::new(format!("compile {}: {error}", spec.id)))?;
    let upstream_compile_command = successful_command_receipt(
        &compile_output,
        &format!("upstream compile for {}", spec.id),
    )?;
    let (upstream_artifact_path, mut resolved_features) = parse_cargo_artifact(
        &compile_output.stdout,
        snapshot,
        build_target,
        "regex_automata",
        "lib",
    )?;
    resolved_features.sort();
    let expected_features = expected_resolved_features(spec)?;
    if resolved_features != expected_features
        || resolved_features.windows(2).any(|pair| pair[0] >= pair[1])
        || resolved_features
            .iter()
            .any(|feature| !feature_token(feature))
    {
        return Err(InventoryError::new(
            "upstream resolved feature closure is invalid",
        ));
    }
    let observer = observer_root.join(&spec.id);
    create_private_directory(&observer)?;
    let held_root = observer.join("held");
    create_private_directory(&held_root)?;
    let upstream_held = hold_artifact(
        &upstream_artifact_path,
        &held_root.join("upstream-libtest"),
        build_target,
    )?;
    let upstream_artifact = upstream_held.identity.clone();
    prepare_held_artifact(&upstream_held)?;
    let observer_source = observer.join("src");
    create_private_directory(&observer_source)?;
    let dependency_features = if spec.all_features {
        all_features.to_vec()
    } else {
        spec.features.clone()
    };
    let manifest = observer_manifest(
        snapshot,
        &candidate.join("crates/fre-kernels"),
        spec.default_features,
        &dependency_features,
    )?;
    let observer_manifest_sha256 = sha256(manifest.as_bytes());
    write_generated_file(&observer.join("Cargo.toml"), manifest.as_bytes())?;
    write_generated_file(&observer_source.join("main.rs"), OBSERVER_SOURCE.as_bytes())?;

    let lock_args = vec!["generate-lockfile".to_owned(), "--offline".to_owned()];
    let lock_output = bounded_cargo_output(
        &observer,
        build_target,
        cargo_home,
        cargo,
        rustc,
        &lock_args,
    )
    .map_err(|error| InventoryError::new(format!("lock observer {}: {error}", spec.id)))?;
    let observer_lock_command =
        successful_command_receipt(&lock_output, &format!("observer lock for {}", spec.id))?;
    let lockfile = read_single_link_file(
        &observer.join("Cargo.lock"),
        GENERATED_FILE_BYTES_LIMIT,
        None,
    )?;
    let lockfile_sha256 = sha256(&lockfile);
    let lock_closure = validate_observer_lock(
        &lockfile,
        &read_single_link_file(
            &snapshot.join("Cargo.lock"),
            GENERATED_FILE_BYTES_LIMIT,
            Some(0o644),
        )?,
        &read_single_link_file(
            &candidate.join("Cargo.lock"),
            GENERATED_FILE_BYTES_LIMIT,
            Some(0o644),
        )?,
    )?;
    seal_existing_generated_file(&observer.join("Cargo.lock"), &lockfile)?;
    authenticate_observer_inputs(
        &observer,
        manifest.as_bytes(),
        OBSERVER_SOURCE.as_bytes(),
        &lockfile,
    )?;

    let metadata_args = vec![
        "metadata".to_owned(),
        "--offline".to_owned(),
        "--locked".to_owned(),
        "--format-version=1".to_owned(),
    ];
    let metadata_output = bounded_cargo_output(
        &observer,
        build_target,
        cargo_home,
        cargo,
        rustc,
        &metadata_args,
    )
    .map_err(|error| InventoryError::new(format!("inspect observer {}: {error}", spec.id)))?;
    let observer_metadata_command = successful_command_receipt(
        &metadata_output,
        &format!("observer metadata for {}", spec.id),
    )?;
    let dependency = parse_observer_metadata(
        &metadata_output.stdout,
        &observer,
        snapshot,
        &candidate.join("crates/fre-kernels"),
    )?;
    if dependency.resolved_features != resolved_features {
        return Err(InventoryError::new(format!(
            "observer/upstream feature closure mismatch in {}",
            spec.id
        )));
    }
    authenticate_observer_inputs(
        &observer,
        manifest.as_bytes(),
        OBSERVER_SOURCE.as_bytes(),
        &lockfile,
    )?;

    let observer_args = vec![
        "build".to_owned(),
        "--offline".to_owned(),
        "--locked".to_owned(),
        "--message-format=json-render-diagnostics".to_owned(),
    ];
    let observer_output = bounded_cargo_output(
        &observer,
        build_target,
        cargo_home,
        cargo,
        rustc,
        &observer_args,
    )
    .map_err(|error| InventoryError::new(format!("compile observer {}: {error}", spec.id)))?;
    authenticate_observer_inputs(
        &observer,
        manifest.as_bytes(),
        OBSERVER_SOURCE.as_bytes(),
        &lockfile,
    )?;
    let observer_compile_command = successful_command_receipt(
        &observer_output,
        &format!("observer compile for {}", spec.id),
    )?;
    let (observer_artifact_path, observer_features) = parse_cargo_artifact(
        &observer_output.stdout,
        &observer,
        build_target,
        "start-mode-observer",
        "bin",
    )?;
    if !observer_features.is_empty() {
        return Err(InventoryError::new(
            "generated observer unexpectedly defines Cargo features",
        ));
    }
    let observer_held = hold_artifact(
        &observer_artifact_path,
        &held_root.join("observer"),
        build_target,
    )?;
    let observer_artifact = observer_held.identity.clone();
    prepare_held_artifact(&observer_held)?;

    verify_prepared_artifact(&observer_held)?;
    let selftest_output =
        run_held_executable(&observer_held, "held-observer", &["--selftest"], &observer)?;
    let selftest_command = successful_command_receipt(
        &selftest_output,
        &format!("observer selftest in {}", spec.id),
    )?;
    let selftest_accounting = parse_selftest_output(&selftest_output.stdout)?;
    if verify_prepared_artifact(&observer_held).is_err() {
        return Err(InventoryError::new(
            "observer artifact changed during selftest",
        ));
    }

    let mut cases = Vec::with_capacity(CASE_SPECS.len());
    for (case_spec, source_contract) in CASE_SPECS.iter().zip(source_contracts) {
        verify_prepared_artifact(&upstream_held)?;
        let upstream_output = run_held_executable(
            &upstream_held,
            "held-upstream-libtest",
            &[
                case_spec.case_id,
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ],
            snapshot,
        )?;
        let upstream_command = successful_command_receipt(
            &upstream_output,
            &format!("upstream test {} in {}", case_spec.case_id, spec.id),
        )?;
        validate_libtest_output(&upstream_output.stdout, case_spec.case_id)?;
        if verify_prepared_artifact(&upstream_held).is_err() {
            return Err(InventoryError::new(
                "upstream libtest artifact changed during execution",
            ));
        }

        verify_prepared_artifact(&observer_held)?;
        let observer_output = run_held_executable(
            &observer_held,
            "held-observer",
            &[case_spec.case_id],
            &observer,
        )?;
        let observer_command = successful_command_receipt(
            &observer_output,
            &format!("observer test {} in {}", case_spec.case_id, spec.id),
        )?;
        let (observations, accounting) = parse_observer_output(&observer_output.stdout, case_spec)?;
        if verify_prepared_artifact(&observer_held).is_err() {
            return Err(InventoryError::new(
                "observer artifact changed during execution",
            ));
        }
        let source_contract_sha256 = hash_json(source_contract, "encode start source contract")?;
        let mut case = RegexAutomataStartCaseReceipt {
            mode_id: spec.id.clone(),
            harness: RegexAutomataHarnessKind::Unit,
            case_id: case_spec.case_id.to_owned(),
            source_contract_sha256,
            upstream_command,
            observer_command,
            observations,
            accounting,
            evidence_sha256: String::new(),
        };
        case.evidence_sha256 = case_evidence(&case)?;
        cases.push(case);
    }

    let mut mode = RegexAutomataStartModeReceipt {
        mode_id: spec.id.clone(),
        harness: RegexAutomataHarnessKind::Unit,
        default_features: spec.default_features,
        all_features: spec.all_features,
        requested_features: spec.features.clone(),
        resolved_features,
        cargo_arguments_sha256: hash_json(&cargo_args, "encode upstream Cargo arguments")?,
        observer_manifest_sha256,
        lockfile_sha256,
        lock_package_closure_sha256: lock_closure.sha256,
        lock_packages: lock_closure.packages,
        upstream_compile_command,
        observer_lock_command,
        observer_metadata_command,
        observer_compile_command,
        observer_upstream_manifest_sha256: dependency.upstream_manifest_sha256,
        observer_kernels_manifest_sha256: dependency.kernels_manifest_sha256,
        observer_dependency_features: dependency.resolved_features,
        upstream_artifact,
        observer_artifact,
        selftest_command,
        selftest_accounting,
        cases,
        evidence_sha256: String::new(),
    };
    mode.evidence_sha256 = mode_evidence(&mode)?;
    Ok(mode)
}

fn upstream_compile_arguments(spec: &ModeSpec) -> Vec<String> {
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
    args.extend([
        "--lib".to_owned(),
        "--no-run".to_owned(),
        "--message-format=json-render-diagnostics".to_owned(),
    ]);
    args
}

fn observer_manifest(
    snapshot: &Path,
    kernels: &Path,
    default_features: bool,
    features: &[String],
) -> Result<String, InventoryError> {
    let snapshot = snapshot
        .to_str()
        .ok_or_else(|| InventoryError::new("snapshot path is not UTF-8"))?;
    let kernels = kernels
        .to_str()
        .ok_or_else(|| InventoryError::new("candidate path is not UTF-8"))?;
    let snapshot = serde_json::to_string(snapshot)
        .map_err(|error| InventoryError::new(format!("encode snapshot path: {error}")))?;
    let kernels = serde_json::to_string(kernels)
        .map_err(|error| InventoryError::new(format!("encode candidate path: {error}")))?;
    let features = serde_json::to_string(features)
        .map_err(|error| InventoryError::new(format!("encode observer features: {error}")))?;
    Ok(format!(
        "[package]\nname = \"start-mode-observer\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nfre-kernels = {{ path = {kernels} }}\nregex_automata_mode = {{ package = \"regex-automata\", path = {snapshot}, version = \"=0.4.14\", default-features = {default_features}, features = {features} }}\n\n[workspace]\n",
    ))
}

struct LockClosure {
    sha256: String,
    packages: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct LockPackageIdentity {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn lock_package_identities(bytes: &[u8]) -> Result<BTreeSet<LockPackageIdentity>, InventoryError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| InventoryError::new(format!("lockfile is not UTF-8: {error}")))?;
    let document = toml::from_str::<toml::Value>(text)
        .map_err(|error| InventoryError::new(format!("decode lockfile: {error}")))?;
    let version = document
        .get("version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| InventoryError::new("lockfile version is absent"))?;
    if !matches!(version, 3 | 4) {
        return Err(InventoryError::new("unsupported lockfile version"));
    }
    let packages = document
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| InventoryError::new("lockfile package array is absent"))?;
    if packages.is_empty() || packages.len() > 256 {
        return Err(InventoryError::new(
            "lockfile package denominator is unsafe",
        ));
    }
    let mut identities = BTreeSet::new();
    for package in packages {
        let table = package
            .as_table()
            .ok_or_else(|| InventoryError::new("lockfile package is not a table"))?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|value| feature_token(value))
            .ok_or_else(|| InventoryError::new("lockfile package name is invalid"))?;
        let version = table
            .get("version")
            .and_then(toml::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .ok_or_else(|| InventoryError::new("lockfile package version is invalid"))?;
        let source = table
            .get("source")
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| value.starts_with("registry+"))
                    .map(str::to_owned)
                    .ok_or_else(|| InventoryError::new("lockfile package source is invalid"))
            })
            .transpose()?;
        let checksum = table
            .get("checksum")
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| hex64(value))
                    .map(str::to_owned)
                    .ok_or_else(|| InventoryError::new("lockfile checksum is invalid"))
            })
            .transpose()?;
        if source.is_some() != checksum.is_some() {
            return Err(InventoryError::new(
                "lockfile source/checksum presence mismatch",
            ));
        }
        if !identities.insert(LockPackageIdentity {
            name: name.to_owned(),
            version: version.to_owned(),
            source,
            checksum,
        }) {
            return Err(InventoryError::new("duplicate lockfile package identity"));
        }
    }
    Ok(identities)
}

fn validate_observer_lock(
    generated: &[u8],
    upstream: &[u8],
    candidate: &[u8],
) -> Result<LockClosure, InventoryError> {
    let generated = lock_package_identities(generated)?;
    let authenticated = lock_package_identities(upstream)?
        .into_iter()
        .chain(lock_package_identities(candidate)?)
        .collect::<BTreeSet<_>>();
    let authenticated_registry = authenticated
        .iter()
        .filter(|package| package.source.is_some())
        .cloned()
        .collect::<BTreeSet<_>>();
    let authenticated_paths = authenticated
        .iter()
        .filter(|package| package.source.is_none())
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect::<BTreeSet<_>>();
    let expected_paths = BTreeSet::from([
        ("start-mode-observer", "0.0.0"),
        ("regex-automata", "0.4.14"),
        ("fre-kernels", "0.1.0"),
        ("fre-exact-alloc", "0.1.0"),
    ]);
    let mut observed_paths = BTreeSet::new();
    for package in &generated {
        if package.source.is_some() {
            if !authenticated_registry.contains(package) {
                return Err(InventoryError::new(
                    "generated lock contains unauthenticated registry package",
                ));
            }
        } else {
            let identity = (package.name.as_str(), package.version.as_str());
            if identity != ("start-mode-observer", "0.0.0")
                && !authenticated_paths.contains(&identity)
            {
                return Err(InventoryError::new(
                    "generated lock contains unauthenticated path package",
                ));
            }
            observed_paths.insert(identity);
        }
    }
    if observed_paths != expected_paths {
        return Err(InventoryError::new(
            "generated lock path package closure mismatch",
        ));
    }
    Ok(LockClosure {
        sha256: hash_json(&generated, "encode observer lock package closure")?,
        packages: generated.len(),
    })
}

struct ObserverDependencyMetadata {
    upstream_manifest_sha256: String,
    kernels_manifest_sha256: String,
    resolved_features: Vec<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete Cargo dependency graph authentication stays in one parser"
)]
fn parse_observer_metadata(
    stdout: &[u8],
    observer: &Path,
    snapshot: &Path,
    kernels: &Path,
) -> Result<ObserverDependencyMetadata, InventoryError> {
    if stdout.len() > COMMAND_OUTPUT_LIMIT {
        return Err(InventoryError::new("Cargo metadata output exceeds bound"));
    }
    let metadata: serde_json::Value = serde_json::from_slice(stdout)
        .map_err(|error| InventoryError::new(format!("decode Cargo metadata: {error}")))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| InventoryError::new("Cargo metadata lacks packages"))?;
    let observer_manifest = observer
        .join("Cargo.toml")
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize observer manifest: {error}")))?;
    let upstream_manifest = snapshot
        .join("Cargo.toml")
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize upstream manifest: {error}")))?;
    let kernels_manifest = kernels
        .join("Cargo.toml")
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize kernels manifest: {error}")))?;
    let mut observer_id = None;
    let mut upstream_id = None;
    let mut kernels_id = None;
    for package in packages {
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("metadata package lacks manifest path"))?;
        let manifest = PathBuf::from(manifest).canonicalize().map_err(|error| {
            InventoryError::new(format!("canonicalize metadata manifest: {error}"))
        })?;
        let id = package
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("metadata package lacks id"))?;
        let name = package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("metadata package lacks name"))?;
        let version = package
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("metadata package lacks version"))?;
        if manifest == observer_manifest {
            if name != "start-mode-observer"
                || version != "0.0.0"
                || observer_id.replace(id.to_owned()).is_some()
            {
                return Err(InventoryError::new("observer package metadata mismatch"));
            }
        } else if manifest == upstream_manifest {
            if name != "regex-automata"
                || version != "0.4.14"
                || upstream_id.replace(id.to_owned()).is_some()
            {
                return Err(InventoryError::new("upstream dependency metadata mismatch"));
            }
        } else if manifest == kernels_manifest
            && (name != "fre-kernels" || kernels_id.replace(id.to_owned()).is_some())
        {
            return Err(InventoryError::new("kernels dependency metadata mismatch"));
        }
    }
    let observer_id = observer_id.ok_or_else(|| InventoryError::new("observer root absent"))?;
    let upstream_id =
        upstream_id.ok_or_else(|| InventoryError::new("upstream dependency absent"))?;
    let kernels_id = kernels_id.ok_or_else(|| InventoryError::new("kernels dependency absent"))?;
    if metadata
        .get("resolve")
        .and_then(|resolve| resolve.get("root"))
        != Some(&serde_json::Value::String(observer_id.clone()))
    {
        return Err(InventoryError::new("observer metadata root mismatch"));
    }
    let nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| InventoryError::new("Cargo metadata lacks resolve nodes"))?;
    let root_node = nodes
        .iter()
        .find(|node| node.get("id").and_then(serde_json::Value::as_str) == Some(&observer_id))
        .ok_or_else(|| InventoryError::new("observer resolve node absent"))?;
    let root_dependencies = root_node
        .get("deps")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| InventoryError::new("observer resolve node lacks dependencies"))?;
    let mut bound = BTreeMap::new();
    for dependency in root_dependencies {
        let name = dependency
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("observer dependency name is absent"))?;
        let package = dependency
            .get("pkg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("observer dependency package is absent"))?;
        if bound.insert(name, package).is_some() {
            return Err(InventoryError::new("duplicate observer dependency name"));
        }
    }
    if bound.get("regex_automata_mode") != Some(&upstream_id.as_str())
        || bound.get("fre_kernels") != Some(&kernels_id.as_str())
        || bound.len() != 2
    {
        return Err(InventoryError::new(
            "observer direct dependency resolution mismatch",
        ));
    }
    let upstream_node = nodes
        .iter()
        .find(|node| node.get("id").and_then(serde_json::Value::as_str) == Some(&upstream_id))
        .ok_or_else(|| InventoryError::new("upstream resolve node absent"))?;
    let mut resolved_features = upstream_node
        .get("features")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| InventoryError::new("upstream resolve node lacks features"))?
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| InventoryError::new("resolved feature is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    resolved_features.sort();
    if resolved_features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(InventoryError::new("duplicate observer dependency feature"));
    }
    let upstream_manifest_bytes =
        read_single_link_file(&upstream_manifest, GENERATED_FILE_BYTES_LIMIT, Some(0o644))?;
    let kernels_manifest_bytes =
        read_single_link_file(&kernels_manifest, GENERATED_FILE_BYTES_LIMIT, Some(0o644))?;
    Ok(ObserverDependencyMetadata {
        upstream_manifest_sha256: sha256(&upstream_manifest_bytes),
        kernels_manifest_sha256: sha256(&kernels_manifest_bytes),
        resolved_features,
    })
}

fn parse_cargo_artifact(
    stdout: &[u8],
    manifest_root: &Path,
    build_target: &Path,
    target_name: &str,
    target_kind: &str,
) -> Result<(PathBuf, Vec<String>), InventoryError> {
    if stdout.len() > COMMAND_OUTPUT_LIMIT {
        return Err(InventoryError::new("Cargo JSON output exceeds bound"));
    }
    let text = std::str::from_utf8(stdout)
        .map_err(|error| InventoryError::new(format!("Cargo JSON is not UTF-8: {error}")))?;
    let expected_manifest = manifest_root
        .join("Cargo.toml")
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize manifest: {error}")))?;
    let mut matches = Vec::new();
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| InventoryError::new(format!("decode Cargo JSON: {error}")))?;
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            || value
                .pointer("/target/name")
                .and_then(serde_json::Value::as_str)
                != Some(target_name)
            || !value
                .pointer("/target/kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some(target_kind)))
        {
            continue;
        }
        let manifest = value
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("Cargo artifact lacks manifest path"))?;
        let manifest = PathBuf::from(manifest).canonicalize().map_err(|error| {
            InventoryError::new(format!("canonicalize artifact manifest: {error}"))
        })?;
        if manifest != expected_manifest {
            continue;
        }
        let executable = value
            .get("executable")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| InventoryError::new("root Cargo artifact lacks executable"))?;
        let features = value
            .get("features")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| InventoryError::new("Cargo artifact lacks feature closure"))?
            .iter()
            .map(|feature| {
                feature
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| InventoryError::new("Cargo feature is not text"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let executable = PathBuf::from(executable).canonicalize().map_err(|error| {
            InventoryError::new(format!("canonicalize Cargo executable: {error}"))
        })?;
        let build_target = build_target
            .canonicalize()
            .map_err(|error| InventoryError::new(format!("canonicalize Cargo target: {error}")))?;
        if !executable.starts_with(&build_target) {
            return Err(InventoryError::new(
                "Cargo executable escaped the private build target",
            ));
        }
        matches.push((executable, features));
    }
    if matches.len() != 1 {
        return Err(InventoryError::new(format!(
            "expected one root {target_name} {target_kind} artifact, found {}",
            matches.len()
        )));
    }
    Ok(matches.pop().expect("length checked"))
}

struct HeldArtifact {
    path: PathBuf,
    file: fs::File,
    identity: RegexAutomataStartArtifactIdentity,
}

fn open_nofollow(path: &Path) -> Result<fs::File, InventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(InventoryError::new("refusing symlink artifact"));
    }
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW_FLAG)
        .open(path)
        .map_err(|error| InventoryError::new(format!("open {}: {error}", path.display())))
}

fn read_artifact_file(file: &fs::File, length: u64) -> Result<Vec<u8>, InventoryError> {
    let length = usize::try_from(length)
        .map_err(|_| InventoryError::new("artifact length exceeds address space"))?;
    if length == 0 || length > usize::try_from(ARTIFACT_BYTES_LIMIT).unwrap_or(usize::MAX) {
        return Err(InventoryError::new("compiled artifact size mismatch"));
    }
    let mut bytes = vec![0_u8; length];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = file
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).unwrap_or(u64::MAX),
            )
            .map_err(|error| InventoryError::new(format!("read artifact descriptor: {error}")))?;
        if read == 0 {
            return Err(InventoryError::new("artifact descriptor ended early"));
        }
        offset = offset
            .checked_add(read)
            .ok_or_else(|| InventoryError::new("artifact read offset overflow"))?;
    }
    let mut probe = [0_u8; 1];
    let end =
        u64::try_from(length).map_err(|_| InventoryError::new("artifact probe offset overflow"))?;
    if file
        .read_at(&mut probe, end)
        .map_err(|error| InventoryError::new(format!("probe artifact descriptor: {error}")))?
        != 0
    {
        return Err(InventoryError::new(
            "artifact grew beyond authenticated length",
        ));
    }
    Ok(bytes)
}

fn artifact_identity_from_file(
    file: &fs::File,
) -> Result<RegexAutomataStartArtifactIdentity, InventoryError> {
    let metadata = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat artifact descriptor: {error}")))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || mode != 0o500
        || metadata.len() == 0
        || metadata.len() > ARTIFACT_BYTES_LIMIT
    {
        return Err(InventoryError::new("compiled artifact metadata mismatch"));
    }
    let bytes = read_artifact_file(file, metadata.len())?;
    Ok(RegexAutomataStartArtifactIdentity {
        bytes: metadata.len(),
        sha256: sha256(&bytes),
        mode: format!("{mode:04o}"),
        uid: metadata.uid(),
        nlink: metadata.nlink(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn hold_artifact(
    source: &Path,
    destination: &Path,
    build_target: &Path,
) -> Result<HeldArtifact, InventoryError> {
    let source = source
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize artifact source: {error}")))?;
    let build_target = build_target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize build target: {error}")))?;
    if !source.starts_with(&build_target) {
        return Err(InventoryError::new("artifact source escaped build target"));
    }
    let source_file = open_nofollow(&source)?;
    let before = source_file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat source artifact: {error}")))?;
    let source_mode = before.permissions().mode() & 0o7777;
    if !before.file_type().is_file()
        || before.uid() != unsafe_free_euid()
        || before.nlink() != 1
        || source_mode & 0o111 == 0
        || before.len() == 0
        || before.len() > ARTIFACT_BYTES_LIMIT
    {
        return Err(InventoryError::new("source artifact metadata mismatch"));
    }
    let bytes = read_artifact_file(&source_file, before.len())?;
    let after = source_file
        .metadata()
        .map_err(|error| InventoryError::new(format!("restat source artifact: {error}")))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
    {
        return Err(InventoryError::new(
            "source artifact changed during held copy",
        ));
    }
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| InventoryError::new(format!("create held artifact: {error}")))?;
    output
        .write_all(&bytes)
        .map_err(|error| InventoryError::new(format!("write held artifact: {error}")))?;
    output
        .sync_all()
        .map_err(|error| InventoryError::new(format!("sync held artifact: {error}")))?;
    output
        .set_permissions(fs::Permissions::from_mode(0o500))
        .map_err(|error| InventoryError::new(format!("seal held artifact: {error}")))?;
    output
        .sync_all()
        .map_err(|error| InventoryError::new(format!("sync sealed held artifact: {error}")))?;
    drop(output);
    let file = open_nofollow(destination)?;
    let identity = artifact_identity_from_file(&file)?;
    if identity.sha256 != sha256(&bytes) {
        return Err(InventoryError::new("held artifact bytes changed"));
    }
    let held = HeldArtifact {
        path: destination.to_path_buf(),
        file,
        identity,
    };
    verify_held_artifact(&held)?;
    Ok(held)
}

fn verify_held_artifact(held: &HeldArtifact) -> Result<(), InventoryError> {
    let path_metadata = fs::symlink_metadata(&held.path)
        .map_err(|error| InventoryError::new(format!("stat held artifact path: {error}")))?;
    let descriptor_metadata = held
        .file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat held artifact descriptor: {error}")))?;
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || artifact_identity_from_file(&held.file)? != held.identity
    {
        return Err(InventoryError::new(
            "held artifact path/inode identity changed",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn detach_held_artifact(held: &HeldArtifact) -> Result<(), InventoryError> {
    verify_held_artifact(held)?;
    fs::remove_file(&held.path)
        .map_err(|error| InventoryError::new(format!("unlink held artifact: {error}")))?;
    let parent = held
        .path
        .parent()
        .ok_or_else(|| InventoryError::new("held artifact has no parent"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| InventoryError::new(format!("sync held artifact parent: {error}")))?;
    verify_detached_artifact(held)
}

fn prepare_held_artifact(held: &HeldArtifact) -> Result<(), InventoryError> {
    #[cfg(target_os = "macos")]
    {
        verify_held_artifact(held)
    }
    #[cfg(not(target_os = "macos"))]
    {
        detach_held_artifact(held)
    }
}

fn verify_prepared_artifact(held: &HeldArtifact) -> Result<(), InventoryError> {
    #[cfg(target_os = "macos")]
    {
        verify_held_artifact(held)
    }
    #[cfg(not(target_os = "macos"))]
    {
        verify_detached_artifact(held)
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_detached_artifact(held: &HeldArtifact) -> Result<(), InventoryError> {
    match fs::symlink_metadata(&held.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(InventoryError::new("detached artifact path reappeared")),
        Err(error) => {
            return Err(InventoryError::new(format!(
                "stat detached artifact path: {error}"
            )));
        }
    }
    let metadata = held
        .file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat detached descriptor: {error}")))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != held.identity.uid
        || metadata.nlink() != 0
        || metadata.dev() != held.identity.device
        || metadata.ino() != held.identity.inode
        || metadata.len() != held.identity.bytes
        || format!("{mode:04o}") != held.identity.mode
        || sha256(&read_artifact_file(&held.file, metadata.len())?) != held.identity.sha256
    {
        return Err(InventoryError::new(
            "detached artifact descriptor identity changed",
        ));
    }
    Ok(())
}

struct BoundedCommandOutput {
    output: Output,
    command_contract_sha256: String,
    post_command_target_file_limit: u64,
    post_command_target_byte_limit: u64,
    target_files_after: u64,
    target_bytes_after: u64,
}

impl Deref for BoundedCommandOutput {
    type Target = Output;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

#[derive(Serialize)]
struct CommandContract<'a> {
    executable: &'a str,
    executable_identity_sha256: Option<&'a str>,
    arguments: &'a [String],
    current_directory: &'a str,
    environment: &'a BTreeMap<String, String>,
}

#[cfg(test)]
fn bounded_pipe(pipe: impl Read, maximum: usize) -> std::io::Result<(Vec<u8>, bool)> {
    bounded_pipe_with_overflow(pipe, maximum, || {})
}

fn bounded_pipe_with_overflow(
    mut pipe: impl Read,
    maximum: usize,
    mut on_overflow: impl FnMut(),
) -> std::io::Result<(Vec<u8>, bool)> {
    let retained_limit = maximum.saturating_add(1);
    let mut retained = Vec::with_capacity(retained_limit.min(64 * 1_024));
    let mut buffer = [0_u8; 16 * 1_024];
    let mut overflow = false;
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let available = retained_limit.saturating_sub(retained.len());
        let keep = available.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        let crossed = keep != read || retained.len() > maximum;
        if crossed && !overflow {
            on_overflow();
        }
        overflow |= crossed;
    }
    Ok((retained, overflow))
}

enum PipeEvent {
    Overflow,
    Done,
}

fn kill_command_group(child: &mut std::process::Child) -> Result<(), InventoryError> {
    let process_group = format!("-{}", child.id());
    let group_status = Command::new("/bin/kill")
        .args(["-KILL", &process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| InventoryError::new(format!("kill bounded process group: {error}")))?;
    if !group_status.success()
        && child
            .try_wait()
            .map_err(|error| InventoryError::new(format!("inspect bounded child: {error}")))?
            .is_none()
    {
        child
            .kill()
            .map_err(|error| InventoryError::new(format!("kill bounded child: {error}")))?;
    }
    Ok(())
}

fn bounded_command_output(
    command: &mut Command,
    command_contract_sha256: String,
) -> Result<BoundedCommandOutput, InventoryError> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| InventoryError::new(format!("spawn bounded command: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| InventoryError::new("bounded command stdout pipe absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| InventoryError::new("bounded command stderr pipe absent"))?;
    let (events, receiver) = std::sync::mpsc::channel();
    let stdout_events = events.clone();
    let stdout_reader = thread::spawn(move || {
        let result = bounded_pipe_with_overflow(stdout, COMMAND_OUTPUT_LIMIT, || {
            let _ = stdout_events.send(PipeEvent::Overflow);
        });
        let _ = stdout_events.send(PipeEvent::Done);
        result
    });
    let stderr_events = events.clone();
    let stderr_reader = thread::spawn(move || {
        let result = bounded_pipe_with_overflow(stderr, COMMAND_OUTPUT_LIMIT, || {
            let _ = stderr_events.send(PipeEvent::Overflow);
        });
        let _ = stderr_events.send(PipeEvent::Done);
        result
    });
    drop(events);
    let mut completed_pipes = 0_usize;
    let mut observed_overflow = false;
    while completed_pipes != 2 {
        match receiver
            .recv()
            .map_err(|_| InventoryError::new("bounded pipe event channel closed early"))?
        {
            PipeEvent::Overflow if !observed_overflow => {
                observed_overflow = true;
                kill_command_group(&mut child)?;
            }
            PipeEvent::Overflow => {}
            PipeEvent::Done => {
                completed_pipes = completed_pipes
                    .checked_add(1)
                    .ok_or_else(|| InventoryError::new("bounded pipe count overflow"))?;
            }
        }
    }
    let status = child
        .wait()
        .map_err(|error| InventoryError::new(format!("wait for bounded command: {error}")))?;
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| InventoryError::new("bounded stdout reader panicked"))?
        .map_err(|error| InventoryError::new(format!("read bounded stdout: {error}")))?;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| InventoryError::new("bounded stderr reader panicked"))?
        .map_err(|error| InventoryError::new(format!("read bounded stderr: {error}")))?;
    if observed_overflow || stdout_overflow || stderr_overflow {
        return Err(InventoryError::new(
            "command output exceeded live retention bound",
        ));
    }
    Ok(BoundedCommandOutput {
        output: Output {
            status,
            stdout,
            stderr,
        },
        command_contract_sha256,
        post_command_target_file_limit: 0,
        post_command_target_byte_limit: 0,
        target_files_after: 0,
        target_bytes_after: 0,
    })
}

fn bounded_cargo_output(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    args: &[String],
) -> Result<BoundedCommandOutput, InventoryError> {
    let package = package
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize Cargo package: {error}")))?;
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize Cargo target: {error}")))?;
    let cargo_home = cargo_home
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize Cargo home: {error}")))?;
    if !cargo.is_absolute() || !rustc.is_absolute() {
        return Err(InventoryError::new("Cargo tools must use absolute paths"));
    }
    let cargo = cargo.to_path_buf();
    let rustc = rustc.to_path_buf();
    let home = cargo_home
        .parent()
        .ok_or_else(|| InventoryError::new("Cargo home has no parent"))?;
    let cargo_bin = cargo_home.join("bin");
    let controlled_path = format!(
        "{}:/usr/bin:/bin:/usr/sbin:/sbin",
        cargo_bin
            .to_str()
            .ok_or_else(|| InventoryError::new("Cargo bin path is not UTF-8"))?
    );
    let mut environment = BTreeMap::new();
    for (key, value) in [
        ("CARGO_HOME", cargo_home.as_path()),
        ("CARGO_TARGET_DIR", target.as_path()),
        ("HOME", home),
        ("RUSTC", rustc.as_path()),
        ("TMPDIR", target.as_path()),
    ] {
        environment.insert(
            key.to_owned(),
            value
                .to_str()
                .ok_or_else(|| InventoryError::new("controlled Cargo path is not UTF-8"))?
                .to_owned(),
        );
    }
    environment.insert("CARGO_INCREMENTAL".to_owned(), "0".to_owned());
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    environment.insert("PATH".to_owned(), controlled_path);
    let executable = cargo
        .to_str()
        .ok_or_else(|| InventoryError::new("Cargo executable is not UTF-8"))?;
    let current_directory = package
        .to_str()
        .ok_or_else(|| InventoryError::new("Cargo package path is not UTF-8"))?;
    let contract = hash_json(
        &CommandContract {
            executable,
            executable_identity_sha256: None,
            arguments: args,
            current_directory,
            environment: &environment,
        },
        "encode bounded Cargo command contract",
    )?;
    let mut command = Command::new(&cargo);
    command
        .args(args)
        .current_dir(&package)
        .env_clear()
        .envs(&environment);
    let mut output = bounded_command_output(&mut command, contract)?;
    let resources = audit_tree_resources(&target)?;
    output.post_command_target_file_limit = TARGET_FILE_COUNT_LIMIT;
    output.post_command_target_byte_limit = TARGET_RETAINED_BYTES_LIMIT;
    output.target_files_after = resources.files;
    output.target_bytes_after = resources.bytes;
    Ok(output)
}

fn bounded_control_output(
    executable: &Path,
    arguments: &[String],
    directory: &Path,
) -> Result<BoundedCommandOutput, InventoryError> {
    if !executable.is_absolute() {
        return Err(InventoryError::new("control executable is not absolute"));
    }
    let directory = directory
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize control directory: {error}")))?;
    let executable_text = executable
        .to_str()
        .ok_or_else(|| InventoryError::new("control executable is not UTF-8"))?;
    let directory_text = directory
        .to_str()
        .ok_or_else(|| InventoryError::new("control directory is not UTF-8"))?;
    let environment = BTreeMap::new();
    let contract = hash_json(
        &CommandContract {
            executable: executable_text,
            executable_identity_sha256: None,
            arguments,
            current_directory: directory_text,
            environment: &environment,
        },
        "encode bounded control command contract",
    )?;
    let mut command = Command::new(executable);
    command.args(arguments).current_dir(&directory).env_clear();
    bounded_command_output(&mut command, contract)
}

fn write_bounded_blob(path: &Path, bytes: &[u8], maximum: usize) -> Result<(), InventoryError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(InventoryError::new("bounded blob size mismatch"));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| InventoryError::new(format!("create bounded blob: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| InventoryError::new(format!("write bounded blob: {error}")))?;
    file.sync_all()
        .map_err(|error| InventoryError::new(format!("sync bounded blob: {error}")))?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|error| InventoryError::new(format!("seal bounded blob: {error}")))?;
    file.sync_all()
        .map_err(|error| InventoryError::new(format!("sync sealed bounded blob: {error}")))?;
    if read_single_link_file(
        path,
        u64::try_from(maximum).map_err(|_| InventoryError::new("bounded blob limit overflow"))?,
        Some(0o400),
    )? != bytes
    {
        return Err(InventoryError::new("bounded blob postcondition mismatch"));
    }
    Ok(())
}

fn snapshot_candidate_tree(
    candidate: &Path,
    revision: &str,
    target: &Path,
) -> Result<CandidateSnapshot, InventoryError> {
    if !is_oid(revision) {
        return Err(InventoryError::new(
            "candidate snapshot revision is invalid",
        ));
    }
    let archive_arguments = vec![
        "--no-replace-objects".to_owned(),
        "-c".to_owned(),
        "tar.umask=0022".to_owned(),
        "-C".to_owned(),
        candidate
            .to_str()
            .ok_or_else(|| InventoryError::new("candidate path is not UTF-8"))?
            .to_owned(),
        "archive".to_owned(),
        "--format=tar".to_owned(),
        revision.to_owned(),
    ];
    let archive_output =
        bounded_control_output(Path::new("/usr/bin/git"), &archive_arguments, target)?;
    let archive_command = successful_command_receipt(&archive_output, "candidate git archive")?;
    let archive_sha256 = sha256(&archive_output.stdout);
    let archive = target.join("candidate-source.tar");
    write_bounded_blob(&archive, &archive_output.stdout, COMMAND_OUTPUT_LIMIT)?;
    let root = target.join("candidate-source");
    create_private_directory(&root)?;
    let extract_arguments = vec![
        "-xpf".to_owned(),
        archive
            .to_str()
            .ok_or_else(|| InventoryError::new("candidate archive path is not UTF-8"))?
            .to_owned(),
        "-C".to_owned(),
        root.to_str()
            .ok_or_else(|| InventoryError::new("candidate snapshot path is not UTF-8"))?
            .to_owned(),
    ];
    let extract_output =
        bounded_control_output(Path::new("/usr/bin/tar"), &extract_arguments, target)?;
    let extract_command =
        successful_command_receipt(&extract_output, "candidate archive extraction")?;
    let resources = audit_tree_resources(&root)?;
    let tree_sha256 = candidate_tree_seal(&root)?;
    Ok(CandidateSnapshot {
        root,
        archive_sha256,
        tree_sha256,
        entries: resources.files,
        bytes: resources.bytes,
        archive_command,
        extract_command,
    })
}

fn run_held_executable(
    held: &HeldArtifact,
    logical_executable: &str,
    arguments: &[&str],
    directory: &Path,
) -> Result<BoundedCommandOutput, InventoryError> {
    verify_prepared_artifact(held)?;
    #[cfg(not(target_os = "macos"))]
    let executable = "/proc/self/fd/0";
    let directory = directory
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize run directory: {error}")))?;
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let environment = BTreeMap::new();
    let contract = hash_json(
        &CommandContract {
            executable: logical_executable,
            executable_identity_sha256: Some(&held.identity.sha256),
            arguments: &arguments,
            current_directory: directory
                .to_str()
                .ok_or_else(|| InventoryError::new("run directory is not UTF-8"))?,
            environment: &environment,
        },
        "encode bounded artifact command contract",
    )?;
    #[cfg(target_os = "macos")]
    let mut command = Command::new(&held.path);
    #[cfg(not(target_os = "macos"))]
    let mut command = {
        let executable_input = held
            .file
            .try_clone()
            .map_err(|error| InventoryError::new(format!("clone held executable fd: {error}")))?;
        let mut command = Command::new(executable);
        command.stdin(Stdio::from(executable_input));
        command
    };
    command.args(&arguments).current_dir(&directory).env_clear();
    let output = bounded_command_output(&mut command, contract)?;
    verify_prepared_artifact(held)?;
    Ok(output)
}

fn successful_command_receipt(
    bounded: &BoundedCommandOutput,
    context: &str,
) -> Result<RegexAutomataStartCommandReceipt, InventoryError> {
    let output = &bounded.output;
    if output.stdout.len() > COMMAND_OUTPUT_LIMIT || output.stderr.len() > COMMAND_OUTPUT_LIMIT {
        return Err(InventoryError::new(format!(
            "{context} output exceeds bound"
        )));
    }
    let exit_code = output
        .status
        .code()
        .ok_or_else(|| InventoryError::new(format!("{context} terminated by signal")))?;
    if exit_code != 0 {
        return Err(InventoryError::new(format!(
            "{context} failed: evidence_sha256={}",
            command_evidence(output)
        )));
    }
    let mut receipt = RegexAutomataStartCommandReceipt {
        command_contract_sha256: bounded.command_contract_sha256.clone(),
        exit_code,
        stdout_bytes: output.stdout.len(),
        stdout_sha256: sha256(&output.stdout),
        stderr_bytes: output.stderr.len(),
        stderr_sha256: sha256(&output.stderr),
        post_command_target_file_limit: bounded.post_command_target_file_limit,
        post_command_target_byte_limit: bounded.post_command_target_byte_limit,
        target_files_after: bounded.target_files_after,
        target_bytes_after: bounded.target_bytes_after,
        evidence_sha256: String::new(),
    };
    receipt.evidence_sha256 = command_receipt_evidence(&receipt)?;
    Ok(receipt)
}

fn command_receipt_evidence(
    receipt: &RegexAutomataStartCommandReceipt,
) -> Result<String, InventoryError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        command_contract_sha256: &'a str,
        exit_code: i32,
        stdout_bytes: usize,
        stdout_sha256: &'a str,
        stderr_bytes: usize,
        stderr_sha256: &'a str,
        post_command_target_file_limit: u64,
        post_command_target_byte_limit: u64,
        target_files_after: u64,
        target_bytes_after: u64,
    }
    hash_json(
        &Seal {
            command_contract_sha256: &receipt.command_contract_sha256,
            exit_code: receipt.exit_code,
            stdout_bytes: receipt.stdout_bytes,
            stdout_sha256: &receipt.stdout_sha256,
            stderr_bytes: receipt.stderr_bytes,
            stderr_sha256: &receipt.stderr_sha256,
            post_command_target_file_limit: receipt.post_command_target_file_limit,
            post_command_target_byte_limit: receipt.post_command_target_byte_limit,
            target_files_after: receipt.target_files_after,
            target_bytes_after: receipt.target_bytes_after,
        },
        "encode start command receipt",
    )
}

fn validate_libtest_output(stdout: &[u8], case_id: &str) -> Result<(), InventoryError> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|error| InventoryError::new(format!("libtest output is not UTF-8: {error}")))?;
    let case_marker = format!("test {case_id} ... ok");
    let lines = stdout.lines().map(str::trim).collect::<Vec<_>>();
    let case_lines = lines.iter().filter(|line| **line == case_marker).count();
    let running_lines = lines
        .iter()
        .filter(|line| **line == "running 1 test")
        .count();
    let result_lines = lines
        .iter()
        .filter(|line| {
            line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
                && line.contains(" filtered out; finished in ")
        })
        .count();
    if case_lines != 1
        || running_lines != 1
        || result_lines != 1
        || lines.iter().any(|line| line.contains("FAILED"))
    {
        return Err(InventoryError::new(
            "exact upstream libtest output lacks one passing target",
        ));
    }
    Ok(())
}

fn parse_observer_output(
    stdout: &[u8],
    spec: &CaseSpec,
) -> Result<(Vec<String>, RegexAutomataStartCaseAccounting), InventoryError> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|error| InventoryError::new(format!("observer output is not UTF-8: {error}")))?;
    let lines = stdout.lines().collect::<Vec<_>>();
    let expected_lines = spec
        .assertions
        .len()
        .checked_add(1)
        .ok_or_else(|| InventoryError::new("observer line denominator overflow"))?;
    if lines.len() != expected_lines {
        return Err(InventoryError::new(
            "observer output line denominator mismatch",
        ));
    }
    let header = lines[0].split('\t').collect::<Vec<_>>();
    if header.len() != 12 || header[0] != "FRE_START_V1" || header[1] != spec.case_id {
        return Err(InventoryError::new("observer output header mismatch"));
    }
    let numbers = header[2..]
        .iter()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| InventoryError::new("observer accounting is not numeric"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accounting = RegexAutomataStartCaseAccounting {
        assertions: numbers[0],
        input_bytes: numbers[1],
        context_reads: numbers[2],
        build_entries: numbers[3],
        build_work: numbers[4],
        build_scratch_bytes: numbers[5],
        build_persistent_bytes: numbers[6],
        build_peak_bytes: numbers[7],
        lookup_prospective_work: numbers[8],
        lookup_actual_work: numbers[9],
    };
    validate_accounting(&accounting, spec)?;
    let mut observations = Vec::with_capacity(spec.assertions.len());
    for (line, assertion) in lines[1..].iter().zip(spec.assertions) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields != ["OBS", assertion.id, assertion.expected] {
            return Err(InventoryError::new("observer assertion output mismatch"));
        }
        observations.push(assertion.expected.to_owned());
    }
    Ok((observations, accounting))
}

fn validate_accounting(
    accounting: &RegexAutomataStartCaseAccounting,
    spec: &CaseSpec,
) -> Result<(), InventoryError> {
    if accounting.assertions != spec.assertions.len()
        || accounting.input_bytes != spec.primary_input_bytes
        || accounting.context_reads != spec.primary_context_reads
        || accounting.build_entries != 256
        || accounting.build_work != 8_224
        || accounting.build_scratch_bytes != 256
        || accounting.build_persistent_bytes != EXACT_BUILD_PERSISTENT_BYTES
        || accounting.build_peak_bytes != EXACT_BUILD_PEAK_BYTES
        || accounting.lookup_prospective_work != spec.primary_prospective_work
        || accounting.lookup_actual_work != spec.primary_actual_work
    {
        return Err(InventoryError::new("observer resource accounting mismatch"));
    }
    Ok(())
}

fn parse_selftest_output(
    stdout: &[u8],
) -> Result<RegexAutomataStartSelftestAccounting, InventoryError> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|error| InventoryError::new(format!("selftest output is not UTF-8: {error}")))?;
    let fields = stdout.trim_end().split('\t').collect::<Vec<_>>();
    if fields.len() != 14 || fields[0] != "FRE_START_SELFTEST_V1" {
        return Err(InventoryError::new("selftest output header mismatch"));
    }
    let numbers = fields[1..]
        .iter()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| InventoryError::new("selftest accounting is not numeric"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accounting = RegexAutomataStartSelftestAccounting {
        successful_builds: numbers[0],
        rejected_build_admissions: numbers[1],
        build_prospective_work: numbers[2],
        retained_persistent_bytes: numbers[3],
        peak_bytes: numbers[4],
        successful_lookups: numbers[5],
        rejected_lookup_admissions: numbers[6],
        invalid_windows: numbers[7],
        lookup_input_bytes: numbers[8],
        lookup_prospective_work: numbers[9],
        lookup_actual_work: numbers[10],
        random_access_bytes: numbers[11],
        exhaustive_byte_probes: numbers[12],
    };
    validate_selftest_accounting(&accounting)?;
    Ok(accounting)
}

fn validate_selftest_accounting(
    accounting: &RegexAutomataStartSelftestAccounting,
) -> Result<(), InventoryError> {
    if accounting.successful_builds != 2
        || accounting.rejected_build_admissions != 4
        || accounting.build_prospective_work != 49_344
        || accounting.retained_persistent_bytes != EXACT_SELFTEST_RETAINED_BYTES
        || accounting.peak_bytes != EXACT_SELFTEST_PEAK_BYTES
        || accounting.successful_lookups != 517
        || accounting.rejected_lookup_admissions != 3
        || accounting.invalid_windows != 1
        || accounting.lookup_input_bytes != 1_044
        || accounting.lookup_prospective_work != 41_600
        || accounting.lookup_actual_work != 41_360
        || accounting.random_access_bytes != 517
        || accounting.exhaustive_byte_probes != 512
    {
        return Err(InventoryError::new("selftest resource accounting mismatch"));
    }
    Ok(())
}

fn validate_mode(
    mode: &RegexAutomataStartModeReceipt,
    spec: &ModeSpec,
    source_contracts: &[RegexAutomataStartSourceContract],
) -> Result<(), InventoryError> {
    let expected_args = upstream_compile_arguments(spec);
    if mode.mode_id != spec.id
        || mode.harness != RegexAutomataHarnessKind::Unit
        || mode.default_features != spec.default_features
        || mode.all_features != spec.all_features
        || mode.requested_features != spec.features
        || mode.resolved_features != expected_resolved_features(spec)?
        || mode.cargo_arguments_sha256
            != hash_json(&expected_args, "encode upstream Cargo arguments")?
        || !hex64(&mode.observer_manifest_sha256)
        || !hex64(&mode.lockfile_sha256)
        || !hex64(&mode.lock_package_closure_sha256)
        || mode.lock_packages == 0
        || mode.lock_packages > 256
        || mode
            .resolved_features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || mode
            .resolved_features
            .iter()
            .any(|feature| !feature_token(feature))
        || spec
            .features
            .iter()
            .any(|feature| !mode.resolved_features.contains(feature))
        || mode.observer_dependency_features != mode.resolved_features
        || mode.observer_upstream_manifest_sha256
            != "83e288a27db86536cc16d1b1b82e9c5e89276781340518d234ecc919dde093fc"
        || !hex64(&mode.observer_kernels_manifest_sha256)
        || mode.cases.len() != CASE_SPECS.len()
    {
        return Err(InventoryError::new("start-mode receipt tuple mismatch"));
    }
    validate_command_receipt(&mode.upstream_compile_command)?;
    validate_command_receipt(&mode.observer_lock_command)?;
    validate_command_receipt(&mode.observer_metadata_command)?;
    validate_command_receipt(&mode.observer_compile_command)?;
    validate_command_receipt(&mode.selftest_command)?;
    for receipt in [
        &mode.upstream_compile_command,
        &mode.observer_lock_command,
        &mode.observer_metadata_command,
        &mode.observer_compile_command,
    ] {
        if receipt.post_command_target_file_limit != TARGET_FILE_COUNT_LIMIT
            || receipt.post_command_target_byte_limit != TARGET_RETAINED_BYTES_LIMIT
        {
            return Err(InventoryError::new(
                "Cargo command lacks exact post-command target limit",
            ));
        }
    }
    if mode.selftest_command.post_command_target_file_limit != 0 {
        return Err(InventoryError::new(
            "artifact command unexpectedly carries Cargo target accounting",
        ));
    }
    validate_artifact(&mode.upstream_artifact)?;
    validate_artifact(&mode.observer_artifact)?;
    validate_selftest_accounting(&mode.selftest_accounting)?;
    for ((case, case_spec), source_contract) in
        mode.cases.iter().zip(&CASE_SPECS).zip(source_contracts)
    {
        if case.mode_id != mode.mode_id
            || case.harness != RegexAutomataHarnessKind::Unit
            || case.case_id != case_spec.case_id
            || case.source_contract_sha256
                != hash_json(source_contract, "encode start source contract")?
            || case.observations
                != case_spec
                    .assertions
                    .iter()
                    .map(|assertion| assertion.expected.to_owned())
                    .collect::<Vec<_>>()
            || case.evidence_sha256 != case_evidence(case)?
        {
            return Err(InventoryError::new("start-mode case receipt mismatch"));
        }
        validate_command_receipt(&case.upstream_command)?;
        validate_command_receipt(&case.observer_command)?;
        if case.upstream_command.post_command_target_file_limit != 0
            || case.observer_command.post_command_target_file_limit != 0
        {
            return Err(InventoryError::new(
                "case execution unexpectedly carries Cargo target accounting",
            ));
        }
        validate_accounting(&case.accounting, case_spec)?;
    }
    if mode.evidence_sha256 != mode_evidence(mode)? {
        return Err(InventoryError::new("start-mode evidence seal mismatch"));
    }
    Ok(())
}

fn validate_command_receipt(
    receipt: &RegexAutomataStartCommandReceipt,
) -> Result<(), InventoryError> {
    let no_target = receipt.post_command_target_file_limit == 0
        && receipt.post_command_target_byte_limit == 0
        && receipt.target_files_after == 0
        && receipt.target_bytes_after == 0;
    let bounded_target = receipt.post_command_target_file_limit == TARGET_FILE_COUNT_LIMIT
        && receipt.post_command_target_byte_limit == TARGET_RETAINED_BYTES_LIMIT
        && receipt.target_files_after <= receipt.post_command_target_file_limit
        && receipt.target_bytes_after <= receipt.post_command_target_byte_limit;
    if receipt.exit_code != 0
        || !hex64(&receipt.command_contract_sha256)
        || receipt.stdout_bytes > COMMAND_OUTPUT_LIMIT
        || receipt.stderr_bytes > COMMAND_OUTPUT_LIMIT
        || !hex64(&receipt.stdout_sha256)
        || !hex64(&receipt.stderr_sha256)
        || (!no_target && !bounded_target)
        || receipt.evidence_sha256 != command_receipt_evidence(receipt)?
    {
        return Err(InventoryError::new("start command receipt mismatch"));
    }
    Ok(())
}

fn validate_artifact(artifact: &RegexAutomataStartArtifactIdentity) -> Result<(), InventoryError> {
    let mode = u32::from_str_radix(&artifact.mode, 8)
        .map_err(|_| InventoryError::new("artifact mode is not octal"))?;
    if artifact.bytes == 0
        || artifact.bytes > ARTIFACT_BYTES_LIMIT
        || !hex64(&artifact.sha256)
        || artifact.mode.len() != 4
        || mode != 0o500
        || artifact.uid != unsafe_free_euid()
        || artifact.nlink != 1
        || artifact.device == 0
        || artifact.inode == 0
    {
        return Err(InventoryError::new("start artifact identity mismatch"));
    }
    Ok(())
}

fn case_evidence(case: &RegexAutomataStartCaseReceipt) -> Result<String, InventoryError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        mode_id: &'a str,
        harness: RegexAutomataHarnessKind,
        case_id: &'a str,
        source_contract_sha256: &'a str,
        upstream_command: &'a RegexAutomataStartCommandReceipt,
        observer_command: &'a RegexAutomataStartCommandReceipt,
        observations: &'a [String],
        accounting: &'a RegexAutomataStartCaseAccounting,
    }
    hash_json(
        &Seal {
            mode_id: &case.mode_id,
            harness: case.harness,
            case_id: &case.case_id,
            source_contract_sha256: &case.source_contract_sha256,
            upstream_command: &case.upstream_command,
            observer_command: &case.observer_command,
            observations: &case.observations,
            accounting: &case.accounting,
        },
        "encode start case evidence",
    )
}

fn mode_evidence(mode: &RegexAutomataStartModeReceipt) -> Result<String, InventoryError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        mode_id: &'a str,
        harness: RegexAutomataHarnessKind,
        default_features: bool,
        all_features: bool,
        requested_features: &'a [String],
        resolved_features: &'a [String],
        cargo_arguments_sha256: &'a str,
        observer_manifest_sha256: &'a str,
        lockfile_sha256: &'a str,
        lock_package_closure_sha256: &'a str,
        lock_packages: usize,
        upstream_compile_command: &'a RegexAutomataStartCommandReceipt,
        observer_lock_command: &'a RegexAutomataStartCommandReceipt,
        observer_metadata_command: &'a RegexAutomataStartCommandReceipt,
        observer_compile_command: &'a RegexAutomataStartCommandReceipt,
        observer_upstream_manifest_sha256: &'a str,
        observer_kernels_manifest_sha256: &'a str,
        observer_dependency_features: &'a [String],
        upstream_artifact: &'a RegexAutomataStartArtifactIdentity,
        observer_artifact: &'a RegexAutomataStartArtifactIdentity,
        selftest_command: &'a RegexAutomataStartCommandReceipt,
        selftest_accounting: &'a RegexAutomataStartSelftestAccounting,
        cases: &'a [RegexAutomataStartCaseReceipt],
    }
    hash_json(
        &Seal {
            mode_id: &mode.mode_id,
            harness: mode.harness,
            default_features: mode.default_features,
            all_features: mode.all_features,
            requested_features: &mode.requested_features,
            resolved_features: &mode.resolved_features,
            cargo_arguments_sha256: &mode.cargo_arguments_sha256,
            observer_manifest_sha256: &mode.observer_manifest_sha256,
            lockfile_sha256: &mode.lockfile_sha256,
            lock_package_closure_sha256: &mode.lock_package_closure_sha256,
            lock_packages: mode.lock_packages,
            upstream_compile_command: &mode.upstream_compile_command,
            observer_lock_command: &mode.observer_lock_command,
            observer_metadata_command: &mode.observer_metadata_command,
            observer_compile_command: &mode.observer_compile_command,
            observer_upstream_manifest_sha256: &mode.observer_upstream_manifest_sha256,
            observer_kernels_manifest_sha256: &mode.observer_kernels_manifest_sha256,
            observer_dependency_features: &mode.observer_dependency_features,
            upstream_artifact: &mode.upstream_artifact,
            observer_artifact: &mode.observer_artifact,
            selftest_command: &mode.selftest_command,
            selftest_accounting: &mode.selftest_accounting,
            cases: &mode.cases,
        },
        "encode start mode evidence",
    )
}

fn write_generated_file(path: &Path, bytes: &[u8]) -> Result<(), InventoryError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > GENERATED_FILE_BYTES_LIMIT) {
        return Err(InventoryError::new("generated observer file exceeds bound"));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| InventoryError::new(format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| InventoryError::new(format!("sync {}: {error}", path.display())))?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|error| InventoryError::new(format!("set mode {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| InventoryError::new(format!("sync sealed {}: {error}", path.display())))?;
    drop(file);
    let observed = read_single_link_file(path, GENERATED_FILE_BYTES_LIMIT, Some(0o400))?;
    if observed != bytes {
        return Err(InventoryError::new("generated observer file changed"));
    }
    Ok(())
}

fn seal_existing_generated_file(path: &Path, expected: &[u8]) -> Result<(), InventoryError> {
    let file = open_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat generated file: {error}")))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || !matches!(mode, 0o600 | 0o644)
        || metadata.len() == 0
        || metadata.len() > GENERATED_FILE_BYTES_LIMIT
        || read_artifact_file(&file, metadata.len())? != expected
    {
        return Err(InventoryError::new(
            "generated file pre-seal identity mismatch",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|error| InventoryError::new(format!("seal generated file: {error}")))?;
    file.sync_all()
        .map_err(|error| InventoryError::new(format!("sync generated file: {error}")))?;
    drop(file);
    if read_single_link_file(path, GENERATED_FILE_BYTES_LIMIT, Some(0o400))? != expected {
        return Err(InventoryError::new(
            "generated file post-seal identity mismatch",
        ));
    }
    Ok(())
}

fn authenticate_observer_inputs(
    observer: &Path,
    manifest: &[u8],
    source: &[u8],
    lockfile: &[u8],
) -> Result<(), InventoryError> {
    for (relative, expected) in [
        ("Cargo.toml", manifest),
        ("src/main.rs", source),
        ("Cargo.lock", lockfile),
    ] {
        if read_single_link_file(
            &observer.join(relative),
            GENERATED_FILE_BYTES_LIMIT,
            Some(0o400),
        )? != expected
        {
            return Err(InventoryError::new(format!(
                "generated observer input changed: {relative}"
            )));
        }
    }
    Ok(())
}

fn read_single_link_file(
    path: &Path,
    maximum: u64,
    required_mode: Option<u32>,
) -> Result<Vec<u8>, InventoryError> {
    let file = open_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.len() > maximum
        || required_mode.is_some_and(|required| mode != required)
    {
        return Err(InventoryError::new("unsafe start-mode input file"));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| InventoryError::new("start-mode input length exceeds address space"))?;
    let mut bytes = vec![0_u8; length];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = file
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset)
                    .map_err(|_| InventoryError::new("input read offset overflow"))?,
            )
            .map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))?;
        if read == 0 {
            return Err(InventoryError::new("start-mode input ended early"));
        }
        offset = offset
            .checked_add(read)
            .ok_or_else(|| InventoryError::new("input read offset overflow"))?;
    }
    let observed = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("restat {}: {error}", path.display())))?;
    if observed.file_type().is_symlink()
        || observed.dev() != metadata.dev()
        || observed.ino() != metadata.ino()
        || observed.len() != metadata.len()
        || observed.mode() != metadata.mode()
        || observed.nlink() != metadata.nlink()
    {
        return Err(InventoryError::new(
            "start-mode input path/descriptor identity changed",
        ));
    }
    Ok(bytes)
}

fn output_directory(target: &RegexAutomataStartModeOutputTarget) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        target.canonical_parent.clone()
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from(format!("/proc/self/fd/{}", target.parent.as_raw_fd()))
    }
}

fn output_target_path(
    target: &RegexAutomataStartModeOutputTarget,
) -> Result<PathBuf, InventoryError> {
    if target.name.contains('/') || matches!(target.name.as_str(), "" | "." | "..") {
        return Err(InventoryError::new("unsafe output target name"));
    }
    Ok(output_directory(target).join(&target.name))
}

fn authenticate_output_target(
    target: &RegexAutomataStartModeOutputTarget,
) -> Result<(), InventoryError> {
    let descriptor = target
        .parent
        .metadata()
        .map_err(|error| InventoryError::new(format!("stat output parent descriptor: {error}")))?;
    let path = fs::symlink_metadata(&target.canonical_parent)
        .map_err(|error| InventoryError::new(format!("stat canonical output parent: {error}")))?;
    if !descriptor.file_type().is_dir()
        || !path.file_type().is_dir()
        || path.file_type().is_symlink()
        || descriptor.uid() != unsafe_free_euid()
        || path.uid() != unsafe_free_euid()
        || descriptor.dev() != target.parent_device
        || descriptor.ino() != target.parent_inode
        || path.dev() != target.parent_device
        || path.ino() != target.parent_inode
    {
        return Err(InventoryError::new("output parent identity changed"));
    }
    Ok(())
}

fn write_new_json(
    target: &RegexAutomataStartModeOutputTarget,
    value: &impl Serialize,
) -> Result<(), InventoryError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| InventoryError::new(format!("encode start-mode output: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > REPORT_BYTES_LIMIT {
        return Err(InventoryError::new("start-mode output exceeds bound"));
    }
    let expected_sha256 = sha256(&bytes);
    authenticate_output_target(target)?;
    let path = output_target_path(target)?;
    if fs::symlink_metadata(&path).is_ok() {
        return Err(InventoryError::new(format!(
            "start-mode output already exists: {}",
            path.display()
        )));
    }
    let temporary =
        output_directory(target).join(format!(".{}.tmp.{}", target.name, std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create output: {error}")))?;
    let mut installed = false;
    let result = (|| {
        output
            .write_all(&bytes)
            .map_err(|error| InventoryError::new(format!("write output: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync output: {error}")))?;
        output
            .set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|error| InventoryError::new(format!("seal output: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync sealed output: {error}")))?;
        fs::hard_link(&temporary, &path)
            .map_err(|error| InventoryError::new(format!("install output: {error}")))?;
        installed = true;
        if let Err(error) = fs::remove_file(&temporary) {
            remove_if_descriptor_matches(&path, &output);
            return Err(InventoryError::new(format!("remove temporary: {error}")));
        }
        target
            .parent
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync output parent: {error}")))?;
        authenticate_output_target(target)?;
        let observed = read_single_link_file(&path, REPORT_BYTES_LIMIT_U64, Some(0o400))?;
        if observed != bytes || sha256(&observed) != expected_sha256 {
            return Err(InventoryError::new(
                "published output postcondition mismatch",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        remove_if_descriptor_matches(&temporary, &output);
        if installed {
            remove_if_descriptor_matches(&path, &output);
        }
    }
    result
}

fn remove_if_descriptor_matches(path: &Path, file: &fs::File) {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return;
    };
    let Ok(file_metadata) = file.metadata() else {
        return;
    };
    if !path_metadata.file_type().is_symlink()
        && path_metadata.dev() == file_metadata.dev()
        && path_metadata.ino() == file_metadata.ino()
    {
        let _ = fs::remove_file(path);
    }
}

const OBSERVER_SOURCE: &str = r#"use fre_kernels::{
    ByteStartClass, ByteStartDirection, ByteStartMap, ByteStartMapBuildError,
    ByteStartMapBuildLimits, ByteStartMapLookupError, ByteStartMapLookupLimits,
    ByteStartMapResource,
};
use regex_automata_mode::{Input, util::{look::LookMatcher, start::Config}};

fn main() {
    let mut args = std::env::args();
    let _program = args.next().unwrap();
    let case = args.next().expect("one exact case argument");
    assert!(args.next().is_none(), "one exact case argument");
    let terminator = LookMatcher::default().get_line_terminator();
    assert_eq!(terminator, b'\n');
    if case == "--selftest" {
        resource_selftest(terminator);
        return;
    }
    match case.as_str() {
        "util::start::tests::start_fwd" => run_fwd(terminator),
        "util::start::tests::start_fwd_done_range" => run_fwd_done(terminator),
        "util::start::tests::start_rev" => run_rev(terminator),
        "util::start::tests::start_rev_done_range" => run_rev_done(terminator),
        _ => panic!("foreign start case"),
    }
}

fn exact_build_limits() -> ByteStartMapBuildLimits {
    let needed = ByteStartMap::build_requirements();
    ByteStartMapBuildLimits {
        max_work: needed.work,
        max_scratch_bytes: needed.scratch_bytes,
        max_persistent_bytes: needed.persistent_bytes,
        max_peak_bytes: needed.peak_bytes,
    }
}

fn exact_lookup_limits(
    accounting: fre_kernels::ByteStartMapLookupAccounting,
) -> ByteStartMapLookupLimits {
    ByteStartMapLookupLimits {
        max_input_bytes: accounting.input_bytes,
        max_work: accounting.prospective_work,
        max_random_access_bytes: accounting.random_access_bytes,
    }
}

fn resource_selftest(terminator: u8) {
    let needed = ByteStartMap::build_requirements();
    assert_eq!(needed.initialized_entries, 256);
    assert_eq!(needed.work, 8_224);
    assert_eq!(needed.scratch_bytes, 256);
    assert_eq!(needed.persistent_bytes, 296);
    assert_eq!(needed.peak_bytes, 552);
    let exact = exact_build_limits();
    let map = ByteStartMap::build(terminator, exact).unwrap();
    assert_eq!(map.build_accounting(), needed);
    let build_cases = [
        (
            ByteStartMapBuildLimits { max_work: needed.work - 1, ..exact },
            ByteStartMapResource::BuildWork,
        ),
        (
            ByteStartMapBuildLimits {
                max_scratch_bytes: needed.scratch_bytes - 1,
                ..exact
            },
            ByteStartMapResource::ScratchBytes,
        ),
        (
            ByteStartMapBuildLimits {
                max_persistent_bytes: needed.persistent_bytes - 1,
                ..exact
            },
            ByteStartMapResource::PersistentBytes,
        ),
        (
            ByteStartMapBuildLimits {
                max_peak_bytes: needed.peak_bytes - 1,
                ..exact
            },
            ByteStartMapResource::PeakBytes,
        ),
    ];
    for (limits, expected) in build_cases {
        assert!(matches!(
            ByteStartMap::build(terminator, limits),
            Err(ByteStartMapBuildError::ResourceLimit { resource, .. }) if resource == expected
        ));
    }

    let lookup = map
        .lookup_requirements(3, ByteStartDirection::Forward, 1, 3)
        .unwrap();
    let exact_lookup = exact_lookup_limits(lookup);
    assert_eq!(
        map.lookup(b"abc", ByteStartDirection::Forward, 1, 3, exact_lookup)
            .unwrap()
            .class,
        ByteStartClass::WordByte,
    );
    let lookup_cases = [
        (
            ByteStartMapLookupLimits {
                max_input_bytes: lookup.input_bytes - 1,
                ..exact_lookup
            },
            ByteStartMapResource::InputBytes,
        ),
        (
            ByteStartMapLookupLimits {
                max_work: lookup.prospective_work - 1,
                ..exact_lookup
            },
            ByteStartMapResource::LookupWork,
        ),
        (
            ByteStartMapLookupLimits {
                max_random_access_bytes: lookup.random_access_bytes - 1,
                ..exact_lookup
            },
            ByteStartMapResource::RandomAccessBytes,
        ),
    ];
    for (limits, expected) in lookup_cases {
        assert!(matches!(
            map.lookup(b"abc", ByteStartDirection::Forward, 1, 3, limits),
            Err(ByteStartMapLookupError::ResourceLimit { resource, .. }) if resource == expected
        ));
    }
    let zero = ByteStartMapLookupLimits {
        max_input_bytes: 0,
        max_work: 0,
        max_random_access_bytes: 0,
    };
    assert!(matches!(
        map.lookup(b"abc", ByteStartDirection::Forward, 0, 4, zero),
        Err(ByteStartMapLookupError::InvalidWindow { .. })
    ));

    for byte in u8::MIN..=u8::MAX {
        let forward = [byte, b'x'];
        let input = Input::new(&forward).range(1..2);
        assert_eq!(Config::from_input_forward(&input).get_look_behind(), Some(byte));
        assert_eq!(
            map.lookup(
                &forward,
                ByteStartDirection::Forward,
                1,
                2,
                exact_lookup_limits(
                    map.lookup_requirements(2, ByteStartDirection::Forward, 1, 2)
                        .unwrap(),
                ),
            )
            .unwrap()
            .class,
            classify(byte, terminator),
        );
        let reverse = [b'x', byte];
        let input = Input::new(&reverse).range(0..1);
        assert_eq!(Config::from_input_reverse(&input).get_look_behind(), Some(byte));
        assert_eq!(
            map.lookup(
                &reverse,
                ByteStartDirection::Reverse,
                0,
                1,
                exact_lookup_limits(
                    map.lookup_requirements(2, ByteStartDirection::Reverse, 0, 1)
                        .unwrap(),
                ),
            )
            .unwrap()
            .class,
            classify(byte, terminator),
        );
    }
    let custom = ByteStartMap::build(b'a', exact).unwrap();
    assert_eq!(lookup_byte(&custom, b'a'), ByteStartClass::CustomLineTerminator);
    assert_eq!(lookup_byte(&custom, b'b'), ByteStartClass::WordByte);
    assert_eq!(lookup_byte(&custom, b'\n'), ByteStartClass::LineLf);
    assert_eq!(lookup_byte(&custom, b'\r'), ByteStartClass::LineCr);
    println!(
        "FRE_START_SELFTEST_V1\t2\t4\t49344\t{}\t{}\t517\t3\t1\t1044\t41600\t41360\t517\t512",
        needed.persistent_bytes * 2,
        needed.persistent_bytes * 2 + needed.scratch_bytes,
    );
}

fn lookup_byte(map: &ByteStartMap, byte: u8) -> ByteStartClass {
    let accounting = map
        .lookup_requirements(2, ByteStartDirection::Forward, 1, 2)
        .unwrap();
    map.lookup(
        &[byte, b'x'],
        ByteStartDirection::Forward,
        1,
        2,
        exact_lookup_limits(accounting),
    )
    .unwrap()
    .class
}

fn classify(byte: u8, terminator: u8) -> ByteStartClass {
    if !matches!(terminator, b'\r' | b'\n') && byte == terminator {
        ByteStartClass::CustomLineTerminator
    } else if byte == b'\n' {
        ByteStartClass::LineLf
    } else if byte == b'\r' {
        ByteStartClass::LineCr
    } else if byte == b'_' || byte.is_ascii_alphanumeric() {
        ByteStartClass::WordByte
    } else {
        ByteStartClass::NonWordByte
    }
}

fn observe(
    map: &ByteStartMap,
    direction: ByteStartDirection,
    haystack: &[u8],
    start: usize,
    end: usize,
) -> (ByteStartClass, fre_kernels::ByteStartMapLookupAccounting) {
    let input = Input::new(haystack).range(start..end);
    let upstream = match direction {
        ByteStartDirection::Forward => Config::from_input_forward(&input).get_look_behind(),
        ByteStartDirection::Reverse => Config::from_input_reverse(&input).get_look_behind(),
    };
    let expected_byte = match direction {
        ByteStartDirection::Forward => start.checked_sub(1).filter(|&index| index < haystack.len()),
        ByteStartDirection::Reverse => Some(end).filter(|&index| index < haystack.len()),
    }
    .map(|index| haystack[index]);
    assert_eq!(upstream, expected_byte);
    let accounting = map
        .lookup_requirements(haystack.len(), direction, start, end)
        .unwrap();
    let result = map
        .lookup(
            haystack,
            direction,
            start,
            end,
            exact_lookup_limits(accounting),
        )
        .unwrap();
    assert_eq!(result.accounting, accounting);
    (result.class, accounting)
}

fn run_case(
    case: &str,
    terminator: u8,
    vectors: &[(ByteStartDirection, &[u8], usize, usize, &str, &str)],
) {
    let map = ByteStartMap::build(terminator, exact_build_limits()).unwrap();
    let build = map.build_accounting();
    let mut input_bytes = 0usize;
    let mut reads = 0usize;
    let mut prospective = 0usize;
    let mut actual = 0usize;
    let mut observations = Vec::new();
    for &(direction, haystack, start, end, id, expected) in vectors {
        let (class, accounting) = observe(&map, direction, haystack, start, end);
        assert_eq!(label(class), expected);
        input_bytes += haystack.len();
        reads += accounting.random_access_bytes;
        prospective += accounting.prospective_work;
        actual += accounting.actual_work;
        observations.push((id, expected));
    }
    println!(
        "FRE_START_V1\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        case,
        observations.len(),
        input_bytes,
        reads,
        build.initialized_entries,
        build.work,
        build.scratch_bytes,
        build.persistent_bytes,
        build.peak_bytes,
        prospective,
        actual,
    );
    for (id, observation) in observations {
        println!("OBS\t{id}\t{observation}");
    }
}

fn run_fwd(terminator: u8) {
    run_case(
        "util::start::tests::start_fwd",
        terminator,
        &[
            (ByteStartDirection::Forward, b"", 0, 0, "start-fwd-empty-text", "Text"),
            (ByteStartDirection::Forward, b"abc", 0, 3, "start-fwd-begin-text", "Text"),
            (ByteStartDirection::Forward, b"\nabc", 0, 3, "start-fwd-begin-lf-text", "Text"),
            (ByteStartDirection::Forward, b"\nabc", 1, 3, "start-fwd-line-lf", "LineLF"),
            (ByteStartDirection::Forward, b"\rabc", 1, 3, "start-fwd-line-cr", "LineCR"),
            (ByteStartDirection::Forward, b"abc", 1, 3, "start-fwd-word", "WordByte"),
            (ByteStartDirection::Forward, b" abc", 1, 3, "start-fwd-nonword", "NonWordByte"),
        ],
    );
}

fn run_fwd_done(terminator: u8) {
    run_case(
        "util::start::tests::start_fwd_done_range",
        terminator,
        &[(ByteStartDirection::Forward, b"", 1, 0, "start-fwd-done-text", "Text")],
    );
}

fn run_rev(terminator: u8) {
    run_case(
        "util::start::tests::start_rev",
        terminator,
        &[
            (ByteStartDirection::Reverse, b"", 0, 0, "start-rev-empty-text", "Text"),
            (ByteStartDirection::Reverse, b"abc", 0, 3, "start-rev-end-text", "Text"),
            (ByteStartDirection::Reverse, b"abc\n", 0, 4, "start-rev-end-lf-text", "Text"),
            (ByteStartDirection::Reverse, b"abc\nz", 0, 3, "start-rev-line-lf", "LineLF"),
            (ByteStartDirection::Reverse, b"abc\rz", 0, 3, "start-rev-line-cr", "LineCR"),
            (ByteStartDirection::Reverse, b"abc", 0, 2, "start-rev-word", "WordByte"),
            (ByteStartDirection::Reverse, b"abc ", 0, 3, "start-rev-nonword", "NonWordByte"),
        ],
    );
}

fn run_rev_done(terminator: u8) {
    run_case(
        "util::start::tests::start_rev_done_range",
        terminator,
        &[(ByteStartDirection::Reverse, b"", 1, 0, "start-rev-done-text", "Text")],
    );
}

fn label(class: ByteStartClass) -> &'static str {
    match class {
        ByteStartClass::NonWordByte => "NonWordByte",
        ByteStartClass::WordByte => "WordByte",
        ByteStartClass::Text => "Text",
        ByteStartClass::LineLf => "LineLF",
        ByteStartClass::LineCr => "LineCR",
        ByteStartClass::CustomLineTerminator => "CustomLineTerminator",
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSITION_ADVERSARIAL_FIXTURE: &str =
        include_str!("../fixtures/start-transition-v11-adversarial-v1.tsv");
    const TRANSITION_ADVERSARIAL_FIXTURE_SHA256: &str =
        "db402f66050c4c88d77032da445e71c0fca8f8d2a89582cc3e831f42854c952a";

    #[test]
    fn exact_target_and_source_contract_seals_are_exhaustive() {
        let specs = mode_specs()
            .into_iter()
            .filter(|spec| spec.harness == RegexAutomataHarnessKind::Unit)
            .collect::<Vec<_>>();
        let modes = specs
            .iter()
            .map(|spec| spec.id.clone())
            .collect::<BTreeSet<_>>();
        let cases = CASE_IDS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let targets = modes
            .iter()
            .flat_map(|mode| {
                cases
                    .iter()
                    .map(move |case| format!("{mode}\tunit\t{case}"))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(specs.len(), REGEX_AUTOMATA_START_MODE_COUNT);
        assert_eq!(targets.len(), REGEX_AUTOMATA_START_MODE_MEMBERSHIPS);
        assert_eq!(hash_lines(&modes), MODE_IDS_SHA256);
        assert_eq!(hash_lines(&cases), CASE_IDS_SHA256);
        assert_eq!(hash_lines(&targets), TARGET_MEMBERSHIPS_SHA256);

        let contracts = source_contracts().unwrap();
        assert_eq!(contracts.len(), 4);
        assert_eq!(
            contracts
                .iter()
                .map(|contract| contract.assertions.len())
                .sum::<usize>(),
            EXPECTED_ASSERTIONS_PER_MODE,
        );
        let identities = contracts
            .iter()
            .flat_map(|contract| {
                contract.assertions.iter().map(move |assertion| {
                    (
                        contract.case_id.clone(),
                        assertion.assertion_id.clone(),
                        assertion.source_line,
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(identities.len(), EXPECTED_ASSERTIONS_PER_MODE);
        assert_eq!(START_FIXTURE_BYTES, 2_299);
    }

    #[test]
    fn observer_output_requires_ordered_assertions_and_exact_accounting() {
        let spec = &CASE_SPECS[1];
        let valid = format!(
            "FRE_START_V1\t{}\t1\t0\t0\t256\t8224\t256\t296\t552\t80\t64\nOBS\tstart-fwd-done-text\tText\n",
            spec.case_id,
        );
        let (observations, accounting) = parse_observer_output(valid.as_bytes(), spec).unwrap();
        assert_eq!(observations, ["Text"]);
        assert_eq!(accounting.build_peak_bytes, EXACT_BUILD_PEAK_BYTES);

        assert!(
            parse_observer_output(valid.replace("\tText\n", "\tLineLF\n").as_bytes(), spec)
                .is_err()
        );
        assert!(
            parse_observer_output(valid.replace("\t8224\t", "\t8223\t").as_bytes(), spec).is_err()
        );
        assert!(parse_observer_output(valid.lines().next().unwrap().as_bytes(), spec).is_err());
    }

    #[test]
    fn nested_evidence_seals_reject_tampering() {
        let output = BoundedCommandOutput {
            output: Output {
                status: std::process::ExitStatus::default(),
                stdout: b"ok\n".to_vec(),
                stderr: Vec::new(),
            },
            command_contract_sha256: "0".repeat(64),
            post_command_target_file_limit: 0,
            post_command_target_byte_limit: 0,
            target_files_after: 0,
            target_bytes_after: 0,
        };
        let mut receipt = successful_command_receipt(&output, "fixture").unwrap();
        validate_command_receipt(&receipt).unwrap();
        receipt.stdout_bytes += 1;
        assert!(validate_command_receipt(&receipt).is_err());
    }

    #[test]
    fn selftest_accounting_requires_exact_limits_and_one_below_failures() {
        let valid = "FRE_START_SELFTEST_V1\t2\t4\t49344\t592\t848\t517\t3\t1\t1044\t41600\t41360\t517\t512\n";
        let accounting = parse_selftest_output(valid.as_bytes()).unwrap();
        assert_eq!(
            accounting.retained_persistent_bytes,
            EXACT_SELFTEST_RETAINED_BYTES
        );
        assert_eq!(accounting.peak_bytes, EXACT_SELFTEST_PEAK_BYTES);
        for invalid in [
            valid.replace("\t592\t", "\t591\t"),
            valid.replace("\t848\t", "\t847\t"),
            valid.replace("\t49344\t", "\t49343\t"),
            valid.replace("\t41600\t", "\t41599\t"),
        ] {
            assert!(parse_selftest_output(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn exact_feature_closure_rejects_mode_projection() {
        let specs = mode_specs();
        let default = specs
            .iter()
            .find(|spec| spec.id == "package-default-unit")
            .unwrap();
        let all = specs
            .iter()
            .find(|spec| spec.id == "vcs-all-features-unit")
            .unwrap();
        let default_features = expected_resolved_features(default).unwrap();
        let all_features = expected_resolved_features(all).unwrap();
        assert!(default_features.contains(&"default".to_owned()));
        assert_eq!(all_features, DECLARED_FEATURES.map(str::to_owned));
        assert_ne!(default_features, all_features);
    }

    #[test]
    fn observer_lock_rejects_unpinned_registry_identity() {
        let registry = "registry+https://github.com/rust-lang/crates.io-index";
        let checksum = "1".repeat(64);
        let generated = format!(
            "version = 4\n\n[[package]]\nname = \"start-mode-observer\"\nversion = \"0.0.0\"\n\n[[package]]\nname = \"regex-automata\"\nversion = \"0.4.14\"\n\n[[package]]\nname = \"fre-kernels\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"fre-exact-alloc\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\nsource = \"{registry}\"\nchecksum = \"{checksum}\"\n"
        );
        let upstream = format!(
            "version = 3\n\n[[package]]\nname = \"regex-automata\"\nversion = \"0.4.14\"\n\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\nsource = \"{registry}\"\nchecksum = \"{checksum}\"\n"
        );
        let candidate = "version = 4\n\n[[package]]\nname = \"fre-kernels\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"fre-exact-alloc\"\nversion = \"0.1.0\"\n";
        validate_observer_lock(
            generated.as_bytes(),
            upstream.as_bytes(),
            candidate.as_bytes(),
        )
        .unwrap();
        let forged = generated.replace(&checksum, &"2".repeat(64));
        assert!(
            validate_observer_lock(forged.as_bytes(), upstream.as_bytes(), candidate.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn bounded_pipe_retains_only_cap_plus_overflow_witness() {
        let (bytes, overflow) = bounded_pipe(&b"abc"[..], 3).unwrap();
        assert_eq!(bytes, b"abc");
        assert!(!overflow);
        let (bytes, overflow) = bounded_pipe(&b"abcde"[..], 3).unwrap();
        assert_eq!(bytes, b"abcd");
        assert!(overflow);
    }

    #[test]
    fn candidate_scope_parser_requires_exact_nul_delimited_paths() {
        let paths = parse_candidate_scope(
            b"tools/rust-regex-conformance/src/lib.rs\0tools/rust-regex-conformance/src/main.rs\0",
        )
        .unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains("tools/rust-regex-conformance/src/lib.rs"));
        assert!(parse_candidate_scope(b"path-without-terminator").is_err());
        assert!(parse_candidate_scope(b"duplicate\0duplicate\0").is_err());
        assert!(parse_candidate_scope(b"line\nbreak\0").is_err());
    }

    #[test]
    fn prepared_artifact_executes_authenticated_bytes() {
        let root = std::env::temp_dir().join(format!(
            "fre-start-held-artifact-test-{}",
            std::process::id()
        ));
        create_private_directory(&root).unwrap();
        let build = root.join("build");
        let held_root = root.join("held");
        create_private_directory(&build).unwrap();
        create_private_directory(&held_root).unwrap();
        let source = build.join("fixture");
        fs::copy(std::env::current_exe().unwrap(), &source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let held = hold_artifact(&source, &held_root.join("copy"), &build).unwrap();
        prepare_held_artifact(&held).unwrap();
        #[cfg(target_os = "macos")]
        assert!(held.path.exists());
        #[cfg(not(target_os = "macos"))]
        assert!(!held.path.exists());
        let output = run_held_executable(
            &held,
            "held-test-fixture",
            &["fre-no-such-test", "--exact"],
            &root,
        )
        .unwrap();
        assert!(output.status.success());
        assert!(
            output
                .stdout
                .windows(b"running 0 tests".len())
                .any(|window| window == b"running 0 tests")
        );
        verify_prepared_artifact(&held).unwrap();
        drop(held);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn held_output_parent_publishes_one_immutable_report() {
        let root =
            std::env::temp_dir().join(format!("fre-start-output-test-{}", std::process::id()));
        create_private_directory(&root).unwrap();
        let path = root.join("report.json");
        let target = preflight_regex_automata_start_mode_output(&path, &[]).unwrap();
        let value = BTreeMap::from([("result".to_owned(), "pass".to_owned())]);
        write_new_json(&target, &value).unwrap();
        let bytes = read_single_link_file(&path, REPORT_BYTES_LIMIT_U64, Some(0o400)).unwrap();
        assert_eq!(
            serde_json::from_slice::<BTreeMap<String, String>>(&bytes).unwrap(),
            value
        );
        assert!(write_new_json(&target, &value).is_err());
        drop(target);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn generated_lock_transition_accepts_only_safe_initial_modes() {
        let root = std::env::temp_dir().join(format!("fre-start-lock-test-{}", std::process::id()));
        create_private_directory(&root).unwrap();
        let bytes = b"version = 4\n";
        let safe = root.join("safe.lock");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&safe)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        seal_existing_generated_file(&safe, bytes).unwrap();
        assert_eq!(
            read_single_link_file(&safe, GENERATED_FILE_BYTES_LIMIT, Some(0o400)).unwrap(),
            bytes
        );

        let unsafe_path = root.join("unsafe.lock");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&unsafe_path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o664))
            .unwrap();
        drop(file);
        assert!(seal_existing_generated_file(&unsafe_path, bytes).is_err());
        fs::remove_file(safe).unwrap();
        fs::remove_file(unsafe_path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn observer_is_generic_across_modes_and_contains_adversarial_gates() {
        assert!(!OBSERVER_SOURCE.contains("vcs-lib-"));
        assert!(!OBSERVER_SOURCE.contains("package-default-unit"));
        assert!(OBSERVER_SOURCE.contains("for byte in u8::MIN..=u8::MAX"));
        assert!(OBSERVER_SOURCE.contains("max_peak_bytes: needed.peak_bytes - 1"));
        assert!(OBSERVER_SOURCE.contains("Config::from_input_forward"));
        assert!(OBSERVER_SOURCE.contains("Config::from_input_reverse"));
    }

    #[test]
    fn transition_adversarial_fixture_is_persistent_and_exact() {
        let (fields, mutations) = parse_transition_adversarial_fixture();
        assert_eq!(fields["baseline_counts"], "151,3691,0,3842");
        assert_eq!(fields["current_counts"], "267,3575,0,3842");
        assert_eq!(fields["retained_memberships"], "4");
        assert_eq!(fields["gained_memberships"], "116");
        assert_eq!(fields["lost_memberships"], "0");
        assert_eq!(
            mutations,
            BTreeSet::from([
                "baseline-counts".to_owned(),
                "baseline-retained-pass".to_owned(),
                "baseline-revision".to_owned(),
                "baseline-tree".to_owned(),
                "duplicate-target".to_owned(),
                "missing-mode".to_owned(),
                "missing-target".to_owned(),
                "qualification-gain".to_owned(),
                "qualification-retained-receipt".to_owned(),
                "qualification-target-receipt".to_owned(),
                "resealed-case-observation".to_owned(),
                "stale-v5-baseline".to_owned(),
                "target-already-pass".to_owned(),
            ])
        );
    }

    #[test]
    #[ignore = "requires authenticated external inventory, baseline and mode fixtures"]
    #[allow(
        clippy::too_many_lines,
        reason = "all resealed transition mutations remain adjacent to the accepted fixture"
    )]
    fn authenticated_v11_start_transition_rejects_resealed_adversarial_mutations() {
        let (fields, mutations) = parse_transition_adversarial_fixture();
        let inventory_path = authenticated_transition_fixture(
            "FRE_START_INVENTORY",
            fields.get("inventory_sha256").unwrap(),
        );
        let baseline_path = authenticated_transition_fixture(
            "FRE_START_CURRENT_BASELINE",
            fields.get("baseline_report_sha256").unwrap(),
        );
        let stale_v5_path = authenticated_transition_fixture(
            "FRE_START_V5_STALE",
            fields.get("stale_v5_report_sha256").unwrap(),
        );
        let mode_fixture_path = authenticated_transition_fixture(
            "FRE_START_MODE_FIXTURE",
            fields.get("mode_fixture_sha256").unwrap(),
        );
        let inventory = crate::read_regex_automata_corpus_report(&inventory_path).unwrap();
        let baseline = read_regex_automata_start_baseline(&baseline_path, &inventory)
            .unwrap()
            .report;
        let stale_v5 =
            crate::read_regex_automata_adapter_report(&stale_v5_path, &inventory).unwrap();
        let mode_fixture = serde_json::from_slice::<RegexAutomataStartModeMatrixReport>(
            &fs::read(&mode_fixture_path).unwrap(),
        )
        .unwrap();
        let candidate = CandidateIdentity {
            revision: "f".repeat(40),
            tree: "e".repeat(40),
            tracked_and_untracked_worktree_clean: true,
        };
        let qualification = build_qualification(
            &inventory,
            &baseline,
            &candidate,
            &mode_fixture.payload.modes,
        )
        .unwrap();
        assert_eq!(
            qualification.baseline_counts,
            parse_transition_counts(fields.get("baseline_counts").unwrap()),
        );
        assert_eq!(
            qualification.current_counts,
            parse_transition_counts(fields.get("current_counts").unwrap()),
        );
        assert_eq!(
            qualification.gained_memberships,
            fields["gained_memberships"].parse::<usize>().unwrap(),
        );
        assert_eq!(
            qualification.retained_target_memberships,
            fields["retained_memberships"].parse::<usize>().unwrap(),
        );
        assert_eq!(
            qualification.lost_memberships,
            fields["lost_memberships"].parse::<usize>().unwrap(),
        );
        validate_qualification(
            &inventory,
            &candidate,
            &mode_fixture.payload.modes,
            &qualification,
        )
        .unwrap();
        let target_identities = mode_fixture
            .payload
            .modes
            .iter()
            .flat_map(|mode| {
                mode.cases
                    .iter()
                    .map(move |case| (mode.mode_id.clone(), mode.harness, case.case_id.clone()))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            target_identities.len(),
            REGEX_AUTOMATA_START_MODE_MEMBERSHIPS
        );
        let mut retained_passes = 0;
        let mut target_transitions = 0;
        for (before, after) in baseline
            .payload
            .receipts
            .iter()
            .zip(&qualification.current_receipts)
        {
            let identity = (
                before.mode_id.clone(),
                before.harness,
                before.case_id.clone(),
            );
            if matches!(
                before.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            ) {
                assert_eq!(before, after);
                retained_passes += 1;
            } else if target_identities.contains(&identity) {
                assert!(matches!(
                    before.disposition,
                    RegexAutomataAdapterDisposition::Unsupported { .. }
                ));
                assert!(matches!(
                    after.disposition,
                    RegexAutomataAdapterDisposition::Pass { .. }
                ));
                target_transitions += 1;
            } else {
                assert_eq!(before, after);
            }
        }
        assert_eq!(retained_passes, 151);
        assert_eq!(target_transitions, 116);

        for mutation in mutations {
            match mutation.as_str() {
                "baseline-revision" => {
                    let mut changed = baseline.clone();
                    changed.payload.candidate.revision = "0".repeat(40);
                    reseal_adapter_report(&mut changed);
                    assert!(authenticate_exact_baseline(&inventory, &changed).is_err());
                }
                "baseline-tree" => {
                    let mut changed = baseline.clone();
                    changed.payload.candidate.tree = "1".repeat(40);
                    reseal_adapter_report(&mut changed);
                    assert!(authenticate_exact_baseline(&inventory, &changed).is_err());
                }
                "stale-v5-baseline" => {
                    assert!(authenticate_exact_baseline(&inventory, &stale_v5).is_err());
                }
                "baseline-counts" => {
                    let mut changed = baseline.clone();
                    let receipt = changed
                        .payload
                        .receipts
                        .iter_mut()
                        .find(|receipt| {
                            matches!(
                                receipt.disposition,
                                RegexAutomataAdapterDisposition::Unsupported { .. }
                            )
                        })
                        .unwrap();
                    receipt.disposition = RegexAutomataAdapterDisposition::Fault {
                        stage: "adversarial-fixture".to_owned(),
                        reason_code: "resealed-count-change".to_owned(),
                    };
                    reseal_adapter_report(&mut changed);
                    assert!(authenticate_exact_baseline(&inventory, &changed).is_err());
                }
                "baseline-retained-pass" => {
                    let mut changed = baseline.clone();
                    let receipt = changed
                        .payload
                        .receipts
                        .iter_mut()
                        .find(|receipt| {
                            matches!(
                                receipt.disposition,
                                RegexAutomataAdapterDisposition::Pass { .. }
                            )
                        })
                        .unwrap();
                    let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
                        &mut receipt.disposition
                    else {
                        unreachable!()
                    };
                    *evidence_sha256 = "2".repeat(64);
                    reseal_adapter_report(&mut changed);
                    assert!(authenticate_exact_baseline(&inventory, &changed).is_err());
                }
                "target-already-pass" => {
                    let mut changed = baseline.clone();
                    let receipt = changed
                        .payload
                        .receipts
                        .iter_mut()
                        .find(|receipt| receipt.case_id == CASE_IDS[0])
                        .unwrap();
                    receipt.disposition = RegexAutomataAdapterDisposition::Pass {
                        evidence_sha256: "3".repeat(64),
                    };
                    reseal_adapter_report(&mut changed);
                    assert!(authenticate_exact_baseline(&inventory, &changed).is_err());
                }
                "missing-mode" => {
                    let mut modes = mode_fixture.payload.modes.clone();
                    modes.pop().unwrap();
                    assert!(
                        build_qualification(&inventory, &baseline, &candidate, &modes).is_err()
                    );
                }
                "missing-target" => {
                    let mut modes = mode_fixture.payload.modes.clone();
                    modes[0].cases.pop().unwrap();
                    modes[0].evidence_sha256 = mode_evidence(&modes[0]).unwrap();
                    assert!(
                        build_qualification(&inventory, &baseline, &candidate, &modes).is_err()
                    );
                }
                "duplicate-target" => {
                    let mut modes = mode_fixture.payload.modes.clone();
                    modes[0].cases[1] = modes[0].cases[0].clone();
                    modes[0].evidence_sha256 = mode_evidence(&modes[0]).unwrap();
                    assert!(
                        build_qualification(&inventory, &baseline, &candidate, &modes).is_err()
                    );
                }
                "resealed-case-observation" => {
                    let mut modes = mode_fixture.payload.modes.clone();
                    let case = &mut modes[0].cases[0];
                    case.observations[0].push_str("-forged");
                    case.evidence_sha256 = case_evidence(case).unwrap();
                    modes[0].evidence_sha256 = mode_evidence(&modes[0]).unwrap();
                    assert!(
                        build_qualification(&inventory, &baseline, &candidate, &modes).is_err()
                    );
                }
                "qualification-retained-receipt" => {
                    let mut changed = qualification.clone();
                    let receipt = changed
                        .current_receipts
                        .iter_mut()
                        .find(|receipt| {
                            matches!(
                                receipt.disposition,
                                RegexAutomataAdapterDisposition::Pass { .. }
                            ) && !CASE_IDS.contains(&receipt.case_id.as_str())
                        })
                        .unwrap();
                    let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
                        &mut receipt.disposition
                    else {
                        unreachable!()
                    };
                    *evidence_sha256 = "4".repeat(64);
                    assert!(
                        validate_qualification(
                            &inventory,
                            &candidate,
                            &mode_fixture.payload.modes,
                            &changed,
                        )
                        .is_err()
                    );
                }
                "qualification-target-receipt" => {
                    let mut changed = qualification.clone();
                    let receipt = changed
                        .current_receipts
                        .iter_mut()
                        .find(|receipt| receipt.case_id == CASE_IDS[0])
                        .unwrap();
                    let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
                        &mut receipt.disposition
                    else {
                        panic!("qualified start target is not a pass")
                    };
                    *evidence_sha256 = "5".repeat(64);
                    assert!(
                        validate_qualification(
                            &inventory,
                            &candidate,
                            &mode_fixture.payload.modes,
                            &changed,
                        )
                        .is_err()
                    );
                }
                "qualification-gain" => {
                    let mut changed = qualification.clone();
                    changed.gained_memberships += 1;
                    assert!(
                        validate_qualification(
                            &inventory,
                            &candidate,
                            &mode_fixture.payload.modes,
                            &changed,
                        )
                        .is_err()
                    );
                }
                other => panic!("unknown transition adversarial mutation {other:?}"),
            }
        }
    }

    fn parse_transition_adversarial_fixture() -> (BTreeMap<String, String>, BTreeSet<String>) {
        assert_eq!(
            sha256(TRANSITION_ADVERSARIAL_FIXTURE.as_bytes()),
            TRANSITION_ADVERSARIAL_FIXTURE_SHA256,
        );
        let mut fields = BTreeMap::new();
        let mut mutations = BTreeSet::new();
        for line in TRANSITION_ADVERSARIAL_FIXTURE.lines() {
            let (key, value) = line.split_once('\t').unwrap();
            assert!(!key.is_empty() && !value.is_empty());
            if key == "mutation" {
                assert!(mutations.insert(value.to_owned()));
            } else {
                assert!(fields.insert(key.to_owned(), value.to_owned()).is_none());
            }
        }
        assert_eq!(
            fields["schema"],
            "fre.regex-automata-start-transition-adversarial.v1"
        );
        assert_eq!(fields.len(), 10);
        assert_eq!(mutations.len(), 13);
        (fields, mutations)
    }

    fn authenticated_transition_fixture(variable: &str, expected_sha256: &str) -> PathBuf {
        let path = PathBuf::from(std::env::var(variable).expect("authenticated fixture path"));
        let metadata = fs::symlink_metadata(&path).expect("stat authenticated fixture");
        assert!(!metadata.file_type().is_symlink());
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), unsafe_free_euid());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o400);
        assert_eq!(sha256(&fs::read(&path).unwrap()), expected_sha256);
        path
    }

    fn parse_transition_counts(value: &str) -> RegexAutomataAdapterCounts {
        let values = value
            .split(',')
            .map(|field| field.parse::<usize>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 4);
        RegexAutomataAdapterCounts {
            pass: values[0],
            unsupported: values[1],
            fault: values[2],
            total: values[3],
        }
    }

    fn reseal_adapter_report(report: &mut RegexAutomataAdapterReport) {
        report.payload.counts = adapter_counts(&report.payload.receipts);
        report.payload_sha256 =
            hash_json(&report.payload, "encode adversarial start baseline payload").unwrap();
    }
}
