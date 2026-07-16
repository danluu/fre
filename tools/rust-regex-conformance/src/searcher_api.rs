//! Executable conformance for the pinned upstream pattern-searcher tests.

use std::{
    fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use fre::{AggregateBuilder, AggregateRunLimits, AggregateSearchStep, RustProfile};
use serde::{Deserialize, Serialize};

use crate::{CandidateIdentity, InventoryError, UPSTREAM_REPOSITORY, UPSTREAM_REVISION, sha256};

/// Stable schema for the non-TOML searcher API report.
pub const SEARCHER_API_REPORT_SCHEMA: &str = "fre.upstream-rust-regex.searcher-api-report.v1";
/// Exact number of named tests in upstream `tests/searcher.rs` at the pin.
pub const SEARCHER_API_CASES: usize = 11;

const UPSTREAM_PACKAGE: &str = "regex";
const UPSTREAM_VERSION: &str = "1.12.4";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const VCS_INFO_PATH: &str = ".cargo_vcs_info.json";
const VCS_INFO_SHA256: &str = "985255199f0cbe66b15087ac718981b349db800d87b913da314e95d065ceb2f5";
const MANIFEST_PATH: &str = "Cargo.toml.orig";
const MANIFEST_SHA256: &str = "2fd5c1a0957af57186560cfb501eceaa7761bc612b26245be792284eee4763e0";
const SOURCE_PATH: &str = "tests/searcher.rs";
const SOURCE_SHA256: &str = "04152e5c86431deec0c196d2564a11bc4ec36f14c77e8c16a2f9d1cbc9fc574e";
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 1_048_576;

/// Capability exercised by the upstream searcher suite.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearcherCapability {
    /// Complete alternating match/reject step sequence over a UTF-8 haystack.
    Utf8StepSequence,
}

/// One canonical pattern-searcher step.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum SearcherStep {
    /// The regex matched the half-open byte range.
    Match { start: usize, end: usize },
    /// The regex rejected the half-open byte range between matches.
    Reject { start: usize, end: usize },
}

/// Mandatory result for one named upstream API test. There is no skip state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum SearcherApiDisposition {
    Pass {
        expected_sha256: String,
        observed_sha256: String,
    },
    Mismatch {
        expected_sha256: String,
        observed_sha256: String,
        reason_code: String,
    },
    Unsupported {
        capability: SearcherCapability,
        reason_code: String,
    },
    Fault {
        reason_code: String,
    },
}

/// Authenticated identity of the packaged upstream source used by the run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearcherSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub package_sha256: String,
    pub vcs_info_path: String,
    pub vcs_info_sha256: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub source_path: String,
    pub source_sha256: String,
}

/// One mandatory, path-bound upstream searcher receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearcherApiReceipt {
    pub case_id: String,
    pub source_path: String,
    pub source_sha256: String,
    pub capability: SearcherCapability,
    pub disposition: SearcherApiDisposition,
}

/// Complete result cardinalities for the 11-case searcher suite.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearcherApiCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`SearcherApiReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearcherApiReportPayload {
    pub source: SearcherSourceIdentity,
    pub candidate: CandidateIdentity,
    pub counts: SearcherApiCounts,
    pub receipts: Vec<SearcherApiReceipt>,
}

/// Immutable report for every pinned pattern-searcher obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearcherApiReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: SearcherApiReportPayload,
}

#[derive(Clone, Copy, Debug)]
struct SearcherCase {
    id: &'static str,
    pattern: &'static str,
    haystack: &'static str,
    expected: &'static [SearcherStep],
}

const fn matched(start: usize, end: usize) -> SearcherStep {
    SearcherStep::Match { start, end }
}

const fn rejected(start: usize, end: usize) -> SearcherStep {
    SearcherStep::Reject { start, end }
}

const CASES: [SearcherCase; SEARCHER_API_CASES] = [
    SearcherCase {
        id: "searcher_empty_regex_empty_haystack",
        pattern: r"",
        haystack: "",
        expected: &[matched(0, 0)],
    },
    SearcherCase {
        id: "searcher_empty_regex",
        pattern: r"",
        haystack: "ab",
        expected: &[
            matched(0, 0),
            rejected(0, 1),
            matched(1, 1),
            rejected(1, 2),
            matched(2, 2),
        ],
    },
    SearcherCase {
        id: "searcher_empty_haystack",
        pattern: r"\d",
        haystack: "",
        expected: &[],
    },
    SearcherCase {
        id: "searcher_one_match",
        pattern: r"\d",
        haystack: "5",
        expected: &[matched(0, 1)],
    },
    SearcherCase {
        id: "searcher_no_match",
        pattern: r"\d",
        haystack: "a",
        expected: &[rejected(0, 1)],
    },
    SearcherCase {
        id: "searcher_two_adjacent_matches",
        pattern: r"\d",
        haystack: "56",
        expected: &[matched(0, 1), matched(1, 2)],
    },
    SearcherCase {
        id: "searcher_two_non_adjacent_matches",
        pattern: r"\d",
        haystack: "5a6",
        expected: &[matched(0, 1), rejected(1, 2), matched(2, 3)],
    },
    SearcherCase {
        id: "searcher_reject_first",
        pattern: r"\d",
        haystack: "a6",
        expected: &[rejected(0, 1), matched(1, 2)],
    },
    SearcherCase {
        id: "searcher_one_zero_length_matches",
        pattern: r"\d*",
        haystack: "a1b2",
        expected: &[
            matched(0, 0),
            rejected(0, 1),
            matched(1, 2),
            rejected(2, 3),
            matched(3, 4),
        ],
    },
    SearcherCase {
        id: "searcher_many_zero_length_matches",
        pattern: r"\d*",
        haystack: "a1bbb2",
        expected: &[
            matched(0, 0),
            rejected(0, 1),
            matched(1, 2),
            rejected(2, 3),
            matched(3, 3),
            rejected(3, 4),
            matched(4, 4),
            rejected(4, 5),
            matched(5, 6),
        ],
    },
    SearcherCase {
        id: "searcher_unicode",
        pattern: r".+?",
        haystack: "Ⅰ1Ⅱ2",
        expected: &[matched(0, 3), matched(3, 4), matched(4, 7), matched(7, 8)],
    },
];

#[derive(Clone, Copy, Debug)]
struct ExecutionRefusal {
    fault: bool,
    reason_code: &'static str,
}

/// Authenticate the exact packaged upstream source and execute all 11 cases.
pub fn build_searcher_api_report(
    upstream_root: &Path,
    candidate: CandidateIdentity,
) -> Result<SearcherApiReport, InventoryError> {
    let source = authenticate_source(upstream_root)?;
    validate_candidate(&candidate)?;
    let mut receipts = Vec::with_capacity(CASES.len());
    for case in CASES {
        let disposition = match catch_unwind(AssertUnwindSafe(|| execute_case(case))) {
            Ok(Ok(observed)) => compare(case.expected, &observed)?,
            Ok(Err(refusal)) if refusal.fault => SearcherApiDisposition::Fault {
                reason_code: refusal.reason_code.to_owned(),
            },
            Ok(Err(refusal)) => SearcherApiDisposition::Unsupported {
                capability: SearcherCapability::Utf8StepSequence,
                reason_code: refusal.reason_code.to_owned(),
            },
            Err(_) => SearcherApiDisposition::Fault {
                reason_code: "searcher.adapter-panic".to_owned(),
            },
        };
        receipts.push(SearcherApiReceipt {
            case_id: case.id.to_owned(),
            source_path: SOURCE_PATH.to_owned(),
            source_sha256: SOURCE_SHA256.to_owned(),
            capability: SearcherCapability::Utf8StepSequence,
            disposition,
        });
    }
    let counts = SearcherApiCounts::from_receipts(&receipts)?;
    let payload = SearcherApiReportPayload {
        source,
        candidate,
        counts,
        receipts,
    };
    let payload_sha256 = hash_json(&payload)?;
    let report = SearcherApiReport {
        schema: SEARCHER_API_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate a searcher API report.
pub fn read_searcher_api_report(path: &Path) -> Result<SearcherApiReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read searcher API report {}: {error}",
            path.display()
        ))
    })?;
    let report: SearcherApiReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode searcher API report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON for one authenticated API report.
pub fn write_searcher_api_report(
    path: &Path,
    report: &SearcherApiReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode searcher API report: {error}")))?;
    bytes.push(b'\n');
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "searcher API report output has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!(
                "invalid searcher API report name: {}",
                path.display()
            ))
        })?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", temporary.display())))?;
    let result = (|| {
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!("write {}: {error}", temporary.display()))
        })?;
        output.sync_all().map_err(|error| {
            InventoryError::new(format!("sync {}: {error}", temporary.display()))
        })?;
        fs::rename(&temporary, path).map_err(|error| {
            InventoryError::new(format!(
                "rename {} to {}: {error}",
                temporary.display(),
                path.display()
            ))
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

impl SearcherApiReport {
    /// Validate source/candidate identity, payload hash, ordering and counts.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != SEARCHER_API_REPORT_SCHEMA {
            return Err(InventoryError::new("searcher API report schema mismatch"));
        }
        if self.payload_sha256 != hash_json(&self.payload)? {
            return Err(InventoryError::new(
                "searcher API report payload SHA-256 mismatch",
            ));
        }
        if self.payload.source != expected_source_identity() {
            return Err(InventoryError::new("searcher API source identity mismatch"));
        }
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != CASES.len() {
            return Err(InventoryError::new("searcher API receipt count mismatch"));
        }
        for (case, receipt) in CASES.iter().zip(&self.payload.receipts) {
            if receipt.case_id != case.id
                || receipt.source_path != SOURCE_PATH
                || receipt.source_sha256 != SOURCE_SHA256
                || receipt.capability != SearcherCapability::Utf8StepSequence
            {
                return Err(InventoryError::new(format!(
                    "searcher API obligation mismatch for {}",
                    case.id
                )));
            }
            validate_disposition(&receipt.disposition)?;
        }
        let counts = SearcherApiCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts || counts.total != SEARCHER_API_CASES {
            return Err(InventoryError::new(
                "searcher API disposition count mismatch",
            ));
        }
        Ok(())
    }
}

impl SearcherApiCounts {
    fn from_receipts(receipts: &[SearcherApiReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                SearcherApiDisposition::Pass { .. } => &mut counts.pass,
                SearcherApiDisposition::Mismatch { .. } => &mut counts.mismatch,
                SearcherApiDisposition::Unsupported { .. } => &mut counts.unsupported,
                SearcherApiDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("searcher API count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("searcher API total overflow"))?;
        }
        Ok(counts)
    }
}

fn execute_case(case: SearcherCase) -> Result<Vec<SearcherStep>, ExecutionRefusal> {
    let regex = AggregateBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("searcher.selector-build-refused"))?;
    let spans = regex
        .spans(case.haystack.as_bytes(), AggregateRunLimits::default())
        .map_err(|_| unsupported("searcher.execution-refused"))?;
    Ok(spans.search_steps().map(canonical_step).collect())
}

fn canonical_step(step: AggregateSearchStep) -> SearcherStep {
    let span = step.span();
    if step.is_match() {
        matched(span.start(), span.end())
    } else {
        rejected(span.start(), span.end())
    }
}

fn compare(
    expected: &[SearcherStep],
    observed: &[SearcherStep],
) -> Result<SearcherApiDisposition, InventoryError> {
    let expected_sha256 = hash_json(expected)?;
    let observed_sha256 = hash_json(observed)?;
    if expected == observed {
        Ok(SearcherApiDisposition::Pass {
            expected_sha256,
            observed_sha256,
        })
    } else {
        Ok(SearcherApiDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code: "searcher.steps-differ".to_owned(),
        })
    }
}

const fn unsupported(reason_code: &'static str) -> ExecutionRefusal {
    ExecutionRefusal {
        fault: false,
        reason_code,
    }
}

fn authenticate_source(root: &Path) -> Result<SearcherSourceIdentity, InventoryError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        InventoryError::new(format!("stat upstream package {}: {error}", root.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "upstream package root must be a real directory",
        ));
    }
    let vcs = read_authenticated_file(root, VCS_INFO_PATH, VCS_INFO_SHA256)?;
    let manifest = read_authenticated_file(root, MANIFEST_PATH, MANIFEST_SHA256)?;
    let _source = read_authenticated_file(root, SOURCE_PATH, SOURCE_SHA256)?;

    let vcs: VcsInfo = serde_json::from_slice(&vcs)
        .map_err(|error| InventoryError::new(format!("decode {VCS_INFO_PATH}: {error}")))?;
    if vcs.git.sha1 != UPSTREAM_REVISION || !vcs.path_in_vcs.is_empty() {
        return Err(InventoryError::new(
            "upstream packaged VCS identity mismatch",
        ));
    }
    let manifest: toml::Value = toml::from_slice(&manifest)
        .map_err(|error| InventoryError::new(format!("decode {MANIFEST_PATH}: {error}")))?;
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| InventoryError::new("upstream manifest has no package table"))?;
    if package.get("name").and_then(toml::Value::as_str) != Some(UPSTREAM_PACKAGE)
        || package.get("version").and_then(toml::Value::as_str) != Some(UPSTREAM_VERSION)
    {
        return Err(InventoryError::new(
            "upstream package name/version mismatch",
        ));
    }
    Ok(expected_source_identity())
}

fn read_authenticated_file(
    root: &Path,
    relative: &str,
    expected_sha256: &str,
) -> Result<Vec<u8>, InventoryError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_AUTHENTICATED_FILE_BYTES
    {
        return Err(InventoryError::new(format!(
            "authenticated upstream path is not a bounded regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(&path)
        .map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))?;
    if sha256(&bytes) != expected_sha256 {
        return Err(InventoryError::new(format!(
            "authenticated upstream file digest mismatch: {relative}"
        )));
    }
    Ok(bytes)
}

fn expected_source_identity() -> SearcherSourceIdentity {
    SearcherSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        revision: UPSTREAM_REVISION.to_owned(),
        package_sha256: UPSTREAM_PACKAGE_SHA256.to_owned(),
        vcs_info_path: VCS_INFO_PATH.to_owned(),
        vcs_info_sha256: VCS_INFO_SHA256.to_owned(),
        manifest_path: MANIFEST_PATH.to_owned(),
        manifest_sha256: MANIFEST_SHA256.to_owned(),
        source_path: SOURCE_PATH.to_owned(),
        source_sha256: SOURCE_SHA256.to_owned(),
    }
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !is_oid(&candidate.revision)
        || !is_oid(&candidate.tree)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "searcher API candidate identity is invalid",
        ));
    }
    Ok(())
}

fn validate_disposition(disposition: &SearcherApiDisposition) -> Result<(), InventoryError> {
    match disposition {
        SearcherApiDisposition::Pass {
            expected_sha256,
            observed_sha256,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 != observed_sha256
            {
                return Err(InventoryError::new(
                    "searcher API pass digests are invalid or unequal",
                ));
            }
        }
        SearcherApiDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 == observed_sha256
                || !valid_reason_code(reason_code)
            {
                return Err(InventoryError::new(
                    "searcher API mismatch disposition is invalid",
                ));
            }
        }
        SearcherApiDisposition::Unsupported {
            capability,
            reason_code,
        } => {
            if *capability != SearcherCapability::Utf8StepSequence
                || !valid_reason_code(reason_code)
            {
                return Err(InventoryError::new(
                    "searcher API unsupported disposition is invalid",
                ));
            }
        }
        SearcherApiDisposition::Fault { reason_code } => {
            if !valid_reason_code(reason_code) {
                return Err(InventoryError::new(
                    "searcher API fault disposition is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn hash_json<T: Serialize + ?Sized>(value: &T) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("encode searcher API value: {error}")))
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
}

fn is_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VcsInfo {
    git: VcsGit,
    path_in_vcs: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VcsGit {
    sha1: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> CandidateIdentity {
        CandidateIdentity {
            revision: "1111111111111111111111111111111111111111".to_owned(),
            tree: "2222222222222222222222222222222222222222".to_owned(),
            tracked_and_untracked_worktree_clean: true,
        }
    }

    fn report(receipts: Vec<SearcherApiReceipt>, counts: SearcherApiCounts) -> SearcherApiReport {
        let payload = SearcherApiReportPayload {
            source: expected_source_identity(),
            candidate: candidate(),
            counts,
            receipts,
        };
        SearcherApiReport {
            schema: SEARCHER_API_REPORT_SCHEMA.to_owned(),
            payload_sha256: hash_json(&payload).unwrap(),
            payload,
        }
    }

    fn passing_receipts() -> Vec<SearcherApiReceipt> {
        CASES
            .into_iter()
            .map(|case| {
                let observed =
                    execute_case(case).unwrap_or_else(|error| panic!("{}: {error:?}", case.id));
                SearcherApiReceipt {
                    case_id: case.id.to_owned(),
                    source_path: SOURCE_PATH.to_owned(),
                    source_sha256: SOURCE_SHA256.to_owned(),
                    capability: SearcherCapability::Utf8StepSequence,
                    disposition: compare(case.expected, &observed).unwrap(),
                }
            })
            .collect()
    }

    #[test]
    fn every_searcher_obligation_executes_and_passes() {
        let receipts = passing_receipts();
        let mut ids = CASES.iter().map(|case| case.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SEARCHER_API_CASES);

        let counts = SearcherApiCounts::from_receipts(&receipts).unwrap();
        assert_eq!(counts.pass, SEARCHER_API_CASES);
        assert_eq!(counts.mismatch, 0);
        assert_eq!(counts.unsupported, 0);
        assert_eq!(counts.fault, 0);
        assert_eq!(counts.total, SEARCHER_API_CASES);
        report(receipts, counts).validate().unwrap();
    }

    #[test]
    fn validation_rejects_omission_reordering_and_false_pass() {
        let receipts = passing_receipts();
        let counts = SearcherApiCounts::from_receipts(&receipts).unwrap();

        let mut omitted = receipts.clone();
        omitted.pop();
        assert!(report(omitted, counts.clone()).validate().is_err());

        let mut reordered = receipts.clone();
        reordered.swap(0, 1);
        assert!(report(reordered, counts.clone()).validate().is_err());

        let mut false_pass = receipts;
        false_pass[0].disposition = SearcherApiDisposition::Pass {
            expected_sha256: "1".repeat(64),
            observed_sha256: "2".repeat(64),
        };
        assert!(report(false_pass, counts).validate().is_err());
    }
}
