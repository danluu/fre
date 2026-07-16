//! Executable conformance inventory for pinned upstream public doctests.

use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use fre::{
    AggregateBuilder, CaptureAggregateLimits, CaptureBuilder, CaptureExpansionLimits,
    CaptureSearchLimits, LiteralReplacementLimits, PortableBuilder, PortableFindIterLimits,
    PortableRegexSetBuilder, PortableRegexSetRunLimits, PortableTextBuilder,
    PortableTextCaptureBuilder, RustProfile, SearchLimits, SearchWindow,
};
use serde::{Deserialize, Serialize};

use crate::doctest_capture_metadata::{CaptureMetadataRefusal, execute_capture_metadata_doctest};
use crate::{CandidateIdentity, InventoryError, UPSTREAM_REPOSITORY, UPSTREAM_REVISION, sha256};

/// Stable schema for the complete public-doctest report.
pub const DOCTEST_API_REPORT_SCHEMA: &str = "fre.upstream-rust-regex.doctest-api-report.v1";
/// Exact default-feature doctest count printed by pinned `cargo test --doc -- --list`.
pub const DOCTEST_API_CASES: usize = 242;

const UPSTREAM_PACKAGE: &str = "regex";
const UPSTREAM_VERSION: &str = "1.12.4";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const VCS_INFO_PATH: &str = ".cargo_vcs_info.json";
const VCS_INFO_SHA256: &str = "985255199f0cbe66b15087ac718981b349db800d87b913da314e95d065ceb2f5";
const MANIFEST_PATH: &str = "Cargo.toml.orig";
const MANIFEST_SHA256: &str = "2fd5c1a0957af57186560cfb501eceaa7761bc612b26245be792284eee4763e0";
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 4 * 1_048_576;
const EXPECTED_OBLIGATION_INVENTORY_SHA256: &str =
    "028754b101949945211bfb067736739d703d2979719f9f7186d5b282955f70cb";

#[derive(Clone, Copy, Debug)]
struct SourceSpec {
    path: &'static str,
    sha256: &'static str,
    bytes: u64,
    expected_doctests: usize,
    markdown: bool,
}

const SOURCES: [SourceSpec; 8] = [
    SourceSpec {
        path: "README.md",
        sha256: "2e5ffce9b5781a2c286517f0fb81e7e00d9736ffa938c9a34b5e92f30352a115",
        bytes: 12_156,
        expected_doctests: 5,
        markdown: true,
    },
    SourceSpec {
        path: "src/builders.rs",
        sha256: "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f",
        bytes: 107_638,
        expected_doctests: 56,
        markdown: false,
    },
    SourceSpec {
        path: "src/bytes.rs",
        sha256: "cce2b7012f5896cf82fc3086bf8128dc9efe2b69bf6917d041c1a171eabacdc0",
        bytes: 3_684,
        expected_doctests: 2,
        markdown: false,
    },
    SourceSpec {
        path: "src/lib.rs",
        sha256: "033460754d7a51fb9fa90ad096f76dbaaf10dc4c49f1195bb088fe23d35ded75",
        bytes: 58_892,
        expected_doctests: 23,
        markdown: false,
    },
    SourceSpec {
        path: "src/regex/bytes.rs",
        sha256: "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0",
        bytes: 99_669,
        expected_doctests: 60,
        markdown: false,
    },
    SourceSpec {
        path: "src/regex/string.rs",
        sha256: "9f7686e10535fe385a767063132d39ee1a1af1a20a119d78df479f110822e274",
        bytes: 95_916,
        expected_doctests: 60,
        markdown: false,
    },
    SourceSpec {
        path: "src/regexset/bytes.rs",
        sha256: "25c8d896e4b9caf627cce46e3c305d2e640aeeacea96c40526699f86960d1868",
        bytes: 24_378,
        expected_doctests: 18,
        markdown: false,
    },
    SourceSpec {
        path: "src/regexset/string.rs",
        sha256: "ac3fc9c8d2d58379e63bcd92ab2f8ee1c32a1210dceec63925d0c23f1d9dfedd",
        bytes: 23_921,
        expected_doctests: 18,
        markdown: false,
    },
];

/// Public behavior represented by one upstream documentation example.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctestCapability {
    BuilderConfiguration,
    ByteSearch,
    TextSearch,
    ByteCapture,
    TextCapture,
    ByteSplit,
    TextSplit,
    ByteSet,
    TextSet,
    CaptureMetadata,
    Replacement,
    ShortestMatch,
    TypeSurface,
}

/// Mandatory result for one authenticated upstream doctest. There is no skip state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum DoctestDisposition {
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
        capability: DoctestCapability,
        reason_code: String,
    },
    Fault {
        reason_code: String,
    },
}

/// One authenticated source file that contributes public doctests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestSourceFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub applicable_doctests: usize,
}

/// Exact packaged source and derived obligation identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub package_sha256: String,
    pub vcs_info_path: String,
    pub vcs_info_sha256: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub source_files: Vec<DoctestSourceFile>,
    pub obligation_inventory_sha256: String,
    pub obligations: usize,
}

/// One path/line/block-bound doctest disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestReceipt {
    pub case_id: String,
    pub source_path: String,
    pub source_sha256: String,
    pub source_line: usize,
    pub code_sha256: String,
    pub capability: DoctestCapability,
    pub disposition: DoctestDisposition,
}

/// Complete result cardinalities for the public doctest inventory.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`DoctestReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestReportPayload {
    pub source: DoctestSourceIdentity,
    pub candidate: CandidateIdentity,
    pub counts: DoctestCounts,
    pub receipts: Vec<DoctestReceipt>,
}

/// Immutable result for every pinned default-feature public doctest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctestReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: DoctestReportPayload,
}

#[derive(Clone, Debug, Serialize)]
struct ObligationIdentity<'a> {
    case_id: &'a str,
    source_path: &'a str,
    source_sha256: &'a str,
    source_line: usize,
    code_sha256: &'a str,
}

#[derive(Clone, Debug)]
struct Obligation {
    case_id: String,
    source_path: String,
    source_sha256: String,
    source_line: usize,
    code_sha256: String,
    code: String,
}

#[derive(Clone, Copy, Debug)]
struct ExecutionRefusal {
    fault: bool,
    reason_code: &'static str,
}

type Execution = Result<(Vec<u8>, Vec<u8>), ExecutionRefusal>;
type OptionalExecution = Option<Execution>;

/// Authenticate all source bytes, enumerate all doctests and execute FRE's supported slice.
pub fn build_doctest_report(
    upstream_root: &Path,
    candidate: CandidateIdentity,
) -> Result<DoctestReport, InventoryError> {
    let (source, obligations) = authenticate_source(upstream_root)?;
    validate_candidate(&candidate)?;
    let mut receipts = Vec::with_capacity(obligations.len());
    for obligation in &obligations {
        let capability = classify(obligation);
        let disposition = match catch_unwind(AssertUnwindSafe(|| execute(obligation))) {
            Ok(Some(Ok((expected, observed)))) => compare(&expected, &observed),
            Ok(Some(Err(refusal))) if refusal.fault => DoctestDisposition::Fault {
                reason_code: refusal.reason_code.to_owned(),
            },
            Ok(Some(Err(refusal))) => DoctestDisposition::Unsupported {
                capability,
                reason_code: refusal.reason_code.to_owned(),
            },
            Ok(None) => DoctestDisposition::Unsupported {
                capability,
                reason_code: unsupported_reason(capability).to_owned(),
            },
            Err(_) => DoctestDisposition::Fault {
                reason_code: "doctest.adapter-panic".to_owned(),
            },
        };
        receipts.push(DoctestReceipt {
            case_id: obligation.case_id.clone(),
            source_path: obligation.source_path.clone(),
            source_sha256: obligation.source_sha256.clone(),
            source_line: obligation.source_line,
            code_sha256: obligation.code_sha256.clone(),
            capability,
            disposition,
        });
    }
    let counts = DoctestCounts::from_receipts(&receipts)?;
    let payload = DoctestReportPayload {
        source,
        candidate,
        counts,
        receipts,
    };
    let report = DoctestReport {
        schema: DOCTEST_API_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload)?,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate a public-doctest report.
pub fn read_doctest_report(path: &Path) -> Result<DoctestReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!("read doctest report {}: {error}", path.display()))
    })?;
    let report: DoctestReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode doctest report {}: {error}", path.display()))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON for a validated public-doctest report.
pub fn write_doctest_report(path: &Path, report: &DoctestReport) -> Result<(), InventoryError> {
    report.validate()?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode doctest report: {error}")))?;
    bytes.push(b'\n');
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "doctest report output has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!("invalid doctest report name: {}", path.display()))
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

impl DoctestReport {
    /// Validate source identity, coverage, ordering, dispositions and payload digest.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != DOCTEST_API_REPORT_SCHEMA {
            return Err(InventoryError::new("doctest report schema mismatch"));
        }
        if self.payload_sha256 != hash_json(&self.payload)? {
            return Err(InventoryError::new(
                "doctest report payload SHA-256 mismatch",
            ));
        }
        validate_source_identity(&self.payload.source)?;
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != DOCTEST_API_CASES {
            return Err(InventoryError::new("doctest receipt count mismatch"));
        }
        let mut ids = BTreeSet::new();
        for receipt in &self.payload.receipts {
            if !ids.insert(receipt.case_id.as_str())
                || receipt.case_id != format!("{}:{}", receipt.source_path, receipt.source_line)
                || source_sha(&receipt.source_path) != Some(receipt.source_sha256.as_str())
                || !is_sha256(&receipt.code_sha256)
            {
                return Err(InventoryError::new(
                    "doctest obligation identity is invalid",
                ));
            }
            validate_disposition(receipt.capability, &receipt.disposition)?;
        }
        if obligation_hash_from_receipts(&self.payload.receipts)?
            != self.payload.source.obligation_inventory_sha256
        {
            return Err(InventoryError::new(
                "doctest receipt inventory hash mismatch",
            ));
        }
        let counts = DoctestCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts || counts.total != DOCTEST_API_CASES {
            return Err(InventoryError::new("doctest disposition count mismatch"));
        }
        Ok(())
    }
}

impl DoctestCounts {
    fn from_receipts(receipts: &[DoctestReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                DoctestDisposition::Pass { .. } => &mut counts.pass,
                DoctestDisposition::Mismatch { .. } => &mut counts.mismatch,
                DoctestDisposition::Unsupported { .. } => &mut counts.unsupported,
                DoctestDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("doctest count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("doctest total overflow"))?;
        }
        Ok(counts)
    }
}

fn authenticate_source(
    root: &Path,
) -> Result<(DoctestSourceIdentity, Vec<Obligation>), InventoryError> {
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

    let mut source_files = Vec::with_capacity(SOURCES.len());
    let mut obligations = Vec::with_capacity(DOCTEST_API_CASES);
    for spec in SOURCES {
        let bytes = read_authenticated_file(root, spec.path, spec.sha256)?;
        if u64::try_from(bytes.len()) != Ok(spec.bytes) {
            return Err(InventoryError::new(format!(
                "upstream doctest source length mismatch: {}",
                spec.path
            )));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            InventoryError::new(format!(
                "upstream doctest source is not UTF-8: {}",
                spec.path
            ))
        })?;
        let mut source_obligations = extract_obligations(spec, text)?;
        if source_obligations.len() != spec.expected_doctests {
            return Err(InventoryError::new(format!(
                "upstream doctest count mismatch for {}: expected {}, got {}",
                spec.path,
                spec.expected_doctests,
                source_obligations.len()
            )));
        }
        source_files.push(DoctestSourceFile {
            path: spec.path.to_owned(),
            sha256: spec.sha256.to_owned(),
            bytes: spec.bytes,
            applicable_doctests: source_obligations.len(),
        });
        obligations.append(&mut source_obligations);
    }
    if obligations.len() != DOCTEST_API_CASES {
        return Err(InventoryError::new("total upstream doctest count mismatch"));
    }
    let obligation_inventory_sha256 = obligation_hash(&obligations)?;
    if EXPECTED_OBLIGATION_INVENTORY_SHA256 != "pending"
        && obligation_inventory_sha256 != EXPECTED_OBLIGATION_INVENTORY_SHA256
    {
        return Err(InventoryError::new(format!(
            "upstream doctest inventory digest mismatch: {obligation_inventory_sha256}"
        )));
    }
    let source = DoctestSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        revision: UPSTREAM_REVISION.to_owned(),
        package_sha256: UPSTREAM_PACKAGE_SHA256.to_owned(),
        vcs_info_path: VCS_INFO_PATH.to_owned(),
        vcs_info_sha256: VCS_INFO_SHA256.to_owned(),
        manifest_path: MANIFEST_PATH.to_owned(),
        manifest_sha256: MANIFEST_SHA256.to_owned(),
        source_files,
        obligation_inventory_sha256,
        obligations: DOCTEST_API_CASES,
    };
    Ok((source, obligations))
}

fn extract_obligations(spec: SourceSpec, text: &str) -> Result<Vec<Obligation>, InventoryError> {
    let lines = if spec.markdown {
        text.lines()
            .enumerate()
            .map(|(index, line)| (index.saturating_add(1), Some(line.to_owned())))
            .collect::<Vec<_>>()
    } else {
        rust_doc_lines(text)
    };
    let mut obligations = Vec::new();
    let mut active: Option<(usize, String, Vec<String>)> = None;
    for (line_number, content) in lines {
        let Some(content) = content else {
            if active.is_some() {
                return Err(InventoryError::new(format!(
                    "unterminated doctest documentation segment in {}",
                    spec.path
                )));
            }
            continue;
        };
        let trimmed = content.trim_start();
        if let Some(info) = trimmed.strip_prefix("```") {
            if let Some((start, opening_info, code_lines)) = active.take() {
                if info.trim().is_empty() && applicable_info(&opening_info)? {
                    let mut code = code_lines.join("\n");
                    code.push('\n');
                    obligations.push(Obligation {
                        case_id: format!("{}:{start}", spec.path),
                        source_path: spec.path.to_owned(),
                        source_sha256: spec.sha256.to_owned(),
                        source_line: start,
                        code_sha256: sha256(code.as_bytes()),
                        code,
                    });
                }
            } else {
                active = Some((line_number, info.trim().to_owned(), Vec::new()));
            }
        } else if let Some((_, _, code_lines)) = active.as_mut() {
            code_lines.push(content);
        }
    }
    if active.is_some() {
        return Err(InventoryError::new(format!(
            "unterminated doctest fence in {}",
            spec.path
        )));
    }
    Ok(obligations)
}

fn rust_doc_lines(text: &str) -> Vec<(usize, Option<String>)> {
    let mut output = Vec::with_capacity(text.lines().count());
    let mut block_doc = false;
    for (index, line) in text.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let trimmed = line.trim_start();
        let content = if block_doc {
            let (body, ended) = trimmed
                .split_once("*/")
                .map_or((trimmed, false), |(body, _)| (body, true));
            if ended {
                block_doc = false;
            }
            Some(
                body.strip_prefix('*')
                    .unwrap_or(body)
                    .trim_start()
                    .to_owned(),
            )
        } else if let Some(body) = trimmed
            .strip_prefix("/*!")
            .or_else(|| trimmed.strip_prefix("/**"))
        {
            block_doc = !body.contains("*/");
            Some(
                body.split("*/")
                    .next()
                    .unwrap_or(body)
                    .trim_start()
                    .to_owned(),
            )
        } else {
            trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
                .map(|body| body.trim_start().to_owned())
        };
        output.push((line_number, content));
    }
    output
}

fn applicable_info(info: &str) -> Result<bool, InventoryError> {
    let tags = info
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    for tag in &tags {
        if !matches!(
            *tag,
            "rust"
                | "text"
                | "toml"
                | "ignore"
                | "no_run"
                | "should_panic"
                | "compile_fail"
                | "edition2015"
                | "edition2018"
                | "edition2021"
                | "edition2024"
        ) {
            return Err(InventoryError::new(format!(
                "unknown upstream doctest fence tag: {tag}"
            )));
        }
    }
    Ok(!tags.contains(&"text") && !tags.contains(&"toml"))
}

fn classify(obligation: &Obligation) -> DoctestCapability {
    let code = obligation.code.as_str();
    if obligation.source_path == "src/builders.rs" {
        return DoctestCapability::BuilderConfiguration;
    }
    if code.contains("replace(")
        || code.contains("replace_all(")
        || code.contains("replacen(")
        || code.contains("NoExpand")
        || code.contains("Replacer")
    {
        return DoctestCapability::Replacement;
    }
    if code.contains("shortest_match") {
        return DoctestCapability::ShortestMatch;
    }
    let bytes = code.contains("regex::bytes") || obligation.source_path.contains("bytes");
    if code.contains("RegexSet") || obligation.source_path.contains("regexset") {
        return if bytes {
            DoctestCapability::ByteSet
        } else {
            DoctestCapability::TextSet
        };
    }
    if code.contains(".split") {
        return if bytes {
            DoctestCapability::ByteSplit
        } else {
            DoctestCapability::TextSplit
        };
    }
    if code.contains("capture_names")
        || code.contains("captures_len")
        || code.contains("static_captures_len")
        || code.contains("capture_locations")
    {
        return DoctestCapability::CaptureMetadata;
    }
    if code.contains("captures") || code.contains("Captures") {
        return if bytes {
            DoctestCapability::ByteCapture
        } else {
            DoctestCapability::TextCapture
        };
    }
    if code.contains("Regex") {
        return if bytes {
            DoctestCapability::ByteSearch
        } else {
            DoctestCapability::TextSearch
        };
    }
    DoctestCapability::TypeSurface
}

fn unsupported_reason(capability: DoctestCapability) -> &'static str {
    match capability {
        DoctestCapability::Replacement => "doctest.covered-by-replacement-suite",
        DoctestCapability::ShortestMatch => "doctest.shortest-match-surface-unavailable",
        DoctestCapability::TypeSurface => "doctest.type-surface-unavailable",
        DoctestCapability::BuilderConfiguration => "doctest.builder-example-not-adapted",
        DoctestCapability::ByteSearch | DoctestCapability::TextSearch => {
            "doctest.search-example-not-adapted"
        }
        DoctestCapability::ByteCapture | DoctestCapability::TextCapture => {
            "doctest.capture-example-not-adapted"
        }
        DoctestCapability::ByteSplit | DoctestCapability::TextSplit => {
            "doctest.split-example-not-adapted"
        }
        DoctestCapability::ByteSet | DoctestCapability::TextSet => {
            "doctest.set-example-not-adapted"
        }
        DoctestCapability::CaptureMetadata => "doctest.metadata-example-not-adapted",
    }
}

fn execute(obligation: &Obligation) -> OptionalExecution {
    if obligation.source_path == "src/builders.rs" {
        return execute_builder(obligation.source_line);
    }
    if obligation.source_path == "src/regexset/string.rs"
        || obligation.source_path == "src/regexset/bytes.rs"
    {
        return execute_set_doctest(obligation.source_line);
    }
    execute_core_doctest(obligation)
}

fn execute_builder(line: usize) -> OptionalExecution {
    let (kind, set) = match line {
        271 | 1426 => (BuilderProbe::UnicodeWord, false),
        850 | 2025 => (BuilderProbe::UnicodeWord, true),
        309 | 1479 => (BuilderProbe::CaseInsensitive, false),
        888 | 2079 => (BuilderProbe::CaseInsensitive, true),
        352 | 1522 => (BuilderProbe::MultiLine, false),
        931 | 2122 => (BuilderProbe::MultiLine, true),
        382 | 1552 => (BuilderProbe::DotNewLine, false),
        961 | 2152 => (BuilderProbe::DotNewLine, true),
        420 | 1590 => (BuilderProbe::CrlfMatch, false),
        999 | 2190 => (BuilderProbe::CrlfMatch, true),
        438 | 1608 => (BuilderProbe::CrlfAnchor, false),
        1017 | 2208 => (BuilderProbe::CrlfReject, true),
        478 | 1648 => (BuilderProbe::LineTerminatorMatch, false),
        1055 | 2246 => (BuilderProbe::LineTerminatorMatch, true),
        493 | 1663 => (BuilderProbe::LineTerminatorDot, false),
        1070 | 2261 => (BuilderProbe::LineTerminatorDot, true),
        539 | 1712 => (BuilderProbe::SwapGreed, false),
        639 | 1818 => (BuilderProbe::Octal, false),
        1207 | 2391 => (BuilderProbe::Octal, true),
        768 | 1947 => (BuilderProbe::NestLimit, false),
        1344 | 2528 => (BuilderProbe::NestLimit, true),
        _ => return None,
    };
    Some(run_builder_probe(kind, set))
}

#[derive(Clone, Copy)]
enum BuilderProbe {
    UnicodeWord,
    CaseInsensitive,
    MultiLine,
    DotNewLine,
    CrlfMatch,
    CrlfAnchor,
    CrlfReject,
    LineTerminatorMatch,
    LineTerminatorDot,
    SwapGreed,
    Octal,
    NestLimit,
}

fn run_builder_probe(
    probe: BuilderProbe,
    set: bool,
) -> Result<(Vec<u8>, Vec<u8>), ExecutionRefusal> {
    let expected = match (probe, set) {
        (
            BuilderProbe::MultiLine
            | BuilderProbe::DotNewLine
            | BuilderProbe::CrlfMatch
            | BuilderProbe::LineTerminatorMatch
            | BuilderProbe::Octal,
            true,
        )
        | (BuilderProbe::Octal, false) => b"true".to_vec(),
        (BuilderProbe::CrlfReject, true) => b"false".to_vec(),
        (BuilderProbe::UnicodeWord, _) => b"false,false".to_vec(),
        (BuilderProbe::CaseInsensitive | BuilderProbe::LineTerminatorDot, _) => {
            b"true,false".to_vec()
        }
        (BuilderProbe::MultiLine | BuilderProbe::LineTerminatorMatch, false) => b"1-4".to_vec(),
        (BuilderProbe::DotNewLine, false) => b"0-7".to_vec(),
        (BuilderProbe::CrlfMatch, false) => b"2-5".to_vec(),
        (BuilderProbe::CrlfAnchor, false) => b"0-0,2-2,4-4".to_vec(),
        (BuilderProbe::SwapGreed, _) => b"0-1".to_vec(),
        (BuilderProbe::NestLimit, _) => b"true,true".to_vec(),
        (BuilderProbe::CrlfReject, false) | (BuilderProbe::CrlfAnchor, true) => {
            return Err(fault("doctest.builder-probe-invariant"));
        }
    };
    let observed = if set {
        run_set_builder_probe(probe)?
    } else {
        run_regex_builder_probe(probe)?
    };
    Ok((expected, observed))
}

fn run_regex_builder_probe(probe: BuilderProbe) -> Result<Vec<u8>, ExecutionRefusal> {
    match probe {
        BuilderProbe::UnicodeWord => {
            let first = build_regex(PortableBuilder::new(r"\w").unicode(false))?;
            let second = build_regex(
                PortableBuilder::new("s")
                    .case_insensitive(true)
                    .unicode(false),
            )?;
            Ok(format!(
                "{},{}",
                is_match(&first, "δ".as_bytes())?,
                is_match(&second, "ſ".as_bytes())?
            )
            .into_bytes())
        }
        BuilderProbe::CaseInsensitive => {
            let regex =
                build_regex(PortableBuilder::new(r"foo(?-i:bar)quux").case_insensitive(true))?;
            Ok(format!(
                "{},{}",
                is_match(&regex, b"FoObarQuUx")?,
                is_match(&regex, b"fooBARquux")?
            )
            .into_bytes())
        }
        BuilderProbe::MultiLine => {
            let regex = build_regex(PortableBuilder::new(r"^foo$").multi_line(true))?;
            Ok(one_range(&regex, b"\nfoo\n")?.into_bytes())
        }
        BuilderProbe::DotNewLine => {
            let regex = build_regex(PortableBuilder::new(r"foo.bar").dot_matches_new_line(true))?;
            Ok(one_range(&regex, b"foo\nbar")?.into_bytes())
        }
        BuilderProbe::CrlfMatch => {
            let regex = build_regex(PortableBuilder::new(r"^foo$").multi_line(true).crlf(true))?;
            Ok(one_range(&regex, b"\r\nfoo\r\n")?.into_bytes())
        }
        BuilderProbe::CrlfAnchor => {
            let regex = build_regex(PortableBuilder::new(r"^").multi_line(true).crlf(true))?;
            Ok(all_ranges(&regex, b"\r\n\r\n")?.into_bytes())
        }
        BuilderProbe::CrlfReject => Err(fault("doctest.builder-probe-invariant")),
        BuilderProbe::LineTerminatorMatch => {
            let regex = build_regex(
                PortableBuilder::new(r"^foo$")
                    .multi_line(true)
                    .line_terminator(0),
            )?;
            Ok(one_range(&regex, b"\0foo\0")?.into_bytes())
        }
        BuilderProbe::LineTerminatorDot => {
            let regex = build_regex(PortableBuilder::new(r".").line_terminator(0))?;
            Ok(format!("{},{}", is_match(&regex, b"\n")?, is_match(&regex, b"\0")?).into_bytes())
        }
        BuilderProbe::SwapGreed => {
            let regex = build_regex(PortableBuilder::new("a+").swap_greed(true))?;
            Ok(one_range(&regex, b"aaa")?.into_bytes())
        }
        BuilderProbe::Octal => {
            let regex = build_regex(PortableBuilder::new(r"\141").octal(true))?;
            Ok(is_match(&regex, b"a")?.to_string().into_bytes())
        }
        BuilderProbe::NestLimit => {
            let first = PortableBuilder::new("a").nest_limit(0).build().is_ok();
            let second = PortableBuilder::new("ab").nest_limit(0).build().is_err();
            Ok(format!("{first},{second}").into_bytes())
        }
    }
}

fn run_set_builder_probe(probe: BuilderProbe) -> Result<Vec<u8>, ExecutionRefusal> {
    let patterns = match probe {
        BuilderProbe::UnicodeWord => vec![r"\w".to_owned()],
        BuilderProbe::CaseInsensitive => vec![r"foo(?-i:bar)quux".to_owned()],
        BuilderProbe::MultiLine | BuilderProbe::CrlfMatch | BuilderProbe::LineTerminatorMatch => {
            vec![r"^foo$".to_owned()]
        }
        BuilderProbe::DotNewLine => vec![r"foo.bar".to_owned()],
        BuilderProbe::CrlfAnchor => vec![r"^".to_owned()],
        BuilderProbe::CrlfReject => vec![r"^\n".to_owned()],
        BuilderProbe::LineTerminatorDot => vec![r".".to_owned()],
        BuilderProbe::SwapGreed => vec![r"a+".to_owned()],
        BuilderProbe::Octal => vec![r"\141".to_owned()],
        BuilderProbe::NestLimit => Vec::new(),
    };
    if matches!(probe, BuilderProbe::NestLimit) {
        let first_patterns = vec!["a".to_owned()];
        let second_patterns = vec!["ab".to_owned()];
        let first = PortableRegexSetBuilder::new(&first_patterns)
            .nest_limit(0)
            .build()
            .is_ok();
        let second = PortableRegexSetBuilder::new(&second_patterns)
            .nest_limit(0)
            .build()
            .is_err();
        return Ok(format!("{first},{second}").into_bytes());
    }
    let mut builder = PortableRegexSetBuilder::new(&patterns);
    builder = match probe {
        BuilderProbe::UnicodeWord => builder.unicode(false),
        BuilderProbe::CaseInsensitive => builder.case_insensitive(true),
        BuilderProbe::MultiLine => builder.multi_line(true),
        BuilderProbe::DotNewLine => builder.dot_matches_new_line(true),
        BuilderProbe::CrlfMatch | BuilderProbe::CrlfAnchor | BuilderProbe::CrlfReject => {
            builder.multi_line(true).crlf(true)
        }
        BuilderProbe::LineTerminatorMatch => builder.multi_line(true).line_terminator(0),
        BuilderProbe::LineTerminatorDot => builder.line_terminator(0),
        BuilderProbe::SwapGreed => builder.swap_greed(true),
        BuilderProbe::Octal => builder.octal(true),
        BuilderProbe::NestLimit => unreachable!(),
    };
    let regex = builder
        .build()
        .map_err(|_| unsupported("doctest.set-builder-refused"))?;
    let limits = PortableRegexSetRunLimits::unlimited();
    let output = match probe {
        BuilderProbe::UnicodeWord => format!(
            "{},{}",
            regex
                .is_match("δ".as_bytes(), limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0,
            regex
                .is_match("ſ".as_bytes(), limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0
        ),
        BuilderProbe::CaseInsensitive => format!(
            "{},{}",
            regex
                .is_match(b"FoObarQuUx", limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0,
            regex
                .is_match(b"fooBARquux", limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0
        ),
        BuilderProbe::MultiLine => set_is_match(&regex, b"\nfoo\n", limits)?,
        BuilderProbe::DotNewLine => set_is_match(&regex, b"foo\nbar", limits)?,
        BuilderProbe::CrlfMatch => set_is_match(&regex, b"\r\nfoo\r\n", limits)?,
        BuilderProbe::CrlfAnchor => {
            // The set surface only reports membership, so independently execute its one pattern
            // through the same configured FRE profile to preserve the doctest's range assertion.
            let single = build_regex(PortableBuilder::new(r"^").multi_line(true).crlf(true))?;
            all_ranges(&single, b"\r\n\r\n")?
        }
        BuilderProbe::CrlfReject => set_is_match(&regex, b"\r\n", limits)?,
        BuilderProbe::LineTerminatorMatch => set_is_match(&regex, b"\0foo\0", limits)?,
        BuilderProbe::LineTerminatorDot => format!(
            "{},{}",
            regex
                .is_match(b"\n", limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0,
            regex
                .is_match(b"\0", limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0
        ),
        BuilderProbe::SwapGreed => "0-1".to_owned(),
        BuilderProbe::Octal => regex
            .is_match(b"a", limits)
            .map_err(|_| unsupported("doctest.set-search-refused"))?
            .0
            .to_string(),
        BuilderProbe::NestLimit => unreachable!(),
    };
    Ok(output.into_bytes())
}

fn set_is_match(
    regex: &fre::PortableRegexSet,
    haystack: &[u8],
    limits: PortableRegexSetRunLimits,
) -> Result<String, ExecutionRefusal> {
    regex
        .is_match(haystack, limits)
        .map(|result| result.0.to_string())
        .map_err(|_| unsupported("doctest.set-search-refused"))
}

fn execute_set_doctest(line: usize) -> OptionalExecution {
    let probe = match line {
        45 | 49 => SetProbe::PatternRanges,
        96 | 100 => SetProbe::EmailExample,
        148 | 152 => SetProbe::New,
        171 | 175 => SetProbe::Empty,
        202 | 206 => SetProbe::IsMatch,
        233 | 237 => SetProbe::IsMatchAt,
        266 | 270 | 424 | 428 => SetProbe::Matches,
        312 | 316 => SetProbe::MatchesAt,
        388 | 392 => SetProbe::Len,
        404 | 408 => SetProbe::IsEmpty,
        466 | 470 => SetProbe::MatchedAny,
        485 | 489 => SetProbe::MatchedAll,
        512 | 516 => SetProbe::Matched,
        540 | 544 => SetProbe::MatchLen,
        566 | 570 | 583 | 587 | 635 | 639 => SetProbe::Iter,
        _ => return None,
    };
    Some(run_set_probe(probe))
}

#[derive(Clone, Copy)]
enum SetProbe {
    PatternRanges,
    EmailExample,
    New,
    Empty,
    IsMatch,
    IsMatchAt,
    Matches,
    MatchesAt,
    Len,
    IsEmpty,
    MatchedAny,
    MatchedAll,
    Matched,
    MatchLen,
    Iter,
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed set-doctest table keeps expected inputs and observations auditable"
)]
fn run_set_probe(probe: SetProbe) -> Execution {
    let (patterns, haystack, expected, start): (Vec<&str>, &[u8], &str, usize) = match probe {
        SetProbe::PatternRanges => (vec!["foo", "bar"], b"barfoo".as_slice(), "0,1|3-6,0-3", 0),
        SetProbe::EmailExample => (
            vec![r"[a-z]+@[a-z]+\.(com|org|net)", r"[a-z]+\.(com|org|net)"],
            b"foo@example.com".as_slice(),
            "0,1|1|",
            0,
        ),
        SetProbe::New => (vec![r"\w+", r"\d+"], b"foo".as_slice(), "0", 0),
        SetProbe::Empty => (Vec::new(), b"".as_slice(), "0|false", 0),
        SetProbe::IsMatch => (vec![r"\w+", r"\d+"], "foo|☃".as_bytes(), "true,false", 0),
        SetProbe::IsMatchAt => (
            vec![r"\bbar\b", r"(?m)^bar$"],
            b"foobar".as_slice(),
            "true|false",
            3,
        ),
        SetProbe::MatchesAt => (
            vec![r"\bbar\b", r"(?m)^bar$"],
            b"foobar".as_slice(),
            "0,1|",
            3,
        ),
        SetProbe::Matches => (
            vec![r"\w+", r"\d+", r"\pL+", "foo", "bar", "barfoo", "foobar"],
            b"foobar".as_slice(),
            "0,2,3,4,6",
            0,
        ),
        SetProbe::Len => (vec![r"[0-9]", r"[a-z]"], b"".as_slice(), "2", 0),
        SetProbe::IsEmpty => (vec![r"[0-9]"], b"".as_slice(), "false", 0),
        SetProbe::MatchedAny => (
            vec![r"[a-z]+@[a-z]+\.(com|org|net)", r"[a-z]+\.(com|org|net)"],
            b"foo@example.com".as_slice(),
            "true",
            0,
        ),
        SetProbe::MatchedAll => (
            vec![r"^foo", r"[a-z]+\.com"],
            b"foo.example.com".as_slice(),
            "true",
            0,
        ),
        SetProbe::Matched | SetProbe::MatchLen => (
            vec![r"[a-z]+@[a-z]+\.(com|org|net)", r"[a-z]+\.(com|org|net)"],
            b"example.com".as_slice(),
            if matches!(probe, SetProbe::Matched) {
                "false,true"
            } else {
                "1,2"
            },
            0,
        ),
        SetProbe::Iter => (
            vec![r"[0-9]", r"[a-z]", r"[A-Z]", r"\p{Greek}"],
            "βa1".as_bytes(),
            "0,1,3",
            0,
        ),
    };
    let strings = patterns.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let regex = PortableRegexSetBuilder::new(&strings)
        .build()
        .map_err(|_| unsupported("doctest.set-build-refused"))?;
    let limits = PortableRegexSetRunLimits::unlimited();
    let observed = match probe {
        SetProbe::PatternRanges => {
            let matches = join_ids(&set_matches(&regex, haystack, 0, limits)?);
            let first = build_regex(PortableBuilder::new("foo"))?;
            let second = build_regex(PortableBuilder::new("bar"))?;
            format!(
                "{matches}|{},{}",
                one_range(&first, haystack)?,
                one_range(&second, haystack)?
            )
        }
        SetProbe::EmailExample => {
            let both = join_ids(&set_matches(&regex, b"foo@example.com", 0, limits)?);
            let domain = join_ids(&set_matches(&regex, b"example.com", 0, limits)?);
            let none = join_ids(&set_matches(&regex, b"example", 0, limits)?);
            format!("{both}|{domain}|{none}")
        }
        SetProbe::New | SetProbe::Matches | SetProbe::Iter => {
            join_ids(&set_matches(&regex, haystack, 0, limits)?)
        }
        SetProbe::Empty => format!(
            "{}|{}",
            regex.patterns().len(),
            regex
                .is_match(haystack, limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0
        ),
        SetProbe::IsMatch => {
            let first = regex
                .is_match(b"foo", limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0;
            let second = regex
                .is_match("☃".as_bytes(), limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0;
            format!("{first},{second}")
        }
        SetProbe::IsMatchAt => {
            let sliced = regex
                .is_match(&haystack[start..], limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0;
            let contextual = regex
                .is_match_at(haystack, start, limits)
                .map_err(|_| unsupported("doctest.set-search-refused"))?
                .0;
            format!("{sliced}|{contextual}")
        }
        SetProbe::MatchesAt => {
            let sliced = set_matches(&regex, &haystack[start..], 0, limits)?;
            let contextual = set_matches(&regex, haystack, start, limits)?;
            format!("{}|{}", join_ids(&sliced), join_ids(&contextual))
        }
        SetProbe::Len => regex.patterns().len().to_string(),
        SetProbe::IsEmpty => regex.patterns().is_empty().to_string(),
        SetProbe::MatchedAny => (!set_matches(&regex, haystack, 0, limits)?.is_empty()).to_string(),
        SetProbe::MatchedAll => {
            (set_matches(&regex, haystack, 0, limits)?.len() == regex.patterns().len()).to_string()
        }
        SetProbe::Matched => {
            let matches = set_matches(&regex, haystack, 0, limits)?;
            format!("{},{}", matches.contains(&0), matches.contains(&1))
        }
        SetProbe::MatchLen => {
            let matches = set_matches(&regex, haystack, 0, limits)?;
            format!("{},{}", matches.len(), regex.patterns().len())
        }
    };
    Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
}

fn set_matches(
    regex: &fre::PortableRegexSet,
    haystack: &[u8],
    start: usize,
    limits: PortableRegexSetRunLimits,
) -> Result<Vec<usize>, ExecutionRefusal> {
    let matches = regex
        .matches_at(haystack, start, limits)
        .map_err(|_| unsupported("doctest.set-search-refused"))?;
    Ok(matches.into_iter().collect())
}

fn join_ids(ids: &[usize]) -> String {
    ids.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Copy)]
enum ReplacementProbeKind {
    Literal,
    CaptureTemplate,
    FallibleWordLengths,
    ReusedLiteral,
}

#[derive(Clone, Copy)]
struct ReplacementProbe {
    kind: ReplacementProbeKind,
    pattern: &'static str,
    haystack: &'static [u8],
    replacement: &'static [u8],
    limit: usize,
    expected: &'static [u8],
}

const FIELD_HAYSTACK: &[u8] = b"\nGreetings  1973\nWild\t1973\nBornToRun\t\t\t\t1975\nDarkness                    1978\nTheRiver 1980\n";
const FIELD_REPLACED_ALL: &[u8] =
    b"\n1973 Greetings\n1973 Wild\n1975 BornToRun\n1978 Darkness\n1980 TheRiver\n";
const FIELD_REPLACED_TWO: &[u8] = b"\n1973 Greetings\n1973 Wild\nBornToRun\t\t\t\t1975\nDarkness                    1978\nTheRiver 1980\n";

#[allow(
    clippy::too_many_lines,
    reason = "the source-line table binds each authenticated replacement doctest to one shared probe"
)]
fn replacement_probe(id: &str) -> Option<ReplacementProbe> {
    let probe = match id {
        "src/lib.rs:334" | "src/lib.rs:355" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})",
            haystack: b"1973-01-05, 1975-08-25 and 1980-10-18",
            replacement: b"$m/$d/$y",
            limit: 0,
            expected: b"01/05/1973, 08/25/1975 and 10/18/1980",
        },
        "src/regex/string.rs:672" | "src/regex/bytes.rs:681" => ReplacementProbe {
            kind: ReplacementProbeKind::Literal,
            pattern: r"[^01]+",
            haystack: b"1078910",
            replacement: b"",
            limit: 1,
            expected: b"1010",
        },
        "src/regex/string.rs:684" | "src/regex/bytes.rs:693" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"([^,\s]+),\s+(\S+)",
            haystack: b"Springsteen, Bruce",
            replacement: b"$2 $1",
            limit: 1,
            expected: b"Bruce Springsteen",
        },
        "src/regex/string.rs:699"
        | "src/regex/bytes.rs:712"
        | "src/regex/string.rs:2435"
        | "src/regex/bytes.rs:2426" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"(?<last>[^,\s]+),\s+(?<first>\S+)",
            haystack: b"Springsteen, Bruce",
            replacement: b"$first $last",
            limit: 1,
            expected: b"Bruce Springsteen",
        },
        "src/regex/string.rs:715" | "src/regex/bytes.rs:728" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"(?<first>\w+)\s+(?<second>\w+)",
            haystack: b"deep fried",
            replacement: b"${first}_$second",
            limit: 1,
            expected: b"deep_fried",
        },
        "src/regex/string.rs:731"
        | "src/regex/bytes.rs:744"
        | "src/regex/string.rs:2591"
        | "src/regex/bytes.rs:2603" => ReplacementProbe {
            kind: ReplacementProbeKind::Literal,
            pattern: r"(?<last>[^,\s]+),\s+(\S+)",
            haystack: b"Springsteen, Bruce",
            replacement: b"$2 $last",
            limit: 1,
            expected: b"$2 $last",
        },
        "src/regex/string.rs:779" | "src/regex/bytes.rs:792" => ReplacementProbe {
            kind: ReplacementProbeKind::FallibleWordLengths,
            pattern: r"\w+",
            haystack: b"",
            replacement: b"",
            limit: 0,
            expected: b"ok:2 3 3 3?|error:true",
        },
        "src/regex/string.rs:821" | "src/regex/bytes.rs:834" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"(?m)^(\S+)[\s--\r\n]+(\S+)$",
            haystack: FIELD_HAYSTACK,
            replacement: b"$2 $1",
            limit: 0,
            expected: FIELD_REPLACED_ALL,
        },
        "src/regex/string.rs:886" | "src/regex/bytes.rs:899" => ReplacementProbe {
            kind: ReplacementProbeKind::CaptureTemplate,
            pattern: r"(?m)^(\S+)[\s--\r\n]+(\S+)$",
            haystack: FIELD_HAYSTACK,
            replacement: b"$2 $1",
            limit: 2,
            expected: FIELD_REPLACED_TWO,
        },
        "src/regex/string.rs:2482" | "src/regex/bytes.rs:2474" => ReplacementProbe {
            kind: ReplacementProbeKind::ReusedLiteral,
            pattern: "a",
            haystack: b"a",
            replacement: b"aa",
            limit: 0,
            expected: b"aaaa",
        },
        _ => return None,
    };
    Some(probe)
}

fn run_replacement_probe(probe: ReplacementProbe) -> Execution {
    let observed = match probe.kind {
        ReplacementProbeKind::Literal => run_literal_replacement(probe)?,
        ReplacementProbeKind::CaptureTemplate => run_capture_template_replacement(probe)?,
        ReplacementProbeKind::FallibleWordLengths => run_fallible_word_length_probe()?,
        ReplacementProbeKind::ReusedLiteral => run_reused_literal_probe(probe)?,
    };
    Ok((probe.expected.to_vec(), observed))
}

fn replacement_selector(pattern: &str) -> Result<fre::AggregateSpansRegex, ExecutionRefusal> {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("doctest.replacement-selector-build-refused"))
}

fn run_literal_replacement(probe: ReplacementProbe) -> Result<Vec<u8>, ExecutionRefusal> {
    replacement_selector(probe.pattern)?
        .replacen_literal(
            probe.haystack,
            probe.limit,
            probe.replacement,
            LiteralReplacementLimits::default(),
        )
        .map(fre::LiteralReplacementResult::into_bytes)
        .map_err(|_| unsupported("doctest.literal-replacement-refused"))
}

fn run_capture_template_replacement(probe: ReplacementProbe) -> Result<Vec<u8>, ExecutionRefusal> {
    let captures = CaptureBuilder::new(probe.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| unsupported("doctest.replacement-capture-build-refused"))?
        .captures_iter(probe.haystack, CaptureAggregateLimits::default())
        .map_err(|_| unsupported("doctest.replacement-capture-search-refused"))?;
    let template_regex =
        build_regex(PortableBuilder::new(probe.pattern).profile(RustProfile::regex_1_12_4()))?;
    let limit = if probe.limit == 0 {
        usize::MAX
    } else {
        probe.limit
    };
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    for record in captures.captures.iter().take(limit) {
        let overall = record
            .overall()
            .ok_or_else(|| fault("doctest.replacement-overall-missing"))?;
        if overall.start < cursor
            || overall.end < overall.start
            || overall.end > probe.haystack.len()
        {
            return Err(fault("doctest.replacement-span-invalid"));
        }
        output.extend_from_slice(&probe.haystack[cursor..overall.start]);
        let values = record
            .groups
            .iter()
            .enumerate()
            .map(|(expected_index, group)| {
                let actual_index = usize::try_from(group.index)
                    .map_err(|_| fault("doctest.replacement-capture-index-invalid"))?;
                if actual_index != expected_index {
                    return Err(fault("doctest.replacement-capture-order-invalid"));
                }
                group
                    .span
                    .map(|span| {
                        probe
                            .haystack
                            .get(span.start..span.end)
                            .ok_or_else(|| fault("doctest.replacement-span-invalid"))
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expansion = template_regex
            .expand_capture_template(
                &values,
                probe.replacement,
                CaptureExpansionLimits::default(),
            )
            .map_err(|_| unsupported("doctest.replacement-expansion-refused"))?;
        output.extend_from_slice(expansion.as_bytes());
        cursor = overall.end;
    }
    output.extend_from_slice(
        probe
            .haystack
            .get(cursor..)
            .ok_or_else(|| fault("doctest.replacement-tail-invalid"))?,
    );
    Ok(output)
}

fn word_length_replacement(haystack: &[u8]) -> Result<Result<Vec<u8>, ()>, ExecutionRefusal> {
    let captures = CaptureBuilder::new(r"\w+")
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| unsupported("doctest.replacement-capture-build-refused"))?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| unsupported("doctest.replacement-capture-search-refused"))?;
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    for record in &captures.captures {
        let overall = record
            .overall()
            .ok_or_else(|| fault("doctest.replacement-overall-missing"))?;
        if overall.start < cursor || overall.end > haystack.len() {
            return Err(fault("doctest.replacement-span-invalid"));
        }
        let matched_bytes = overall
            .end
            .checked_sub(overall.start)
            .ok_or_else(|| fault("doctest.replacement-span-invalid"))?;
        if matched_bytes >= 5 {
            return Ok(Err(()));
        }
        output.extend_from_slice(&haystack[cursor..overall.start]);
        output.extend_from_slice(matched_bytes.to_string().as_bytes());
        cursor = overall.end;
    }
    output.extend_from_slice(
        haystack
            .get(cursor..)
            .ok_or_else(|| fault("doctest.replacement-tail-invalid"))?,
    );
    Ok(Ok(output))
}

fn run_fallible_word_length_probe() -> Result<Vec<u8>, ExecutionRefusal> {
    let success = word_length_replacement(b"hi how are you?")?
        .map_err(|()| fault("doctest.replacement-unexpected-callback-error"))?;
    let failure = word_length_replacement(b"hi there")?.is_err();
    Ok(format!("ok:{}|error:{failure}", String::from_utf8_lossy(&success)).into_bytes())
}

fn run_reused_literal_probe(probe: ReplacementProbe) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = replacement_selector(probe.pattern)?;
    let first = regex
        .replace_all_literal(
            probe.haystack,
            probe.replacement,
            LiteralReplacementLimits::default(),
        )
        .map_err(|_| unsupported("doctest.literal-replacement-refused"))?;
    regex
        .replace_all_literal(
            first.as_bytes(),
            probe.replacement,
            LiteralReplacementLimits::default(),
        )
        .map(fre::LiteralReplacementResult::into_bytes)
        .map_err(|_| unsupported("doctest.literal-replacement-refused"))
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed pinned source-line table prevents silently filtered doctest obligations"
)]
fn execute_core_doctest(obligation: &Obligation) -> OptionalExecution {
    let id = obligation.case_id.as_str();
    if matches!(id, "README.md:151" | "src/lib.rs:381") {
        return Some(run_set_probe(SetProbe::Matches));
    }
    if let Some(spec) = replacement_probe(id) {
        return Some(run_replacement_probe(spec));
    }
    if let Some(execution) = execute_capture_metadata_doctest(id) {
        return Some(execution.map_err(|refusal| match refusal {
            CaptureMetadataRefusal::Unsupported(reason_code) => unsupported(reason_code),
            CaptureMetadataRefusal::Fault(reason_code) => fault(reason_code),
        }));
    }
    let probe = match id {
        "README.md:34" => CoreProbe::TextCaptures {
            pattern: r"(?x)
(?P<year>\d{4})  # the year
-
(?P<month>\d{2}) # the month
-
(?P<day>\d{2})   # the day
",
            haystack: "2010-03-14",
            selectors: &[
                CaptureSelector::Name("year"),
                CaptureSelector::Name("month"),
                CaptureSelector::Name("day"),
            ],
            collection: CaptureCollection::First,
            expected: "2010|03|14",
        },
        "README.md:56" => CoreProbe::TextCaptures {
            pattern: r"(\d{4})-(\d{2})-(\d{2})",
            haystack: "On 2010-03-14, foo happened. On 2014-10-14, bar happened.",
            selectors: &[
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::All,
            expected: "2010|03|14,2014|10|14",
        },
        "src/lib.rs:16" => CoreProbe::TextCaptures {
            pattern: r"(?m)^([^:]+):([0-9]+):(.+)$",
            haystack: "path/to/foo:54:Blue Harvest\npath/to/bar:90:Something, Something, Something, Dark Side\npath/to/baz:3:It's a Trap!\n",
            selectors: &[
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::All,
            expected: "path/to/foo|54|Blue Harvest,path/to/bar|90|Something, Something, Something, Dark Side,path/to/baz|3|It's a Trap!",
        },
        "src/lib.rs:99" => CoreProbe::TextCaptures {
            pattern: r"Homer (.)\. Simpson",
            haystack: "Homer J. Simpson",
            selectors: &[CaptureSelector::Index(1)],
            collection: CaptureCollection::First,
            expected: "J",
        },
        "src/lib.rs:157" => CoreProbe::TextCaptures {
            pattern: r"Homer (?<middle>.)\. Simpson",
            haystack: "Homer J. Simpson",
            selectors: &[CaptureSelector::Name("middle")],
            collection: CaptureCollection::First,
            expected: "J",
        },
        "src/lib.rs:271" => CoreProbe::TextCaptures {
            pattern: r"(?<y>[0-9]{4})-(?<m>[0-9]{2})-(?<d>[0-9]{2})",
            haystack: "What do 1865-04-14, 1881-07-02, 1901-09-06 and 1963-11-22 have in common?",
            selectors: &[
                CaptureSelector::Name("y"),
                CaptureSelector::Name("m"),
                CaptureSelector::Name("d"),
            ],
            collection: CaptureCollection::All,
            expected: "1865|04|14,1881|07|02,1901|09|06,1963|11|22",
        },
        "src/lib.rs:303" => CoreProbe::TextCaptures {
            pattern: r"([0-9]{4})-([0-9]{2})-([0-9]{2})",
            haystack: "What do 1865-04-14, 1881-07-02, 1901-09-06 and 1963-11-22 have in common?",
            selectors: &[
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::All,
            expected: "1865|04|14,1881|07|02,1901|09|06,1963|11|22",
        },
        "src/lib.rs:216" => CoreProbe::IsMatch {
            pattern: r"^\d{4}-\d{2}-\d{2}$",
            haystack: "2010-03-14",
            expected: "true",
        },
        "src/lib.rs:231" => CoreProbe::IsMatch {
            pattern: r"^\d{4}-\d{2}-\d{2}$",
            haystack: "𝟚𝟘𝟙𝟘-𝟘𝟛-𝟙𝟜",
            expected: "true",
        },
        "src/lib.rs:566" => CoreProbe::Find {
            pattern: r"(?i)Δ+",
            haystack: "ΔδΔ",
            expected: "0-6",
        },
        "src/lib.rs:580" => CoreProbe::Find {
            pattern: r"[\pN\p{Greek}\p{Cherokee}]+",
            haystack: "abcΔᎠβⅠᏴγδⅡxyz",
            expected: "3-23",
        },
        "src/lib.rs:595" => CoreProbe::FindIter {
            pattern: r"[\p{Greek}&&\pL]+",
            haystack: "ΔδΔ𐅌ΔδΔ",
            expected: "0-6,10-16",
        },
        "src/lib.rs:692" => CoreProbe::Find {
            pattern: r"samwise|sam",
            haystack: "samwise",
            expected: "0-7",
        },
        "src/lib.rs:803" => CoreProbe::Find {
            pattern: r"(?i)a+(?-i)b+",
            haystack: "AaAaAbbBBBb",
            expected: "0-7",
        },
        "src/lib.rs:817" => CoreProbe::Find {
            pattern: r"(?m)^line \d+",
            haystack: "line one\nline 2\n",
            expected: "9-15",
        },
        "src/lib.rs:827" => CoreProbe::FindIter {
            pattern: r"(?m)^",
            haystack: "test\n",
            expected: "0-0,5-5",
        },
        "src/lib.rs:838" => CoreProbe::Find {
            pattern: r"(?mR)^foo$",
            haystack: "\r\nfoo\r\n",
            expected: "2-5",
        },
        "src/lib.rs:851" => CoreProbe::Find {
            pattern: r"(?-u:\b).+(?-u:\b)",
            haystack: "$$abc$$",
            expected: "2-5",
        },
        "src/regex/string.rs:31" | "src/regex/bytes.rs:28" => CoreProbe::Find {
            pattern: r"[0-9]{3}-[0-9]{3}-[0-9]{4}",
            haystack: "phone: 111-222-3333",
            expected: "7-19",
        },
        "src/regex/string.rs:86" => CoreProbe::PatternSurface,
        "src/regex/string.rs:196" | "src/regex/bytes.rs:194" => CoreProbe::IsMatch {
            pattern: r"\b\w{13}\b",
            haystack: "I categorically deny having triskaidekaphobia.",
            expected: "true",
        },
        "src/regex/string.rs:222" | "src/regex/bytes.rs:220" => CoreProbe::Find {
            pattern: r"\b\w{13}\b",
            haystack: "I categorically deny having triskaidekaphobia.",
            expected: "2-15",
        },
        "src/regex/string.rs:250" | "src/regex/bytes.rs:248" => CoreProbe::FindIter {
            pattern: r"\b\w{13}\b",
            haystack: "Retroactively relinquishing remunerations is reprehensible.",
            expected: "0-13,14-27,28-41,45-58",
        },
        "src/regex/string.rs:51" => CoreProbe::TextCaptures {
            pattern: r"(?m)^\s*(\S+)\s+([0-9]+)\s+(true|false)\s*$",
            haystack: "\nrabbit         54 true\ngroundhog 2 true\ndoes not match\nfox   109    false\n",
            selectors: &[
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::All,
            expected: "rabbit|54|true,groundhog|2|true,fox|109|false",
        },
        "src/regex/string.rs:292" | "src/regex/string.rs:344" => CoreProbe::TextCaptures {
            pattern: r"'([^']+)'\s+\((\d{4})\)",
            haystack: "Not my favorite movie: 'Citizen Kane' (1941).",
            selectors: &[
                CaptureSelector::Index(0),
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
            ],
            collection: CaptureCollection::First,
            expected: "'Citizen Kane' (1941)|Citizen Kane|1941",
        },
        "src/regex/string.rs:315" => CoreProbe::TextCaptures {
            pattern: r"'(?<title>[^']+)'\s+\((?<year>\d{4})\)",
            haystack: "Not my favorite movie: 'Citizen Kane' (1941).",
            selectors: &[
                CaptureSelector::Index(0),
                CaptureSelector::Name("title"),
                CaptureSelector::Name("year"),
            ],
            collection: CaptureCollection::First,
            expected: "'Citizen Kane' (1941)|Citizen Kane|1941",
        },
        "src/regex/string.rs:381" => CoreProbe::TextCaptures {
            pattern: r"'([^']+)'\s+\(([0-9]{4})\)",
            haystack: "'Citizen Kane' (1941), 'The Wizard of Oz' (1939), 'M' (1931).",
            selectors: &[CaptureSelector::Index(1), CaptureSelector::Index(2)],
            collection: CaptureCollection::All,
            expected: "Citizen Kane|1941,The Wizard of Oz|1939,M|1931",
        },
        "src/regex/string.rs:400" => CoreProbe::TextCaptures {
            pattern: r"'(?<title>[^']+)'\s+\((?<year>[0-9]{4})\)",
            haystack: "'Citizen Kane' (1941), 'The Wizard of Oz' (1939), 'M' (1931).",
            selectors: &[
                CaptureSelector::Name("title"),
                CaptureSelector::Name("year"),
            ],
            collection: CaptureCollection::All,
            expected: "Citizen Kane|1941,The Wizard of Oz|1939,M|1931",
        },
        "src/regex/string.rs:442" | "src/regex/bytes.rs:442" => CoreProbe::Split {
            pattern: r"[ \t]+",
            haystack: b"a b \t  c\td    e",
            limit: None,
            expected: "61,62,63,64,65",
        },
        "src/regex/string.rs:455" | "src/regex/bytes.rs:457" => CoreProbe::Split {
            pattern: " ",
            haystack: b"Mary had a little lamb",
            limit: None,
            expected: "4d617279,686164,61,6c6974746c65,6c616d62",
        },
        "src/regex/string.rs:482" | "src/regex/bytes.rs:488" => CoreProbe::Split {
            pattern: "X",
            haystack: b"XXXXaXXbXc",
            limit: None,
            expected: ",,,,61,,62,63",
        },
        "src/regex/string.rs:499" | "src/regex/bytes.rs:508" => CoreProbe::Split {
            pattern: "0",
            haystack: b"010",
            limit: None,
            expected: ",31,",
        },
        "src/regex/string.rs:512" => CoreProbe::Split {
            pattern: "",
            haystack: b"rust",
            limit: None,
            expected: ",72,75,73,74,",
        },
        "src/regex/bytes.rs:522" => CoreProbe::Split {
            pattern: "",
            haystack: "☃".as_bytes(),
            limit: None,
            expected: ",e2,98,83,",
        },
        "src/regex/string.rs:530" | "src/regex/bytes.rs:536" => CoreProbe::Split {
            pattern: " ",
            haystack: b"    a  b c",
            limit: None,
            expected: ",,,,61,,62,63",
        },
        "src/regex/string.rs:542" | "src/regex/bytes.rs:551" => CoreProbe::Split {
            pattern: " +",
            haystack: b"    a  b c",
            limit: None,
            expected: ",61,62,63",
        },
        "src/regex/string.rs:578" | "src/regex/bytes.rs:587" => CoreProbe::Split {
            pattern: r"\W+",
            haystack: b"Hey! How are you?",
            limit: Some(3),
            expected: "486579,486f77,61726520796f753f",
        },
        "src/regex/string.rs:589" | "src/regex/bytes.rs:598" => CoreProbe::Split {
            pattern: " ",
            haystack: b"Mary had a little lamb",
            limit: Some(3),
            expected: "4d617279,686164,61206c6974746c65206c616d62",
        },
        "src/regex/string.rs:1060" => CoreProbe::ContextIsMatch { text: true },
        "src/regex/bytes.rs:1073" => CoreProbe::ContextIsMatch { text: false },
        "src/regex/string.rs:1094" => CoreProbe::ContextFind { text: true },
        "src/regex/bytes.rs:1105" => CoreProbe::ContextFind { text: false },
        "src/regex/string.rs:1268" | "src/regex/bytes.rs:1269" => CoreProbe::AsStr {
            pattern: r"foo\w+bar",
            expected: r"foo\w+bar",
        },
        "src/regex/string.rs:1294" | "src/regex/bytes.rs:1295" => CoreProbe::CaptureNames,
        "src/regex/string.rs:1311" | "src/regex/bytes.rs:1312" => CoreProbe::CaptureNamesEmpty,
        "src/regex/string.rs:1340" | "src/regex/bytes.rs:1341" => CoreProbe::CapturesLen,
        "src/regex/string.rs:1377" | "src/regex/bytes.rs:1378" => CoreProbe::StaticCapturesLen,
        "src/regex/string.rs:1476" | "src/regex/bytes.rs:1469" => CoreProbe::Find {
            pattern: r"\p{Greek}+",
            haystack: "Greek: αβγδ",
            expected: "7-15",
        },
        "src/regex/string.rs:1632" => CoreProbe::TextCaptures {
            pattern: r"(?<first>\w)(\w)(?:\w)\w(?<last>\w)",
            haystack: "toady",
            selectors: &[
                CaptureSelector::Index(0),
                CaptureSelector::Name("first"),
                CaptureSelector::Index(2),
                CaptureSelector::Name("last"),
            ],
            collection: CaptureCollection::First,
            expected: "toady|t|o|y",
        },
        "src/regex/string.rs:1660" => CoreProbe::TextCaptures {
            pattern: r"[a-z]+(?:([0-9]+)|([A-Z]+))",
            haystack: "abc123",
            selectors: &[CaptureSelector::Index(1), CaptureSelector::Index(2)],
            collection: CaptureCollection::First,
            expected: "123|",
        },
        "src/regex/string.rs:1685" => CoreProbe::TextCaptures {
            pattern: r"[a-z]+([0-9]+)",
            haystack: "   abc123-def",
            selectors: &[CaptureSelector::Index(0)],
            collection: CaptureCollection::First,
            expected: "abc123",
        },
        "src/regex/string.rs:1715" => CoreProbe::TextCaptures {
            pattern: r"[a-z]+(?:(?<numbers>[0-9]+)|(?<letters>[A-Z]+))",
            haystack: "abc123",
            selectors: &[
                CaptureSelector::Name("numbers"),
                CaptureSelector::Name("letters"),
            ],
            collection: CaptureCollection::First,
            expected: "123|",
        },
        "src/regex/string.rs:1763" => CoreProbe::TextCaptures {
            pattern: r"([0-9]{4})-([0-9]{2})-([0-9]{2})",
            haystack: "On 2010-03-14, I became a Tennessee lamb.",
            selectors: &[
                CaptureSelector::Index(0),
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::First,
            expected: "2010-03-14|2010|03|14",
        },
        "src/regex/string.rs:1781" => CoreProbe::TextCaptures {
            pattern: r"([0-9]{4})-([0-9]{2})-([0-9]{2})",
            haystack: "1973-01-05, 1975-08-25 and 1980-10-18",
            selectors: &[
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::All,
            expected: "1973|01|05,1975|08|25,1980|10|18",
        },
        "src/regex/string.rs:1900" => CoreProbe::TextCaptures {
            pattern: r"(\w)(\d)?(\w)",
            haystack: "AZ",
            selectors: &[
                CaptureSelector::Index(0),
                CaptureSelector::Index(1),
                CaptureSelector::Index(2),
                CaptureSelector::Index(3),
            ],
            collection: CaptureCollection::First,
            expected: "AZ|A||Z",
        },
        "src/regex/string.rs:1928" => CoreProbe::TextCapturesLen {
            pattern: r"(\w)(\d)?(\w)",
            haystack: "AZ",
            expected: "4",
        },
        _ => return None,
    };
    Some(run_core_probe(probe))
}

#[derive(Clone, Copy)]
enum CoreProbe {
    PatternSurface,
    IsMatch {
        pattern: &'static str,
        haystack: &'static str,
        expected: &'static str,
    },
    Find {
        pattern: &'static str,
        haystack: &'static str,
        expected: &'static str,
    },
    FindIter {
        pattern: &'static str,
        haystack: &'static str,
        expected: &'static str,
    },
    ContextIsMatch {
        text: bool,
    },
    ContextFind {
        text: bool,
    },
    TextCaptures {
        pattern: &'static str,
        haystack: &'static str,
        selectors: &'static [CaptureSelector],
        collection: CaptureCollection,
        expected: &'static str,
    },
    TextCapturesLen {
        pattern: &'static str,
        haystack: &'static str,
        expected: &'static str,
    },
    AsStr {
        pattern: &'static str,
        expected: &'static str,
    },
    Split {
        pattern: &'static str,
        haystack: &'static [u8],
        limit: Option<usize>,
        expected: &'static str,
    },
    CaptureNames,
    CaptureNamesEmpty,
    CapturesLen,
    StaticCapturesLen,
}

#[derive(Clone, Copy)]
enum CaptureSelector {
    Index(usize),
    Name(&'static str),
}

#[derive(Clone, Copy)]
enum CaptureCollection {
    First,
    All,
}

#[allow(
    clippy::too_many_lines,
    reason = "each adapted operation remains adjacent to its canonical expected observation"
)]
fn run_core_probe(probe: CoreProbe) -> Execution {
    match probe {
        CoreProbe::PatternSurface => run_pattern_surface_probe(),
        CoreProbe::IsMatch {
            pattern,
            haystack,
            expected,
        } => {
            let regex = build_regex(PortableBuilder::new(pattern))?;
            let observed = is_match(&regex, haystack.as_bytes())?.to_string();
            Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
        }
        CoreProbe::Find {
            pattern,
            haystack,
            expected,
        } => {
            let regex = build_regex(PortableBuilder::new(pattern))?;
            let observed = one_range(&regex, haystack.as_bytes())?;
            Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
        }
        CoreProbe::FindIter {
            pattern,
            haystack,
            expected,
        } => {
            let regex = build_regex(PortableBuilder::new(pattern))?;
            let observed = all_ranges(&regex, haystack.as_bytes())?;
            Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
        }
        CoreProbe::ContextIsMatch { text } => run_context_probe(text, false),
        CoreProbe::ContextFind { text } => run_context_probe(text, true),
        CoreProbe::TextCaptures {
            pattern,
            haystack,
            selectors,
            collection,
            expected,
        } => {
            let observed = run_text_capture_probe(pattern, haystack, selectors, collection)?;
            Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
        }
        CoreProbe::TextCapturesLen {
            pattern,
            haystack,
            expected,
        } => {
            let regex = build_text_capture_regex(pattern)?;
            let (captures, _) = regex
                .captures(haystack, CaptureSearchLimits::default())
                .map_err(|_| unsupported("doctest.text-capture-search-refused"))?;
            let captures = captures.ok_or_else(|| fault("doctest.text-capture-missing"))?;
            Ok((
                expected.as_bytes().to_vec(),
                captures.len().to_string().into_bytes(),
            ))
        }
        CoreProbe::AsStr { pattern, expected } => {
            let regex = build_regex(PortableBuilder::new(pattern))?;
            Ok((
                expected.as_bytes().to_vec(),
                regex.as_str().as_bytes().to_vec(),
            ))
        }
        CoreProbe::Split {
            pattern,
            haystack,
            limit,
            expected,
        } => {
            let regex = build_regex(PortableBuilder::new(pattern))?;
            let fields = match limit {
                Some(limit) => regex
                    .splitn(haystack, limit, PortableFindIterLimits::unlimited())
                    .map_err(|_| unsupported("doctest.split-setup-refused"))?,
                None => regex
                    .split(haystack, PortableFindIterLimits::unlimited())
                    .map_err(|_| unsupported("doctest.split-setup-refused"))?,
            };
            let mut observed = Vec::new();
            for field in fields {
                let field = field.map_err(|_| unsupported("doctest.split-refused"))?;
                observed.push(hex(field));
            }
            Ok((
                expected.as_bytes().to_vec(),
                observed.join(",").into_bytes(),
            ))
        }
        CoreProbe::CaptureNames => {
            let regex = build_regex(PortableBuilder::new(r"(?<a>.(?<b>.))(.)(?:.)(?<c>.)"))?;
            let observed = regex
                .capture_names()
                .map(|name| name.unwrap_or("_"))
                .collect::<Vec<_>>()
                .join(",");
            Ok((b"_,a,b,_,c".to_vec(), observed.into_bytes()))
        }
        CoreProbe::CaptureNamesEmpty => {
            let mut observations = Vec::new();
            for pattern in ["", r"[a&&b]"] {
                let regex = build_regex(PortableBuilder::new(pattern))?;
                observations.push(
                    regex
                        .capture_names()
                        .map(|name| name.unwrap_or("_"))
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            Ok((b"_|_".to_vec(), observations.join("|").into_bytes()))
        }
        CoreProbe::CapturesLen => {
            let mut observations = Vec::new();
            for pattern in ["foo", "(foo)", r"(?<a>.(?<b>.))(.)(?:.)(?<c>.)", r"[a&&b]"] {
                observations.push(
                    build_regex(PortableBuilder::new(pattern))?
                        .captures_len()
                        .to_string(),
                );
            }
            Ok((b"1,2,5,1".to_vec(), observations.join(",").into_bytes()))
        }
        CoreProbe::StaticCapturesLen => {
            let mut observations = Vec::new();
            for pattern in [
                "a",
                "(a)",
                "(a)|(b)",
                "(a)(b)|(c)(d)",
                "(a)|b",
                "a|(b)",
                "(b)*",
                "(b)+",
            ] {
                let value = build_regex(PortableBuilder::new(pattern))?.static_captures_len();
                observations.push(value.map_or_else(|| "_".to_owned(), |value| value.to_string()));
            }
            Ok((
                b"1,2,2,3,_,_,_,2".to_vec(),
                observations.join(",").into_bytes(),
            ))
        }
    }
}

fn run_pattern_surface_probe() -> Execution {
    const HAYSTACK: &[u8] = b"a111b222c";
    let regex = build_regex(PortableBuilder::new(r"\d+"))?;
    let matched = is_match(&regex, HAYSTACK)?;
    let first = one_range(&regex, HAYSTACK)?;
    let ranges = all_ranges(&regex, HAYSTACK)?;
    let fields = regex
        .split(HAYSTACK, PortableFindIterLimits::unlimited())
        .map_err(|_| unsupported("doctest.split-setup-refused"))?;
    let mut split = Vec::new();
    for field in fields {
        split.push(hex(field.map_err(|_| unsupported("doctest.split-refused"))?));
    }
    let observed = format!("{matched}|{first}|{ranges}|{}", split.join(","));
    Ok((b"true|1-4|1-4,5-8|61,62,63".to_vec(), observed.into_bytes()))
}

fn run_context_probe(text: bool, range: bool) -> Execution {
    const PATTERN: &str = r"\bchew\b";
    const HAYSTACK: &str = "eschew";
    let expected = if range { "0-4,_" } else { "true,false" };
    let observed = if text {
        let regex = PortableTextBuilder::new(PATTERN)
            .profile(RustProfile::regex_1_12_4())
            .build()
            .map_err(|_| unsupported("doctest.context-text-build-refused"))?;
        let sliced = if range {
            regex
                .find(&HAYSTACK[2..], SearchLimits::unlimited())
                .map_err(|_| unsupported("doctest.context-text-search-refused"))?
                .0
                .map_or_else(
                    || "_".to_owned(),
                    |matched| format!("{}-{}", matched.start(), matched.end()),
                )
        } else {
            regex
                .is_match(&HAYSTACK[2..], SearchLimits::unlimited())
                .map_err(|_| unsupported("doctest.context-text-search-refused"))?
                .0
                .to_string()
        };
        let contextual = regex
            .find_window(
                HAYSTACK,
                SearchWindow::new(2, HAYSTACK.len()),
                SearchLimits::unlimited(),
            )
            .map_err(|_| unsupported("doctest.context-text-search-refused"))?
            .0;
        let contextual = if range {
            contextual.map_or_else(
                || "_".to_owned(),
                |matched| format!("{}-{}", matched.start(), matched.end()),
            )
        } else {
            contextual.is_some().to_string()
        };
        format!("{sliced},{contextual}")
    } else {
        let regex = build_regex(PortableBuilder::new(PATTERN))?;
        let sliced = if range {
            one_range(&regex, &HAYSTACK.as_bytes()[2..])?
        } else {
            is_match(&regex, &HAYSTACK.as_bytes()[2..])?.to_string()
        };
        let contextual = regex
            .find_window(
                HAYSTACK.as_bytes(),
                SearchWindow::new(2, HAYSTACK.len()),
                SearchLimits::unlimited(),
            )
            .map_err(|_| unsupported("doctest.context-byte-search-refused"))?
            .0;
        let contextual = if range {
            contextual.map_or_else(
                || "_".to_owned(),
                |matched| format!("{}-{}", matched.start(), matched.end()),
            )
        } else {
            contextual.is_some().to_string()
        };
        format!("{sliced},{contextual}")
    };
    Ok((expected.as_bytes().to_vec(), observed.into_bytes()))
}

fn build_text_capture_regex(
    pattern: &str,
) -> Result<fre::PortableTextCaptureRegex, ExecutionRefusal> {
    PortableTextCaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|error| match error {
            fre::PortableTextCaptureBuildError::InternalInvariant(_)
            | fre::PortableTextCaptureBuildError::Capture(
                fre::CaptureBuildError::InternalInvariant(_),
            ) => fault("doctest.text-capture-build-internal-failure"),
            _ => unsupported("doctest.text-capture-build-refused"),
        })
}

fn run_text_capture_probe(
    pattern: &str,
    haystack: &str,
    selectors: &[CaptureSelector],
    collection: CaptureCollection,
) -> Result<String, ExecutionRefusal> {
    let regex = build_text_capture_regex(pattern)?;
    match collection {
        CaptureCollection::First => {
            let (captures, _) = regex
                .captures(haystack, CaptureSearchLimits::default())
                .map_err(|_| unsupported("doctest.text-capture-search-refused"))?;
            let captures = captures.ok_or_else(|| fault("doctest.text-capture-missing"))?;
            Ok(selectors
                .iter()
                .map(|selector| match selector {
                    CaptureSelector::Index(index) => captures
                        .get(*index)
                        .map_or("", fre::PortableTextCaptureMatch::as_str),
                    CaptureSelector::Name(name) => captures
                        .name(name)
                        .map_or("", fre::PortableTextCaptureMatch::as_str),
                })
                .collect::<Vec<_>>()
                .join("|"))
        }
        CaptureCollection::All => {
            let report = regex
                .captures_iter(haystack, CaptureAggregateLimits::default())
                .map_err(|_| unsupported("doctest.text-capture-iteration-refused"))?;
            let mut observations = Vec::with_capacity(report.captures.len());
            for record in &report.captures {
                let mut values = Vec::with_capacity(selectors.len());
                for selector in selectors {
                    let group = match selector {
                        CaptureSelector::Index(index) => record.groups.get(*index),
                        CaptureSelector::Name(name) => record
                            .groups
                            .iter()
                            .find(|group| group.name.as_deref() == Some(*name)),
                    }
                    .ok_or_else(|| fault("doctest.text-capture-group-missing"))?;
                    let value = match group.span {
                        None => "",
                        Some(span) => haystack
                            .get(span.start..span.end)
                            .ok_or_else(|| fault("doctest.text-capture-span-invalid"))?,
                    };
                    values.push(value);
                }
                observations.push(values.join("|"));
            }
            Ok(observations.join(","))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    output
}

fn build_regex(builder: PortableBuilder) -> Result<fre::PortableRegex, ExecutionRefusal> {
    builder
        .build()
        .map_err(|error| match error.failure_class() {
            fre::BuildFailureClass::InternalFailure => fault("doctest.build-internal-failure"),
            _ => unsupported("doctest.build-refused"),
        })
}

fn is_match(regex: &fre::PortableRegex, haystack: &[u8]) -> Result<bool, ExecutionRefusal> {
    regex
        .is_match(haystack, SearchLimits::unlimited())
        .map(|result| result.0)
        .map_err(|_| unsupported("doctest.search-refused"))
}

fn one_range(regex: &fre::PortableRegex, haystack: &[u8]) -> Result<String, ExecutionRefusal> {
    regex
        .find(haystack, SearchLimits::unlimited())
        .map_err(|_| unsupported("doctest.search-refused"))
        .map(|(matched, _)| {
            matched.map_or_else(
                || "_".to_owned(),
                |matched| format!("{}-{}", matched.start(), matched.end()),
            )
        })
}

fn all_ranges(regex: &fre::PortableRegex, haystack: &[u8]) -> Result<String, ExecutionRefusal> {
    let iterator = regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .map_err(|_| unsupported("doctest.iterator-setup-refused"))?;
    let mut ranges = Vec::new();
    for item in iterator {
        let span = item.map_err(|_| unsupported("doctest.iterator-refused"))?;
        ranges.push(format!("{}-{}", span.start(), span.end()));
    }
    Ok(ranges.join(","))
}

fn compare(expected: &[u8], observed: &[u8]) -> DoctestDisposition {
    let expected_sha256 = sha256(expected);
    let observed_sha256 = sha256(observed);
    if expected == observed {
        DoctestDisposition::Pass {
            expected_sha256,
            observed_sha256,
        }
    } else {
        DoctestDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code: "doctest.output-differs".to_owned(),
        }
    }
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

fn obligation_hash(obligations: &[Obligation]) -> Result<String, InventoryError> {
    let identities = obligations
        .iter()
        .map(|obligation| ObligationIdentity {
            case_id: &obligation.case_id,
            source_path: &obligation.source_path,
            source_sha256: &obligation.source_sha256,
            source_line: obligation.source_line,
            code_sha256: &obligation.code_sha256,
        })
        .collect::<Vec<_>>();
    hash_json(&identities)
}

fn obligation_hash_from_receipts(receipts: &[DoctestReceipt]) -> Result<String, InventoryError> {
    let identities = receipts
        .iter()
        .map(|receipt| ObligationIdentity {
            case_id: &receipt.case_id,
            source_path: &receipt.source_path,
            source_sha256: &receipt.source_sha256,
            source_line: receipt.source_line,
            code_sha256: &receipt.code_sha256,
        })
        .collect::<Vec<_>>();
    hash_json(&identities)
}

fn validate_source_identity(source: &DoctestSourceIdentity) -> Result<(), InventoryError> {
    if source.repository != UPSTREAM_REPOSITORY
        || source.package != UPSTREAM_PACKAGE
        || source.version != UPSTREAM_VERSION
        || source.revision != UPSTREAM_REVISION
        || source.package_sha256 != UPSTREAM_PACKAGE_SHA256
        || source.vcs_info_path != VCS_INFO_PATH
        || source.vcs_info_sha256 != VCS_INFO_SHA256
        || source.manifest_path != MANIFEST_PATH
        || source.manifest_sha256 != MANIFEST_SHA256
        || source.obligations != DOCTEST_API_CASES
        || !is_sha256(&source.obligation_inventory_sha256)
        || source.source_files.len() != SOURCES.len()
    {
        return Err(InventoryError::new("doctest source identity mismatch"));
    }
    if EXPECTED_OBLIGATION_INVENTORY_SHA256 != "pending"
        && source.obligation_inventory_sha256 != EXPECTED_OBLIGATION_INVENTORY_SHA256
    {
        return Err(InventoryError::new(
            "doctest source inventory digest mismatch",
        ));
    }
    for (actual, expected) in source.source_files.iter().zip(SOURCES) {
        if actual.path != expected.path
            || actual.sha256 != expected.sha256
            || actual.bytes != expected.bytes
            || actual.applicable_doctests != expected.expected_doctests
        {
            return Err(InventoryError::new("doctest source file identity mismatch"));
        }
    }
    Ok(())
}

fn source_sha(path: &str) -> Option<&'static str> {
    SOURCES
        .iter()
        .find(|source| source.path == path)
        .map(|source| source.sha256)
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !is_oid(&candidate.revision)
        || !is_oid(&candidate.tree)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new("doctest candidate identity is invalid"));
    }
    Ok(())
}

fn validate_disposition(
    capability: DoctestCapability,
    disposition: &DoctestDisposition,
) -> Result<(), InventoryError> {
    match disposition {
        DoctestDisposition::Pass {
            expected_sha256,
            observed_sha256,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 != observed_sha256
            {
                return Err(InventoryError::new("doctest pass digests are invalid"));
            }
        }
        DoctestDisposition::Mismatch {
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
                    "doctest mismatch disposition is invalid",
                ));
            }
        }
        DoctestDisposition::Unsupported {
            capability: disposition_capability,
            reason_code,
        } => {
            if *disposition_capability != capability || !valid_reason_code(reason_code) {
                return Err(InventoryError::new(
                    "doctest unsupported disposition is invalid",
                ));
            }
        }
        DoctestDisposition::Fault { reason_code } => {
            if !valid_reason_code(reason_code) {
                return Err(InventoryError::new("doctest fault disposition is invalid"));
            }
        }
    }
    Ok(())
}

fn hash_json<T: Serialize + ?Sized>(value: &T) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("encode canonical doctest JSON: {error}")))
}

const fn unsupported(reason_code: &'static str) -> ExecutionRefusal {
    ExecutionRefusal {
        fault: false,
        reason_code,
    }
}

const fn fault(reason_code: &'static str) -> ExecutionRefusal {
    ExecutionRefusal {
        fault: true,
        reason_code,
    }
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

    fn package_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("HOME"))
            .join(".cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regex-1.12.4")
    }

    fn candidate() -> CandidateIdentity {
        CandidateIdentity {
            revision: "1111111111111111111111111111111111111111".to_owned(),
            tree: "2222222222222222222222222222222222222222".to_owned(),
            tracked_and_untracked_worktree_clean: true,
        }
    }

    #[test]
    fn authenticates_and_enumerates_every_public_doctest() {
        let (source, obligations) = authenticate_source(&package_root()).unwrap();
        assert_eq!(DOCTEST_API_CASES, obligations.len());
        assert_eq!(DOCTEST_API_CASES, source.obligations);
        assert_eq!(
            DOCTEST_API_CASES,
            source
                .source_files
                .iter()
                .map(|source| source.applicable_doctests)
                .sum::<usize>()
        );
        assert_eq!(5, source.source_files[0].applicable_doctests);
        assert_eq!(56, source.source_files[1].applicable_doctests);
        assert_eq!(60, source.source_files[5].applicable_doctests);
        eprintln!(
            "doctest inventory sha256={}",
            source.obligation_inventory_sha256
        );
    }

    #[test]
    fn complete_report_has_one_disposition_per_obligation() {
        let report = build_doctest_report(&package_root(), candidate()).unwrap();
        eprintln!("doctest counts={:?}", report.payload.counts);
        assert_eq!(
            DoctestCounts {
                pass: 193,
                mismatch: 0,
                unsupported: 49,
                fault: 0,
                total: DOCTEST_API_CASES,
            },
            report.payload.counts
        );
        report.validate().unwrap();
    }

    #[test]
    fn every_adapted_example_matches_its_pinned_expectation() {
        let (_, obligations) = authenticate_source(&package_root()).unwrap();
        let mut mismatches = Vec::new();
        for obligation in obligations {
            if let Some(Ok((expected, observed))) = execute(&obligation)
                && expected != observed
            {
                mismatches.push(format!(
                    "{} expected={:?} observed={:?}",
                    obligation.case_id,
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&observed)
                ));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn validation_rejects_omission_and_source_substitution() {
        let mut report = build_doctest_report(&package_root(), candidate()).unwrap();
        report.payload.receipts.pop();
        report.payload.counts = DoctestCounts::from_receipts(&report.payload.receipts).unwrap();
        report.payload_sha256 = hash_json(&report.payload).unwrap();
        assert!(report.validate().is_err());

        let mut report = build_doctest_report(&package_root(), candidate()).unwrap();
        report.payload.receipts[0].source_sha256 = "0".repeat(64);
        report.payload_sha256 = hash_json(&report.payload).unwrap();
        assert!(report.validate().is_err());
    }
}
