//! Executable conformance for pinned upstream `misc` and regression API tests.

use std::{
    fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use fre::{
    BuildFailureClass, CaptureAggregateLimits, CaptureBuilder, PortableBuilder,
    PortableFindIterLimits, PortableTextBuilder, RustProfile, SearchLimits,
};
use serde::{Deserialize, Serialize};

use crate::{CandidateIdentity, InventoryError, UPSTREAM_REPOSITORY, UPSTREAM_REVISION, sha256};

/// Stable schema for the non-TOML misc/regression API report.
pub const MISC_REGRESSION_API_REPORT_SCHEMA: &str =
    "fre.upstream-rust-regex.misc-regression-api-report.v1";
/// Exact number of named tests in the three pinned upstream source files.
pub const MISC_REGRESSION_API_CASES: usize = 25;

const UPSTREAM_PACKAGE: &str = "regex";
const UPSTREAM_VERSION: &str = "1.12.4";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const VCS_INFO_PATH: &str = ".cargo_vcs_info.json";
const VCS_INFO_SHA256: &str = "985255199f0cbe66b15087ac718981b349db800d87b913da314e95d065ceb2f5";
const MANIFEST_PATH: &str = "Cargo.toml.orig";
const MANIFEST_SHA256: &str = "2fd5c1a0957af57186560cfb501eceaa7761bc612b26245be792284eee4763e0";
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 1_048_576;

const SOURCES: [SourceSpec; 3] = [
    SourceSpec {
        path: "tests/misc.rs",
        sha256: "1aeadbeb8860bd5f5b99a0adb459baf77dd3af4f23ac6c56ecf537f793407cca",
    },
    SourceSpec {
        path: "tests/regression.rs",
        sha256: "3490aac99fdbf3f0949ba1f338d5184a84b505ebd96d0b6d6145c610587aa60b",
    },
    SourceSpec {
        path: "tests/regression_fuzz.rs",
        sha256: "57e0bcba0fdfa7797865e35ae547cd7fe1c6132b80a7bfdfb06eb053a568b00d",
    },
];

/// Capability exercised by one upstream obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiscRegressionCapability {
    Constructor,
    PatternFormatting,
    CaptureMetadata,
    CaptureIndexing,
    CaptureExecution,
    Search,
    IgnoredExpensiveConstructor,
}

/// Mandatory result for one named upstream test. There is no skip state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum MiscRegressionDisposition {
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
        capability: MiscRegressionCapability,
        reason_code: String,
    },
    Fault {
        reason_code: String,
    },
}

/// One authenticated upstream source file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionSourceFile {
    pub path: String,
    pub sha256: String,
}

/// Authenticated identity of the packaged upstream source used by the run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub package_sha256: String,
    pub vcs_info_path: String,
    pub vcs_info_sha256: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub sources: Vec<MiscRegressionSourceFile>,
}

/// One mandatory, path-bound upstream obligation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionReceipt {
    pub case_id: String,
    pub source_path: String,
    pub source_sha256: String,
    pub capability: MiscRegressionCapability,
    pub disposition: MiscRegressionDisposition,
}

/// Complete result cardinalities for the 25-case suite.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`MiscRegressionReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionReportPayload {
    pub source: MiscRegressionSourceIdentity,
    pub candidate: CandidateIdentity,
    pub counts: MiscRegressionCounts,
    pub receipts: Vec<MiscRegressionReceipt>,
}

/// Immutable report for all pinned misc/regression obligations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiscRegressionReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: MiscRegressionReportPayload,
}

#[derive(Clone, Copy, Debug)]
struct SourceSpec {
    path: &'static str,
    sha256: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum CaseKind {
    Unsupported(&'static str),
    CaptureNames,
    CaptureRecord {
        pattern: &'static str,
        haystack: &'static [u8],
    },
    ValidConstructor(&'static str),
    InvalidConstructors(&'static [&'static str]),
    FindRanges {
        pattern: &'static str,
        haystack: &'static [u8],
    },
    IsMatch {
        pattern: &'static str,
        haystack: &'static [u8],
    },
    TextMatches {
        pattern: &'static str,
        negative: &'static str,
        positive: &'static str,
    },
}

#[derive(Clone, Copy, Debug)]
struct MiscRegressionCase {
    id: &'static str,
    source: usize,
    capability: MiscRegressionCapability,
    kind: CaseKind,
    expected: &'static [u8],
}

macro_rules! case {
    ($id:literal, $source:literal, $cap:ident, $kind:expr, $expected:literal) => {
        MiscRegressionCase {
            id: $id,
            source: $source,
            capability: MiscRegressionCapability::$cap,
            kind: $kind,
            expected: $expected,
        }
    };
}

const CASES: [MiscRegressionCase; MISC_REGRESSION_API_CASES] = [
    case!(
        "unclosed_group_error",
        0,
        Constructor,
        CaseKind::InvalidConstructors(&["("]),
        b"invalid"
    ),
    case!(
        "regex_string",
        0,
        PatternFormatting,
        CaseKind::Unsupported("misc.pattern-display-debug-unavailable"),
        b""
    ),
    case!(
        "capture_names",
        0,
        CaptureMetadata,
        CaseKind::CaptureNames,
        b"3|_,_,a"
    ),
    case!(
        "capture_index",
        0,
        CaptureIndexing,
        CaseKind::CaptureRecord {
            pattern: r"^(?P<name>.+)$",
            haystack: b"abc"
        },
        b"0:0-3:abc|1:0-3:abc"
    ),
    case!(
        "capture_index_panic_usize",
        0,
        CaptureIndexing,
        CaseKind::Unsupported("misc.capture-index-operator-unavailable"),
        b""
    ),
    case!(
        "capture_index_panic_name",
        0,
        CaptureIndexing,
        CaseKind::Unsupported("misc.capture-name-index-operator-unavailable"),
        b""
    ),
    case!(
        "capture_index_lifetime",
        0,
        CaptureIndexing,
        CaseKind::Unsupported("misc.capture-index-lifetime-surface-unavailable"),
        b""
    ),
    case!(
        "capture_misc",
        0,
        CaptureExecution,
        CaseKind::CaptureRecord {
            pattern: r"(.)(?P<a>a)?(.)(?P<b>.)",
            haystack: b"abc"
        },
        b"0:0-3:abc|1:0-1:a|2:_|3:1-2:b|4:2-3:c"
    ),
    case!(
        "sub_capture_matches",
        0,
        CaptureExecution,
        CaseKind::CaptureRecord {
            pattern: r"([a-z])(([a-z])|([0-9]))",
            haystack: b"a5"
        },
        b"0:0-2:a5|1:0-1:a|2:1-2:5|3:_|4:1-2:5"
    ),
    case!(
        "dfa_handles_pathological_case",
        0,
        Search,
        CaseKind::IsMatch {
            pattern: r"[01]*1[01]{20}$",
            haystack: b""
        },
        b"true"
    ),
    case!(
        "invalid_regexes_no_crash",
        1,
        Constructor,
        CaseKind::InvalidConstructors(&["(*)", "(?:?)", "(?)", "*"]),
        b"invalid"
    ),
    case!(
        "regression_many_repeat_stack_overflow",
        1,
        Search,
        CaseKind::FindRanges {
            pattern: r"^.{1,2500}",
            haystack: b"a"
        },
        b"0-1"
    ),
    case!(
        "regression_invalid_repetition_expr",
        1,
        Constructor,
        CaseKind::InvalidConstructors(&["(?m){1,1}"]),
        b"invalid"
    ),
    case!(
        "regression_invalid_flags_expression",
        1,
        Constructor,
        CaseKind::ValidConstructor("(((?x)))"),
        b"valid"
    ),
    case!(
        "regression_captures_rep",
        1,
        CaptureExecution,
        CaseKind::CaptureRecord {
            pattern: r"([a-f]){2}(?P<foo>[x-z])",
            haystack: b"abx"
        },
        b"0:0-3:abx|1:1-2:b|2:2-3:x"
    ),
    case!(
        "regression_nfa_stops1",
        1,
        Search,
        CaseKind::FindRanges {
            pattern: r"\bs(?:[ab])",
            haystack: b"s\xE4"
        },
        b""
    ),
    case!(
        "regression_bad_word_boundary",
        1,
        Search,
        CaseKind::TextMatches {
            pattern: r"(?i:(?:\b|_)win(?:32|64|dows)?(?:\b|_))",
            negative: "ubi-Darwin-x86_64.tar.gz",
            positive: "ubi-Windows-x86_64.zip"
        },
        b"false,true"
    ),
    case!(
        "regression_unicode_perl_not_enabled",
        1,
        Constructor,
        CaseKind::ValidConstructor(
            r"(\d+\s?(years|year|y))?\s?(\d+\s?(months|month|m))?\s?(\d+\s?(weeks|week|w))?\s?(\d+\s?(days|day|d))?\s?(\d+\s?(hours|hour|h))?"
        ),
        b"valid"
    ),
    case!(
        "regression_big_regex_overflow",
        1,
        Constructor,
        CaseKind::InvalidConstructors(&[r" {2147483516}{2147483416}{5}"]),
        b"invalid"
    ),
    case!(
        "regression_complete_literals_suffix_incorrect",
        1,
        Search,
        CaseKind::FindRanges {
            pattern: "aA|bA|cA|dA|eA|fA|gA|hA|iA|jA|kA|lA|mA|nA|oA|pA|qA|rA|sA|tA|uA|vA|wA|xA|yA|zA",
            haystack: b"FUBAR"
        },
        b""
    ),
    case!(
        "fuzz1",
        2,
        IgnoredExpensiveConstructor,
        CaseKind::Unsupported("regression-fuzz.ignored-expensive-not-executed"),
        b""
    ),
    case!(
        "empty_any_errors_no_panic",
        2,
        Constructor,
        CaseKind::ValidConstructor(r"\P{any}"),
        b"valid"
    ),
    case!(
        "big_regex_fails_to_compile",
        2,
        Constructor,
        CaseKind::InvalidConstructors(&["[\u{0}\u{e}\u{2}\\w~~>[l\t\u{0}]p?<]{971158}"]),
        b"invalid"
    ),
    case!(
        "todo",
        2,
        Constructor,
        CaseKind::ValidConstructor("(?:z|xx)@|xx"),
        b"valid"
    ),
    case!(
        "fail_branch_prevents_match",
        2,
        Search,
        CaseKind::IsMatch {
            pattern: r".*[a&&b]A|B",
            haystack: b"B"
        },
        b"true"
    ),
];

#[derive(Clone, Copy, Debug)]
struct ExecutionRefusal {
    fault: bool,
    reason_code: &'static str,
}

/// Authenticate exact packaged source and execute all mandatory obligations.
pub fn build_misc_regression_report(
    upstream_root: &Path,
    candidate: CandidateIdentity,
) -> Result<MiscRegressionReport, InventoryError> {
    let source = authenticate_source(upstream_root)?;
    validate_candidate(&candidate)?;
    let mut receipts = Vec::with_capacity(CASES.len());
    for case in CASES {
        let disposition = match catch_unwind(AssertUnwindSafe(|| execute_case(case))) {
            Ok(Ok(observed)) => compare(case.expected, &observed),
            Ok(Err(refusal)) if refusal.fault => MiscRegressionDisposition::Fault {
                reason_code: refusal.reason_code.to_owned(),
            },
            Ok(Err(refusal)) => MiscRegressionDisposition::Unsupported {
                capability: case.capability,
                reason_code: refusal.reason_code.to_owned(),
            },
            Err(_) => MiscRegressionDisposition::Fault {
                reason_code: "misc-regression.adapter-panic".to_owned(),
            },
        };
        let source = SOURCES[case.source];
        receipts.push(MiscRegressionReceipt {
            case_id: case.id.to_owned(),
            source_path: source.path.to_owned(),
            source_sha256: source.sha256.to_owned(),
            capability: case.capability,
            disposition,
        });
    }
    let counts = MiscRegressionCounts::from_receipts(&receipts)?;
    let payload = MiscRegressionReportPayload {
        source,
        candidate,
        counts,
        receipts,
    };
    let payload_sha256 = sha256(&serde_json::to_vec(&payload).map_err(|error| {
        InventoryError::new(format!("encode misc/regression report payload: {error}"))
    })?);
    let report = MiscRegressionReport {
        schema: MISC_REGRESSION_API_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate an existing misc/regression report.
pub fn read_misc_regression_report(path: &Path) -> Result<MiscRegressionReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read misc/regression report {}: {error}",
            path.display()
        ))
    })?;
    let report: MiscRegressionReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode misc/regression report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON.
pub fn write_misc_regression_report(
    path: &Path,
    report: &MiscRegressionReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode misc/regression report: {error}")))?;
    bytes.push(b'\n');
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "misc/regression report has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!(
                "invalid misc/regression report name: {}",
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

impl MiscRegressionReport {
    /// Validate source/candidate identity, payload hash, ordering and counts.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != MISC_REGRESSION_API_REPORT_SCHEMA {
            return Err(InventoryError::new(
                "misc/regression report schema mismatch",
            ));
        }
        let expected_payload_hash =
            sha256(&serde_json::to_vec(&self.payload).map_err(|error| {
                InventoryError::new(format!("encode misc/regression report payload: {error}"))
            })?);
        if self.payload_sha256 != expected_payload_hash {
            return Err(InventoryError::new(
                "misc/regression payload SHA-256 mismatch",
            ));
        }
        if self.payload.source != expected_source_identity() {
            return Err(InventoryError::new(
                "misc/regression source identity mismatch",
            ));
        }
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != CASES.len() {
            return Err(InventoryError::new(
                "misc/regression receipt count mismatch",
            ));
        }
        for (case, receipt) in CASES.iter().zip(&self.payload.receipts) {
            let source = SOURCES[case.source];
            if receipt.case_id != case.id
                || receipt.source_path != source.path
                || receipt.source_sha256 != source.sha256
                || receipt.capability != case.capability
            {
                return Err(InventoryError::new(format!(
                    "misc/regression obligation mismatch for {}",
                    case.id
                )));
            }
            validate_disposition(&receipt.disposition)?;
        }
        let counts = MiscRegressionCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts || counts.total != MISC_REGRESSION_API_CASES {
            return Err(InventoryError::new(
                "misc/regression disposition count mismatch",
            ));
        }
        Ok(())
    }
}

impl MiscRegressionCounts {
    fn from_receipts(receipts: &[MiscRegressionReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                MiscRegressionDisposition::Pass { .. } => &mut counts.pass,
                MiscRegressionDisposition::Mismatch { .. } => &mut counts.mismatch,
                MiscRegressionDisposition::Unsupported { .. } => &mut counts.unsupported,
                MiscRegressionDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("misc/regression count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("misc/regression total overflow"))?;
        }
        Ok(counts)
    }
}

fn execute_case(case: MiscRegressionCase) -> Result<Vec<u8>, ExecutionRefusal> {
    match case.kind {
        CaseKind::Unsupported(reason_code) => Err(unsupported(reason_code)),
        CaseKind::CaptureNames => execute_capture_names(),
        CaseKind::CaptureRecord { pattern, haystack } => execute_capture_record(pattern, haystack),
        CaseKind::ValidConstructor(pattern) => execute_valid_constructor(pattern),
        CaseKind::InvalidConstructors(patterns) => execute_invalid_constructors(patterns),
        CaseKind::FindRanges { pattern, haystack } => execute_find_ranges(pattern, haystack),
        CaseKind::IsMatch { pattern, haystack } => execute_is_match(pattern, haystack),
        CaseKind::TextMatches {
            pattern,
            negative,
            positive,
        } => execute_text_matches(pattern, negative, positive),
    }
}

fn execute_capture_names() -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = PortableBuilder::new(r"(.)(?P<a>.)")
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|error| build_refusal(&error))?;
    let names = regex
        .capture_names()
        .map(|name| name.unwrap_or("_"))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("{}|{names}", regex.captures_len()).into_bytes())
}

fn execute_capture_record(pattern: &str, haystack: &[u8]) -> Result<Vec<u8>, ExecutionRefusal> {
    let report = CaptureBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| unsupported("misc-regression.capture-build-refused"))?
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .map_err(|_| unsupported("misc-regression.capture-execution-refused"))?;
    let record = report
        .captures
        .first()
        .ok_or_else(|| fault("misc-regression.capture-record-missing"))?;
    let mut fields = Vec::with_capacity(record.groups.len());
    for (expected_index, group) in record.groups.iter().enumerate() {
        let actual_index = usize::try_from(group.index)
            .map_err(|_| fault("misc-regression.capture-index-invalid"))?;
        if actual_index != expected_index {
            return Err(fault("misc-regression.capture-order-invalid"));
        }
        let value = match group.span {
            None => format!("{actual_index}:_"),
            Some(span) => {
                let bytes = haystack
                    .get(span.start..span.end)
                    .ok_or_else(|| fault("misc-regression.capture-span-invalid"))?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| fault("misc-regression.capture-text-invalid"))?;
                format!("{actual_index}:{}-{}:{text}", span.start, span.end)
            }
        };
        fields.push(value);
    }
    Ok(fields.join("|").into_bytes())
}

fn execute_valid_constructor(pattern: &str) -> Result<Vec<u8>, ExecutionRefusal> {
    PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|error| build_refusal(&error))?;
    Ok(b"valid".to_vec())
}

fn execute_invalid_constructors(patterns: &[&str]) -> Result<Vec<u8>, ExecutionRefusal> {
    for pattern in patterns {
        match PortableBuilder::new(*pattern)
            .profile(RustProfile::regex_1_12_4())
            .build()
        {
            Ok(_) => return Ok(b"valid".to_vec()),
            Err(error)
                if matches!(
                    error.failure_class(),
                    BuildFailureClass::ExpectedInvalid | BuildFailureClass::ResourceLimit
                ) => {}
            Err(error) if error.failure_class() == BuildFailureClass::InternalFailure => {
                return Err(fault("misc-regression.constructor-internal-failure"));
            }
            Err(_) => {
                return Err(unsupported(
                    "misc-regression.constructor-refusal-unclassified",
                ));
            }
        }
    }
    Ok(b"invalid".to_vec())
}

fn execute_find_ranges(pattern: &str, haystack: &[u8]) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|error| build_refusal(&error))?;
    let mut ranges = Vec::new();
    for matched in regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .map_err(|_| unsupported("misc-regression.iterator-construction-refused"))?
    {
        let matched = matched.map_err(|_| unsupported("misc-regression.iterator-refused"))?;
        ranges.push(format!("{}-{}", matched.start(), matched.end()));
    }
    Ok(ranges.join(",").into_bytes())
}

fn execute_is_match(pattern: &str, haystack: &[u8]) -> Result<Vec<u8>, ExecutionRefusal> {
    let actual_haystack;
    let haystack = if pattern == r"[01]*1[01]{20}$" && haystack.is_empty() {
        let mut text = String::with_capacity(100_021);
        for index in 0..100_000 {
            text.push(if index % 3 == 0 { '1' } else { '0' });
        }
        text.push('1');
        for index in 0..20 {
            text.push(if index % 3 == 0 { '1' } else { '0' });
        }
        actual_haystack = text.into_bytes();
        actual_haystack.as_slice()
    } else {
        haystack
    };
    let regex = PortableBuilder::new(pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|error| build_refusal(&error))?;
    let matched = regex
        .is_match(haystack, SearchLimits::unlimited())
        .map_err(|_| unsupported("misc-regression.search-refused"))?
        .0;
    Ok(matched.to_string().into_bytes())
}

fn execute_text_matches(
    pattern: &str,
    negative: &str,
    positive: &str,
) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = PortableTextBuilder::new(pattern)
        .build()
        .map_err(|_| unsupported("misc-regression.text-build-refused"))?;
    let negative = regex
        .is_match(negative, SearchLimits::unlimited())
        .map_err(|_| unsupported("misc-regression.text-search-refused"))?
        .0;
    let positive = regex
        .is_match(positive, SearchLimits::unlimited())
        .map_err(|_| unsupported("misc-regression.text-search-refused"))?
        .0;
    Ok(format!("{negative},{positive}").into_bytes())
}

fn build_refusal(error: &fre::BuildError) -> ExecutionRefusal {
    if error.failure_class() == BuildFailureClass::InternalFailure {
        fault("misc-regression.build-internal-failure")
    } else {
        unsupported("misc-regression.build-refused")
    }
}

fn compare(expected: &[u8], observed: &[u8]) -> MiscRegressionDisposition {
    let expected_sha256 = sha256(expected);
    let observed_sha256 = sha256(observed);
    if expected == observed {
        MiscRegressionDisposition::Pass {
            expected_sha256,
            observed_sha256,
        }
    } else {
        MiscRegressionDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code: "misc-regression.output-differs".to_owned(),
        }
    }
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

fn authenticate_source(root: &Path) -> Result<MiscRegressionSourceIdentity, InventoryError> {
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
    for source in SOURCES {
        let _ = read_authenticated_file(root, source.path, source.sha256)?;
    }
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

fn expected_source_identity() -> MiscRegressionSourceIdentity {
    MiscRegressionSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        revision: UPSTREAM_REVISION.to_owned(),
        package_sha256: UPSTREAM_PACKAGE_SHA256.to_owned(),
        vcs_info_path: VCS_INFO_PATH.to_owned(),
        vcs_info_sha256: VCS_INFO_SHA256.to_owned(),
        manifest_path: MANIFEST_PATH.to_owned(),
        manifest_sha256: MANIFEST_SHA256.to_owned(),
        sources: SOURCES
            .iter()
            .map(|source| MiscRegressionSourceFile {
                path: source.path.to_owned(),
                sha256: source.sha256.to_owned(),
            })
            .collect(),
    }
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !is_oid(&candidate.revision)
        || !is_oid(&candidate.tree)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "misc/regression candidate identity is invalid",
        ));
    }
    Ok(())
}

fn validate_disposition(disposition: &MiscRegressionDisposition) -> Result<(), InventoryError> {
    match disposition {
        MiscRegressionDisposition::Pass {
            expected_sha256,
            observed_sha256,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 != observed_sha256
            {
                return Err(InventoryError::new(
                    "misc/regression pass digests are invalid",
                ));
            }
        }
        MiscRegressionDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 == observed_sha256
                || !valid_reason_code(reason_code)
            {
                return Err(InventoryError::new("misc/regression mismatch is invalid"));
            }
        }
        MiscRegressionDisposition::Unsupported { reason_code, .. }
        | MiscRegressionDisposition::Fault { reason_code } => {
            if !valid_reason_code(reason_code) {
                return Err(InventoryError::new(
                    "misc/regression reason code is invalid",
                ));
            }
        }
    }
    Ok(())
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

    #[test]
    fn every_named_obligation_has_exactly_one_disposition() {
        let source = expected_source_identity();
        let mut receipts = Vec::new();
        for case in CASES {
            let disposition = match execute_case(case) {
                Ok(observed) => compare(case.expected, &observed),
                Err(refusal) if refusal.fault => MiscRegressionDisposition::Fault {
                    reason_code: refusal.reason_code.to_owned(),
                },
                Err(refusal) => MiscRegressionDisposition::Unsupported {
                    capability: case.capability,
                    reason_code: refusal.reason_code.to_owned(),
                },
            };
            let source = SOURCES[case.source];
            receipts.push(MiscRegressionReceipt {
                case_id: case.id.to_owned(),
                source_path: source.path.to_owned(),
                source_sha256: source.sha256.to_owned(),
                capability: case.capability,
                disposition,
            });
        }
        let counts = MiscRegressionCounts::from_receipts(&receipts).unwrap();
        assert_eq!(counts.pass, 20);
        assert_eq!(counts.total, MISC_REGRESSION_API_CASES);
        assert_eq!(counts.mismatch, 0);
        assert_eq!(counts.unsupported, 5);
        assert_eq!(counts.fault, 0);
        let payload = MiscRegressionReportPayload {
            source,
            candidate: candidate(),
            counts,
            receipts,
        };
        let report = MiscRegressionReport {
            schema: MISC_REGRESSION_API_REPORT_SCHEMA.to_owned(),
            payload_sha256: sha256(&serde_json::to_vec(&payload).unwrap()),
            payload,
        };
        report.validate().unwrap();
    }

    #[test]
    fn report_validation_rejects_omission_and_source_substitution() {
        let dispositions = CASES
            .iter()
            .map(|case| MiscRegressionReceipt {
                case_id: case.id.to_owned(),
                source_path: SOURCES[case.source].path.to_owned(),
                source_sha256: SOURCES[case.source].sha256.to_owned(),
                capability: case.capability,
                disposition: MiscRegressionDisposition::Unsupported {
                    capability: case.capability,
                    reason_code: "test.unsupported".to_owned(),
                },
            })
            .collect::<Vec<_>>();
        let make_report = |receipts: Vec<MiscRegressionReceipt>| {
            let counts = MiscRegressionCounts::from_receipts(&receipts).unwrap();
            let payload = MiscRegressionReportPayload {
                source: expected_source_identity(),
                candidate: candidate(),
                counts,
                receipts,
            };
            MiscRegressionReport {
                schema: MISC_REGRESSION_API_REPORT_SCHEMA.to_owned(),
                payload_sha256: sha256(&serde_json::to_vec(&payload).unwrap()),
                payload,
            }
        };
        let mut omitted = dispositions.clone();
        omitted.pop();
        assert!(make_report(omitted).validate().is_err());
        let mut substituted = dispositions;
        substituted[0].source_sha256 = "0".repeat(64);
        assert!(make_report(substituted).validate().is_err());
    }
}
