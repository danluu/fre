//! Executable conformance for the pinned upstream replacement API tests.

use std::{
    borrow::Cow,
    fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use fre::{
    AggregateBuilder, CaptureAggregateLimits, CaptureBuilder, CaptureExpansionLimits,
    LiteralReplacementLimits, PortableBuilder, RustProfile,
};
use serde::{Deserialize, Serialize};

use crate::{CandidateIdentity, InventoryError, UPSTREAM_REPOSITORY, UPSTREAM_REVISION, sha256};

/// Stable schema for the non-TOML replacement API report.
pub const REPLACEMENT_API_REPORT_SCHEMA: &str = "fre.upstream-rust-regex.replacement-api-report.v1";
/// Exact number of named tests in upstream `tests/replace.rs` at the pin.
pub const REPLACEMENT_API_CASES: usize = 26;

const UPSTREAM_PACKAGE: &str = "regex";
const UPSTREAM_VERSION: &str = "1.12.4";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const VCS_INFO_PATH: &str = ".cargo_vcs_info.json";
const VCS_INFO_SHA256: &str = "985255199f0cbe66b15087ac718981b349db800d87b913da314e95d065ceb2f5";
const MANIFEST_PATH: &str = "Cargo.toml.orig";
const MANIFEST_SHA256: &str = "2fd5c1a0957af57186560cfb501eceaa7761bc612b26245be792284eee4763e0";
const SOURCE_PATH: &str = "tests/replace.rs";
const SOURCE_SHA256: &str = "78ff9bf7f78783ad83a78041bb7ee0705c7efc85b4d12301581d0ce5b2a59325";
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 1_048_576;

/// Capability exercised by one upstream replacement obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplacementCapability {
    /// Fixed replacement bytes, including upstream's `NoExpand` wrapper.
    LiteralOrNoExpand,
    /// `$` capture interpolation over materialized FRE capture records.
    CaptureExpansion,
    /// Replacement produced once per selected match by a callback.
    FunctionalReplacer,
    /// Standard owned, borrowed and `Cow<str>` replacement containers.
    ReplacerTypeSurface,
}

/// Mandatory result for one named upstream API test. There is no skip state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum ReplacementApiDisposition {
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
        capability: ReplacementCapability,
        reason_code: String,
    },
    Fault {
        reason_code: String,
    },
}

/// Authenticated identity of the packaged upstream source used by the run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementSourceIdentity {
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

/// One mandatory, path-bound upstream replacement receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementApiReceipt {
    pub case_id: String,
    pub source_path: String,
    pub source_sha256: String,
    pub capability: ReplacementCapability,
    pub disposition: ReplacementApiDisposition,
}

/// Complete result cardinalities for the 26-case replacement suite.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementApiCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`ReplacementApiReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementApiReportPayload {
    pub source: ReplacementSourceIdentity,
    pub candidate: CandidateIdentity,
    pub counts: ReplacementApiCounts,
    pub receipts: Vec<ReplacementApiReceipt>,
}

/// Immutable report for every pinned replacement API obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementApiReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: ReplacementApiReportPayload,
}

#[derive(Clone, Copy, Debug)]
enum ReplaceMode {
    First,
    All,
    N(usize),
}

#[derive(Clone, Copy, Debug)]
enum CaseKind {
    Literal,
    CaptureExpansion,
    FunctionalFirstByte,
    FunctionalConstant,
    TypeSurface(u8),
}

#[derive(Clone, Copy, Debug)]
struct ReplacementCase {
    id: &'static str,
    capability: ReplacementCapability,
    kind: CaseKind,
    mode: ReplaceMode,
    pattern: &'static str,
    haystack: &'static [u8],
    replacement: &'static [u8],
    expected: &'static [u8],
}

macro_rules! case {
    ($id:literal, $cap:ident, $kind:expr, $mode:expr, $pattern:literal,
     $haystack:literal, $replacement:literal, $expected:literal) => {
        ReplacementCase {
            id: $id,
            capability: ReplacementCapability::$cap,
            kind: $kind,
            mode: $mode,
            pattern: $pattern,
            haystack: $haystack,
            replacement: $replacement,
            expected: $expected,
        }
    };
}

const CASES: [ReplacementCase; REPLACEMENT_API_CASES] = [
    case!(
        "first",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "plus",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::First,
        r"[0-9]+",
        b"age: 26",
        b"Z",
        b"age: Z"
    ),
    case!(
        "all",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::All,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: ZZ"
    ),
    case!(
        "groups",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::First,
        r"([^ ]+)[ ]+([^ ]+)",
        b"w1 w2",
        b"$2 $1",
        b"w2 w1"
    ),
    case!(
        "double_dollar",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::First,
        r"([^ ]+)[ ]+([^ ]+)",
        b"w1 w2",
        b"$2 $$1",
        b"w2 $1"
    ),
    case!(
        "named",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::All,
        r"(?P<first>[^ ]+)[ ]+(?P<last>[^ ]+)(?P<space>[ ]*)",
        b"w1 w2 w3 w4",
        b"$last $first$space",
        b"w2 w1 w4 w3"
    ),
    case!(
        "trim",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::All,
        "^[ \t]+|[ \t]+$",
        b" \t  trim me\t   \t",
        b"",
        b"trim me"
    ),
    case!(
        "number_hyphen",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::First,
        r"(.)(.)",
        b"ab",
        b"$1-$2",
        b"a-b"
    ),
    case!(
        "simple_expand",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::All,
        r"([a-z]) ([a-z])",
        b"a b",
        b"$2 $1",
        b"b a"
    ),
    case!(
        "literal_dollar1",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::All,
        r"([a-z]+) ([a-z]+)",
        b"a b",
        b"$$1",
        b"$1"
    ),
    case!(
        "literal_dollar2",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::All,
        r"([a-z]+) ([a-z]+)",
        b"a b",
        b"$2 $$c $1",
        b"b $c a"
    ),
    case!(
        "no_expand1",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::First,
        r"([^ ]+)[ ]+([^ ]+)",
        b"w1 w2",
        b"$2 $1",
        b"$2 $1"
    ),
    case!(
        "no_expand2",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::First,
        r"([^ ]+)[ ]+([^ ]+)",
        b"w1 w2",
        b"$$1",
        b"$$1"
    ),
    case!(
        "closure_returning_reference",
        FunctionalReplacer,
        CaseKind::FunctionalFirstByte,
        ReplaceMode::First,
        r"([0-9]+)",
        b"age: 26",
        b"",
        b"age: 2"
    ),
    case!(
        "closure_returning_value",
        FunctionalReplacer,
        CaseKind::FunctionalConstant,
        ReplaceMode::First,
        r"[0-9]+",
        b"age: 26",
        b"Z",
        b"age: Z"
    ),
    case!(
        "match_at_start_replace_with_empty",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::All,
        r"foo",
        b"foobar",
        b"",
        b"bar"
    ),
    case!(
        "single_empty_match",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::First,
        r"^",
        b"bar",
        b"foo",
        b"foobar"
    ),
    case!(
        "capture_longest_possible_name",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::All,
        r"(.)",
        b"b",
        b"${1}a $1a",
        b"ba "
    ),
    case!(
        "impl_string",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(0),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "impl_string_ref",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(1),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "impl_cow_str_borrowed",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(2),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "impl_cow_str_borrowed_ref",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(3),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "impl_cow_str_owned",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(4),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "impl_cow_str_owned_ref",
        ReplacerTypeSurface,
        CaseKind::TypeSurface(5),
        ReplaceMode::First,
        r"[0-9]",
        b"age: 26",
        b"Z",
        b"age: Z6"
    ),
    case!(
        "replacen_no_captures",
        LiteralOrNoExpand,
        CaseKind::Literal,
        ReplaceMode::N(2),
        r"[0-9]",
        b"age: 1234",
        b"Z",
        b"age: ZZ34"
    ),
    case!(
        "replacen_with_captures",
        CaptureExpansion,
        CaseKind::CaptureExpansion,
        ReplaceMode::N(2),
        r"([0-9])",
        b"age: 1234",
        b"${1}Z",
        b"age: 1Z2Z34"
    ),
];

#[derive(Clone, Copy, Debug)]
struct ExecutionRefusal {
    fault: bool,
    reason_code: &'static str,
}

/// Authenticate the exact packaged upstream source and execute all 26 cases.
pub fn build_replacement_api_report(
    upstream_root: &Path,
    candidate: CandidateIdentity,
) -> Result<ReplacementApiReport, InventoryError> {
    let source = authenticate_source(upstream_root)?;
    validate_candidate(&candidate)?;
    let mut receipts = Vec::with_capacity(CASES.len());
    for case in CASES {
        let disposition = match catch_unwind(AssertUnwindSafe(|| execute_case(case))) {
            Ok(Ok(observed)) => compare(case.expected, &observed),
            Ok(Err(refusal)) if refusal.fault => ReplacementApiDisposition::Fault {
                reason_code: refusal.reason_code.to_owned(),
            },
            Ok(Err(refusal)) => ReplacementApiDisposition::Unsupported {
                capability: case.capability,
                reason_code: refusal.reason_code.to_owned(),
            },
            Err(_) => ReplacementApiDisposition::Fault {
                reason_code: "replacement.adapter-panic".to_owned(),
            },
        };
        receipts.push(ReplacementApiReceipt {
            case_id: case.id.to_owned(),
            source_path: SOURCE_PATH.to_owned(),
            source_sha256: SOURCE_SHA256.to_owned(),
            capability: case.capability,
            disposition,
        });
    }
    let counts = ReplacementApiCounts::from_receipts(&receipts)?;
    let payload = ReplacementApiReportPayload {
        source,
        candidate,
        counts,
        receipts,
    };
    let payload_sha256 = sha256(&serde_json::to_vec(&payload).map_err(|error| {
        InventoryError::new(format!("encode replacement API report payload: {error}"))
    })?);
    let report = ReplacementApiReport {
        schema: REPLACEMENT_API_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate a replacement API report.
pub fn read_replacement_api_report(path: &Path) -> Result<ReplacementApiReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read replacement API report {}: {error}",
            path.display()
        ))
    })?;
    let report: ReplacementApiReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode replacement API report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON for one authenticated API report.
pub fn write_replacement_api_report(
    path: &Path,
    report: &ReplacementApiReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode replacement API report: {error}")))?;
    bytes.push(b'\n');
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "replacement API report output has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!(
                "invalid replacement API report name: {}",
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

impl ReplacementApiReport {
    /// Validate source/candidate identity, payload hash, ordering and counts.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != REPLACEMENT_API_REPORT_SCHEMA {
            return Err(InventoryError::new(
                "replacement API report schema mismatch",
            ));
        }
        let expected_payload_hash =
            sha256(&serde_json::to_vec(&self.payload).map_err(|error| {
                InventoryError::new(format!("encode replacement API report payload: {error}"))
            })?);
        if self.payload_sha256 != expected_payload_hash {
            return Err(InventoryError::new(
                "replacement API report payload SHA-256 mismatch",
            ));
        }
        if self.payload.source != expected_source_identity() {
            return Err(InventoryError::new(
                "replacement API source identity mismatch",
            ));
        }
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != CASES.len() {
            return Err(InventoryError::new(
                "replacement API receipt count mismatch",
            ));
        }
        for (case, receipt) in CASES.iter().zip(&self.payload.receipts) {
            if receipt.case_id != case.id
                || receipt.source_path != SOURCE_PATH
                || receipt.source_sha256 != SOURCE_SHA256
                || receipt.capability != case.capability
            {
                return Err(InventoryError::new(format!(
                    "replacement API obligation mismatch for {}",
                    case.id
                )));
            }
            validate_disposition(&receipt.disposition)?;
        }
        let counts = ReplacementApiCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts || counts.total != REPLACEMENT_API_CASES {
            return Err(InventoryError::new(
                "replacement API disposition count mismatch",
            ));
        }
        Ok(())
    }
}

impl ReplacementApiCounts {
    fn from_receipts(receipts: &[ReplacementApiReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                ReplacementApiDisposition::Pass { .. } => &mut counts.pass,
                ReplacementApiDisposition::Mismatch { .. } => &mut counts.mismatch,
                ReplacementApiDisposition::Unsupported { .. } => &mut counts.unsupported,
                ReplacementApiDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("replacement API count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("replacement API total overflow"))?;
        }
        Ok(counts)
    }
}

fn execute_case(case: ReplacementCase) -> Result<Vec<u8>, ExecutionRefusal> {
    match case.kind {
        CaseKind::Literal => execute_literal(case),
        CaseKind::CaptureExpansion => execute_capture_expansion(case),
        CaseKind::FunctionalFirstByte => execute_functional_first_byte(case),
        CaseKind::FunctionalConstant => execute_functional_constant(case),
        CaseKind::TypeSurface(surface) => execute_type_surface(case, surface),
    }
}

fn execute_literal(case: ReplacementCase) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = AggregateBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("replacement.selector-build-refused"))?;
    let result = match case.mode {
        ReplaceMode::First => regex.replace_literal(
            case.haystack,
            case.replacement,
            LiteralReplacementLimits::default(),
        ),
        ReplaceMode::All => regex.replace_all_literal(
            case.haystack,
            case.replacement,
            LiteralReplacementLimits::default(),
        ),
        ReplaceMode::N(limit) => regex.replacen_literal(
            case.haystack,
            limit,
            case.replacement,
            LiteralReplacementLimits::default(),
        ),
    }
    .map_err(|_| unsupported("replacement.literal-execution-refused"))?;
    Ok(result.into_bytes())
}

fn execute_capture_expansion(case: ReplacementCase) -> Result<Vec<u8>, ExecutionRefusal> {
    let captures = CaptureBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| unsupported("replacement.capture-build-refused"))?
        .captures_iter(case.haystack, CaptureAggregateLimits::default())
        .map_err(|_| unsupported("replacement.capture-execution-refused"))?;
    let template_regex = PortableBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build()
        .map_err(|_| unsupported("replacement.expander-build-refused"))?;
    let limit = match case.mode {
        ReplaceMode::First => 1,
        ReplaceMode::All => usize::MAX,
        ReplaceMode::N(limit) => limit,
    };
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    for record in captures.captures.iter().take(limit) {
        let overall = record
            .overall()
            .ok_or_else(|| fault("replacement.capture-overall-missing"))?;
        if overall.start < cursor
            || overall.end < overall.start
            || overall.end > case.haystack.len()
        {
            return Err(fault("replacement.capture-span-invalid"));
        }
        output.extend_from_slice(&case.haystack[cursor..overall.start]);
        let values = record
            .groups
            .iter()
            .enumerate()
            .map(|(expected_index, group)| {
                let actual_index = usize::try_from(group.index)
                    .map_err(|_| fault("replacement.capture-index-invalid"))?;
                if actual_index != expected_index {
                    return Err(fault("replacement.capture-order-invalid"));
                }
                group
                    .span
                    .map(|span| {
                        case.haystack
                            .get(span.start..span.end)
                            .ok_or_else(|| fault("replacement.capture-span-invalid"))
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expansion = template_regex
            .expand_capture_template(&values, case.replacement, CaptureExpansionLimits::default())
            .map_err(|_| unsupported("replacement.capture-expansion-refused"))?;
        output.extend_from_slice(expansion.as_bytes());
        cursor = overall.end;
    }
    output.extend_from_slice(
        case.haystack
            .get(cursor..)
            .ok_or_else(|| fault("replacement.capture-tail-invalid"))?,
    );
    Ok(output)
}

fn execute_functional_first_byte(case: ReplacementCase) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = AggregateBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("replacement.selector-build-refused"))?;
    let result = regex
        .replace_with_match(
            case.haystack,
            |matched, haystack| {
                haystack
                    .get(matched.start()..matched.start().saturating_add(1))
                    .unwrap_or_default()
            },
            LiteralReplacementLimits::default(),
        )
        .map_err(|_| unsupported("replacement.functional-execution-refused"))?;
    Ok(result.into_bytes())
}

fn execute_functional_constant(case: ReplacementCase) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = AggregateBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("replacement.selector-build-refused"))?;
    let result = regex
        .replace_with_match(
            case.haystack,
            |_, _| case.replacement,
            LiteralReplacementLimits::default(),
        )
        .map_err(|_| unsupported("replacement.functional-execution-refused"))?;
    Ok(result.into_bytes())
}

fn execute_type_surface(case: ReplacementCase, surface: u8) -> Result<Vec<u8>, ExecutionRefusal> {
    let regex = AggregateBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .build_spans()
        .map_err(|_| unsupported("replacement.selector-build-refused"))?;
    let replacement = std::str::from_utf8(case.replacement)
        .map_err(|_| fault("replacement.type-surface-non-utf8"))?;
    let limits = LiteralReplacementLimits::default();
    let result = match surface {
        0 => regex.replace_literal(case.haystack, replacement.to_owned(), limits),
        1 => {
            let owned = replacement.to_owned();
            regex.replace_literal(case.haystack, &owned, limits)
        }
        2 => regex.replace_literal(case.haystack, Cow::Borrowed(replacement), limits),
        3 => {
            let borrowed = Cow::Borrowed(replacement);
            regex.replace_literal(case.haystack, &borrowed, limits)
        }
        4 => regex.replace_literal(
            case.haystack,
            Cow::<'_, str>::Owned(replacement.to_owned()),
            limits,
        ),
        5 => {
            let owned = Cow::<'_, str>::Owned(replacement.to_owned());
            regex.replace_literal(case.haystack, &owned, limits)
        }
        _ => return Err(fault("replacement.type-surface-invalid")),
    }
    .map_err(|_| unsupported("replacement.type-surface-execution-refused"))?;
    Ok(result.into_bytes())
}

fn compare(expected: &[u8], observed: &[u8]) -> ReplacementApiDisposition {
    let expected_sha256 = sha256(expected);
    let observed_sha256 = sha256(observed);
    if expected == observed {
        ReplacementApiDisposition::Pass {
            expected_sha256,
            observed_sha256,
        }
    } else {
        ReplacementApiDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code: "replacement.output-differs".to_owned(),
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

fn authenticate_source(root: &Path) -> Result<ReplacementSourceIdentity, InventoryError> {
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

fn expected_source_identity() -> ReplacementSourceIdentity {
    ReplacementSourceIdentity {
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
            "replacement API candidate identity is invalid",
        ));
    }
    Ok(())
}

fn validate_disposition(disposition: &ReplacementApiDisposition) -> Result<(), InventoryError> {
    match disposition {
        ReplacementApiDisposition::Pass {
            expected_sha256,
            observed_sha256,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 != observed_sha256
            {
                return Err(InventoryError::new(
                    "replacement API pass digests are invalid or unequal",
                ));
            }
        }
        ReplacementApiDisposition::Mismatch {
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
                    "replacement API mismatch disposition is invalid",
                ));
            }
        }
        ReplacementApiDisposition::Unsupported { reason_code, .. }
        | ReplacementApiDisposition::Fault { reason_code } => {
            if !valid_reason_code(reason_code) {
                return Err(InventoryError::new(
                    "replacement API reason code is invalid",
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
    fn every_replacement_obligation_executes_and_passes() {
        assert_eq!(CASES.len(), REPLACEMENT_API_CASES);
        let mut ids = CASES.iter().map(|case| case.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), REPLACEMENT_API_CASES);

        let receipts = CASES
            .into_iter()
            .map(|case| {
                let observed =
                    execute_case(case).unwrap_or_else(|error| panic!("{}: {error:?}", case.id));
                ReplacementApiReceipt {
                    case_id: case.id.to_owned(),
                    source_path: SOURCE_PATH.to_owned(),
                    source_sha256: SOURCE_SHA256.to_owned(),
                    capability: case.capability,
                    disposition: compare(case.expected, &observed),
                }
            })
            .collect::<Vec<_>>();
        let counts = ReplacementApiCounts::from_receipts(&receipts).unwrap();
        assert_eq!(counts.pass, REPLACEMENT_API_CASES);
        assert_eq!(counts.mismatch, 0);
        assert_eq!(counts.unsupported, 0);
        assert_eq!(counts.fault, 0);
        assert_eq!(counts.total, REPLACEMENT_API_CASES);

        let payload = ReplacementApiReportPayload {
            source: expected_source_identity(),
            candidate: candidate(),
            counts,
            receipts,
        };
        let report = ReplacementApiReport {
            schema: REPLACEMENT_API_REPORT_SCHEMA.to_owned(),
            payload_sha256: sha256(&serde_json::to_vec(&payload).unwrap()),
            payload,
        };
        report.validate().unwrap();
    }

    #[test]
    fn validation_rejects_omission_reordering_and_false_pass() {
        let receipts = CASES
            .into_iter()
            .map(|case| ReplacementApiReceipt {
                case_id: case.id.to_owned(),
                source_path: SOURCE_PATH.to_owned(),
                source_sha256: SOURCE_SHA256.to_owned(),
                capability: case.capability,
                disposition: compare(case.expected, case.expected),
            })
            .collect::<Vec<_>>();
        let counts = ReplacementApiCounts::from_receipts(&receipts).unwrap();
        let make_report = |receipts: Vec<ReplacementApiReceipt>, counts| {
            let payload = ReplacementApiReportPayload {
                source: expected_source_identity(),
                candidate: candidate(),
                counts,
                receipts,
            };
            ReplacementApiReport {
                schema: REPLACEMENT_API_REPORT_SCHEMA.to_owned(),
                payload_sha256: sha256(&serde_json::to_vec(&payload).unwrap()),
                payload,
            }
        };

        let mut omitted = receipts.clone();
        omitted.pop();
        assert!(make_report(omitted, counts.clone()).validate().is_err());

        let mut reordered = receipts.clone();
        reordered.swap(0, 1);
        assert!(make_report(reordered, counts.clone()).validate().is_err());

        let mut false_pass = receipts;
        false_pass[0].disposition = ReplacementApiDisposition::Pass {
            expected_sha256: "1".repeat(64),
            observed_sha256: "2".repeat(64),
        };
        assert!(make_report(false_pass, counts).validate().is_err());
    }
}
