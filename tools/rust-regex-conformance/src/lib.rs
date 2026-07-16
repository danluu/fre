//! Authenticated inventory for the pinned upstream Rust `regex` test corpus.
//!
//! This crate inventories inputs and records adapter obligations. It does not
//! execute FRE and therefore cannot make a compatibility claim.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fmt, fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    process::Command,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod adapter;
mod doctest_api;
mod doctest_builder_remaining;
mod doctest_byte_captures;
mod doctest_capture_metadata;
mod doctest_core_remaining;
mod feature_matrix;
mod misc_regression_api;
mod replacement_api;
mod searcher_api;

pub use adapter::{
    ADAPTER_ID, ADAPTER_REPORT_SCHEMA, AdapterDispositionCounts, AdapterReport,
    AdapterReportPayload, CandidateIdentity, ExecutableCase, ExpectedCaptures, ExpectedSpan,
    FreRegexAdapter, SearchBounds, authenticate_candidate_source, build_adapter_report,
    load_executable_cases, read_adapter_report, write_adapter_report,
};
pub use doctest_api::{
    DOCTEST_API_CASES, DOCTEST_API_REPORT_SCHEMA, DoctestCapability, DoctestCounts,
    DoctestDisposition, DoctestReceipt, DoctestReport, DoctestReportPayload, DoctestSourceFile,
    DoctestSourceIdentity, build_doctest_report, read_doctest_report, write_doctest_report,
};
pub use feature_matrix::{
    FEATURE_MATRIX_CONFIGURATIONS, FEATURE_MATRIX_DECLARED_FEATURES, FEATURE_MATRIX_REPORT_SCHEMA,
    FeatureMatrixCounts, FeatureMatrixDisposition, FeatureMatrixReport, FeatureMatrixReportPayload,
    FeatureMatrixUnsupportedKind, build_feature_matrix_report, read_feature_matrix_report,
    write_feature_matrix_report,
};
pub use misc_regression_api::{
    MISC_REGRESSION_API_CASES, MISC_REGRESSION_API_REPORT_SCHEMA, MiscRegressionCapability,
    MiscRegressionCounts, MiscRegressionDisposition, MiscRegressionReceipt, MiscRegressionReport,
    MiscRegressionReportPayload, MiscRegressionSourceFile, MiscRegressionSourceIdentity,
    build_misc_regression_report, read_misc_regression_report, write_misc_regression_report,
};
pub use replacement_api::{
    REPLACEMENT_API_CASES, REPLACEMENT_API_REPORT_SCHEMA, ReplacementApiCounts,
    ReplacementApiDisposition, ReplacementApiReceipt, ReplacementApiReport,
    ReplacementApiReportPayload, ReplacementCapability, ReplacementSourceIdentity,
    build_replacement_api_report, read_replacement_api_report, write_replacement_api_report,
};
pub use searcher_api::{
    SEARCHER_API_CASES, SEARCHER_API_REPORT_SCHEMA, SearcherApiCounts, SearcherApiDisposition,
    SearcherApiReceipt, SearcherApiReport, SearcherApiReportPayload, SearcherCapability,
    SearcherSourceIdentity, SearcherStep, build_searcher_api_report, read_searcher_api_report,
    write_searcher_api_report,
};

/// Checked-in manifest schema.
pub const MANIFEST_SCHEMA: &str = "fre.upstream-rust-regex.inventory.v1";
/// Exact upstream package version represented by this inventory.
pub const UPSTREAM_VERSION: &str = "1.12.4";
/// Exact upstream Git revision represented by this inventory.
pub const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
/// Normative upstream repository.
pub const UPSTREAM_REPOSITORY: &str = "https://github.com/rust-lang/regex";
/// Number of raw `[[test]]` records under upstream `testdata`.
pub const EXPECTED_CASES: usize = 1_184;
/// Number of raw records loaded by the `regex` crate's own `tests/lib.rs`.
pub const EXPECTED_RUST_REGEX_CASES: usize = 1_175;

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1_048_576;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Every file under upstream `testdata` at the pinned revision.
pub const EXPECTED_SOURCE_FILES: [&str; 31] = [
    "README.md",
    "anchored.toml",
    "bytes.toml",
    "crazy.toml",
    "crlf.toml",
    "earliest.toml",
    "empty.toml",
    "expensive.toml",
    "flags.toml",
    "fowler/basic.toml",
    "fowler/dat/README",
    "fowler/dat/basic.dat",
    "fowler/dat/nullsubexpr.dat",
    "fowler/dat/repetition.dat",
    "fowler/nullsubexpr.toml",
    "fowler/repetition.toml",
    "iter.toml",
    "leftmost-all.toml",
    "line-terminator.toml",
    "misc.toml",
    "multiline.toml",
    "no-unicode.toml",
    "overlapping.toml",
    "regex-lite.toml",
    "regression.toml",
    "set.toml",
    "substring.toml",
    "unicode.toml",
    "utf8.toml",
    "word-boundary-special.toml",
    "word-boundary.toml",
];

/// Error from authentication, import, or manifest validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryError(String);

impl InventoryError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InventoryError {}

/// Authenticated manifest wrapper. `payload_sha256` covers canonical compact
/// JSON serialization of `payload`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: InventoryPayload,
}

/// Content covered by `Inventory::payload_sha256`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPayload {
    pub upstream: UpstreamIdentity,
    pub scope: InventoryScope,
    pub source_files: Vec<SourceFileReceipt>,
    pub cases: Vec<CaseReceipt>,
    pub adapter_contract: AdapterContract,
    pub unresolved: Vec<String>,
}

/// Exact upstream identity authenticated before source is read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub tracked_and_untracked_worktree_clean: bool,
}

/// Cardinalities for the imported corpus and its explicit adapter obligation
/// cross product.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryScope {
    pub source_files: usize,
    pub rust_regex_corpus_toml_files: usize,
    pub other_upstream_corpus_toml_files: usize,
    pub auxiliary_files: usize,
    pub raw_cases: usize,
    pub rust_regex_cases: usize,
    pub other_upstream_cases: usize,
    pub adapter_surfaces: usize,
    pub adapter_obligations: usize,
}

/// Whether a source file is decoded or retained only for provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFileKind {
    RustRegexCorpusToml,
    OtherUpstreamCorpusToml,
    Auxiliary,
}

/// Whether the pinned `regex` crate integration runner loads a raw case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusMembership {
    RustRegexSuite,
    OtherUpstreamTestdata,
}

/// Digest and size of one upstream source file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFileReceipt {
    pub path: String,
    pub kind: SourceFileKind,
    pub bytes: u64,
    pub sha256: String,
    pub raw_cases: usize,
}

/// Stable match-selection modes from the upstream TOML schema.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchKind {
    All,
    #[default]
    LeftmostFirst,
    LeftmostLongest,
}

/// Stable search modes from the upstream TOML schema.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchKind {
    Earliest,
    #[default]
    Leftmost,
    Overlapping,
}

/// Stable, product-level capability dimensions used by inventory and future
/// unsupported receipts. These are not free-form diagnostic strings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityId {
    RustTextFacade,
    RustBytesFacade,
    RustTextSetFacade,
    RustBytesSetFacade,
    FindIteration,
    CaptureIteration,
    PatternSetExecution,
    CompileAccepted,
    CompileRejected,
    PatternSetEmpty,
    PatternSingle,
    PatternSetMany,
    SearchFullRange,
    SearchBounded,
    SearchAnchored,
    SearchUnanchored,
    SearchLeftmost,
    SearchEarliest,
    SearchOverlapping,
    MatchAll,
    MatchLeftmostFirst,
    MatchLeftmostLongest,
    UnicodeOn,
    UnicodeOff,
    Utf8EmptyOn,
    Utf8EmptyOff,
    CaseSensitive,
    CaseInsensitive,
    LineTerminatorLf,
    LineTerminatorCustom,
    HaystackLiteralUtf8,
    HaystackUnescapedBytes,
    MatchLimitUnlimited,
    MatchLimitBounded,
    ExpectedWholeMatches,
    ExpectedCaptureSlots,
}

/// One raw upstream case with semantic defaults made explicit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "booleans materialize the pinned upstream TOML schema as explicit receipt axes"
)]
pub struct CaseReceipt {
    /// Globally unique, path-qualified inventory ID.
    pub id: String,
    /// Name used by upstream's `regex-test` runner.
    pub upstream_name: String,
    pub source_file: String,
    pub source_ordinal: usize,
    pub corpus_membership: CorpusMembership,
    /// Digest of canonical parsed case content with defaults materialized.
    pub case_sha256: String,
    pub pattern_count: usize,
    pub compiles: bool,
    pub anchored: bool,
    pub bounded_search: bool,
    pub case_insensitive: bool,
    pub unescape_haystack: bool,
    pub unicode: bool,
    pub utf8: bool,
    pub custom_line_terminator: bool,
    pub match_limit: Option<usize>,
    pub match_kind: MatchKind,
    pub search_kind: SearchKind,
    pub maximum_expected_capture_slots: usize,
    pub capabilities: Vec<CapabilityId>,
}

/// A facade/operation boundary that must receive a disposition for every raw
/// case. Applicability is an explicit disposition, never an omitted row.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterSurface {
    RustTextCompile,
    RustTextIsMatch,
    RustTextFindIter,
    RustTextCapturesIter,
    RustBytesCompile,
    RustBytesIsMatch,
    RustBytesFindIter,
    RustBytesCapturesIter,
    RustTextSetCompile,
    RustTextSetIsMatch,
    RustTextSetWhich,
    RustBytesSetCompile,
    RustBytesSetIsMatch,
    RustBytesSetWhich,
}

impl AdapterSurface {
    pub const ALL: [Self; 14] = [
        Self::RustTextCompile,
        Self::RustTextIsMatch,
        Self::RustTextFindIter,
        Self::RustTextCapturesIter,
        Self::RustBytesCompile,
        Self::RustBytesIsMatch,
        Self::RustBytesFindIter,
        Self::RustBytesCapturesIter,
        Self::RustTextSetCompile,
        Self::RustTextSetIsMatch,
        Self::RustTextSetWhich,
        Self::RustBytesSetCompile,
        Self::RustBytesSetIsMatch,
        Self::RustBytesSetWhich,
    ];
}

/// Manifested rule preventing an adapter from silently filtering cases.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterContract {
    pub surfaces: Vec<AdapterSurface>,
    pub disposition_required_for_every_case_surface_pair: bool,
    pub silent_skip_permitted: bool,
}

/// Explicit reason an upstream case does not apply to one high-level facade.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotApplicableReason {
    ProfileCannotRepresentSearchMode,
    ProfileCannotRepresentMatchMode,
    ProfileCannotRepresentBounds,
    ProfileCannotRepresentAnchoring,
    ProfileCannotRepresentUtf8Mode,
    InvalidUtf8Haystack,
    PatternMultiplicity,
    CompileOnlyCase,
}

/// Result produced by an adapter. There is intentionally no `Skip` or
/// `Option` variant. Passes and mismatches bind both semantic values by their
/// canonical JSON SHA-256.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum AdapterDisposition {
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
        capability: CapabilityId,
        reason_code: String,
    },
    NotApplicable {
        reason: NotApplicableReason,
    },
    Fault {
        reason_code: String,
    },
}

/// One mandatory adapter disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterReceipt {
    pub case_id: String,
    pub case_sha256: String,
    pub surface: AdapterSurface,
    pub disposition: AdapterDisposition,
}

/// Adapter boundary used by the future execution/comparison layer.
pub trait CaseAdapter {
    fn execute(&mut self, surface: AdapterSurface, case: &CaseReceipt) -> AdapterDisposition;
}

/// Produce the complete case × surface receipt cross product. Since the
/// adapter returns a concrete enum, it cannot silently omit a case.
pub fn run_adapter_scaffold(
    inventory: &Inventory,
    adapter: &mut impl CaseAdapter,
) -> Result<Vec<AdapterReceipt>, InventoryError> {
    inventory.validate()?;
    let expected = inventory.payload.scope.adapter_obligations;
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(expected)
        .map_err(|_| InventoryError::new("adapter receipt allocation failed"))?;
    for case in &inventory.payload.cases {
        if case.corpus_membership != CorpusMembership::RustRegexSuite {
            continue;
        }
        for surface in AdapterSurface::ALL {
            let disposition = catch_unwind(AssertUnwindSafe(|| adapter.execute(surface, case)))
                .unwrap_or_else(|_| AdapterDisposition::Fault {
                    reason_code: "adapter.panic".to_owned(),
                });
            validate_disposition(&disposition)?;
            receipts.push(AdapterReceipt {
                case_id: case.id.clone(),
                case_sha256: case.case_sha256.clone(),
                surface,
                disposition,
            });
        }
    }
    if receipts.len() != expected {
        return Err(InventoryError::new(format!(
            "adapter emitted {} receipts, expected {expected}",
            receipts.len()
        )));
    }
    Ok(receipts)
}

/// Authenticate a clean checkout at the pinned revision and import all source
/// files and raw TOML cases.
pub fn build_inventory(checkout: &Path) -> Result<Inventory, InventoryError> {
    authenticate_git_checkout(checkout, UPSTREAM_REVISION)?;
    build_inventory_from_authenticated_source(checkout)
}

/// Read and structurally authenticate a checked-in manifest.
pub fn read_inventory(path: &Path) -> Result<Inventory, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!("read inventory {}: {error}", path.display()))
    })?;
    let inventory: Inventory = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode inventory {}: {error}", path.display()))
    })?;
    inventory.validate()?;
    Ok(inventory)
}

/// Atomically write canonical pretty JSON. An existing byte-identical file is
/// left untouched.
pub fn write_inventory(path: &Path, inventory: &Inventory) -> Result<(), InventoryError> {
    inventory.validate()?;
    let bytes = inventory.to_pretty_json()?;
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "inventory output has no parent: {}",
            path.display()
        ))
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!("invalid inventory output name: {}", path.display()))
        })?;
    let temporary = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    if temporary.exists() {
        return Err(InventoryError::new(format!(
            "inventory temporary already exists: {}",
            temporary.display()
        )));
    }
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

impl Inventory {
    /// Validate identity, cardinality, ordering, hashes, and adapter contract.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(InventoryError::new(format!(
                "inventory schema is {:?}, expected {MANIFEST_SCHEMA:?}",
                self.schema
            )));
        }
        let expected_payload_hash =
            sha256(&serde_json::to_vec(&self.payload).map_err(|error| {
                InventoryError::new(format!("encode inventory payload: {error}"))
            })?);
        if self.payload_sha256 != expected_payload_hash {
            return Err(InventoryError::new("inventory payload SHA-256 mismatch"));
        }
        let upstream = &self.payload.upstream;
        if upstream.repository != UPSTREAM_REPOSITORY
            || upstream.package != "regex"
            || upstream.version != UPSTREAM_VERSION
            || upstream.revision != UPSTREAM_REVISION
            || !upstream.tracked_and_untracked_worktree_clean
        {
            return Err(InventoryError::new("inventory upstream identity mismatch"));
        }
        validate_source_files(&self.payload.source_files)?;
        validate_cases(&self.payload.cases)?;
        let scope = &self.payload.scope;
        let rust_regex_corpus_files = self
            .payload
            .source_files
            .iter()
            .filter(|file| file.kind == SourceFileKind::RustRegexCorpusToml)
            .count();
        let other_upstream_corpus_files = self
            .payload
            .source_files
            .iter()
            .filter(|file| file.kind == SourceFileKind::OtherUpstreamCorpusToml)
            .count();
        let auxiliary_files = self
            .payload
            .source_files
            .iter()
            .filter(|file| file.kind == SourceFileKind::Auxiliary)
            .count();
        let obligations = EXPECTED_RUST_REGEX_CASES
            .checked_mul(AdapterSurface::ALL.len())
            .ok_or_else(|| InventoryError::new("adapter obligation count overflow"))?;
        let other_upstream_cases = EXPECTED_CASES
            .checked_sub(EXPECTED_RUST_REGEX_CASES)
            .ok_or_else(|| InventoryError::new("case scope subtraction underflow"))?;
        if scope.source_files != EXPECTED_SOURCE_FILES.len()
            || scope.rust_regex_corpus_toml_files != rust_regex_corpus_files
            || scope.other_upstream_corpus_toml_files != other_upstream_corpus_files
            || scope.auxiliary_files != auxiliary_files
            || scope.raw_cases != EXPECTED_CASES
            || scope.rust_regex_cases != EXPECTED_RUST_REGEX_CASES
            || scope.other_upstream_cases != other_upstream_cases
            || scope.adapter_surfaces != AdapterSurface::ALL.len()
            || scope.adapter_obligations != obligations
            || self.payload.cases.len() != EXPECTED_CASES
        {
            return Err(InventoryError::new("inventory scope cardinality mismatch"));
        }
        let contract = &self.payload.adapter_contract;
        if contract.surfaces != AdapterSurface::ALL
            || !contract.disposition_required_for_every_case_surface_pair
            || contract.silent_skip_permitted
        {
            return Err(InventoryError::new(
                "adapter contract permits incomplete accounting",
            ));
        }
        if self.payload.unresolved != unresolved_claims() {
            return Err(InventoryError::new(
                "inventory unresolved-claim ledger mismatch",
            ));
        }
        Ok(())
    }

    /// Canonical checked-in representation.
    pub fn to_pretty_json(&self) -> Result<Vec<u8>, InventoryError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| InventoryError::new(format!("encode inventory: {error}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSuite {
    #[serde(default, rename = "test")]
    tests: Vec<RawCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fields deliberately mirror the deny-unknown-fields upstream TOML schema"
)]
struct RawCase {
    #[serde(default)]
    name: String,
    regex: toml::Value,
    haystack: String,
    bounds: Option<toml::Value>,
    matches: Vec<toml::Value>,
    #[serde(rename = "match-limit")]
    match_limit: Option<usize>,
    #[serde(default = "default_true")]
    compiles: bool,
    #[serde(default)]
    anchored: bool,
    #[serde(default, rename = "case-insensitive")]
    case_insensitive: bool,
    #[serde(default)]
    unescape: bool,
    #[serde(default = "default_true")]
    unicode: bool,
    #[serde(default = "default_true")]
    utf8: bool,
    #[serde(default, rename = "line-terminator")]
    line_terminator: String,
    #[serde(default, rename = "match-kind")]
    match_kind: MatchKind,
    #[serde(default, rename = "search-kind")]
    search_kind: SearchKind,
}

const fn default_true() -> bool {
    true
}

#[allow(
    clippy::too_many_lines,
    reason = "the single transaction keeps source authentication, decoding, and cardinality assembly auditable"
)]
fn build_inventory_from_authenticated_source(checkout: &Path) -> Result<Inventory, InventoryError> {
    let testdata = checkout.join("testdata");
    let actual_paths = collect_source_paths(&testdata)?;
    let expected_paths = EXPECTED_SOURCE_FILES
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    if actual_paths != expected_paths {
        return Err(InventoryError::new(format!(
            "upstream testdata file set mismatch: expected {expected_paths:?}, observed {actual_paths:?}"
        )));
    }
    let mut source_files = Vec::new();
    let mut cases = Vec::new();
    source_files
        .try_reserve_exact(actual_paths.len())
        .map_err(|_| InventoryError::new("source receipt allocation failed"))?;
    cases
        .try_reserve_exact(EXPECTED_CASES)
        .map_err(|_| InventoryError::new("case receipt allocation failed"))?;
    let mut upstream_names = BTreeSet::new();
    for relative in actual_paths {
        let path = testdata.join(&relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(InventoryError::new(format!(
                "upstream source is not a regular non-symlink file: {}",
                path.display()
            )));
        }
        if metadata.len() > MAX_SOURCE_FILE_BYTES {
            return Err(InventoryError::new(format!(
                "upstream source exceeds byte limit: {}",
                path.display()
            )));
        }
        let bytes = fs::read(&path)
            .map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))?;
        let kind = if is_rust_regex_corpus(&relative) {
            SourceFileKind::RustRegexCorpusToml
        } else if is_toml(&relative) {
            SourceFileKind::OtherUpstreamCorpusToml
        } else {
            SourceFileKind::Auxiliary
        };
        let before = cases.len();
        if kind != SourceFileKind::Auxiliary {
            let membership = if kind == SourceFileKind::RustRegexCorpusToml {
                CorpusMembership::RustRegexSuite
            } else {
                CorpusMembership::OtherUpstreamTestdata
            };
            import_cases(
                &relative,
                &bytes,
                membership,
                &mut cases,
                &mut upstream_names,
            )?;
        }
        let raw_cases = cases
            .len()
            .checked_sub(before)
            .ok_or_else(|| InventoryError::new("case count moved backward"))?;
        source_files.push(SourceFileReceipt {
            path: relative,
            kind,
            bytes: metadata.len(),
            sha256: sha256(&bytes),
            raw_cases,
        });
    }
    if cases.len() != EXPECTED_CASES {
        return Err(InventoryError::new(format!(
            "pinned corpus decoded {} raw cases, expected {EXPECTED_CASES}",
            cases.len()
        )));
    }
    let rust_regex_corpus_toml_files = source_files
        .iter()
        .filter(|file| file.kind == SourceFileKind::RustRegexCorpusToml)
        .count();
    let other_upstream_corpus_toml_files = source_files
        .iter()
        .filter(|file| file.kind == SourceFileKind::OtherUpstreamCorpusToml)
        .count();
    let auxiliary_files = source_files
        .iter()
        .filter(|file| file.kind == SourceFileKind::Auxiliary)
        .count();
    let rust_regex_cases = cases
        .iter()
        .filter(|case| case.corpus_membership == CorpusMembership::RustRegexSuite)
        .count();
    let other_upstream_cases = cases
        .len()
        .checked_sub(rust_regex_cases)
        .ok_or_else(|| InventoryError::new("case scope subtraction underflow"))?;
    if rust_regex_cases != EXPECTED_RUST_REGEX_CASES {
        return Err(InventoryError::new(format!(
            "pinned regex integration suite decoded {rust_regex_cases} cases, expected {EXPECTED_RUST_REGEX_CASES}"
        )));
    }
    let adapter_obligations = rust_regex_cases
        .checked_mul(AdapterSurface::ALL.len())
        .ok_or_else(|| InventoryError::new("adapter obligation count overflow"))?;
    let payload = InventoryPayload {
        upstream: UpstreamIdentity {
            repository: UPSTREAM_REPOSITORY.to_owned(),
            package: "regex".to_owned(),
            version: UPSTREAM_VERSION.to_owned(),
            revision: UPSTREAM_REVISION.to_owned(),
            tracked_and_untracked_worktree_clean: true,
        },
        scope: InventoryScope {
            source_files: source_files.len(),
            rust_regex_corpus_toml_files,
            other_upstream_corpus_toml_files,
            auxiliary_files,
            raw_cases: cases.len(),
            rust_regex_cases,
            other_upstream_cases,
            adapter_surfaces: AdapterSurface::ALL.len(),
            adapter_obligations,
        },
        source_files,
        cases,
        adapter_contract: AdapterContract {
            surfaces: AdapterSurface::ALL.to_vec(),
            disposition_required_for_every_case_surface_pair: true,
            silent_skip_permitted: false,
        },
        unresolved: unresolved_claims(),
    };
    let payload_sha256 = sha256(
        &serde_json::to_vec(&payload)
            .map_err(|error| InventoryError::new(format!("encode inventory payload: {error}")))?,
    );
    let inventory = Inventory {
        schema: MANIFEST_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    inventory.validate()?;
    Ok(inventory)
}

fn import_cases(
    relative: &str,
    bytes: &[u8],
    corpus_membership: CorpusMembership,
    cases: &mut Vec<CaseReceipt>,
    upstream_names: &mut BTreeSet<String>,
) -> Result<(), InventoryError> {
    let source = std::str::from_utf8(bytes).map_err(|error| {
        InventoryError::new(format!("upstream TOML {relative} is not UTF-8: {error}"))
    })?;
    let suite: RawSuite = toml::from_str(source).map_err(|error| {
        InventoryError::new(format!("decode upstream TOML {relative}: {error}"))
    })?;
    let stem = Path::new(relative)
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| InventoryError::new(format!("invalid source file stem: {relative}")))?;
    let base = relative
        .strip_suffix(".toml")
        .ok_or_else(|| InventoryError::new(format!("invalid corpus suffix: {relative}")))?;
    let mut unnamed = 0_usize;
    for (index, raw) in suite.tests.into_iter().enumerate() {
        let ordinal = index
            .checked_add(1)
            .ok_or_else(|| InventoryError::new("case ordinal overflow"))?;
        let name = if raw.name.is_empty() {
            unnamed = unnamed
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("unnamed case counter overflow"))?;
            unnamed.to_string()
        } else {
            raw.name.clone()
        };
        validate_case_name(&name)?;
        let upstream_name = format!("{stem}/{name}");
        if !upstream_names.insert(upstream_name.clone()) {
            return Err(InventoryError::new(format!(
                "duplicate upstream case name {upstream_name:?}"
            )));
        }
        let id = format!("{base}/{name}");
        let pattern_count = pattern_count(&raw.regex)?;
        let bounded_search = raw.bounds.is_some();
        if let Some(bounds) = &raw.bounds {
            validate_bounds(bounds, relative, &name)?;
        }
        let maximum_expected_capture_slots = maximum_capture_slots(&raw.matches)?;
        let custom_line_terminator =
            !raw.line_terminator.is_empty() && raw.line_terminator != "\\n";
        let capabilities = classify_case(
            &raw,
            pattern_count,
            bounded_search,
            custom_line_terminator,
            maximum_expected_capture_slots,
        );
        let case_sha256 =
            sha256(&serde_json::to_vec(&raw).map_err(|error| {
                InventoryError::new(format!("encode upstream case {id}: {error}"))
            })?);
        cases.push(CaseReceipt {
            id,
            upstream_name,
            source_file: relative.to_owned(),
            source_ordinal: ordinal,
            corpus_membership,
            case_sha256,
            pattern_count,
            compiles: raw.compiles,
            anchored: raw.anchored,
            bounded_search,
            case_insensitive: raw.case_insensitive,
            unescape_haystack: raw.unescape,
            unicode: raw.unicode,
            utf8: raw.utf8,
            custom_line_terminator,
            match_limit: raw.match_limit,
            match_kind: raw.match_kind,
            search_kind: raw.search_kind,
            maximum_expected_capture_slots,
            capabilities,
        });
    }
    Ok(())
}

fn classify_case(
    raw: &RawCase,
    pattern_count: usize,
    bounded_search: bool,
    custom_line_terminator: bool,
    maximum_capture_slots: usize,
) -> Vec<CapabilityId> {
    let mut capabilities = BTreeSet::new();
    capabilities.insert(if raw.compiles {
        CapabilityId::CompileAccepted
    } else {
        CapabilityId::CompileRejected
    });
    capabilities.insert(match pattern_count {
        0 => CapabilityId::PatternSetEmpty,
        1 => CapabilityId::PatternSingle,
        _ => CapabilityId::PatternSetMany,
    });
    capabilities.insert(if bounded_search {
        CapabilityId::SearchBounded
    } else {
        CapabilityId::SearchFullRange
    });
    capabilities.insert(if raw.anchored {
        CapabilityId::SearchAnchored
    } else {
        CapabilityId::SearchUnanchored
    });
    capabilities.insert(match raw.search_kind {
        SearchKind::Earliest => CapabilityId::SearchEarliest,
        SearchKind::Leftmost => CapabilityId::SearchLeftmost,
        SearchKind::Overlapping => CapabilityId::SearchOverlapping,
    });
    capabilities.insert(match raw.match_kind {
        MatchKind::All => CapabilityId::MatchAll,
        MatchKind::LeftmostFirst => CapabilityId::MatchLeftmostFirst,
        MatchKind::LeftmostLongest => CapabilityId::MatchLeftmostLongest,
    });
    capabilities.insert(if raw.unicode {
        CapabilityId::UnicodeOn
    } else {
        CapabilityId::UnicodeOff
    });
    capabilities.insert(if raw.utf8 {
        CapabilityId::Utf8EmptyOn
    } else {
        CapabilityId::Utf8EmptyOff
    });
    capabilities.insert(if raw.case_insensitive {
        CapabilityId::CaseInsensitive
    } else {
        CapabilityId::CaseSensitive
    });
    capabilities.insert(if custom_line_terminator {
        CapabilityId::LineTerminatorCustom
    } else {
        CapabilityId::LineTerminatorLf
    });
    capabilities.insert(if raw.unescape {
        CapabilityId::HaystackUnescapedBytes
    } else {
        CapabilityId::HaystackLiteralUtf8
    });
    capabilities.insert(if raw.match_limit.is_some() {
        CapabilityId::MatchLimitBounded
    } else {
        CapabilityId::MatchLimitUnlimited
    });
    capabilities.insert(CapabilityId::ExpectedWholeMatches);
    if maximum_capture_slots > 1 {
        capabilities.insert(CapabilityId::ExpectedCaptureSlots);
    }
    capabilities.into_iter().collect()
}

fn pattern_count(value: &toml::Value) -> Result<usize, InventoryError> {
    match value {
        toml::Value::String(_) => Ok(1),
        toml::Value::Array(patterns) => {
            if patterns.iter().all(toml::Value::is_str) {
                Ok(patterns.len())
            } else {
                Err(InventoryError::new(
                    "regex array contains a non-string pattern",
                ))
            }
        }
        _ => Err(InventoryError::new(
            "regex field is neither string nor string array",
        )),
    }
}

fn validate_bounds(value: &toml::Value, file: &str, name: &str) -> Result<(), InventoryError> {
    let pair = match value {
        toml::Value::Array(values) if values.len() == 2 => {
            let start = values[0].as_integer();
            let end = values[1].as_integer();
            start.zip(end)
        }
        toml::Value::Table(table) => table
            .get("start")
            .and_then(toml::Value::as_integer)
            .zip(table.get("end").and_then(toml::Value::as_integer)),
        _ => None,
    };
    let Some((start, end)) = pair else {
        return Err(InventoryError::new(format!(
            "invalid bounds in {file}/{name}"
        )));
    };
    if start < 0 || end < start {
        return Err(InventoryError::new(format!(
            "invalid bounds order in {file}/{name}"
        )));
    }
    Ok(())
}

fn maximum_capture_slots(matches: &[toml::Value]) -> Result<usize, InventoryError> {
    let mut maximum = 0_usize;
    for matched in matches {
        let slots = match matched {
            toml::Value::Array(values) => {
                if values.len() == 2 && values.iter().all(toml::Value::is_integer) {
                    1
                } else if values
                    .iter()
                    .all(|value| matches!(value, toml::Value::Array(_)))
                {
                    values.len()
                } else {
                    return Err(InventoryError::new("unrecognized expected match array"));
                }
            }
            toml::Value::Table(table) => {
                if let Some(toml::Value::Array(spans)) = table.get("spans") {
                    spans.len()
                } else if table.contains_key("span") {
                    1
                } else {
                    return Err(InventoryError::new("unrecognized expected match table"));
                }
            }
            _ => return Err(InventoryError::new("unrecognized expected match value")),
        };
        maximum = maximum.max(slots);
    }
    Ok(maximum)
}

fn validate_source_files(files: &[SourceFileReceipt]) -> Result<(), InventoryError> {
    let paths = files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    if paths != EXPECTED_SOURCE_FILES {
        return Err(InventoryError::new(
            "manifest source file set/order mismatch",
        ));
    }
    for file in files {
        let expected_kind = if is_rust_regex_corpus(&file.path) {
            SourceFileKind::RustRegexCorpusToml
        } else if is_toml(&file.path) {
            SourceFileKind::OtherUpstreamCorpusToml
        } else {
            SourceFileKind::Auxiliary
        };
        if file.kind != expected_kind
            || file.bytes > MAX_SOURCE_FILE_BYTES
            || !is_sha256(&file.sha256)
            || (file.kind == SourceFileKind::Auxiliary && file.raw_cases != 0)
        {
            return Err(InventoryError::new(format!(
                "invalid source receipt for {}",
                file.path
            )));
        }
    }
    let decoded = files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.raw_cases)
            .ok_or_else(|| InventoryError::new("source case count overflow"))
    })?;
    if decoded != EXPECTED_CASES {
        return Err(InventoryError::new("source receipt case total mismatch"));
    }
    Ok(())
}

fn validate_cases(cases: &[CaseReceipt]) -> Result<(), InventoryError> {
    let mut ids = BTreeSet::new();
    let mut upstream_names = BTreeSet::new();
    let source_set = EXPECTED_SOURCE_FILES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for case in cases {
        if !ids.insert(case.id.as_str())
            || !upstream_names.insert(case.upstream_name.as_str())
            || !source_set.contains(case.source_file.as_str())
            || !is_toml(&case.source_file)
            || case.corpus_membership
                != if is_rust_regex_corpus(&case.source_file) {
                    CorpusMembership::RustRegexSuite
                } else {
                    CorpusMembership::OtherUpstreamTestdata
                }
            || case.source_ordinal == 0
            || !is_sha256(&case.case_sha256)
            || case.capabilities.is_empty()
            || !case.capabilities.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(InventoryError::new(format!(
                "invalid or duplicate case receipt {}",
                case.id
            )));
        }
    }
    let rust_regex_cases = cases
        .iter()
        .filter(|case| case.corpus_membership == CorpusMembership::RustRegexSuite)
        .count();
    if rust_regex_cases != EXPECTED_RUST_REGEX_CASES {
        return Err(InventoryError::new(
            "manifest Rust regex suite membership count mismatch",
        ));
    }
    Ok(())
}

fn validate_disposition(disposition: &AdapterDisposition) -> Result<(), InventoryError> {
    match disposition {
        AdapterDisposition::Pass {
            expected_sha256,
            observed_sha256,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 != observed_sha256
            {
                return Err(InventoryError::new(
                    "adapter pass semantic digests are invalid or unequal",
                ));
            }
        }
        AdapterDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code,
        } => {
            if !is_sha256(expected_sha256)
                || !is_sha256(observed_sha256)
                || expected_sha256 == observed_sha256
            {
                return Err(InventoryError::new(
                    "adapter mismatch semantic digests are invalid or equal",
                ));
            }
            validate_reason_code(reason_code)?;
        }
        AdapterDisposition::Unsupported { reason_code, .. }
        | AdapterDisposition::Fault { reason_code } => validate_reason_code(reason_code)?,
        AdapterDisposition::NotApplicable { .. } => {}
    }
    Ok(())
}

fn validate_reason_code(reason: &str) -> Result<(), InventoryError> {
    if reason.is_empty()
        || !reason.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(InventoryError::new(format!(
            "invalid stable adapter reason code {reason:?}"
        )));
    }
    Ok(())
}

fn validate_case_name(name: &str) -> Result<(), InventoryError> {
    if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(InventoryError::new(format!(
            "invalid upstream case name {name:?}"
        )));
    }
    Ok(())
}

fn unresolved_claims() -> Vec<String> {
    vec![
        "FRE execution and semantic comparison require the separately authenticated adapter report; inventory completeness alone is not execution evidence".to_owned(),
        "upstream Rust API integration tests, doctests, and feature-matrix tests are not inventoried here"
            .to_owned(),
        "regex-syntax and regex-automata internal suites require separate authenticated inventories"
            .to_owned(),
        "no compatibility, coverage, performance, or release claim follows from inventory completeness"
            .to_owned(),
    ]
}

fn authenticate_git_checkout(checkout: &Path, expected: &str) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(checkout).map_err(|error| {
        InventoryError::new(format!("stat checkout {}: {error}", checkout.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "upstream checkout must be a real directory",
        ));
    }
    if !is_commit_oid(expected) {
        return Err(InventoryError::new(
            "expected upstream revision is not a 40-hex OID",
        ));
    }
    let head = git_output(checkout, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head != expected {
        return Err(InventoryError::new(format!(
            "upstream revision mismatch: expected {expected}, observed {head}"
        )));
    }
    let status = git_output(
        checkout,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(InventoryError::new(format!(
            "upstream checkout is dirty: {status:?}"
        )));
    }
    Ok(())
}

fn git_output(checkout: &Path, args: &[&str]) -> Result<String, InventoryError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(args)
        .output()
        .map_err(|error| InventoryError::new(format!("run git {args:?}: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!(
            "git {args:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| InventoryError::new(format!("git output is not UTF-8: {error}")))
}

fn collect_source_paths(root: &Path) -> Result<Vec<String>, InventoryError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", root.display())))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "upstream testdata must be a real directory",
        ));
    }
    let mut paths = Vec::new();
    collect_source_paths_at(root, root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_source_paths_at(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> Result<(), InventoryError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| InventoryError::new(format!("read {}: {error}", directory.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| InventoryError::new(format!("read {}: {error}", directory.display())))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
        if metadata.file_type().is_symlink() {
            return Err(InventoryError::new(format!(
                "symlink in upstream testdata: {}",
                path.display()
            )));
        }
        if metadata.file_type().is_dir() {
            collect_source_paths_at(root, &path, paths)?;
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| InventoryError::new(format!("strip testdata prefix: {error}")))?;
            let relative = relative.to_str().ok_or_else(|| {
                InventoryError::new(format!("non-UTF-8 testdata path: {}", path.display()))
            })?;
            paths.push(relative.replace(std::path::MAIN_SEPARATOR, "/"));
        } else {
            return Err(InventoryError::new(format!(
                "non-regular object in upstream testdata: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_commit_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_toml(path: &str) -> bool {
    Path::new(path).extension() == Some(std::ffi::OsStr::new("toml"))
}

fn is_rust_regex_corpus(path: &str) -> bool {
    is_toml(path) && path != "regex-lite.toml"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct UnsupportedAdapter;

    struct PanicOnceAdapter(bool);

    impl CaseAdapter for UnsupportedAdapter {
        fn execute(&mut self, _surface: AdapterSurface, _case: &CaseReceipt) -> AdapterDisposition {
            AdapterDisposition::Unsupported {
                capability: CapabilityId::PatternSingle,
                reason_code: "adapter.not-implemented".to_owned(),
            }
        }
    }

    impl CaseAdapter for PanicOnceAdapter {
        fn execute(&mut self, _surface: AdapterSurface, _case: &CaseReceipt) -> AdapterDisposition {
            if !self.0 {
                self.0 = true;
                panic!("injected adapter panic");
            }
            AdapterDisposition::Unsupported {
                capability: CapabilityId::PatternSingle,
                reason_code: "adapter.not-implemented".to_owned(),
            }
        }
    }

    #[test]
    fn checked_in_inventory_is_complete_and_cannot_silently_skip() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/upstream-regex/regex-1.12.4-inventory.json");
        let inventory = read_inventory(&path).expect("checked-in inventory validates");
        assert_eq!(inventory.payload.scope.source_files, 31);
        assert_eq!(inventory.payload.scope.rust_regex_corpus_toml_files, 25);
        assert_eq!(inventory.payload.scope.other_upstream_corpus_toml_files, 1);
        assert_eq!(inventory.payload.scope.auxiliary_files, 5);
        assert_eq!(inventory.payload.scope.raw_cases, EXPECTED_CASES);
        assert_eq!(
            inventory.payload.scope.rust_regex_cases,
            EXPECTED_RUST_REGEX_CASES
        );
        assert_eq!(inventory.payload.scope.other_upstream_cases, 9);
        assert_eq!(inventory.payload.scope.adapter_surfaces, 14);
        assert_eq!(inventory.payload.scope.adapter_obligations, 16_450);
        let receipts = run_adapter_scaffold(&inventory, &mut UnsupportedAdapter)
            .expect("explicit unsupported receipts are valid");
        assert_eq!(receipts.len(), 16_450);
        assert!(
            receipts.iter().all(|receipt| matches!(
                receipt.disposition,
                AdapterDisposition::Unsupported { .. }
            ))
        );
    }

    #[test]
    fn one_adapter_panic_becomes_one_fault_without_losing_obligations() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/upstream-regex/regex-1.12.4-inventory.json");
        let inventory = read_inventory(&path).expect("checked-in inventory validates");
        let receipts = run_adapter_scaffold(&inventory, &mut PanicOnceAdapter(false))
            .expect("panic is converted into an explicit fault receipt");
        assert_eq!(receipts.len(), 16_450);
        assert!(matches!(
            receipts[0].disposition,
            AdapterDisposition::Fault { .. }
        ));
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| matches!(receipt.disposition, AdapterDisposition::Fault { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn checked_in_inventory_retains_adversarial_capability_axes() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/upstream-regex/regex-1.12.4-inventory.json");
        let inventory = read_inventory(&path).expect("checked-in inventory validates");
        let anchored = case(&inventory, "anchored/greedy");
        assert!(
            anchored
                .capabilities
                .contains(&CapabilityId::SearchAnchored)
        );
        assert!(anchored.maximum_expected_capture_slots > 1);
        let invalid_bytes = inventory
            .payload
            .cases
            .iter()
            .find(|case| {
                case.capabilities
                    .contains(&CapabilityId::HaystackUnescapedBytes)
            })
            .expect("unescaped byte case exists");
        assert!(invalid_bytes.unescape_haystack);
        let compile_rejection = inventory
            .payload
            .cases
            .iter()
            .find(|case| !case.compiles)
            .expect("compile rejection exists");
        assert!(
            compile_rejection
                .capabilities
                .contains(&CapabilityId::CompileRejected)
        );
        assert!(
            inventory
                .payload
                .cases
                .iter()
                .any(|case| { case.source_file.starts_with("fowler/") })
        );
        let regex_lite = case(&inventory, "regex-lite/perl-class-decimal");
        assert_eq!(
            regex_lite.corpus_membership,
            CorpusMembership::OtherUpstreamTestdata
        );
    }

    #[test]
    fn payload_tamper_is_rejected() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../research/upstream-regex/regex-1.12.4-inventory.json");
        let mut inventory = read_inventory(&path).expect("checked-in inventory validates");
        inventory.payload.cases[0].pattern_count = 99;
        assert_eq!(
            inventory
                .validate()
                .expect_err("tamper must fail")
                .to_string(),
            "inventory payload SHA-256 mismatch"
        );
    }

    #[test]
    fn unknown_toml_fields_and_malformed_match_shapes_fail_closed() {
        let unknown = r#"
            [[test]]
            name = "unknown"
            regex = "a"
            haystack = "a"
            matches = [[0, 1]]
            surprise = true
        "#;
        assert!(toml::from_str::<RawSuite>(unknown).is_err());
        let malformed = vec![toml::Value::String("not-a-match".to_owned())];
        assert!(maximum_capture_slots(&malformed).is_err());
    }

    #[test]
    fn git_authentication_rejects_wrong_revision_and_dirty_checkout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fre-rust-regex-inventory-git-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        run_git(&root, &["init", "--quiet"]);
        fs::write(root.join("tracked"), b"one\n").expect("write tracked file");
        run_git(&root, &["add", "tracked"]);
        run_git(
            &root,
            &[
                "-c",
                "user.name=FRE Selftest",
                "-c",
                "user.email=fre-selftest.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        );
        let head = git_output(&root, &["rev-parse", "--verify", "HEAD^{commit}"])
            .expect("read fixture head");
        authenticate_git_checkout(&root, &head).expect("clean exact checkout authenticates");
        assert!(authenticate_git_checkout(&root, UPSTREAM_REVISION).is_err());
        fs::write(root.join("tracked"), b"two\n").expect("dirty tracked file");
        assert!(authenticate_git_checkout(&root, &head).is_err());
        fs::remove_dir_all(&root).expect("remove fixture root");
    }

    fn case<'a>(inventory: &'a Inventory, id: &str) -> &'a CaseReceipt {
        inventory
            .payload
            .cases
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("missing case {id}"))
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("run git fixture command");
        assert!(status.success(), "git fixture command failed: {args:?}");
    }
}
